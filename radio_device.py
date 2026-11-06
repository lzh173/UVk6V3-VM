#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
radio_device.py — 手持机的"设备侧"模型：4MB 虚拟固件空间 + 串口协议栈

分层原因
--------
真机上串口协议跑在固件里；但被仿真的 原厂固件 固件本身没有串口代码。
所以把「串口 + 存储」做成设备级模型（相当于电台里的伴生 MCU / ROM bootloader），
与 MCU 仿真解耦：串口可以**常开**，MCU 暂停/重启都不影响。

存储布局 (device_flash.bin, 4 MB)
--------------------------------
    0x000000 .. 0x000FFF     4 KB    配置/信道区 ("EEPROM"，写频工具读写)
    0x001000 .. 0x3FFFFF   ~4 MB    固件区 (刷机模式擦写)

    * 擦除粒度 4 KB，写入粒度 256 B（模拟 NOR）
    * 写入只能 1→0（AND 语义），擦除置 0xFF；写 1 会报错，和真 NOR 一致
    * 每次改动立即落盘，掉电不丢

串口人格 1：应用模式（写频）—— 与 uv-k5-firmware app/uart.c 对齐
-----------------------------------------------------------------
传输帧:
    请求  AB CD | size(LE16) | obf(payload | crc16) | DC BA
    应答  AB CD | size(LE16) | obf(payload) | pad0 pad1 | DC BA
    payload = [cmd(LE16)][size(LE16)][body...]
    obf: 前 size(+2, 仅请求) 字节与 16 字节表循环异或
    crc16: CCITT, poly 0x1021, init 0, 不反射
    pad:  Obf[size%16]^0xFF, Obf[(size+1)%16]^0xFF

命令(id → 应答 id+1):
    0x0514 握手/版本   body: timestamp(4)        → 0x0515 ver[16] hasAes lock pad[2] challenge[4]
    0x051B 读 EEPROM   body: off(2) size(1) pad(1) ts(4) → 0x051C off(2) size(1) pad(1) data[size]
    0x051D 写 EEPROM   body: off(2) size(1) allow(1) ts(4) data[size] → 0x051E off(2)
    0x0527 读 RSSI                               → 0x0528 rssi(2) exnoise(1) glitch(1)
    0x0529 读电池                                → 0x052A volt(2) curr(2)
    0x052D 鉴权        body: response(4)         → 0x052E locked(1) pad
    0x052F 复位        body: timestamp(4)        → 0x0515 (同握手)
    0x05DD 重启进刷机  —                          → 无应答，切 bootloader

    0x051B/0x051D 要求 timestamp 与 0x0514 一致，否则静默丢弃（和固件一致）

串口人格 2：刷机模式（bootloader）
---------------------------------
复位后 800ms 内收到 "FLSH" 进入；或在应用模式发 0x05DD 重启。
（真机这段在 ROM 里，本协议按 UV-K5 风格自定义，字段定长小端，便于研究写入流程）

    "FLSH"                              → "FLSH"
    0x30                                  → 0x30 status chunk(4) totalMB(4)
    0x31 [addr:4][len:2]                  → 0x31 len(2) data
    0x32 [addr:4][len:2][data][crc16:2]   → 0x32 status(1)   (0=OK,1=CRC错,2=越界)
    0x33 [addr:4][len:4]                  → 0x33 status(1)
    0x34                                  → 0x34，回应用模式

用法
----
    python radio_device.py --port 8801 --flash device_flash.bin -v
    # pyserial: serial_for_url("socket://127.0.0.1:8801", timeout=1)
"""

import argparse
import os
import socket
import struct
import threading
import time

M32 = 0xFFFFFFFF

FLASH_SIZE = 4 * 1024 * 1024

# ---- EEPROM <-> 外部 NOR 映射 (抄自 Dondji App/driver/eeprom_compat.c) ----
EEPROM_MAP = [
    # 校准条目放在最前: 源码是先匹配先赢, 这样 EEPROM 0x1E00/0xB000 直达 NOR 0x010000
    (0x010000, 0x1E00, 0x2000),   # 校准 512B (v4.x 兼容)
    (0x010000, 0xB000, 0xB200),   # 校准 512B (v5.0.0+)
    (0x000000, 0x0000, 0x1000),
    (0x001000, 0x1000, 0x2000),
    (0x002000, 0x2000, 0x3000),
    (0x003000, 0x3000, 0x4000),
    (0x004000, 0x4000, 0x5000),
    (0x005000, 0x5000, 0x6000),
    (0x006000, 0x6000, 0x7000),
    (0x007000, 0x7000, 0x8000),
    (0x008000, 0x8000, 0x886E),
    (0x009000, 0x9000, 0x90D6),
    (0x00A000, 0xA000, 0xA170),
    (0x010000, 0x1E00, 0x2000),   # 校准 512B (v4.x 兼容)
    (0x010000, 0xB000, 0xB200),   # 校准 512B (v5.0.0+)
]
EEPROM_SIZE = 0x2000
SECTOR_SIZE = 0x1000     # PY25Q16 扇区 = 4 KB
SPACE_IMG_OFF = 0x001000     # 空间里 app 的位置 (对应 flash 0x08002800)
SPACE_PARAM_OFF = 0x000F00
APP_AREA_PAGES = 472       # 真机 sub_800059C(0x08002800, 472)   # 空间里 bootloader 参数块 (对应 flash 0x08002700)
SECTOR = 0x1000
PAGE = 0x100

OBFUSCATION = bytes([0x16, 0x6C, 0x14, 0xE6, 0x2E, 0x91, 0x0D, 0x40,
                     0x21, 0x35, 0xD5, 0x40, 0x13, 0x03, 0xE9, 0x80])

SYNC = b"\xAB\xCD"
FOOTER = b"\xDC\xBA"


# --------------------------------------------------------------------------
# CRC16-CCITT (poly 0x1021, init 0, MSB-first, no xorout)
# --------------------------------------------------------------------------
def _mk_table():
    t = []
    for i in range(256):
        c = i << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xFFFF if (c & 0x8000) else (c << 1) & 0xFFFF
        t.append(c)
    return t

_CRCTAB = _mk_table()


def crc16(data):
    crc = 0
    for b in data:
        crc = ((crc << 8) ^ _CRCTAB[((crc >> 8) ^ b) & 0xFF]) & 0xFFFF
    return crc


def xor_obf(data, n=None):
    n = len(data) if n is None else min(n, len(data))
    out = bytearray(data)
    for i in range(n):
        out[i] ^= OBFUSCATION[i % 16]
    return bytes(out)


# --------------------------------------------------------------------------
# 4MB 虚拟固件空间
# --------------------------------------------------------------------------
class Flash4M:
    def __init__(self, path, size=FLASH_SIZE, log=None):
        self.path = path
        self.size = size
        self.log = log or (lambda m: None)
        self.wlock = threading.Lock()
        self.dirty = False
        self.last_save = 0.0
        if os.path.exists(path):
            with open(path, "rb") as f:
                raw = f.read()
            self.data = bytearray(raw[:size])
            if len(self.data) < size:
                self.data += b"\xFF" * (size - len(self.data))
            self.log("[FLASH] 载入 %s (%d 字节已用)" % (os.path.basename(path), len(raw)))
        else:
            self.data = bytearray(b"\xFF" * size)
            self.save()
            self.log("[FLASH] 新建空白 4MB 空间: %s" % os.path.basename(path))
        self.stat_writes = 0
        self.stat_erases = 0
        self.generation = 0

    def save(self):
        with self.wlock:
            blob = bytes(self.data)
            ok = False
            for attempt in range(6):
                try:
                    tmp = self.path + ".tmp"
                    with open(tmp, "wb") as f:
                        f.write(blob)
                    os.replace(tmp, self.path)
                    ok = True
                    break
                except OSError:
                    time.sleep(0.02 * (attempt + 1))
            if not ok:                      # 兜底: 原地覆盖
                try:
                    with open(self.path, "r+b") as f:
                        f.seek(0)
                        f.write(blob)
                        f.truncate()
                    ok = True
                except OSError as e:
                    self.log("[FLASH] 保存失败: %s" % e)
            self.dirty = False
            self.last_save = time.time()
            return ok

    def read(self, addr, n):
        addr &= M32
        if addr >= self.size:
            return b"\xFF" * n
        n = min(n, self.size - addr)
        return bytes(self.data[addr:addr + n])

    def erase(self, addr, n):
        addr &= M32
        start = addr // SECTOR * SECTOR
        end = min(self.size, ((addr + n + SECTOR - 1) // SECTOR) * SECTOR)
        if start >= end:
            return False
        self.data[start:end] = b"\xFF" * (end - start)
        self.stat_erases += (end - start) // SECTOR
        self.generation += 1
        self.log("[FLASH] 擦除 0x%06X..0x%06X (%d 扇区)" % (start, end - 1, (end - start) // SECTOR))
        self.save()
        return True

    def erase_pages(self, addr, n_pages, page=0x100):
        """真机 bootloader 的擦除粒度: 256 字节/页 (sub_800059C)"""
        addr &= M32
        start = addr
        end = min(self.size, addr + n_pages * page)
        if start >= end:
            return False
        self.data[start:end] = b"\xFF" * (end - start)
        self.stat_erases += n_pages
        self.generation += 1
        self.log("[FLASH] 页擦除 0x%06X..0x%06X (%d 页)" % (start, end - 1, n_pages))
        self.save()
        return True

    def program(self, addr, payload):
        addr &= M32
        if addr + len(payload) > self.size:
            self.log("[FLASH] 写入越界 0x%06X+%d" % (addr, len(payload)))
            return False
        bad = 0
        for i, b in enumerate(payload):
            old = self.data[addr + i]
            if b != 0xFF and (old & b) != b:
                bad += 1          # 想写 1 但该位已被擦成 0
            self.data[addr + i] = old & b
        self.stat_writes += 1
        if addr + len(payload) > SPACE_IMG_OFF:      # 只有固件区变化才通知 MCU 重载
            self.generation += 1
        if bad:
            self.log("[FLASH] 警告: 0x%06X 有 %d 字节违反 1→0（该扇区未擦除？）" % (addr, bad))
        self.log("[FLASH] 写入 0x%06X +%d" % (addr, len(payload)))
        self.dirty = True
        # 攒批落盘: 16KB 或 1 秒一次, 避免每 256B 重写 4MB
        if (self.stat_writes & 0xFF) == 0 or (time.time() - self.last_save) > 2.0:
            self.save()
        return True

    def flush(self):
        if self.dirty:
            self.save()


# --------------------------------------------------------------------------
# 设备
# --------------------------------------------------------------------------
class VirtualRadio:
    def __init__(self, flash_path=None, log=None, start_in_boot=False, space=None,
                 legacy_proto=False):
        self.log = log or (lambda m: None)
        self.flash = space if space is not None else Flash4M(flash_path, log=self.log)
        self.lock = threading.RLock()
        self.rx = bytearray()
        self.tx = bytearray()
        self.version = b"UV-K6-VM 1.0"
        self.hw_id = struct.pack("<I", 0x00000001)
        self.session_ts = None
        self.locked = False
        self.boot_mode = False
        self.boot_deadline = 0.0
        # 真实 bootloader (stock-bl 7.02.02) 状态
        self.bl_unlocked = False
        self.bl_total_blocks = 0
        self.bl_last_idx = -1
        self.bl_crc = 0
        self.bl_info_due = 0.0
        self.bl_uid = (0x1A2B3C4D, 0x5E6F7081, 0x92A3B4C5, 0x0F1E2D3C)
        self.flashlight = False
        self.backlight = False
        self.legacy_proto = legacy_proto   # 旧 FLSH/0x30-0x34 兼容层（真机没有）
        self.ptt = False
        self.ptt_idr = 0x0000            # 模拟 GPIOC->IDR；按住 PTT 时 bits14/15/10 为 1
        self.bl_state = 0            # 0=空闲 1=接收中 2=完成待跳转
        self.bl_cookie = b""
        self.bl_next_idx = 0
        self.bl_finish_at = 0.0
        if start_in_boot:
            self.hold_boot()
        else:
            self.enter_boot_window(0.8)

    # ---- 状态 ----
    def enter_boot_window(self, secs):
        already = getattr(self, "boot_mode", False)
        self.boot_mode = True
        self.boot_deadline = time.time() + secs
        self.bl_unlocked = False
        if not already:
            self._bl_banner()
            self.log("[DEV] 进入 bootloader 窗口 %.1fs（等待 FLSH / 0x0518 会话）" % secs)

    def hold_boot(self, ptt=False):
        """直接进刷机模式并保持 (不等 0.8s 超时)

        真机行为: 开机时按住 PTT -> 手电筒常亮 + 屏幕背光开 + 进 bootloader,
        应用固件完全不运行。这里把外设状态一起建模。
        """
        self.boot_mode = True
        self.boot_deadline = float("inf")
        self.bl_unlocked = False
        self.flashlight = True
        self.backlight = True
        self._bl_banner()
        if ptt:
            self.ptt = True
            self.ptt_idr = 0xC400
            self.log("[BOOT] PTT 按住 (GPIOB->IDR & 0xC000 == 0xC000 且 bit10==0) "
                     "-> 手电筒常亮(PC13) + 背光开 + 进刷机模式, 固件不运行")
        else:
            self.log("[DEV] 已进入刷机模式 (--flsh), 协议 = stock-bl 7.02.02")

    def _bl_banner(self):
        """真机行为: 上电先发 ASCII 版本横幅 '7.02.02\\0\\0\\0\\xc4 \\r\\n'"""
        self.tx.extend(b"7.02.02\x00\x00\x00\xc4 \r\n")
        self.bl_info_due = time.time() + 0.2

    def _bl_info_frame(self):
        """0x0518: 版本(16B) + UID(16B) —— 刷机软件靠它读机器信息"""
        body = struct.pack("<4I", *self.bl_uid) + b"7.02.02".ljust(16, b"\x00")
        self._reply(0x0518, body, inner_size=len(body))
        if getattr(self, "verbose_info", False):
            self.log("[BOOT] -> 0x0518 信息帧 (UID + 版本)")

    @staticmethod
    def eeprom_to_nor(addr):
        """EEPROM 逻辑地址 -> 外部 NOR 地址 (按源码映射表, 先匹配先赢)"""
        for nor, lo, hi in EEPROM_MAP:
            if lo <= addr < hi:
                return nor + (addr - lo)
        return None

    def eeprom_read(self, addr, n):
        """按映射表分段读 EEPROM -> NOR"""
        out = bytearray()
        while n > 0:
            nor = self.eeprom_to_nor(addr)
            if nor is None:
                out.append(0xFF); addr += 1; n -= 1; continue
            seg = 1
            while seg < n and self.eeprom_to_nor(addr + seg) == nor + seg:
                seg += 1
            out += self.flash.read(nor, seg)
            addr += seg; n -= seg
        return bytes(out)

    def eeprom_write(self, addr, data):
        """按映射表写 EEPROM -> NOR

        真机 PY25Q16_WriteBuffer 是"整扇区读-改-写"（SectorCache），
        不是每次都擦一页；否则 16 字节一写的调用会把前一写覆盖掉。
        """
        i = 0
        while i < len(data):
            nor = self.eeprom_to_nor(addr + i)
            if nor is None:
                i += 1; continue
            seg = 1
            while i + seg < len(data) and self.eeprom_to_nor(addr + i + seg) == nor + seg:
                seg += 1
            sec = nor // SECTOR_SIZE * SECTOR_SIZE
            off = nor - sec
            if off + seg > SECTOR_SIZE:                 # 跨扇区就截断，下次循环继续
                seg = SECTOR_SIZE - off
            buf = bytearray(self.flash.read(sec, SECTOR_SIZE))
            if buf[off:off + seg] != data[i:i + seg]:
                buf[off:off + seg] = data[i:i + seg]
                self.flash.erase_pages(sec, SECTOR_SIZE // 0x100)
                self.flash.program(sec, bytes(buf))
            i += seg

    def power_cycle(self, ptt=False):
        """冷启动：PTT 按住 -> bootloader；否则 -> 应用模式"""
        with self.lock:
            self.rx.clear()
            self.tx.clear()
            self.bl_state = 0
            self.bl_unlocked = False
            if ptt:
                self.hold_boot(ptt=True)
            else:
                self.flashlight = False
                self.backlight = True
                self.go_app()
                self.session_ts = None

    def go_app(self):
        self.boot_mode = False
        self.session_ts = None
        self.tx.clear()
        self.log("[DEV] 切换到应用模式（写频）")

    def reset(self):
        with self.lock:
            self.rx.clear()
            self.tx.clear()
            self.locked = False
            self.enter_boot_window(0.8)

    # ---- 字节流 ----
    def feed(self, data):
        with self.lock:
            self.rx.extend(data)

    def tick(self):
        with self.lock:
            self.flash.flush()
            if self.boot_mode:
                now = time.time()
                # 收到过任何帧/解锁过 -> 不再超时回应用模式（真机 bootloader 死等）
                if self.bl_unlocked or self.bl_state:
                    self.boot_deadline = float("inf")
                if self.bl_state == 2 and now >= self.bl_finish_at:
                    sp = struct.unpack("<I", self.flash.read(SPACE_IMG_OFF, 4))[0]
                    self.flashlight = False          # 真机: GPIOC->BRR = 1<<13
                    self.log("[BOOT] 手电筒熄灭")
                    if (sp & 0x2FFC0000) == 0x20000000:
                        self.log("[BOOT] app 有效 (SP=%08X), 跳转执行" % sp)
                        self.bl_state = 0
                        self.go_app()
                    else:
                        self.log("[BOOT] app 无效 (SP=%08X), 留在 bootloader" % sp)
                        self.bl_state = 0
                    return
                if now >= self.bl_info_due:
                    self._bl_info_frame()
                    self.bl_info_due = now + 0.5
                elif now > self.boot_deadline:
                    self.go_app()

    def poll(self):
        with self.lock:
            self._dispatch()
            out = bytes(self.tx)
            self.tx.clear()
            return out

    # ================= 分发 =================
    def _dispatch(self):
        while self.rx:
            if self.boot_mode and self._try_boot():
                continue
            if not self._try_app():
                return

    # ---------------- bootloader (stock-bl 7.02.02 真实协议) ----------------
    def _try_boot(self):
        buf = self.rx
        if not buf:
            return False
        # ---- 真实协议: 0xABCD 帧 ----
        if buf[:1] == b"\xAB":
            payload = self._extract_frame()
            if payload is None:
                return False
            self._bl_handle(payload)
            return True
        # ---- 兼容层 (需 --legacy-proto): FLSH / 0x30-0x34 ----
        if not getattr(self, "legacy_proto", False):
            del buf[:1]
            return True
        if buf[:1] == b"F" or (len(buf) < 4 and b"FLSH".startswith(bytes(buf))):
            if len(buf) < 4:
                return False
            if bytes(buf[:4]) != b"FLSH":
                self.go_app()
                return True
            del buf[:4]
            self.tx.extend(b"FLSH")
            self.boot_deadline = time.time() + 3600
            self.log("[DEV] FLSH 握手 OK -> 刷机模式")
            return True

        cmd = buf[0]
        if cmd == 0x30:
            del buf[:1]
            self.tx.extend(b"\x30" + struct.pack("<II", PAGE, FLASH_SIZE // (1024 * 1024)))
            self.log("[BOOT] 信息: 页 %d B, 空间 %d MB" % (PAGE, FLASH_SIZE // (1024 * 1024)))
            return True
        if cmd == 0x31:
            if len(buf) < 7:
                return False
            addr, n = struct.unpack_from("<IH", buf, 1)
            del buf[:7]
            data = self.flash.read(addr, n)
            self.tx.extend(b"\x31" + struct.pack("<H", len(data)) + data)
            self.log("[BOOT] 读 0x%06X +%d" % (addr, n))
            return True
        if cmd == 0x32:
            if len(buf) < 8:
                return False
            addr, n = struct.unpack_from("<IH", buf, 1)
            need = 1 + 4 + 2 + n + 2
            if len(buf) < need:
                return False
            data = bytes(buf[7:7 + n])
            crc_rx = struct.unpack_from("<H", buf, 7 + n)[0]
            st = 0 if crc16(data) == crc_rx else 1
            del buf[:need]
            if st == 0:
                ok = self.flash.program(addr, data)
                st = 0 if ok else 2
            self.tx.extend(b"\x32" + bytes([st]))
            self.log("[BOOT] 写 0x%06X +%d -> %s" % (addr, n, "OK" if st == 0 else "ERR%d" % st))
            return True
        if cmd == 0x33:
            if len(buf) < 9:
                return False
            addr, n = struct.unpack_from("<II", buf, 1)
            del buf[:9]
            ok = self.flash.erase(addr, n)
            self.tx.extend(b"\x33" + bytes([0 if ok else 2]))
            return True
        if cmd == 0x34:
            del buf[:1]
            self.tx.extend(b"\x34")
            self.go_app()
            return True
        del buf[:1]
        return True

    def _bl_handle(self, payload):
        """真实 bootloader 命令: 0x0516 / 0x0519 / 0x0530"""
        self.boot_deadline = float("inf")      # 有帧进来就别再回应用模式
        if len(payload) < 4:
            return
        cmd, inner = struct.unpack_from("<HH", payload, 0)
        if getattr(self, "verbose_frames", False):
            self.log("[RX] %04X inner=%d %s" % (cmd, inner, payload[:32].hex()))
        body = payload[4:]
        self.log("[BOOT] <- 0x%04X inner=%d len=%d" % (cmd, inner, len(body)))

        if cmd == 0x0530:
            magic = body[:4]
            ok = (magic == b"7.02") or (len(body) >= 1 and body[0] == 0x2A)
            self.bl_unlocked = ok
            self.log("[BOOT] 解锁 %s (magic=%r)" % ("OK" if ok else "FAILED", magic))
            return

        if cmd == 0x0516:
            # 真机: 擦 1 页(256B) @0x08002700, 再把 104 字节写进去
            data = bytes(body[:0x68]).ljust(256, b"\x00")
            self.flash.erase_pages(SPACE_PARAM_OFF, 1)
            self.flash.program(SPACE_PARAM_OFF, data)
            self._reply(0x0517, b"\x00\x00\x00\x00", inner_size=4)
            self.log("[BOOT] 参数块 104B -> flash 0x08002700")
            return

        if cmd == 0x0519:
            cookie = bytes(body[0:4])
            idx = struct.unpack_from("<H", body, 4)[0] if len(body) >= 8 else 0
            total = struct.unpack_from("<H", body, 6)[0] if len(body) >= 8 else 0
            if not self.bl_unlocked:
                # 真机: 未解锁 -> 直接回 cookie=0 的状态帧, 不写
                self._reply(0x051A, b"\x00\x00\x00\x00" + struct.pack("<HBB", idx, 1, 0),
                            inner_size=8)
                self.log("[BOOT] 未解锁, 拒绝块 %d" % idx)
                return
            if len(body) < 12 + 256:
                self._reply(0x051A, cookie + struct.pack("<HBB", idx, 2, 0), inner_size=8)
                return
            data = bytes(body[12:12 + 256])
            if idx == 0:
                # 块 0: 记录会话 + 整区擦除 472 页 (120,832 B)
                self.bl_cookie = cookie
                self.bl_total = total
                self.bl_next_idx = 0
                self.bl_state = 1
                self.flash.erase_pages(SPACE_IMG_OFF, APP_AREA_PAGES)
                self.log("[BOOT] 块 0: 整区擦除 %d 页 (%d B), total=%d"
                         % (APP_AREA_PAGES, APP_AREA_PAGES * 256, total))
            elif cookie != self.bl_cookie or idx != self.bl_next_idx:
                # 真机 (sub_80002A0): cookie 不一致 或 块号不连续 -> 报错, **不写**
                self.bl_state = 0
                self.log("[BOOT] 块 %d 顺序/cookie 错 (期望 cookie=%s idx=%d)*"
                         % (idx, self.bl_cookie.hex(), self.bl_next_idx))
                self._reply(0x051A, cookie + struct.pack("<HBB", idx, 1, 0), inner_size=8)
                return
            self.flash.program(SPACE_IMG_OFF + idx * 256, data)
            self.bl_next_idx = idx + 1
            done = (total and idx + 1 >= total)
            self._reply(0x051A, cookie + struct.pack("<HBB", idx, 0, 0), inner_size=8)
            self.log("[BOOT] 块 %d/%d -> flash 0x%06X%s"
                     % (idx + 1, total, 0x08002800 + idx * 256, "  [完成]" if done else ""))
            if done:
                self.bl_state = 2
                self.bl_finish_at = time.time() + 1.0     # 真机 delay(100000) 后跳转
            return

        self.log("[BOOT] 未知命令 0x%04X" % cmd)

    def _extract_frame(self):
        """从 rx 取一个完整帧 (AB CD | size | obf(payload+crc) | DC BA), 返回 payload"""
        buf = self.rx
        i = buf.find(SYNC)
        if i < 0:
            if len(buf) > 4096:
                del buf[:-64]
            return None
        if i:
            del buf[:i]
        if len(buf) < 8:
            return None
        size = buf[2] | (buf[3] << 8)
        if size < 4 or size > 512:
            del buf[:2]
            return None
        total = size + 8
        if len(buf) < total:
            return None
        frame = bytes(buf[:total])
        if frame[-2:] != FOOTER:
            del buf[:2]
            return None
        del buf[:total]
        plain = xor_obf(frame[4:4 + size + 2], size + 2)
        payload = plain[:size]
        crc_rx = struct.unpack_from("<H", plain, size)[0]
        if crc16(payload) != crc_rx:
            self.log("[FRAME] CRC 错 rx=%04X calc=%04X" % (crc_rx, crc16(payload)))
            return None
        return payload

    # ---------------- 应用协议 ----------------
    def _try_app(self):
        buf = self.rx
        i = buf.find(SYNC)
        if i < 0:
            if len(buf) > 4096:
                del buf[:-64]
            return False
        if i:
            del buf[:i]
        if len(buf) < 8:
            return False
        size = buf[2] | (buf[3] << 8)
        if size < 4 or size > 512:
            del buf[:2]
            return True
        total = size + 8
        if len(buf) < total:
            return False
        frame = bytes(buf[:total])
        if frame[-2:] != FOOTER:
            del buf[:2]
            return True
        enc = frame[4:4 + size + 2]               # 请求: payload + crc 都被异或
        plain = xor_obf(enc, size + 2)
        payload = plain[:size]
        crc_rx = struct.unpack_from("<H", plain, size)[0]
        crc_calc = crc16(payload)
        if crc_calc != crc_rx:
            self.log("[APP] CRC 错 rx=%04X calc=%04X" % (crc_rx, crc_calc))
            del buf[:total]
            return True
        del buf[:total]
        self._handle_app(payload)
        return True

    def _reply(self, cmd, body, inner_size=None):
        inner = (4 + len(body)) if inner_size is None else inner_size
        payload = struct.pack("<HH", cmd, inner) + body
        n = len(payload)
        pad0 = OBFUSCATION[n & 0xF] ^ 0xFF
        pad1 = OBFUSCATION[(n + 1) & 0xF] ^ 0xFF
        enc = xor_obf(payload, n)
        frame = SYNC + struct.pack("<H", n) + enc + bytes([pad0, pad1]) + FOOTER
        self.tx.extend(frame)
        if cmd != 0x0518 or getattr(self, "verbose_info", False):
            self.log("[TX] -> %04X len=%d" % (cmd, len(payload)))

    def _handle_app(self, payload):
        if len(payload) < 4:
            return
        cmd, size = struct.unpack_from("<HH", payload, 0)
        body = payload[4:]
        self.log("[APP] <- %04X size=%d" % (cmd, size))

        if cmd in (0x0514, 0x052F):
            self.session_ts = struct.unpack_from("<I", body + b"\x00" * 4, 0)[0] if len(body) >= 4 else 0
            ver = self.version.ljust(16, b"\x00")[:16]
            challenge = bytes(range(0x11, 0x21))          # 16 B
            self._reply(0x0515, ver + b"\x00\x00\x00\x00" + challenge)
            return

        if cmd in (0x051B, 0x051D) and len(body) >= 8:
            ts = struct.unpack_from("<I", body, 4)[0]
            if self.session_ts is not None and ts != self.session_ts:
                self.log("[APP] timestamp 不匹配 (%08X != %08X), 丢弃"
                         % (ts, self.session_ts))
                return

        if cmd == 0x051B:
            if len(body) < 8:
                return
            off, rsize = struct.unpack_from("<HB", body, 0)
            rsize = min(rsize, 128)
            data = self.eeprom_read(off, rsize)
            self._reply(0x051C, struct.pack("<HBB", off, rsize, 0) + data)
            self.log("[APP] 读 EEPROM 0x%04X +%d" % (off, rsize))
            return

        if cmd == 0x051D:
            if len(body) < 8:
                return
            off, wsize, allow = struct.unpack_from("<HBB", body, 0)
            data = body[8:8 + wsize]
            if data:
                self.eeprom_write(off, data)
                self.log("[APP] 写 EEPROM 0x%04X +%d" % (off, len(data)))
            else:
                self.log("[APP] 写越界, 忽略")
            self._reply(0x051E, struct.pack("<H", off))
            return

        if cmd == 0x051F:
            # SPI Flash Read: {Address(4) Size(2) Pad(2) Timestamp(4)} -> 0x0520
            if len(body) < 12:
                return
            addr, size, _pad, ts = struct.unpack_from("<IHHI", body, 0)
            if size > 120:
                size = 120
            data = self.flash.read(addr, size)
            self._reply(0x0520,
                        struct.pack("<IHH", addr, size, 0) + data,
                        inner_size=size + 8)
            self.log("[APP] SPI Flash 读 0x%06X +%d" % (addr, size))
            return

        if cmd == 0x0521:
            # SPI Flash Write: {Address(4) Size(2) Pad(2) Timestamp(4) Data[...]} -> 0x0522
            if len(body) < 12:
                return
            addr, size, _pad, ts = struct.unpack_from("<IHHI", body, 0)
            if size > 120:
                size = 120
            data = body[12:12 + size]
            if data:
                sec = addr // SECTOR_SIZE * SECTOR_SIZE
                off = addr - sec
                buf = bytearray(self.flash.read(sec, SECTOR_SIZE))
                if buf[off:off + len(data)] != data:
                    buf[off:off + len(data)] = data
                    self.flash.erase_pages(sec, SECTOR_SIZE // 0x100)
                    self.flash.program(sec, bytes(buf))
            self._reply(0x0522, struct.pack("<IHH", addr, size, 0), inner_size=8)
            self.log("[APP] SPI Flash 写 0x%06X +%d  %s" % (addr, size, data[:12].hex()))
            self.log("[DUMP] 0x%06X %s" % (addr, data.hex()))
            return

        if cmd == 0x0527:
            self._reply(0x0528, struct.pack("<HBB", 0x0120, 0x10, 0x00))
            return
        if cmd == 0x0529:
            self._reply(0x052A, struct.pack("<HH", 7400, 350))
            return
        if cmd == 0x052D:
            self._reply(0x052E, bytes([1 if self.locked else 0, 0]))
            return
        if cmd == 0x05DD:
            self.log("[APP] 重启 → bootloader")
            self.enter_boot_window(3.0)
            return
        self.log("[APP] 未知命令 %04X" % cmd)


# --------------------------------------------------------------------------
# TCP 串口桥
# --------------------------------------------------------------------------
class SerialBridge:
    def __init__(self, radio, host="127.0.0.1", port=8801, log=None):
        self.radio = radio
        self.log = log or (lambda m: None)
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((host, port))
        self.srv.listen(4)
        self.srv.setblocking(False)
        self.clients = []
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self.thread.start()
        self.log("[UART] 串口就绪 tcp://%s:%d" % self.srv.getsockname())

    def _loop(self):
        while self.running:
            try:
                c, addr = self.srv.accept()
                c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                c.setblocking(False)
                self.clients.append(c)
                self.log("[UART] 客户端接入 %s:%d" % addr)
                if getattr(self.radio, "boot_mode", False):
                    # 插到队首, 保证工具先看到版本横幅
                    self.radio.tx[:0] = b"7.02.02\x00\x00\x00\xc4 \r\n"
            except BlockingIOError:
                pass
            except OSError:
                break
            for c in list(self.clients):
                try:
                    d = c.recv(4096)
                    if d:
                        self.radio.feed(d)
                    else:
                        self.clients.remove(c); c.close()
                        self.log("[UART] 客户端断开")
                except BlockingIOError:
                    pass
                except OSError:
                    try:
                        self.clients.remove(c); c.close()
                    except Exception:
                        pass
            out = self.radio.poll()
            if out:
                for c in list(self.clients):
                    try:
                        c.sendall(out)
                    except OSError:
                        pass
            self.radio.tick()
            time.sleep(0.001)

    def stop(self):
        self.running = False
        for c in self.clients:
            try:
                c.close()
            except Exception:
                pass
        try:
            self.srv.close()
        except Exception:
            pass


class ComBridge:
    """把虚拟电台挂到真实 COM 口上 (配合 com0com 的虚拟串口对)

    用法: com0com 建一对 COM14<->COM15, 本桥占 COM14,
          写频软件打开 COM15 就能直接对话。
    """

    def __init__(self, radio, port="COM14", baud=38400, log=None):
        import serial
        self.radio = radio
        self.log = log or (lambda m: None)
        try:
            self.ser = serial.Serial(port, baud, timeout=0.02, write_timeout=1)
        except Exception as e:
            print("[COM] !! 打不开 %s: %s" % (port, e))
            print("[COM]    常见原因: 另一个程序占着这个口（例如 sniff_param.py / 串口助手 /")
            print("[COM]    上一次的 radio_device.py 还在跑）。先关掉它再试。")
            raise SystemExit(1)
        try:
            self.ser.reset_input_buffer()
            self.ser.reset_output_buffer()
            self.log("[COM] 已清空串口残留缓冲")
        except Exception as e:
            self.log("[COM] 清缓冲失败: %s" % e)
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.log("[COM] 已打开 %s @ %d 8N1" % (port, baud))

    def start(self):
        self.thread.start()
        self.log("[COM] 串口桥运行中 (对端可开另一只虚拟串口)")

    def _loop(self):
        while self.running:
            try:
                d = self.ser.read(256)
                if d:
                    self.radio.feed(d)
                out = self.radio.poll()
                if out:
                    try:
                        self.ser.write(out)
                    except Exception:
                        pass          # 对端没在读: 丢掉这一帧, 别卡住
                self.radio.tick()
            except Exception as e:
                self.log("[COM] 错误: %s" % e)
                time.sleep(0.1)

    def stop(self):
        self.running = False
        try:
            self.ser.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser(description="虚拟电台串口 + 4MB 固件空间")
    ap.add_argument("--port", type=int, default=8801)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--flash", default="device_flash.bin")
    ap.add_argument("--com", default=None, metavar="COMx",
                    help="同时把串口桥到真实 COM 口 (配合 com0com)")
    ap.add_argument("--flsh", action="store_true",
                    help="直接进刷机模式 (不再等待 0.8s 窗口)")
    ap.add_argument("--app", action="store_true",
                    help="直接以应用模式(正常工作界面)启动, 不进 bootloader 窗口")
    ap.add_argument("--ptt", action="store_true",
                    help="模拟开机按住 PTT: 手电筒常亮 + 背光开 + 固件不运行")
    ap.add_argument("--legacy-proto", action="store_true",
                    help="额外启用旧字节命令 FLSH/0x30-0x34（真机没有，调试用）")
    ap.add_argument("--baud", type=int, default=38400)
    args = ap.parse_args()

    radio = VirtualRadio(args.flash, log=print,
                         start_in_boot=(args.flsh or args.ptt) and not args.app,
                         legacy_proto=args.legacy_proto)
    if args.app:
        radio.go_app()
        radio.backlight = True
        print("[DEV] 应用模式: 模拟正常工作界面 (写频/校准工具可直接连)")
    if args.ptt:
        radio.hold_boot(ptt=True)
    br = SerialBridge(radio, args.host, args.port, log=print)
    br.start()
    cb = None
    if args.com:
        cb = ComBridge(radio, args.com, args.baud, log=print)
        cb.start()
    print("[DEV] 4MB 固件空间: %s" % os.path.abspath(args.flash))
    print("[DEV] Ctrl-C 结束")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        if cb:
            cb.stop()
        br.stop()
        print("\n[DEV] 已停止")


if __name__ == "__main__":
    main()
