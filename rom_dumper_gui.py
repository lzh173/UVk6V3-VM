#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rom_dumper_gui.py — 串口导出整片 ROM / Flash（Tk GUI，单文件，PyInstaller 友好）

两条读取通道（**全程只读**，绝不发擦除/写入命令）：

  A. 0x051F "SPI Flash 读" —— 首选，可读满 4 MB，不用重启
     本仓库 原厂固件 固件支持：请求 {addr:4 size:2 pad:2 ts:4} → 应答 0x0520
     {addr:4 size:2 pad:2 data}，单次最多 120 字节。
     设备默认启动即可用；`python radio_device.py --app` 可跳过 0.8s 上电窗口。

  B. 刷机模式 0x31 读 —— 兼容层，可读满 4 MB，但需要设备显式开启
         python radio_device.py --flsh --legacy-proto
     注意：当前 radio_device.py 的 main() 还没把 --legacy-proto 传给
     VirtualRadio（我上一轮审查的 P1-5），所以命令行开启是无效的；
     该通道主要留给“已修好这条”的版本或其它带 0x31 的固件。
     真机原厂 stock-bl（7.02.02）没有读命令，只有 0x0516/0x0519/0x0530。

  C. 应用模式 0x051B 读 —— 兜底，读的是**逻辑 EEPROM 视图**（不是原始 ROM，
     且偏移 u16，最多 64 KB）。

端口写法：
  COM15                 真实/虚拟串口（com0com 对端口）
  tcp:127.0.0.1:8801    直接连仿真器的 socket 桥（免 com0com，调试/自测用）

命令行（无 GUI，便于脚本化与自测）：
  python rom_dumper_gui.py --port tcp:127.0.0.1:8801 --out rom.bin --size 4M
  python rom_dumper_gui.py --port COM15 --out rom.bin --mode spi
  python rom_dumper_gui.py --selftest

打包（PyInstaller）：
  pyinstaller -F -w -n RomDumper rom_dumper_gui.py
  或直接双击 build.bat
"""

import os
import sys
import re
import json
import time
import zlib
import queue
import struct
import socket
import hashlib
import threading
import traceback

# ---------------------------------------------------------------- 协议常量
OBFUSCATION = bytes([0x16, 0x6C, 0x14, 0xE6, 0x2E, 0x91, 0x0D, 0x40,
                     0x21, 0x35, 0xD5, 0x40, 0x13, 0x03, 0xE9, 0x80])
SYNC = b"\xAB\xCD"
FOOTER = b"\xDC\xBA"
MAX_FRAME = 2040            # 真机 UART 缓冲上限（size+8 <= 2048）
APP_READ_MAX = 0x10000      # 0x051B 的偏移是 u16
APP_CHUNK_MAX = 128         # 真机 REPLY_051B_t.Data[128]
SPI_CHUNK = 120             # 0x051F 设备侧硬上限（size > 120 会被截断）
FLASH_4M = 0x400000


def _utf8_stdio():
    """Windows 控制台默认不是 UTF-8，打印中文会抛 UnicodeEncodeError。
    这里把 stdout/stderr 强制成 UTF-8（打包成 exe 后同样有效）。"""
    import sys
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


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


# ---------------------------------------------------------------- 异常
class DumperError(Exception):
    pass


class LinkTimeout(DumperError):
    pass


class Cancelled(DumperError):
    pass


# ---------------------------------------------------------------- 字节链
class Link:
    """串口 / TCP 统一入口：只做收发 + 缓冲，不含协议语义。"""

    def __init__(self, port, baud=115200, log=None, stop=None):
        self.port = port
        self.baud = baud
        self.log = log or (lambda lv, m: None)
        self.stop = stop or (lambda: False)
        self.buf = bytearray()
        self._ser = None
        self._sock = None
        self.kind = "serial"
        self._open()

    def _open(self):
        p = self.port.strip()
        if p.lower().startswith("tcp:"):
            hostport = p[4:].strip()
            host, _, ps = hostport.rpartition(":")
            if not host:
                host, ps = "127.0.0.1", hostport
            try:
                s = socket.create_connection((host, int(ps)), timeout=3.0)
            except OSError as e:
                raise DumperError("连不上 %s：%s" % (p, e))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(0.05)
            self._sock = s
            self.kind = "tcp"
        else:
            try:
                import serial
            except ImportError:
                raise DumperError("缺少 pyserial：请先 pip install pyserial")
            try:
                self._ser = serial.Serial(p, self.baud, timeout=0.05, write_timeout=1.0)
            except Exception as e:
                raise DumperError("打开 %s 失败：%s" % (p, e))
            try:
                self._ser.reset_input_buffer()
                self._ser.reset_output_buffer()
            except Exception:
                pass

    # -- 基本收发 ------------------------------------------------
    def write(self, data):
        if self.stop():
            raise Cancelled("已取消")
        try:
            if self._ser is not None:
                self._ser.write(data)
            else:
                self._sock.sendall(data)
        except Exception as e:
            raise DumperError("写失败：%s" % e)

    def _read_once(self, n, wait):
        if self._ser is not None:
            self._ser.timeout = max(0.01, min(0.05, wait))
            return self._ser.read(n) or b""
        self._sock.settimeout(max(0.01, min(0.05, wait)))
        try:
            return self._sock.recv(n) or b""
        except socket.timeout:
            return b""

    def need(self, n, timeout, what="数据"):
        """确保缓冲里至少有 n 字节；超时抛 LinkTimeout。"""
        end = time.monotonic() + timeout
        while len(self.buf) < n:
            if self.stop():
                raise Cancelled("已取消")
            left = end - time.monotonic()
            if left <= 0:
                raise LinkTimeout("等%s超时（需要 %d B，只有 %d B）" % (what, n, len(self.buf)))
            d = self._read_once(n - len(self.buf), left)
            if d:
                self.buf.extend(d)
        return True

    def drain(self, duration=0.2):
        """丢弃一段时间内收到的所有字节（用于切换模式后清尾巴）。"""
        end = time.monotonic() + duration
        n = 0
        while time.monotonic() < end:
            if self.stop():
                raise Cancelled("已取消")
            d = self._read_once(256, 0.03)
            if d:
                n += len(d)
        self.buf.clear()
        return n

    def close(self):
        try:
            if self._ser is not None:
                self._ser.close()
        except Exception:
            pass
        try:
            if self._sock is not None:
                self._sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------- 协议层
class Proto:
    def __init__(self, link, log=None, stop=None):
        self.link = link
        self.log = log or (lambda lv, m: None)
        self.stop = stop or (lambda: False)
        self.ts = 0
        self.junk = 0
        self.skipped_frames = 0

    @staticmethod
    def _left(end):
        v = end - time.monotonic()
        if v <= 0:
            raise LinkTimeout("超时")
        return v

    # ---- 帧编解码（请求含 CRC，应答不含 CRC —— 与真机一致）----
    def send_frame(self, payload):
        plain = payload + struct.pack("<H", crc16(payload))
        frame = SYNC + struct.pack("<H", len(payload)) + xor_obf(plain, len(plain)) + FOOTER
        self.link.write(frame)

    def _drop_frame_if_ready(self):
        """缓冲头部若是完整 AB CD 帧就吃掉并记日志；返回 True=已处理。"""
        b = self.link.buf
        if len(b) < 2 or b[0] != 0xAB or b[1] != 0xCD:
            return False
        if len(b) < 4:
            return False
        size = b[2] | (b[3] << 8)
        if not (4 <= size <= MAX_FRAME):
            del b[:1]                      # 假同步头
            return True
        if len(b) < size + 8:
            return False
        frame = bytes(b[:size + 8])
        if frame[-2:] != FOOTER:
            del b[:1]
            return True
        payload = xor_obf(frame[4:4 + size], size)
        del b[:size + 8]
        self.skipped_frames += 1
        cmd = struct.unpack_from("<H", payload, 0)[0] if len(payload) >= 2 else -1
        if self.skipped_frames <= 3:
            self.log("INFO", "跳过设备推送帧 0x%04X（%d B）" % (cmd, len(payload)))
        return True

    def _advance(self, end):
        """
        吃掉一点输入让状态前进：完整帧 / 半截帧等齐 / 一字节杂数据 / 阻塞等 1 字节。
        返回 False = 到 end 还没有任何进展（超时）。
        注意：绝不用于“目标字节是当前缓冲前缀”的场合，那种情况由 _expect_bytes 先判。
        """
        b = self.link.buf
        if self._drop_frame_if_ready():
            return True
        if len(b) >= 2 and b[0] == 0xAB and b[1] == 0xCD:
            try:                                     # 半截帧：等它到齐再整帧丢掉
                self.link.need(4, self._left(end), "帧头")
                size = b[2] | (b[3] << 8)
                if 4 <= size <= MAX_FRAME:
                    self.link.need(size + 8, self._left(end), "整帧")
                    return True
            except LinkTimeout:
                return False
            del b[:1]
            return True
        if b:
            del b[:1]
            self.junk += 1
            if self.junk > 8192:
                raise DumperError("串口数据无法识别（端口/波特率不对，或设备不在该模式）")
            return True
        try:
            self.link.need(1, self._left(end), "应答")
            return True
        except LinkTimeout:
            return False

    def _expect_bytes(self, want, timeout):
        """等一段固定 ASCII（如 FLSH），途中跳过 AB CD 帧与杂字节；匹配则消费并返回 True。"""
        end = time.monotonic() + timeout
        while True:
            b = self.link.buf
            if b[:len(want)] == want:
                del b[:len(want)]
                return True
            if b and len(b) < len(want) and want.startswith(bytes(b)):
                # 当前缓冲正好是目标前缀（TCP 可能拆包），继续等，别丢字节
                try:
                    self.link.need(len(b) + 1, self._left(end), "应答")
                except LinkTimeout:
                    return False
                continue
            if not self._advance(end):
                return False

    def recv_frame(self, timeout=1.0):
        """收一个 AB CD 应答帧，返回 payload；超时抛 LinkTimeout。"""
        end = time.monotonic() + timeout
        while True:
            b = self.link.buf
            i = b.find(SYNC)
            if i < 0:
                keep = 1 if (b and b[-1] == 0xAB) else 0
                if len(b) - keep > 0:
                    del b[:len(b) - keep]
                self.link.need(2, self._left(end), "同步头")
                continue
            if i:
                del b[:i]
            self.link.need(4, self._left(end), "帧头")
            size = b[2] | (b[3] << 8)
            if not (4 <= size <= MAX_FRAME):
                del b[:2]
                continue
            self.link.need(size + 8, self._left(end), "整帧")
            frame = bytes(b[:size + 8])
            if frame[-2:] != FOOTER:
                del b[:2]
                continue
            del b[:size + 8]
            return xor_obf(frame[4:4 + size], size)

    def recv_cmd(self, want, timeout=2.0):
        """收帧直到命令字匹配 want（0x0518 之类的周期推送直接跳过）。"""
        end = time.monotonic() + timeout
        skipped = 0
        while True:
            f = self.recv_frame(self._left(end))
            cmd = struct.unpack_from("<H", f, 0)[0] if len(f) >= 2 else -1
            if cmd == want:
                return f
            skipped += 1
            if skipped <= 3:
                self.log("INFO", "跳过非目标应答帧 0x%04X（在等 0x%04X）" % (cmd, want))
            self.skipped_frames += 1

    # ---- A. 刷机模式：裸字节命令（FLSH / 0x30 / 0x31 / 0x34）----
    def _raw_reply(self, want, timeout, fixed=None):
        """
        等一条裸应答：<want>[<len16><data>] 或 <want><fixed 字节>。
        途中若遇到设备推送的 AB CD 帧（boot 模式约 0.5s 一帧 0x0518）就跳过，
        否则那几十字节会混进 ROM 数据里。
        """
        end = time.monotonic() + timeout
        while True:
            b = self.link.buf
            if b[:1] == bytes([want]):
                if fixed is not None:
                    if len(b) < 1 + fixed:
                        self.link.need(1 + fixed, self._left(end), "应答")
                        continue
                    data = bytes(b[1:1 + fixed])
                    del b[:1 + fixed]
                    return data
                if len(b) < 3:
                    self.link.need(3, self._left(end), "应答头")
                    continue
                n = b[1] | (b[2] << 8)
                if len(b) < 3 + n:
                    self.link.need(3 + n, self._left(end), "应答体")
                    continue
                data = bytes(b[3:3 + n])
                del b[:3 + n]
                return data
            if not self._advance(end):
                raise LinkTimeout("等 0x%02X 应答超时（%d 字节已到）" % (want, len(b)))

    def flsh(self, tries=3, per_try=0.5):
        """进刷机模式：发 ASCII 'FLSH'，等回 'FLSH'。"""
        for k in range(tries):
            if self.stop():
                raise Cancelled("已取消")
            self.link.drain(0.05)
            self.link.write(b"FLSH")
            if self._expect_bytes(b"FLSH", per_try):
                self.log("INFO", "FLSH 握手成功（第 %d 次尝试）" % (k + 1))
                return True
        return False

    def info(self):
        """0x30 → (页大小, 总 MB)"""
        self.link.write(b"\x30")
        d = self._raw_reply(0x30, 1.5, fixed=8)
        page, mb = struct.unpack("<II", d)
        return page, mb

    def read_legacy(self, addr, n, timeout=4.0):
        """0x31 [addr:4][len:2] → data（长度以设备回的为准，可能短于 n）"""
        self.link.write(b"\x31" + struct.pack("<IH", addr, n))
        return self._raw_reply(0x31, timeout)

    def exit_boot(self):
        try:
            self.link.drain(0.05)
            self.link.write(b"\x34")
            self._raw_reply(0x34, 0.8, fixed=0)
        except DumperError:
            pass

    # ---- B. 应用模式：0x0514 握手 + 0x051B 读 ----
    def app_handshake(self, timeout=1.0):
        self.ts = int(time.time()) & 0x7FFFFFFF
        body = struct.pack("<I", self.ts)
        self.send_frame(struct.pack("<HH", 0x0514, len(body)) + body)
        end = time.monotonic() + timeout
        while True:
            if time.monotonic() >= end:
                return None
            try:
                f = self.recv_frame(self._left(end))
            except LinkTimeout:
                return None
            if len(f) >= 4 and struct.unpack_from("<H", f, 0)[0] == 0x0515:
                ver = f[4:20].split(b"\x00")[0].decode("latin1", "replace")
                return ver

    def app_read(self, off, n, timeout=2.0):
        """0x051B 逻辑 EEPROM 读（不是原始 ROM），偏移 u16，单次 ≤128。"""
        n = min(n, APP_CHUNK_MAX, max(0, APP_READ_MAX - off))
        body = struct.pack("<HBB", off, n, 0) + struct.pack("<I", self.ts)
        self.send_frame(struct.pack("<HH", 0x051B, len(body)) + body)
        f = self.recv_cmd(0x051C, timeout)
        if len(f) < 8:
            raise DumperError("0x051C 应答过短（%d B）" % len(f))
        o, sz, _pad = struct.unpack_from("<HBB", f, 4)
        if sz > APP_CHUNK_MAX:
            raise DumperError("0x051C 声明长度异常：%d" % sz)
        return f[8:8 + sz]

    def spi_request(self, addr, n):
        """只发 0x051F 请求（批量预读用，不等应答）"""
        n = min(n, SPI_CHUNK)
        body = struct.pack("<IHHI", addr & 0xFFFFFFFF, n, 0, self.ts)
        self.send_frame(struct.pack("<HH", 0x051F, len(body)) + body)

    def spi_parse(self, addr, f):
        """校验并拆 0x0520 应答"""
        if len(f) < 12:
            raise DumperError("0x0520 应答过短（%d B）" % len(f))
        a, sz, _pad = struct.unpack_from("<IHH", f, 4)
        if a != (addr & 0xFFFFFFFF):
            raise DumperError("0x0520 地址回显不符：要 0x%06X 回 0x%06X" % (addr, a))
        if sz > SPI_CHUNK:
            raise DumperError("0x0520 声明长度异常：%d" % sz)
        data = f[12:12 + sz]
        if len(data) != sz:
            raise DumperError("0x0520 数据不足：声明 %d 实到 %d" % (sz, len(data)))
        return data

    def spi_read(self, addr, n, timeout=2.0):
        """0x051F SPI Flash 原始读 {addr:4 size:2 pad:2 ts:4} → 0x0520 {addr,size,pad,data}"""
        self.spi_request(addr, n)
        return self.spi_parse(addr, self.recv_cmd(0x0520, timeout))

    def spi_probe(self, timeout=1.5):
        """探一下设备有没有 0x051F（老固件/uv-k5 原厂 app 没有）"""
        try:
            self.spi_read(0, 16, timeout)
            return True
        except DumperError as e:
            self.log("INFO", "0x051F 探测失败：%s" % e)
            return False

    def reboot_to_bootloader(self):
        try:
            self.send_frame(struct.pack("<HH", 0x05DD, 4) + struct.pack("<I", self.ts))
        except DumperError:
            pass


# ---------------------------------------------------------------- 导出任务
def parse_size(text):
    s = str(text).strip().upper().replace(" ", "")
    if not s:
        raise ValueError("大小为空")
    mult = 1
    if s.endswith("K"):
        mult, s = 1024, s[:-1]
    elif s.endswith("M"):
        mult, s = 1024 * 1024, s[:-1]
    elif s.endswith("G"):
        mult, s = 1024 * 1024 * 1024, s[:-1]
    try:
        v = int(s, 0)
    except ValueError:
        raise ValueError("看不懂的大小：%r（可写 4M / 0x400000 / 4194304）" % text)
    v *= mult
    if v <= 0:
        raise ValueError("大小必须 > 0")
    return v


def parse_addr(text):
    s = str(text).strip()
    if not s:
        return 0
    return int(s, 0)


def human(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return ("%.0f%s" % (n, u)) if u == "B" else ("%.2f%s" % (n, u))
        n /= 1024.0


def run_dump(opts, log, prog, stop):
    """
    opts: dict(port, baud, mode[auto|legacy|app], size, start, chunk, verify, info)
    返回 result dict；失败抛 DumperError / Cancelled。
    """
    t_start = time.time()
    link = Link(opts["port"], opts["baud"], log, stop)
    proto = Proto(link, log, stop)
    csum = hashlib.sha256()
    try:
        total = opts["size"]
        start = opts["start"]
        if total <= 0:
            raise DumperError("导出大小必须 > 0")

        mode = opts["mode"]
        protocol = None
        page = mb = 0

        # ---------- 自动识别 ----------
        # ---------- 选协议 ----------
        if mode == "legacy":
            link.drain(0.25)
            if not proto.flsh(tries=5):
                raise DumperError(
                    "FLSH 无响应：这条通道需要设备开启兼容层（FLSH / 0x30-0x34）。\n"
                    "  仿真器：python radio_device.py --flsh --legacy-proto\n"
                    "  注意：当前 radio_device.py 的 main() 还没把 --legacy-proto 传给\n"
                    "  VirtualRadio，所以命令行开启是无效的 —— 本仓库请直接用默认的\n"
                    "  0x051F 模式（就是本工具的“自动”）。")
            protocol = "legacy"
        else:
            link.drain(0.25)                       # 清掉上电横幅/杂字节
            ver = None
            for _ in range(5):                     # 跨过仿真器 0.8s 上电窗口
                ver = proto.app_handshake(1.0)
                if ver is not None:
                    break
            if ver is None:
                if mode == "auto" and proto.flsh(tries=3):
                    protocol = "legacy"
                else:
                    raise DumperError(
                        "设备无响应（既没有 0x0515 握手，也不认 FLSH）：\n"
                        "  · 仿真器：python radio_device.py --app（或直接默认启动）\n"
                        "  · 确认端口/波特率；com0com 要把对端口里的另一只给本工具\n"
                        "  · 真机原厂 BL 没有读命令，只能进应用模式")
            else:
                log("INFO", "应用模式固件：%s" % (ver or "?"))
                if mode != "eeprom" and proto.spi_probe():
                    protocol = "spi"
                    log("INFO", "设备支持 0x051F SPI Flash 读 → 可整片导出（不用重启）")
                elif mode == "spi":
                    raise DumperError("设备不支持 0x051F（固件较老，或不是这台机器的固件）")
                else:
                    protocol = "eeprom"
                    log("WARN", "只能用 0x051B：读的是逻辑 EEPROM 视图，不是原始 ROM，"
                                "且最多 64 KB")

        # ---------- 依据协议裁剪范围 ----------
        if protocol == "legacy":
            try:
                page, mb = proto.info()
                log("INFO", "设备信息：页 %d B，空间 %d MB" % (page, mb))
                dev_max = mb * 1024 * 1024
                if dev_max and start + total > dev_max:
                    log("WARN", "请求范围超出设备容量，截到 %s" % human(dev_max))
                    total = max(0, dev_max - start)
            except DumperError as e:
                log("WARN", "读设备信息失败（继续按请求范围导出）：%s" % e)
            chunk = opts["chunk"]
        elif protocol == "spi":
            chunk = SPI_CHUNK
            if start + total > FLASH_4M:
                log("WARN", "请求范围超出 4 MB，已截到 0x400000")
                total = max(0, FLASH_4M - start)
        else:
            chunk = APP_CHUNK_MAX
            if total > APP_READ_MAX:
                log("WARN", "0x051B 最多 64 KB，已截断（整片请用 0x051F）")
                total = APP_READ_MAX

        if total <= 0:
            raise DumperError("可读范围为空（start 超出设备容量？）")

        # ---------- 分块读取 ----------
        # 0x051F 支持“先发一批再收一批”，用来摊薄设备桥接线程 ~15ms/轮 的延迟：
        # 窗口=16 时 4MB 从约 9 分钟降到几十秒。
        window = 1
        if protocol == "spi":
            w = int(opts.get("window") or 0)
            if w <= 0:                      # 自动：TCP 走 64，真串口走 8（UART 缓冲小）
                w = 64 if link.kind == "tcp" else 8
            window = max(1, min(128, w))

        def read_batch(batch):
            """按顺序读一批 [(addr, n)]，返回 [bytes]；失败抛异常（调用方负责降级/重试）"""
            if protocol == "spi" and len(batch) > 1:
                for a, n in batch:
                    proto.spi_request(a, n)
                return [proto.spi_parse(a, proto.recv_cmd(0x0520, 3.0)) for a, n in batch]
            out = []
            for a, n in batch:
                if protocol == "legacy":
                    out.append(proto.read_legacy(a, n))
                elif protocol == "spi":
                    out.append(proto.spi_read(a, n))
                else:
                    out.append(proto.app_read(a, n))
            return out

        def make_batch(done):
            batch = []
            off = done
            while len(batch) < window and off < total:
                n = min(chunk, total - off)
                batch.append((start + off, n))
                off += n
            return batch

        # ---------- 开文件 ----------
        out = opts["out"]
        os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
        log("INFO", "开始导出 %s → %s（%s / 块 %d B%s）"
            % (human(total), out, protocol, chunk,
               ("，预读 %d" % window) if window > 1 else ""))

        gaps = []
        done = 0
        last_emit = 0.0
        t0 = time.monotonic()
        with open(out, "wb") as fp:
            while done < total:
                if stop():
                    raise Cancelled("已取消")
                batch = make_batch(done)
                datas, err = None, None
                try:
                    datas = read_batch(batch)
                except (LinkTimeout, DumperError) as e:
                    err = e
                if datas is None:
                    if window > 1:
                        log("WARN", "批量预读失败（%s），降级为逐块" % err)
                        link.drain(0.10)
                        window = 1
                        continue
                    batch = batch[:1]
                    data = b""
                    for attempt in range(3):
                        if stop():
                            raise Cancelled("已取消")
                        try:
                            data = read_batch(batch)[0]
                            err = None
                            break
                        except (LinkTimeout, DumperError) as e2:
                            err = e2
                            link.drain(0.06)      # 丢掉半截应答，重新对齐再试
                            time.sleep(0.05 * (attempt + 1))
                    if err is not None:
                        if done == 0:
                            raise DumperError("第一块就读失败，设备协议不通：%s" % err)
                        log("ERR", "0x%06X +%d 读失败（%s），填 0xFF"
                            % (batch[0][0], batch[0][1], err))
                        data = b""
                    datas = [data]
                for (addr, n), data in zip(batch, datas):
                    if len(data) < n:
                        if data:
                            gaps.append((addr, n, len(data)))
                            log("WARN", "0x%06X 短读：要 %d 只有 %d" % (addr, n, len(data)))
                        data = data + b"\xFF" * (n - len(data))
                    elif len(data) > n:
                        data = data[:n]
                    fp.write(data)
                    csum.update(data)
                    done += n
                now = time.monotonic()
                if now - last_emit > 0.08 or done >= total:
                    last_emit = now
                    elapsed = max(1e-6, now - t0)
                    bps = done / elapsed
                    eta = (total - done) / bps if bps > 0 else 0
                    prog(done, total, bps, eta)
                if done % (chunk * 32) == 0:
                    fp.flush()

        dt = time.time() - t_start
        digest = csum.hexdigest()
        crc = 0
        with open(out, "rb") as fp:
            while True:
                blk = fp.read(1 << 20)
                if not blk:
                    break
                crc = zlib.crc32(blk, crc)

        # ---------- 可选：读第二遍校验 ----------
        verified = None
        if opts.get("verify"):
            log("INFO", "第二遍回读校验中…")
            bad = 0
            with open(out, "rb") as fp:
                done2 = 0
                while done2 < total:
                    if stop():
                        raise Cancelled("已取消")
                    batch = make_batch(done2)
                    try:
                        datas = read_batch(batch)
                    except (LinkTimeout, DumperError) as e:
                        log("ERR", "校验批量读失败（%s），改逐块" % e)
                        link.drain(0.1)
                        datas = []
                        for a, n in batch:
                            try:
                                datas.append(read_batch([(a, n)])[0])
                            except DumperError as e2:
                                log("ERR", "校验 0x%06X 读失败：%s" % (a, e2))
                                datas.append(None)
                    for (a, n), d2 in zip(batch, datas):
                        ref = fp.read(n)
                        if d2 is None:
                            bad += n
                        else:
                            if len(d2) < n:
                                d2 = d2 + b"\xFF" * (n - len(d2))
                            if d2[:n] != ref:
                                bad += n
                                log("ERR", "校验不一致 @0x%06X" % a)
                        done2 += n
                    prog(done2, total, done2 / max(1e-6, time.monotonic() - t0), 0)
            verified = (bad == 0)
            log("INFO" if verified else "ERR",
                "回读校验：%s" % ("全部一致" if verified else "有 %d 字节不一致" % bad))

        if protocol == "legacy":
            proto.exit_boot()

        # ---------- 0xFF 占比 / 空片提示 ----------
        blank = 0
        with open(out, "rb") as fp:
            while True:
                blk = fp.read(1 << 20)
                if not blk:
                    break
                blank += blk.count(0xFF)
        if blank == total:
            log("WARN", "整片都是 0xFF —— 设备没返回数据（空片 / 协议不对）")

        res = dict(ok=True, out=out, size=total, start=start, protocol=protocol,
                   sha256=digest, crc32=crc & 0xFFFFFFFF, gaps=gaps, verified=verified,
                   blank_ratio=(blank / float(total) if total else 0.0),
                   elapsed=dt, page=page, mb=mb)
        if opts.get("info", True):
            try:
                with open(out + ".info.txt", "w", encoding="utf-8") as fp:
                    fp.write("串口 ROM 导出记录\n")
                    fp.write("时间      : %s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
                    fp.write("端口/波特 : %s @ %s\n" % (opts["port"], opts["baud"]))
                    fp.write("协议      : %s\n" % protocol)
                    fp.write("起始/大小 : 0x%06X / %d B (%s)\n" % (start, total, human(total)))
                    fp.write("SHA256    : %s\n" % digest)
                    fp.write("CRC32     : %08X\n" % (crc & 0xFFFFFFFF))
                    fp.write("0xFF 占比 : %.1f%%\n" % (100.0 * blank / fixed_div(total)))
                    fp.write("耗时      : %.1fs\n" % dt)
                    fp.write("缺口      : %s\n" % (gaps if gaps else "无"))
                log("INFO", "已写 %s.info.txt" % os.path.basename(out))
            except OSError as e:
                log("WARN", "写 info.txt 失败：%s" % e)
        return res
    finally:
        try:
            link.close()
        except Exception:
            pass


def fixed_div(x):
    return x if x else 1


# ---------------------------------------------------------------- GUI
def default_out_dir():
    base = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) \
        else os.path.dirname(os.path.abspath(__file__))
    try:
        t = os.path.join(base, ".write_test")
        with open(t, "wb") as f:
            f.write(b"x")
        os.remove(t)
        return base
    except OSError:
        d = os.path.join(os.path.expanduser("~"), "Documents")
        return d if os.path.isdir(d) else os.path.expanduser("~")


def cfg_file():
    base = os.getenv("APPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "RomDumper")
    try:
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, "config.json")
    except OSError:
        return os.path.join(os.path.expanduser("~"), ".romdumper.json")


def load_cfg():
    try:
        with open(cfg_file(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_cfg(d):
    try:
        with open(cfg_file(), "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


def list_ports():
    try:
        from serial.tools import list_ports as lp
        return [(p.device, p.description or "") for p in lp.comports()]
    except Exception:
        return []


def _natkey(s):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", s)]


class App:
    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox
        self.tk, self.ttk = tk, ttk
        self.filedialog, self.messagebox = filedialog, messagebox
        self.root = root
        root.title("串口 ROM 导出工具  v1.0")
        root.geometry("960x660")
        root.minsize(900, 600)
        self.q = queue.Queue()
        self.worker = None
        self.stop_ev = threading.Event()
        self.cfg = load_cfg()
        self._build()
        self.refresh_ports(initial=True)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(60, self._pump)

    # ---------- 界面 ----------
    def _build(self):
        tk, ttk = self.tk, self.ttk
        pad = dict(padx=6, pady=3)

        frm = ttk.LabelFrame(self.root, text="① 连接")
        frm.pack(fill="x", padx=10, pady=(10, 4))

        ttk.Label(frm, text="端口").grid(row=0, column=0, sticky="w", **pad)
        self.cb_port = ttk.Combobox(frm, width=26)
        self.cb_port.grid(row=0, column=1, sticky="w", **pad)
        ttk.Button(frm, text="刷新", width=6, command=self.refresh_ports).grid(row=0, column=2, **pad)
        ttk.Label(frm, text="波特率").grid(row=0, column=3, sticky="w", **pad)
        self.cb_baud = ttk.Combobox(frm, width=10, state="readonly",
                                    values=["9600", "19200", "38400", "57600", "115200",
                                            "230400", "460800", "921600"])
        self.cb_baud.set(str(self.cfg.get("baud", 115200)))
        self.cb_baud.grid(row=0, column=4, sticky="w", **pad)
        ttk.Label(frm, text="（也可直接填 tcp:127.0.0.1:8801）",
                  foreground="#666").grid(row=1, column=1, columnspan=4, sticky="w", padx=6)

        frm2 = ttk.LabelFrame(self.root, text="② 读取方式")
        frm2.pack(fill="x", padx=10, pady=4)
        mode0 = self.cfg.get("mode", "auto")
        if mode0 not in ("auto", "spi", "legacy", "eeprom"):
            mode0 = "auto"
        self.var_mode = tk.StringVar(value=mode0)
        for i, (val, txt) in enumerate([
                ("auto", "自动（0x051F 整片 4 MB ▸ 0x31 整片 ▸ 0x051B 仅 64 KB）"),
                ("spi", "0x051F SPI Flash 读（整片 4 MB，不用重启，推荐）"),
                ("legacy", "刷机模式 0x31（需设备 --legacy-proto）"),
                ("eeprom", "0x051B 逻辑 EEPROM（≤64 KB，不是原始 ROM）")]):
            ttk.Radiobutton(frm2, text=txt, value=val, variable=self.var_mode)\
                .grid(row=i, column=0, sticky="w", padx=6, pady=1)

        frm3 = ttk.LabelFrame(self.root, text="③ 范围与输出")
        frm3.pack(fill="x", padx=10, pady=4)
        ttk.Label(frm3, text="起始").grid(row=0, column=0, sticky="w", **pad)
        self.e_start = ttk.Entry(frm3, width=12)
        self.e_start.insert(0, self.cfg.get("start", "0x000000"))
        self.e_start.grid(row=0, column=1, sticky="w", **pad)

        ttk.Label(frm3, text="大小").grid(row=0, column=2, sticky="w", **pad)
        self.cb_size = ttk.Combobox(frm3, width=10,
                                    values=["4M", "2M", "1M", "64K", "0x400000"])
        self.cb_size.set(self.cfg.get("size", "4M"))
        self.cb_size.grid(row=0, column=3, sticky="w", **pad)

        ttk.Label(frm3, text="块大小").grid(row=0, column=4, sticky="w", **pad)
        self.cb_chunk = ttk.Combobox(frm3, width=8, state="readonly",
                                     values=["1024", "4096", "8192", "16384", "32768"])
        self.cb_chunk.set(str(self.cfg.get("chunk", 8192)))
        self.cb_chunk.grid(row=0, column=5, sticky="w", **pad)

        ttk.Label(frm3, text="预读").grid(row=0, column=6, sticky="w", **pad)
        self.cb_win = ttk.Combobox(frm3, width=6, state="readonly",
                                   values=["自动", "1", "4", "8", "16", "32", "64", "128"])
        self.cb_win.set(str(self.cfg.get("window", "自动")))
        self.cb_win.grid(row=0, column=7, sticky="w", **pad)

        ttk.Label(frm3, text="保存到").grid(row=1, column=0, sticky="w", **pad)
        self.e_out = ttk.Entry(frm3, width=72)
        out0 = self.cfg.get("outdir") or default_out_dir()
        self.e_out.insert(0, os.path.join(out0, "rom_%s.bin" % time.strftime("%Y%m%d_%H%M%S")))
        self.e_out.grid(row=1, column=1, columnspan=7, sticky="we", **pad)
        ttk.Button(frm3, text="浏览…", width=8, command=self.pick_out).grid(row=1, column=8, **pad)
        frm3.columnconfigure(1, weight=1)

        frm4 = ttk.Frame(frm3)
        frm4.grid(row=2, column=0, columnspan=9, sticky="w", padx=4)
        self.var_verify = tk.BooleanVar(value=bool(self.cfg.get("verify", False)))
        self.var_info = tk.BooleanVar(value=bool(self.cfg.get("info", True)))
        ttk.Checkbutton(frm4, text="读两遍校验（慢一倍）", variable=self.var_verify)\
            .pack(side="left", padx=4)
        ttk.Checkbutton(frm4, text="写 .info.txt", variable=self.var_info)\
            .pack(side="left", padx=8)

        bar = ttk.Frame(self.root)
        bar.pack(fill="x", padx=10, pady=6)
        self.btn_start = ttk.Button(bar, text="开始导出", width=14, command=self.on_start)
        self.btn_start.pack(side="left")
        self.btn_stop = ttk.Button(bar, text="取消", width=8, state="disabled", command=self.on_stop)
        self.btn_stop.pack(side="left", padx=6)
        ttk.Button(bar, text="打开所在文件夹", width=14, command=self.open_dir)\
            .pack(side="left", padx=6)
        ttk.Button(bar, text="清空日志", width=10, command=self.clear_log)\
            .pack(side="left")

        self.pb = ttk.Progressbar(self.root, mode="determinate", maximum=1000)
        self.pb.pack(fill="x", padx=10)
        self.lb_status = ttk.Label(self.root, text="就绪", foreground="#0a0")
        self.lb_status.pack(fill="x", padx=10, pady=2)

        box = ttk.Frame(self.root)
        box.pack(fill="both", expand=True, padx=10, pady=(2, 10))
        self.txt = tk.Text(box, height=15, wrap="none", state="disabled",
                           font=("Consolas", 9))
        sb = ttk.Scrollbar(box, orient="vertical", command=self.txt.yview)
        self.txt.configure(yscrollcommand=sb.set)
        self.txt.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.txt.tag_config("ERR", foreground="#c00")
        self.txt.tag_config("WARN", foreground="#b60")
        self.txt.tag_config("OK", foreground="#070")
        self.txt.tag_config("INFO", foreground="#222")

    # ---------- 小工具 ----------
    def log(self, lv, msg):
        self.q.put(("log", lv, msg))

    def _append(self, lv, msg):
        self.txt.configure(state="normal")
        self.txt.insert("end", "[%s] %s\n" % (lv, msg), (lv,))
        self.txt.see("end")
        self.txt.configure(state="disabled")

    def clear_log(self):
        self.txt.configure(state="normal")
        self.txt.delete("1.0", "end")
        self.txt.configure(state="disabled")

    def refresh_ports(self, initial=False):
        ports = list_ports()
        vals = [p for p, _ in ports]
        self._port_desc = dict(ports)
        cur = self.cb_port.get() or self.cfg.get("port", "")
        self.cb_port["values"] = vals + ([] if vals else [])
        if cur and (cur in vals or cur.lower().startswith("tcp:")):
            self.cb_port.set(cur)
        elif vals:
            prefer = [v for v in vals if any(k in (self._port_desc.get(v, "") + v).lower()
                                             for k in ("com0com", "usb", "serial", "uart"))]
            self.cb_port.set(sorted(prefer or vals, key=_natkey)[0])
        elif initial:
            self.cb_port.set("tcp:127.0.0.1:8801")
        if initial:
            self.log("INFO", "端口：%s" % ("、".join(vals) if vals else "没找到 COM 口（可手填 tcp:host:port）"))

    def pick_out(self):
        p = self.filedialog.asksaveasfilename(
            title="导出文件保存到", defaultextension=".bin",
            initialfile=os.path.basename(self.e_out.get() or "rom.bin"),
            initialdir=os.path.dirname(self.e_out.get()) or default_out_dir(),
            filetypes=[("二进制", "*.bin"), ("所有文件", "*.*")])
        if p:
            self.e_out.delete(0, "end")
            self.e_out.insert(0, p)

    def open_dir(self):
        p = self.e_out.get().strip()
        d = os.path.dirname(os.path.abspath(p)) if p else default_out_dir()
        try:
            if os.name == "nt":
                os.startfile(d)                       # noqa: S606
            else:
                import subprocess
                subprocess.Popen(["xdg-open", d])
        except Exception as e:
            self.messagebox.showwarning("打不开", str(e))

    # ---------- 开始 / 取消 ----------
    def on_start(self):
        if self.worker and self.worker.is_alive():
            return
        port = self.cb_port.get().strip()
        if not port:
            self.messagebox.showwarning("缺端口", "请选择串口，或填 tcp:127.0.0.1:8801")
            return
        try:
            size = parse_size(self.cb_size.get())
            start = parse_addr(self.e_start.get())
            chunk = int(self.cb_chunk.get())
        except ValueError as e:
            self.messagebox.showerror("参数错误", str(e))
            return
        out = self.e_out.get().strip()
        if not out:
            self.messagebox.showerror("缺输出", "请填写保存路径")
            return
        if os.path.exists(out):
            if not self.messagebox.askyesno("覆盖？", "%s 已存在，覆盖吗？" % out):
                return
        wtxt = str(self.cb_win.get()).strip()
        try:
            window = int(wtxt)
        except ValueError:
            window = 0                       # 自动
        opts = dict(port=port, baud=int(self.cb_baud.get() or 115200),
                    mode=self.var_mode.get(), size=size, start=start, chunk=chunk,
                    out=out, verify=self.var_verify.get(), info=self.var_info.get(),
                    window=window)
        cfg = dict(port=port, baud=opts["baud"], mode=opts["mode"], size=self.cb_size.get(),
                   start=self.e_start.get(), chunk=chunk, verify=opts["verify"],
                   info=opts["info"], window=wtxt,
                   outdir=os.path.dirname(os.path.abspath(out)))
        save_cfg(cfg)

        self.stop_ev.clear()
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.pb["value"] = 0
        self.lb_status.configure(text="连接中…", foreground="#b60")
        self.clear_log()
        self.log("INFO", "端口 %s @ %s，模式 %s，范围 0x%06X +%s"
                 % (port, opts["baud"], opts["mode"], start, human(size)))

        self.worker = threading.Thread(target=self._run, args=(opts,), daemon=True)
        self.worker.start()

    def _run(self, opts):
        try:
            res = run_dump(opts, self.log, lambda d, t, bps, eta: self.q.put(("prog", d, t, bps, eta)),
                           self.stop_ev.is_set)
            self.q.put(("done", res))
        except Cancelled:
            self.q.put(("cancel", None))
        except DumperError as e:
            self.q.put(("fail", str(e)))
        except Exception as e:                       # noqa: BLE001
            self.q.put(("fail", "%s: %s" % (type(e).__name__, e)))
            self.q.put(("log", "ERR", traceback.format_exc(limit=6)))

    def on_stop(self):
        self.stop_ev.set()
        self.lb_status.configure(text="正在停止…", foreground="#b60")
        self.btn_stop.configure(state="disabled")

    # ---------- 队列泵 ----------
    def _pump(self):
        try:
            while True:
                item = self.q.get_nowait()
                kind = item[0]
                if kind == "log":
                    self._append(item[1], item[2])
                elif kind == "prog":
                    _, d, t, bps, eta = item
                    self.pb["value"] = (d / t * 1000.0) if t else 0
                    self.lb_status.configure(
                        text="%s / %s · %s/s · 剩余 %s" %
                             (human(d), human(t), human(bps), "%ds" % int(eta) if eta else "-"),
                        foreground="#06c")
                elif kind == "done":
                    self._finish_ok(item[1])
                elif kind == "cancel":
                    self._finish_common("已取消（文件可能不完整）", "#b60")
                elif kind == "fail":
                    self._finish_common("失败：%s" % item[1], "#c00")
                    self._append("ERR", item[1])
                    self.messagebox.showerror("导出失败", item[1])
        except queue.Empty:
            pass
        self.root.after(60, self._pump)

    def _finish_common(self, text, color):
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.lb_status.configure(text=text, foreground=color)

    def _finish_ok(self, r):
        self.pb["value"] = 1000
        self._append("OK", "完成：%s（%s，%s，%.1fs）"
                     % (r["out"], human(r["size"]), r["protocol"], r["elapsed"]))
        self._append("OK", "SHA256 %s   CRC32 %08X   0xFF 占 %.1f%%"
                     % (r["sha256"], r["crc32"], r["blank_ratio"] * 100))
        if r["gaps"]:
            self._append("WARN", "有 %d 处短读，已按 0xFF 补齐" % len(r["gaps"]))
        if r["verified"] is False:
            self._append("ERR", "回读校验未通过")
        self._finish_common("完成：%s" % os.path.basename(r["out"]), "#070")
        msg = ("已导出 %s\n\nSHA256:\n%s\n\nCRC32: %08X\n协议: %s\n耗时: %.1fs"
               % (r["out"], r["sha256"], r["crc32"], r["protocol"], r["elapsed"]))
        if r["gaps"]:
            msg += "\n\n注意：%d 处短读已补 0xFF（详见日志）" % len(r["gaps"])
        if self.messagebox.askyesno("完成", msg + "\n\n打开所在文件夹？"):
            self.open_dir()

    def on_close(self):
        if self.worker and self.worker.is_alive():
            if not self.messagebox.askyesno("正在导出", "还在导出，确定退出？"):
                return
            self.stop_ev.set()
            self.worker.join(timeout=2.0)
        self.root.destroy()


# ---------------------------------------------------------------- 入口
def selftest():
    """不连硬件的最小自检：CRC / 混淆 / 帧几何。"""
    ok = True
    # CRC16-CCITT, poly 0x1021, init 0, MSB-first：标准向量
    v = crc16(b"123456789")
    print("CRC16('123456789') = 0x%04X (期望 0x31C3)" % v)
    ok &= (v == 0x31C3)
    # 混淆自反
    blob = bytes(range(64))
    ok &= (xor_obf(xor_obf(blob)) == blob)
    # 请求帧：sync + size + obf(payload+crc) + footer，总长 size+8
    p = struct.pack("<HH", 0x0514, 4) + b"\x01\x02\x03\x04"
    plain = p + struct.pack("<H", crc16(p))
    fr = SYNC + struct.pack("<H", len(p)) + xor_obf(plain) + FOOTER
    ok &= (len(fr) == len(p) + 8)
    ok &= (xor_obf(fr[4:4 + len(p) + 2])[:len(p)] == p)
    ok &= (fr[-2:] == FOOTER)
    print("帧几何 size+8 校验:", "OK" if ok else "FAIL")
    print("大小解析 4M/0x400000/64K:", parse_size("4M"), parse_size("0x400000"), parse_size("64K"))
    return ok


def _enable_dpi_awareness():
    """Windows 高分屏下让 Tk 自己按物理像素排版，否则界面会被系统拉伸变糊"""
    if os.name != "nt":
        return
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)     # Win8.1+
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()          # Vista/7
    except Exception:
        pass


def _attach_console():
    """打包成 GUI 子系统(-w)后，带命令行参数运行时挂回父控制台，才能看到输出"""
    if os.name != "nt" or not getattr(sys, "frozen", False):
        return
    try:
        import ctypes
        if ctypes.windll.kernel32.AttachConsole(0xFFFFFFFF):   # ATTACH_PARENT_PROCESS
            sys.stdout = open("CONOUT$", "w", encoding="utf-8",
                              errors="replace", buffering=1)
            sys.stderr = sys.stdout
    except Exception:
        pass


def main():
    _utf8_stdio()
    _enable_dpi_awareness()
    cli_mode = ("--selftest" in sys.argv) or ("--port" in sys.argv and "--out" in sys.argv)
    if cli_mode:
        _attach_console()
    # PyInstaller --noconsole 时 stdout/stderr 是 None，避免 print 抛异常
    if sys.stdout is None:
        try:
            sys.stdout = open(os.devnull, "w")
        except Exception:
            pass
    if sys.stderr is None:
        try:
            sys.stderr = open(os.devnull, "w")
        except Exception:
            pass
    if "--selftest" in sys.argv:
        ok = selftest()
        # 冻结成 GUI 程序时 stdout 可能为 None，用返回值表达结果
        try:
            sys.stdout.write("SELFTEST %s\n" % ("PASS" if ok else "FAIL"))
            sys.stdout.flush()
        except Exception:
            pass
        sys.exit(0 if ok else 1)

    if "--port" in sys.argv and "--out" in sys.argv:
        # 无 GUI 模式
        import argparse
        ap = argparse.ArgumentParser(description="串口 ROM 导出（无 GUI）")
        ap.add_argument("--port", required=True, help="COM15 或 tcp:127.0.0.1:8801")
        ap.add_argument("--out", required=True)
        ap.add_argument("--baud", type=int, default=115200)
        ap.add_argument("--mode", default="auto",
                        choices=["auto", "spi", "legacy", "eeprom"])
        ap.add_argument("--size", default="4M")
        ap.add_argument("--start", default="0")
        ap.add_argument("--chunk", type=int, default=8192)
        ap.add_argument("--window", type=int, default=0,
                        help="0x051F 批量预读窗口，0=自动")
        ap.add_argument("--verify", action="store_true")
        a = ap.parse_args()
        try:
            res = run_dump(dict(port=a.port, baud=a.baud, mode=a.mode,
                                size=parse_size(a.size), start=parse_addr(a.start),
                                chunk=a.chunk, out=a.out, verify=a.verify, info=True,
                                window=a.window),
                           log=lambda lv, m: print("[%s] %s" % (lv, m), flush=True),
                           prog=lambda d, t, bps, eta: None,
                           stop=lambda: False)
            print("OK %s %d B sha256=%s" % (res["out"], res["size"], res["sha256"]))
            return 0
        except DumperError as e:
            print("FAIL %s" % e)
            return 2
        except KeyboardInterrupt:
            return 130

    import tkinter as tk
    root = tk.Tk()
    try:
        root.call("tk", "scaling", 1.15)
    except Exception:
        pass
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    try:
        import multiprocessing
        multiprocessing.freeze_support()          # PyInstaller onefile 必需
    except Exception:
        pass
    sys.exit(main() or 0)
