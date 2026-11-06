#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
k5tool.py — 虚拟电台的 PC 端工具（写频 + 刷机）

用法
----
  python k5tool.py selftest                      # 自带设备端跑完整流程（无需另开进程）
  python k5tool.py -p 8801 info                  # 握手 + 版本
  python k5tool.py -p 8801 read 0x0000 256       # 读 EEPROM
  python k5tool.py -p 8801 write-channels ch.bin  # 写信道区
  python k5tool.py -p 8801 flash firmware.bin    # 重启进 bootloader 并刷写
  python k5tool.py -p 8801 dump out.bin          # 读回整个 4MB
"""

import argparse
import os
import socket
import struct
import sys
import threading
import time

# 与 radio_device.py 保持一致
OBFUSCATION = bytes([0x16, 0x6C, 0x14, 0xE6, 0x2E, 0x91, 0x0D, 0x40,
                     0x21, 0x35, 0xD5, 0x40, 0x13, 0x03, 0xE9, 0x80])
SYNC = b"\xAB\xCD"
FOOTER = b"\xDC\xBA"


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


class Radio:
    def __init__(self, host="127.0.0.1", port=8801, timeout=2.0, com=None, baud=115200):
        self.ser = None
        if com:
            import serial
            self.ser = serial.Serial(com, baud, timeout=timeout)
            self.s = None
        else:
            self.s = socket.create_connection((host, port), timeout=timeout)
            self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.s.settimeout(timeout)
        self.timestamp = 0

    def close(self):
        for o in (self.s, self.ser):
            try:
                if o is not None:
                    o.close()
            except Exception:
                pass

    # ---------- 低层 ----------
    def _write(self, data):
        if self.ser is not None:
            self.ser.write(data)
            self.ser.flush()
        else:
            self.s.sendall(data)

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            if self.ser is not None:
                d = self.ser.read(n - len(buf))
            else:
                d = self.s.recv(n - len(buf))
            if not d:
                raise IOError("连接断开/超时")
            buf += d
        return buf

    def send_frame(self, payload):
        # 真机: CRC 算在明文上, 然后 payload+crc 一起被混淆
        plain = payload + struct.pack("<H", crc16(payload))
        enc = xor_obf(plain, len(plain))
        frame = SYNC + struct.pack("<H", len(payload)) + enc + FOOTER
        self._write(frame)

    def recv_frame(self):
        # 找同步头
        while True:
            b = self._recv_exact(2)
            if b == SYNC:
                break
        size = struct.unpack("<H", self._recv_exact(2))[0]
        enc = self._recv_exact(size)
        self._recv_exact(2)                      # pad0 pad1
        tail = self._recv_exact(2)
        if tail != FOOTER:
            raise IOError("footer 错: %s" % tail.hex())
        return xor_obf(enc, size)

    def cmd(self, cid, body=b"", want=None, tries=8):
        """发命令并取应答；want 给定时跳过不相干的帧(如迟到的 0x051E/0x0518)"""
        payload = struct.pack("<HH", cid, 4 + len(body)) + body
        self.send_frame(payload)
        for _ in range(tries if want else 1):
            f = self.recv_frame()
            if want is None or (len(f) >= 2 and struct.unpack_from("<H", f, 0)[0] == want):
                return f
        raise IOError("没等到期望的应答 0x%04X" % want)

    # ---------- 应用层 ----------
    def handshake(self):
        self.timestamp = int(time.time()) & 0x7FFFFFFF
        r = self.cmd(0x0514, struct.pack("<I", self.timestamp), want=0x0515)
        cid, size = struct.unpack_from("<HH", r, 0)
        ver = r[4:20].split(b"\x00")[0].decode("latin1")
        return cid, ver

    def read_eeprom(self, off, n):
        body = struct.pack("<HBB I", off, n, 0, self.timestamp)
        r = self.cmd(0x051B, body, want=0x051C)
        cid, size = struct.unpack_from("<HH", r, 0)
        o, sz, pad = struct.unpack_from("<HBB", r, 4)
        return r[8:8 + sz]

    def write_eeprom(self, off, data):
        body = struct.pack("<HBB I", off, len(data), 0, self.timestamp) + data
        r = self.cmd(0x051D, body, want=0x051E)
        return struct.unpack_from("<HH", r, 0)[0] == 0x051E

    def reboot_to_bootloader(self):
        """0x05DD: 无应答, 直接发, 不等待"""
        payload = struct.pack("<HH", 0x05DD, 4) + struct.pack("<I", self.timestamp)
        plain = payload + struct.pack("<H", crc16(payload))
        self._write(SYNC + struct.pack("<H", len(payload))
                    + xor_obf(plain, len(plain)) + FOOTER)
        time.sleep(0.15)

    def ensure_bootloader(self):
        """已在 bootloader 就直接返回; 否则发 0x05DD 再握手

        先认真实 bootloader 的 0x0518 信息帧 (真机 7.02.02 会周期推送),
        再退回旧的 FLSH 握手。
        """
        # 1) 已在 bootloader: 0x0518 周期帧
        ver, uid = self.boot_wait_info(0.8)
        if ver:
            return True
        # 2) 应用模式: 发 0x05DD 重启, 然后**只**认 0x0518（不要用 FLSH 硬碰）
        self.reboot_to_bootloader()
        ver, uid = self.boot_wait_info(2.5)
        if ver:
            return True
        # 3) 旧协议兜底（仅当设备开了 --legacy-proto）
        return self.boot_enter(tries=5)

    # ---------- bootloader ----------
    def _set_timeout(self, t):
        if self.ser is not None:
            self.ser.timeout = t
        else:
            self.s.settimeout(t)

    def boot_enter(self, tries=20):
        for _ in range(tries):
            self._write(b"FLSH")
            try:
                self._set_timeout(0.3)
                if self._recv_exact(4) == b"FLSH":
                    self._set_timeout(2.0)
                    return True
            except Exception:
                pass
            time.sleep(0.05)
        return False

    def boot(self, data, expect=None):
        self._write(data)
        if expect is None:
            return None
        n = expect if isinstance(expect, int) else len(expect)
        return self._recv_exact(n)

    def boot_info(self):
        """兼容旧命令 0x30: 返回 (页大小, 空间MB)"""
        r = self.boot(b"\x30", 9)
        page, mb = struct.unpack_from("<II", r, 1)
        return page, mb

    def boot_read_banner(self, timeout=1.5):
        """读上电 ASCII 横幅 '7.02.02...'"""
        self._set_timeout(timeout)
        buf = b""
        try:
            while len(buf) < 14:
                if self.ser is not None:
                    d = self.ser.read(1)
                else:
                    d = self.s.recv(1)
                if not d:
                    break
                buf += d
                if buf.startswith(b"7.") and len(buf) >= 14:
                    break
        except Exception:
            pass
        self._set_timeout(2.0)
        return buf

    def boot_wait_info(self, timeout=2.0):
        """等 0x0518 信息帧 -> (version, uid4)"""
        t0 = time.time()
        self._set_timeout(0.3)
        try:
            while time.time() - t0 < timeout:
                try:
                    f = self.recv_frame()
                except Exception:
                    continue
                if len(f) >= 4 and struct.unpack_from("<H", f, 0)[0] == 0x0518:
                    uid = struct.unpack_from("<4I", f, 4)
                    ver = f[20:36].split(b"\x00")[0].decode("latin1")
                    return ver, uid
        finally:
            self._set_timeout(2.0)
        return None, None

    def boot_unlock(self, magic=b"7.02"):
        """0x0530 解锁 (真机: 4 字节 magic 或单字节 '*' )"""
        body = magic.ljust(4, b"\x00")
        self.send_frame(struct.pack("<HH", 0x0530, 4 + len(body)) + body)

    def boot_read(self, addr, n):
        r = self.boot(b"\x31" + struct.pack("<IH", addr, n), 3 + n)
        ln = struct.unpack_from("<H", r, 1)[0]
        return r[3:3 + ln]

    def boot_erase(self, addr, n):
        r = self.boot(b"\x33" + struct.pack("<II", addr, n), 2)
        return r[1] == 0

    def boot_write(self, addr, data):
        frame = b"\x32" + struct.pack("<IH", addr, len(data)) + data + struct.pack("<H", crc16(data))
        r = self.boot(frame, 2)
        return r[1] == 0

    def boot_exit(self):
        try:
            self.boot(b"\x34", 1)
        except Exception:
            pass


    # ---------- 真协议写入 (stock-bl 7.02.02) ----------
    def boot_write_image(self, path, param=None, cookie=b"\xef\xbe\xad\xde", verbose=True):
        return self.boot_write_image_from_bytes(open(path, "rb").read(),
                                                param=param, cookie=cookie, verbose=verbose)

    def boot_write_image_from_bytes(self, data, param=None, cookie=b"\xef\xbe\xad\xde",
                                    verbose=True):
        """0x0516 参数块 + 0x0519 数据块 (256B/块, 块0 会触发整区擦除)"""
        total = (len(data) + 255) // 256
        if verbose:
            print("[BL] 镜像 %d B -> %d 块 (256B/块)" % (len(data), total))
        # 参数块 (104B)
        pblk = (param or b"").ljust(0x68, b"\x00")[:0x68]
        self.send_frame(struct.pack("<HH", 0x0516, 4 + len(pblk)) + pblk)
        r = self._wait_cmd(0x0517, 1.0)
        if verbose:
            print("[BL] 参数块 -> %s" % ("0x0517 OK" if r else "无应答"))
        t0 = time.time()
        for idx in range(total):
            piece = data[idx * 256:(idx + 1) * 256].ljust(256, b"\xFF")
            body = cookie + struct.pack("<HH", idx, total) + b"\x00" * 4 + piece
            self.send_frame(struct.pack("<HH", 0x0519, 4 + len(body)) + body)
            r = self._wait_cmd(0x051A, 1.0)
            if r is None:
                raise RuntimeError("块 %d 无应答" % idx)
            st = r[10] if len(r) >= 12 else 0    # payload: cmd(2)+inner(2)+cookie(4)+idx(2)+status(1)
            if st != 0:
                raise RuntimeError("块 %d 被拒 (status=%d)" % (idx, st))
            if verbose and (idx % 32 == 0 or idx + 1 == total):
                print("   %4d / %4d 块" % (idx + 1, total))
        dt = time.time() - t0
        if verbose:
            print("[BL] 写完 %d 块, %.2fs (%.1f KB/s)" % (total, dt, len(data) / 1024 / max(dt, 1e-6)))
        return total

    def _wait_cmd(self, want, timeout=1.0):
        """收包带缓冲: 半包不丢, 非目标帧暂存"""
        t0 = time.time()
        self._set_timeout(0.2)
        try:
            while time.time() - t0 < timeout:
                if getattr(self, "_pending", None):
                    f = self._pending.pop(0)
                    if len(f) >= 2 and struct.unpack_from("<H", f, 0)[0] == want:
                        return f
                    continue
                try:
                    f = self.recv_frame()
                except Exception:
                    continue
                if len(f) >= 2 and struct.unpack_from("<H", f, 0)[0] == want:
                    return f
                self._pending = getattr(self, "_pending", [])
                self._pending.append(f)
        finally:
            self._set_timeout(2.0)
        return None


# --------------------------------------------------------------------------
def do_flash(radio, path, base=0x001000, chunk=256, verbose=True):
    data = open(path, "rb").read()
    if not radio.ensure_bootloader():
        raise RuntimeError("进不了 bootloader")
    page, mb = radio.boot_info()
    if verbose:
        print("[FLASH] 设备报告: 页 %d B, 空间 %d MB" % (page, mb))
    end = base + len(data)
    radio.boot_erase(base, end - base)
    t0 = time.time()
    for off in range(0, len(data), chunk):
        piece = data[off:off + chunk]
        if not radio.boot_write(base + off, piece):
            raise RuntimeError("写 0x%06X 失败" % (base + off))
        if verbose and (off // chunk) % 32 == 0:
            print("  写入 %6d / %6d 字节 (%.0f%%)"
                  % (off, len(data), 100.0 * off / len(data)))
    if verbose:
        print("[FLASH] 写完 %d 字节, 用时 %.2fs" % (len(data), time.time() - t0))
    # 校验
    ok = 0
    for off in range(0, len(data), 1024):
        piece = data[off:off + 1024]
        back = radio.boot_read(base + off, len(piece))
        if back == piece:
            ok += 1
        else:
            print("[FLASH] !! 回读不一致 @0x%06X" % (base + off))
    if verbose:
        print("[FLASH] 回读校验: %d/%d 块一致" % (ok, (len(data) + 1023) // 1024))
    radio.boot_exit()
    return ok == (len(data) + 1023) // 1024


def selftest():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import radio_device

    tmp = "flash_selftest.bin"
    if os.path.exists(tmp):
        os.remove(tmp)
    logs = []
    radio = radio_device.VirtualRadio(tmp, log=lambda m: logs.append(m))
    bridge = radio_device.SerialBridge(radio, port=8899, log=lambda m: logs.append(m))
    bridge.start()
    time.sleep(0.2)

    cli = Radio(port=8899)
    ok = True

    # 1) 应用模式握手
    radio.go_app()
    cid, ver = cli.handshake()
    print("① 握手: cmd=0x%04X version=%r" % (cid, ver))
    ok &= (cid == 0x0515)

    # 2) 写频: 写一段信道数据并回读
    chan = bytes(range(0x40))
    ok &= cli.write_eeprom(0x0100, chan)
    back = cli.read_eeprom(0x0100, 0x40)
    print("② 写频: 写 0x0100 +64, 回读一致 = %s" % (back == chan))
    ok &= (back == chan)

    # 3) 进 bootloader（真协议）
    cli.reboot_to_bootloader()
    radio.enter_boot_window(5.0)
    fw = None
    for cand in ("firmware/firmware_decrypted.bin",
                     "firmware_decrypted.bin",
                     os.environ.get("K5_FW") or ""):
        if os.path.exists(cand):
            fw = cand
            break
    if not fw:
        print("③ 找不到固件样本，跳过刷机测试")
    else:
        t0 = time.time()
        if not cli.ensure_bootloader():
            print("③ 进不了 bootloader")
            ok = False
        else:
            cli.boot_unlock(b"7.02")
            data = open(fw, "rb").read()
            nblk = cli.boot_write_image_from_bytes(data)
            good = (radio.flash.read(0x1000, len(data)) == data)
            print("③ 刷机: %d 字节 / %d 块 -> 空间校验 = %s (%.2fs)"
                  % (len(data), nblk, good, time.time() - t0))
            ok &= good
            hdr = radio.flash.read(0x1000, 16)
            print("④ 掉电保持: 0x1000 前 16 字节 = %s" % hdr.hex())

    cli.close()
    bridge.stop()
    size = os.path.getsize(tmp)
    print("⑤ 虚拟固件空间: %s (%d 字节 = %d MB)" % (tmp, size, size // (1024 * 1024)))
    print("\n结果: %s" % ("全部通过" if ok else "有失败项"))
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--port", type=int, default=8801)
    ap.add_argument("-H", "--host", default="127.0.0.1")
    ap.add_argument("--com", default=None, metavar="COMx", help="走真实串口 (com0com 对端口)")
    ap.add_argument("--baud", type=int, default=115200)
    sub = ap.add_subparsers(dest="op")

    sub.add_parser("selftest")
    sub.add_parser("info")
    sub.add_parser("flsh")
    p_r = sub.add_parser("read"); p_r.add_argument("addr"); p_r.add_argument("len")
    p_w = sub.add_parser("write-channels"); p_w.add_argument("file")
    p_f = sub.add_parser("flash"); p_f.add_argument("file")
    p_f.add_argument("--base", default="0x1000")
    p_f.add_argument("--legacy", action="store_true", help="用旧 0x30-0x34 命令而不是真协议")
    p_d = sub.add_parser("dump"); p_d.add_argument("out")

    args = ap.parse_args()
    if args.op == "selftest" or args.op is None:
        sys.exit(0 if selftest() else 1)

    cli = Radio(args.host, args.port, com=args.com, baud=args.baud)
    if args.op == "info":
        cid, ver = cli.handshake()
        print("命令 0x%04X  版本 %r" % (cid, ver))
    elif args.op == "flsh":
        banner = cli.boot_read_banner(0.8)
        ver, uid = cli.boot_wait_info(2.0)
        if ver:
            print("刷机模式: 版本 %s  UID %s"
                  % (ver, " ".join("%08X" % u for u in uid)))
            if banner.startswith(b"7."):
                print("  横幅: %r" % banner)
        elif cli.ensure_bootloader():
            page, mb = cli.boot_info()
            print("已进入刷机模式(旧协议): 页 %d B, 空间 %d MB" % (page, mb))
        else:
            print("进不了刷机模式")
            return
    elif args.op == "read":
        cli.handshake()
        data = cli.read_eeprom(int(args.addr, 0), int(args.len, 0))
        print(data.hex())
    elif args.op == "write-channels":
        cli.handshake()
        blob = open(args.file, "rb").read()
        print("写入", len(blob), "字节:", cli.write_eeprom(0x0000, blob))
    elif args.op == "flash":
        if args.legacy:
            print("刷机结果(旧协议):", do_flash(cli, args.file, int(args.base, 0)))
        else:
            if not cli.ensure_bootloader():
                print("进不了刷机模式")
                return
            ver, uid = cli.boot_wait_info(1.0)
            if ver:
                print("设备: 版本 %s  UID %s" % (ver, " ".join("%08X" % u for u in uid)))
            cli.boot_unlock(b"7.02")
            n = cli.boot_write_image(args.file)
            print("刷机完成: %d 块, 设备将跳转 app" % n)
    elif args.op == "dump":
        if not cli.ensure_bootloader():
            print("进不了 bootloader")
            return
        buf = bytearray()
        for off in range(0, 4 * 1024 * 1024, 4096):
            buf += cli.boot_read(off, 4096)
        open(args.out, "wb").write(buf)
        print("已保存", args.out, len(buf), "字节")
    cli.close()


if __name__ == "__main__":
    main()
