#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sniff_param.py — 假装成"待刷机的机器"，把真实写入器发来的 0x0516 参数块骗下来

原理
----
真机 bootloader (stock-bl 7.02.02) 的刷机流程是：
    0x0530 解锁 -> 0x0516 写 104 字节参数块到 0x08002700 -> 0x0519 若干 256B 数据块
本脚本在 com0com 的一端（如 COM14）冒充设备，另一端（COM15）接官方写入器：
  * 上电先发 ASCII 横幅 "7.02.02..." + 周期推 0x0518 信息帧（让工具认得出设备）
  * 收到 0x0530 就记下 magic 并置解锁
  * 收到 0x0516 就把 body 存盘（这就是我们要的参数块），并回 0x0517
  * 收到 0x0519 只记账不再写 flash（默认），回 0x051A 让流程继续
所有收到的帧都按十六进制写到日志，方便复盘。

用法
----
    # com0com: COM14 <-> COM15，写入器开 COM15
    python sniff_param.py --com COM14 --out param_0516.bin

    # 没有 com0com 时用 TCP（pyserial: socket://127.0.0.1:8801）
    python sniff_param.py --port 8801 --out param_0516.bin

    # 只监听不回应（工具可能会超时，但能抓到第一帧）
    python sniff_param.py --com COM14 --passive

    # 顺手把 0x0519 的数据块拼成完整固件
    python sniff_param.py --com COM14 --save-image fw_captured.bin

实测（真实写入器）
------------------
    [18.370] <- 0x0530 magic='7.02'      ; 解锁（会连发 3 次）
    [19.729] <- 0x0519 1/469            ; 直接开始灌数据块，**没有 0x0516**
每个 0x0519 body: cookie(4) idx(2) total(2) rsv(4) data(256)
"""

import argparse
import os
import struct
import sys
import time

# ---- 与 radio_device.py 完全一致的帧格式 ----
OBF = bytes([0x16, 0x6C, 0x14, 0xE6, 0x2E, 0x91, 0x0D, 0x40,
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


CRCTAB = _mk_table()


def crc16(data):
    crc = 0
    for b in data:
        crc = ((crc << 8) ^ CRCTAB[((crc >> 8) ^ b) & 0xFF]) & 0xFFFF
    return crc


def xor_obf(data, n=None):
    n = len(data) if n is None else min(n, len(data))
    out = bytearray(data)
    for i in range(n):
        out[i] ^= OBF[i % 16]
    return bytes(out)


class Sniffer:
    def __init__(self, out_path, log_path=None, passive=False, image_path=None):
        self.rx = bytearray()
        self.tx = bytearray()
        self.unlocked = False
        self.blocks = 0
        self.param = None
        self.image_path = image_path
        self.image = {}          # idx -> 256B
        self.image_total = 0
        self.image_cookie = None
        self.out_path = out_path
        self.log_fp = open(log_path, "w", encoding="utf-8") if log_path else None
        self.passive = passive
        self.t0 = time.time()
        self.next_info = 0.0

    # ---------- 日志 ----------
    def log(self, msg):
        line = "[%7.3f] %s" % (time.time() - self.t0, msg)
        print(line)
        if self.log_fp:
            self.log_fp.write(line + "\n")
            self.log_fp.flush()

    # ---------- 输入 ----------
    def feed(self, data):
        self.rx.extend(data)

    # ---------- 输出 ----------
    def _reply(self, cmd, body=b"", inner=None):
        inner = (4 + len(body)) if inner is None else inner
        payload = struct.pack("<HH", cmd, inner) + body
        n = len(payload)
        frame = (SYNC + struct.pack("<H", n) + xor_obf(payload, n)
                 + bytes([OBF[n & 0xF] ^ 0xFF, OBF[(n + 1) & 0xF] ^ 0xFF]) + FOOTER)
        self.tx.extend(frame)

    def _banner(self):
        self.tx.extend(b"7.02.02\x00\x00\x00\xc4 \r\n")

    def _info(self):
        uid = (0x1A2B3C4D, 0x5E6F7081, 0x92A3B4C5, 0x0F1E2D3C)
        body = struct.pack("<4I", *uid) + b"7.02.02".ljust(16, b"\x00")
        self._reply(0x0518, body, inner=len(body))

    def tick(self, now):
        """周期推 0x0518（真机行为），让写入器认出设备"""
        if self.passive:
            return
        if now >= self.next_info:
            self._info()
            self.next_info = now + 0.5

    # ---------- 帧解析 ----------
    def poll(self):
        out = bytes(self.tx)
        self.tx.clear()
        while True:
            i = self.rx.find(SYNC)
            if i < 0:
                if len(self.rx) > 4096:
                    del self.rx[:-64]
                break
            if i:
                del self.rx[:i]
            if len(self.rx) < 8:
                break
            size = self.rx[2] | (self.rx[3] << 8)
            if size < 4 or size > 512:
                del self.rx[:2]
                continue
            total = size + 8
            if len(self.rx) < total:
                break
            frame = bytes(self.rx[:total])
            if frame[-2:] != FOOTER:
                del self.rx[:2]
                continue
            plain = xor_obf(frame[4:4 + size + 2], size + 2)
            payload, crc_rx = plain[:size], struct.unpack_from("<H", plain, size)[0]
            del self.rx[:total]
            if crc16(payload) != crc_rx:
                self.log("!! CRC 错, 丢弃")
                continue
            self._handle(payload)
        return out

    def save_image(self):
        n = max(self.image) + 1
        buf = b"".join(self.image.get(i, b"\xFF" * 256) for i in range(n))
        try:
            with open(self.image_path, "wb") as f:
                f.write(buf)
            self.log("   ★ 固件镜像 %d 块 = %d 字节 -> %s (SP=%08X Reset=%08X)"
                     % (n, len(buf), self.image_path,
                        *struct.unpack_from("<II", buf, 0)))
        except OSError as e:
            self.log("   保存镜像失败: %s" % e)

    def _handle(self, payload):
        cmd, inner = struct.unpack_from("<HH", payload, 0)
        body = payload[4:]
        self.log("<- 0x%04X inner=%d body=%d %s" % (cmd, inner, len(body), body[:24].hex()))

        if cmd == 0x0530:
            magic = body[:4]
            self.unlocked = magic == b"7.02" or (body[:1] == b"*")
            self.log("   解锁 magic=%r -> %s" % (magic, self.unlocked))
            return

        if cmd == 0x0516:
            self.param = bytes(body)
            self.log("   ★ 参数块 %d 字节 -> %s" % (len(self.param), self.out_path))
            try:
                with open(self.out_path, "wb") as f:
                    f.write(self.param)
            except OSError as e:
                self.log("   保存失败: %s" % e)
            if not self.passive:
                self._reply(0x0517, b"\x00\x00\x00\x00", inner=4)
            return

        if cmd == 0x0519:
            self.blocks += 1
            idx = struct.unpack_from("<H", body, 4)[0] if len(body) >= 8 else -1
            total = struct.unpack_from("<H", body, 6)[0] if len(body) >= 8 else -1
            # 攒固件镜像
            if self.image_path and idx >= 0 and len(body) >= 12 + 256:
                if self.image_cookie is None:
                    self.image_cookie = bytes(body[0:4])
                if bytes(body[0:4]) != self.image_cookie:
                    self.log("   !! cookie 变了 (%s -> %s)，可能是新的一次刷机"
                             % (self.image_cookie.hex(), bytes(body[0:4]).hex()))
                    self.image.clear()
                    self.image_cookie = bytes(body[0:4])
                self.image[idx] = bytes(body[12:12 + 256])
                self.image_total = total
                if idx + 1 >= total:
                    self.save_image()
            if self.blocks <= 3 or idx + 1 >= total:
                self.log("   数据块 %d/%d (累计 %d)" % (idx + 1, total, self.blocks))
            if not self.passive:
                cookie = body[0:4]
                self._reply(0x051A, cookie + struct.pack("<HBB", idx & 0xFFFF, 0, 0), inner=8)
            return


def main():
    ap = argparse.ArgumentParser(description="骗取真实写入器的 0x0516 参数块")
    ap.add_argument("--com", default=None, help="串口，如 COM14（com0com 对的一端）")
    ap.add_argument("--port", type=int, default=None, help="或走 TCP 端口")
    ap.add_argument("--baud", type=int, default=38400)
    ap.add_argument("--out", default="param_0516.bin", help="参数块保存路径")
    ap.add_argument("--log", default="sniff_0516.log", help="帧日志")
    ap.add_argument("--passive", action="store_true", help="只收不发（不回应）")
    ap.add_argument("--save-image", default=None,
                    help="把收到的 0x0519 数据块拼成完整固件（如 fw_captured.bin）")
    args = ap.parse_args()

    if not args.com and not args.port:
        ap.error("要么 --com，要么 --port")

    sn = Sniffer(args.out, args.log, passive=args.passive,
                 image_path=args.save_image)
    sn._banner()
    sn.log("模拟设备就绪，等写入器…")

    if args.com:
        import serial
        ser = serial.Serial(args.com, args.baud, timeout=0.02, write_timeout=0.2)
        sn.log("串口 %s @ %d 8N1" % (args.com, args.baud))
        try:
            while True:
                d = ser.read(512)
                if d:
                    sn.feed(d)
                out = sn.poll()
                if out:
                    try:
                        ser.write(out)
                    except Exception:
                        pass
                sn.tick(time.time())
        except KeyboardInterrupt:
            pass
        finally:
            ser.close()
    else:
        import socket
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", args.port))
        srv.listen(1)
        srv.settimeout(0.2)
        sn.log("TCP 127.0.0.1:%d 等连接…" % args.port)
        cli = None
        try:
            while True:
                if cli is None:
                    try:
                        cli, _ = srv.accept()
                        cli.setblocking(False)
                        sn.log("客户端接入")
                    except socket.timeout:
                        continue
                try:
                    d = cli.recv(512)
                    if d:
                        sn.feed(d)
                    else:
                        cli.close()
                        cli = None
                        continue
                except BlockingIOError:
                    pass
                except OSError:
                    cli = None
                    continue
                out = sn.poll()
                if out:
                    try:
                        cli.sendall(out)
                    except OSError:
                        cli = None
                sn.tick(time.time())
        except KeyboardInterrupt:
            pass

    sn.log("结束：参数块 %s，数据块 %d 个%s"
           % ("已保存 " + args.out if sn.param else "未收到（本次流程没发 0x0516）",
              sn.blocks,
              ("，镜像 " + args.save_image) if args.save_image and sn.image else ""))
    if sn.log_fp:
        sn.log_fp.close()


if __name__ == "__main__":
    main()
