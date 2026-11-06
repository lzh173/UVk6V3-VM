#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_bl_protocol.py — 用 stock-bl 7.02.02 的真实协议跟模拟器对话

流程:
  1) 设备以 --flsh 启动
  2) 读上电横幅 "7.02.02..." + 周期 0x0518 信息帧 (版本 + UID)
  3) 0x0530 解锁 (magic "7.02" / '*')
  4) 0x0516 写参数块 (104B -> flash 0x08002700)
  5) 0x0519 按 256B 块写 app (-> flash 0x08002800 + idx*256)
  6) 回读空间校验
"""

import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import radio_device as rd
import k5tool

PORT = 8899
FW = os.environ.get("K5_FW") or "firmware/firmware_decrypted.bin"


def make_radio(space):
    r = rd.VirtualRadio(space=space, log=print)
    r.hold_boot()
    return r


def main():
    space_file = "bl_proto_space.bin"
    if os.path.exists(space_file):
        os.remove(space_file)
    space = rd.Flash4M(space_file, size=4 * 1024 * 1024)
    radio = make_radio(space)
    bridge = rd.SerialBridge(radio, port=PORT, log=lambda m: None)
    bridge.start()
    time.sleep(0.2)

    cli = k5tool.Radio(port=PORT)
    s = cli.s

    # ---- 1) 上电横幅 ----
    s.settimeout(1.5)
    banner = b""
    try:
        while len(banner) < 14:
            d = s.recv(64)
            if not d:
                break
            banner += d
    except socket.timeout:
        pass
    print("① 上电横幅: %r" % banner[:24])

    # ---- 2) 0x0518 信息帧 ----
    frames = []
    def read_frames(seconds, want=None):
        t0 = time.time()
        s.settimeout(0.2)
        while time.time() - t0 < seconds:
            try:
                f = cli.recv_frame()
                frames.append(f)
                cmd = struct.unpack_from("<H", f, 0)[0]
                if want and cmd == want:
                    return f
            except Exception:
                continue
        return None

    info = read_frames(2.0, want=0x0518)
    if info:
        uid = struct.unpack_from("<4I", info, 4)
        ver = info[20:36].split(b"\x00")[0].decode("latin1")
        print("② 0x0518 信息帧: 版本=%r UID=%s" % (ver, " ".join("%08X" % u for u in uid)))
    else:
        print("② 没收到 0x0518 信息帧")
        return 1

    # ---- 3) 解锁 ----
    body = b"7.02" + b"\x00" * 4
    cli.send_frame(struct.pack("<HH", 0x0530, 4 + len(body)) + body)
    time.sleep(0.2)
    print("③ 已发 0x0530 解锁 (magic '7.02')  unlocked=%s" % radio.bl_unlocked)

    # ---- 4) 参数块 ----
    img = open(FW, "rb").read()
    param = img[:0x68].ljust(0x68, b"\x00")
    cli.send_frame(struct.pack("<HH", 0x0516, 4 + len(param)) + param)
    rep = read_frames(1.0, want=0x0517)
    print("④ 0x0516 参数块 -> 应答 %s (%s)"
          % ("0x0517" if rep else "无", rep.hex() if rep else ""))

    # ---- 5) 按块写 ----
    CH = 256
    nblk = (len(img) + CH - 1) // CH
    t0 = time.time()
    ok = 0
    for idx in range(nblk):
        piece = img[idx * CH:(idx + 1) * CH].ljust(CH, b"\xFF")
        body = b"\xEF\xBE\xAD\xDE" + struct.pack("<HH", idx, nblk) + b"\x00" * 4 + piece
        cli.send_frame(struct.pack("<HH", 0x0519, 4 + len(body)) + body)
        r = read_frames(0.6, want=0x051A)
        if r:
            ok += 1
    dt = time.time() - t0
    print("⑤ 写块: %d/%d 块确认, %.2fs (%.1f KB/s)"
          % (ok, nblk, dt, len(img) / 1024 / max(dt, 1e-6)))

    # ---- 6) 校验空间 ----
    disk = space.read(0x1000, nblk * 256)
    match = disk[:len(img)] == img
    print("⑥ 空间回读与源文件一致: %s" % match)
    print("   参数块 0x0F00 前 8 字节: %s" % space.read(0x0F00, 8).hex())

    cli.close()
    bridge.stop()
    space.flush()
    print("\n结果:", "通过" if (match and ok == nblk) else "失败")
    return 0 if (match and ok == nblk) else 1


if __name__ == "__main__":
    sys.exit(main())
