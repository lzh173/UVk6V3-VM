#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_flash_payloads.py — 用真实固件包测试 4MB 空间的写入路径

  mangosteen_v2.3.7.bin   120,736 B   -> 0x001000 (固件槽)
  uvk1_gb2312_font.bin    327,568 B   -> 0x020000 (字库槽)

每个文件: 擦除 -> 分块写(带 CRC) -> 分段回读 -> SHA256 比对 -> 计时/吞吐
"""

import hashlib
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import radio_device as rd
import k5tool

SPACE = "device_flash_payloads.bin"
PORT = 8888
CHUNK = 1024

PAYLOADS = [
    (r"D:\下载\mangosteen_v2.3.7.bin", 0x001000),
    (r"D:\下载\uvk1_gb2312_font.bin", 0x020000),
]


def sha(b):
    return hashlib.sha256(b).hexdigest()[:16]


def main():
    if os.path.exists(SPACE):
        os.remove(SPACE)
    space = rd.Flash4M(SPACE, size=4 * 1024 * 1024)
    radio = rd.VirtualRadio.__new__(rd.VirtualRadio)
    radio.log = lambda m: None
    radio.flash = space
    radio.lock = threading.RLock()
    radio.rx = bytearray(); radio.tx = bytearray()
    radio.version = b"UV-K6-VM 1.0"
    radio.hw_id = b"\x01\x00\x00\x00"
    radio.session_ts = None; radio.locked = False
    radio.boot_mode = False; radio.boot_deadline = 0.0
    radio.enter_boot_window(0.8)

    bridge = rd.SerialBridge(radio, port=PORT, log=lambda m: None)
    bridge.start()
    time.sleep(0.2)

    cli = k5tool.Radio(port=PORT)
    if not cli.boot_enter():
        print("进不了 bootloader")
        return 1
    page, mb = cli.boot_info()
    print("bootloader: 页 %d B, 空间 %d MB\n" % (page, mb))

    all_ok = True
    for path, base in PAYLOADS:
        if not os.path.exists(path):
            print("跳过(不存在):", path)
            continue
        data = open(path, "rb").read()
        name = os.path.basename(path)
        print("== %s (%d B = %.1f KB) -> 0x%06X" % (name, len(data), len(data) / 1024, base))

        t0 = time.time()
        cli.boot_erase(base, len(data))
        t_erase = time.time() - t0

        t1 = time.time()
        for off in range(0, len(data), CHUNK):
            if not cli.boot_write(base + off, data[off:off + CHUNK]):
                print("   写失败 @0x%06X" % (base + off))
                all_ok = False
                break
        t_write = time.time() - t1

        t2 = time.time()
        bad = 0
        for off in range(0, len(data), 4096):
            piece = data[off:off + 4096]
            if cli.boot_read(base + off, len(piece)) != piece:
                bad += 1
        t_read = time.time() - t2

        disk = space.read(base, len(data))
        print("   擦除 %.2fs | 写入 %.2fs (%.1f KB/s) | 回读 %.2fs"
              % (t_erase, t_write, len(data) / 1024 / max(t_write, 1e-6), t_read))
        print("   源 %s  回读 %s  一致=%s  不一致块=%d"
              % (sha(data), sha(disk), data == disk, bad))
        all_ok &= (data == disk and bad == 0)
        print()

    cli.boot_exit()
    cli.close()
    bridge.stop()
    space.flush()
    print("空间文件: %s (%d MB)" % (SPACE, os.path.getsize(SPACE) // (1024 * 1024)))
    print("结果:", "全部通过" if all_ok else "有失败")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
