#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_flash_cycle.py — 端到端: 串口刷机 → 设备自动重载 → 屏幕内容变化

  1. 建 4MB 固件空间, 注入原始固件 @0x1000
  2. 起 MCU 虚拟机, 跑出开机画面 (存 cycle_before.png)
  3. 通过虚拟串口把**打过补丁的固件**刷进 0x1000 (把 "Device MAC" 改成 "FLASH  OK ")
  4. 虚拟机检测到固件区 generation 变化 → 自动重载复位
  5. 再跑出画面 (存 cycle_after.png), 比对
"""

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mcu_vm
import radio_device as rd
import k5tool

FW = os.environ.get("K5_FW") or "firmware/firmware_decrypted.bin"

SPACE = "device_flash.bin"
PORT = 8877


def patch_image(img):
    old = b"Device MAC"
    new = b"FLASH  OK "          # 等长替换
    i = img.find(old)
    if i < 0:
        raise RuntimeError("找不到待替换字符串")
    out = bytearray(img)
    out[i:i + len(old)] = new
    print("[TEST] 补丁: 偏移 0x%X  '%s' -> '%s'" % (i, old.decode(), new.decode()))
    return bytes(out), i


def make_radio(space):
    r = rd.VirtualRadio(space=space, log=lambda m: None)
    r.hold_boot()
    return r


def main():
    img = open(FW, "rb").read()
    print("[TEST] 固件 %s (%d 字节)" % (FW, len(img)))

    if os.path.exists(SPACE):
        os.remove(SPACE)
    space = rd.Flash4M(SPACE, size=4 * 1024 * 1024)
    space.program(0x1000, img)
    space.flush()
    print("[TEST] 4MB 空间已注入原始固件 @0x1000")

    vm = mcu_vm.VM(FW, flash_path=space)
    radio = make_radio(space)
    bridge = rd.SerialBridge(radio, port=PORT, log=lambda m: None)
    bridge.start()
    time.sleep(0.2)

    # ---- 刷机前画面 ----
    vm.run(max_ticks=700)
    before = bytes(vm.framebuffer())
    vm.render_png("cycle_before.png")
    print("[TEST] 刷机前: tick=%d, 帧缓冲非零 %d 字节" % (vm.ticks, sum(1 for b in before if b)))

    # ---- 串口刷入补丁固件 ----
    patched, off = patch_image(img)
    cli = k5tool.Radio(port=PORT)
    if not cli.ensure_bootloader():
        print("[TEST] 进不了 bootloader")
        return 1
    cli.boot_unlock(b"7.02")
    t0 = time.time()
    nblk = cli.boot_write_image_from_bytes(patched)
    cli.close()
    bad = 0 if space.read(0x1000, len(patched)) == patched else 1
    print("[TEST] 刷写 %d 字节 (%d 块), %.2fs, 空间回读不一致: %d"
          % (len(patched), nblk, time.time() - t0, bad))

    # ---- 等虚拟机重载并重新出画面 ----
    t1 = time.time()
    reloaded = False
    while time.time() - t1 < 10:
        vm.run(max_ticks=vm.ticks + 50)
        if getattr(vm, "_space_gen", -1) == getattr(space, "generation", -2):
            reloaded = True
            break
    print("[TEST] 虚拟机自动重载: %s (tick=%d)" % (reloaded, vm.ticks))
    vm.run(max_ticks=vm.ticks + 700)
    after = bytes(vm.framebuffer())
    vm.render_png("cycle_after.png")
    print("[TEST] 刷机后: tick=%d, 帧缓冲非零 %d 字节" % (vm.ticks, sum(1 for b in after if b)))
    changed = before != after
    print("[TEST] 画面变化: %s" % changed)

    bridge.stop()
    ok = changed and bad == 0 and reloaded
    print("\n结果:", "通过" if ok else "失败")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

