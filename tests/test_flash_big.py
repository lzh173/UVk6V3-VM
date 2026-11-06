#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_flash_big.py — 用真实 bootloader 协议刷入 469 块的大固件，然后确认能跑

复现用户场景：原厂固件 → 串口刷入 Dondji(119,876 字节 = 469 块) → bootloader 跳转 → 运行
关键校验：跳转后不能跑飞（老代码只重载 35KB，后面是旧镜像 → PC=0x08008000 崩）
"""

import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mcu_vm
import radio_device as rd
import k5tool

STOCK = os.environ.get("K5_FW") or "firmware/firmware_decrypted.bin"
BIG = r"D:\下载\Dondji.fusion.bin"
SPACE = "device_flash_big.bin"
PORT = 8878


def main():
    if not os.path.exists(BIG):
        print("[TEST] 找不到大固件:", BIG)
        return 2
    big = open(BIG, "rb").read()
    print("[TEST] 待刷固件 %s: %d 字节 = %d 块"
          % (os.path.basename(BIG), len(big), (len(big) + 255) // 256))

    if os.path.exists(SPACE):
        os.remove(SPACE)
    space = rd.Flash4M(SPACE, size=4 * 1024 * 1024)
    stock = open(STOCK, "rb").read()
    space.program(0x1000, stock)
    space.flush()

    vm = mcu_vm.VM(STOCK, flash_path=space)
    vm.periph.nor[0xA000:0xA170] = open(os.path.join("data", "fake_settings.bin"), "rb").read()
    radio = rd.VirtualRadio(space=space, log=lambda m: None)
    radio.hold_boot()
    bridge = rd.SerialBridge(radio, port=PORT, log=lambda m: None)
    bridge.start()
    time.sleep(0.2)

    vm.run(max_ticks=200)
    print("[TEST] 刷机前 tick=%d 空间 reset=0x%08X"
          % (vm.ticks, struct.unpack("<I", space.read(0x1004, 4))[0]))

    cli = k5tool.Radio(port=PORT)
    if not cli.ensure_bootloader():
        print("[TEST] 进不了 bootloader")
        bridge.stop()
        return 1
    cli.boot_unlock(b"7.02")
    t0 = time.time()
    nblk = cli.boot_write_image_from_bytes(big)
    cli.close()
    ok_space = space.read(0x1000, len(big)) == big
    print("[TEST] 刷写 %d 块, %.2fs, 空间回读一致: %s" % (nblk, time.time() - t0, ok_space))

    # 等自动重载
    t1 = time.time()
    reloaded = False
    while time.time() - t1 < 15:
        vm.run(max_ticks=vm.ticks + 50)
        if getattr(vm, "_space_gen", -1) == getattr(space, "generation", -2):
            reloaded = True
            break
    print("[TEST] 自动重载: %s (tick=%d)" % (reloaded, vm.ticks))

    reset = struct.unpack("<I", vm.uc.mem_read(vm.img_base + 4, 4))[0]
    print("[TEST] flash 里 Reset=0x%08X (期望 0x%08X)"
          % (reset, struct.unpack("<I", big[4:8], )[0]))

    vm.run(max_ticks=vm.ticks + 6000)
    print("[TEST] 跳转后运行: pc=0x%08X fault=%s lcd=%d RF写=%d"
          % (vm.uc.reg_read(15), vm.fault or "-",
             sum(1 for b in vm.periph.lcd if b), len(vm.periph.rf.writes)))

    bridge.stop()
    ok = (ok_space and reloaded and not vm.fault
          and reset == struct.unpack("<I", big[4:8])[0])
    print("[TEST] 结果:", "通过" if ok else "失败")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
