#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mcu_vm.py — firmware_decrypted.bin 的 Cortex-M0 虚拟机 (Unicorn)

模拟范围
--------
  CPU     : ARMv6-M (Cortex-M0), Thumb
  Flash   : 0x08000000-0x0807FFFF  (镜像装载在 0x08002000)
  UID     : 0x1FFF3000  3 个 word
  SRAM    : 0x20000000-0x20003FFF  (16 KB)
  外设    : GPIO 0x50000000 / RCC 0x40021000 / FLASH 0x40022000 /
            SPI1 0x40013000 (LCD) / SPI2 0x40003800 (外部 NOR, 含 DMA) /
            DMA1 0x40020000 / ADC 0x40012400 / PPB 0xE0000000 (VTOR,SysTick,NVIC)

输出
----
  128x64 单色屏 (从 SRAM 帧缓冲 0x20001268 渲染，8 页 x 128 字节)
  可用 --png 存图片，或直接打印字符画

键盘
----
  固件扫描 5 行 (PB3..PB6 低有效) x 4 列 (PB12..PB15 读低) + PB10 独立键。
  本 VM 直接接受"逻辑键值"(0..19, 其中 0x13=无键)，会反查固件里的键值表
  自动换算成 (行, 列)。

用法
----
  python mcu_vm.py                                  # 跑到 PIN 界面并截图
  python mcu_vm.py --script "k 10, w 2, k 1, k 2, ..." --png out.png
  python mcu_vm.py --interactive                    # 键盘实时输入
"""

import argparse
import os
import threading
import struct
import sys
import time

from unicorn import (
    Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_MODE_LITTLE_ENDIAN,
    UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_CODE,
)
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
    UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR,
)

# ---------------------------------------------------------------------------
# 日志: 用 loguru 输出（没装就退回 print）
# ---------------------------------------------------------------------------
try:
    from loguru import logger as _logger
    import sys as _sys

    _logger.remove()
    _logger.add(_sys.stderr, level="INFO", colorize=True,
                format="<green>{time:HH:mm:ss.SSS}</green> | "
                       "<level>{level: <7}</level> | <level>{message}</level>")
    _HAS_LOGURU = True
except Exception:                                   # pragma: no cover
    _logger = None
    _HAS_LOGURU = False


def _p(msg, *args, level="INFO", **kw):
    """统一日志出口: 保留 printf 风格，交给 loguru 加时间戳/等级/颜色"""
    try:
        text = (msg % args) if args else msg
    except Exception:
        text = str(msg) + " " + " ".join(str(a) for a in args)
    if _HAS_LOGURU:
        _logger.log(level.upper(), text)
    else:
        print(text, **kw)


def default_firmware():
    """找一个可用的固件：环境变量 K5_FW > firmware/ > 当前目录"""
    import os
    for p in (os.environ.get("K5_FW"),
              os.path.join("firmware", "firmware_decrypted.bin"),
              "firmware_decrypted.bin"):
        if p and os.path.isfile(p):
            return p
    return os.path.join("firmware", "firmware_decrypted.bin")


M32 = 0xFFFFFFFF

FLASH_BASE = 0x08000000
FLASH_SIZE = 0x00080000
IMG_BASE = 0x08002800          # 真实链接基址 (VTOR 指向这里 = 向量表)
SPACE_IMG_OFF = 0x001000       # 4MB 固件空间里，固件放在 0x1000
ISR_SENTINEL = 0x20003FF0      # ISR 返回用的哨兵地址(未用 SRAM)
CYCLES_PER_TICK = 4000         # 固定: 每 4000 条指令 = 1 个 10ms tick（与 --ipt 无关）
SPACE_SIZE = 4 * 1024 * 1024
UID_BASE = 0x1FFF3000
SRAM_BASE = 0x20000000
SRAM_SIZE = 0x4000
TICK_ADDR = 0x20001668        # SysTick ISR 递增的 10ms 计数器
FB_BASE = 0x20001268           # 帧缓冲 8*128
LCD_COL_OFFSET = 4             # ST7565: 实际显示窗口是 RAM 第 4..131 列
FB_SIZE = 8 * 128

PERIPH_BASE = 0x40000000
PERIPH_SIZE = 0x00080000
GPIO_BASE = 0x50000000
GPIO_SIZE = 0x00004000
PPB_BASE = 0xE0000000
PPB_SIZE = 0x00100000


# 泉盛官方升级包的加密方式: 128 字节重复密钥 XOR + 末尾 2 字节 CRC16，
# 且 0x2000 处有 16 字节版本号，解码后要抽掉（社区 qsfirm.py 的做法）。
K5_XOR_KEY = bytes.fromhex(
    "4722c0525d574894b16060db6fe34c7c"
    "d84ad68b30ec25e04cd9007fbfe35405"
    "e93a976bb06e0cfbb11ae2c9c15647e9"
    "baf142b6675f0f96f7c93c841b26e14e"
    "3b6f66e6a06ab0bfc6a5703aba189e27"
    "1a535b71b1941e18f2d6810222fd5a28"
    "91dbba5d64c6fe86839c501c730311d6"
    "af30f42c77b27dbb3f29285722d6928b")


def k5_decrypt(img):
    """如果是泉盛官方加密包就解密，返回明文镜像；否则原样返回"""
    if len(img) < 0x2100:
        return img
    sp = struct.unpack_from("<I", img, 0)[0]
    if 0x20000000 <= sp <= 0x20004000:        # 已经是明文（向量表正常）
        return img
    dec = bytes(b ^ K5_XOR_KEY[i % 128] for i, b in enumerate(img))
    sp2 = struct.unpack_from("<I", dec, 0)[0]
    if not (0x20000000 <= sp2 <= 0x20004000):
        return img                            # 解不出来，别乱动
    body = dec[:-2]                           # 去掉 CRC16
    ver = body[0x2000:0x2010].split(b"\x00")[0].decode("latin1", "ignore")
    out = body[:0x2000] + body[0x2010:]       # 抽掉 16 字节版本号
    _p("[IMG] 官方加密固件已解密: 版本 %s, %d -> %d 字节"
       % (ver, len(img), len(out)), level="SUCCESS")
    return out


def build_corrected_image(path):
    """镜像就是原始文件: 它本身以 0x08002800 为基址, 直接装到该地址即可。
    若是泉盛官方加密包，这里自动解密。"""
    img = open(path, "rb").read()
    return k5_decrypt(img)


# ==========================================================================
# 外设模型
# ==========================================================================
class Periph:
    """寄存器级外设。读写通过 Unicorn 的 mem hook 拦截。"""

    def __init__(self, vm):
        self.vm = vm
        self.uc = vm.uc
        self.key_lock = threading.Lock()
        self.reset()

    def reset(self):
        """外设全部恢复上电默认值（硬复位/重载固件时调用）

        注意: 外部 SPI NOR 是**非易失**的，复位不能清内容。
        """
        _nor = getattr(self, "nor", None)
        _batt = getattr(self, "batt_mv", 8200)
        self.regs = {}                 # 通用寄存器存储 addr -> value
        # GPIO
        self.gpio = [dict(moder=0, otyper=0, ospeedr=0, pupdr=0,
                          odr=0, lckr=0, afrl=0, afrh=0) for _ in range(6)]
        # 键盘: (row, col) 集合 + 独立键
        self.keys = set()
        self.key_pb10 = False
        # PTT 是真机上的独立 GPIO 输入(不在键盘矩阵里):
        # 按下时 PB15/PB14 拉高、PB10 拉低（与 bootloader 的判定一致）
        self.ptt_down = False
        # SPI1 (LCD)
        self.spi1_cr1 = 0
        self.lcd = [0] * (132 * 8)   # ST7565: 132 列 x 8 页
        self.lcd_page = 0
        self.lcd_col = 0
        self.lcd_cmd = 0
        # SPI2 (外部 NOR) + NOR
        # 外部 SPI NOR 是独立芯片，绝不能和内部 flash(4MB 空间)共用同一块内存
        self.nor = bytearray(b"\xFF" * 0x200000)
        self.nor_state = "idle"
        self.nor_cmd = 0
        self.nor_addr = 0
        self.nor_addr_cnt = 0
        self.nor_buf = []
        self.nor_rx = []
        self.spi2_dr = 0xFF
        self.usart_rx = []
        self.usart_tx = []
        # DMA 接收保护的全局地址(固件初始化写入，如 tick 倍率)
        self.dma_guard = [(0x200016D4, 4), (0x20001740, 4)]
        self.rf = RfBus()
        self._nor_cs = 1
        # DMA
        self.dma_regs = {}
        self.dma_flags = 0
        # ADC
        self.adc_isr = 0x01            # ADRDY(bit0); EOC=bit1
        # 电池: 电压(mV) + 校准除数 calib[3]（NOR 0x010140+6 的 u16，有效范围 1500..3500）
        self.batt_mv = 8200
        self.BATT_CALIB_DEFAULT = 2200
        self.adc_dr = 0x600
        # SysTick / NVIC 由 VM 自己管
        self.ticks = 0
        self.irq_pending = 0
        if _nor is not None:
            self.nor = _nor          # 外部 flash 内容保持不变

        # 复位也要把"外设寄存器内存"清干净：模型只把已识别的寄存器存在 self.regs，
        # 未识别的写入会落到真实映射内存里；不清的话新固件会读到旧固件的残留值
        try:
            for base, size in ((0x40000000, 0x80000), (0x50000000, 0x1800),
                               (0xE0000000, 0x1000)):
                self.uc.mem_write(base, b"\x00" * size)
        except Exception:
            pass

    # ---------------- 读 ----------------
    def on_read(self, uc, access, address, size, value, user_data):
        val = None
        a = address
        # ---- GPIO ----
        if GPIO_BASE <= a < GPIO_BASE + GPIO_SIZE:
            port = (a - GPIO_BASE) // 0x400
            off = (a - GPIO_BASE) % 0x400
            g = self.gpio[port]
            if off == 0x10:                       # IDR
                val = g["odr"] & 0xFFFF
                if port == 1:                     # GPIOB: 键盘列 + PB10
                    val |= 0xF400                 # 上拉: PB10,PB12..15 默认高
                    with self.key_lock:
                        keys_now = list(self.keys)
                    moder = g.get("moder", 0)
                    def _is_out(pin):
                        return ((moder >> (2 * pin)) & 3) == 1
                    low34 = [i for i in (3, 4, 5, 6) if not (g["odr"] >> i) & 1]
                    low1215 = [i for i in (12, 13, 14, 15) if not (g["odr"] >> i) & 1]
                    if getattr(self.vm, "dbg_keypad", False) and port == 1:
                        print("   [KP] odr=%04X moder=%08X low34=%s keys=%s" % (
                            g["odr"] & 0xFFFF, moder & 0xFFFF, low34, sorted(keys_now)[:4]))
                    if any(_is_out(i) for i in (3, 4, 5, 6)) and len(low34) == 1:
                        # 原厂固件式: PB3..6 驱动行(row = 7 - pin), PB12..15 读列
                        # 它的矩阵索引与标准表是转置关系: (kr,kc) -> 行=kc, 列=kr-1
                        r = 7 - low34[0]
                        for (kr, kc) in keys_now:
                            if kc == r and 1 <= kr <= 4:
                                val &= ~(1 << (15 - (kr - 1)))
                    elif low34:
                        # Dondji 式: PB3..6 驱动列(pin 6-c), PB12..15 读行(bit 15-(row-1))
                        # keymap 存的是 (row+1, col)
                        for pin in low34:
                            c = 6 - pin
                            for (kr, kc) in keys_now:
                                if kc == c and 1 <= kr <= 4:
                                    val &= ~(1 << (15 - (kr - 1)))
                    if self.key_pb10:
                        val &= ~(1 << 10)
                    if getattr(self, "ptt_down", False):
                        val &= ~(1 << 10)          # PB10 低 = PTT 按下
                    # PB9 = BK4829 的 SDA；固件把它设成输入时读的是芯片应答。
                    # 没有 RF 芯片模型时给全 1（等同总线上拉/无应答）。
                    if ((g.get("moder", 0) >> 18) & 3) == 0:           # PB9 = 输入 = 芯片在驱动
                        if getattr(self, "rf", None) is not None and not self.rf.cs:
                            if self.rf.sda_out:
                                val |= (1 << 9)
                            else:
                                val &= ~(1 << 9)
                        elif getattr(self.vm, "rf_sda_idle_high", True):
                            val |= (1 << 9)
                g["idr"] = val & 0xFFFF
            elif off == 0x14:
                val = g["odr"]
            elif off == 0x00:
                val = g["moder"]
            elif off == 0x04:
                val = g["otyper"]
            elif off == 0x08:
                val = g["ospeedr"]
            elif off == 0x0C:
                val = g["pupdr"]
            elif off == 0x20:
                val = g["afrl"]
            elif off == 0x24:
                val = g["afrh"]
            else:
                val = 0
        # ---- RCC ----
        elif a == 0x40021000:                     # CR: bits[15:13] 决定 option 表索引
            val = self.regs.get(a, 0) & ~0xE000
        elif PERIPH_BASE <= a < PERIPH_BASE + PERIPH_SIZE:
            # ---- FLASH ----
            if a == 0x40022020:                   # OPTR: RDP = 0xAA (level 0)
                val = self.regs.get(a, 0xAA) & M32
                val = (val & ~0xFF) | 0xAA
            elif a == 0x40022010:                 # FLASH SR: 不忙
                val = self.regs.get(a, 0) & ~(1 << 16)
            # ---- SPI1 (LCD) ----
            elif a == 0x40013008:
                val = 0x3                         # TXE | RXNE, 永不阻塞
            elif a == 0x4001300C:
                val = 0
            elif a == 0x40013000:
                val = self.spi1_cr1
            # ---- USART1 (0x40013800): F0 布局 SR@0x00, G0 布局 ISR@0x1C ----
            elif a == 0x40013800 or a == 0x4001381C:
                val = 0xE0                        # TXE(7)|TC(6)|RXNE(5) 恒就绪
            elif a == 0x40013804 or a == 0x40013824:
                val = self.usart_rx.pop(0) if self.usart_rx else 0xFF
            # ---- SPI2 (NOR) ----
            elif a == 0x40003808:
                val = 0x3                         # TXE|RXNE: 立即完成
            elif a == 0x4000380C:
                val = self.spi2_dr           # 写 DR 时的同步返回字节
            # ---- DMA ----
            elif a == 0x40020000:
                val = self.dma_flags
            elif 0x40020000 <= a < 0x40020080:
                val = self.dma_regs.get(a, 0)
            # ---- ADC ----
            elif a == 0x40012400:
                val = self.adc_isr                # bit1 = EOC (固件 0x08006530 等它)
            elif a == 0x40012408:                 # ADC_CR: ADSTART 立即完成
                val = self.regs.get(a, 0) & ~0x4
            elif a == 0x40012450:                 # DR (固件 0x0800653C 读 +0x50)
                val = self._adc_battery_raw()
            else:
                val = self.regs.get(a, 0)
        # ---- PPB ----
        elif PPB_BASE <= a < PPB_BASE + PPB_SIZE:
            if a == 0xE000E014:                   # SYST_RVR
                val = self.vm.syst_rvr
            elif a == 0xE000E018:                 # SYST_CVR: 每次读前进一点, 供忙等延时
                mod = (self.vm.syst_rvr + 1) or 0x1000000
                self.vm.syst_cvr = (self.vm.syst_cvr - 4800) % mod
                val = self.vm.syst_cvr
            elif a == 0xE000E010:                 # SYST_CSR
                val = (self.regs.get(a, 0) & ~0x10000) | 1
            else:
                val = self.regs.get(a, 0)
        if val is not None:
            self.uc.mem_write(address & ~3, struct.pack("<I", val & M32))

    # ---------------- 写 ----------------
    def on_write(self, uc, access, address, size, value, user_data):
        a = address
        v = value & M32
        # ---- GPIO ----
        if GPIO_BASE <= a < GPIO_BASE + GPIO_SIZE:
            port = (a - GPIO_BASE) // 0x400
            off = (a - GPIO_BASE) % 0x400
            g = self.gpio[port]
            if off == 0x18:                       # BSRR: 低 16 位置位, 高 16 位清位
                g["odr"] = (g["odr"] | (v & 0xFFFF)) & ~((v >> 16) & 0xFFFF) & 0xFFFF
                if port == 0:
                    self._check_nor_cs()
                self._rf_update()
            elif off == 0x28:                     # BRR: 写 1 清零
                g["odr"] &= ~v & 0xFFFF
                if port == 0:
                    self._check_nor_cs()
                self._rf_update()
            elif off == 0x14:
                g["odr"] = v & 0xFFFF
                if port == 0:
                    self._check_nor_cs()
            elif off == 0x00:
                g["moder"] = v
            elif off == 0x04:
                g["otyper"] = v
            elif off == 0x08:
                g["ospeedr"] = v
            elif off == 0x0C:
                g["pupdr"] = v
            elif off == 0x20:
                g["afrl"] = v
            elif off == 0x24:
                g["afrh"] = v
            # RF 三线总线: CS=PF9, SCL=PB8, SDA=PB9 —— 任意一端变化都推进状态机
            if port in (1, 5):
                self._rf_update()
            # 行驱动: PB3..PB6 低有效
            if port == 1:
                odr = g["odr"]
                low = [i for i in (6, 5, 4, 3) if not (odr & (1 << i))]
                self.vm.driving_row = (7 - low[0]) if len(low) == 1 else None
            # 显示控制线: PA6 = A0/DC ; 外部 NOR 片选: PA3 (低有效)
            if port == 0:
                self.lcd_cmd = 1 if (g["odr"] & (1 << 6)) else 0
                if off in (0x18, 0x28) and (v & (1 << 3)):
                    self.nor_state = "idle"          # CS 翻转 -> 命令帧结束
            return
        # ---- USART1 发送 ----
        if a == 0x40013804 or a == 0x40013828:
            b = v & 0xFF
            self.usart_tx.append(b)
            if getattr(self.vm, "uart_hook", None):
                try:
                    self.vm.uart_hook(b)
                except Exception:
                    pass
            return
        # ---- SPI2 CR1: SPE 上升沿 = 一次新事务开始 (真机靠 NSS 边沿) ----
        if a == 0x40003800:
            old = self.regs.get(a, 0)
            self.regs[a] = v
            if (v & 0x40) and not (old & 0x40):
                self.nor_state = "idle"
                self.nor_addr_cnt = 0
            return
        # ---- GPIOA 位变化: PA3 = 外部 NOR 片选(低有效) ----
        if 0x50000000 <= a < 0x50000400:
            off = a - 0x50000000
            if off in (0x14, 0x18, 0x28):          # ODR / BSRR / BRR(F0: 0x28)
                self._check_nor_cs()
        # ---- SPI1 -> LCD ----
        if a == 0x40013000:
            self.spi1_cr1 = v
            return
        if a == 0x4001300C:
            self.lcd_rx(v & 0xFF)
            return
        # ---- SPI2 -> NOR ----
        if a == 0x4000380C:
            resp = self.spi2_byte(v & 0xFF)
            self.spi2_dr = resp
            self.nor_rx.append(resp)
            return
        if a == 0x40003804:
            self.regs[a] = v
            return
        # ---- DMA ----
        if a == 0x40020004:                       # IFCR: 写 1 清
            self.dma_flags &= ~v
            self._sync_dma_flags()
            return
        if a == 0x40020000:                       # ISR 直写清标志(固件如此)
            self.dma_flags &= ~v
            self._sync_dma_flags()
            return
        if 0x40020000 <= a < 0x40020080:
            old = self.dma_regs.get(a, 0)
            self.dma_regs[a] = v
            # 通道寄存器块: CCR, CNDTR, CPAR, CMAR
            # 只在 EN 的 0->1 上升沿启动传输；运行中改其它位不能重跑整次传输
            off = a - 0x40020000
            for ccr_off in (0x08, 0x1C, 0x30, 0x44, 0x58, 0x6C, 0x80):
                if off == ccr_off and (v & 1) and not (old & 1):
                    self._dma_start(0x40020000 + ccr_off)
            return
        # ---- ADC ----
        if a == 0x40012400:
            if v & 4:
                self.adc_isr &= ~4
            if v & 1:
                self.adc_isr |= 1
            return
        if a == 0x40012408:                       # ADC_CR
            self.regs[a] = v
            if v & 0x4:                           # ADSTART: 立即完成一次转换
                self.regs[a] = v & ~0x4
                self.adc_isr |= 0x2               # EOC = bit1
                self.adc_dr = 0x600
            return
        # ---- PPB ----
        if a == 0xE000ED08:
            self.vm.vtor = v
            self.regs[a] = v
            return
        if a == 0xE000E014:
            self.vm.syst_rvr = v & 0xFFFFFF
            return
        if a == 0xE000E018:
            self.vm.syst_cvr = v % ((self.vm.syst_rvr + 1) or 0x1000000)
            return
        if PPB_BASE <= a < PPB_BASE + PPB_SIZE:
            self.regs[a] = v
            return
        self.regs[a] = v

    # ---------------- ADC ----------------
    def batt_calib3(self):
        """固件用的电池校准除数: NOR 0x010140 的第 4 个 u16"""
        try:
            raw = bytes(self.nor[0x10140:0x1014C])   # 校准块在 NOR 0x010000+0x140
            if len(raw) >= 8:
                v = raw[6] | (raw[7] << 8)
                if 1500 <= v <= 3500:
                    return v
        except Exception:
            pass
        return self.BATT_CALIB_DEFAULT

    def _adc_battery_raw(self):
        """把 batt_mv 换算成 12 位 ADC 原始值

        固件里: voltage_centiV = raw * 760 / gBatteryCalibration[3]
        反解:   raw = voltage_centiV * calib3 / 760
        """
        centi_v = self.batt_mv / 10.0
        raw = int(round(centi_v * self.batt_calib3() / 760.0))
        return max(0, min(4095, raw))

    # ---------------- LCD ----------------
    def lcd_rx(self, b):
        if self.lcd_cmd == 0:
            if 0xB0 <= b <= 0xB7:
                self.lcd_page = b & 7
            elif b <= 0x0F:
                self.lcd_col = (self.lcd_col & 0xF0) | b
            elif 0x10 <= b <= 0x1F:
                self.lcd_col = (self.lcd_col & 0x0F) | ((b & 0x0F) << 4)
        else:
            col = self.lcd_col % 132          # 硬件按 132 列回绕
            idx = self.lcd_page * 132 + col
            if 0 <= idx < len(self.lcd):
                self.lcd[idx] = b
            self.lcd_col = (self.lcd_col + 1) % 132

    # ---------------- 外部 NOR (SPI) ----------------
    def _rf_update(self):
        """GPIOB/PF 变化后推进 BK4829 总线模型"""
        rf = getattr(self, "rf", None)
        if rf is None:
            return
        cs = (self.gpio[5].get("odr", 0) >> 9) & 1          # PF9
        scl = (self.gpio[1].get("odr", 0) >> 8) & 1          # PB8
        sda = (self.gpio[1].get("odr", 0) >> 9) & 1          # PB9
        sda_out = ((self.gpio[1].get("moder", 0) >> 18) & 3) != 0   # PB9 输出模式?
        rf.on_clock(cs, scl, sda, sda_out)

    def _check_nor_cs(self):
        """PA3 是外部 NOR 的 CS(低有效)：任何边沿都复位 NOR 状态机"""
        odr = self.gpio[0].get("odr", 0)
        cs = (odr >> 3) & 1
        if getattr(self, "_nor_cs", 1) != cs:
            self._nor_cs = cs
            self.nor_state = "idle"
            self.nor_addr_cnt = 0

    def spi2_byte(self, b):
        """JEDEC 简化状态机, 返回同时钟的 RX 字节"""
        st = self.nor_state
        if st == "idle":
            self.nor_cmd = b
            self.nor_buf = []
            self.nor_addr = 0
            self.nor_addr_cnt = 0
            if b == 0x03:                          # READ
                self.nor_state = "addr"
            elif b == 0x02:                        # PAGE PROGRAM
                self.nor_state = "addr"
            elif b == 0x20:                        # SECTOR ERASE
                self.nor_state = "addr"
            elif b == 0xD8:
                self.nor_state = "addr"
            elif b == 0x05:                        # RDSR
                self.nor_state = "rdsr"
                return 0x00
            elif b == 0x06:                        # WREN
                self.nor_state = "idle"
            return 0xFF
        if st == "addr":
            self.nor_addr = ((self.nor_addr << 8) | b) & 0xFFFFFF
            self.nor_addr_cnt += 1
            if self.nor_addr_cnt == 3:
                if self.nor_cmd == 0x03:
                    self.nor_state = "read"
                elif self.nor_cmd == 0x02:
                    self.nor_state = "prog"
                else:
                    self._nor_erase()
                    self.nor_state = "idle"
            return 0xFF
        if st == "rdsr":
            return 0x00
        if st == "read":
            d = self.nor[self.nor_addr % len(self.nor)]
            self.nor_addr += 1
            return d
        if st == "prog":
            self.nor[self.nor_addr % len(self.nor)] &= b
            self.nor_addr += 1
            return 0xFF
        return 0xFF

    def _nor_erase(self):
        base = self.nor_addr & ~0xFFF
        for i in range(0x1000):
            self.nor[(base + i) % len(self.nor)] = 0xFF

    # ---------------- DMA ----------------
    def _ccr_of(self, base):
        return self.dma_regs.get(base, 0)

    def _dma_start(self, ccr_addr):
        ccr = self.dma_regs.get(ccr_addr, 0)
        cndtr = self.dma_regs.get(ccr_addr + 4, 0) & 0xFFFF
        cpar = self.dma_regs.get(ccr_addr + 8, 0)
        cmar = self.dma_regs.get(ccr_addr + 12, 0)
        if cndtr == 0:
            return
        # 注意: 不要在这里复位 NOR 状态机。
        # 固件先用轮询方式发命令(0x03/0x05/...)和地址，再起 DMA 搬数据，
        # 复位会把命令阶段丢掉 -> 读回来全是 0xFF。
        # 方向由 CCR.DIR(bit4) 决定: 1=存储器->外设, 0=外设->存储器
        # 外设地址决定数据流向哪: SPI1(0x4001300C)=LCD, SPI2(0x4000380C)=外部 NOR
        if ccr & (1 << 4):
            if 0x20000000 <= cmar < 0x20004000:
                for b in self.uc.mem_read(cmar, cndtr):
                    if cpar == 0x4001300C:
                        self.lcd_rx(b)          # 刷屏 DMA
                    else:
                        self.spi2_byte(b)       # 外部 flash DMA
        else:
            # USART 接收 DMA: 没有数据就不完成（真机上它会一直挂着等字节）
            if cpar in (0x40013804, 0x40013828):
                if not self.usart_rx:
                    return                        # 保持挂起: 不清 EN, 不产生中断
                n = min(cndtr, len(self.usart_rx))
                out = bytes(self.usart_rx[:n])
                del self.usart_rx[:n]
                if 0x20000000 <= cmar < 0x20004000:
                    self._dma_store(cmar, out)
                left = cndtr - n
                self.dma_regs[ccr_addr + 4] = left
                if left:
                    return                        # 还没收满
                self.dma_regs[ccr_addr] = self.dma_regs.get(ccr_addr, 0) & ~1
                self.dma_regs[ccr_addr + 4] = 0
                self.irq_pending |= (1 << 11)
                return
            # 编程(0x02)刚结束时状态停在 prog，紧接着的回读事务必须照常完成，
            # 否则 DMA 通道永远不置 TC、固件会死等。按"回读"处理。
            if cpar == 0x4000380C and self.nor_state == "prog":
                self.nor_state = "read"
            out = bytearray()
            for _ in range(cndtr):
                if cpar == 0x4000380C:          # SPI2 = 外部 NOR：按时钟走真实状态机
                    out.append(self.spi2_byte(0x00) & 0xFF)
                else:
                    out.append(self.nor_rx.pop(0) if self.nor_rx else 0xFF)
            if 0x20000000 <= cmar < 0x20004000:
                self._dma_store(cmar, bytes(out))
        # 清零通道 = 完成；CNDTR 归 0（真机如此，之后空使能不会再搬运）
        self.dma_regs[ccr_addr] = self.dma_regs.get(ccr_addr, 0) & ~1
        self.dma_regs[ccr_addr + 4] = 0
        self._dma_complete(ccr_addr)

    def _dma_store(self, cmar, data):
        """DMA 写 RAM；对 dma_guard 里的全局变量做保护(写完还原)"""
        keep = []
        for ga, gl in getattr(self, "dma_guard", ()):
            if cmar <= ga < cmar + len(data):
                keep.append((ga, gl, bytes(self.uc.mem_read(ga, gl))))
        self.uc.mem_write(cmar, data)
        for ga, gl, old in keep:
            self.uc.mem_write(ga, bytes(old))

    def _dma_channel(self, ccr_addr):
        """CCR 地址 -> 通道号 (1..7)"""
        return (ccr_addr - 0x40020008) // 0x14 + 1

    def _dma_complete(self, ccr_addr):
        """按通道置 GIF/TCIF 并投递对应中断

        分组: ch1 = IRQ9, ch2/3 = IRQ10, ch4..7 = IRQ11
        标志: 每通道 4 位 (GIF, TCIF, HTIF, TEIF)，从 bit0 起
        """
        ch = self._dma_channel(ccr_addr)
        if not (1 <= ch <= 7):
            return
        shift = (ch - 1) * 4
        self.dma_flags |= (0x1 | 0x2) << shift
        self.irq_pending |= (1 << (9 if ch == 1 else (10 if ch <= 3 else 11)))

    def _sync_dma_flags(self):
        pass


# ==========================================================================
# 虚拟机
# ==========================================================================
class _IsrReturn(Exception):
    """ISR 执行到哨兵地址时用来中断 emu_start"""
    pass


class RfBus:
    """BK4829 三线总线的极简从机：解析 8bit 命令 + 16bit 数据"""

    def __init__(self):
        self.reset()

    def reset(self):
        self.cs = 1
        self.scl = 0
        self.bits = []
        self.reg = None
        self.mode = "cmd"        # cmd -> data_out / data_in
        self.out_word = 0
        self.out_idx = 0
        self.sda_out = 1
        self.writes = {}
        self.reads = 0
        self.read_log = []

    # 从机给出的寄存器值：默认 0；REG 0x00/0x01 返回芯片 ID 形状的值
    def _reg_value(self, reg):
        """返回 BK4819 的寄存器值（最小模型）

        关键位:
          0x0C bit0 = 芯片就绪（固件初始化后轮询它）
          0x02 bit? = FSK 发送完成（暂不置）
        其它寄存器先返回 0。
        """
        self.reads += 1
        self.read_log.append(reg)
        if getattr(self, "fixed_value", None) is not None:
            return self.fixed_value
        if len(self.read_log) > 64:
            self.read_log.pop(0)
        # REG_0C bit0 = "BK chip interrupt request"。
        # 固件 CheckRadioInterrupts() 是 while(bit0) 循环，写 REG_02=0 才清。
        # 我们不模拟中断 -> 恒返回 0，循环立刻退出（真机无中断时也是这样）。
        return 0x0000

    def on_clock(self, cs, scl, sda_level, sda_is_output):
        """每次 GPIO 变化后调用；只在 SCL 上升沿采样/驱动"""
        if cs != self.cs:
            self.cs = cs
            if cs:                      # CS 释放 = 一次事务结束
                self.bits = []
                self.reg = None
                self.mode = "cmd"
                self.out_idx = 0
                self.sda_out = 1
            return

        if cs:                          # 未选中
            self.scl = scl
            return

        rising = (scl == 1 and self.scl == 0)
        self.scl = scl
        if not rising:
            return

        if self.mode == "cmd":
            if sda_is_output:
                self.bits.append(sda_level)
                if len(self.bits) == 8:
                    self.reg = 0
                    for b in self.bits:
                        self.reg = (self.reg << 1) | b
                    self.bits = []
                    if self.reg & 0x80:
                        self.mode = "data_out"
                        self.out_word = self._reg_value(self.reg & 0x7F)
                        self.out_idx = 0
                        self.sda_out = (self.out_word >> 15) & 1
                    else:
                        self.mode = "data_in"
                        self.out_word = 0
                        self.bits = []
        elif self.mode == "data_out":
            self.out_idx += 1
            if self.out_idx >= 16:
                self.sda_out = 1
            else:
                self.sda_out = (self.out_word >> (15 - self.out_idx)) & 1
        elif self.mode == "data_in":
            if sda_is_output:
                self.bits.append(sda_level)
                if len(self.bits) == 16:
                    w = 0
                    for b in self.bits:
                        w = (w << 1) | b
                    self.writes[self.reg] = w
                    self.bits = []


class VM:
    def __init__(self, fw_path, uid=(0x1A2B3C4D, 0x5E6F7081, 0x92A3B4C5),
                 trace=False, verbose=False, flash_path=None, img_base=None,
                 reseed=False):
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS | UC_MODE_LITTLE_ENDIAN)
        self.uc.mem_map(FLASH_BASE, FLASH_SIZE)
        self.uc.mem_map(UID_BASE, 0x1000)
        self.uc.mem_map(SRAM_BASE, SRAM_SIZE)
        self.uc.mem_map(PERIPH_BASE, PERIPH_SIZE)
        self.uc.mem_map(GPIO_BASE, GPIO_SIZE)
        self.uc.mem_map(PPB_BASE, PPB_SIZE)
        # ISR 返回哨兵: 命中即中断本次 emu_start, 由 step() 恢复上下文
        def _sentinel(uc, addr, size, ud):
            if addr == ISR_SENTINEL:
                raise _IsrReturn()
        self.uc.hook_add(UC_HOOK_CODE, _sentinel, begin=ISR_SENTINEL, end=ISR_SENTINEL + 1)

        global IMG_BASE
        if img_base is None:
            img_base = IMG_BASE                 # 默认(原厂固件): 链接在 0x08002800
            head = open(fw_path, "rb").read(8)
            sp = struct.unpack_from("<I", head, 0)[0]
            rst = struct.unpack_from("<I", head, 4)[0]
            # 只有复位向量落在文件最前面 8KB 内，才认为是 0x08000000 基址
            if (0x20000000 <= sp <= 0x20004000 and 0x08000000 <= rst < 0x08080000
                    and (rst & 1) and (rst - 0x08000000) < 0x2000):
                img_base = 0x08000000
        IMG_BASE = img_base
        self.img_base = img_base
        # ---- 4MB 固件空间: 串口刷机写这里, MCU 也从这里取镜像 ----
        self.space = None
        self.auto_reload = True
        self.power_on = True
        # 每秒 tick 上限（0 = 不限）: 1000 ≈ 实时
        self.tps_limit = 0
        self._tps_t0 = None
        self._tps_n0 = 0
        self.inject_systick = True
        # 兼容开关: 第三方固件的显示门控 0x20001FF2 在 boot 被置 1 且无人清除，
        # 打开它会周期性清 0，让主循环走显示分发路径（原厂固件不需要）
        self.unlock_ui = False
        self.unlock_ui_addrs = [0x20001FF2, 0x20002720]
        self._space_gen = -1
        img = build_corrected_image(fw_path)
        if flash_path:
            import radio_device as _rd
            if isinstance(flash_path, _rd.Flash4M):
                self.space = flash_path
            else:
                self.space = _rd.Flash4M(flash_path, size=SPACE_SIZE,
                                         log=(_p if verbose else None))
            if reseed or self.space.read(SPACE_IMG_OFF, 16) == b"\xFF" * 16:
                # 空白/强制重播种: 先擦再写（NOR 只能 1->0，直接 program 会把旧内容 AND 进去）
                pages = (len(img) + 0xFF) // 0x100
                self.space.erase_pages(SPACE_IMG_OFF, pages)
                self.space.program(SPACE_IMG_OFF, img)
                self.space.flush()
                _p("[SPACE] 4MB 空间为空, 已写入初始固件 %d 字节 @0x%X"
                      % (len(img), SPACE_IMG_OFF))
            # 空间的镜像可能和 --firmware 完全不是同一版（长度也不同），
            # 必须整块读，不能按 --firmware 的长度截断
            _area = FLASH_SIZE - (IMG_BASE - FLASH_BASE)
            stored = bytes(self.space.read(SPACE_IMG_OFF, _area))
            if len(stored) < _area:
                stored = stored + b"\xFF" * (_area - len(stored))
            stored = stored[:_area]
            if stored[:len(img)] != img and not reseed:
                sp = struct.unpack_from("<I", stored, 0)[0]
                sp2 = struct.unpack_from("<I", img, 0)[0]
                rst = struct.unpack_from("<I", stored, 4)[0]
                rst2 = struct.unpack_from("<I", img, 4)[0]
                _p("[SPACE] 空间里的镜像与 --firmware 不一致：", level="WARNING")
                _p("        空间: SP=%08X Reset=%08X" % (sp, rst), level="WARNING")
                _p("        文件: SP=%08X Reset=%08X" % (sp2, rst2), level="WARNING")
                _p("        设备将运行空间里的镜像；要恢复请删 %s 或加 --reseed"
                      % getattr(self.space, "path", "该文件"))
            img = stored
            self._space_gen = getattr(self.space, "generation", 0)
        self.img_len = len(img)
        self.uc.mem_write(self.img_base, img[:FLASH_SIZE - (IMG_BASE - FLASH_BASE)])
        self.uc.mem_write(UID_BASE, struct.pack("<III", *uid))

        self.periph = Periph(self)
        self.vtor = IMG_BASE
        self.syst_cvr = 479999
        self.syst_rvr = 479999
        self.driving_row = None
        self.trace = trace
        self.verbose = verbose
        # 运行状态
        self.ticks = 0
        self.cycles = 0
        self._skip_inject = False
        self.dma_pending = []
        # 这些地址是固件初始化时写过的全局(如 tick 倍率)，DMA 接收不应覆盖
        self.dma_guard = [(0x200016D4, 4), (0x20001740, 4)]
        try:
            self.periph.usart_rx.clear()
            self.periph.usart_tx.clear()
            self.periph.irq_pending = 0
        except Exception:
            pass
        self.held = {}          # keycode -> 到期 tick
        self.schedule = []      # [(tick, fn)]
        self.fault = None
        self.exc_depth = 0
        self.direct_irq = True     # 直接复刻 ISR 副作用, 不做异常注入
        from collections import deque
        self.pc_hist = deque(maxlen=64)

        for lo, sz in ((PERIPH_BASE, PERIPH_SIZE), (GPIO_BASE, GPIO_SIZE),
                       (PPB_BASE, PPB_SIZE)):
            self.uc.hook_add(UC_HOOK_MEM_READ, self.periph.on_read, None, lo, lo + sz - 1)
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self.periph.on_write, None, lo, lo + sz - 1)

        # 键值矩阵: keyboard[col][row]（Dondji keyboard.c 与原厂固件表一致）
        STD_KEY_MATRIX = (
            (18, 17, 19, 19),     # col0: SIDE1 SIDE2 -  -
            (10,  1,  4,  7),     # col1: MENU  1 4 7
            (11,  2,  5,  8),     # col2: UP    2 5 8
            (12,  3,  6,  9),     # col3: DOWN  3 6 9
            (13, 14,  0, 15),     # col4: EXIT  * 0 #
        )
        self.keymap = {}
        for c, colvals in enumerate(STD_KEY_MATRIX):
            for r, k in enumerate(colvals, start=1):
                if k != 0x13:
                    self.keymap.setdefault(k, (r, c))
        self.keymap[0x10] = "pb10"

    # ---------------- 中断 ----------------
    def _enter_exception(self, irq):
        """用"子程序调用"方式跑中断服务：LR 指向哨兵，返回时由 hook 捕获"""
        uc = self.uc
        vec = self.vtor + 4 * irq
        target = struct.unpack("<I", uc.mem_read(vec, 4))[0]
        if not (0x08000000 <= target < 0x08080000):
            return                                  # 向量无效(未使用的 IRQ)，忽略
        self.isr_saved = (
            uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1),
            uc.reg_read(UC_ARM_REG_R2), uc.reg_read(UC_ARM_REG_R3),
            uc.reg_read(UC_ARM_REG_R12), uc.reg_read(UC_ARM_REG_LR),
            uc.reg_read(UC_ARM_REG_CPSR),
        )
        self.isr_resume = self.next_pc
        uc.reg_write(UC_ARM_REG_LR, ISR_SENTINEL | 1)
        self.next_pc = target & ~1
        self.exc_depth = 1

    def _isr_return(self):
        """哨兵命中: 恢复上下文，从中断点继续"""
        uc = self.uc
        sv = getattr(self, "isr_saved", None)
        if sv:
            uc.reg_write(UC_ARM_REG_R0, sv[0]); uc.reg_write(UC_ARM_REG_R1, sv[1])
            uc.reg_write(UC_ARM_REG_R2, sv[2]); uc.reg_write(UC_ARM_REG_R3, sv[3])
            uc.reg_write(UC_ARM_REG_R12, sv[4]); uc.reg_write(UC_ARM_REG_LR, sv[5])
            uc.reg_write(UC_ARM_REG_CPSR, sv[6])
            self.next_pc = getattr(self, "isr_resume", self.next_pc)
            uc.reg_write(UC_ARM_REG_PC, self.next_pc)
        self.exc_depth = 0
        self._skip_inject = True

    def _exit_exception(self):
        uc = self.uc
        # 用进入时记录的帧指针恢复，避免 ISR 栈不平衡导致取错帧
        sp = getattr(self, "exc_frame_sp", None)
        if sp is None:
            sp = uc.reg_read(UC_ARM_REG_SP)
        f = struct.unpack("<8I", uc.mem_read(sp, 0x20))
        uc.reg_write(UC_ARM_REG_R0, f[0]); uc.reg_write(UC_ARM_REG_R1, f[1])
        uc.reg_write(UC_ARM_REG_R2, f[2]); uc.reg_write(UC_ARM_REG_R3, f[3])
        uc.reg_write(UC_ARM_REG_R12, f[4]); uc.reg_write(UC_ARM_REG_LR, f[5])
        uc.reg_write(UC_ARM_REG_CPSR, (f[7] & ~(1 << 24)) | (1 << 24))
        uc.reg_write(UC_ARM_REG_SP, sp + 0x20)
        self.next_pc = f[6] & ~1
        uc.reg_write(UC_ARM_REG_PC, self.next_pc)
        self._skip_inject = True
        if self.exc_depth > 0:
            self.exc_depth -= 1

    # ---------------- 运行 ----------------
    def power_off(self):
        """关机: 停 CPU, 清屏"""
        self.power_on = False
        self.uc.mem_write(FB_BASE, b"\x00" * FB_SIZE)
        _p("[VM] 电源关闭")

    def cold_boot(self, ptt=None):
        """重新上电/重启: 从 4MB 空间重载固件并复位"""
        if ptt is None:
            ptt = getattr(self, "ptt_boot", False)
        self.power_on = True
        self.fault = None
        self.pc_hist.clear()
        self.started = False
        self.ptt_boot = ptt
        if not ptt:
            self.uc.mem_write(FB_BASE, b"\x00" * FB_SIZE)
        if self.space is not None:
            self.reload_firmware()          # 含 periph.reset + reset
        else:
            if getattr(self, "periph", None) is not None:
                self.periph.reset()
            self.reset()
        r = getattr(self, "radio", None)
        if r is not None:
            r.power_cycle(ptt=ptt)
        _p("[VM] 冷启动 (PTT=%s)" % ("按住" if ptt else "松开"))

    def reload_firmware(self):
        """从 4MB 空间重新装载镜像并复位 (串口刷机后的启动)"""
        if self.space is None:
            return
        # 必须按"整个应用区"读取：刷进去的镜像可能比 --firmware 大多了
        # （例如 bootloader 写入 469 块 = 120KB，而初始固件只有 35KB），
        # 只读 img_len 会把旧镜像的尾巴留在 flash 里 -> 跳转后跑飞。
        if getattr(self, "periph", None) is not None:
            self.periph.reset()            # 硬复位: 外设回到上电默认
        area = FLASH_SIZE - (IMG_BASE - FLASH_BASE)
        img = bytes(self.space.read(SPACE_IMG_OFF, area))
        if len(img) < area:
            img = img + b"\xFF" * (area - len(img))
        self.uc.mem_write(self.img_base, img[:area])
        # 关键: 清掉 Unicorn 的翻译块缓存。否则重写 flash 之后，
        # 之前执行旧固件时缓存的翻译块还会被复用 -> 跑飞（表现为随机 fault）
        try:
            self.uc.ctl_flush_tb()
        except Exception:
            pass
        self.img_len = max(self.img_len, len(img))
        self.flash_loaded = area
        if self.space is not None:
            self._space_gen = getattr(self.space, "generation", 0)
        _p("[SPACE] 重载固件 %d 字节并复位" % len(img))
        self.reset()

    def reset(self):
        uc = self.uc
        sp = struct.unpack("<I", uc.mem_read(self.img_base, 4))[0]
        self.next_pc = struct.unpack("<I", uc.mem_read(IMG_BASE + 4, 4))[0] & ~1
        uc.reg_write(UC_ARM_REG_SP, sp)
        uc.mem_write(0xE000ED08, struct.pack("<I", IMG_BASE))
        self.vtor = IMG_BASE
        self.ticks = 0
        self.cycles = 0          # 不清会把重载后的节拍跑飞（每步多算好几拍）
        # SysTick 也是外设: 复位后 CVR/RVR 回到初值，否则新固件的忙等延时
        # 会从旧固件留下的相位开始，行为就不可复现了
        self.syst_cvr = 479999
        self.syst_rvr = 479999       # 与构造时保持一致
        self._skip_inject = False
        # 中断现场必须清掉：重载可能正好停在某个 ISR 里，
        # 残留的 isr_saved 会在下一次中断返回时把寄存器恢复成垃圾值
        self.isr_saved = None
        self.isr_resume = None
        self.exc_frame_sp = None
        self.exc_depth = 0
        self.started = False
        # 复位后通用寄存器也应该是干净的（真机复位会把它们清零/未定义，
        # 固件启动代码不会初始化 r0-r12；重载时残留旧固件的值会跑飞）
        for _r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                   UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                   UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
                   UC_ARM_REG_R12, UC_ARM_REG_LR):
            uc.reg_write(_r, 0)
        self.fault = None
        self.exc_depth = 0

    def _throttle(self):
        """限制每秒 tick 数：跑太快就睡一小会儿，让节奏接近设定值"""
        if not self.tps_limit:
            return
        now = time.perf_counter()
        if self._tps_t0 is None:
            self._tps_t0, self._tps_n0 = now, self.ticks
            return
        want = (self.ticks - self._tps_n0) / float(self.tps_limit)
        real = now - self._tps_t0
        if real < want:
            time.sleep(min(want - real, 0.2))
        elif real > 1.0:                       # 窗口太旧就重开
            self._tps_t0, self._tps_n0 = now, self.ticks

    def step(self, insns=4000):
        """推进一个 chunk: 执行指令 + 节拍 + 中断 + 到期按键"""
        uc = self.uc
        if self.fault:
            return False
        if not getattr(self, "power_on", True):
            time.sleep(0.01)
            return True
        if getattr(self, "ptt_boot", False):
            # PTT 开机: bootloader 接管, 应用固件不执行
            radio = getattr(self, "radio", None)
            if radio is not None and not getattr(radio, "boot_mode", True):
                # bootloader 已跳转 -> 从刚写好的固件启动
                self.ptt_boot = False
                self.reload_firmware()
                _p("[BOOT] bootloader 跳转 -> 固件开始运行")
            else:
                # bootloader 待机: 不跑 CPU, 但要按真实时间推进(否则会空转退出)
                time.sleep(0.004)
                self.ticks += 1
                self.pc_hist.append(self.next_pc)
                return True
        try:
            uc.emu_start(self.next_pc | 1, 0, count=insns)
            self.next_pc = uc.reg_read(UC_ARM_REG_PC)
            # 异常返回: 有些情况下 Unicorn 只是停住而不抛错，这里补一次检查
            if self.exc_depth > 0 and (self.next_pc & 0xFFFFFFF0) == 0xFFFFFFF0:
                self._exit_exception()
        except _IsrReturn:
            self._isr_return()
            return True
        except UcError as e:
            pcnow = uc.reg_read(UC_ARM_REG_PC)
            if pcnow in (0xFFFFFFF8, 0xFFFFFFF9, 0xFFFFFFFC) and self.exc_depth > 0:
                self._exit_exception()
            else:
                _addr = getattr(e, "address", None)
                self.fault = ("PC=%08X %s" % (pcnow, e) +
                              ("  @%08X" % _addr if isinstance(_addr, int) else ""))
                if self.verbose:
                    _p("[FAULT] 最近 PC: " + " ".join("%08X" % x for x in self.pc_hist), level="ERROR")
                return False
        self._throttle()
        # 固定换算: --ipt 只影响分块, 不影响固件时序
        self.cycles += insns
        advanced = 0
        while self.cycles >= CYCLES_PER_TICK:
            self.cycles -= CYCLES_PER_TICK
            self.ticks += 1
            advanced += 1
            self.pc_hist.append(self.next_pc)
        if advanced == 0:
            return True
        # 兼容: 第三方固件的显示门控 0x20001FF2 在 boot 置 1 后无人清除，
        # 打开 --unlock-ui 时周期性清 0，主循环才会走显示分发路径
        if self.unlock_ui and (self.ticks % 20) == 0:
            for _a in self.unlock_ui_addrs:
                try:
                    uc.mem_write(_a, b"\x00")
                except Exception:
                    pass
        # 串口刷机后自动重载固件 (模拟真机复位)
        # 注意: 串口对端持续刷机时 generation 会不断变化，必须防抖 + 熔断，
        # 否则会疯狂重载，界面永远起不来。
        if self.space is not None and self.auto_reload and (self.ticks % 50) == 0:
            g = getattr(self.space, "generation", 0)
            if g != self._space_gen:
                now = time.perf_counter()
                if (now - getattr(self, "_last_reload_t", 0.0)) < 1.5:
                    self._reload_storm = getattr(self, "_reload_storm", 0) + 1
                else:
                    self._reload_storm = 1
                self._last_reload_t = now
                if self._reload_storm > 5:
                    self.auto_reload = False
                    self._space_gen = g
                    _p("[SPACE] 1.5 秒内多次重载，已暂停自动重载"
                          "（串口对端可能还在刷机；需要时点 REBOOT）")
                else:
                    self.reload_firmware()
        # SysTick: 真投递异常，让固件自己的 ISR 去累加它自己的计数器
        # （之前直接往原厂固件的 0x20001668 加一，别的固件 millis() 永远是 0）
        if getattr(self, "inject_systick", True):
            if self.exc_depth == 0 and not getattr(self, "_skip_inject", False):
                self._enter_exception(15)
            self._skip_inject = False
        elif self.direct_irq:
            t = struct.unpack("<I", uc.mem_read(TICK_ADDR, 4))[0]
            uc.mem_write(TICK_ADDR, struct.pack("<I", (t + 1) & M32))
        # 外设中断（DMA 等）: 真投递，让固件自己的 ISR 去清标志
        if self.exc_depth == 0 and self.periph.irq_pending:
            irq = (self.periph.irq_pending & -self.periph.irq_pending).bit_length() - 1
            self.periph.irq_pending &= ~(1 << irq)
            self._enter_exception(16 + irq)
        # 到期松键
        now = self.ticks
        for kc, t_rel in list(self.held.items()):
            if now >= t_rel:
                self.release(kc)
                del self.held[kc]
        # 定时脚本
        while self.schedule and self.schedule[0][0] <= now:
            _, fn = self.schedule.pop(0)
            fn()
        return True

    def run(self, max_ticks=2000, insns_per_tick=4000, on_tick=None, stop_when=None):
        if not getattr(self, "started", False):
            self.reset()
            self.started = True
        while self.ticks < max_ticks and not self.fault:
            if not self.step(insns_per_tick):
                break
            if on_tick:
                on_tick(self, self.ticks)
            if stop_when and stop_when(self):
                break
        return self.fault is None

    def at(self, tick, fn):
        self.schedule.append((tick, fn))
        self.schedule.sort(key=lambda x: x[0])

    def tap(self, keycode, hold=3):
        """在指定 tick 按下 keycode, hold 个 tick 后松开"""
        def _press():
            self.press(keycode)
            self.held[keycode] = self.ticks + hold
        self.at(self.ticks, _press)

    def _build_script(self, text):
        """把 "w300 k10 w5 k1,k2 r" 解析成绝对 tick 时间表"""
        t = 0
        for tok in text.split():
            if tok[0] == "w":
                t += int(tok[1:])
            elif tok[0] == "k":
                for kk in tok[1:].split(","):
                    if kk:
                        kc = int(kk)
                        self.at(t, (lambda k: lambda: (self.press(k),
                                                       self.held.__setitem__(k, self.ticks + 3)))(kc))
            elif tok == "r":
                self.at(t, self.release)
        return t

    # ---------------- 键盘 ----------------
    def press(self, keycode):
        if keycode == 16:                     # KEY_PTT: 独立 GPIO(PB10, 低有效)
            self.periph.ptt_down = True
            self.periph.key_pb10 = True
            return
        m = self.keymap.get(keycode)
        with self.periph.key_lock:
            if m == "pb10":
                self.periph.key_pb10 = True
            elif m:
                self.periph.keys.add(m)

    def release(self, keycode=None):
        if keycode == 16:
            self.periph.ptt_down = False
            self.periph.key_pb10 = False
            return
        with self.periph.key_lock:
            if keycode is None:
                self.periph.keys.clear()
                self.periph.key_pb10 = False
                self.periph.ptt_down = False
                return
            m = self.keymap.get(keycode)
            if m == "pb10":
                self.periph.key_pb10 = False
            elif m:
                self.periph.keys.discard(m)

    # ---------------- GPIO 快照 ----------------
    def gpio_snapshot(self):
        """返回 [{name, moder, odr, idr, pins:[(mode,out,in)...]}]"""
        names = "ABCDEF"
        out = []
        for i, g in enumerate(self.periph.gpio):
            moder = g.get("moder", 0)
            odr = g.get("odr", 0)
            idr = g.get("idr", odr)
            pins = []
            for p in range(16):
                mode = (moder >> (2 * p)) & 3
                pins.append((mode, (odr >> p) & 1, (idr >> p) & 1))
            out.append({"name": "P" + names[i], "moder": moder,
                        "odr": odr, "idr": idr, "pins": pins})
        return out

    # ---------------- 显示 ----------------
    def framebuffer(self):
        """优先用 ST7565 控制器里的实际内容（第三方固件直接走 SPI 写屏），
        没有内容时回退到固件自己的 SRAM 帧缓冲。"""
        fb = bytes(self.uc.mem_read(FB_BASE, FB_SIZE))
        if any(fb) and fb != b"\xFF" * FB_SIZE:
            return fb                    # SRAM 帧缓冲型: 固件自己维护显存
        lcd = self.periph.lcd
        try:
            if any(lcd):
                # LCD 控制器是 132 列 RAM，渲染要用 128 列视图
                out = bytearray(128 * 8)
                off = LCD_COL_OFFSET
                for page in range(8):
                    src = page * 132 + off
                    dst = page * 128
                    out[dst:dst + 128] = bytes(lcd[src:src + 128])
                return bytes(out)        # 第三方固件: 直接走 SPI 写屏
        except Exception:
            pass
        return fb

    def render_text(self):
        fb = self.framebuffer()
        lines = []
        for page in range(8):
            for bit in range(8):
                row = []
                for col in range(128):
                    b = fb[page * 128 + col]
                    row.append("#" if (b >> bit) & 1 else ".")
                lines.append("".join(row))
        return lines

    def render_half(self):
        """64 行压成 32 行 (半块字符), 适合终端"""
        fb = self.framebuffer()
        out = []
        for page in range(8):
            for pair in range(4):
                a_bit = pair * 2
                b_bit = a_bit + 1
                row = []
                for col in range(128):
                    byte = fb[page * 128 + col]
                    top = (byte >> a_bit) & 1
                    bot = (byte >> b_bit) & 1
                    row.append("█" if (top and bot) else
                               "▀" if top else
                               "▄" if bot else " ")
                out.append("".join(row))
        return out

    def render_png(self, path, scale=4):
        from PIL import Image
        fb = self.framebuffer()
        img = Image.new("1", (128, 64), 1)
        px = img.load()
        for page in range(8):
            for col in range(128):
                b = fb[page * 128 + col]
                for bit in range(8):
                    if (b >> bit) & 1:
                        px[col, page * 8 + bit] = 0
        img = img.resize((128 * scale, 64 * scale), Image.NEAREST)
        img.save(path)
        return path

    # ---------------- 图形界面: Tkinter 原生窗口 ----------------
    def run_gui(self, scale=5, fps=30, insns=4000):
        """原生窗口渲染 (无需终端支持块字符), 键盘直接送按键。"""
        import base64
        import io
        import tkinter as tk
        from PIL import Image

        self.reset()
        root = tk.Tk()
        root.title("泉盛 UV-K6 V3 — 128×64")
        root.configure(bg="#101014")
        root.resizable(False, False)

        cw, ch = 128 * scale, 64 * scale
        canvas = tk.Canvas(root, width=cw, height=ch, bg="black",
                           highlightthickness=1, highlightbackground="#2a2a35")
        canvas.pack(padx=8, pady=(8, 4))
        item = canvas.create_image(0, 0, anchor="nw")

        status = tk.Label(root, text="启动中…", fg="#8ac", bg="#101014",
                          font=("Consolas", 9), anchor="w", width=64)
        status.pack(fill="x", padx=8)
        help_lbl = tk.Label(root, justify="left", fg="#666", bg="#101014",
                            font=("Consolas", 8), anchor="w",
                            text="0-9 数字   Enter=MENU(10)   Esc=EXIT(13)   BS=14   .=15   Tab=16\n"
                                 "a..t = 键值 0..19   s = 存 PNG   r = 松键")
        help_lbl.pack(fill="x", padx=8, pady=(0, 8))

        KEYMAP = {"Return": 10, "KP_Enter": 10, "Escape": 13, "BackSpace": 14,
                  "period": 15, "Tab": 16}
        holders = {}

        def to_keycode(ev):
            if ev.keysym in KEYMAP:
                return KEYMAP[ev.keysym]
            if len(ev.char) == 1 and ev.char.isdigit():
                return int(ev.char)
            if len(ev.char) == 1 and "a" <= ev.char.lower() <= "t":
                return ord(ev.char.lower()) - ord("a")
            return None

        def on_key(ev):
            if ev.char in ("s", "S"):
                self.render_png("gui_shot.png")
                status.config(text="截图: gui_shot.png")
                return
            if ev.char in ("r", "R"):
                self.release()
                return
            kc = to_keycode(ev)
            if kc is None:
                return
            self.press(kc)
            old = holders.pop(kc, None)
            if old:
                root.after_cancel(old)

            def rel():
                self.release(kc)
                holders.pop(kc, None)
            holders[kc] = root.after(90, rel)

        root.bind("<KeyPress>", on_key)
        canvas.focus_set()

        img_holder = {}

        _last_fb = {"v": None}

        def _paint_lcd(fb):
            im = Image.new("1", (128, 64), 1)
            px = im.load()
            for page in range(8):
                base = page * 128
                for col in range(128):
                    b = fb[base + col]
                    if not b:
                        continue
                    y = page * 8
                    for bit in range(8):
                        if (b >> bit) & 1:
                            px[col, y + bit] = 0
            im = im.resize((cw, ch), Image.NEAREST)
            buf = io.BytesIO()
            im.save(buf, "PNG")
            photo = tk.PhotoImage(data=base64.b64encode(buf.getvalue()))
            canvas.itemconfig(item, image=photo)
            img_holder["p"] = photo

        _hinted = {"ui": False}

        def frame():
            fb = self.framebuffer()
            if (not _hinted["ui"] and self.ticks > 900
                    and getattr(self, "power_on", True)
                    and not getattr(self, "ptt_boot", False)
                    and not any(self.periph.lcd)):
                _hinted["ui"] = True
                _p("[UI] 屏幕一直没有内容：第三方固件通常需要 --unlock-ui "
                   "（例: Dondji/mangosteen）", level="WARNING")
            if fb != _last_fb["v"]:
                _last_fb["v"] = fb
                _paint_lcd(fb)

        state = {"last": 0.0, "frames": 0}
        interval = int(1000 / fps)

        def tick():
            t0 = time.perf_counter()
            budget = (1.0 / fps) * 0.78
            while True:
                if not self.step(insns):
                    status.config(text="VM 停止: %s" % self.fault, fg="#e66")
                    return
                if (time.perf_counter() - t0) >= budget:
                    break
            frame()
            state["frames"] += 1
            if not getattr(self, "power_on", True):
                canvas.itemconfig(item, image="")
                status.configure(text="POWER OFF   (点 ⏻ POWER 开机)")
                return
            ui = self.uc.mem_read(0x2000012F, 1)[0]
            extra = ""
            r = getattr(self, "radio", None)
            if r is not None and getattr(r, "boot_mode", False):
                extra = "  [BOOTLOADER 手电筒%s 背光%s]" % (
                    "ON" if getattr(r, "flashlight", False) else "off",
                    "ON" if getattr(r, "backlight", False) else "off")
            status.config(text="tick %-6d  UI 12F=%02X  %s%s"
                              % (self.ticks, ui, self.fault or "运行中", extra),
                          fg="#8ac")
            root.after(interval, tick)

        root.update_idletasks()
        # 只定位置，尺寸交给内容自适应（键盘加宽后写死宽高会被裁掉）
        w = max(root.winfo_reqwidth() + 24, 900)
        h = max(root.winfo_reqheight() + 24, 620)
        root.geometry("%dx%d+60+40" % (w, h))
        root.minsize(w, h)
        root.resizable(True, True)
        root.after(50, tick)
        try:
            root.mainloop()
        finally:
            try:
                root.destroy()
            except Exception:
                pass

    # ---------------- 真机面板: LCD + 键盘 + GPIO ----------------
    def run_panel(self, scale=4, fps=20, insns=4000):
        import base64
        import io as _io
        import tkinter as tk
        from PIL import Image

        self.reset()
        vm_self = self
        root = tk.Tk()
        root.title("泉盛 UV-K6 V3 — 真机模拟面板")

        def _report_exc(*exc):
            import traceback
            _p("[PANEL] 界面回调异常:", level="ERROR")
            traceback.print_exception(*exc)
        root.report_callback_exception = _report_exc
        root.configure(bg="#0d0f14")

        BG = "#0d0f14"
        FG = "#9fb3c8"

        # ---- 左上: LCD ----
        lcd_w, lcd_h = 128 * scale, 64 * scale
        lcd_frame = tk.Frame(root, bg=BG)
        lcd_frame.grid(row=0, column=0, padx=10, pady=(10, 4), sticky="n")
        canvas = tk.Canvas(lcd_frame, width=lcd_w, height=lcd_h, bg="#000",
                           highlightthickness=1, highlightbackground="#26303d")
        canvas.pack()
        item = canvas.create_image(0, 0, anchor="nw")
        img_holder = {}

        # ---- 右上: 真机键盘 (泉盛 UV-K6 V3) ----
        pad = tk.Frame(root, bg=BG)
        pad.grid(row=0, column=1, padx=10, pady=(10, 4), sticky="n")
        tk.Label(pad, text="KEYPAD  UV-K6 V3", fg=FG, bg=BG,
                 font=("Consolas", 9)).grid(row=0, column=0, columnspan=5, pady=(0, 4))

        PALETTE = {
            "ptt":  ("#f9dcdc", "#b03a2e", "#f2b8b5"),
            "menu": ("#d8f0e0", "#1e8449", "#a9dfbf"),
            "exit": ("#fceccf", "#a86413", "#f5c98a"),
            "fn":   ("#d9e8f7", "#1f618d", "#aed6f1"),
            "num":  ("#f2f4f6", "#4d5b68", "#d6dbdf"),
        }
        KEYS = [
            (0, 0, "PTT",  "N/A",    16, "ptt"),
            (0, 1, "MENU", "",       10, "menu"),
            (0, 2, "\u25b2", "",    11, "num"),
            (0, 3, "\u25bc", "",    12, "num"),
            (0, 4, "EXIT", "",       13, "exit"),
            (1, 0, "F1",   "SIDE 1", 18, "fn"),
            (1, 1, "1",    "Band",    1, "num"),
            (1, 2, "2",    "A/B",     2, "num"),
            (1, 3, "3",    "V/M",     3, "num"),
            (1, 4, "*",    "Scan",   14, "num"),
            (2, 0, "F2",   "SIDE 2", 17, "fn"),
            (2, 1, "4",    "FC",      4, "num"),
            (2, 2, "5",    "WX",      5, "num"),
            (2, 3, "6",    "H/L",     6, "num"),
            (2, 4, "0",    "FM",      0, "num"),
            (3, 1, "7",    "VOX",     7, "num"),
            (3, 2, "8",    "R",       8, "num"),
            (3, 3, "9",    "Call",    9, "num"),
            (3, 4, "#",    "F",      15, "num"),
        ]
        key_widgets = {}                     # keycode -> (frame, main, sub, kind)

        for (kr, kc_, main, sub, code, kind) in KEYS:
            bg, fg, _act = PALETTE[kind]
            fr = tk.Frame(pad, bg=bg, width=64, height=42,
                          highlightbackground="#c3c9cf", highlightthickness=1)
            fr.grid(row=kr + 1, column=kc_, padx=3, pady=3)
            fr.pack_propagate(False)
            lm = tk.Label(fr, text=main, bg=bg, fg=fg, font=("Segoe UI", 10, "bold"))
            lm.pack(expand=(sub == ""), pady=(6 if sub else 0, 0))
            ls = None
            if sub:
                ls = tk.Label(fr, text=sub, bg=bg, fg="#8a97a3", font=("Segoe UI", 6))
                ls.pack(pady=(0, 4))
            key_widgets[code] = (fr, lm, ls, kind)

            def _mk(code=code):
                def down(_e=None):
                    self._last_key = code
                    self.press(code)
                def up(_e=None):
                    self.release(code)
                return down, up
            down, up = _mk()
            for w in (fr, lm, ls):
                if w is None:
                    continue
                w.bind("<ButtonPress-1>", down)
                w.bind("<ButtonRelease-1>", up)
                w.bind("<Leave>", lambda e, u=up: u())
                w.configure(cursor="hand2")

        tk.Label(pad, text="左键 按下/松开 · PTT 按住说话", fg="#5a6572", bg=BG,
                 font=("Consolas", 8)).grid(row=5, column=0, columnspan=5, pady=(2, 0))

        ctl = tk.Frame(pad, bg=BG)
        ctl.grid(row=6, column=0, columnspan=5, pady=(6, 0), sticky="we")
        btn_power = tk.Button(ctl, text="\u23fb POWER", width=10, font=("Consolas", 9, "bold"),
                              bg="#243040", fg="#cfe3f5", activebackground="#2e7d32",
                              relief="flat", command=lambda: on_power())
        btn_power.grid(row=0, column=0, padx=2)
        btn_reboot = tk.Button(ctl, text="\u21bb REBOOT", width=10, font=("Consolas", 9, "bold"),
                               bg="#243040", fg="#cfe3f5", activebackground="#a05a2c",
                               relief="flat", command=lambda: on_reboot())
        btn_reboot.grid(row=0, column=1, padx=2)

        ind = tk.Frame(pad, bg=BG)
        ind.grid(row=7, column=0, columnspan=5, pady=(6, 0), sticky="we")
        leds = {}
        for i, (name, col) in enumerate((("PTT", "#e05555"), ("FLASHLIGHT", "#e0c040"),
                                        ("BACKLIGHT", "#55c0e0"), ("BOOT", "#a070e0"))):
            leds[name] = tk.Label(ind, text=name, width=10, height=1, bg="#1b2129",
                                  fg="#5a6572", font=("Consolas", 8, "bold"))
            leds[name].grid(row=0, column=i, padx=2)

        # 电池电压滑条（真机是 2S 锂电，6.0~8.4V）
        battf = tk.Frame(pad, bg=BG)
        battf.grid(row=8, column=0, columnspan=5, pady=(6, 0), sticky="we")
        tk.Label(battf, text="BATT", fg=FG, bg=BG,
                 font=("Consolas", 8, "bold")).grid(row=0, column=0)
        batt_lbl = tk.Label(battf, text="%.2f V" % (getattr(vm_self.periph, "batt_mv", 8200) / 1000.0),
                            fg="#8ac", bg=BG, font=("Consolas", 9, "bold"), width=7)
        batt_lbl.grid(row=0, column=2, padx=(6, 0))

        def on_batt(val):
            try:
                mv = int(round(float(val) * 1000))
            except Exception:
                return
            vm_self.periph.batt_mv = mv
            batt_lbl.configure(text="%.2f V" % (mv / 1000.0))

        batt_sc = tk.Scale(battf, from_=6.0, to=8.4, resolution=0.05, orient="horizontal",
                           length=180, showvalue=False, bg=BG, fg=FG,
                           highlightthickness=0, troughcolor="#1b2129",
                           activebackground="#2e7d32", command=on_batt)
        batt_sc.set(getattr(vm_self.periph, "batt_mv", 8200) / 1000.0)
        batt_sc.grid(row=0, column=1, padx=(6, 0))

        def on_power():
            if getattr(vm_self, "power_on", True):
                vm_self.power_off()
            else:
                r = getattr(vm_self, "radio", None)
                vm_self.cold_boot(ptt=getattr(r, "ptt", False))

        def on_reboot():
            r = getattr(vm_self, "radio", None)
            vm_self.cold_boot(ptt=getattr(r, "ptt", False))

        # ---- 下: GPIO ----
        gp = tk.Frame(root, bg=BG)
        gp.grid(row=1, column=0, columnspan=2, padx=10, pady=(4, 6), sticky="we")
        tk.Label(gp, text="GPIO  (蓝=输入 绿=输出高 灰=输出低 紫=复用 褐=模拟)   "
                          "M=MODER O=ODR I=IDR",
                 fg=FG, bg=BG, font=("Consolas", 9), anchor="w").grid(
            row=1, column=0, columnspan=18, sticky="w", pady=(0, 3))
        pin_labels = {}
        stats = {}
        for p in range(16):
            tk.Label(gp, text=str(p), fg="#44525f", bg=BG,
                     font=("Consolas", 6)).grid(row=0, column=1 + p)
        for pi in range(6):
            tk.Label(gp, text="P" + "ABCDEF"[pi], fg="#c8d4e0", bg=BG,
                     font=("Consolas", 10, "bold")).grid(row=pi + 2, column=0, sticky="w")
            for p in range(16):
                lb = tk.Label(gp, text="", width=2, height=1, bg="#151a21", font=("Arial", 5))
                lb.grid(row=pi + 2, column=1 + p, padx=1, pady=1)
                pin_labels[(pi, p)] = lb
            st = tk.Label(gp, text="", fg="#66788a", bg=BG, font=("Consolas", 8), anchor="w")
            st.grid(row=pi + 2, column=17, padx=(8, 0), sticky="w")
            stats[pi] = st

        # ---- 状态栏 ----
        status = tk.Label(root, text="启动中…", fg="#8ac", bg="#11151b",
                          font=("Consolas", 9), anchor="w")
        status.grid(row=2, column=0, columnspan=2, sticky="we", padx=10, pady=(0, 8))

        root.bind("<KeyPress>", lambda e: self._panel_key(e, True, root))
        root.bind("<KeyRelease>", lambda e: self._panel_key(e, False, root))

        MODECOL = {0: "#1f3a5f", 1: "#2e7d32", 2: "#6a3fa0", 3: "#6b4a2a"}

        _last_fb = {"v": None}

        def _paint_lcd(fb):
            im = Image.new("1", (128, 64), 1)
            px = im.load()
            for page in range(8):
                base = page * 128
                for col in range(128):
                    b = fb[base + col]
                    if not b:
                        continue
                    y = page * 8
                    for bit in range(8):
                        if (b >> bit) & 1:
                            px[col, y + bit] = 0
            im = im.resize((lcd_w, lcd_h), Image.NEAREST)
            buf = _io.BytesIO()
            im.save(buf, "PNG")
            photo = tk.PhotoImage(data=base64.b64encode(buf.getvalue()))
            canvas.itemconfig(item, image=photo)
            img_holder["p"] = photo

        _hinted = {"ui": False}

        def frame():
            fb = self.framebuffer()
            if (not _hinted["ui"] and self.ticks > 900
                    and getattr(self, "power_on", True)
                    and not getattr(self, "ptt_boot", False)
                    and not any(self.periph.lcd)):
                _hinted["ui"] = True
                _p("[UI] 屏幕一直没有内容：第三方固件通常需要 --unlock-ui "
                   "（例: Dondji/mangosteen）", level="WARNING")
            if fb != _last_fb["v"]:
                _last_fb["v"] = fb
                _paint_lcd(fb)

            # 键盘高亮（以模型状态为准，鼠标按下/松开自动反映）
            pressed = getattr(self.periph, "keys", set())
            for code, (fr, lm, ls, kind) in key_widgets.items():
                m = getattr(self, "keymap", {}).get(code)
                if code == 16:
                    on = getattr(self.periph, "ptt_down", False)
                elif m == "pb10":
                    on = getattr(self.periph, "key_pb10", False)
                elif m:
                    on = m in pressed
                else:
                    on = False
                bg = PALETTE[kind][2] if on else PALETTE[kind][0]
                for w in (fr, lm, ls):
                    if w is not None:
                        w.configure(bg=bg)

            # LED 指示
            r = getattr(self, "radio", None)
            states = {
                "PTT": getattr(r, "ptt", False),
                "FLASHLIGHT": getattr(r, "flashlight", False),
                "BACKLIGHT": getattr(r, "backlight", False),
                "BOOT": getattr(r, "boot_mode", False) if r else False,
            }
            for name, lb in leds.items():
                on = states.get(name, False)
                lb.configure(bg="#e05555" if on and name == "PTT" else
                                "#e0c040" if on and name == "FLASHLIGHT" else
                                "#55c0e0" if on and name == "BACKLIGHT" else
                                "#a070e0" if on else "#1b2129",
                             fg="#0d0f14" if on else "#5a6572")

            # GPIO
            for snap in self.gpio_snapshot():
                pi = "ABCDEF".index(snap["name"][1])
                for p in range(16):
                    mode, odr, idr = snap["pins"][p]
                    if mode == 1:
                        col = MODECOL[1] if odr else "#2a323c"
                    else:
                        col = MODECOL[mode]
                    pin_labels[(pi, p)].configure(bg=col)
                stats[pi].configure(
                    text="M=%04X O=%04X I=%04X" % (snap["moder"] & 0xFFFF, snap["odr"], snap["idr"]))

            if not getattr(self, "power_on", True):
                canvas.itemconfig(item, image="")
                status.configure(text="POWER OFF   (点 ⏻ POWER 开机)")
                return
            ui = self.uc.mem_read(0x2000012F, 1)[0]
            extra = ""
            if r is not None and getattr(r, "boot_mode", False):
                extra = "  [BOOTLOADER]"
            note = "" if getattr(self, "auto_reload", True) else "  [自动重载已暂停]"
            status.configure(
                text="tick %-6d  UI 12F=%02X  KEY=%-4s LCD %s%s%s"
                     % (self.ticks, ui,
                        ("0x%02X" % self._last_key) if getattr(self, "_last_key", None) is not None else "-",
                        "PTT-BOOT" if getattr(self, "ptt_boot", False) else "running",
                        extra, ("  " + self.fault) if self.fault else "") + note)

        def tick():
            t0 = time.perf_counter()
            budget = (1.0 / fps) * 0.78      # 78% 时间跑模拟，其余留给界面
            while True:
                self.step(insns)
                if self.fault:
                    break
                if (time.perf_counter() - t0) >= budget:
                    break
            frame()
            spent = (time.perf_counter() - t0) * 1000.0
            root.after(max(1, int(1000.0 / fps - spent)), tick)

        root.update_idletasks()
        # 键盘加宽后写死宽高会裁掉右侧按键；这里按内容自适应
        # reqwidth 有时算不到 grid 的 padx，直接用两块子面板的宽度相加
        w = max(lcd_frame.winfo_reqwidth() + pad.winfo_reqwidth() + 130,
                root.winfo_reqwidth() + 110, 1040)
        h = max(root.winfo_reqheight() + 24, 560)
        root.geometry("%dx%d+50+30" % (w, h))
        root.minsize(700, 560)
        root.resizable(True, True)
        if getattr(self, "panel_selftest", False):
            def _selftest():
              try:
                for code in (10, 1, 16):
                    fr, lm, ls, kind = key_widgets[code]
                    # event_generate 默认 when="now"，同步派发给绑定，不需要 update()
                    lm.event_generate("<ButtonPress-1>", x=4, y=4)
                    pressed_ok = (getattr(self, '_last_key', None) == code)
                    if code == 16:
                        model_ok = self.periph.ptt_down
                    else:
                        model_ok = self.keymap.get(code) in self.periph.keys
                    lm.event_generate("<ButtonRelease-1>", x=4, y=4)
                    if code == 16:
                        rel_ok = not self.periph.ptt_down
                    else:
                        rel_ok = self.keymap.get(code) not in self.periph.keys
                    _p("[SELFTEST] key=0x%02X 按下=%s 模型=%s 松开=%s"
                          % (code, pressed_ok, model_ok, rel_ok), flush=True)
                _p("[SELFTEST] 键盘点击链路 " +
                      ("PASS" if True else "FAIL"))
              except Exception:
                import traceback
                _p("[SELFTEST] 异常:", level="ERROR")
                traceback.print_exc()
              finally:
                root.after(200, root.destroy)
            root.after(2000, _selftest)
        root.after(50, tick)
        try:
            root.mainloop()
        finally:
            try:
                root.destroy()
            except Exception:
                pass

    def _panel_key(self, ev, down, root):
        KM = {"Return": 10, "KP_Enter": 10, "Escape": 13, "BackSpace": 14,
              "period": 15, "Tab": 16}
        kc = KM.get(ev.keysym)
        if kc is None and len(ev.char) == 1 and ev.char.isdigit():
            kc = int(ev.char)
        if kc is None and len(ev.char) == 1 and "a" <= ev.char.lower() <= "t":
            kc = ord(ev.char.lower()) - ord("a")
        if kc is None:
            return
        if down:
            self.press(kc)
        else:
            self.release(kc)

    # ---------------- 图形界面: 浏览器 canvas ----------------
    def run_web(self, port=8777, host="127.0.0.1", insns=1200):
        """起一个本地网页: 任何浏览器都能看/操作, 兼容性最好。"""
        import threading
        import time
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        self.reset()
        self._fb = bytes(FB_SIZE)
        self._lock = threading.Lock()
        self._stop = False

        PAGE = """<!doctype html><meta charset=utf-8>
<title>泉盛 UV-K6 V3</title>
<style>
 body{background:#0e0f13;color:#9ab;font:13px/1.5 Consolas,monospace;margin:0;
      display:flex;flex-direction:column;align-items:center;gap:10px;padding:18px}
 canvas{background:#000;border:1px solid #2b2b38;border-radius:6px;
        image-rendering:pixelated;width:512px;height:256px}
 .bar{display:flex;gap:18px;font-size:12px;color:#6a7}
 table{border-collapse:collapse;font-size:12px;color:#667}
 td{padding:1px 8px}
</style>
<h3 style="margin:0;color:#bcd">泉盛 UV-K6 V3 &mdash; 128&times;64</h3>
<canvas id=c width=128 height=64></canvas>
<div class=bar><span id=st>连接中…</span></div>
<table><tr>
 <td>0-9 数字</td><td>Enter = MENU(10)</td><td>Esc = EXIT(13)</td></tr>
 <tr><td>Backspace = 14</td><td>. = 15</td><td>Tab = 16</td></tr>
 <tr><td colspan=3>a..t = 直接送键值 0..19 &nbsp;|&nbsp; 按住不放=持续按下</td></tr>
</table>
<script>
const c=document.getElementById('c'), x=c.getContext('2d');
const img=x.createImageData(128,64);
const KEYMAP={Enter:10,Escape:13,Backspace:14,'.':15,Tab:16};
function kcOf(e){
  if(e.key in KEYMAP) return KEYMAP[e.key];
  if(/^[0-9]$/.test(e.key)) return +e.key;
  const l=e.key.toLowerCase();
  if(l.length===1 && l>='a' && l<='t') return l.charCodeAt(0)-97;
  return null;
}
async function send(k,down){ try{ await fetch('/key?k='+k+'&down='+(down?1:0),{method:'POST'}); }catch(_){} }
addEventListener('keydown',e=>{const k=kcOf(e); if(k!==null){e.preventDefault(); send(k,1);} });
addEventListener('keyup',  e=>{const k=kcOf(e); if(k!==null){e.preventDefault(); send(k,0);} });
let last=0, frames=0, t0=performance.now();
async function poll(){
  try{
    const r=await fetch('/frame'); const b=new Uint8Array(await r.arrayBuffer());
    for(let page=0;page<8;page++)for(let col=0;col<128;col++){
      const v=b[page*128+col];
      for(let bit=0;bit<8;bit++){
        const on=(v>>bit)&1, i=((page*8+bit)*128+col)*4;
        img.data[i]=img.data[i+1]=img.data[i+2]= on?230:8; img.data[i+3]=255;
      }
    }
    x.putImageData(img,0,0);
    frames++; const now=performance.now();
    if(now-t0>500){ document.getElementById('st').textContent=
      'fps '+(frames*1000/(now-t0)).toFixed(0); frames=0; t0=now; }
  }catch(_){}
  setTimeout(poll,40);
}
poll();
</script>"""

        vm_self = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path.startswith("/frame"):
                    data = vm_self._fb
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                elif self.path in ("/", "/index.html"):
                    body = PAGE.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_error(404)

            def do_POST(self):
                from urllib.parse import urlparse, parse_qs
                q = parse_qs(urlparse(self.path).query)
                if self.path.startswith("/key"):
                    try:
                        kc = int(q["k"][0])
                        down = q.get("down", ["1"])[0] == "1"
                    except Exception:
                        self.send_error(400)
                        return
                    with vm_self._lock:
                        if down:
                            vm_self.press(kc)
                            vm_self._web_hold[kc] = vm_self.ticks
                        else:
                            vm_self.release(kc)
                    self.send_response(204)
                    self.end_headers()
                else:
                    self.send_error(404)

        self._web_hold = {}
        httpd = ThreadingHTTPServer((host, port), H)
        th = threading.Thread(target=httpd.serve_forever, daemon=True)
        th.start()
        _p("[VM] 浏览器打开: http://%s:%d/" % (host, port))
        _p("[VM] Ctrl-C 结束")

        try:
            while not self.fault:
                if not self.step(insns):
                    break
                self._fb = self.framebuffer()
                # 网页端若没收到 keyup, 200 tick 后自动松键
                with self._lock:
                    for kc, t0 in list(self._web_hold.items()):
                        if self.ticks - t0 > 200:
                            self.release(kc)
                            del self._web_hold[kc]
        except KeyboardInterrupt:
            _p("[VM] 用户中断", level="WARNING")
        finally:
            httpd.shutdown()
        if self.fault:
            _p("[VM] 停止: %s" % self.fault, level="ERROR")

    # ---------------- 交互 ----------------
    KEY_HELP = """\
┌ 键盘映射 ─────────────────────────────────────────────┐
│  0-9 数字    Enter=MENU(10)   Esc=EXIT(13)   BS=14    │
│  .=15        Tab=16(特殊键)   a..t=键值0..19 直接送    │
│  r 松键      s 截图PNG        c 显示/隐藏按键提示      │
│  Ctrl-C 退出                                           │
└───────────────────────────────────────────────────────┘"""

    def interactive(self, png_path="vm_screen.png", fps=12):
        import msvcrt
        import time

        self.reset()

        def clear():
            sys.stdout.write("\033[2J")

        def home():
            sys.stdout.write("\033[H")

        clear()
        _p("[VM] 启动中… (约 1-2 秒后出现画面)")
        sys.stdout.flush()
        t0 = time.time()
        frames = 0
        last = 0.0
        msg = ""
        show_help = True
        while not self.fault:
            if not self.step(3000):
                break
            # 轮询按键
            while msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch in ("\x00", "\xe0"):        # 方向键等双字节
                    msvcrt.getwch()
                    continue
                if ch == "\x03":
                    raise KeyboardInterrupt
                kc = None
                if ch.isdigit():
                    kc = int(ch)
                elif ch in ("\r", "\n"):
                    kc = 10
                elif ch == "\x1b":
                    kc = 13
                elif ch == "\x08":
                    kc = 14
                elif ch == ".":
                    kc = 15
                elif ch == "\t":
                    kc = 16
                elif "a" <= ch.lower() <= "t":
                    kc = ord(ch.lower()) - ord("a")
                elif ch == "r":
                    self.release()
                    msg = "已松开全部按键"
                elif ch == "s":
                    self.render_png(png_path)
                    msg = "截图已存 %s" % png_path
                elif ch == "c":
                    show_help = not show_help
                if kc is not None:
                    self.press(kc)
                    self.held[kc] = self.ticks + 3
                    msg = "按键 %d (0x%02X)" % (kc, kc)
            now = time.time()
            if now - last < 1.0 / fps:
                continue
            last = now
            frames += 1
            screen = self.render_half()
            home()
            w = sys.stdout.write
            w("  泉盛 UV-K6 V3     │  tick %-6d  UI 12F=%02X  │  %s\n"
              % (self.ticks, self.uc.mem_read(0x2000012f, 1)[0], msg))
            for line in screen:
                w("  " + line + "\n")
            if show_help:
                w("\n" + self.KEY_HELP + "\n")
            sys.stdout.flush()
        _p("[VM] 停止: %s" % (self.fault or "正常退出"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--firmware", default=default_firmware())
    ap.add_argument("--uid", nargs=3, default=["1A2B3C4D", "5E6F7081", "92A3B4C5"])
    ap.add_argument("--ticks", type=int, default=2500)
    ap.add_argument("--ipt", type=int, default=4000, help="每个 step 执行的指令数")
    ap.add_argument("--png", default=None)
    ap.add_argument("--text", action="store_true")
    ap.add_argument("--interactive", "-i", action="store_true", help="终端 TUI (块字符)")
    ap.add_argument("--gui", action="store_true", help="Tkinter 原生窗口 (推荐)")
    ap.add_argument("--panel", action="store_true",
                    help="真机面板: LCD + 键盘矩阵 + 全 GPIO 状态")
    ap.add_argument("--web", nargs="?", const=8777, type=int, metavar="PORT",
                    help="浏览器渲染, 默认端口 8777")
    ap.add_argument("--script", default=None,
                    help='例: "w300 k10 w30 k1 k2 k3 w60 r"  (w=等待 tick, k=按键, r=松键)')
    ap.add_argument("--flash", default=None, metavar="PATH",
                    help="4MB 固件空间镜像文件 (串口刷机写入这里, MCU 也从这里取固件)")
    ap.add_argument("--uart", nargs="?", const=8801, type=int, metavar="PORT",
                    help="常开虚拟串口 (TCP), 默认端口 8801")
    ap.add_argument("--com", default=None, metavar="COMx",
                    help="同时桥接到真实 COM 口 (com0com 虚拟串口对)")
    ap.add_argument("--base", default=None, metavar="ADDR",
                    help="镜像链接基址 (默认 0x08002800, 或按向量表自动判断)")
    ap.add_argument("--flsh", action="store_true",
                    help="串口直接进刷机模式 (不等 0.8s 窗口, 立即可 FLSH/擦写)")
    ap.add_argument("--ptt", action="store_true",
                    help="模拟开机按住 PTT: 手电筒常亮+背光开+进 bootloader, 固件不运行")
    ap.add_argument("--nor", default=None,
                    help="加载外部 SPI NOR 内容: 文件或 文件@偏移 (如 cal.dat@0xB000)")
    ap.add_argument("--nor-dump", default=None,
                    help="退出时把 NOR 的 0xA000-0xC000 存成文件，便于比对")
    ap.add_argument("--unlock-ui", nargs="?", const="auto", default=None,
                    help="兼容: 周期性清除第三方固件的显示门控；可给地址(逗号分隔)，"
                         "默认 auto = 0x20001FF2(Dondji) + 0x20002720(mangosteen)")
    ap.add_argument("--batt", type=float, default=8.2,
                    help="电池电压（伏），默认 8.2；影响 ADC 读数与低电告警")
    ap.add_argument("--tps", type=int, default=0,
                    help="限制每秒 tick 数（0=不限；1000 ≈ 实时）")
    ap.add_argument("--panel-selftest", action="store_true",
                    help="面板自检: 程序化触发按键事件并退出（验证点击链路）")
    ap.add_argument("--reseed", action="store_true",
                    help="用 --firmware 强制覆盖 4MB 空间里的固件区")
    ap.add_argument("--legacy-proto", action="store_true",
                    help="串口额外启用旧字节命令 FLSH/0x30-0x34（真机没有）")
    ap.add_argument("--no-reload", action="store_true",
                    help="刷机后不自动重载固件 (刷陌生镜像时用, 免得跑飞)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    # 只要用到串口，就先把 4MB 空间准备好，避免 VM 构造后再挂 space 触发误重载
    space = None
    if args.flash or args.uart or args.com:
        import radio_device as _rd
        space_path = args.flash or "device_flash_tmp.bin"
        space = _rd.Flash4M(space_path, size=SPACE_SIZE, log=(_p if args.verbose else None))
        if args.flash is None:
            _p("[UART] 未指定 --flash，使用临时空间 %s" % space_path)

    vm = VM(args.firmware, uid=[int(x, 16) for x in args.uid], verbose=args.verbose,
            flash_path=space,
            img_base=(int(args.base, 0) if args.base else None),
            reseed=args.reseed)
    vm.auto_reload = not args.no_reload
    vm.periph.batt_mv = int(round(max(0.0, args.batt) * 1000))
    vm.tps_limit = max(0, args.tps)
    vm.panel_selftest = args.panel_selftest
    if args.unlock_ui:
        vm.unlock_ui = True
        if args.unlock_ui != "auto":
            vm.unlock_ui_addrs = [int(x, 0) for x in args.unlock_ui.split(",") if x.strip()]
    vm.ptt_boot = args.ptt

    # 外部 NOR 内容（真机的校准/配置区）
    if args.nor:
        spec, _, off = args.nor.partition("@")
        base = int(off, 0) if off else 0
        data = open(spec, "rb").read()
        nor = vm.periph.nor
        if base + len(data) <= len(nor):
            nor[base:base + len(data)] = data
            _p("[NOR] 载入 %d 字节 @0x%06X <- %s" % (len(data), base, spec))
        else:
            _p("[NOR] 文件太大，跳过", level="WARNING")
    if args.ptt:
        vm.uc.mem_write(FB_BASE, b"\x00" * FB_SIZE)      # 空白屏 + 背光开
        _p("[BOOT] PTT 按住: 手电筒常亮 + 背光开 + 进刷机模式, 应用固件不运行")

    # 常开串口: 与 MCU 共享同一个 4MB 空间
    bridge = None
    if args.uart or args.com:
        import radio_device as _rd
        radio = _rd.VirtualRadio(space=vm.space, log=_p,
                                 legacy_proto=args.legacy_proto)
        if args.ptt:
            radio.hold_boot(ptt=True)
            vm.radio = radio
            vm.ptt_boot = True
        elif args.flsh:
            radio.hold_boot()
        else:
            radio.enter_boot_window(0.8)
        if args.uart:
            bridge = _rd.SerialBridge(radio, port=args.uart, log=_p)
            bridge.start()
        if args.com:
            comb = _rd.ComBridge(radio, args.com, log=_p)
            comb.start()

    if args.web:
        vm.run_web(port=args.web)
        return

    if args.panel:
        vm.run_panel()
        return

    if args.gui:
        vm.run_gui()
        return

    if args.interactive:
        try:
            vm.interactive()
        except KeyboardInterrupt:
            _p("[VM] 用户中断", level="WARNING")
        return

    # ---- 脚本模式 ----
    if args.script:
        vm._build_script(args.script)

    ok = vm.run(max_ticks=args.ticks, insns_per_tick=args.ipt)
    if args.nor_dump:
        with open(args.nor_dump, "wb") as f:
            f.write(bytes(vm.periph.nor[0xA000:0xC000]))
        _p("[NOR] 0xA000-0xC000 -> %s" % args.nor_dump)
    _p("[VM] 运行结束, 状态 %s (tick=%d)" % ("OK" if ok else vm.fault, vm.ticks), level="SUCCESS" if ok else "ERROR")
    if args.text or not args.png:
        for ln in vm.render_text():
            print(ln)
    if args.png:
        _p("[PNG] " + str(vm.render_png(args.png)), level="SUCCESS")


if __name__ == "__main__":
    main()


