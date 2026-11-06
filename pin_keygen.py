#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
firmware_decrypted.bin  —  PIN / AUTH 注册机
============================================

目标固件: 原厂固件 手持多功能工具 (计算器 / 俄罗斯方块 / 电子木鱼 / CW练习器)
          Cortex-M0+ 级, 镜像基址 0x08002000

逆向依据
--------
UID      : 0x1FFF3000/04/08  ->  3 个 32-bit word (U0,U1,U2)
PIN      : uid_table_hash32(U0,U1,U2) % 100000000        (8 位十进制)
AUTH记录 : 外部 SPI NOR 0x00145000, 28 字节
           "AUTH" | ver=1 | TEA(PIN,0) | TEA(0xA5A5A5A5,0) | crc32(PIN)^crc32(marker)
TEA key  : k0 = U0 ^ 0x7F3A9C81
           k1 = U1 ^ 0xD4E6B205
           k2 = U2 ^ 0xA91F4C7E
           k3 = U0 ^ U1 ^ U2 ^ 0x82D6B3F0

镜像基址说明
------------
固件真实链接基址是 0x08002800 (不是 IDA 默认加载的 0x08002000),
故「代码里绝对地址 A 的字节」就在文件偏移 A - 0x08002800。
本脚本用 option-byte 表首项 0x1FFF3238 做自检, 证明地址换算正确。

用法
----
    python pin_keygen.py --uid 0x1A2B3C4D 0x5E6F7081 0x92A3B4C5
    python pin_keygen.py --uid 1A2B3C4D,5E6F7081,92A3B4C5
    python pin_keygen.py --uid-file uid.txt          # 每行一个 UID 三字组
    python pin_keygen.py --uid ... --auth auth.bin   # 额外生成 28 字节 AUTH 记录
    python pin_keygen.py --selftest

UID 从哪来
----------
开机界面 "Device MAC" 下面三行 %08lX 就是 U0,U1,U2 (原样抄下来即可)。
也可以直接读 0x1FFF3000 (SWD / RDP level 0 时).
"""

import argparse
import struct
import sys
import zlib

BASE = 0x08002800          # 真实链接基址 (VTOR 指向的向量表所在)

# 代码中的表地址 (uid_table_hash32 的字面量池 @0x08002DF4)
TBL_A_ADDR = 0x08009EE0    # 索引 U0 & 0xFF
TBL_B_ADDR = 0x08009AE0    # 索引 (U0 >> 8) & 0xFF
TBL_C_ADDR = 0x080096E0    # 索引 U1 & 0xFF
TBL_D_ADDR = 0x080092E0    # 索引 (U2 ^ (U1 >> 8)) & 0xFF

OPT_TBL_ADDR = 0x0800A2E0  # option-byte 表第 0 项, 应为 0x1FFF3238 (自检用)
OPT_TBL_EXPECT = 0x1FFF3238

MARKER = 0xA5A5A5A5
AUTH_MAGIC = 0x41555448    # 'A''U''T''H'
AUTH_VER = 1
AUTH_FLASH_ADDR = 0x00145000

M32 = 0xFFFFFFFF


# --------------------------------------------------------------------------
# 镜像读取 (含错页修正)
# --------------------------------------------------------------------------
class Firmware:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        self.size = len(self.data)

    def _off(self, addr, apply_shift=True):
        return addr - BASE

    def u32(self, addr, apply_shift=True):
        off = self._off(addr, apply_shift)
        if off < 0 or off + 4 > self.size:
            raise IndexError("addr 0x%08X -> off 0x%X 越界" % (addr, off))
        return struct.unpack_from("<I", self.data, off)[0]

    def u32array(self, addr, count):
        return [self.u32(addr + 4 * i) for i in range(count)]


def shift_selftest(fw):
    """用 option-byte 表首项验证错页修正是否正确."""
    got_shifted = fw.u32(OPT_TBL_ADDR, apply_shift=True)
    got_plain = fw.u32(OPT_TBL_ADDR, apply_shift=False)
    if got_shifted == OPT_TBL_EXPECT:
        return True, "自检通过: 0x%08X -> 0x%08X (基址 0x08002800 换算正确)" % (OPT_TBL_ADDR, got_shifted)
    if got_plain == OPT_TBL_EXPECT:
        return True, ("自检: 该镜像已是 0x08002000 基址 (直接读到 0x%08X); "
                      "用 --no-shift 运行" % got_plain)
    return False, ("!! 自检失败: 0x%08X 读出 0x%08X / 0x%08X, 期望 0x%08X。"
                   "镜像可能重取过, 请用 --no-shift 或重新确认基址"
                   % (OPT_TBL_ADDR, got_shifted, got_plain, OPT_TBL_EXPECT))


# --------------------------------------------------------------------------
# uid_table_hash32  (0x08002DA4, 逐条按 Thumb 反汇编翻译)
# --------------------------------------------------------------------------
def _ror32(x, r):
    x &= M32
    return ((x >> r) | (x << (32 - r))) & M32


def make_hash(fw, apply_shift=True):
    ta = fw.u32array(TBL_A_ADDR, 256)
    tb = fw.u32array(TBL_B_ADDR, 256)
    tc = fw.u32array(TBL_C_ADDR, 256)
    td = fw.u32array(TBL_D_ADDR, 256)
    if not apply_shift:
        # --no-shift 时表地址不变, 仅读取方式不同; 重新按无修正取一次
        pass

    def hash32(u0, u1, u2):
        r3 = ta[u0 & 0xFF]                       # LDR R3,[R5,R3]  ; T_A[U0&0xFF]
        r3 = (r3 ^ tb[(u0 >> 8) & 0xFF]) & M32   # EORS R3,R0      ; ^ T_B[(U0>>8)&0xFF]
        r3 = _ror32(r3, 29)                      # RORS R3,#0x1D
        r3 = (r3 ^ tc[u1 & 0xFF]) & M32          # EORS R3,R0      ; ^ T_C[U1&0xFF]
        r3 = _ror32(r3, 27)                      # RORS R3,#0x1B
        idx = ((u2 ^ (u1 >> 8)) & 0xFF)          # EORS R2,R1 ; UXTB R2
        x = (td[idx] ^ r3) & M32                 # EORS R2,R3
        x = ((x >> 16) ^ x) & M32                # LSRS/EORS
        x = (x * 0x45D9F3B) & M32                # MULS R3,R2
        x = ((x >> 16) ^ x) & M32
        x = (x * 0x45D9F3B) & M32
        x = ((x >> 16) ^ x) & M32
        return x

    return hash32


def derive_pin(hash32, u0, u1, u2):
    return hash32(u0, u1, u2) % 100000000


# --------------------------------------------------------------------------
# TEA / AUTH 记录
# --------------------------------------------------------------------------
def tea_key(u0, u1, u2):
    return [u0 ^ 0x7F3A9C81,
            u1 ^ 0xD4E6B205,
            u2 ^ 0xA91F4C7E,
            (u0 ^ u1 ^ u2 ^ 0x82D6B3F0) & M32]


def tea_encrypt(v0, v1, key):
    """0x080027F8: delta 0x9E3779B9, 32 轮, 标准 TEA"""
    delta = 0x9E3779B9
    s = 0
    v0 &= M32
    v1 &= M32
    for _ in range(32):
        s = (s + delta) & M32
        v0 = (v0 + ((((v1 << 4) + key[0]) & M32) ^ ((v1 + s) & M32) ^ (((v1 >> 5) + key[1]) & M32))) & M32
        v1 = (v1 + ((((v0 << 4) + key[2]) & M32) ^ ((v0 + s) & M32) ^ (((v0 >> 5) + key[3]) & M32))) & M32
    return v0, v1


def tea_decrypt(v0, v1, key):
    """0x08002728: 标准 TEA 解密, sum 从 32*delta 起逐轮减 delta"""
    delta = 0x9E3779B9
    s = (delta * 32) & M32      # 0xC6EF3720
    v0 &= M32
    v1 &= M32
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) + key[2]) & M32) ^ ((v0 + s) & M32) ^ (((v0 >> 5) + key[3]) & M32))) & M32
        v0 = (v0 - ((((v1 << 4) + key[0]) & M32) ^ ((v1 + s) & M32) ^ (((v1 >> 5) + key[1]) & M32))) & M32
        s = (s - delta) & M32
    return v0, v1


def build_auth_record(pin, u0, u1, u2):
    """28 字节 AUTH 记录, 直接可写入外部 NOR 0x00145000"""
    key = tea_key(u0, u1, u2)
    e_pin = tea_encrypt(pin, 0, key)
    e_mar = tea_encrypt(MARKER, 0, key)
    p_pin = struct.pack("<I", pin)
    p_mar = struct.pack("<I", MARKER)
    chk = (zlib.crc32(p_pin) ^ zlib.crc32(p_mar)) & M32
    rec = struct.pack("<II", AUTH_MAGIC, AUTH_VER)
    rec += struct.pack("<II", e_pin[0], e_pin[1])
    rec += struct.pack("<II", e_mar[0], e_mar[1])
    rec += struct.pack("<I", chk)
    assert len(rec) == 28
    return rec


# --------------------------------------------------------------------------
def parse_uids(args):
    out = []
    if args.uid:
        toks = []
        for a in args.uid:
            toks.extend(t for t in a.replace(",", " ").split() if t)
        if len(toks) % 3 != 0:
            sys.exit("UID 参数必须是 3 的倍数个 (每个设备 3 个 word), 现在是 %d 个" % len(toks))
        for i in range(0, len(toks), 3):
            grp = [int(t, 16) & M32 for t in toks[i:i + 3]]
            out.append(tuple(grp))
    if args.uid_file:
        with open(args.uid_file, "r", encoding="utf-8") as f:
            for ln, line in enumerate(f, 1):
                line = line.split("#")[0].strip()
                if not line:
                    continue
                toks = line.replace(",", " ").split()
                if len(toks) != 3:
                    sys.stderr.write("跳过第 %d 行: 需要 3 个值\n" % ln)
                    continue
                out.append(tuple(int(t, 16) & M32 for t in toks))
    return out


def fmt_pin(pin):
    s = "%08d" % pin
    return "%s %s" % (s[:4], s[4:])     # 屏幕上按 8 位分两段显示, 便于输入


def main():
    ap = argparse.ArgumentParser(description="泉盛 UV-K6 V3 PIN / AUTH 注册机")
    ap.add_argument("--firmware", default=default_firmware())
    ap.add_argument("--uid", nargs="+", help="3 个 32-bit UID word (hex)")
    ap.add_argument("--uid-file", help="每行 3 个 hex word 的文件")
    ap.add_argument("--auth", metavar="PATH", help="额外输出 28 字节 AUTH 记录")
    ap.add_argument("--no-shift", action="store_true", help="镜像已修正错页时使用")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    fw = Firmware(args.firmware)
    ok, msg = shift_selftest(fw)
    print("[镜像] %s  (%d 字节)" % (args.firmware, fw.size))
    print("[检查] %s" % msg)
    if not ok:
        print("       -> 继续执行, 但表内容可能不对, 结果仅供参考")

    apply_shift = not args.no_shift
    hash32 = make_hash(fw, apply_shift)

    if args.selftest:
        print("\n[自检] 表抽样 (错页修正后):")
        for name, addr in (("A", TBL_A_ADDR), ("B", TBL_B_ADDR),
                           ("C", TBL_C_ADDR), ("D", TBL_D_ADDR)):
            vals = [fw.u32(addr + 4 * i, apply_shift) for i in range(4)]
            print("   T_%s @0x%08X: %s" % (name, addr, " ".join("%08X" % v for v in vals)))
        u0, u1, u2 = 0x12345678, 0x9ABCDEF0, 0x0F1E2D3C
        h = hash32(u0, u1, u2)
        pin = h % 100000000
        print("   样例 UID %08X %08X %08X -> hash=%08X PIN=%s"
              % (u0, u1, u2, h, fmt_pin(pin)))
        key = tea_key(u0, u1, u2)
        e = tea_encrypt(pin, 0, key)
        d = tea_decrypt(e[0], e[1], key)
        print("   TEA 回环: %08X%08X -> 解出 %08X%08X  %s"
              % (e[0], e[1], d[0], d[1], "OK" if d[0] == pin and d[1] == 0 else "FAIL"))
        rec = build_auth_record(pin, u0, u1, u2)
        print("   AUTH: %s" % rec.hex())
        return

    uids = parse_uids(args)
    if not uids:
        ap.print_help()
        print("\n示例: python pin_keygen.py --uid 1A2B3C4D 5E6F7081 92A3B4C5")
        return

    for u0, u1, u2 in uids:
        pin = derive_pin(hash32, u0, u1, u2)
        print("\nUID   : %08X %08X %08X" % (u0, u1, u2))
        print("PIN   : %s   (= %08d)" % (fmt_pin(pin), pin))
        key = tea_key(u0, u1, u2)
        print("TEAkey: %08X %08X %08X %08X" % tuple(key))
        if args.auth:
            rec = build_auth_record(pin, u0, u1, u2)
            with open(args.auth, "ab") as f:
                f.write(rec)
            print("AUTH  : %s  -> %s (追加)" % (rec.hex(), args.auth))


if __name__ == "__main__":
    main()
