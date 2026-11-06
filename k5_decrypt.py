# -*- coding: utf-8 -*-
"""解密/还原 泉盛 (Quansheng) 官方固件 .bin

官方升级包的格式（社区 qsfirm.py 的做法）:
  1. 全文件按 128 字节重复密钥 XOR
  2. 末尾 2 字节 = CRC16-CCITT(前面所有字节)，小端
  3. 明文偏移 0x2000 处有 16 字节版本号（如 "7.01.09\\0..."），
     **解码成可运行镜像时要把这 16 字节抽掉**，后面内容整体前移

用法:
    python k5_decrypt.py <官方固件.bin> [输出镜像.bin]

例:
    python k5_decrypt.py "D:\\下载\\官方固件_K5_V.7.01.09.bin" k5_v7.01.09.img.bin

说明: 密钥是用"同代码家族的明文固件做参考直方图"逐列恢复出来的，
      前 16 字节与社区公开值一致（16/16），另用 276 个已知明文片段交叉验证过。
"""
import struct
import sys

XOR_KEY = bytes.fromhex(
    "4722c0525d574894b16060db6fe34c7c"
    "d84ad68b30ec25e04cd9007fbfe35405"
    "e93a976bb06e0cfbb11ae2c9c15647e9"
    "baf142b6675f0f96f7c93c841b26e14e"
    "3b6f66e6a06ab0bfc6a5703aba189e27"
    "1a535b71b1941e18f2d6810222fd5a28"
    "91dbba5d64c6fe86839c501c730311d6"
    "af30f42c77b27dbb3f29285722d6928b")


def crc16_ccitt(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def decrypt(raw):
    """返回 (镜像, 版本串, 说明)"""
    sp = struct.unpack_from("<I", raw, 0)[0]
    if 0x20000000 <= sp <= 0x20004000:
        return raw, "", "已经是明文镜像（向量表正常），不再解密"

    plain = bytes(b ^ XOR_KEY[i % 128] for i, b in enumerate(raw))
    sp2 = struct.unpack_from("<I", plain, 0)[0]
    if not (0x20000000 <= sp2 <= 0x20004000):
        raise SystemExit("解密失败：向量表仍不合法（SP=0x%08X）" % sp2)

    stored = raw[-2] | (raw[-1] << 8)
    calc = crc16_ccitt(raw[:-2])
    crc_note = "CRC OK" if stored == calc else "CRC 不一致(0x%04X/0x%04X)" % (stored, calc)

    body = plain[:-2]
    ver = body[0x2000:0x2010].split(b"\x00")[0].decode("latin1", "ignore")
    img = body[:0x2000] + body[0x2010:]
    return img, ver, "解密完成（%s，抽掉 16 字节版本号）" % crc_note


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else src.rsplit(".", 1)[0] + ".img.bin"
    raw = open(src, "rb").read()
    img, ver, note = decrypt(raw)
    if img is raw:
        print("跳过:", note)
        return
    print("版本:", ver)
    print("大小: %d -> %d 字节" % (len(raw), len(img)))
    print(note)
    print("SP=%08X Reset=%08X" % (struct.unpack_from("<I", img, 0)[0],
                                  struct.unpack_from("<I", img, 4)[0]))
    open(dst, "wb").write(img)
    print("已写出:", dst)


if __name__ == "__main__":
    main()
