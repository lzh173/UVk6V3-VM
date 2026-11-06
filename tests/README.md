# 回归测试

所有测试都需要**你自己的固件**（仓库不附带）。默认从 `firmware/firmware_decrypted.bin` 读，
也可以用环境变量覆盖：

```bash
export K5_FW=/path/to/your.bin      # Windows: set K5_FW=D:\path\your.bin
```

| 脚本 | 内容 | 需要固件 |
|---|---|---|
| `test_bl_protocol.py` | bootloader 全流程：横幅 / 0x0518 / 0x0530 / 0x0516 / 0x0519 写块 / 回读校验 | ✅ |
| `test_flash_cycle.py` | 串口刷机 → 设备自动重载 → 画面变化（端到端） | ✅ |
| `test_flash_big.py` | 刷 469 块（约 120 KB）大镜像 → 跳转后不跑飞 | ✅ |
| `test_flash_payloads.py` | 各种 payload 的编解码 | ✅ |

运行：

```bash
cd ..
python tests/test_bl_protocol.py
python tests/test_flash_cycle.py
python tests/test_flash_big.py
```

通过的输出形如 `结果: 通过`。
