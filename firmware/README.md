# 把固件放这里

本仓库**不附带任何固件**。测试和示例需要你自己准备固件文件，放到本目录，例如：

```
firmware/firmware_decrypted.bin      # mcu_vm.py 的默认查找名
```

也可以不放在这里，用环境变量或命令行指定：

```bash
export K5_FW=/path/to/your.bin
python mcu_vm.py --firmware /path/to/your.bin --panel
```

> 请只使用你自己合法获得的固件。厂商固件受版权保护，勿随仓库分发。
