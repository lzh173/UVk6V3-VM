# 手持对讲机固件虚拟机（泉盛 UV-K5 / UV-K6 系列）

[![build](https://github.com/lzh173/UVk6V3-VM/actions/workflows/build.yml/badge.svg)](https://github.com/lzh173/UVk6V3-VM/actions/workflows/build.yml)

仓库：<https://github.com/lzh173/UVk6V3-VM>

用 [Unicorn](https://github.com/unicorn-engine/unicorn) 在 PC 上跑手持对讲机的 ARM Cortex-M0+ 固件：
外设寄存器级建模、128×64 点阵屏、仿真键盘、串口刷机协议、写频协议，全部用 Python 实现。

> 项目最初是为了分析一台 **泉盛 UV-K6 V3（兼容 K1）** 手持机的固件，
> 后来扩展成一套通用的固件运行/调试/刷机工具链。

---

## 能做什么

| 功能 | 说明 |
|---|---|
| **固件运行** | Cortex-M0+ 指令级模拟（Unicorn），无需硬件即可跑原厂/第三方固件 |
| **屏幕渲染** | ST7565（132×64）控制器建模，终端字符画 / PNG / 实时面板三种显示 |
| **真机面板** | Tk 面板：LCD + 真机键盘（可点击）+ GPIO 矩阵 + 电池电压滑条 + 电源/重启 |
| **刷机协议** | 完整复刻 bootloader：`0x0518` 会话、`0x0530` 解锁、`0x0516` 参数、`0x0519` 数据块 |
| **写频协议** | 应用态 `0x0514/0x051B/0x051D/0x051F/0x0521` 等，可对接厂商网页写频工具 |
| **PC 工具** | `k5tool.py`：握手 / 读 EEPROM / 写频 / 刷机 / 自检 |
| **ROM 导出** | `RomDumper`（带 GUI，可打包 exe）走 `0x051F` 快速导出整片 4 MB SPI Flash |
| **官方固件解密** | 自动识别泉盛官方升级包（128 字节重复密钥 XOR + CRC16 + 版本号间隙） |
| **PIN 注册机** | 从固件里还原 PIN/AUTH 校验逻辑并离线算码 |

## 快速开始

```bash
pip install -r requirements.txt

# 把你的固件放到 firmware/ 目录（仓库不附带任何固件）
python mcu_vm.py --firmware firmware/xxx.bin --panel      # 真机面板
python mcu_vm.py --firmware firmware/xxx.bin --text       # 终端字符画
python mcu_vm.py --firmware firmware/xxx.bin --png out.png
```

常用参数：

```
--panel / --gui / --text        显示方式
--unlock-ui                     兼容开关：第三方固件不刷新屏幕时用（Dondji / mangosteen）
--flash fw.bin                  挂一个 4 MB 固件空间（可被刷机写入，掉电保持）
--com COM14 / --uart 8801       串口桥（真实串口 或 TCP）
--batt 7.2                      电池电压（影响 ADC 读数与低电图标）
--tps 1000                      限制每秒 tick 数（0 = 不限速，1000 ≈ 实时）
--ptt                           PTT 开机：手电筒常亮 + 背光 + 进刷机模式
```

命令行工具：

```bash
python k5tool.py selftest                     # 协议自检
python k5tool.py flash firmware/xxx.bin       # 通过 bootloader 刷机
python k5_decrypt.py 官方固件.bin out.img.bin # 解密泉盛官方升级包
python pin_keygen.py                          # PIN / AUTH 注册机
dist/RomDumper.exe --port COM15 --out rom.bin --size 4M   # 导出整片 Flash
```

## 构建与 CI

`.github/workflows/build.yml` 一次产出 **6 个可执行文件**（3 个工具 × 2 种打包器）：

| 工具 | PyInstaller 工件 | Nuitka 工件 |
|---|---|---|
| RomDumper（ROM 导出 GUI） | `pyinstaller-romdumper` | `nuitka-romdumper` |
| K5Tool（PC 客户端） | `pyinstaller-k5tool` | `nuitka-k5tool` |
| MCUVM（固件虚拟机） | `pyinstaller-mcuvm` | `nuitka-mcuvm` |

- **PyInstaller**：每次 push / PR 都跑（几分钟出结果）
- **Nuitka**：单个数分钟到十几分钟，只在 **打 tag** 或 **手动触发** 时跑
- **打 tag** 时自动把 6 个 exe 附到 GitHub Release

本地打包：

```bash
pip install pyinstaller                 # 或者：pip install nuitka ordered-set zstandard
python tools/build.py --list            # 看有哪些工具
python tools/build.py --backend pyinstaller              # 3 个全打
python tools/build.py --backend nuitka --tool k5tool     # 只打一个
```

产物分别落在 `dist/pyinstaller/` 和 `dist/nuitka/`，互不覆盖。

## 目录结构

```
mcu_vm.py            Cortex-M0+ 虚拟机 + 外设模型 + 面板 UI + 命令行
radio_device.py      设备侧模型：4MB 固件空间、bootloader/写频协议、串口桥
k5tool.py            PC 侧客户端（握手/读写/刷机/自检）
k5_decrypt.py        泉盛官方加密固件解密
pin_keygen.py        PIN / AUTH 注册机
rom_dumper_gui.py    整片 ROM 导出工具（Tk GUI，可 PyInstaller 打包）
sniff_param.py       协议嗅探：伪装成 bootloader 抓真实写频器的参数
tests/               协议、刷机闭环、大镜像刷机等回归测试
tools/               build.py（统一打包）、截图、演示脚本
docs/                逆向分析报告（ANALYSIS.md）与复核记录
data/                合成的最小可用设置块（非真机数据）
assets/              截图
firmware/            放你自己的固件（已 gitignore）
ref/                 第三方固件源码参考（已 gitignore）
```

## 建模范围

- **CPU**：Cortex-M0+（Thumb），SysTick/异常用"子程序调用 + 哨兵返回"方式模拟
- **GPIO**：A~F 全端口，含双向键盘矩阵（行/列方向自适应）、上拉、复用
- **显示**：SPI1 + ST7565，132 列 RAM、A0/DC、页/列寻址
- **外置 Flash**：SPI2 + PY25Q16 状态机（读/写/擦、DMA、片选）
- **DMA1**：7 通道、GIF/TCIF 标志、IRQ 9/10/11 分发
- **串口**：USART1 + RX DMA
- **其它**：ADC（电池换算）、TIM7（背光）、RCC、SYSCFG、NVIC、BK4829 三线总线（位操作）

## 已知限制

- 仓库**不附带任何固件**（版权原因）。测试脚本需要你自己提供固件，见 `firmware/README.md`。
- 第三方固件（Dondji / mangosteen 等）需要 `--unlock-ui`：它们的显示门控在启动时被置位且固件自身不会清除。
- 泉盛官方 7.01.09 固件可以解密并运行（RF 初始化完成），但界面尚未绘制——
  它的 `gCurrentFunction` 会直接进入省电态，详见 `docs/ANALYSIS.md` §14.40。
- 屏幕渲染按 128 列窗口（ST7565 RAM 第 4..131 列）对齐。

## 致谢

- [Unicorn Engine](https://github.com/unicorn-engine/unicorn)、[Capstone](https://github.com/capstone-engine/capstone)
- [Pillow](https://python-pillow.org/)、[pyserial](https://github.com/pyserial/pyserial)、[loguru](https://github.com/Delgan/loguru)
- 社区固件项目：DualTachyon / egzumer / amnemonic 等（协议格式与官方包解密思路参考其公开资料）

## 许可

[AGPL-3.0](LICENSE)。仓库不包含任何厂商标识、固件二进制或设备校准数据。

> 使用本项目的衍生作品需同样以 AGPL-3.0 开源（含网络服务场景）。
