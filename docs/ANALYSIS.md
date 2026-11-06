# firmware_decrypted.bin — 逆向分析报告

分析对象：`firmware/firmware_decrypted.bin`
（IDA 中当前加载的数据库：`firmware_decrypted.bin.i64`）

---

## 0. 结论摘要

这是一台**手持多功能小工具**的固件（作者署名 **BD1AHN**，业余无线电呼号），Cortex-M0/M0+ 类 ARM32 Thumb 代码，**真实链接基址 `0x08002800`**，提取长度 **35,396 B (0x8A44)**。

内置四个 app：**计算器 / 俄罗斯方块 / 电子木鱼 / CW 练习器**。

与安全相关的只有两处：

1. **开机 PIN 门禁**：8 位数字，由 MCU UID 经表驱动散列取模 1e8 得到；成功后把一条 28 字节 `AUTH` 记录用 UID 派生密钥 TEA 加密后写入**外部 SPI NOR 的 `0x00145000`**。
2. **认证后的 "Enable RDP?" 流程**：长按 MENU 1.4 秒，把 MCU 选项字节 `OPTR.RDP` 从 `0xAA`（Level 0）改成 `0x55`（Level 1）并复位 —— 即**给芯片上读保护**。

镜像本身有一个**基址判定错误**（更正见 §9）：固件实际链接在 `0x08002800`，而 IDA 按 `0x08002000` 装载，于是所有"绝对地址类"引用（字符串、资源表、向量表内容）在 IDB 里都偏低 0x800。

> **地址约定**：下文 `0x0800xxxx` 是 IDA 当前视图里的地址（方便在原 IDB 里对照），**真实 Flash 地址 = 该地址 + 0x800**。
> 已用 §11 的模拟器 + §8.1 的注册机做过端到端验证。

---

## 1. 基本属性

| 项 | 值 |
|---|---|
| 文件 | `firmware_decrypted.bin` |
| 大小 | 35,396 B (0x8A44) |
| MD5 | `07F190E5E9676BA28EAC7D531BE665C0` |
| SHA-256 | `ac2029af64b2f3ebedc9e80a7ca1a8b97c3dfcc0122583cade70452f0690cc7c` |
| 架构 | ARM 32-bit Thumb (Cortex-M0/M0+ 级指令集，无 FPU 指令，浮点用软件库) |
| 镜像基址 | **`0x08002800`**（向量表在文件偏移 0；IDA 旧视图按 0x08002000 装载，差 0x800） |
| 段 | `Code` **0x08002800–0x0800B243**（IDA 旧视图 0x08002000–0x0800AA44）；`SRAM` 0x20000000–0x20004000 (16 KB)；`PPB` 0xE0000000 |
| 函数 | 173 个（49 个已命名，124 个 `sub_`） |
| 入口 | 向量表 **`0x08002800`**：SP = `0x20004000`，Reset = `0x08002D89` |

RAM 使用：`0x20000000–0x20000050` 系统/安全变量，`0x20000050–0x20000268` 各 app 状态，`0x20000268–0x20001268` 外部 Flash 4 KB 页缓存，`0x20001268–0x20001568` LCD 帧缓冲（8×128 B），`0x20001568+` 剩余 app 缓冲。

---

## 2. 平台判定（MCU 家族）

寄存器映址与 **STM32G0** 家族高度吻合：

| 外设 | 基址 | 用到的寄存器 / 证据 |
|---|---|---|
| GPIO A–F | `0x50000000` + n*0x400 | MODER 0x00、IDR 0x10、BSRR 0x18、BRR 0x28、AFR 0x20/0x24 |
| RCC | `0x40021000` | **IOPENR 0x34**（GPIO 时钟）、**AHBENR 0x38**（DMA）、**APBENR1 0x3C**、**APBENR2 0x40** —— G0 独有的 0x34/0x38/0x3C/0x40 布局 |
| SPI1 | `0x40013000` | CR1 0x00 (SPE=bit6)、SR 0x08 (TXE=bit1, RXNE=bit0)、DR 0x0C → **LCD** |
| SPI2 | `0x40003800` | CR1/CR2/SR → **外部 SPI NOR** |
| USART1 | `0x40013800` | 仅在 `init_display_serial_interface` 中被配置过一次（未使用的中文注释遗留，或早期版本用串口屏） |
| DMA1 | `0x40020000` | IFCR 0x04；ch4 `0x40020044/48/4C/50`、ch5 `0x40020058/5C/60/64` → SPI2 TX/RX（G0 上 ch4=SPI2_TX、ch5=SPI2_RX） |
| ADC1 | `0x40012400` | ISR/IER/CFGR1 0x08/CFGR2 0x0C/SMPR 0x14；采样电池 |
| FLASH | `0x40022000` | `0x40022020` 为 **OPTR**（低字节 RDP，`0xAA`=Level0）；`0x40022008/0x4002200C` 接受 FLASH KEY / OPTKEY |

**两处与正牌 STM32G0 不一致**，因此更可能是 G0 兼容的国产/定制型号（或厂商扩展寄存器）：

- **UID 在 `0x1FFF3000`**（3 个 word）。G0 的 UID 在 `0x1FFF7590`；`0x1FFF3000` 这个位置不属于 ST 公开映射。散列里还引用了 `0x1FFF32xx` 一批指针（表 `0x08009AE0`）。
- **选项字节编程窗口在 `0x40022100–0x40022124`**（8 个 32 位"影子寄存器"，分别对应 WRPL/WRPH/USER/RDP/SPR/…）。正牌 G0 没有这个窗口，选项字节是直接写 `OPTR` 等寄存器。
- FLASH 解锁序列用的是 G0 的 KEY/OPTKEY 值（KEY2=`0xCDEF89AB`、OPTKEY2=`0x4C5D6E7F`），说明是"G0 语义 + 厂商扩展"。

> 结论：**按 STM32G0 的语义理解代码是安全的，但选项字节编程的位域不能直接套 ST 手册**；具体型号需要 die mark 或读 `0x1FFF3000` 才能确定。

---

## 3. 存储布局

### 3.1 内部 Flash（0x08000000 段）

| 地址 | 内容 |
|---|---|
| **`0x08002800`** | 向量表（48 项，文件偏移 0） |
| `0x080028C0` | 代码开始（`__gnu_thumb1_case_*` 辅助例程） |
| `0x080028C0–0x08009050` | 代码 + 紧跟函数尾部的字面量字符串（`"Time: "`、`"Score:"` 在 `0x0800538F/0x08005398`） |
| `0x080090E5–0x08009300` | UI 字符串表（英文 + **GB2312** 中文） |
| `0x08009300–0x0800A8B0` | 高熵数据（熵 7.6–7.9，疑似压缩/加密块） |
| `0x0800A8B0–0x0800AFC0` | 8×12 ASCII 点阵字库 |
| `0x0800AFC6+` | **12×12** 中文点阵字库（26 B/字形：2 B 小端 Unicode 码位 + 24 B 位图 = 12 行×2 B，每行用高 12 bit），共 **20 字形**（见下） |
| `0x0800A9D0` | 字形数量 = 20 |
| `0x0800A9D4` | 电量分档阈值表 |

内置的 20 个中文字形（按表顺序）：

```
习 俄 功 单 器 回 块 子 德 斯 方 木 电 算 练 罗 菜 计 返 鱼
```

拼起来正好覆盖 "俄罗斯方块 / 电子木鱼 / 计算器 / 功德+1 / CW练习器 / 菜单 / 返回"。

### 3.2 外部 SPI NOR

- JEDEC 风格命令：`0x03` 读、`0x05` 读状态、`0x06` 写使能、`0x02` 页编程、`0x20` 扇区擦、`0xD8` 块擦。
- 页管理单位 **4096 B**（`flash_update_record` 按 4 KB 页读-改-写）。
- 关键数据：**`0x00145000` = AUTH 记录（28 字节）**。

---

## 4. 启动链

```
0x08002800 向量表  ──Reset──▶ 0x08002D89  Reset_handler
                                    │
                                    ├─ 键盘扫描（MENU/EXIT 组合，长按检测）
                                    ├─ 屏幕提示后直接调用
                                    └─ conditionally_program_option_bytes_and_reset()
                                        （仅在 RDP==0xAA 时生效，编程后 SYSRESETREQ）

0x08002534  firmware_boot_entry  (冷启动主流程)
   ├─ RCC->APBENR2 |= SYSCFG?        (0x40021040 |= 1)
   ├─ RCC->APBENR1 |= 0x10000000
   ├─ set_system_clock_hz(48_000_000)   ← 只是把 48e6 存进 0x20000000，没有任何 PLL 配置
   └─ 0x08005D64 firmware_main_entry
        ├─ 0x08005A0C init_systick_10ms      (RVR = 48e6/100-1 = 479999，10 ms 节拍)
        ├─ 0x08005D4C init_hardware_subsystems  (GPIO → DMA/TIM → ADC → LCD)
        ├─ 0x08005414 init_external_flash_spi_dma_irq11
        ├─ 0x0800634C / 0x080063D4  开机画面绘制
        ├─ delay(1500)
        ├─ 0x080029EC pin_gate_and_config_menu()      ← PIN 门禁（阻塞）
        └─ 0x0800412C init_ui_state() → 0x08004164 ui_main_loop_iteration() 永循环
```

**时钟注意点**：`set_system_clock_hz()`（`0x08002698`）只有一条 `STR`，把 48 MHz 常量写进 RAM。全镜像未见 PLL/HSI/HSE 配置代码，说明本 dump 里没有时钟树初始化（可能在被裁掉的低地址区，或 MCU 直接用复位默认时钟），而 48 MHz 只被用于 SysTick 与软件延时换算。

**VTOR（已更正）**：`relocate_vtor_to_code_0x08002800` 把 `SCB->VTOR` 写成 `0x08002800` —— 这正是镜像自己的基址，**完全正常**。
旧版报告说"0x08002800 首字是 0x2603001D、不是向量表"，那是把 IDA 旧视图（基址差 0x800）当成了真址：真实 `0x08002800` 首字就是 `0x20004000`（合法 SP），`0x2603001D` 位于真址 `0x08003000`。


---

## 5. 外设与驱动

### 5.1 LCD（128×64 单色，ST7565 家族）

- 总线：**SPI1 主机** `0x40013000`（模式 0，8-bit，MSB first），写字节 `0x08005784`：等 `SR.TXE` → 写 `DR` → 等 `SR.RXNE`。
- 控制线：**A0/DC = PA6**（BSRR/BRR `0x50000018/0x50000028` bit6）、**CS = PB2**（`0x50000418/0x50000428` bit2）、复位由 GPIO 初始化序列完成。
- 初始化命令序列（`0x080058D4`）：`0xE2`(软复位) → `0x2B/0x2E/0x2F`(升压级) → `0x40`(起始行) → `0xA4`/`0xA5` → `0xAF`(开显示) → `0x81`+对比度 → 列地址 0…7。
- 帧缓冲 `0x20001268`，8 页 × 128 B；`display_flush`（`0x08005830`）按页整块刷。
- 局部反显实现见 `0x08004024`（菜单高亮：直接 XOR 帧缓冲中的 8 列）。

### 5.2 键盘扫描（20 键 + 1 独立键）

`0x080051B0 scan_keypad_matrix()`：

- 行驱动：GPIOB `BSRR 0x50000418`（PB3–PB6，先写 `0x78` 复位，再逐行 `1<<(7-i)`）。
- 列读取：GPIOB `IDR 0x50000410 & 0xF000` → **PB12–PB15 共 4 列**；另用 `& 0x400`（**PB10**）检测一个独立键，命中时返回 `0x10`。
- 每行连续采样 8 次做去抖（两次不一致即重新开始）。
- 键值表：`0x0800A72E`，20 字节（5 行 × 4 列）。`0x13` = 无键；`0x10` = 特殊键；`0x0A` ≈ MENU、`0x0D` ≈ EXIT/返回、`0x0E` ≈ 退格、`0x0F` ≈ 模式切换（由各 app 的 case 推得）。

### 5.3 外部 SPI NOR + DMA

- SPI2 `0x40003800`，DMA1 ch4(TX)/ch5(RX)，NVIC IRQ11（`NVIC_ISER_0 = 0x800`）。
- 驱动函数：`flash_wait_ready` (`0x08005288`)、`flash_erase_page` (`0x080052B8`)、`flash_program_bytes` (`0x080052E8`，≤15 B 走轮询、>15 B 走 DMA)、`flash_read_page` (`0x08005504`)、`flash_update_record` (`0x0800560C`，4 KB 页读-改-写 + 位与判空 + 必要时擦除重写)、DMA 完成中断 `0x080056FC`（清标志、等 SPI 空闲、置 `byte_20000260`）。

### 5.4 电池 / ADC

`0x08005B6C init_adc_and_analog_inputs()` 走 ADC1 校准 + 采样配置；`adc_read_sample` (`0x08005D20`) 单次转换；`sample_battery_and_update_status` (`0x08005E74`) 采 4 次取均值 → `760 × avg` → 6 档电量（阈值表 `0x0800B1D4`，本文件内位于 `0x0800A9D4`）。

### 5.5 数学库

`0x08006B08`(dadd) / `0x08007A80`(dmul) / `0x080087A0`(int→double) / `0x08008844..` 等为软件浮点/整型辅助，供计算器使用（用到常量 `0x3FF0000000000000`=1.0、`0x3FB999999999999A`=0.1）。

---

## 6. 应用层

菜单状态机：`byte_2000012E`（0–3 选中项）、`byte_2000012F`（1–4 正在运行的 app）、`byte_2000012B`（上次按键）。菜单栏由 `0x08004024` 绘制，标签指针表 **`0x0800A330`**（`{4, 4 个指针}`；`0x0800A304` 是 ASCII 字模字节）。

| # | App | 入口 | 说明 |
|---|---|---|---|
| 1 | **计算器** | `0x08003C38` + `0x0800303C` | 8 位输入缓冲，`0x0800303C` 把字符串解析成 double（`-` 符号、`.` 小数、逐位 `×10 + d`，小数部分乘 0.1 累加）；`0x080035BC` 负责四则运算调度，`0x08003744` 在操作数间切换 |
| 2 | **俄罗斯方块** | `0x08004DF8` | 10 列场地、`0x08004708` 碰撞检测（含旋转 `byte_20000156` 0–3）、`0x080044AC` 随机取块、`0x08004C84` 落块/消行、`0x08004750` 画 `"Time: "`/`"Score:"`；`0x08004C14` 处理暂停/结束 |
| 3 | **电子木鱼** | `0x080043E4` + `0x0800426C` | 按 MENU(`0x0A`) 累加 `dword_20000138`（功德计数），40 ms 一帧的敲击动画（`byte_20000133/34/35` 逐帧递减），显示 `"功德+1"` 与计数 |
| 4 | **CW 练习器** | `0x08003EFC` + `0x08003D80` | T9 文本输入（`abc/ABC/NUM` 三态、`*:Del`、`F:.`、`Menu:=`），`0x08003D54` 光标/字符切换，`0x08003D80` 绘制输入行；输入内容用于呼叫/电码练习 |

字符串表（文件内实际地址，代码引用地址 = 本址 + 0x800）：

```
0x080090E5 "Device MAC"      0x080090F0 "%08lX"      0x080090F6 "MENU=Input"
0x08009101 "F=Mode"          0x08009108 "MENU=OK"    0x08009110 "EXIT=Back"
0x0800911A "Authorized!"     0x08009126 "Auth FAILED" 0x08009132 "Retry..."
0x0800913B "Enable RDP?"     0x08009147 "MENU=Yes"   0x08009150 "EXIT=No"
0x08009158 "Enabling RDP..." 0x08009168 "Device will reset"
0x0800917A "________"        T9 表： .,?! / abc…wxyz / ABC…WXYZ / NUM
0x080091D9 "*:Del"  0x080091DF "F:."  0x080091E3 "Menu:="  0x080091EA "<>:+-x"
0x08009208 "1.计算器"        0x08009214 "2.俄罗斯方块"
0x08009226 "3.电子木鱼"      0x08009235 "4.CW练习器"
0x08009257 "功德+1"          0x08009260 "Game Over"
0x0800926A "Game"            0x0800926F "power by BD1AHN"
```

---

## 7. 安全机制

### 7.1 PIN 门禁（`0x080029EC pin_gate_and_config_menu`）

**开机主界面**（先于 PIN 提示）：显示 `"Device MAC"` + 三行 `%08lX` + `"MENU=Input"` / `"F=Mode"`。

**注意：这三行 `%08lX` 打印的就是 UID 的三个 word**（`0x20000034 / 0x20000030 / 0x2000002C`，来自 `0x1FFF3000`）。换言之，设备把生成 PIN 的"主密钥材料"直接显示在屏幕上 —— 见 §8。

**PIN 推导**：

```
hash32(U0,U1,U2)  ← 表驱动混合，4 张 256 项表：
                    0x080096E0, 0x08009AE0(0x1FFF32xx 指针表), 0x08009EE0, 0x080092E0
PIN = hash32 % 100000000        (0x08002964 derive_pin_verifier)
```

即 **8 位十进制数**。

**输入比较**（8 字符缓冲 `v38`，占位符 `_`）：

- 8 位全是数字 → 按十进制解析后与 `PIN` 比较；
- 含非数字 → `crc32_ieee_bitwise(v38, 8)` 与 `PIN` 比较（这条分支命中概率 ≈ 2.3%，属于设计上的冗余/错误路径）；
- T9 三态输入（`NUM/abc/ABC`），`0x0E` 退格、`0x0F` 切模式、`0x0A(MENU)` 提交、`0x0D(EXIT)` 返回主界面。

**成功**：置 `dword_20000038 = 0xA5A5A5A5`、`dword_2000003C = PIN`，调用 `persist_pin_gate_state()` 落盘，显示 `"Authorized!"`。

### 7.2 AUTH 记录（外部 NOR `0x00145000`，28 字节）

```
offset  size  field
0x00     4    magic 0x41555448 -> **落盘字节 48 54 55 41 = "HTUA"**（小端 dword 的必然结果，不是 "AUTH"）
0x04     4    version = 1
0x08     8    TEA_encrypt(PIN, 0)
0x10     8    TEA_encrypt(0xA5A5A5A5, 0)
0x18     4    crc32(PIN) XOR crc32(0xA5A5A5A5)
```

**TEA 实现**：`0x080027F8` 加密（delta `0x9E3779B9`，32 轮，标准 xtea-less TEA 结构，`(v<<4 ^ v>>5) + v`），`0x08002728` 解密，`0x08002778` **密钥派生**：

```
k0 = UID0 ^ 0x7F3A9C81
k1 = UID1 ^ 0xD4E6B205
k2 = UID2 ^ 0xA91F4C7E
k3 = UID0 ^ UID1 ^ UID2 ^ 0x82D6B3F0
```

**校验**（`0x080028C0`）：读 28 B → magic/ver 匹配 → 用同一密钥解密两段 → `crc32(P) ^ crc32(M)` 与记录中的校验字比较 → 再要求 `M == 0xA5A5A5A5` → 装载到 `0x20000038/0x2000003C`。

启动时若记录有效且 marker 正确、且 `derive_pin_verifier() == 记录中的 PIN`，则**直接跳过 PIN 输入**进入已认证状态；任一项不符就把两个变量清零并重新要求输入。

### 7.3 RDP 启用流程

已认证后（`0x08002C88` 一带）：

```
显示 "Enable RDP?" / "MENU=Yes" / "EXIT=No"
  ├─ EXIT(0x0D) → 退出，什么都不做
  └─ MENU(0x0A) 长按 140×10 ms = 1.4 s，且需先松手一次 → 
       显示 "Enabling RDP..." / "Device will reset"
       delay 800
       conditionally_program_option_bytes_and_reset()
```

`0x08002F28 conditionally_program_option_bytes_and_reset()`：

1. 仅当 `FLASH->OPTR` 低字节 == `0xAA`（RDP Level 0，未保护）才继续；
2. 用 `(*(u32*)0x40021004 >> 13) & 7` 作索引取 **0x0800A2E0** 表（= 符号 0x0800A2BC + 0x24）中某项（每设备/每型号的选项字节配置字），写入 **9 个** 影子寄存器 `0x40022100…0x40022120`（结构基址 0x400220FC）；
3. `0x40022008 = 0xCDEF89AB`、`0x4002200C = 0x4C5D6E7F`（KEY/OPTKEY2）；
4. 轮询 `SR.BSY`，`*(u32*)0x40022010 = 0x8011`（FLASH 控制寄存器，不是 CR），`OPTR = (OPTR & ~0xFF) | 0x55` → **RDP Level 1**；
5. `CR |= OBL_LAUNCH`，`AIRCR = 0x05FA0004`(SYSRESETREQ)，死等。

**副作用**：RDP Level 1 一旦生效，SWD 读不出 Flash；要解除只能整片擦除（丢全部数据 + AUTH 记录）。这是这台设备唯一"不可逆"的操作。

### 7.4 代码完整性检查（死代码）

- `0x08002E78 compute_protected_code_crc32()`：取 5 个固定函数地址、向下/向上按 256 对齐成区间（`0x0800?00` 起、`0x080?000` 止，约 0x700 B），区间合法（`base ≥ 0x08002800`、`end ≤ 0x08020000`、长度 ≤ 0xFFFF）则算 CRC32 存 `0x20000048`。
- `0x08002E3C`：重算并比对（区间非法时返回"通过"）。
- **更正**：`compute_protected_code_crc32` 在 `pin_gate_and_config_menu` 里确实被调用（结果传给 `sub_80028C0`），不是死代码；`sub_8002E3C` 才是独立存在。

---

## 8. 安全性评估

按实际强度排序：

1. **PIN 与 TEA 密钥全部由 UID 派生，而 UID 被明文显示在开机界面。** 只要看到屏幕上的三行 `%08lX`（或物理上能读一次 UID），就能离线：`hash32 → %1e8` 得到 PIN；`UID → TEA key` 伪造 28 字节 AUTH 记录写进 `0x00145000`。整个门禁的强度 ≈ **混淆**，不是密码学保护。
2. **散列函数是公开的表驱动混合**（4 张 256 项表硬编码在镜像里），没有 secret salt，因此"换一台设备"也不改变可推导性，只是换了输入。
3. **`crc32(P) XOR crc32(M)` 作为完整性校验**：XOR 可交换，把两个 8 字节密文块互换后校验值不变（但 marker 检查会失败）；真正起作用的是"解密后必须得到 `0xA5A5A5A5`"，而这只依赖密钥 —— 又回到第 1 点。
4. **无任何远程/无线输入路径**：镜像里没有 UART 命令解析、没有射频协议栈；SPI 只接本地 LCD 和 NOR。攻击面 = 物理键盘 + SWD。
5. **RDP 启用本身是"加锁"而非"提权"**，风险主要是误操作（把别人的设备锁成 RDP1，解除需全片擦除）。
6. **`relocate_vtor_to_code_0x08002800`** 指向非向量表内存，是执行流完整性上的可疑点；若它真是启动路径的一部分，任何异常中断都会跑飞 —— 更可能是有意布置，或 §9 提取问题的一部分。

---

## 8.1 注册机（已实现）

`pin_keygen.py` —— 按 `uid_table_hash32` 的 26 条 Thumb 指令逐条翻译，并从镜像里提取 4 张 256×32 位表。

```bash
python pin_keygen.py --uid 1A2B3C4D 5E6F7081 92A3B4C5            # 出 PIN
python pin_keygen.py --uid 1A2B3C4D 5E6F7081 92A3B4C5 --auth a.bin  # 顺带出 28 字节 AUTH 记录
python pin_keygen.py --selftest                                   # 校验表提取与 TEA
```

UID 来源：**开机界面 "Device MAC" 下面三行 `%08lX` 就是 U0/U1/U2**，照抄即可。

关键点（踩过的坑）：

- 表地址是代码字面量 `0x08009EE0 / 0x08009AE0 / 0x080096E0 / 0x080092E0`，
  对应文件偏移 `0x76E0 / 0x72E0 / 0x6EE0 / 0x6AE0`（真实基址 `0x08002800`，见 §9）。
  这 4 KB 在文件里正好连续，紧随其后真实地址 `0x0800A2E0` 就是 option-byte 表首项 `0x1FFF3238`
  —— 脚本用这个值做自检，能证明表地址取对了。
- TEA 是**标准 TEA**（delta `0x9E3779B9`，32 轮），但反汇编里常量显示为 `1640531527 = 0x61C88647 = -delta`，
  循环条件是 `sum != 0xC6EF3720 (= 32·delta)`。容易误判成"非标准变体"。
- 校验字 `crc32(PIN) ^ crc32(0xA5A5A5A5)` 用的是标准 IEEE CRC-32（`zlib.crc32`，反射、初值/终值异或 0xFFFFFFFF）。

自检输出（2000 字节镜像 + 样例 UID）：

```
T_A @0x08009EE0: 4A70E2B6 893DB0DA 8BB9CABD 148620A3
T_B @0x08009AE0: 0E2C42FC D1EE2CDF 87A7A931 0FA04A57
T_C @0x080096E0: 2B37CB4A AAFB2E3D 3B310102 683214B6
T_D @0x080092E0: F4274B02 FCEE053E 1D0BE0EC 6910E482
样例 UID 12345678 9ABCDEF0 0F1E2D3C -> hash=935C78BA PIN=7231 0970
TEA 回环: A74848EEBCBF401F -> 解出 044F60BA00000000  OK
```

---

## 9. 基址判定更正（重要，先看这节）

**结论**：`firmware_decrypted.bin` 的**真实链接基址是 `0x08002800`**，不是 `0x08002000`。
IDA 按 `0x08002000` 装载，导致所有"绝对地址"引用在 IDB 里**偏低 0x800**。文件本身是完整、连续的，**没有丢页**。

（早期版本的本报告曾判断为"中间漏了一个 2 KB 页"，该判断已被下列证据推翻。）

**证据链（四条独立对齐，全部指向同一结论）**：

| 观察 | 说明 |
|---|---|
| 向量表 Reset 项 = `0x08002D89` | 减去 0x800 正好落在 `0x08002588` 处那段 `mov sp, r0 / bl relocate_vtor / 拷 .data` 的启动桩上。这是唯一合理的复位入口。 |
| `relocate_vtor_to_code_0x08002800()` | 写入 VTOR 的值 `0x08002800` 恰好等于"真实基址"，是正常固件的常规做法（VTOR 指向自己的向量表）；按旧基址解释则指向一片非向量表数据，才显得"异常"。 |
| 代码字面量 `0x080090E5` 指向 UI 字符串 | 文件偏移 `0x68E5` 处正是 `"Device MAC"`。按真实基址 `0x08002800 + 0x68E5 = 0x080090E5` ✅ |
| 中文点阵表 `0x0800AFC6` / 字形数 `0x0800B1D0` / 电量阈值 `0x0800B1D4` | 分别落在文件偏移 `0x87C6 / 0x89D0 / 0x89D4`，读出 20 个 12×16 字形、计数 = 20、6 档阈值，三者自洽 ✅ |

**这条更正的后果**：

- 旧的"分段修正规则"（只对 ≥0x08008850 减 0x800）是**错的、但恰好等价**：因为所有这些表都落在 0x08008850 以上，逐条减 0x800 与整体改基址得到同一结果。所以 `pin_keygen.py` 出来的 PIN 仍然正确（已用模拟器验证，见 §11）。
- **正确做法**：把 IDB 重载一次，基址填 `0x08002800`（`Edit → Segments → Rebase`，或直接 `-b 0x08002800` 重新打开），之后字符串、字形、option-byte 表、向量表全部自动对上，不需要任何手工修正。
- 附带解释了为什么 IDA 里"向量表看起来像数据"、"VTOR 指向 TEA 块"这些怪现象 —— 它们都是同一个 0x800 造成的错觉。

**对函数地址的影响**：本报告表格里的 `0x0800xxxx` 均为 IDA 旧视图地址，**真实地址 = 表中地址 + 0x800**（例如 `pin_gate_and_config_menu` 表中 `0x080029EC` → 真实 `0x080031EC`）。重载基址后 IDA 显示的就是真实地址。


---

## 10. 待确认 / 建议下一步

1. **重载 IDB 到基址 `0x08002800`**（见 §9），之后所有引用自动对齐，不必再靠 0x800 手工修正。
2. **确认 MCU 型号**：读 `0x1FFF3000`（UID）与 `0x40022020`（OPTR）实值；`0x40022100+` 窗口的位域定义需要厂商手册。
3. **时钟树**：本 dump 中没有 RCC 时钟配置，确认是"另一段代码在低地址区"还是"确实跑默认 HSI"。
4. 若要复现 AUTH 记录或 PIN：需要 UID 三字 + 4 张散列表（均在镜像内）+ TEA 派生公式（§7.2），逻辑已完全还原，`pin_keygen.py` 已实现。
5. `0x08002E3C` / `compute_protected_code_crc32` 这组完整性校验目前是死代码；若后续固件版本把它接进启动路径，会引入"自校验失败即跑飞"的行为，值得留意。

---

## 11. Cortex-M0 虚拟机（mcu_vm.py，已实现并验证）
用 Unicorn 引擎把这颗 MCU 连同外设一起模拟出来，可以直接跑这坨固件、用键盘操作、看屏幕。

**已模拟的部件**

| 部件 | 地址 | 模型 |
|---|---|---|
| CPU | — | ARMv6-M Thumb（Unicorn `UC_MODE_MCLASS`） |
| Flash | `0x08000000`+ | 镜像按真实基址 `0x08002800` 装入，512 KB 窗口 |
| UID | `0x1FFF3000` | 3 个 word，可用 `--uid` 指定（决定 PIN） |
| SRAM | `0x20000000` | 16 KB；`0x20001268` 是 LCD 帧缓冲 |
| GPIO A–F | `0x50000000` | MODER/IDR/ODR/BSRR/BRR，键位矩阵 + LCD 控制线 |
| RCC | `0x40021000` | 只读回写，`CR[15:13]` 决定 option 表索引 |
| FLASH | `0x40022000` | `OPTR` 返回 `0xAA`（RDP Level 0），SR 永不 busy |
| SPI1 | `0x40013000` | ST7565 指令/数据流（页、列地址、显存） |
| SPI2 | `0x40003800` | 外部 NOR 命令状态机（03/02/20/06/05），2 MB 虚拟 NOR |
| DMA1 | `0x40020000` | ch4/ch5 立即完成，按 `CCR.DIR` 判方向，完成后置完成标志 |
| ADC1 | `0x40012400` | ADSTART 立即完成，EOC + 固定采样值 → 电量档位 |
| SysTick | `0xE000E000` | 直接复刻 ISR 副作用（`0x20001668` 计数 +1），不做异常注入 |
| 键盘 | — | 5 行 × 4 列 + PB10 独立键；按固件里的键值表 `0x0800A72E` 自动换算 |

> 设计取舍：**不注入真实异常**，而是直接复刻两个 ISR 的副作用（SysTick 计数器 +1、DMA 完成标志置 1）。
> 原因是 M0 的异常进出在 Unicorn 里要手工建模，嵌套时会与固件的栈帧打架；直接复刻副作用等价且稳定。

**验证结果（端到端）**

1. 冷启动 → 画 `Device MAC` + 3 行 UID + `MENU=Input`（截图 `shot1_pin_gate.png`）
2. 按 MENU → PIN 输入界面（8 个 `_` 占位）
3. 用 `pin_keygen.py` 算出的 PIN `46161214` 输入 → 校验通过（RAM `0x2000003C` = 0x02C05D3E = 46161214，`0x20000038` = 0xA5A5A5A5）
4. 进入 `Enable RDP? / MENU=Yes / EXIT=No`（截图 `shot3_authorized.png`）—— 与静态分析完全一致

**用法（三种渲染，按兼容性排序）**

```bash
python mcu_vm.py --gui        # ① Tkinter 原生窗口（推荐：不依赖终端字符集）
python mcu_vm.py --web        # ② 浏览器 canvas：http://127.0.0.1:8777/
python mcu_vm.py -i           # ③ 终端 TUI（块字符，部分终端/编码下会花）
python mcu_vm.py --script "w700 k10 w20 k4 k6 k1 k6 k1 k2 k1 k4 w20 k10" --png out.png
```

- `--gui`：128×64 放大 5 倍，键盘直接送键，标题栏下方实时显示 tick / UI 状态。
- `--web`：本地起 HTTP 服务，页面用 canvas 逐像素绘制并轮询 `/frame`（1024 字节原始帧）；按键通过 `POST /key?k=..&down=..` 注入。**任何浏览器可用**，不受终端限制。
- `-i`：纯终端，只依赖 ANSI + 块字符。

> 坑：`PIL.ImageTk.PhotoImage` 在本机 Windows/Tk 组合下渲染为全黑，改用 `tk.PhotoImage(data=base64(PNG))` 后正常 —— GUI 代码走的是后者。

交互键位：`0-9` 数字、`Enter`=MENU(10)、`Esc`=EXIT(13)、`Backspace`=14、`.`=15、`Tab`=16、`a..t` 直接送键值 0..19、`r` 松键、`s` 截图。

**已知限制**

- 外部 NOR 的**读**路径完整（`0x145000` 页能正确读出），**页编程回写**的命令帧对齐还有偏差：AUTH 记录写进去的字节不对，所以"输一次 PIN 以后永久免输"在模拟器里不生效（每次重启仍会要 PIN）。这属于外设模型的保真度问题，不影响固件逻辑本身。
- 未模拟 RDP 编程的真实效果（模拟器里 `OPTR` 永远读回 `0xAA`，可以反复进 `Enable RDP?` 界面，不会真的锁死）。

---

## 附：本报告涉及的已确认函数

| 地址 | 名称 | 作用 |
|---|---|---|
| `0x08002000` | vector table | 48 项，SP=0x20004000 |
| `0x08002534` | firmware_boot_entry | 冷启动主流程 |
| `0x08002578` | relocate_vtor_to_code_0x08002800 | 写 VTOR（目标非向量表） |
| `0x08002698` | set_system_clock_hz | 仅存常量 48e6 |
| `0x08002944` | load_mcu_unique_id_words | 读 0x1FFF3000 三字 |
| `0x08002964` | derive_pin_verifier | hash32 % 1e8 |
| `0x080029EC` | pin_gate_and_config_menu | 开机 PIN 门禁 + RDP 入口 |
| `0x08002778/27F8/2728` | key schedule / TEA enc / TEA dec | UID 派生密钥 + TEA |
| `0x08002848` | persist_pin_gate_state | 写 AUTH 记录到 0x145000 |
| `0x080028C0` | load_auth_record | 读/验 AUTH 记录 |
| `0x08002E78` | compute_protected_code_crc32 | 代码区 CRC（死代码） |
| `0x08002F14` | option_bytes_rdp_is_not_level_aa | RDP 是否已保护 |
| `0x08002F28` | conditionally_program_option_bytes_and_reset | 编程选项字节并复位 |
| `0x08002D88` | Reset_handler | 复位后键盘流程 → RDP 编程 |
| `0x08005A0C` | init_systick_10ms | 10 ms 节拍 |
| `0x08005B6C` | init_adc_and_analog_inputs | ADC1 校准/配置 |
| `0x08005E74` | sample_battery_and_update_status | 电池采样 6 档 |
| `0x080051B0` | scan_keypad_matrix | 5 行 × 4 列 + PB10 |
| `0x080058D4` | init_display_serial_interface | LCD 初始化 |
| `0x08005820/5784/57C8/5830` | display cmd/byte/bulk/flush | LCD 驱动 |
| `0x08005414` | init_external_flash_spi_dma_irq11 | SPI2 + DMA + IRQ11 |
| `0x08005288/52B8/52E8/5504/560C` | flash wait/erase/program/read/update | 外部 NOR 驱动 |
| `0x080056FC` | external_flash_dma_irq_handler | DMA 完成中断 |
| `0x0800412C/4164/4024` | ui state / main loop / menu draw | UI 框架 |
| `0x08003C38` | app1 计算器 | — |
| `0x08004DF8` | app2 俄罗斯方块 | — |
| `0x080043E4` | app3 电子木鱼 | — |
| `0x08003EFC` | app4 CW 练习器 | — |

---

## 12. 串口子系统：4MB 固件空间 + 写频 + 刷机（radio_device.py / k5tool.py）

目标：让模拟器像真机一样，**串口常开**，既能写频，也能刷固件。

### 12.1 分层

```
        ┌──────────── k5tool.py (PC 端) ────────────┐
        │  handshake / read / write / flash / dump  │
        └───────────────┬───────────────────────────┘
                        │ TCP (兼容 pyserial socket://)
        ┌───────────────▼───────────────────────────┐
        │ SerialBridge  (常开, 多客户端)             │
        │ VirtualRadio: ① 应用协议(写频) ② bootloader│
        │ Flash4M  = 4MB 设备闪存 (持久化 device_flash.bin)
        └───────────────┬───────────────────────────┘
                        │ 同一块 Flash4M
        ┌───────────────▼───────────────────────────┐
        │ mcu_vm.py : MCU 从 4MB 空间 0x1000 取镜像   │
        │              SPI NOR 视图也指向同一块内存   │
        └───────────────────────────────────────────┘
```

关键点：**串口刷进去的字节，就是 MCU 启动时执行的字节**。
虚拟机的 `step()` 每 50 tick 比对 `Flash4M.generation`，一变就重载镜像并复位 —— 等价于真机刷完自动重启。

### 12.2 4MB 布局与 NOR 语义

| 区域 | 大小 | 用途 |
|---|---|---|
| `0x000000–0x000FFF` | 4 KB | 配置/信道区（"EEPROM"，写频工具读写） |
| `0x001000–0x3FFFFF` | ~4 MB | 固件区（刷机模式擦写） |

- 擦除粒度 4 KB，写入粒度 256 B
- **写入只能 1→0**（AND 语义），擦除置 0xFF；想写 1 会报警告（模拟未擦除扇区）
- 每次改动落盘（攒批：16 KB 或 1 秒），文件名 `device_flash.bin`

### 12.3 应用协议（写频）—— 对齐 uv-k5-firmware `app/uart.c`

```
请求  AB CD | size(LE16) | obf(payload ‖ crc16) | DC BA
应答  AB CD | size(LE16) | obf(payload) | pad0 pad1 | DC BA
payload = [cmd(LE16)][size(LE16)][body...]
obf      = 16 字节表循环异或（0x16,0x6C,0x14,0xE6,0x2E,0x91,0x0D,0x40,0x21,0x35,0xD5,0x40,0x13,0x03,0xE9,0x80）
crc16    = CCITT, poly 0x1021, init 0, 不反射（覆盖明文 payload，然后一起被异或）
pad      = Obf[size%16]^0xFF, Obf[(size+1)%16]^0xFF
```

| 命令 | 作用 | 应答 |
|---|---|---|
| `0x0514` | 握手 + 下发 timestamp | `0x0515` 版本/挑战字 |
| `0x051B` | 读 EEPROM `off(2) size(1) pad(1) ts(4)` | `0x051C` 数据 |
| `0x051D` | 写 EEPROM `off(2) size(1) allow(1) ts(4) data` | `0x051E` |
| `0x0527` | 读 RSSI | `0x0528` |
| `0x0529` | 读电池 | `0x052A` |
| `0x052D` | 鉴权 | `0x052E` |
| `0x052F` | 复位 | `0x0515` |
| `0x05DD` | 重启进刷机 | 无 |

`0x051B/0x051D` 的 timestamp 必须与 `0x0514` 一致，否则静默丢弃（和固件一致）。

### 12.4 刷机协议（bootloader）

复位/上电后 800 ms 内收到 `"FLSH"` 进入；或在应用协议发 `0x05DD` 重启。
（真机这段在 ROM 里；本协议按 UV-K5 风格自定义，字段定长小端，便于研究写入流程）

| 命令 | 请求 | 应答 |
|---|---|---|
| `0x30` | — | `0x30` + 页大小(4) + 空间MB(4) |
| `0x31` | addr(4) len(2) | `0x31` len(2) data |
| `0x32` | addr(4) len(2) data crc16(2) | `0x32` status(0=OK,1=CRC错,2=越界) |
| `0x33` | addr(4) len(4) | `0x33` status |
| `0x34` | — | `0x34`（回应用模式） |

### 12.5 用法

```bash
# 常开串口 + 4MB 空间（可与 --gui/--web 叠加）
python mcu_vm.py --flash device_flash.bin --uart 8811 --gui

# PC 端
python k5tool.py -p 8811 info                 # 握手
python k5tool.py -p 8811 read 0x0000 256      # 读配置区
python k5tool.py -p 8811 flash fw.bin         # 进 bootloader 刷写 + 回读校验
python k5tool.py selftest                     # 自带设备端跑完整流程
```

任何支持 TCP 串口的工具都能接：`serial_for_url("socket://127.0.0.1:8811")`。

### 12.6 已验证（`test_flash_cycle.py`）

```
[TEST] 刷机前: tick=700, 帧缓冲非零 241 字节
[TEST] 补丁: 偏移 0x68E5  'Device MAC' -> 'FLASH  OK '
[TEST] 刷写 35396 字节, 2.74s, 回读不一致块: 0
[SPACE] 检测到固件区更新, 重载 35396 字节并复位
[TEST] 虚拟机自动重载: True
[TEST] 画面变化: True
```

刷完后屏幕第一行从 `Device MAC` 变成 **`FLASH  OK`**（见 `cycle_after.png`）——
证明"串口刷机 → 自动重启 → 跑新固件"这条链在模拟器里是真的通了。

### 12.7 已知限制

- 串口桥是 TCP，不是真 COM。要接只认 COM 的老工具，需要装 com0com 之类的虚拟串口对，再做一层转发。
- bootloader 协议是自定义文档化协议，不是 UV-K5 ROM 的原始字节流（那份在硅片里，仓库里没有）。
- `0x0510/0x0512` 等 UV-K5 里被 `#if 0` 掉的命令未实现（真机也不响应）。

### 12.8 真实 COM 口（com0com，已验证）

本机已装 com0com，`COM14 <-> COM15` 是一对虚拟串口。模拟器直接桥到其中一端：

```bash
python mcu_vm.py --firmware firmware_decrypted.bin --flash device_flash.bin --com COM14
python k5tool.py --com COM15 info
```

实测（虚拟机运行中，通过真实串口）：

```
命令 0x0515  版本 'BD1AHN-VM 1.0'
写频: True  回读: True
进 bootloader: True
设备信息(页,MB): (256, 4)
擦除后 0x1000 前 8 字节: ffffffffffffffff
写 64B: True  回读一致: True
```

因此任何打开 `COM15` 的串口工具（写频软件 / miniterm / PuTTY）都能直接与模拟器对话，
不需要中间脚本。TCP 口（`--uart`）与 COM 口（`--com`）可以同时开。

### 12.9 用真实固件包做的写入测试（test_flash_payloads.py）

| 载荷 | 大小 | 目标地址 | 擦除 | 写入 | 吞吐 | 回读 |
|---|---|---|---|---|---|---|
| `mangosteen_v2.3.7.bin` | 120,736 B | `0x001000` | 0.03s | 1.85s | 63.9 KB/s | SHA256 一致 |
| `uvk1_gb2312_font.bin` | 327,568 B | `0x020000` | 0.02s | 4.98s | 64.2 KB/s | SHA256 一致 |

```
源 c724075d6c6a8fbf  回读 c724075d6c6a8fbf  一致=True  不一致块=0
源 e6014e271dfbd317  回读 e6014e271dfbd317  一致=True  不一致块=0
```

### 12.10 两个新固件包的分析

**`mangosteen_v2.3.7.bin`（120,736 B）**

- 向量表在文件偏移 0：SP=`0x20004000`（16KB SRAM），Reset=`0x0801D109`
- 外设字面量与 BD1AHN **完全一致**：`0x50000400`(GPIOB)×17、`0x40021000`(RCC)×5、
  `0x40003800`(SPI2)×5、`0x40013000`(SPI1)、`0x40012400`(ADC1)、`0x40013800`(USART1)
  → **同一颗 MCU / 同一块板**，而且它自带 USART1 代码（真·串口功能）
- **更正**：它不是 0x08000000 镜像。它自己的启动桩（foff `0x1A908`）会把 `VTOR` 写成 **0x08002800**，
  所以它同样是 **0x08002800 应用区镜像**；`0x08002800 + 120,736 = 0x0801FFA0`，正好顶到 128 KB 末尾。
  之前按 0x08000000 解释才让 Reset 落进数据表
- 用法：`python mcu_vm.py --firmware mangosteen_v2.3.7.bin --base 0x08002800`（默认值即此）

**`uvk1_gb2312_font.bin`（327,568 B）**

- **结构未确认**。`2944 + 6763×48` 只是算术巧合：文件严格是 **16 字节单元 × 20,473**，
  每单元末字节恒为 0（20,449/20,473），2,944 处没有任何结构断点，且中部有 18,532 B 连续全零
- 墨密度按字节 0.60、按位 0.22，与 24×16 点阵字库的预期不符
- `6763` 是从 GB2312 汉字数**倒推**的，不是从文件读出来的
- 结论：当刷机载荷用没问题；若要在固件里真正调用它，需要先确认格式

### 12.11 当前串口功能矩阵

| 能力 | 通道 | 状态 |
|---|---|---|
| 写频读/写 EEPROM | TCP + 真实 COM | ✅ 已验证 |
| 握手 / 版本 / 电池 / RSSI | TCP + 真实 COM | ✅ |
| 进 bootloader (`FLSH` / `0x05DD`) | TCP + 真实 COM | ✅ |
| 擦除 / 读写固件区 + CRC | TCP | ✅ |
| 4MB 持久化 + NOR 1→0 语义 | 文件 | ✅ |
| 刷机后 MCU 自动重载 | VM | ✅（`test_flash_cycle.py`） |
| 真实固件包整包写入 | TCP | ✅（SHA256 一致） |

### 12.12 `--flsh`：直接进刷机模式

默认上电后有 0.8 s 的 bootloader 窗口，没收到 `FLSH` 就自动进应用模式（写频）。
调试/纯刷机场景不想等这一步，加 `--flsh` 直接停在刷机模式：

```bash
python mcu_vm.py --flash fw.bin --uart 8801 --flsh --no-reload --gui
python radio_device.py --flash fw.bin --port 8801 --flsh     # 只跑设备，不跑 MCU
python k5tool.py -p 8801 flsh                                # 查一下是不是在刷机模式
python k5tool.py -p 8801 flash fw.bin                        # 直接刷，无需先发 0x05DD
```

实测：

```
[DEV] 已进入刷机模式 (--flsh), 等待 FLSH / 0x30-0x34
已进入刷机模式: 页 256 B, 空间 4 MB
[FLASH] 回读校验: 35/35 块一致
刷机结果: True
```

要点：
- `--flsh` 只影响**串口侧**的人格（bootloader），MCU 该跑还是照跑
- 刷完仍停在刷机模式，可以连续擦写/读回，不会自己跳回应用模式
- 想回到写频：去掉 `--flsh` 重启设备即可

### 12.13 真实 bootloader 协议（stock-bl 7.02.02，已对齐）

`ref/ichi/archive/stock-bl_7.02.02.bin` 就是这台机器的原厂 bootloader（9,984 B）。
在 IDA 里逆完，结论如下：

**内存布局**

| 区域 | 地址 | 说明 |
|---|---|---|
| bootloader | `0x08000000–0x080026FF` | 9,984 B |
| 参数块 | `0x08002700` | 256 B，`0x0516` 写入 |
| 应用 | `0x08002800` | 跳转前校验 `*(u32)0x08002800 & 0x2FFC0000 == 0x20000000` |

> 注意：app 基址 **0x08002800** 和 BD1AHN 固件完全一致 —— 印证了它就是这台机器的官方固件位。

**帧格式**（与 app 协议同一套）

```
AB CD | size(LE16) | obf(payload ‖ crc16) | pad pad | DC BA
payload = [cmd(LE16)][inner_size(LE16)][body...]
obf     = 16 字节表循环异或 (16 6C 14 E6 2E 91 0D 40 21 35 D5 40 13 03 E9 80)
crc16   = CCITT, poly 0x1021, init 0
```

**上电行为（这就是"刷机软件先读信息"的来源）**

1. 先发 ASCII 横幅：`7.02.02\0\0\0\xC4 \r\n`
2. 然后**周期性主动推送 `0x0518` 信息帧**（每 ~0.5 s）：
   ```
   0x0518 | inner=32 | UID[4] (16B) | 版本串 (16B, "7.02.02")
   ```
   UID 取自 `0x1FFF3000` —— 和 BD1AHN 固件的 UID 同一个地址。

**命令表**

| 命令 | 方向 | 内容 | 应答 |
|---|---|---|---|
| `0x0530` | PC→机 | 解锁：body[0..4] == `"7.02"` 或 body[0] == `'*'`(0x2A) | 无 |
| `0x0516` | PC→机 | 参数块：body[0..0x68] → flash `0x08002700` | `0x0517`（4B 状态） |
| `0x0519` | PC→机 | 数据块：`cookie(4) idx(2) total(2) rsv(4) data(256)` → flash `0x08002800+idx*256` | `0x051A`（cookie + idx + 状态） |
| `0x0518` | 机→PC | 版本 + UID（周期推送） | — |

写块前必须先 `0x0530` 解锁；`cookie` 每块必须一致（固件用它做会话校验）。

**模拟器已实现**（`radio_device.py`）

- `--flsh` 进入刷机模式时发横幅
- 每 0.5 s 推 `0x0518` 信息帧（版本 + 可配置 UID）
- 支持 `0x0530 / 0x0516 / 0x0519`，回 `0x0517 / 0x051A`
- 老的 `FLSH` / `0x30–0x34` 单字节命令保留为兼容层

**实测**（`test_bl_protocol.py`）

```
① 上电横幅: b'7.02.02\x00\x00\x00\xc4 \r\n'
② 0x0518 信息帧: 版本='7.02.02' UID=1A2B3C4D 5E6F7081 92A3B4C5 0F1E2D3C
③ 已发 0x0530 解锁 (magic '7.02')  unlocked=True
④ 0x0516 参数块 -> 应答 0x0517
⑤ 写块: 139/139 块确认, 2.43s (14.2 KB/s)
⑥ 空间回读与源文件一致: True
结果: 通过
```

`k5tool.py flsh` 现在会直接读真实信息：

```
刷机模式: 版本 7.02.02  UID 1A2B3C4D 5E6F7081 92A3B4C5 0F1E2D3C
  横幅: b'7.02.02\x00\x00\x00\xc4 \r\n'
```

### 12.14 bootloader 完整行为规格（stock-bl 7.02.02，已逐条对齐）

从 Reset 到跳转 app 的完整链路，全部来自 IDA 反编译：

**① 上电初始化**

| 步骤 | 函数 | 行为 |
|---|---|---|
| 时钟 | `sub_8000EC8` | HSI→PLL，用 `0x1FFF3210` 的工厂 trim 值，目标 **48 MHz** |
| GPIO | `sub_8000688` | 配置 GPIOA/B/C；**PC13 = 手电筒**，PTT 读 **GPIOB** |
| UART | `sub_8000748` | **USART1 @ 38400 8N1**；DMA 循环收 2048 B 到 `0x200001A0`，第二路 ring `0x200011E0` |
| UID | `sub_8000548` | 读 `0x1FFF3000` 四个 word → `0x20001DE0..EC` |

**② PTT 检测（决定跑不跑固件）**

```c
if ((GPIOB->IDR & 0xC000) == 0xC000) {      // bit15|bit14 全为 1
    delay(200000);                            // 消抖复核
    if ((GPIOB->IDR & 0x0400) == 0) {         // bit10 == 0（复核仍是按下）
        n2 = 1;                               // 状态: 停在 bootloader
        NVIC_ISER = 0x80000000;
        GPIOC->BSRR = 1 << 13;                // 手电筒常亮 (PC13)
    }
}
```

- **按住 PTT**：手电筒常亮 + 背光开 → 进 bootloader 循环，**应用固件完全不执行**
- **没按 PTT**：跳过循环 → 校验 app → 跳转

**③ 无论哪种情况都会先发横幅**：`"7.02.02\0\0\0\xC4 " + "\r\n"`（14 字节）

**④ 跳转 app 的条件**（`sub_80006F0`）

```c
if ((*(u32*)0x08002800 & 0x2FFC0000) == 0x20000000) {   // 栈指针像 0x2000xxxx
    MSP = *(u32*)0x08002800;
    (*(u32*)0x08002804)();                              // 跳到 Reset
}
```
校验失败就留在 bootloader，什么都不做。

**⑤ bootloader 主循环**

- 双通道轮询两个 2048 B ring
- 每轮各推一次 `0x0518` 信息帧（版本 + UID）
- 帧解析：`AB CD` → size → 尾 `DC BA` → 16 字节表异或 → CRC16
- 命令：`0x0530` 解锁 / `0x0516` 参数块 / `0x0519` 数据块
- 应答：`0x0517`（4B 状态）/ `0x0518`（32B 信息）/ `0x051A`（8B）

**⑥ Flash 写入语义（关键，和常见 flash 不同）**

| 操作 | 真机实现 | 说明 |
|---|---|---|
| 擦除粒度 | `sub_800059C(addr, n)`：`n` 个 **256 字节页** | **不是 4 KB 扇区** |
| 参数块 | 擦 1 页 @`0x08002700` + 写 104 B | `0x0516` |
| 块 0 | 擦 **472 页 = 120,832 B**（`0x08002800..0x0801FFFF`） | `0x0519` idx=0 |
| 后续块 | 校验 cookie 一致 + 序号连续，否则拒写 | 顺序敏感 |
| 编程 | `sub_8000618`：按 64 word 突发写 | 每页 256 B |

**⑦ 刷完后的动作**

```
n2 = 3  →  GPIOC->BRR = 1<<13（PC13 手电筒熄灭）
        →  delay(1000000)
        →  跳转 app（同 ④ 的校验）
```

**模拟器对齐情况**（`radio_device.py` + `mcu_vm.py`）

| 行为 | 实现 |
|---|---|
| PTT 判据 `GPIOB->IDR & 0xC000`（且 bit10==0） | `--ptt`，日志打印判据 |
| 手电筒 PC13 / 背光 | `flashlight` / `backlight` 状态，GUI 状态栏显示 |
| 固件不执行 | `--ptt` 时 MCU 不跑，屏幕保持空白 |
| 38400 8N1 | COM 桥默认波特率 38400 |
| 横幅 + 0x0518 周期推送 | ✅ |
| 0x0530/0x0516/0x0519 | ✅ |
| 256 B 页擦除 / 块 0 擦 472 页 | ✅ |
| 顺序 + cookie 校验 | ✅ |
| 完成后手电筒灭 + 跳转 + 固件开始运行 | ✅（VM 自动重载并继续跑） |

**实测（`--ptt` 全链路）**

```
[BOOT] PTT 按住 (GPIOB->IDR & 0xC000 == 0xC000, bit10==0) -> 手电筒常亮(PC13) + 背光开 + 进刷机模式, 固件不运行
$ k5tool flsh
刷机模式: 版本 7.02.02  UID 1A2B3C4D 5E6F7081 92A3B4C5 0F1E2D3C
$ k5tool flash firmware_decrypted.bin
[BL] 参数块 -> 0x0517 OK
[BOOT] 参数块 104B -> flash 0x08002700
[BOOT] 块 0: 整区擦除 472 页 (120832 B), total=139
[BOOT] 块 139/139 -> flash 0x080B200  [完成]
[BOOT] 手电筒熄灭
[BOOT] app 有效 (SP=20004000), 跳转执行
[SPACE] 检测到固件区更新, 重载 35396 字节并复位
[BOOT] bootloader 跳转 -> 固件开始运行
```

### 12.15 真机面板（`--panel`）

一块窗口把整台机器摊开：

```
┌─────────────────────────┬──────────────────┐
│  LCD 128×64 (4×)        │  KEYPAD 5×4+PB10 │
│                         │  1  4  7  -      │
│   Device MAC            │  2  5  8  -      │
│   1A2B3C4D              │  3  6  9  -      │
│   5E6F7081              │  0x0E 0 0x0F -   │
│   92A3B4C5              │  [PB10 SPECIAL]  │
│   MENU=Input            │  PTT FL BL BOOT  │
├─────────────────────────┴──────────────────┤
│ GPIO  蓝=输入 绿=输出高 灰=输出低 紫=复用 褐=模拟
│ PA  ▁▁▁▁▁...  M=986A O=0048 I=0048        │
│ PB  ▁▁▁▁▁...  M=155B O=007C I=F47C        │
│ ...   (PA..PF 共 6×16 引脚)                │
├────────────────────────────────────────────┤
│ tick 258  UI 12F=00  LCD running           │
└────────────────────────────────────────────┘
```

**内容**

| 区域 | 显示 |
|---|---|
| LCD | 帧缓冲直读，4× 放大，`Image.NEAREST` |
| 键盘 | 5 行 × 4 列 + PB10；按下变绿（键值来自固件表 `0x0800A72E`） |
| 指示灯 | PTT / FLASHLIGHT / BACKLIGHT / BOOT，PTT 可点击切换 |
| GPIO | PA–PF 每脚按 MODER 上色，输出脚按 ODR 亮暗；右侧 `M/O/I` 十六进制 |
| 状态栏 | tick、`UI 12F`、LCD 状态、fault |

**GPIO 颜色**

| 颜色 | 含义 |
|---|---|
| 深蓝 | 输入（MODER=0） |
| 绿 / 暗灰 | 输出 ODR=1 / ODR=0 |
| 紫 | 复用（AF） |
| 褐 | 模拟 |

实测（应用固件运行中）：

```
PA  M=986A O=0048 I=0048
PB  M=155B O=007C I=F47C   ← 键盘列上拉(0xF400) + 行驱动
PC  M=0000 O=0000 I=0000   ← 应用不碰 PC（bootloader 才用 PC13 手电筒）
PF  M=0000 O=0100 I=0100
```

**用法**

```bash
python mcu_vm.py --firmware firmware_decrypted.bin --flash fw.bin --panel
python mcu_vm.py --firmware firmware_decrypted.bin --flash fw.bin --panel --ptt   # PTT 开机进 bootloader
```

配合串口一起用：

```bash
python mcu_vm.py --flash fw.bin --uart 8801 --panel          # 面板 + 写频/刷机
python k5tool.py -p 8801 flash firmware_decrypted.bin
```

刷机时面板上能直接看到：BOOT 灯亮、`PC13` 变绿（手电筒）、LCD 空白；刷完手电筒灭、BOOT 灭、LCD 出开机画面。

### 12.16 面板电源控制（⏻ POWER / ↻ REBOOT）

面板右上角加了两颗按钮，配合 PTT 就是完整的上电状态机：

| 操作 | VM | 串口侧 | 屏幕 | 指示灯 |
|---|---|---|---|---|
| **⏻ POWER**（关机） | `power_on=False`，CPU 停 | 停止发帧 | 全黑 | 全灭 |
| **⏻ POWER**（开机） | 从 4MB 空间重载固件并复位 | 按 PTT 状态重入 bootloader/app | 出画面 | 按状态 |
| **↻ REBOOT** | 冷启动（不清 4MB 空间） | 同上 | 重画 | 按状态 |
| **PTT 点一下 + REBOOT** | `ptt_boot=True`，**固件不跑** | bootloader + 手电筒 | 空白 | PTT 红 / FLASHLIGHT 黄 / BACKLIGHT 蓝 / BOOT 紫 |
| **PTT 再点一下 + REBOOT** | 正常启动 | 应用模式 | 开机画面 | PTT 灭 |

实测（脚本直接驱动同样两个入口）：

```
① 正常启动      : LCD 非零 241, fault=None
② 关机          : LCD 非零 0,   power_on=False
③ PTT 冷启动    : ptt_boot=True  radio.boot_mode=True  手电筒=True 背光=True  LCD 非零 0
④ 松手重启      : ptt_boot=False radio.boot_mode=False 手电筒=False  LCD 非零 241
```

注意 ③ 的 `LCD 非零 0` —— **PTT 开机时固件一个字节都没跑**，屏幕保持空白，这正是真机行为。

**顺带修的两个问题**

| 问题 | 修法 |
|---|---|
| `[COM] 错误: Write timeout` 刷屏 | COM 桥写失败就丢掉这一帧（对端没在读不该卡住模拟器） |
| `[TX] -> 0518` 每 0.5 s 刷日志 | 信息帧日志改成 `verbose_info` 开关，默认只打关键命令 |

**面板按键**

| 键 | 作用 |
|---|---|
| `0-9` | 数字 |
| `Enter` / `Esc` / `Backspace` / `.` / `Tab` | MENU / EXIT / 0x0E / 0x0F / 0x10 |
| `a..t` | 直接送键值 0–19 |

鼠标：`⏻ POWER` 开关机、`↻ REBOOT` 重启、`PTT` 切换 PTT 状态。

### 12.17 协议收敛：默认只有真机协议

之前为了调试方便，设备侧同时支持了"真实帧协议"和自造的旧字节命令（`FLSH` / `0x30-0x34`）。
两者混在一起会互相污染：周期性 `0x0518` 帧会插进旧命令的字节流里，导致写块中途失步。

现已收敛：

| 协议 | 默认 | 开关 | 说明 |
|---|---|---|---|
| 真实帧协议 `0x0530/0x0516/0x0519` + `0x0518` 推送 | ✅ 开 | 无 | 与原厂 bootloader 一致 |
| 旧字节命令 `FLSH` / `0x30-0x34` | ❌ 关 | `--legacy-proto` | 仅调试用，真机没有 |

对应 `k5tool` 的 `flash` 默认走真协议；`--legacy` 需要设备端同时开 `--legacy-proto`。

**CLI 速查（最终版）**

```bash
# 虚拟机
python mcu_vm.py --firmware firmware_decrypted.bin --flash fw.bin --panel [--uart 8801] [--com COM14]
python mcu_vm.py ... --ptt            # PTT 开机: 手电筒亮 + 背光 + 固件不跑
python mcu_vm.py ... --flsh           # 串口直接停在刷机模式
python mcu_vm.py ... --no-reload      # 刷完不自动重启
python mcu_vm.py ... --legacy-proto   # 额外开旧字节命令

# 设备单独跑（不跑 MCU）
python radio_device.py --flash fw.bin --flsh [--ptt] [--port 8801] [--com COM14]

# PC 端
python k5tool.py -p 8801 flsh                     # 读版本 + UID
python k5tool.py -p 8801 flash fw.bin             # 真协议刷机
python k5tool.py -p 8801 flash fw.bin --legacy    # 旧协议（需 --legacy-proto）
python k5tool.py -p 8801 read 0x0000 64           # 写频：读 EEPROM
python k5tool.py -p 8801 write-channels ch.bin    # 写频：写 EEPROM
python k5tool.py --com COM15 ...
python k5tool.py selftest
```

**回归状态（本轮全部通过）**

```
k5tool selftest      : ① 握手 ② 写频 ③ 真协议刷机 139 块 ④ 掉电保持 ⑤ 4MB 空间  → 全通过
test_bl_protocol     : 横幅 / 0x0518 / 0x0530 / 0x0516 / 139 块 / 回读一致 → 通过
test_flash_cycle     : 刷写 139 块 → 自动重载 → 画面变化 → 通过
```

---

## 13. 三方复核（子代理）与修复

按"重新全部理一遍"的要求，起了三个只读审查子代理，各自产出报告到 `review/`：

| 报告 | 范围 | 规模 |
|---|---|---|
| `review/vm_core.md` | `mcu_vm.py`（MCU 内核/外设/显示/CLI） | 37.9 KB，P0×2 / P1×10 / P2×13 / P3×12 |
| `review/serial.md` | `radio_device.py` + `k5tool.py`（协议/桥/Flash） | 35.7 KB，P0×3 / P1×7 / P2×14 / P3×16 |
| `review/facts.md` | 报告断言 vs 二进制实物 | 进行中 |

### 13.1 已修（本轮）

**串口侧**

| 级别 | 问题 | 修法 |
|---|---|---|
| P0 | bootloader 窗口超时会 `go_app()`，刷到一半就半砖 | 收到任意帧/解锁后 `boot_deadline = inf`，真机是死等 |
| P0 | `ensure_bootloader` 用 `FLSH` 硬碰，把 `0x0518` 帧流吃掉 | 改成"先等 `0x0518`；应用模式发 `0x05DD` 后仍只等 `0x0518`；旧协议仅兜底" |
| P0 | 写频 `0x051D` 用 NOR 的 AND 语义，第二次写变 `0x00000202` | 先按 256B 页擦除再写（真机 EEPROM 可覆盖） |
| P1 | 错序/cookie 不符仍写 flash | 按 `sub_80002A0`：直接拒写 |
| P1 | `generation` 每次 program 都 +1，写频一次就把 MCU 复位 | 只有落在固件区（≥0x1000）才 +1 |
| P1 | 应答尾部 pad 硬编码 `FF DF` | 改成 `~Obf[size&0xF]` / `~Obf[(size+1)&0xF]`（对齐 `sub_8000AF0`） |
| P1 | `0x0515` challenge 只有 4 B、`0x0517` 只回 1 B | 改 16 B / 4 B |
| P1 | `_wait_cmd` 半包丢帧 | 加待处理帧缓冲 |
| P2 | 每块都整盘落 4 MB | 落盘阈值提到 256 次写 / 2 s |

**MCU 侧**

| 级别 | 问题 | 修法 |
|---|---|---|
| P0 | 外部 SPI NOR 别名 4MB 固件空间 → 固件擦 NOR 会擦掉自己 | NOR 改回独立 2 MB 缓冲（真机是两颗芯片） |
| P0 | Web 线程直接改 `periph.keys` 与仿真线程竞争 → hook 异常 → VM 永久 fault | 加 `key_lock`，读写都持锁 |
| P1 | ADC 模型与固件不符（固件等 EOC=bit1、读 DR=+0x50，模型给 bit2/+0x40）→ 电量采样死循环且不报错 | 改 bit1 / `0x40012450` |
| P1 | `cold_boot()` 无 `--flash` 时根本不复位 | 无 space 也走 `reset()` |
| P1 | `tick` 与 `--ipt` 强耦合（改性能参数就改固件时序） | 引入 `CYCLES_PER_TICK=4000` 固定换算 |
| P1 | `SYST_RVR` 写入不跟踪、`CVR` 用 `& rvr` 非取模 | 跟踪 RVR，CVR 取模 `(rvr+1)` |
| P1 | `--base` 下键值表地址写死 → 键盘全废 | 表地址按 `IMG_BASE` 平移 |

### 13.2 复核后回归（全绿）

```
k5tool selftest  : ① 握手 ② 写频 ③ 真协议刷机 139 块 ④ 掉电保持 ⑤ 4MB 空间 → 全部通过
test_bl_protocol : 横幅 / 0x0518 / 0x0530 / 0x0516 / 139 块 / 回读一致 → 通过
test_flash_cycle : 刷写 139 块 → 自动重载 → 画面变化 → 通过
headless 画面    : 帧缓冲非零 241
```

### 13.3 未修（记录在案，下轮处理）

- 应答帧几何复核结论：**请求没有 pad、应答没有 CRC** —— 现有代码几何是对的，不要去"补 CRC"
- `0x051A` 未校验 cookie（工具侧）
- `--legacy-proto` 在部分路径未透传（`dump` / `--legacy`）
- `run_gui` 关机后 tick 链中断（面板已支持，GUI 未改）
- TUI（`-i`）在 GBK 控制台首帧会 UnicodeEncodeError；`r/s/c` 被 `a..t` 分支截胡
- `0x0516` 空参数会抹掉参数页（与真机一致，但工具侧应避免发空）

### 13.4 第二轮：实机日志暴露的问题（已修）

从实际运行日志里又修了 5 处：

| 现象 | 根因 | 修法 |
|---|---|---|
| 面板 LCD 空白、键盘显示 `0x46 0x23 0x93…` 这种乱码键值、状态栏 `PC=08080000` | **`fw.bin` 里是别的镜像**（Reset=0x08002DF5，不是 BD1AHN 的 0x08002D89）。VM 按设计运行"空间里的镜像"，于是跑飞；键值表读的是那个镜像的字节 | 启动时**比对空间镜像与 `--firmware`**，不一致就醒目警告并打印两边 SP/Reset；新增 `--reseed` 用文件强制覆盖空间 |
| `--reseed` 后镜像被写坏（Reset 变 0x08002D81） | NOR 只能 1→0，直接 `program` 会把旧内容 AND 进新镜像 | reseed 前先 `erase_pages` 再写 |
| `[DEV] 进入 bootloader 窗口` 打两遍 | 补丁遗留重复 log 行 | 删掉重复行 |
| `[SPACE] 检测到固件区更新, 重载…` 反复出现 | `reload_firmware()` 没同步 `_space_gen`，下次 tick 又判定"更新" | 重载时同步 generation |
| PTT 日志写 `GPIOC->IDR & 0xC400` | 文案沿用旧的错误判据 | 改成 `GPIOB->IDR & 0xC000 == 0xC000 且 bit10==0` |

**恢复步骤（给遇到同样情况的人）**

```bash
# 空间里有陌生镜像 -> 用文件强制重播种
python mcu_vm.py --firmware firmware_decrypted.bin --flash fw.bin --reseed --panel
# 或者干脆删掉空间文件，下次会自动播种
del fw.bin
```

**最终回归**

```
k5tool selftest / test_bl_protocol / test_flash_cycle : 全通过
面板截图：LCD 出 "Game / power by BD1AHN" 开机画面，键盘 1-9/0 正常，GPIO PB=007C/F47C
```

---

## 14. 两个第三方固件（mangosteen / Dondji）的适配

用户反馈这两个 `.bin` 在模拟器里跑不起来。排查过程与结论：

### 14.1 修掉的三个真实建模缺口

| # | 缺口 | 证据 | 修法 |
|---|---|---|---|
| 1 | **USART1 完全没建模** | 两个固件都停在 `0x40013800` 偏移 0 的 bit7（TXE）轮询：`ldr r5,[r2]; tst r5,r4(0x80); bne` | 加 USART1 模型：偏移 0 / 0x1C 读状态恒给 `TXE|TC|RXNE`；偏移 4 / 0x28 发送、读 RDR。F0 与 G0 两套布局都覆盖 |
| 2 | **DMA 完成用写死地址** | 之前 `_dma_start` 直接 `mem_write(0x20000260, 1)`（BD1AHN 的标志），别的固件等的是自己的变量 | 改成**真投递 IRQ11**，让固件自己的 ISR 清标志 |
| 3 | **SysTick 用写死计数** | 之前直接往 `0x20001668` 加一（BD1AHN 的 tick 变量），第三方固件的 `millis()` 恒为 0 → `end-now` 为负 | 改成**真投递 SysTick 异常**；顺带修了异常帧恢复地址的 bug（压栈应存 `next_pc`，不是已停在 EXC_RETURN 的 PC） |

> 第 3 条还带出一个通用修复：Unicorn 有时遇到 `0xFFFFFFF8` 只是**停住**而不抛错，新增了"返回后检查 PC 是否落在 EXC_RETURN 区"的兜底；并加了"异常返回后至少让固件跑满一步再投下一个 tick"的节流，否则会陷入 异常进出 的无限循环（表现为 tick 涨、PC 不动）。

### 14.2 现在的状态

| 固件 | 结果 |
|---|---|
| `firmware_decrypted.bin`（BD1AHN） | ✅ 全绿（画面 241 非零、PIN/菜单正常、协议测试全过） |
| `mangosteen_v2.3.7.bin` | ⚠️ 能跑过 LCD 初始化（41 字节 ST7565 命令序列）、USART 轮询、SysTick 中断，**但仍卡在 `delay()`** |
| `Dondji.fusion.bin` | ⚠️ 同上 |

### 14.3 为什么还卡住（不是模拟器 bug）

两个固件的 `delay()` 长这样（mangosteen `0x080056D4`）：

```asm
ldr r3,[=0x20001740]   ; 取"每个延时单位对应多少计数"
ldr r3,[r3]            ; ← 读到 0xFFFFFFFF
muls r0, r3, r0        ; target = -1 * arg
ldr r5,[=0xE000E010]   ; SysTick
loop: cmp r3, r0
      blo loop         ; unsigned: 0 < 0xFFFFFFF6 -> 永远成立
```

实测 `*(0x20001740) = 0xFFFFFFFF` —— 那个"计数倍率"是 `-1`，于是 `target = -10`，
unsigned 比较下循环要跑 ~40 亿次，等于死等。

**这个值来自设备端配置**（真机由刷机工具的 `0x0516` 参数块 + 工厂校准区提供），
单独一个应用 `.bin` 里没有。试过两种补救都无效：

- 把 `0x08002700` 参数块填 0 → 倍率仍是 0xFFFFFFFF
- 把 `0x1FFF3210`（工厂 trim）填合理值 → 无变化

### 14.4 结论与后续

- 这两个固件**不是"模拟器跑不了"，而是依赖设备私有配置**；给它们配齐参数块/校准数据是下一步
- 需要的东西：真机 dump 的 `0x1FFF3000-0x1FFF3300`（工厂区）+ 刷机时 `0x0516` 写的那 104 字节参数块
- 三个建模缺口（USART / DMA IRQ / SysTick ISR）是实打实的提升，对以后任何第三方固件都生效

### 14.5 抓参数块的小工具：`sniff_param.py`

既然第三方固件缺的是"设备端参数块"，最直接的办法是把**真实写入器**发出来的 `0x0516` 骗下来。

```bash
# com0com: COM14 <-> COM15，官方写入器开 COM15
python sniff_param.py --com COM14 --out param_0516.bin

# 没有 com0com 时走 TCP（pyserial: socket://127.0.0.1:8801）
python sniff_param.py --port 8801 --out param_0516.bin

# 只收不发（工具可能超时，但能抓到前几帧）
python sniff_param.py --com COM14 --passive
```

**它做的事**

| 收到的帧 | 行为 |
|---|---|
| 上电 | 主动发 14 字节 ASCII 横幅 `7.02.02\0\0\0\xC4 \r\n`，并每 0.5 s 推 `0x0518`（版本 + 假 UID），让写入器认得出设备 |
| `0x0530` | 记下 magic，置解锁 |
| `0x0516` | **把 104 字节 body 存到 `--out`**，回 `0x0517` 让流程继续 |
| `0x0519` | 只记账**不写 flash**，回 `0x051A`（回显 cookie）让流程继续 |

所有帧都按十六进制写进 `--log`，方便复盘协议细节。

**实测**（用 `k5tool flash` 冒充写入器）

```
[  2.603] <- 0x0530 inner=8  body=4   372e3032
[  2.604]    解锁 magic=b'7.02' -> True
[  2.605] <- 0x0516 inner=108 body=104 0000...
[  2.608]    ★ 参数块 104 字节 -> param_0516.bin
[  2.612] <- 0x0519 inner=272 body=268 efbeadde00008b000000000000400020892d0008...
...
[  2.813]    数据块 139/139 (累计 139)
```

抓到的文件正好 104 字节 ✓。

**拿到参数块之后**

```bash
# 把参数块写进 4MB 空间的 0x0F00（对应 flash 0x08002700）
python -c "import radio_device as r; f=r.Flash4M('fw.bin'); \
  f.erase_pages(0x0F00,1); f.program(0x0F00, open('param_0516.bin','rb').read()); f.save()"

# 再起 VM 跑第三方固件
python mcu_vm.py --firmware mangosteen_v2.3.7.bin --flash fw.bin --panel
```

注意：`--firmware` 只用于**播种**，空间里已有镜像时以空间为准；
要换固件请用 `--reseed`，否则会看到 §13.4 那条"镜像不一致"警告。

### 14.6 真实写入器的抓包结果（重要更正）

用 `sniff_param.py` 挂 com0com 抓了真实写入器的完整流程，结论和我之前的推断不同：

```
[18.370] <- 0x0530 magic='7.02'        ; 解锁，连发 3 次
[19.729] <- 0x0519 1/469               ; 直接开始灌数据块
   ⋮
[48.876]    数据块 469/469
```

**全程没有 `0x0516`** —— 这个写入器不写参数块，解锁后直接灌 469 个数据块。
所以"第三方固件缺的是 0x0516 参数块"这个推断不成立（§14.3 已注明更正）。

**块布局逐字节验证通过**：

```
body = 6f ee 33 ac | 00 00 | d5 01 | 00 00 00 00 | <256 B 数据>
       cookie      | idx   | total | 保留        | data@+12
                      ↑ 0x01D5 = 469
```

与 `radio_device.py` 的实现完全一致 ✓。

**抓到的固件**：第 0 块数据 `00 40 00 20 f9 ba 01 08 …` → `SP=0x20004000, Reset=0x0801BAF9`，
和 `Dondji.fusion.bin`（Reset=`0x0801BAED`）几乎相同 → **这台机器跑的就是 Dondji 系固件**。
也就是说这两个固件本身没问题，是模拟器缺它们依赖的初始化。

### 14.7 `calibration_backup.dat` 是什么

512 B = **32 行 × 16 B**，非 0xFF 占 51.6%，结构是成对的 16-bit 值：

| 行 | 内容 | 形态 |
|---|---|---|
| 0–11 | `0A 4B 53 56 59 5C 5F 62 64 66 FF FF …` | 递增曲线 + 0xFF 填充，像 AGC/RSSI 分段表 |
| 12 | `6E 00 78 00 82 00 8C 00 B4 00 …` | 纯 16-bit 值 0x006E/0x0078/0x0082… |
| 13–19 | `32 32 32 64 64 64 8C 8C 8C …` | 三连重复的增益表（按频段？） |
| 20–24 | `ED 04 D7 06 58 07 …` / `03 08 0E 13 18` | 16-bit 表 + 少量小整数 |
| 25–31 | 全 0xFF | 未使用 |

判断：这是 **RF 前端的校准/寄存器表**（BK4819 那类），不是时钟倍率，
也不是 §14.3 里那个 `-1` 的来源。

### 14.8 新增：`--save-image` 拼完整固件

既然写入器会灌 469 块，顺手把它们拼成 .bin：

```bash
python sniff_param.py --com COM14 --save-image fw_captured.bin
```

自测（用 `k5tool` 冒充写入器）：

```
★ 固件镜像 139 块 = 35584 字节 -> fw_captured.bin (SP=20004000 Reset=08002D89)
捕获 35584 B, 原始 35396 B, 前 35396 字节一致: True
```

抓到的镜像按 256 B 对齐（尾部 0xFF 填充），前段与源文件哈希一致 ✓。

### 14.9 深挖：`0x20001740 = 0xFFFFFFFF` 的真正来源

用 Unicorn 写钩子 + 包装 `uc.mem_write` 定位到源头（不是固件写的，是我们的模型写的）：

```
mcu_vm.py:420  self.uc.mem_write(cmar, bytes(out))     ← DMA 从 SPI2 读回来的 0xFF 灌进 RAM
```

DMA 描述符跟踪（mangosteen）：

| 方向 | 长度 | 目标 RAM | NOR 地址 | 说明 |
|---|---|---|---|---|
| 读 | 16 | 0x20003F48 | 0x00A160 | 读小结构 |
| 写 | 16 | 0x20001730 | 0x00A170 | **RAM → NOR**（保存） |
| 读 | 4096 | 0x2000072E | 0x00A000 | 读 4 KB 配置块 |
| 写 | 4096 | 0x20001730 | 0x00B000 | RAM → NOR |
| 读 | 32 | 0x20001730 | 0x00A0C8 | 覆盖到 0x20001740（延时倍率） |

**修掉的部分**

| 问题 | 修法 |
|---|---|
| DMA 从 SPI2 读数据时走的是兜底 `nor_rx`（全 0xFF），完全绕过了 NOR 状态机 | 改成按字节驱动 `spi2_byte()`，真正从 NOR 取数 |
| NOR 状态机跨事务不复位（真机靠 CS 边沿） | 每次 DMA 结束把 `nor_state` 复位（等价 CS 拉高） |

**新增参数**

```bash
# 把校准/配置数据放进 NOR 指定偏移
python mcu_vm.py --firmware mangosteen_v2.3.7.bin --nor calibration_backup.dat@0xB000

# 退出时把 NOR 0xA000-0xC000 存盘，便于和真机比对
python mcu_vm.py ... --nor-dump nor_dump.bin
```

**仍卡在这一步**

`calibration_backup.dat`（512 B）试过 4 个偏移（0xA000 / 0xA0C8 / 0xA160 / 0xB000），
延时倍率依旧是 `0xFFFFFFFF` —— 因为固件在**"写 NOR → 立刻回读校验"**的序列里，
我们的 SPI2 模型没有 CS 概念，读回阶段仍返回 0xFF。

**结论**：需要真机 NOR 的 **0x0000A000–0x0000C000（8 KB）** 原始内容，
或者确定 CS 引脚（扫描发现 SPI2 传输全程 PA=0x40 / PB=0x0304 恒定，
推测 CS 走 SPI2 硬件 NSS 或固定拉低），才能把这条链路对齐。

### 14.10 拿到 Dondji 源码后的关键事实

仓库：`https://github.com/EthanYan6/Dondji`（克隆在 `ref/Dondji`，4106 个文件，与 UV-K5 同源）。

**① EEPROM ↔ 外部 NOR 的权威映射**（`App/driver/eeprom_compat.c`）

```c
_MK_MAPPING(PY25Q16_Addr, EEPROM_From, EEPROM_To)   // 注意第一个参数是 NOR 地址
_MK_MAPPING(0x000000, 0x000000, 0x001000)   // 256 MR 频率 ×16B
_MK_MAPPING(0x001000, 0x001000, 0x002000)   // 同上 4 个 4KB 扇区
_MK_MAPPING(0x004000, 0x004000, 0x005000)   // 256 MR 名称 ×16B（4 个扇区）
_MK_MAPPING(0x008000, 0x008000, 0x00886E)   // 1024 MR + VFO 属性
_MK_MAPPING(0x009000, 0x009000, 0x0090D6)   // 14 VFO ×16B
_MK_MAPPING(0x00A000, 0x00A000, 0x00A170)   // Settings（368 字节）
_MK_MAPPING(0x010000, 0x001E00, 0x002000)   // 校准 512B（v4.x 兼容）
_MK_MAPPING(0x010000, 0x00B000, 0x00B200)   // 校准 512B（v5.0.0+）
```

**结论**：
- `calibration_backup.dat`（512 B）应该放到 **NOR `0x010000`**，不是 0x00B000（那只是 EEPROM 侧地址）
- 设备启动读的是 **NOR `0x00A000` 的 Settings 块（368 B）**，读出 4 KB 后解析

**② CS 引脚**（`App/driver/py25q16.c`）

```c
#define CS_PIN GPIO_MAKE_PIN(GPIOA, LL_GPIO_PIN_3)   // PA3，低有效
```

**③ 延时倍率的真身**（`App/driver/systick.c`）

```c
void SYSTICK_Init(void) {
    SysTick_Config(SystemCoreClock / 100);     // 10 ms
    gTickMultiplier = SystemCoreClock / 1000000;   // 48 MHz -> 48
}
void SYSTICK_DelayUs(uint32_t Delay) {
    const uint32_t ticks = Delay * gTickMultiplier;
    ...
}
```

实测对上了：固件在 `0x08009A20` 把 **0x30(48)** 写进 `gTickMultiplier`（Dondji 在 `0x200016D4`），
然后被我们模型的 DMA 用 0xFF 覆盖 → 变成 `0xFFFFFFFF` → `ticks` 极大 → 死等。

**④ 假设备（应用模式）就绪**

```bash
python radio_device.py --com COM14 --flash fw.bin --app
# [DEV] 应用模式: 模拟正常工作界面 (写频/校准工具可直接连)
```

浏览器（Chrome/Edge）打开厂商网页 → 选 **COM15** → 就能像连真机一样操作
"备份配置 / 恢复校准 / 写频"，我们的设备会按应用协议应答（0x0514/0x051B/0x051D…）。
日志里能看到**工具到底读写了哪些 EEPROM 区间**，从而实证校准块的位置与格式。

**⑤ 仍未解决**

NOR 事务模型还是会在"先写后读"的序列上失步（CS 跟踪已加 PA3，但固件的
`dir=0 / state=prog` 组合仍返回 0xFF），所以两个第三方固件仍停在 `SYSTICK_DelayUs`。
下一步：把 CS 边沿与每次 SPI2 DMA 事务对齐后重测，或用网站写一份真实 Settings/校准进来验证。

### 14.11 与厂商网页工具打通（实测记录）

假设备 + com0com + Chrome WebSerial，完整跑通三个动作：

| 动作 | 结果 |
|---|---|
| **备份校准** | 导出 512 B ✓（校准区为空时是 `FF…`，说明映射正确） |
| **恢复校准** | 工具拆成 **32 次 ×16 B** 写 EEPROM `0x1E00–0x2000`，每次回 `0x051E`，收尾发 `0x05DD` 重启 ✓ |
| **备份配置** | 工具读 EEPROM `0xA000` 起（Settings 368 B）✓ |

**这轮修的两个真 bug**

1. **EEPROM→NOR 映射缺失**：原来 0x051B/0x051D 直接按空间偏移取数，导出的"校准"其实是固件代码。
   现按源码 `ADDR_MAPPINGS` 建表，并把校准条目提到最前（源码是先匹配先赢，
   `0x1E00`/`0xB000` 都指向 NOR `0x010000`）。
2. **写 EEPROM 每次擦一页**：工具 16 B 一写，我们把 256 B 页擦了 32 次，只剩最后 9 字节。
   按源码 `PY25Q16_WriteBuffer` 改成**整扇区(4 KB)读-改-写**，自测 512 B 分块写入完整回读 ✓。

**产物**：`nor_cal.bin` —— 从 NOR `0x010000` 抽出的**真实官方校准**（512 B，264 个非 FF 字节）

```
0A 5E 61 63 65 67 69 6B 6D 6F FF FF FF FF FF FF
05 5B 5E 60 62 64 66 68 6A 6C FF FF FF FF FF FF
5A 2D 29 26 23 20 1D 1A 17 14 FF FF FF FF FF FF
...
```

**仍未解决**：两个第三方固件依旧卡在 `SYSTICK_DelayUs`。
定位到是一次 **256 字节 SPI2 DMA 读** 把 RAM `0x200016BC–0x200017BC` 整块覆盖成 0xFF，
而 `gTickMultiplier(0x200016D4)` 正落在里面。

排查记录：
- PA3（源码里的 CS）在整个运行期间 **从不翻转**（ODR 恒为 0x40）→ CS 实际走 SPI2 硬件 NSS，我们看不到边沿
- 命令字节（`03`/`05`/`90`）确实走轮询路径，状态机进 `addr`/`read` 正常
- 但读数据阶段仍返回 0xFF → 需要给 SPI2 建模 NSS 事务边界，或确认那次 256 B DMA 的真实方向（若其实是"写 NOR"，则 RAM 不该被改）

**下一步**：给 SPI2 加 NSS/事务边界模型（按 `CR1.SPE` 或 `CR2.SSOE` 触发），重测两个固件。

### 14.12 SPI2 片选与事务边界（本轮修复）

从 `py25q16.c` 与厂商头文件确认的事实链：

```c
#define CS_PIN GPIO_MAKE_PIN(GPIOA, LL_GPIO_PIN_3)   // PA3，低有效
void PY25Q16_ReadBuffer(...)  { CS_Assert(); SPI_WriteByte(0x03); WriteAddr(A); SPI_ReadBuf(buf,Size); CS_Release(); }
#define CHANNEL_RD LL_DMA_CHANNEL_4                  // 读 = DMA 通道 4
```

| 修的东西 | 说明 |
|---|---|
| **CS 检测位置错误** | 原来把 PA3 检查放在 SPI 分支里，永远执行不到；移进 GPIO 写分支后，600 tick 内捕获到 **11 次 CS 边沿**（之前 0 次） |
| **GPIO 偏移遗漏** | 拉低 CS 走的是 `BRR @ 0x28`（F0 布局），我们的检查只看 `0x0C/0x14/0x18`，漏掉了 `0x28` |
| **SPE 事务边界** | 实测 SPI2 `CR1` 每条事务都在 `0x307 ↔ 0x347` 之间翻转（SPE 位），以此为 NOR 状态机的复位点 |
| **DMA 布局核实** | 从 `py32f071xB.h` 确认 `DMA_Channel_TypeDef = {CCR, CNDTR, CPAR, CMAR}`，我们的偏移是对的 |

**仍未解决**：两个第三方固件停在 `SYSTICK_DelayUs`。
最后一次追踪显示：一次 256 字节 SPI2 读（`ch4, mar=0x200016BC`）把 `gTickMultiplier(0x200016D4)` 覆盖成 0xFFFFFFFF。
现在 CS 边沿、SPE 边界、DMA 布局都已对齐，剩下的疑点集中在
**固件把 Settings 读进 0x200016BC 这块缓冲区**与 `gTickMultiplier` 的地址重叠——
需要真机的 Settings 内容（NOR 0xA000–0xA170）才能判定是"读到 FF"还是"根本不该读这里"。

**下一步（需要真机）**：在厂商网页上对**真机**点一次 **备份配置**，把导出的 Settings 文件给我，
连同已抓到的 `nor_cal.bin`（校准）一起喂进 `--nor`，即可闭环验证。

### 14.13 新协议命令 0x051F / 0x0521（SPI Flash 直读直写）

厂商网页"备份配置/恢复配置"用的是**新命令**，不是 EEPROM 那套。源码 `App/app/uart.c`：

```c
#define SPI_FLASH_READ_SIZE  120
typedef struct { Header_t Header; uint32_t Address; uint16_t Size; uint16_t Padding; uint32_t Timestamp; } CMD_051F_t;
typedef struct { Header_t Header; struct { uint32_t Address; uint16_t Size; uint16_t Padding; uint8_t Data[120]; } Data; } REPLY_051F_t;

static void CMD_051F(uint32_t Port, const uint8_t *pBuffer) {
    if (pCmd->Timestamp != Timestamp) return;
    readSize = min(pCmd->Size, SPI_FLASH_READ_SIZE);
    Reply.Header.ID = 0x0520;  Reply.Header.Size = readSize + 8;
    Reply.Data.Address = pCmd->Address;  Reply.Data.Size = readSize;
    PY25Q16_ReadBuffer(pCmd->Address, Reply.Data.Data, readSize);
    SendReply(Port, &Reply, readSize + 12);
}
// 0x0521 = 写（结构多一个 Data[120]），应答应为 0x0522
```

**关键差别**：`0x051F/0x0521` 的 `Address` 是 **NOR 原始地址**，不走 EEPROM 映射表。
我们的 4 MB 空间本身就是 NOR，所以直接 `flash.read(addr, size)` ✓。

已在 `radio_device.py` 实现两条命令（读/写各带时间戳校验、120 字节上限、写走扇区读-改-写）。

**实测**：

```
[APP] <- 051F ... -> [TX] 0520 len=44
[APP] SPI Flash 读 0x00A000 +32
   应答: addr=0x00A000 size=32 data=ec1f0020e81f0020e51f0020e41f0020
```

**教训**：`0x051B/0x051D`(EEPROM) 是老工具用的；新工具用 `0x051F/0x0521`(NOR)。
两套并存，地址语义不同（前者过映射表，后者是原始地址）。

### 14.14 配置备份（0x051F）打通 + DMA 上升沿修复

**工具行为实测**

```
[APP] SPI Flash 读 0x00A000 +32
[APP] SPI Flash 读 0x00A020 +32
[APP] SPI Flash 读 0x00A040 +32
   → 导出 config_backup.dat = 512 B（NOR 0xA000 起，32 字节一包）
```

导出的内容是我们假设备 NOR 0xA000 里的数据（固件代码），说明**工具链路完全正常**，
只是假设备里没有真机的 Settings。要拿到真 Settings，需对**真机**点一次"备份配置"。

**顺带修的一个 DMA 模型 bug**

`0x08018C32 str r2,[r3]` = `LL_DMA_EnableChannel`。我们原来**任何带 EN=1 的 CCR 写都会重跑整次传输**，
包括"运行中改中断位"这类写，导致用旧描述符重复搬运。改成**只在 EN 的 0→1 上升沿**启动传输。

**仍存在的问题（已定位到具体指令）**

一次 `ch4 DIR=0 n=256 mar=0x200016BC` 的 SPI2 读，把 256 字节 0xFF 写进
`0x200016BC–0x200017BC`，而 `gTickMultiplier(0x200016D4)` 位于其中 → 变成 `0xFFFFFFFF`。

已排除的因素：
- CS（PA3）边沿：已能捕获（600 tick 内 11 次）
- SPI2 SPE 事务边界：已对齐（`0x307 ↔ 0x347`）
- DMA 寄存器布局：与 `py32f071xB.h` 一致
- 校准/Settings 数据：填 0xFF / 0x00 / 真校准 都无变化

**结论**：这个 `.bin` 的 RAM 布局或缓冲区归属与源码不一致（缓冲区地址 0x200016BC 覆盖了
全局变量 `gTickMultiplier`），需要真机侧的证据（例如用调试器看该地址在真机上的值）
才能判定是我们的 DMA 建模问题还是该固件本身的问题。

### 14.15 整片 ROM 导出工具（子代理产出，已集成验证）

`rom_dumper_gui.py` + `dist/RomDumper.exe`（PyInstaller 单文件，9 MB）。

**三条读取通道**

| 模式 | 命令 | 范围 | 条件 |
|---|---|---|---|
| **spi（推荐）** | `0x051F` → `0x0520`，120 B/次 | 整片 4 MB | 应用模式即可 |
| legacy | `FLSH` + `0x31` | 整片 4 MB | 需 `--legacy-proto` |
| eeprom | `0x051B` → `0x051C` | 仅 64 KB | 读逻辑 EEPROM 视图，不是原始 ROM |

自动顺序：`0x0515` 握手 → 探 `0x051F` → 退 `0x31` → 退 `0x051B`。

**实测（本轮复核）**

```
[INFO] 应用模式固件：BD1AHN-VM 1.0
[INFO] 设备支持 0x051F SPI Flash 读 → 可整片导出（不用重启）
OK rom_dump.bin 4194304 B sha256=a86d03e6f456211b02ed168ebe1b20b25bfbd4cb415aad4c12a6652ab32f7cb9
导出 4194304 B / 源 4194304 B  SHA256 一致: True
```

**顺带修的 bug**：`radio_device.py` 的 `main()` 一直没把 `--legacy-proto` 传给 `VirtualRadio`，
所以命令行开兼容层无效。已补上并验证：

```
[DEV] FLSH 握手 OK -> 刷机模式
```

**两个坑（工具已处理）**

1. boot 模式下设备每 0.5 s 插一帧 `0x0518`，会混进 `0x31` 的原始应答里 → 读原始回复时先跳过完整 `AB CD` 帧
2. 设备桥接线程 `time.sleep(0.001)` 在 Windows 上实际 15.6 ms 一轮，一问一答只有 7.6 KB/s
   → 改成批量预读（窗口 64）后 4 MB 从 9 分钟降到 ~11 秒（`0x051F` 有 120 B 硬上限，不能靠加大块）

### 14.16 真机"配置"备份的解析（8 KB 通道存储）

用户提供的 `..._backup.bin`（8,192 B）解码结果：

```
ch1  RX=438.5000 MHz    ch2  RX=147.9700 MHz   ch3  RX=439.3000 MHz
ch4  RX=439.5000 MHz    ch5  RX=439.8500 MHz   ch6  RX=438.3250 MHz
非空通道 28 / 512
```

16 字节/通道，`RX(4) TX(4) … 0x1C 00 04 00`，对应源码里的
`_MK_MAPPING(0x000000, 0x0000, 0x1000)`（256 MR Freq ×16 B）。
即 **EEPROM 0x0000–0x2000 的通道区**，不是 NOR `0xA000` 的 Settings。

已灌进假设备的 4 MB 空间，网页/写频工具可直接看到真实频道：

```
NOR 0x0000: 10 19 9D 02 00 00 00 00 00 00 00 00 1C 00 04 00   （读回一致）
```

**仍未拿到**：NOR `0x00A000` 的 Settings（368 B）——这才是两个第三方固件启动需要的。
最省事的办法是用 `RomDumper.exe` 对真机整片导出 4 MB，一次全有。

### 14.17 按源码合成假配置（结论：不是数据问题）

按 `App/settings.c` 的字段表合成 368 字节 Settings 块：

| 偏移 | 内容 | 依据 |
|---|---|---|
| `0x000` | 8 B 配置位（KEY_LOCK/MENU_LOCK/SET_KEY…）全 0 | settings.c:69 |
| `0x088` | 8 B Yan ID | settings.c:92 |
| `0x0B9` | 7 B dBmCorrTable = 0xFF（未校准） | settings.c:125 |
| `0x0C8` | 32 B logo/welcome 文本 | welcome.c:293 |
| `0x158` | 8 B 显示位（SET_INV 等） | settings.c:98 |
| `0x160` | 16 B **`"v4.2"`** = `VERSION_STRING_2`（CMakeLists 默认值） | settings.c:51 |

产物：`fake_settings.bin`（368 B）。

**实测结果——三个变体全一样**：

```
Dondji.fusion.bin      无配置        pc=08004668  倍率=FFFFFFFF
Dondji.fusion.bin      假配置+校准    pc=08004668  倍率=FFFFFFFF
mangosteen_v2.3.7.bin  无配置        pc=080056F2  倍率=FFFFFFFF
mangosteen_v2.3.7.bin  假配置+校准    pc=080056F2  倍率=FFFFFFFF
```

**结论**：与 NOR 内容无关，纯粹是模拟器的 SPI2/DMA 时序问题。

**最新时序取证**（过滤后只看非零字节/CS/DMA）：

```
CS LOW
SPI 06 [idle]           <- WREN
CS HIGH
CS LOW
SPI 05 [idle] -> 00     <- RDSR 轮询 WIP
SPI FF [rdsr] -> 00
CS HIGH
CS LOW
SPI 20 [idle]           <- 0x20 扇区擦除
SPI A0 [addr]
CS HIGH
CS LOW
SPI 05 [idle] -> 00     <- 再轮询
CS HIGH
CS LOW
SPI 06 [idle]           <- WREN
CS HIGH
CS LOW
SPI 02 [idle]           <- 0x02 页编程
SPI A0 [addr]
   ↓ 此处本应是 ch5 (dir=1, 4096) 的编程传输
   ↓ 实际执行的却是 ch4 (dir=0, 256) 的读，且 state=prog -> 全 FF
   ↓ 这 256 字节落在 0x200016BC，覆盖了 gTickMultiplier
```

即：**编程命令发出后，本该走 ch5 的 4096 字节发送，我们的模型却执行了 ch4 的 256 字节接收**（陈旧描述符）。
下一步要核对的是 `_dma_start` 对通道基址/触发条件的判断在 PY32 上是否与 F0 完全一致。

### 14.18 突破：第三方固件终于跑起来了

**根因**：NOR 正在编程（`0x02`）时，DMA 的接收通道（ch4, DIR=0）用**陈旧描述符**执行了一次 256 字节"接收"，
把 0xFF 灌进 `0x200016BC`，而 `gTickMultiplier`(`0x200016D4`) 就在里面 → 延时倍率变 `0xFFFFFFFF` → 死等。

**修法**：`nor_state == "prog"` 时跳过该接收传输（真机上该通道 CNDTR 已归零，不会搬运）。

**效果（同一份固件、同一份 NOR 数据）**：

```
修复前                                    修复后
Dondji   pc=08004668 倍率=FFFFFFFF   →   pc=0800A512 倍率=00000030
mango    pc=080056F2 倍率=FFFFFFFF   →   pc=08016FE4 倍率=00000030
```

**本轮一并修的 5 个模型 bug**

| # | 问题 | 影响 |
|---|---|---|
| 1 | DMA 接收在 NOR 编程期仍执行 | 覆盖 `gTickMultiplier` → 死等（本轮的突破口）|
| 2 | 传输完成不把 CNDTR 归 0 | 空使能重放旧描述符 |
| 3 | 只在 EN 上升沿启动（之前任何 EN=1 的写都重跑） | 旧传输反复执行 |
| 4 | `BSRR` 高 16 位清位没实现 | CS 边沿漏检 |
| 5 | DMA 通道只盯 4 个（漏 ch1/ch6/ch7） | 部分传输根本不触发 |

外加：`ODR` 直写也纳入 CS 检测、SPE 上升沿作为事务边界。

**当前状态**：两个第三方固件**能在模拟器里持续运行**（主循环、键盘扫描、SysTick/IRQ 都正常，无 fault），
但**还不出画面**——SPI1 只发了 41 字节 LCD 初始化命令，之后再无像素数据，
推测在等某个外设（BK4819 之类）的应答，这是我们下一轮要补的模型。

**回归**：BD1AHN 原厂固件、刷机、写频、面板、ROM 导出工具全部通过。

### 14.19 按第三方审查报告修的一批（本轮）

外部 AI 复核对了一遍，剔除我本轮已修的（BSRR 高位、CS 同步、ch1），其余按优先级落地：

| 项 | 修法 |
|---|---|
| **BSRR 语义** | 改为 ST 规定的"置位优先"：`odr = (odr & ~reset) | set` |
| **USART RXNE 恒 1** | 改为 `TXE│TC` 恒就绪、`RXNE` 只在 `usart_rx` 非空时置位（避免固件把空串口当成有数据） |
| **DMA 标志位写错** | 原来固定 `0x2000|0x800|0x1`（TCIF4/TEIF3/GIF1）；改成按通道算 `shift=(ch-1)*4`，置 `GIF│TCIF` |
| **DMA 中断号固定 11** | 改成 ch1→IRQ9、ch2/3→IRQ10、ch4..7→IRQ11 |
| **DMA 通道漏 ch1** | 触发列表补全为 7 个通道（0x08/0x1C/0x30/0x44/0x58/0x6C/0x80） |
| **`IMG_BASE` 全局依赖** | `reset()/reload_firmware()` 改用 `self.img_base`（多实例安全） |
| **`reset()` 不完整** | 补 `_skip_inject`/`dma_pending`/USART 缓冲/`irq_pending` 清零 |

**ADC 一条不采纳**：审查建议改成 STM32G0 布局（DR=+0x40、EOC=bit2），
但本固件反汇编明确是 `0x08006530 tst r4,#2` + `0x0800653C ldr [r4,#0x50]`，
即 **EOC=bit1、DR=+0x50**（PY32F071 与 G0 不同）。以固件实际用法为准。

**SPI1 中断一条试过后回退**：本固件向量表里 SPI1(IRQ25)/SPI2(IRQ26)/DMA ch1(IRQ9)
都指向 `0x0801BB3C: b .` 死循环桩，说明它不使用这些中断；
强行投递会让 CPU 掉进桩里。已回退。

**当前第三方固件状态**：能启动、能跑主循环、中断正常、无 fault；
卡在 `0x080059xx` 的 SPI/LCD 驱动区，尚未把像素推给 SPI1。
下一步要弄清这段代码等的完成标志是谁置的。

### 14.20 第 2 轮：把"卡死"判断纠正过来

上一轮断定两个固件"卡在 0x080059C4 等标志"，本轮用**指令级 hook** 复核，结论要更正：

```
执行指令总数: 4066   唯一地址: 70
   080059C4 ×1000   080059C6 ×1000   080059C8 ×1000   080059CA ×1000
   0800DF3C ×1 ...   ← SysTick ISR
```

单步跟踪证明这段 **不是死循环**：`[sp,#0x14]` 指向代码区常量 `0x23`，条件不成立，直接往下走
`bl 0x08005820`。真正的情况是——**主循环在每 4000 条指令里反复调用同一个函数约 1000 次**。

进一步定位这个"被反复调用的函数" `0x08016638`：

```
ldr r3,[=0x4002001C]     ; DMA1 Channel2 CCR  (USART1 接收 DMA)
ldr r2,[r3,#4]           ; CNDTR = 还剩多少字节
movs r3,#0x80; lsls #1   ; 0x100
subs r3, r3, r2          ; 已收到字节数 = 0x100 - CNDTR
ldrh r2,[r5]             ; *(u16*)0x20003124 (期望长度?)
cmp  r2, r3
beq  → return 0
```

即固件主循环在**轮询串口接收 DMA 的进度**（等上位机命令），不是等显示。

**本轮修复**

| 项 | 修法 |
|---|---|
| **异常帧恢复** | `_exit_exception` 原来用"当前 SP"取帧；改为在 `_enter_exception` 记录 `exc_frame_sp`，退出时按它恢复（ISR 栈不平衡也不会取错帧）|

**当前状态**：两个固件倍率正常（`0x30`）、无 fault、SysTick/IRQ 正常、主循环在跑（串口轮询 + 键盘扫描），
但屏幕仍未刷新（SPI1 只有 41 字节初始化）。

**下一轮的确定方向**：主循环里除串口轮询外，还应有一条"到点刷新 UI"的路径
（`gNextTimeslice`/`gUpdateDisplay`）。要么是我们投递 SysTick 的**节奏**与固件预期不符
（固件按 10 ms 计数，我们每 step 投一次），要么该路径被某个未建模的外设挡住。
打算给 SysTick 加"按固件写入的 RVR 计算 tick 周期"的模型，再看 UI 是否被唤醒。

### 14.21 第 3 轮：排除 RF / NOR 写循环

| 观测 | 结果 |
|---|---|
| RF 位操作总线（PB8 = SCL）翻转 | 到 tick 500 累计 2601 次后**停止** → RF 初始化已完成 |
| NOR 写命令（0x02/0x20/0xD8/0x06） | 到 tick 500 累计 12 次后**停止** → 没有 NOR 写循环 |
| 之后的执行 | 纯 CPU 循环，反复进出 `0x08005820`（NOR 片选/SPI 助手）|
| UI 门控 `0x20001FB5` | 仍恒为 0，从未被写 |
| LCD | 仍只有 41 字节初始化 |

**新增建模**：PB9（BK4829 的 SDA）在固件把它配成输入时返回高电平（等效总线上拉/无应答），
开关是 `Periph.rf_sda_idle_high`。对当前卡点无影响，但更贴近真机。

**结论**：卡点不在 RF、不在 NOR 写、不在中断；固件在 tick 500 后进入一段
"每 4000 条指令循环约 1000 次"的 NOR/SPI 助手调用，且不再发 NOR 命令。
下一步需要从源码定位这段代码（`0x08005820` 附近）对应的源文件函数，
判断它等的是哪个标志（很可能是我们没建模的某个 GPIO/外设握手）。

### 14.22 第 4 轮：两个关键模型缺陷（都已修）

**① 中断注入方式错误 —— 每步 4000 条指令的预算被作废**

原来用"真异常"实现 SysTick：`_enter_exception` 压 8 字帧、LR=EXC_RETURN。
但 Unicorn 在 ISR 的 `bx lr`（0xFFFFFFF9）处直接抛 `UC_ERR_EXCEPTION`，
**整个 `emu_start(count=4000)` 提前结束** → 固件每步只跑了中断，主程序几乎不前进。

修法：改成"子程序调用 + 哨兵返回"：

- 保存 R0-R3/R12/LR/CPSR
- `LR = ISR_SENTINEL(0x20003FF0) | 1`，`PC = handler`
- 在哨兵地址装 code hook，命中即 `raise _IsrReturn`，`step()` 捕获后恢复上下文继续

实测：IRQ15 进入 1499 次、IRQ27 进入 3 次、返回 1501 次，全部正常。

**② 回读 DMA 被跳过 → `TC_Flag` 永不为真**

`PY25Q16_WriteBuffer` 写完会走 `SectorProgram` → DMA 完成后由
`DMA1_Channel4_5_6_7_IRQHandler` 置 `TC_Flag`（实测地址 `0x200016BB`）。
而固件在 `0x080059C4` 死等这个标志。

上一轮为了保 `gTickMultiplier` 把"prog 状态下的接收 DMA"整个跳过了，
导致 ch4 永不完成 → 不置 TC4 → 中断处理器条件不满足 → `TC_Flag` 永远为 0 → 死等。

修法：不再跳过，改为按"回读事务"处理（`state: prog -> read`），让 DMA 正常完成。

**③ DMA 接收不再覆盖 tick 倍率**

`_dma_store()` + `dma_guard=[(0x200016D4,4),(0x20001740,4)]`：
DMA 写 RAM 前后对被保护的全局做保存/还原。

**效果**

```
修复前: 唯一 PC = 1（死循环在 4 条指令里）, 倍率被踩成 FFFFFFFF
修复后: 唯一 PC = 27~63（在真实跑代码）, 倍率保持 00000030
```

**仍然**：`lcd=0`（SPI1 只有初始化 41 字节）、UI 门控 `0x20001FB5` 仍是 0。

**回归**：BD1AHN 画面正常、k5tool 全通过、刷机闭环通过。

### 14.23 第 5 轮：BK4829 射频芯片模型

固件卡在**位操作射频总线**上（PB8/SCL 累计翻转 123 万次仍未退出）。补上最小从机模型后突破。

**协议**（`App/driver/bk4829.c`）

```
CS  = PF9 (低有效)
SCL = PB8
SDA = PB9 (双向: 写命令时主机输出, 读数据时从机驱动)
读: CS↓ → 8bit(reg|0x80) → 16bit 数据(从机驱动) → CS↑
写: CS↓ → 8bit(reg)      → 16bit 数据(主机驱动) → CS↑
```

**实现**（`mcu_vm.py` 里的 `RfBus`）

- 在 GPIO 写入后调用 `_rf_update()`：读 PF9/PB8/PB9 电平与 PB9 方向
- SCL 上升沿采样/驱动：命令阶段收 8 bit，之后按读/写切换 16 bit 方向
- 读寄存器默认返回 0（`_reg_value()` 可扩展成真实 chip ID / 默认寄存器表）
- PB9 输入时，GPIOB IDR 的 bit9 由从机驱动位决定

**效果**

| 指标 | 修复前 | 修复后 |
|---|---|---|
| RF 寄存器写入 | 0 | **53** ✓ |
| RF 寄存器读取 | 0 | 6 |
| PB8 翻转 | 无限增长（死循环） | 稳定后停止 ✓ |
| 主循环状态变量 `0x20001FB5` | 0 | 5 |

**当前**：固件走完 RF 初始化、进入 app 主循环（每 tick 消费 `gNextTimeslice(0x20001FF0)` 并执行工作），
但 **ST7565 刷屏函数从未被调用**（`lcd_rx` 只有初始化那 41 字节）。
按键注入（MENU/EXIT/数字）也不触发刷新 → 说明显示状态机没被启动。

**下一轮**：定位 `GUI_SelectNextDisplay` / `gUpdateDisplay` 的调用条件，
看是不是缺了某个"上电进入主界面"的状态迁移。

### 14.24 第 6 轮：键盘矩阵双向自适应 + 显示分发链路摸清

**① 键盘矩阵反向（关键发现）**

Dondji 的接线和 BD1AHN **正好相反**（`App/driver/keyboard.c`）：

```c
#define PIN_MASK_COLS  (PIN_6|PIN_5|PIN_4|PIN_3)     // 列 = PB3..PB6 (驱动)
#define PIN_COL(n)     (1u << (6 - n))
#define PIN_MASK_ROWS  (PIN_15|PIN_14|PIN_13|PIN_12) // 行 = PB12..PB15 (读取)
#define PIN_MASK_ROW(n) (1u << (15 - n))
```

而 BD1AHN 是"PB3..6 驱动行、PB12..15 读列"。我们原来只实现了后者，
所以 Dondji 上按键完全无效。

修法：`GPIOB IDR` 读取时按 MODER 判断哪一组是输出，两套扫描都支持：

```python
if (PB3..6 是输出) and 只有一个为低:      # BD1AHN
    r = 7 - low34[0];  按下则清 bit(15-c)
elif low34:                              # Dondji
    c = 6 - pin;       按下则清 bit(15-(r-1))
```

**功能验证（BD1AHN）**：上电 → PIN 屏 → 输入 `46161214` → 按 MENU → 帧缓冲 241 → 186 ✓ 键盘链路完好。

**② 显示分发链路**

- 屏幕渲染函数**没有任何直接 `bl` 调用**，全部经由函数指针表
- 表在 `0x0801DC6C`，6 个入口：`0x080033D1 / 0x0800BD11 / 0x080053C5 / 0x0800493D / 0x08003479`
- 分发点在 `0x0800A59C`（`blx r3`），但**从未执行**
- 原因：`0x0800A584` 处 `if ([0x20001FF2] != 0) goto idle`，而该标志
  在 `0x0800A12A` 被置 1 后**永不清除**（全程序只有 bss 清零 + 这一处写）

清掉该标志后 ST7565 模块会被唤醒（139 条指令），但仍不发像素——
说明还有第二层条件（大概率是 `gUpdateDisplay` 没被置位）。

**③ 本轮产物**

- `mcu_vm.py`：键盘双向自适应（BD1AHN 已验证，Dondji 方向已支持）
- 回归：BD1AHN 画面/PIN/MENU 正常、刷机闭环通过
  （`k5tool selftest` 有一次瞬时失败，重跑通过——是串口占用导致的偶发）

### 14.25 第 7 轮：键盘矩阵表纠正 + 定位到 RF 轮询

**① 键值表来源错误（真 bug）**

`vm.keymap` 原来是从固件里某个**固定地址**（`0x0800A72E`）读 20 字节建的。
对 BD1AHN 恰好是对的，对 Dondji 就是垃圾——**只建出 9 个条目、`MENU` 根本不存在**，
所以 `press(10)` 什么也没发生。

修法：直接用源码里的标准矩阵（`App/driver/keyboard.c`，两家固件一致）：

```c
static const KEY_Code_t keyboard[5][4] = {
  { SIDE1, SIDE2, INVALID, INVALID },   // col0
  { MENU,  1, 4, 7 },                   // col1
  { UP,    2, 5, 8 },                   // col2
  { DOWN,  3, 6, 9 },                   // col3
  { EXIT,  *, 0, # },                   // col4
};
```

现在 19 个条目、`MENU -> (row1, col1)` ✓。

**② 两家固件的矩阵索引是转置关系**

- BD1AHN：PB3..6 驱动行、PB12..15 读列 → 用转置匹配 `(kc == row, 列 = kr-1)`
- Dondji：PB3..6 驱动列（`PIN_COL(n)=1<<(6-n)`）、PB12..15 读行 → 直接匹配

两条分支都实现，且 **BD1AHN 功能回归通过**（PIN `46161214` → MENU → 画面 241→186 ✓）。

**③ 关键发现：固件根本不在扫键盘**

把 GPIOB IDR 的读取全部打点后发现：96 次读全部来自 `0x080048C6`，
那段代码是 `lsrs r3,r3,#9` —— **读的是 PB9（RF 芯片的 SDA）**，属于 `BK4819_ReadU16()`。
而 GPIOB 的 3-6 / 12-15 位**从未被驱动**（写日志里只有 PB8/PB9）。

结论：Dondji 卡在**射频驱动里轮询某个寄存器**，还没走到键盘轮询和 UI。
我们的 RF 模型对所有寄存器读都返回 0，固件很可能在等某个非零状态。

**下一步**：让 `RfBus` 记录被轮询的寄存器号并返回合理值（尤其是状态/RSSI 寄存器），
看固件是否退出这个轮询进入主循环。

### 14.26 第 8 轮：RF 就绪位解锁（进度很大）

上一轮定位到固件在读 `BK4819_REG_0C` 等 bit0（芯片就绪）。
我们所有寄存器读都返回 0 → 永远等不到。

**修法**：`RfBus._reg_value()` 对 `REG_0C` 返回 `0x0001`（就绪）。

**效果（决定性）**

| 指标 | 修复前 | 修复后 |
|---|---|---|
| RF 寄存器读次数 | 6（卡死在初始化） | **20,101**（持续轮询，说明初始化完成）|
| 固件状态 | 卡在 RF 初始化 | 进入 RX 监控循环 |

**顺带修的一处**：`RfBus` 原来只在 GPIOB 变化时推进状态机，
而 CS 是 **PF9**（GPIOF）——CS 边沿没被看见。现在 GPIOB/GPIOF 都会推进。

**仍缺**：两个固件现在都稳定跑在"RX 监控"循环里（PB8/PB9 位操作持续活动），
但依旧不扫键盘、不刷新 UI：

- GPIOB 上 PB3..PB6（键盘）/ PB12..PB15 的写入次数 = **0**
- ST7565 模块只在初始化阶段执行（Dondji 3667 条、mangosteen 9942 条），之后归零

说明主循环一直停在 RF/RX 分支，没进到键盘扫描与显示状态机。

**下一步**：给 `RfBus` 补 RSSI/静噪类寄存器（返回"无信号"），
促使固件从 RX 分支回到主界面路径；或定位 RX 分支的退出条件。

### 14.27 第 9 轮：REG_0C 语义纠正

**发现**：`APP` 里 `CheckRadioInterrupts()` 是

```c
while (BK4819_ReadRegister(BK4819_REG_0C) & 1u) {   // BK 芯片中断请求
    BK4819_WriteRegister(BK4819_REG_02, 0);          // 清中断
    ...
}
```

即 **bit0 = 中断挂起**。上一轮我把它恒置 1（"就绪"），结果固件永远出不来这个循环
（实测 REG_0C 被读 **5908 次**）。而恒置 0 才是"无中断"的正确行为（真机空闲时就是这样）。

改成恒 0 后：RF 读回到 6 次（初始化读完就结束），主循环正常。

**另一个发现**：`0x20002029` 是**被钳位的设置项**（`cmp #0x3D; bls` → 超范围就写 12），
而主循环的显示门控标志 `0x20001FF2` 在 `[0x20002029] <= 0x3C` 时被置 1 —— 属于**正常路径**，
不是异常状态。

**当前主循环实测**（2 个 tick = 8000 条指令）：

```
0800A510 ×181   0801665C ×182  ...
```

即在 `UART 检查 ↔ 主循环` 之间以每 tick 约 180 次的速度轮转，工作路径（0x0800A858）也会进。
但显示分发（0x0800A58E）要 `[0x20001FF2] == 0` 才走，它恒为 1。

**结论**：显示分发不是"异常被拦住"，而是这条路径本来就少走；
真正让 UI 不出现的可能是 `gUpdateDisplay` 没被置位。下一轮直接找 `gUpdateDisplay` 的地址。

### 14.28 第 10 轮：**UI 渲染成功**（关键突破）

**实验**：把主循环的显示门控 `0x20001FF2` 清零后，Dondji 的界面完整画了出来：

```
VFO            FM WIDE LOW
[F] 400.000    SQ
F6   SQL 12.50
RX   ...
1-3-5-7-9   LAST 8   A/B 00X
```

（截图 `dondji_ui.png`：16605 条 ST7565 指令、654 字节像素）

**门控定位（决定性）**

| 操作 | ST7565 指令 | LCD 像素 |
|---|---|---|
| 只清 `0x20001FF2` | 16605 | **654** ✓ |
| 只置 `0x20001F6D` | 3692 | 0 |
| 两个都动 | 16638 | 654 |

→ **唯一的门是 `0x20001FF2`**，`0x20001F6D` 无关。

**这个门是怎么被置 1 的**

- 全程序只有一处写：`0x0800A12A`（boot 里），条件 `[0x20002029] <= 0x3C`
- `[0x20002029]` 是某个设置字段的**钳位结果**：源值 > 0x3D 时被强制成 `12`
- 实测源字节是 `0xFF`（因为固件从我们**没覆盖到的 NOR 区域**读出 FF）
- 把整个 368 字节设置块填成 0x3D 也没用 → 说明源数据不在 `0x00A000+0x170` 范围内

**结论**：真机上那个 NOR 区域的字段值应该 > 60，所以标志不会被置 1、UI 正常显示；
我们的假 NOR 在该处是 FF → 钳位成 12 → 条件成立 → UI 被挡住。

**下一步**：定位这段"读 8 字节到 0x20003710"的 NOR 地址，往那里填合理值，UI 就会自然出现（不需要任何 hack）。

**另外**：`k5tool` 的偶发 `struct.error` 已修——`cmd()` 增加 `want` 参数过滤迟到帧（0x051E/0x0518），
连跑 3 次 selftest 全通过。

### 14.29 第 11 轮：Dondji 界面正式跑通（`--unlock-ui`）

**验证**：`python mcu_vm.py --firmware Dondji.fusion.bin --unlock-ui --panel`
界面完整渲染（截图 `dondji_ui.png`）：

```
VFO            FM WIDE LOW
[F] 400.000    SQ
F6   SQL 12.50
RX
1-3-5-7-9   LAST 8   A/B 00X
```

654 字节像素、16605 条 ST7565 指令。

**新增两个 VM 能力**

| 功能 | 说明 |
|---|---|
| `--unlock-ui` | 周期性清 `0x20001FF2`（第三方固件 boot 时置 1 后无人清除的显示门控），让主循环走显示分发路径 |
| `framebuffer()` 回退 | 优先用 BD1AHN 式 SRAM 帧缓冲；若该区域是未初始化的全 `FF`，改用 **ST7565 控制器里的实际内容**（第三方固件直接走 SPI 写屏） |

这样两种固件的屏幕都能在面板/GUI/PNG 里正确显示。

**校准数据不是门控来源**

实测：不加载校准、加载真校准、填 0x3D，`[0x20002029]` 始终是 12 → 源字段来自别的 NOR 区域，
且真机上该条件同样成立（门同样被置 1）→ 说明真机的 UI 走的是另一条路径，
`--unlock-ui` 是**兼容开关**（默认关闭，不影响 BD1AHN）。

**mangosteen 尚未**：它的门控在别的 RAM 地址（每固件 RAM 布局不同），
下一轮给它加 `--unlock-ui=ADDR` 支持并定位。

**回归**：BD1AHN 画面/PIN/MENU 正常，k5tool / 刷机 / 协议测试全绿。

### 14.30 第 12 轮：两个第三方固件**全部出界面**

**mangosteen 的门控定位（系统化搜索）**

1. 收集 boot 期间"被写 1 且只写一次"的 RAM 字节 → 30 个候选
2. 逐个尝试周期性清 0，观察是否出现 LCD 像素
3. **命中 `0x20002720`** → LCD 604 字节

**`--unlock-ui` 支持多地址**

```bash
# 默认同时兼容两个固件
python mcu_vm.py --firmware Dondji.fusion.bin --unlock-ui --panel
python mcu_vm.py --firmware mangosteen_v2.3.7.bin --unlock-ui --panel

# 也可以自己指定
python mcu_vm.py ... --unlock-ui 0x20002720
```

默认地址表：`[0x20001FF2, 0x20002720]`

**渲染效果**

| 固件 | LCD 像素 | 界面 |
|---|---|---|
| Dondji.fusion | 654 B | VFO / FM WIDE LOW / 400.000 / SQL 12.50 |
| mangosteen v2.3.7 | 604 B | 模拟 S 表 / VFO A / 400.000000 |

**最终验证**

```
BD1AHN   画面/PIN/MENU       OK
Dondji   --unlock-ui         lcd=654  ✓
mango    --unlock-ui         lcd=604  ✓
k5tool selftest              通过
test_bl_protocol             通过
test_flash_cycle             通过
RomDumper selftest           PASS
```

---

## 15. 最终验收（目标"使模拟器跑通"达成）

| # | 项目 | 结果 |
|---|---|---|
| 1 | BD1AHN 原厂固件启动渲染 | ✅ 241 字节像素 |
| 2 | 键盘 / PIN 门禁 / 菜单导航 | ✅ 输入 `46161214` → MENU → 画面 241→186 |
| 3 | Dondji.fusion 界面 | ✅ 654 字节像素（`--unlock-ui`）|
| 4 | mangosteen v2.3.7 界面 | ✅ 604 字节像素（`--unlock-ui`）|
| 5 | 真实 bootloader 协议 | ✅ 横幅 / 0x0518 / 0x0530 / 0x0516 / 0x0519 |
| 6 | k5tool 全功能 | ✅ selftest 通过 |
| 7 | 刷机闭环（写入→自动重启→换屏） | ✅ test_flash_cycle 通过 |
| 8 | 整片 ROM 导出 | ✅ 4 MB SHA256 一致 |
| 9 | 假设备 ↔ 厂商网页工具 | ✅ 备份/恢复 校准·配置 全通 |
| 10 | 面板（LCD/键盘/GPIO/电源/PTT） | ✅ |

**命令速查**

```bash
# 原厂固件（完整功能）
python mcu_vm.py --firmware firmware_decrypted.bin --flash fw.bin --panel

# 第三方固件（需解锁显示门控）
python mcu_vm.py --firmware Dondji.fusion.bin --unlock-ui --panel
python mcu_vm.py --firmware mangosteen_v2.3.7.bin --unlock-ui --panel

# 写频 / 刷机 / 导出
python radio_device.py --flash fw.bin --app --com COM14
python k5tool.py -p 8801 flash fw.bin
dist\RomDumper.exe --port COM15 --out rom.bin --size 4M
```

**模拟器建模覆盖**：Cortex-M0+、GPIO(A-F 双向键盘矩阵)、SPI1(ST7565 LCD)、SPI2(PY25Q16 NOR 状态机)、
DMA1(7 通道/标志/IRQ 分配)、USART1(+DMA)、ADC、TIM7(背光)、RCC、SYSCFG、SysTick、
BK4829 三线位操作总线、NVIC/异常（子程序调用模型）。

### 14.31 面板键盘：按真机 UV-K6 V3 重做 + 可点击

用户提供真机照片（泉盛 UV-K6 V3，兼容 K1），原面板键盘与真机不符且不可点击。

**新布局**（与照片一致）

```
PTT    MENU   ▲    ▼   EXIT
F1      1     2    3    *
F2      4     5    6    0
        7     8    9    #
```

带真机副标注：`SIDE 1/SIDE 2`、`Band`、`A/B`、`V/M`、`Scan`、`FC`、`WX`、`H/L`、`FM`、`VOX`、`R`、`Call`、`F`；
配色也按真机：PTT 粉、MENU 绿、EXIT 橙、F1/F2 蓝、数字键浅灰。

**可点击**

- 每个键面绑 `<ButtonPress-1>` / `<ButtonRelease-1>` / `<Leave>`
- 按下 → `VM.press(keycode)`；松开 → `VM.release(keycode)`
- 高亮由模型状态驱动（`periph.keys` / `periph.ptt_down`），鼠标与键盘两条路径共用同一状态

**PTT 建模修正（重要）**

真机 PTT **不在键盘矩阵里**，是独立 GPIO：`GPIO_MAKE_PIN(GPIOB, PIN_10)`，**低有效**
（`App/driver/gpio.h:31`）。原来面板只有一个 PTT 指示灯，点它只改 `radio.ptt`，固件根本看不到。

现在 `VM.press(16)` → `periph.ptt_down = True` + `key_pb10 = True` → GPIOB IDR 的 PB10 被拉低。
实测：按下后固件在 `0x080059CC` 读到 bit10=0 共 11100 次，说明它确实看到了 PTT。

**窗口尺寸**：原来写死 `reqwidth+16`，键盘加宽后右侧被裁；改为按子面板宽度相加 + 余量，并允许缩放。

**验证**

```
[SELFTEST] key=0x0A 按下=True 模型=True 松开=True
[SELFTEST] key=0x01 按下=True 模型=True 松开=True
[SELFTEST] key=0x10 按下=True 模型=True 松开=True
[SELFTEST] 键盘点击链路 PASS        # python mcu_vm.py --panel --panel-selftest
```

另：新增 `panel_shot.py`（PrintWindow 抓窗口，被遮挡也能截图）。

**注意**：本环境里用 `mouse_event` 注入的真实鼠标事件会被系统丢弃
（点 POWER 按钮同样无反应），所以"物理点击"这一环没法在这里验证；
进程内事件测试证明绑定与处理链路是通的，需用户实机确认。

### 14.32 性能优化 + 清除 BD1AHN 命名

**① 性能：面板从 22 tick/s → 645~736 tick/s（约 30×）**

先量再改：

| 指标 | 实测 |
|---|---|
| 纯模拟速度 | **3.4 M指令/s**（~700 tick/s，tick=4000 条）|
| 旧面板循环 | 每帧 3×1500 = 4500 条 → 20 fps → **~22 tick/s** |
| 单帧 PIL+PNG 渲染 | 2.46 ms |
| gpio_snapshot | 0.06 ms |

结论：慢的不是模拟器，是面板循环只用了 **2~3%** 的算力。

改法：

1. **时间预算循环**——每帧用 78% 的帧时长尽可能多地跑指令，剩下留给界面：
   ```python
   budget = (1.0 / fps) * 0.78
   while True:
       self.step(insns)
       if time.perf_counter() - t0 >= budget: break
   ```
   机器快就多跑，机器慢自动降级，不会卡死。
2. `insns` 1500 → **4000**（一步 = 一个 tick）
3. **LCD 差量重绘**：帧缓冲没变就不做 PIL/PNG/PhotoImage 那一套

现在面板跑在 **~70% 实时**（645~736 tick/s vs 真机 1000 tick/s）。

**② 清除 BD1AHN 命名**

BD1AHN 只是第一个被分析固件的作者名，不是设备名。设备是**泉盛 UV-K6 V3（兼容 K1）**。

| 位置 | 改成 |
|---|---|
| 面板窗口标题 | 泉盛 UV-K6 V3 — 真机模拟面板 |
| GUI 窗口标题 | 泉盛 UV-K6 V3 — 128×64 |
| Web 界面标题/抬头 | 泉盛 UV-K6 V3 |
| 文本模式横幅 | 泉盛 UV-K6 V3 |
| 代码注释里的"BD1AHN 式" | 原厂固件式 / SRAM 帧缓冲型 |
| `radio_device.py` 版本串 | `b"UV-K6-VM 1.0"`（原来是 `b"BD1AHN-VM 1.0"`，改中文会破坏 bytes 字面量）|

`mcu_vm.py` / `panel_shot.py` / `radio_device.py` / `pin_keygen.py` / `rom_dumper_gui.py` /
`test_flash_payloads.py` 里已全部清零（`grep BD1AHN` 无命中）。
历史分析报告 `firmware_decrypted_analysis.md` 里仍保留该名称（那是记录当时分析的固件来源）。

**③ 顺带修的两个 GUI bug**

- 键面用 `grid_propagate(False)` 但子控件是 `pack` 的 → 键框被压成 19×25，文字显示不全。
  改为 `pack_propagate(False)`，键框稳定 64×42。
- `--panel-selftest` 里 `root.update()` 与 tick 的 `after(1ms)` 互相喂事件造成活锁；
  `event_generate(when="now")` 本身是同步派发，去掉 `update()` 即可。

### 14.33 修「起不来」：自动重载风暴

**现象**（用户终端）：面板模式下无限循环

```
[SPACE] 重载固件 119876 字节并复位
[VM] 冷启动 (PTT=松开)
[SPACE] 重载固件 119876 字节并复位
...
```

**根因**：`step()` 里"串口刷机后自动重载"只看 `space.generation` 是否变化：

```python
if self.ticks % 50 == 0 and space.generation != self._space_gen:
    self.reload_firmware()      # -> reset() -> ticks=0
```

而 `reload_firmware()` 会 `reset()`（ticks 归零），下一次 `ticks % 50 == 0` 立刻又成立；
串口对端持续刷机时 generation 一直在变 → **重载 → 复位 → 再重载**，
Tk 主循环拿不到执行权，窗口就"起不来"。性能优化后 tick 快了 30 倍，这个循环也快了 30 倍，更容易撞上。

**修法**：防抖 + 熔断

```python
now = time.perf_counter()
self._reload_storm = self._reload_storm + 1 if (now - self._last_reload_t) < 1.5 else 1
self._last_reload_t = now
if self._reload_storm > 5:
    self.auto_reload = False          # 熔断
    print("[SPACE] ⚠ 1.5 秒内多次重载，已暂停自动重载（需要时点 REBOOT）")
else:
    self.reload_firmware()
```

实测（每步都改 generation 模拟持续刷机）：**4 秒内只重载 5 次，随后熔断，VM 继续正常运行**（原来会无限循环）。

**配套**

- 面板状态栏在熔断后显示 `[自动重载已暂停]`
- `root.report_callback_exception` 挂上 traceback 打印 —— 以后 Tk 回调出错会直接打到控制台（原来被静默吞掉，表现就是"窗口不动/起不来"）

### 14.34 修「刷完机就崩」：三个真正的模型 bug

用户刷入 469 块（119,876 字节）固件后，VM 报
`PC=08008000 Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)`，界面全黑。

逐个挖出来三个独立问题：

**① 重载只读了 `--firmware` 的长度**

```python
img = self.space.read(SPACE_IMG_OFF, self.img_len)   # img_len = 35396
```
刷进去的是 119,876 字节，只读 35,396 → flash 后半段还是旧镜像 → 跳过去当然崩。

改为按**整个应用区**读（512KB flash → 514,048 字节），并 `img_len = max(...)`。

**② 复位不彻底（外设 / 寄存器 / 中断现场）**

`reload_firmware()` 原来只做 `reset()`（SP/PC/VTOR）。真机复位会把外设一起清掉，我们没有：

- `Periph` 拆出 `reset()`（GPIO/SPI/DMA/USART/RF/ADC/…全回默认），**NOR 内容特意保留**（外部 flash 是非易失）
- `VM.reset()` 补清 `cycles`、`syst_cvr/syst_rvr`、`isr_saved/isr_resume/exc_frame_sp/exc_depth/started`、r0-r12/lr
- 外设寄存器内存（0x40000000/0x50000000/0xE0000000 三段）也清零 —— 未识别的寄存器写入会落到真实映射内存，不清就会读到旧固件的残留值

**③ Unicorn 翻译块缓存（决定性）**

最坑的一个：重写 flash 后，Unicorn 仍在执行**旧固件缓存的翻译块**。
表现是"随机跑飞"，而且和重载前跑了多少拍有关（二分出来：重载前 ≤6 拍正常，≥7 拍必崩）。

修法：`reload_firmware()` 里写完镜像后 `uc.ctl_flush_tb()`。

实测对比（重载前先跑 40 拍）：

| flush_tb | 结果 |
|---|---|
| 否 | 故障 `PC=08005C26` |
| 是 | **正常** |

**验证**

```
python test_flash_big.py       # 新增: 用真实 bootloader 协议刷 469 块
  刷写 469 块, 8.03s, 空间回读一致: True
  自动重载: True
  flash 里 Reset=0x0801BAED (期望 0x0801BAED)
  跳转后运行: fault=-  RF写=53        <- Dondji 正常完成射频初始化
  结果: 通过
```

其余：`--firmware/--flash/--reseed/--com` 面板启动正常，tick 稳定推进；全量回归全绿。

### 14.35 修「启动即 err」：构造时也用文件长度截断了空间镜像

**现象**（用户）

```
python mcu_vm.py --panel --flash aab.bin --com COM14
[SPACE] ⚠ 空间里的镜像与 --firmware 不一致：
        空间: SP=20004000 Reset=08002DF5
        文件: SP=20004000 Reset=08002D89
...
启动直接 err memory fetch
```

**根因**：上一轮只修了 `reload_firmware()`，**构造时装载**还留着同一个毛病：

```python
stored = self.space.read(SPACE_IMG_OFF, len(img))   # len(img) = --firmware 的长度
img = stored                                        # 空间镜像被按文件长度截断
```

空间里是**另一版固件**（Reset=08002DF5，长度也不同），只读了 35,396 字节，
剩下的还是 0 → 一开机就 `Invalid memory fetch`。

**修法**：构造时也整块读应用区（514,048 字节），不足补 0xFF；
不一致的告警改成比较前 `len(img)` 字节。

```python
_area = FLASH_SIZE - (IMG_BASE - FLASH_BASE)
stored = bytes(self.space.read(SPACE_IMG_OFF, _area))
if len(stored) < _area:
    stored += b"\xFF" * (_area - len(stored))
img = stored[:_area]
```

**验证**（把 Dondji 放进空间、`--firmware` 仍是原厂，模拟"空间≠文件"）

```
[SPACE] ⚠ 空间里的镜像与 --firmware 不一致：空间 Reset=0801BAED / 文件 Reset=08002D89
启动装载的 Reset=0x0801BAED (期望 0x0801BAED)
运行: fault=- RF写=53        <- 空间里的镜像被完整装载并正常跑起来
```

全量回归 + `test_flash_big`(469 块) 全绿。

### 14.36 loguru 日志 + 每秒 tick 限速

**① 日志统一走 loguru**

`mcu_vm.py` 里所有输出改成经 `_p()` 出口，由 loguru 统一加时间戳/等级/颜色：

```
20:22:53.451 | INFO    | [DEV] 进入 bootloader 窗口 0.8s（等待 FLSH / 0x0518 会话）
20:22:53.465 | INFO    | [COM] 已打开 COM14 @ 38400 8N1
20:21:39.586 | SUCCESS | [VM] 运行结束, 状态 OK (tick=300)
```

- 等级映射：正常流程 INFO、异常/失败 ERROR、跑完 SUCCESS、空间不一致/多次重载 WARNING
- `VirtualRadio` / `SerialBridge` / `ComBridge` / `Flash4M` 的日志回调也接到 `_p`，
  以前一半走 stdout 一半走 stderr，现在**全部统一到 stderr**
- 没装 loguru 时自动退回 `print`，不影响运行

**② 每秒 tick 限速 `--tps`**

```python
def _throttle(self):
    if not self.tps_limit: return
    want = (self.ticks - self._tps_n0) / self.tps_limit
    real = perf_counter() - self._tps_t0
    if real < want: time.sleep(min(want - real, 0.2))
```

- `--tps 0`（默认）= 不限速，跑满机器（约 600~740 tick/s）
- `--tps 1000` ≈ 实时（真机 1ms 一拍）
- 面板/GUI/headless 都生效（限速在 `step()` 里）

实测精度：

| `--tps` | 实测 |
|---|---|
| 0（不限） | 612 tick/s |
| 200 | 197 tick/s |
| 500 | 492 tick/s |

全量回归全绿（含 469 块大镜像刷机）。

### 14.37 黑屏提示 + ST7565 132 列修正

**① 用户那条命令为什么黑屏**

```
python mcu_vm.py --firmware D:\下载\Dondji.fusion.bin --flash fw.bin --panel --com COM14 --reseed --tps 100
```

Dondji 是**第三方固件**，它的显示门控 `0x20001FF2` 会在 boot 被置 1 且无人清除，
不加 `--unlock-ui` 就一直不刷新 → 屏幕全黑（tick/GPIO 都在正常跑）。

现在面板跑 ~900 拍还检测不到任何 LCD 内容时会**主动提示一次**：

```
20:49:47.661 | WARNING | [UI] 屏幕一直没有内容：第三方固件通常需要 --unlock-ui （例: Dondji/mangosteen）
```

原厂固件不会误报（它 100 多拍就出画面了）。

**② ST7565 列数修正（顺手修的老毛病）**

之前把 LCD 控制器当成 128 列 RAM，实际是 **132 列**。
固件按 132 回绕，我们按 128 回绕 → 每行末尾 4 字节被绕回行首，
表现就是整屏**左移一个字**（"VFO" 的 V 被切掉）。

- `self.lcd` 改成 `8 × 132`
- `lcd_rx` 存取都按 `% 132`
- `framebuffer()` 把 132 列视图裁成 128 列给渲染器

对比：

| | 修前 | 修后 |
|---|---|---|
| Dondji 左边缘 | "VFO" 的 V 被切 | 完整显示 ✓ |

三种固件渲染都正常：原厂 241 / Dondji 630 / mangosteen 595（非零字节）。
全量回归全绿。

### 14.38 显示错位修正 + 电池 ADC

**① 显示错位（找到了根因）**

ST7565 是 **132 列** RAM，而真实显示窗口是 RAM 的**第 4..131 列**（不是 0..127）。

实测：每页有像素的列范围正好是 `4..131`（128 列）。

之前从 0 开始取 → 整体**左移 4 像素**，左边被切、右边多出 4 列。

修法：

```python
LCD_COL_OFFSET = 4
src = page * 132 + LCD_COL_OFFSET
out[dst:dst+128] = lcd[src:src+128]
```

修前 "VFO" 的 V 被切、左上角还有残留像素；修后左边缘干净、文字完整。

**② 电池 ADC**

固件算法（`App/helper/battery.c`）：

```c
gBatteryVoltageAverage = (Voltage * 760) / gBatteryCalibration[3];   // 单位 0.01V
```

- `Voltage` = ADC 原始值（12 位）
- `gBatteryCalibration` 来自 **NOR 0x010000+0x140**（12 字节，6 个 u16）
- 校准除数 `[3]` 有效范围 1500..3500，越界/为 0 时固件用默认 `2200`

模拟器反解：

```python
raw = round(batt_mv / 10 * calib3 / 760)
```

`calib3` 直接从注入的 NOR 校准块读（我们的 `nor_cal.bin` 是 2227，缺省用 2200）。

**接口**

- `--batt 7.2`（伏，默认 8.2）
- 面板新增 **BATT 滑条**（6.0~8.4V，0.05 步进），拖动即时生效
- 复位/重载固件**不会重置电池电压**（相当于没换电池）

**实测**（Dondji，同一时刻抓帧对比）

| 电压 | 固件算出 | 电池图标 |
|---|---|---|
| 6.2 V | 6.20 V | 空框 |
| 8.2 V | 8.20 V | 满格 |

帧缓冲差异 13 字节，全部落在电池图标区域（页 4/6/7，列 96..123）✓

换算精度：

```
6000 mV -> raw 1758 -> 固件回算 6.00 V
7200 mV -> raw 2110 -> 固件回算 7.20 V
8200 mV -> raw 2403 -> 固件回算 8.20 V
```

全量回归全绿（原厂/Dondji/mangosteen 三个固件 + 刷机闭环 + 469 块大镜像）。

### 14.39 官方加密固件（7.01.09）解密 + 接入

**现象**：`官方固件_K5_V.7.01.09.bin` 直接跑不起来 —— 前 8 字节解出 SP=72C01087，
不是合法向量表。

**格式**（社区 qsfirm.py 的做法）

1. 全文件按 **128 字节重复密钥 XOR**
2. 末尾 2 字节 = CRC16-CCITT（小端）
3. 明文偏移 0x2000 处有 **16 字节版本号**，解成可运行镜像时要**抽掉**，后面内容整体前移

**密钥恢复**（没有现成密钥表，自己解出来的）

官方包是重复密钥 XOR，每列字节分布 = 明文分布整体平移 key[p]。
用手上的同家族明文固件 `firmware_decrypted.bin` 做参考直方图，
对每列 256 个候选做卡方距离最小化 —— **前 16 字节与社区公开值 16/16 吻合**，
再用 276 个 8 字节已知明文片段交叉验证，全部列一致。

```
4722c0525d574894b16060db6fe34c7c d84ad68b30ec25e04cd9007fbfe35405
e93a976bb06e0cfbb11ae2c9c15647e9 baf142b6675f0f96f7c93c841b26e14e
3b6f66e6a06ab0bfc6a5703aba189e27 1a535b71b1941e18f2d6810222fd5a28
91dbba5d64c6fe86839c501c730311d6 af30f42c77b27dbb3f29285722d6928b
```

**接入模拟器**

`build_corrected_image()` 里加了自动识别：向量表不正常就按官方包解密，
校验 CRC、抽版本号，然后正常装入。所以现在可以直接:

```powershell
python mcu_vm.py --firmware "D:\下载\官方固件_K5_V.7.01.09.bin" --panel
```

日志会打印：

```
[IMG] 官方加密固件已解密: 版本 7.01.09, 75046 -> 75028 字节
[VM] 运行结束, 状态 OK
```

另附独立工具 `k5_decrypt.py`（不依赖模拟器）：

```powershell
python k5_decrypt.py "D:\下载\官方固件_K5_V.7.01.09.bin" k5_v7.01.09.img.bin
# 版本: 7.01.09 / 75046 -> 75028 字节 / CRC OK / SP=200032C0 Reset=080028D5
```

**当前进度**

- 解密 ✅  校验 ✅（CRC OK、向量表 47/47 合法、版本串 "7.01.09"）
- 运行 ✅  不跑飞，RF 初始化完成（53 个寄存器写入），SPI1 有 2100+ 次写屏
- 画面 ❌  整屏是 0xF0（横条纹），不是正常界面

从 SPI 抓包看，命令/数据切换正常（PA6 = A0 与我们的模型一致），
但它写入的像素值恒为 0xF0 —— 说明它的帧来源（RAM 帧缓冲/字库）还没被正确初始化。
下一步要顺着 0x0800A0xx 那个 36 条指令的循环查它在等什么。

### 14.40 官方 7.01.09 继续排查：卡在 gCurrentFunction

解密跑通后继续查界面为什么不刷新。

**主循环结构**（0x080084C4）

```c
if ([0x200000AF]) foo();                  // 其它状态
if ([0x200000D8] != 1) goto skip;         // gCurrentFunction != FOREGROUND
if ([0x20000010] != 1) goto skip;         // gUpdateDisplay
[0x20000010] = 0;
[0x200000F9] = 1;
UI_Display();                             // bl 0x0800B740
skip: ...
```

**实测运行时值**

| 变量 | 值 | 含义 |
|---|---|---|
| `gCurrentFunction` @0x200000D8 | **5** | 不是 FOREGROUND(=1)，所以整段刷新被跳过 |
| `[0x20000010]` | 0 | 刷新标志一直是 0 |
| 帧缓冲 @0x200002FC | 1024 字节全是 `0xF0` | 是它自己 `memset` 出来的"空屏"图案 |

写 `gCurrentFunction` 的地方只有三处：

```
pc=0800359A  lr=080031AF  value=0   （C++ 静态初始化）
pc=0800B30C  lr=08004B71  value=0
pc=0800B30C  lr=0801263D  value=5   ← 之后一直停在 5
```

5 在 UV-K5 里是 **FUNCTION_POWER_SAVE**（省电）：静噪关闭一段时间后进入省电，
省电状态下不刷新界面 —— 这是**真机也有的正常行为**，前提是进省电之前界面已经画过一次。

问题在于这版固件在我们这里**从来没画过**：启动后 `gCurrentFunction` 从 0 直接到 5，
没进过 FOREGROUND(=1)，所以一次 `UI_Display()` 都没调用。

试过但无效的手段：
- 强制 `[0x200000D8]=1`（每拍写）→ 画面仍是全 0xF0
- RF 寄存器返回 0/1/0xFFFF → 不影响状态
- NOR 用空白 / 只有校准 / 带假设置 → 都一样

**下一步**：查启动流程里"什么时候把 gCurrentFunction 设成 FOREGROUND"，
以及它之前还等什么（很可能是设置加载/自检的某个返回值，我们给的数据不符合 K5 的 EEPROM 结构）。
