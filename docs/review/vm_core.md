# mcu_vm.py 代码审查报告（只读审查）

**审查对象**：`E:\CODEX-NOworkspaces\firmware_analysis\mcu_vm.py`
**快照**：`sha256 = 155D651AD3169A8A87E83D459D94251740B46DDF79DFC6391A918E2ED3C10D61`，**1444 行**
（审查期间该文件在 21:43:29 被并发修改过一次：新增 `--legacy-proto`，1441→1444 行。**下文所有行号均以该 sha256 为准**；若文件再变动，请用行号附近的代码片段定位。）
**审查方式**：纯静态审查 + 在隔离目录 `review/_probe`（拷贝件，已清理）里做行为探针 + 用 capstone 反汇编 `firmware_decrypted.bin` 交叉验证模型是否符合固件真实用法。**未修改任何 .py 文件。**

---

## 0. 总体结论

VM 的**主路径是能跑通的**：实测 2500 tick / 3.0 s（≈3.3 M insn/s）无 fault，SRAM 0x20001268 的帧缓冲被正确填充，`render_text()` 能还原出开机界面文字。说明 Unicorn 集成、向量表装载、mem-hook 式外设、帧缓冲选择这几块基本正确。

真正的问题集中在三类：

1. **两个"共享可变状态"没有隔离**（NOR 与 4MB 固件空间同一块 bytearray；Web 线程与仿真线程同改 `periph.keys`）→ 会导致镜像被毁 / VM 永久停机。
2. **外设模型与固件实际用法不一致的地方没有交叉验证**（ADC 的 EOC 位与 DR 偏移、SysTick RVR 只读不写、`--base` 下键值表地址写死）→ 固件进入对应分支就**死循环假死**（不是 fault，是 PC 卡在一个 `beq` 上，外部完全看不出错）。
3. **状态机耦合缺一致性约束**（`cold_boot`/`reload_firmware`/`reset`/`started`/`ticks`/`_space_gen` 各自为政）→ 重复重载、关机后无法恢复、重载后残留按键。

下文按 P0/P1/P2/P3 分级，每条给：位置、现象、触发条件、修法。

---

## P0 — 会跑飞 / 会让 VM 永久停机

### P0-1　外部 NOR 模型直接别名 4MB 固件空间，固件擦一次 NOR 就可能毁掉自己的镜像

**位置**：`mcu_vm.py:99`（`self.nor = vm.space.data`）、`:354-366`（`spi2_byte` / `_nor_erase`）、`:543-551`（`reload_firmware`）

```python
# 99
self.nor = vm.space.data if getattr(vm, "space", None) else bytearray(b"\xFF" * 0x200000)
...
# 363-366
def _nor_erase(self):
    base = self.nor_addr & ~0xFFF
    for i in range(0x1000):
        self.nor[(base + i) % len(self.nor)] = 0xFF
```

**现象**：SPI2（外部 NOR）的 `PAGE PROGRAM(0x02)` 与 `SECTOR ERASE(0x20/0xD8)` 直接把 `Flash4M.data` 当 NOR 用；而 `reload_firmware()` 又从**同一块缓冲**的 `SPACE_IMG_OFF = 0x1000` 处取固件镜像（`:547`）。只要固件对外部 NOR 擦/写落在 `0x0000 ~ 0x1000+35396 = 0x6A44` 区间内的任一 4 KB 扇区，**4MB 空间里的固件镜像就被擦成 0xFF**。

更糟的是这条路**绕过了 `Flash4M.program()`，不会 `generation += 1`**，也不置 `dirty`（已核对 `radio_device.py:202-231`）。于是：

- `step()` 的自动重载判据（`:601-605`）看不到变化 → **不会自愈**；
- 下一次 `cold_boot()`（面板 REBOOT / POWER OFF→ON）或任何 `reload_firmware()` 会装载一份全 0xFF 的镜像；
- `reset()` 于是把 `SP = 0xFFFFFFFF`、`next_pc = 0xFFFFFFFE`（`:555-556`）→ 下一次 `emu_start` 立刻 `fault`，或者（如果 `F8/F9/FC` 撞上 EXC_RETURN 判据）被误判成异常返回而**跑飞**。

**触发条件**：任意一次 NOR 擦除/编程命中 `< 0x6A44`；典型场景是固件把配置/校准数据存在 NOR 起始扇区。

**修法**（二选一，推荐 A）：

```python
# A. NOR 用独立缓冲，彻底和固件空间解耦
# Periph.__init__
self.nor = bytearray(b"\xFF" * 0x200000)      # 独立 2MB NOR 镜像

# B. 若确实想保留"能擦到固件区"的语义，至少要显式告警 + 让重载能看见
def _nor_touch(self, base, n):
    img_lo, img_hi = SPACE_IMG_OFF, SPACE_IMG_OFF + getattr(self.vm, "img_len", 0)
    if base < img_hi and base + n > img_lo:
        print("[NOR] 警告: NOR 擦写命中固件镜像区 0x%X..0x%X" % (base, base + n))
        self.vm.space.generation += 1       # 让 auto_reload 至少能看见
```

---

### P0-2　`--web` 的 HTTP 线程直接改 `periph.keys`，与仿真线程的 set 迭代竞争 → hook 抛异常 → VM 永久 fault

**位置**：`mcu_vm.py:131`（仿真线程里迭代）、`mcu_vm.py:1204-1219`（HTTP 线程里写）

```python
# 131  (在 mem-read hook 里, 仿真线程)
for (r, c) in self.keys:
    if r == self.vm.driving_row:
        val &= ~(1 << (15 - c))

# 1214-1219 (HTTP 线程)
with vm_self._lock:
    if down:
        vm_self.press(kc)          # -> self.periph.keys.add(m)
```

**现象**：`_lock` 只保护了 `_web_hold` 这个字典，**没有保护 `press()` 对 `periph.keys` 的修改**。`on_read` 每读一次 GPIOB->IDR 就迭代一次 `self.keys`（固件一次按键扫描要读 8×5 次 IDR，几乎是连续发生的），而 HTTP 线程随时可能 `add()`/`discard()`。一旦 CPython 在 `set_next()` 之间切换线程，就抛 `RuntimeError: Set changed size during iteration`。

**这个异常会被 Unicorn 吞成 `UcError`**（我在本机 unicorn 2.1.2 实测：hook 内抛任意 Python 异常 → `emu_start` 抛 `UcError: Unhandled CPU exception (UC_ERR_EXCEPTION)`），然后落到 `step()` 的 `except UcError`（`:589-597`）→ `self.fault = "PC=... Unhandled CPU exception"` → `run_web` 的 `while not self.fault` 退出，页面永远定格。

**触发条件**：`--web` 模式下点键盘按钮；概率低但一旦命中就是"页面卡死、无任何提示"。同理适用于任何"其他线程调用 `press/release`"的用法。

**修法**：HTTP 线程只入队，主循环消费。

```python
# run_web 初始化
import queue
self._keyq = queue.SimpleQueue()

# do_POST
if self.path.startswith("/key"):
    ...
    vm_self._keyq.put((kc, down))     # 只入队, 绝不碰 VM 内部状态
    self.send_response(204); self.end_headers()

# 主循环 (1232-1242 处)
while not self.fault:
    if not self.step(insns):
        break
    while True:
        try:
            kc, down = self._keyq.get_nowait()
        except queue.Empty:
            break
        self.press(kc) if down else self.release(kc)
    ...
```

---

## P1 — 行为错误 / 功能失效

### P1-1　ADC 模型与固件实际寄存器映射不符：EOC 位错、DR 偏移错 → 固件调用即死循环

**位置**：`mcu_vm.py:111-112`、`:181-186`、`:275-287`

```python
self.adc_isr = 0x04            # 111  -> 当成 bit2 = EOC
self.adc_dr = 0x600            # 112
...
elif a == 0x40012440:          # 185  -> DR 按 STM32F0 的 +0x40 建模
    val = self.adc_dr
```

**固件侧证据**（反汇编，`0x08006520` 处的"读一次 ADC"辅助函数）：

```
08006522  ldr  r3, [pc, #0x24]     ; r3 = 0x40012400 (ADC)
08006526  ldr  r4, [r3, #8]        ; CR
0800652C  str  r2, [r3, #8]        ; CR |= cfg<<15   (启动转换)
0800652E  movs r2, #2
08006530  ldr  r4, [r3]            ; <- ADC->ISR
08006532  tst  r4, r2              ; 等 bit1 (EOC)
08006534  beq  0x8006530           ; <-- 死等
08006538  rsbs r2, r2, #0          ; 写 -5 清标志
0800653A  str  r2, [r3]
0800653C  ldr  r3, [r3, #0x50]     ; <- ADC->DR 在 +0x50, 不是 +0x40!
0800653E  strh r3, [r0]
```

调用者 `0x0800668A` 连读 4 次取平均（电量采样）。而 VM 的 `adc_isr` 从初值 `0x04` 开始、写 ISR 只会清 bit2/置 bit0（`:276-279`），**bit1 永远是 0** → 固件在 `0x08006534` 无限循环。这不是 `fault`，外部只看到"画面不动了"，非常难查。

**触发条件**：固件进入电量/电压采样界面（默认开机路径未走到，所以冒烟测试没暴露）。

**修法**（按固件实测映射改；顺带把 +0x40 保留为别名以防别的镜像）：

```python
# Periph.__init__
self.adc_isr = 0x02                    # EOC = bit1（本芯片/本固件）
self.adc_dr  = 0x600

# on_read
elif a == 0x40012400:                  # ISR
    val = self.adc_isr
elif a in (0x40012450, 0x40012440):    # DR (+0x50 为实际偏移)
    val = self.adc_dr
    self.adc_isr &= ~0x02              # 读 DR 清 EOC（若硬件如此）

# on_write 段, ADSTART 之后
if v & 0x4:
    self.regs[a] = v & ~0x4
    self.adc_isr |= 0x02               # 置 EOC=bit1
    self.adc_dr = 0x600
```

> 附带问题：`adc_isr` 初值就带 EOC、`adc_dr` 恒为 `0x600`、读 DR 不产生新值 → 即使修好位定义，ADC 也只是"常数源"。若要做真模型，至少按通道号给不同值（如电量随 `--battery` 变化）。

---

### P1-2　`run_gui` 关机后 tick 链断开，窗口永久失效；且提示一个不存在的 POWER 按钮

**位置**：`mcu_vm.py:847-868`（尤其 `:854-857`）

```python
if not getattr(self, "power_on", True):
    canvas.itemconfig(item, image="")
    status.configure(text="POWER OFF   (点 ⏻ POWER 开机)")
    return                     # <-- 没有 root.after(interval, tick)
...
root.after(interval, tick)
```

**现象**：一旦 `power_off()`（`run_gui` 里没有任何入口能触发，但 API/外部脚本可以），`tick()` 返回且不再 reschedule → 整个 Tk 回调链死掉。此时**即使之后 `cold_boot()` 把 `power_on=True`，界面也不会再刷新一行**。另外 `run_gui` 只创建了 canvas/status/help 三个控件（`:770-782`），根本没有 POWER 按钮，提示文字误导用户（POWER 按钮只在 `run_panel` 里，`:936`）。

**修法**：

```python
if not getattr(self, "power_on", True):
    canvas.itemconfig(item, image="")
    status.configure(text="POWER OFF   (按 p 开机)")
    root.after(interval, tick)        # 关键：保持心跳
    return
```
并在 `on_key` 里加：`if ev.char in ("p", "P"): self.cold_boot(...)`。

---

### P1-3　`cold_boot()` 在无 `--flash`（默认场景）时根本没复位 —— 面板的 POWER/REBOOT 是空操作

**位置**：`mcu_vm.py:526-541` + `:543-551`

```python
def cold_boot(self, ptt=None):
    ...
    self.started = False
    self.ptt_boot = ptt
    ...
    self.reload_firmware()          # 537

def reload_firmware(self):
    if self.space is None:
        return                      # 546  <-- 直接返回，reset() 永不执行
```

**现象**：不传 `--flash/--uart/--com` 时 `self.space is None`（`:431`），于是 `run_panel` 的 POWER OFF→ON、REBOOT（`:953-962`）只会把 `power_on=True`、`fault=None`，**PC/SP/ticks 全是关机前的值**。若关机前刚 fault，再次开机立刻在同一个 PC 上再 fault；若关机前停在 `step()` 的 sleep 分支，再次开机就从半路继续。文档说"重新上电/重启"（`:527` 注释）与实际行为不符。

**修法**：复位与"是否从 4MB 空间重载"解耦。

```python
def reload_firmware(self):
    if self.space is not None:
        img = self.space.read(SPACE_IMG_OFF, self.img_len)
        self.uc.mem_write(self.img_base, img[:FLASH_SIZE - (self.img_base - FLASH_BASE)])
        self._space_gen = getattr(self.space, "generation", self._space_gen)
        print("[SPACE] 重载 %d 字节并复位" % len(img))
    self.periph_reset()             # 新增：清 keys/lcd/nor_state/dma_flags
    self.held.clear(); self.schedule.clear()
    self.reset()                    # 无条件

def periph_reset(self):
    p = self.periph
    p.keys.clear(); p.key_pb10 = False
    p.nor_state = "idle"; p.nor_addr = 0; p.nor_rx.clear()
    p.dma_flags = 0; p.adc_isr = 0x02
```

---

### P1-4　SysTick：RVR 写入完全不跟踪，读回永远是 479999

**位置**：`mcu_vm.py:191-192`（读）、`:293-299`（写，缺 RVR 分支）

```python
if a == 0xE000E014:            # 读 RVR
    val = self.vm.syst_rvr     # 只在 __init__ 设为 479999 (457-458)
...
# on_write 里没有 0xE000E014 分支，落到 296-299 的通用 self.regs[a] = v
```

**固件侧证据**：`0x0800626C` 的 `delay()` 里 `ldr r5,[r4,#4]`（r4 = 0xE000E010）读 **RVR** 用于回绕补偿：

```
08006272  ldr  r4, [pc, #0x2c]   ; r4 = 0xE000E010
08006278  ldr  r5, [r4, #4]      ; r5 = SYST_RVR
0800627A  ldr  r2, [r4, #8]      ; r2 = SYST_CVR
```

**现象**：固件若把 RVR 改成别的值（例如 23999 做 1 ms 节拍），读回仍是 479999，`delay()` 的 `r3 += (RVR - old)` 分支就按 480000 计，延时长度完全错乱。实测探针：写入 23999 后读回 `0x752FF`（479999）。

**修法**：

```python
# on_write 里补一条（放在 0xE000E018 前面）
if a == 0xE000E014:                       # RVR
    self.vm.syst_rvr = v & 0xFFFFFF
    self.regs[a] = v
    return
```

---

### P1-5　CVR 伪递减用 `& syst_rvr` 当模运算 → 序列非单调，固件的回绕判定会误判

**位置**：`mcu_vm.py:193-195`

```python
self.vm.syst_cvr = (self.vm.syst_cvr - 4800) & self.vm.syst_rvr   # 479999 = 0x752FF
```

**现象**：`0x752FF` 不是 `2^n-1`，按位与不等价于取模。实测序列：`479999 → 475199 → 458879 → 409791`（而不是 475199 → 470399 → …）。固件 `delay()` 用 `cmp r2, r1 / bls` 判断"是否回绕"，遇到这种跳变会把一次普通递减当成回绕，把 `elapsed` 加上一个 `RVR`，延时可能瞬间完成或变得极长。

**修法**：

```python
rvr = self.vm.syst_rvr or 479999
self.vm.syst_cvr = (self.vm.syst_cvr - 4800) % (rvr + 1)
```

---

### P1-6　键值表地址硬编码 `0x0800A72E`，不随 `--base` / `img_base` 平移

**位置**：`mcu_vm.py:479`

```python
tbl = bytes(self.uc.mem_read(0x0800A72E, 20))
```

**现象**：`--base 0x08000000`（或自动判定走 `:425-427` 分支时）镜像被装到 0x08000000，但键值表仍从 0x0800A72E 读 —— 对本镜像那正好落在镜像尾部之外（文件只有 0x8A44 字节，偏移 0xA72E 全 0）→ `keymap` 里除键值 0 以外**全部失配**，键盘整体失灵，且没有任何报错。

**修法**：

```python
tbl_addr = self.img_base + (0x0800A72E - 0x08002800)
tbl = bytes(self.uc.mem_read(tbl_addr, 20))
```

（同理 `self.uc.mem_write(IMG_BASE, ...)` 的 3 处、`reset()` 的 4 处都该用 `self.img_base`，见 P2-9。）

---

### P1-7　`direct_irq` 的"时间"与 `--ipt` 强耦合：改性能参数就改固件行为

**位置**：`mcu_vm.py:601-609`

```python
if self.direct_irq:
    t = struct.unpack("<I", uc.mem_read(TICK_ADDR, 4))[0]
    uc.mem_write(TICK_ADDR, struct.pack("<I", (t + 1) & M32))
```

**现象**：`TICK_ADDR` 是固件 SysTick ISR 递增的 10 ms 计数器（固件 `0x080061FC`：`ldr r2,[pc,#8]; ldr r3,[r2]; adds r3,#1; str r3,[r2]`，计数器 = 0x20001668）。这里**每调用一次 `step()` 就 +1**，而一次 `step()` 执行的是 `insns` 条指令（`--ipt`，默认 4000）。于是：

- `--ipt 4000` 与 `--ipt 1000` 下，同样的固件代码，"10 ms 过去了多少次"差 4 倍；
- 所有基于 tick 的超时、去抖、闪烁、动画速度全部随 `--ipt` 变化；
- GUI 用 `insns=1500`、web 用 `1200`、TUI 用 `3000`，**三种界面的固件时间流速都不一样**（同一固件三种行为）。

**修法**：按指令数换算，而不是按 chunk 数。

```python
CYCLES_PER_TICK = 240_000        # 24 MHz × 10 ms（按实际主频填）
self._cyc_acc += insns           # 近似 IPC=1
while self._cyc_acc >= CYCLES_PER_TICK:
    self._cyc_acc -= CYCLES_PER_TICK
    t = struct.unpack("<I", uc.mem_read(TICK_ADDR, 4))[0]
    uc.mem_write(TICK_ADDR, struct.pack("<I", (t + 1) & M32))
```

---

### P1-8　`interactive()` 在 GBK(cp936) 控制台第一帧就崩（UnicodeEncodeError）

**位置**：`mcu_vm.py:1322-1331`（`render_half()` 的 `█▀▄` 与 `KEY_HELP` 的框线字符）

**现象**：Windows 中文默认控制台 `sys.stdout.encoding == "cp936"`，`w("  " + line + "\n")` 直接抛 `UnicodeEncodeError: 'gbk' codec can't encode character '\u2580'`。我在本机实测复现（同样的 `print` 立刻失败）→ `--interactive` 完全不可用。

**修法**（二选一）：

```python
# 启动时强制 UTF-8
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
```
或者把 `render_half()`/`KEY_HELP` 换成纯 ASCII（`#`/`-`/`|`），并把 `interactive()` 写成不依赖块字符。

---

### P1-9　`interactive()` 里 `r` / `s` / `c` 三个功能键被 `a..t` 分支截胡

**位置**：`mcu_vm.py:1290-1316`

```python
elif "a" <= ch.lower() <= "t":
    kc = ord(ch.lower()) - ord("a")     # 1303-1304：r/s/c 先被这里吃掉
elif ch == "r":                         # 1305：永远到不了
    self.release()                      # 1306
elif ch == "s":  ...                    # 1308
elif ch == "c":  ...                    # 1311
```

**现象**：按 `r` 不是"松键"而是注入键值 17；`s` 变成 18（截图永远存不了）；`c` 变成 2。`KEY_HELP`（`:1251-1257`）承诺的这三项完全不可用。

**修法**：把功能键分支提到 `a..t` 之前，或从字母映射里排除：

```python
elif ch in ("r", "s", "c"):
    ... 功能键处理 ...
elif "a" <= ch.lower() <= "t" and ch.lower() not in ("r", "s", "c"):
    kc = ord(ch.lower()) - ord("a")
```

---

### P1-10　`run_panel` 的键盘矩阵列号 off-by-one：最左一列永远不显示，最右一格永远是 "-"

**位置**：`mcu_vm.py:920-929`

```python
for r in range(1, 5):
    for c in range(2, 6):               # c = 2..5
        kc = rev.get((r, c - 1))        # (r,1)..(r,4) —— keymap 的列是 0..3
        lbl.grid(row=r, column=c - 1)   # 网格列 1..4，还空出第 0 列
```

**现象**：`rev` 的键是 `(1..4, 0..3)`（`:915-918` + `keymap` 构造），这里查的是 `(r,1)..(r,4)` → 列 4 不存在（显示 `-`），列 0（键值 0x0A/0x0B/0x0C/0x0D，即 MENU/上/下/返回那一列）**根本不显示**。面板上看到 4 列键，实际只有 3 列是真的，且整体左移一格。

**修法**：`for c in range(4): kc = rev.get((r, c)); lbl.grid(row=r, column=c, ...)`。

---

### P1-11　`run_panel` 的 PTT 开关写的是 `radio.ptt_idr`，而 VM 的 GPIO 模型从不读它 → PTT 对固件无效

**位置**：`mcu_vm.py:964-968`

```python
def toggle_ptt(_e=None):
    r = getattr(self, "radio", None)
    if r is not None:
        r.ptt = not getattr(r, "ptt", False)
        r.ptt_idr = 0xC400 if r.ptt else 0x0000     # 没人消费
```

**现象**：`Periph.on_read` 的 GPIOC（port 2）IDR 分支只返回 `g["odr"] & 0xFFFF`（`:126-136` 只对 `port == 1` 做了特殊处理），`radio_device.VirtualRadio.ptt_idr`（`radio_device.py:257`、`:292`）在 `mcu_vm.py` 里没有任何读取点（grep 只有这一处写入）。→ 面板上点 PTT 只是点亮一个 LED，固件永远读不到 PTT 按下。

**修法**：

```python
# on_read, port == 2 分支
elif port == 2:
    r = getattr(self.vm, "radio", None)
    if r is not None:
        val |= getattr(r, "ptt_idr", 0) & 0xFFFF
```

---

### P1-12　DMA：CNDTR 不递减/不清零、TCIF 固定写成通道 4/5、`GIF1` 与通道号无关

**位置**：`mcu_vm.py:368-398`

```python
self.dma_regs[ccr_addr] = self.dma_regs.get(ccr_addr, 0) & ~1   # 391: 只清 EN
self.dma_flags |= 0x2000 | 0x800                                # 392: TCIF5|TCIF4
self.dma_flags |= 0x1                                           # 393: GIF1
```

**现象**：
- 真实硬件传输完成后 `CNDTR` 会减到 0；这里保持原值。固件若用 `while (DMA1_ChannelX->CNDTR);` 判完成 → 死等。
- `TCIF5|TCIF4` 与"到底哪个通道在跑"无关（启动判断支持 CH1..CH5 的 4 个 CCR 偏移 `0x1C/0x30/0x44/0x58`，见 `:270`），若固件查 `TCIF1`/`GIF2` 之类就永远等不到。
- `dma_flags |= 0x1` 是 `GIF1`，同样与通道无关。

**修法**：

```python
ch = (ccr_addr - 0x40020000 - 0x08) // 0x14 + 1     # CH1..CH5
self.dma_regs[ccr_addr + 4] = 0                     # CNDTR -> 0
self.dma_regs[ccr_addr] &= ~1
self.dma_flags |= (1 << (4 * (ch - 1)))             # GIFx
self.dma_flags |= (1 << (4 * (ch - 1) + 1))         # TCIFx
```

---

### P1-13　DMA 的"外设→存储器"方向从残留在 `nor_rx` 里的字节取数 → 读回全 0xFF / 错位 4 字节

**位置**：`mcu_vm.py:384-389`；`nor_rx` 只在 `:252` 由 **CPU 写 SPI2->DR** 时追加

```python
else:
    out = bytearray()
    for _ in range(cndtr):
        out.append(self.nor_rx.pop(0) if self.nor_rx else 0xFF)
```

**现象**：正常用法是"CPU 写命令+地址（这几拍也会被塞进 `nor_rx` 的是 0xFF），再让 DMA 读 N 字节"。这里 `nor_rx` 里躺着的是**命令阶段的响应字节**（4 个 0xFF），DMA 会先吃掉它们，然后才是数据 → 读回的数据整体错位 4 字节，且数量不对时全 0xFF。若固件用 DMA 从 NOR 搬运（很可能的用法，因为 DMA 通道就是给 SPI2 配的），读到的全是垃圾。

**修法**：外设→存储器方向直接从 NOR 状态机取，不碰 `nor_rx`：

```python
else:
    out = bytearray(self.spi2_byte(0x00) for _ in range(cndtr))   # 走 read 状态
    # 或：if self.nor_state == "read": ...
```

---

### P1-14　`run_web` 的 `/key` 接口按 `ticks` 超时松键，而 `press()` 走的是"永远按下"路径

**位置**：`mcu_vm.py:1214-1219`、`:1237-1242`

**现象**：`_web_hold[kc] = self.ticks` 只有在 `down=1` 时记录；`down=0` 时直接从 `release` 走，但不清理 `_web_hold` 里可能已存在的过期项 —— 若浏览器先发 `up` 再（因为重连/重放）发 `down`，旧项仍在，200 tick 后会把刚按下的键强行松开。属于状态清理不完整；影响小但会造成"按键偶发丢帧"。

**修法**：`release` 分支同时 `vm_self._web_hold.pop(kc, None)`。

---

## P2 — 健壮性 / 会把错误藏起来

### P2-1　`reset()` 不清外设状态、不清按键、不清定时器 → 重载/重启后是脏状态

**位置**：`mcu_vm.py:553-562`（只复位 CPU 与 `ticks`）

**现象**：`cold_boot()`、自动重载（`:601-605`）都走 `reset()`。但 `periph.keys` / `key_pb10` / `lcd_page` / `nor_state` / `dma_flags` / `adc_isr` / `TICK_ADDR`（0x20001668）以及 `self.held` / `self.schedule` 全保留。具体害处：

- 关机时正按着键 → 重启后那个键**永远按住**（固件以为用户一直按着）；
- `held` 里的绝对 tick 是旧时间轴，`ticks` 归零后 `now >= t_rel` 立刻成立 → 一堆延迟松键在重启瞬间集中触发；
- `TICK_ADDR` 不清零而 `self.ticks` 归零 → 两套时间基准错位（`run()` 的 `max_ticks` 与固件看到的 tick 不再同步）。

**修法**：见 P1-3 的 `periph_reset()`，另加 `self.uc.mem_write(TICK_ADDR, b"\x00"*4)`。

---

### P2-2　`Periph.on_read` 用 `mem_write(address & ~3, 4 字节)` 回填 → 字节/半字访问会污染相邻寄存器

**位置**：`mcu_vm.py:200-201`

```python
if val is not None:
    self.uc.mem_write(address & ~3, struct.pack("<I", val & M32))
```

**现象**：Unicorn 的 `MEM_READ` hook 只是通知，读完仍走真实内存，所以必须先把值写回去 —— 思路是对的。但按 `& ~3` 对齐写 4 字节，对 `LDRB/LDRH` 访问会**覆盖同一条 4 字节字里的其它寄存器**。例如 `ldrb r0,[0x40020001]` 会把 4 字节写到 0x40020000，把 DMA ISR 整个冲掉（虽然读路径本身被拦截，但任何走 `uc.mem_read` 的旁路、以及后续按不同宽度读取同一地址都会看到脏值）。另外地址落在 PPB/PERIPH 区间末尾时（如 0xE00FFFFF）对齐后仍在区间内，暂不越界。

**修法**：按访问宽度写：

```python
if val is not None:
    fmt = {1: "<B", 2: "<H", 4: "<I"}.get(size, "<I")
    self.uc.mem_write(address & ~(size - 1), struct.pack(fmt, val & ((1 << (size * 8)) - 1)))
```

---

### P2-3　GPIO 端口越界会抛 IndexError，而 hook 内异常会被转成 `UcError` 让 VM 直接停机

**位置**：`mcu_vm.py:122-125`、`:208-211`（`self.gpio[port]`，只建了 6 个端口），映射范围却是 0x4000 字节（16 个端口）

**现象**：实测访问 `0x50001800` 直接 `IndexError`；在仿真中表现为 `UcError(UC_ERR_EXCEPTION)` → `step()` 置 `fault`，VM 停机，且错误信息只有 "Unhandled CPU exception"，完全定位不到是外设模型崩了。

**修法**：

```python
if port >= len(self.gpio):
    val = 0
else:
    ...
```
并把 `step()` 的 `except UcError` 里加上 `traceback.print_exc()`（verbose 时），否则这类 hook 内异常永远查不出来。

---

### P2-4　两套显示状态：`Periph.lcd`（SPI 抓包）与 `FB_BASE`（渲染源）互不同步

**位置**：`mcu_vm.py:94`（`self.lcd`）、`:302-314`（`lcd_rx` 写入）、`:706-707`（`framebuffer()` 读 0x20001268）

**现象**：所有渲染路径（`render_text/render_half/render_png/run_gui/run_panel/run_web`）都只从 SRAM 0x20001268 取图；`Periph.lcd` 记录了 ST7565 收到的字节流，但**没有任何地方读它**。当前固件确实是"在 RAM 组成 8×128 帧缓冲 → 整屏 flush"（0x20001268 在镜像里有 14 处引用），所以现在是对的；但只要固件出现任何"绕过 RAM 帧缓冲直接写屏"的局部刷新路径（比如只发一页/一个矩形），VM 屏幕就会不更新，而且很难察觉。

**修法**：加一个自检/调试口，或干脆让 `lcd_rx` 同时把字节镜像进 `FB_BASE`（`self.uc.mem_write(FB_BASE + idx, bytes([b]))`），两条路径就天然一致；或者在 `frame()` 里比对两者并打印告警。

---

### P2-5　`_sync_dma_flags()` 是空函数；`periph.ticks` / `periph.irq_pending` 是死字段

**位置**：`mcu_vm.py:400-401`、`:114-115`

**现象**：`on_write` 的 IFCR/ISR 清除路径（`:258-265`）调用 `_sync_dma_flags()` 什么也不做，读代码的人会以为标志位会同写到某处内存。`self.periph.ticks` 从未被读写，`irq_pending` 只在 `direct_irq=False`（未暴露到 CLI）时用。属于"看起来有逻辑其实没有"，容易在后续改动里踩坑。

**修法**：删掉空函数与死字段，或补上真实语义（把 `dma_flags` 同步到 `0x20000260` 之类）。

---

### P2-6　`run_web` 没有 `server_close()`、线程不 join，也没有电源控制

**位置**：`mcu_vm.py:1226-1248`

```python
finally:
    httpd.shutdown()
```

**现象**：`shutdown()` 只让 `serve_forever` 退出，监听 socket 要等 `server_close()`（或 GC）才释放；`th` 是 daemon 且未 join。同进程里二次 `run_web()` 时端口可能仍被占用（`ThreadingHTTPServer` 默认 `allow_reuse_address=1`，所以多半能重绑，但属于运气）。另外网页端完全没有开机/关机入口，`power_off()` 后页面永远停在最后一帧。

**修法**：

```python
finally:
    httpd.shutdown()
    httpd.server_close()
    th.join(timeout=2)
```

---

### P2-7　`--uart/--com` 不带 `--flash` 时固定写 `device_flash_tmp.bin`，跨运行复用且从不清理

**位置**：`mcu_vm.py:1374-1377`

**现象**：`space_path = args.flash or "device_flash_tmp.bin"`。该文件一旦生成（4 MB），下次运行会被 `Flash4M` 原样读回 —— 如果上一次刷机中途失败/刷了半个镜像，下一次启动会**静默**使用这份陈旧/残缺空间（只在"全 0xFF"时才用当前固件初始化，`:443-448`）。用户得不到任何提示，症状是"莫名其妙跑飞"。

**修法**：临时文件用 `tempfile.mkstemp()` 并在退出时删除；或者在复用旧文件时打印一次摘要（`generation` / 镜像 CRC）。

---

### P2-8　`--ptt` 不带 `--uart/--com` 是一条死胡同

**位置**：`mcu_vm.py:1383-1397` + `:572-585`

**现象**：`--ptt` 只设 `vm.ptt_boot=True`；`vm.radio` 只有 `--uart/--com` 分支才创建。于是 `step()` 永远走 else 分支（`:581-585`）：`time.sleep(0.004); ticks += 1; return True` —— CPU 一次都不执行，界面永远空白，且**没有任何入口能把 PTT 松开**（`toggle_ptt` 需要 `radio`）。`--ptt --gui` 就是一个空窗口，`--ticks` 跑完后打印 "OK"。

**修法**：`--ptt` 时若无 `radio` 就自动建一个（或直接报错退出）：

```python
if args.ptt and not (args.uart or args.com):
    ap.error("--ptt 需要同时给 --uart 或 --com（否则无法松开 PTT，固件永远不运行）")
```

---

### P2-9　`global IMG_BASE`：多实例互相污染，且 `reset()/reload_firmware()` 用的是全局量

**位置**：`mcu_vm.py:418-428`（`global IMG_BASE`）、`:548`、`:555-559`

**现象**：同一进程里 `VM(fw1, img_base=A)` 之后再 `VM(fw2, img_base=B)`，第一个实例的 `reset()/reload_firmware()` 会去读 B 基址，直接错位。`self.img_base` 明明存了（`:429`）却不用。

**修法**：删掉 `global`，全部改成 `self.img_base`（`reset` 里 4 处、`reload_firmware` 1 处、`__init__` 1 处）。

---

### P2-10　`run()` 在 `ticks >= max_ticks` 时立即返回，`cold_boot()` 之后调用 `run()` 什么也不做

**位置**：`mcu_vm.py:629-640`

**现象**：`while self.ticks < max_ticks`。若 `space is None`（`cold_boot` 不复位，见 P1-3），`ticks` 保留旧值 → 后续 `run(max_ticks=旧值+50)` 才动得了；更常见的坑是脚本里 `vm.run(max_ticks=2500)` 跑完后 `vm.cold_boot(); vm.run(max_ticks=2500)` → 立刻返回。现有 `test_flash_cycle.py:91` 已经用 `vm.ticks + 50` 绕过这个坑，说明这个坑是真实存在的。

**修法**：`run()` 的语义改成"再跑 `max_ticks` 个 tick"（内部用 `end = self.ticks + max_ticks`），或者 `cold_boot()` 一定把 `ticks` 清零。

---

### P2-11　`step()` 的关机分支只 sleep，`run()` 会空转 `max_ticks × 10 ms`

**位置**：`mcu_vm.py:569-571`

```python
if not getattr(self, "power_on", True):
    time.sleep(0.01)
    return True
```

**现象**：默认 `--ticks 2500` → 关机状态下 `run()` 要空转 **25 秒**才返回（而且 `ok=True`，看起来像成功）。web 模式下则 100 fps 空转拉帧。

**修法**：关机时直接 `self.ticks = max_ticks` 或 `return False`（让调用方知道"没在跑"）。

---

### P2-12　`run_gui` / `run_panel` 每帧把 128×64 位图编码成 PNG 再交给 Tk 解码

**位置**：`mcu_vm.py:838-842`、`:1020-1024`

```python
buf = io.BytesIO(); im.save(buf, "PNG")
photo = tk.PhotoImage(data=base64.b64encode(buf.getvalue()))
```

**现象**：30 fps 下每秒做 30 次 PNG 编码 + 30 次 Tk 端 PNG 解码 + base64，纯 CPU 开销远超模拟本身（实测模拟 4000 指令只要 ~1 ms）。实际帧率远低于 `fps` 参数，且 `root.after(interval, ...)` 是"做完再等"，误差会累积。

**修法**：直接用 `tk.PhotoImage(width=128, height=64)` + `photo.put("#000000", to=(x,y))` 或一次 `photo.put(data_str)`；或改用 Canvas 矩形只重绘变化像素。

---

### P2-13　`--com` 打开失败直接抛栈

**位置**：`mcu_vm.py:1406-1407` → `radio_device.ComBridge.__init__` 里 `serial.Serial(port, ...)`

**现象**：没装 pyserial 或 COM 口不存在 → `ImportError` / `SerialException` 直接冒到顶层，用户看到一长串 traceback，而前面已经打印了 "[SPACE] ..." 等日志，容易误以为刷机流程已经启动。

**修法**：`try/except` 包住并 `ap.error("--com %s 打不开: %s" % (args.com, e))`。

---

## P3 — 可读性 / 小陷阱

| # | 位置 | 问题 | 建议 |
|---|---|---|---|
| P3-1 | `:71-73`、`:421` | `build_corrected_image()` 名不副实（其实就是读文件）；两处 `open()` 都没有 `with`，fd 靠 GC | 改名 `load_image()`，用 `with open(...)` |
| P3-2 | `:1409-1426` | `--ticks` / `--script` 在 `--gui/--panel/--web/--interactive` 下**静默忽略**；多个界面开关同时给出时取第一个，无提示 | 互斥检查 + 打印"已忽略" |
| P3-3 | `:1395-1399` | `--flsh` 只在 `if args.uart or args.com:` 里被读取；单独给 `--flsh` 完全无效 | 加 `ap.error` 或用 `parser.add_mutually_exclusive_group` |
| P3-4 | `:1379` | `--uid` 用 `int(x, 16)`，非十六进制直接 `ValueError` 栈 | 用 `type=lambda s: int(s, 0)` 并 catch |
| P3-5 | `:477-485`、`:780-781`、`:1254` | 键值表里 `0x11/0x12` 从未映射（`r >= 1` 过滤掉了第 0 行），但帮助文字写"a..t = 键值 0..19" | 帮助改成 0..16 并注明 17/18 不可用 |
| P3-6 | `:425-427` | 基址自动判定启发式（`rst-0x08000000 < 0x2000`）只对本镜像凑巧成立 | 改成"向量表里 SP/PC 都落在合法区间且向量表前 8 个字有 ≥3 个非零"之类 |
| P3-7 | `:1403-1407` | `bridge` / `comb` 创建后从不 `stop()`；进程退出靠 daemon 线程 | `finally` 里调用 `stop()` |
| P3-8 | `:797-807` | `run_gui` 里 `s`/`r` 抢占了键值 18/17（`to_keycode` 永远不会返回它们） | 帮助里注明，或改成 `Ctrl+S/Ctrl+R` |
| P3-9 | `:630-632`、`:763`、`:890`、`:1120`、`:1263` | `started` 只在 `run()` 里用，其余四个入口自己 `reset()` 绕过；`cold_boot` 又把它置 False | 统一成一个 `_ensure_started()` |
| P3-10 | `:457-458` | `syst_cvr` 初值等于 `syst_rvr`，第一次读立刻"回绕" | 初值设 0 或 `rvr//2` |
| P3-11 | `:543-551` | `reload_firmware()` 无条件打印"检测到固件区更新"，从 `cold_boot()` 调用时日志误导 | 加参数或区分日志 |
| P3-12 | `:452`、`:548` | 镜像长度超出 flash 剩余空间时被 `img[:...]` 静默截断 | 检查 `len(img) <= FLASH_SIZE-(base-FLASH_BASE)` 并报错 |

---

## 已交叉核对、**确认没问题**的点（避免后续误改）

这些是我用固件反汇编核对过的，**不要动**：

1. **键盘行列映射完全正确**。固件扫描函数 `0x080059B0`：`str r3,[r4,#0x18]`（BSRR=0x78 拉高 PB3..PB6）→ `subs r3,#0x71` → `lsls r2,r3` → `str r2,[r4,#0x28]`，即第 `r` 行驱动 `1<<(7-r)`；列判据 `IDR & 0xF000`，PB15→col0、PB14→col1、PB13→col2、PB12→col3；表索引 `tbl[r*4+col]`。VM 的 `driving_row = 7 - low[0]`（`:233-234`）与 `val &= ~(1 << (15 - c))`（`:133`）与之逐位一致。键值表实测内容 `12 11 13 13 | 0A 01 04 07 | 0B 02 05 08 | 0C 03 06 09 | 0D 0E 00 0F`，`r>=1` 过滤掉废行 0 是对的。
2. **SPI 状态位**：固件 `0x08005F84`（SPI1）与 `0x08005A4C`（SPI2）都是 `ldr r1,[r3,#8]; tst r1,#2`（等 TXE）、`tst r1,#1`（等 RXNE）→ VM 返回 `0x3`（`:164-165`、`:171-172`）正确。
3. **GPIO 寄存器偏移**：固件用 `[r4,#0x18]`（BSRR）、`[r4,#0x28]`（BRR）、`[r4,#0x10]`（IDR）、`[r4,#0x20]`（AFR/CR）→ VM 的 `0x18/0x28/0x10/0x14/0x20` 分支正确。
4. **A0/DC = PA6、CS = PA3**：固件 `0x08005FA0` 用 `str r2,[r3,#0x28]`（r2=0x40，PA6 清零=命令态）、`0x08005FDC` 用 BSRR=0x40（数据态）；`0x08005A88` 用 BRR=8 拉低 PA3 起 NOR 事务。与 `:237-239` 一致。
5. **ST7565 命令解析**：固件发送 `0xB0|page`、`0x10|(col>>4)`、`0x0F&col` 序列（`0x08005FA0` 三个字节），VM 的 `lcd_rx`（`:302-314`）解析正确。
6. **FLASH OPTR / RDP=0xAA**：固件 `0x08003716` 与 `0x0800372C` 都是 `ldr r0,[r3,#0x20]; uxtb; cmp #0xAA` → VM `:158-160` 正确。
7. **向量表/基址**：文件头 `SP=0x20004000`、`Reset=0x08002D89`（thumb 位正常），与 `IMG_BASE = 0x08002800` 一致；VM 从复位向量开始跑（不是 main），所以固件自己的 `.data` 拷贝（`0x08002D90`）能正常执行。
8. **`emu_start(next_pc | 1)` 的 Thumb 位处理**、`until=0 + count` 的用法、`_exit_exception` 里 `f[6] & ~1` 都对。
9. **帧缓冲地址 0x20001268 是正确的渲染源**（镜像中有 14 处引用），`render_text/render_png` 的位序（page×8+bit）正确 —— 实测能还原出界面文字。

---

## 最该先修的 5 条

1. **P0-1　NOR 别名 4MB 固件空间**（`:99`）
   一行改动（`self.nor = bytearray(...)`），消除"擦 NOR 毁镜像 → 冷启动跑飞"这一类最难查的故障。**先修这个。**
2. **P1-1　ADC 的 EOC 位与 DR 偏移**（`:111-112`、`:181-186`）
   这是"固件死循环但 VM 不报 fault"的典型：`while(!(ISR&2))` 永远不成立，界面定格且没有任何错误信息。按固件 `0x08006530/0x0800653C` 改成 bit1 与 +0x50。
3. **P0-2　Web 线程直接改 `periph.keys`**（`:131` + `:1214-1219`）
   数据竞争 + hook 内异常 → VM 永久 fault。改成入队消费，顺便把"其它线程调 press"这个 API 隐患一并封掉。
4. **P1-3 / P1-2　`cold_boot()` 不复位（无 space 时）＋ `run_gui` 关机后断链**（`:543-551`、`:854-857`）
   面板的 POWER/REBOOT 现在有一半是空的，GUI 关机后永远恢复不了。两处合计不到 20 行改动，直接决定"界面能不能用"。
5. **P1-7　tick 与 `--ipt` 强耦合**（`:601-609`）
   它不影响"能不能跑"，但会让**同一份固件在不同界面/不同参数下表现不同**，是所有"行为不一致"类问题的根源；越早修，后面所有调试结论越可信。

> 次优先：P1-4/P1-5（SysTick RVR/CVR）、P1-6（`--base` 下键盘全废）、P1-8~P1-10（TUI/面板的显示与按键 bug）。

---

## 附：复现与取证方式（供复核）

- 审查快照：`sha256=155D651A…C10D61`，1444 行（`review/_probe/mcu_vm.py` 的临时拷贝已删除，未改动原文件）。
- 行为探针要点（隔离目录里 `import mcu_vm`，直接调 `Periph.on_read/on_write`，避免依赖完整仿真）：
  - `RVR` 写入 23999 → 读回 `0x752FF`（应 23999）；
  - 连续读 CVR → `0x752FF, 0x7403F, 0x7007F, 0x640BF`（非单调）；
  - `on_read(0x50001800)` → `IndexError`；
  - hook 内抛异常 → `UcError: Unhandled CPU exception`（据此推断 `step()` 会置 `fault`）。
- 固件侧取证（capstone 反汇编 `firmware_decrypted.bin`，基址 0x08002800）：
  `0x080059B0`（键盘扫描）、`0x08005A4C`/`0x08005F84`（SPI 收发）、`0x08005FA0`（LCD 命令）、
  `0x080061FC`（SysTick ISR）、`0x0800626C`（`delay()` 轮询 RVR/CVR）、`0x08006520`（ADC 采样）、
  `0x08003716`（读 OPTR 判 RDP）。
