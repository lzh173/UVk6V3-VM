# `radio_device.py` / `k5tool.py` 串口协议与刷机链路 只读代码审查

- 审查对象快照（审查期间未改动，行号以此为准）
  - `radio_device.py` — 32021 B / 818 行，mtime 2026-11-05 21:43:29，SHA256 `659E45A7678AC82F553A941F54893317392843BAAF6F008F81A7CB85E570CF99`
  - `k5tool.py` — 17863 B / 488 行，mtime 2026-11-05 21:44:02，SHA256 `06B70226848F6721FBF92D5033975078F86D5F118597140CE9DB293BE15533FE`
  - 备注：这两个文件在我拿到任务后仍被并发编辑过（21:43 / 21:44）。若 Lead 手上是更晚的版本，请对本文行号做一次 diff 复核。
- 判定基准（不只看代码，全部回到原厂实现核对）
  - 反汇编：IDA 库 `ref/ichi/archive/stock-bl_7.02.02.bin.i64` 中
    `sub_80009D8`（收帧/解析）、`sub_8000AF0`（UART 发帧）、`sub_8000964`（USB 发帧）、
    `sub_80003C4`（通道分发）、`sub_8000204`（命令分发）、`sub_8000268`（0x0516）、
    `sub_80002A0`（0x0519）、`sub_8000240`（0x0530）、`sub_80003A4`（0x051A 应答）、
    `sub_8000388`（0x0517 应答）、`sub_80003DC`（0x0518 信息帧）、`sub_8001328`（主循环）
  - 应用侧参考：`ref/uv-k5-firmware/app/uart.c`、`driver/eeprom.c`、`driver/crc.c`
  - 另外对两个文件做了只读黑盒复现（import 后喂帧，未修改源文件），结论标注为「实测」。
- 本报告只读，未修改任何 `.py`；临时探针脚本已在得出结论后删除（复现片段见各条「实测」说明）。

---

## 0. 先纠正一条基准事实（很重要，否则会做出错误修复）

任务里给的事实是「帧：`AB CD | size | obf(payload‖crc16) | pad pad | DC BA`」，对**两个方向都成立**。
实测原厂实现**只对请求成立**，应答是另一种几何：

| 方向 | 真实布局 | 总长 | 依据 |
|---|---|---|---|
| 请求 PC→设备 | `AB CD` `size` `obf(payload‖crc16)`（混淆长度 = size+2）`DC BA`，**没有 pad** | size+8 | `sub_80009D8`：footer 在 `v0+4+size+2`，`word_200019E0` 拷 `size+2` 字节，crc 取 `plain[size]`；`uv-k5 uart.c:435-449` 同样 |
| 应答 设备→PC | `AB CD` `size` `obf(payload)`（混淆长度 = size，**不含 CRC**）`pad0 pad1` `DC BA` | size+8 | `sub_8000AF0`：只混淆 `i` 字节、拷贝到 +4、`pad0=~Obf[i&0xF]`、`pad1=~Obf[(i+1)&0xF]`、footer；`uv-k5 uart.c:153-181` 同构 |

两个方向的 `size` 都等于 **payload 长度**，所以总长都是 `size+8`，**这是它容易被误判成「对称帧」的原因**。

结论：
1. 两处代码的**帧几何是对的**（`_try_app`/`_extract_frame` 用 `total=size+8`、混淆区 `size+2`；`_reply`/`recv_frame` 用混淆区 `size` + 2 字节 pad）。**不要**给应答补 CRC，那会把总长变成 `size+10`，真机和现有工具都会错位。
2. 真正错的是**应答 pad 的两个字节**（见 P2-1）。原厂 UART 通道算的是 `~Obf[size%16], ~Obf[(size+1)%16]`；`sub_8000964` 里那对 `FF FF` 是 **USB 通道**用的，且 UART 通道从不出现 `0xDF`。

已核对**正确、不要动**的部分：混淆表（`0x8001FF0` 处 16 字节一致）、CRC16（poly 0x1021 / init 0 / MSB-first / 不反射，对应 `driver/crc.c` 的 `CRC_16_CCITT`+`CRC_IV=0`）、`0x0530` 的 `"7.02"`/`'*'` 判定（`sub_8000240`）、`0x0516` 擦 1 页 @0x08002700 再写（`sub_8000268`）、`0x0519` body 布局 `cookie/idx/total/rsv/data` 与块 0 擦 472 页 @0x08002800（`sub_80002A0`）、`0x051A` 12 字节 payload + inner=8 + cookie/idx/status（`sub_80003A4`）、`0x0518` 36 字节 payload + inner=32 + UID 在前版本在后（`sub_80003DC`）、`0x051B/0x051D` 的 timestamp 偏移与静默丢弃（`uv-k5 uart.c:237/268`）、空间映射 `0x08002800↔0x1000`、`0x08002700↔0x0F00`、分片/半包/粘包的解析行为（实测）。

---

## P0（会直接损坏数据或让主流程跑不通）

### P0-1　bootloader 窗口在刷机中途到期，块被静默吞掉 → 半砖
**文件**：`radio_device.py:271`（`enter_boot_window` 设 deadline）、`:343-364`（`tick`）、`:481-521`（`_bl_handle` 从不续期）
**现象**：`boot_deadline` 只在进入时设一次（启动 0.8 s / `0x05DD` 后 3.0 s / `--flsh` 为 inf）。`_bl_handle` 收到 0x0516/0x0519 后**从不延长 deadline**。一旦到期，`tick()` 执行 `go_app()`，后续 `0x0519` 帧被 `_try_app` 当未知应用命令吃掉（`_handle_app` 落到 `未知命令 0519`，无应答），客户端只能等超时。此时块 0 已经把 472 页（120832 B）擦成 0xFF ⇒ 应用区被清空只写进前几块，正是“半砖”。
**触发**：默认启动后的 0.8 s 窗口内开始刷机；或 `0x05DD` 之后超过 3 s（长镜像、工具侧 `boot_wait_info(0.8)`+`boot_unlock`+读文件即可耗尽）。
**实测**：`k5tool.py flash` 生产流程（`VirtualRadio` 默认参数 + `SerialBridge`）→ `ensure_bootloader() -> True (0.51s)`，随后 `boot_write_image_from_bytes` 在**块 1（或块 3，随计时波动）** 抛 `RuntimeError: 块 N 无应答`；设备状态 `boot_mode=False, bl_state=1, bl_next_idx=1`，应用区非 0xFF 的块只有 `[0]`。对照组：设备用 `--flsh`（deadline=inf）同一镜像 16 块全过、回读一致。另外单测：把 `boot_deadline` 置为过期后 `tick()`，`boot_mode` 立刻变 False、续发块 1 无任何应答、`flash[0x1100]` 仍为 `FF`。
**依据**：原厂 `sub_8001328` 里 `n2==1`（boot 模式）是**无限循环**等帧，只有刷完 `n2==3` 才跳应用；`n2==2`（接收中）只做 `delay(10000)`。真机**没有**“刷机窗口超时”，所以这不是拟真而是一个 bug。
**建议修法**：
```python
# radio_device.py  _try_boot()，成功解析出一个完整帧之后
payload = self._extract_frame()
if payload is None:
    return False
self.boot_deadline = float("inf")      # 一旦开始通信就常驻 bootloader（与真机一致）
self._bl_handle(payload)
return True

# 并且 tick() 不要在有会话时退场
if self.bl_state != 0:                 # 1=接收中 2=待跳转
    pass                               # 只做周期信息帧，不改 boot_mode
elif now > self.boot_deadline:
    self.go_app()
```
`0x05DD` 之后也应把窗口设为 inf（真机是复位重进 BL，不会自己回 app）。

### P0-2　`ensure_bootloader()` 回退顺序错误 + `boot_enter` 按 4 字节吞帧 ⇒ 冷启动 100% 进不去刷机
**文件**：`k5tool.py:153-165`、`k5tool.py:174-185`
**现象**：`ensure_bootloader()` 的顺序是 `boot_wait_info(0.8)` → `boot_enter(tries=2)` → `reboot_to_bootloader()` → `boot_enter(tries=20)`。发完 `0x05DD` 后设备其实已经在推 `0x0518` 了，但代码接着用 `boot_enter` 发 ASCII `FLSH`，而 `boot_enter` 用 `_recv_exact(4)` 每轮硬读 4 字节去比 `b"FLSH"`：这 4 字节实际取走的是 `0x0518` 帧的碎片，于是①永远匹配不上，②把帧流的对齐彻底打乱（后续 `recv_frame` 按 2 字节找 `AB CD`，奇偶一旦错位就再也对齐不回来）。
**触发**：设备处于应用模式时执行 `python k5tool.py -p 8801 flash fw.bin`（文档主线用法）。
**实测**：设备跑在 app 模式 → `ensure_bootloader() -> False`，耗时 3.07 s，结束时 `radio.boot_mode=True`（`0x05DD` 明明生效了）。随后 `boot_wait_info(0.8)` 才会成功——也就是说只差“换个顺序”。
**建议修法**：
```python
def ensure_bootloader(self):
    ver, _ = self.boot_wait_info(0.8)         # 已在 BL？
    if ver:
        return True
    self.reboot_to_bootloader()               # 0x05DD → 真 BL 会立刻推 0x0518
    ver, _ = self.boot_wait_info(3.0)         # 关键：先等 0x0518，不要发 FLSH
    if ver:
        return True
    if self.boot_enter(tries=20):             # 仅当目标是旧/兼容固件时兜底
        return True
    return False
```
同时 `boot_enter` 不应裸读 4 字节：要么先 `boot_wait_info` 再判断，要么给它加落盘缓冲（见 P1-6）。

### P0-3　写频 `0x051D` 只做 AND、不擦除 ⇒ 同一个地址第二次写必定损坏（工具还报成功）
**文件**：`radio_device.py:632-643`（`_handle_app` 的 0x051D）、`:202-222`（`program` 的 1→0 语义）
**现象**：应用侧 EEPROM 区按 NOR 的 `old & new` 写入，但上层从不清除。第一次写 `A0A1A2A3`、第二次写 `0F0E0F0E`，实际得到 `00 00 02 02`——静默改动数据，`program()` 只打一条 `违反 1→0` 的 warning，`k5tool.write_eeprom()` 因为只比较应答 ID `0x051E` 仍然返回 `True`。
**触发**：任何对同一偏移的重复写频（改信道参数即触发）；连续两次 `write-channels`。
**实测**：`0x0100 <- A0A1A2A3` 得 `a0a1a2a3`；`0x0100 <- 0F0E0F0E` 得 `00000202`（期望 `0f0e0f0e`）。
**依据**：被仿真的 0x000–0xFFF 是 `uv-k5` 的 **I2C EEPROM**（`ref/uv-k5-firmware/driver/eeprom.c:39-54`，`EEPROM_WriteBuffer` 直接 `I2C_WriteBuffer(pBuffer, 8)`，没有擦除步骤，擦除由器件内部完成），**允许任意覆盖**。而 0x1000 以上才是 NOR 语义的 Flash。现在的实现把两者用同一套 AND 语义，0–0xFFF 区语义错了。
**建议修法**：EEPROM 区用覆盖语义（推荐），或写前擦页：
```python
# radio_device.py  _handle_app  0x051D 分支
if off + len(data) <= EEPROM_SIZE:
    self.flash.data[off:off + len(data)] = data      # I2C EEPROM: 直接覆盖
    self.flash.dirty = True
    self.flash.generation_eeprom += 1                # 见 P1-4，不与固件区共用计数
else:
    ... 回复 0x051E 前先置错误标志，别假装成功 ...
```
若坚持保留 NOR 语义，至少要 `self.flash.erase_pages(off // 0x100 + 0x100, ...)`（把 0x000–0xFFF 也按 256 B 页擦）之后再 `program`，并且只在 `program()` 返回 True 时才回 `0x051E`。

---

## P1（功能/并发/性能缺陷，正常用法下会踩到）

### P1-1　`0x0519` 的“块号不连续 / cookie 不符”分支仍然把数据写进 flash
**文件**：`radio_device.py:504-511`（第 506 行是多写的 `program`）
**现象**：错误分支先 `self.flash.program(SPACE_IMG_OFF + idx*256, data)`，再回 `status=1`。真机 `sub_80002A0` 在 `idx != last+1 || cookie_hash != stored_hash` 时**直接跳到应答、不写 flash**（program 调用在 if/else 之后）。乱序或串会话的块会污染已擦区，配合 P0-1 的“半砖”会把现场搞得更脏；而且 `bl_state = 0` 与真机的 `n2 = 1` 也不同。
**实测**：块 0 之后发 `idx=5` 的块：应答 `...05 00 01 00`（status=1），`flash[0x1000+5*256]` 从 `ffffffff...` 变成 `5a5a5a5a...`。
**修法**：删掉 504-511 里那次 `program`，并把错误分支改为真机式的“回 cookie + 中止会话”：
```python
elif cookie != self.bl_cookie or idx != self.bl_next_idx:
    self.bl_state = 0
    self._reply(0x051A, cookie + struct.pack("<HBB", idx, 1, 0), inner_size=8)
    return
```

### P1-2　`tick()` 里的 `flush()` 把 `program()` 的攒批完全抵消 ⇒ 每收 1 块就整盘写 4 MB
**文件**：`radio_device.py:343-345`（`tick` 开头 `self.flash.flush()`）、`:218-221`（`dirty=True` 与“64 次/1 s”攒批）、`:224-226`（`flush`）
**现象**：`program()` 攒批，但桥线程 ~1 kHz 调 `tick()`，每次看到 `dirty` 就 `save()` 整个 4 MB。于是攒批形同虚设：**每收到一个 256 B 块就重写一遍 4 MB 文件**，而且全程持有 `radio.lock`（见 P1-3/P1-6），把应答延后到可能超过 `_wait_cmd` 的 200 ms 读超时。
**实测**：16 块（4 KB）→ `Flash4M.save()` 被调用 **17 次**、每块平均落盘 4.2 MB；按 472 块（120 KB）外推约 **2.0 GB** 磁盘写。
**修法**：`tick()` 不要承担落盘；改成按时间/大小节流，并且只在空闲时刷：
```python
def tick(self):
    with self.lock:
        # 不再无条件 flush；交给后台节流（下列条件与 program() 共用）
        if self.flash.dirty and (time.time() - self.flash.last_save) > 0.5 \
                and self.bl_state == 0:
            self.flash.save()
```
并把 `program()` 的判据从 `(stat_writes & 0x3F) == 0` 改成“累计字节数 ≥ 64 KB 或距上次 ≥ 1 s”，避免小镜像每块都落。

### P1-3　单一 `radio.tx` 队列 + 两个桥线程 ⇒ 应答被错误的链路取走（跨线串扰）
**文件**：`radio_device.py:366-371`（`poll` 是全局单一队列）、`:711-718`（TCP 线程 `poll`）、`:754-769`（COM 线程 `poll`）、`:691`（bridge 线程直接 `tx[:0]` 插 banner，未持锁）
**现象**：`poll()` 取走并清空**唯一**的 `tx`。同时开 `--com` 和 TCP 时，谁先 poll 谁拿走全部字节：TCP 请求的应答可能被写到 COM 口，反之亦然；另一侧则“永远丢帧”。banner 的 `self.radio.tx[:0] = ...` 还在锁外直接改 `bytearray`（另一个线程可能正 `bytes(self.tx)`），属于未定义行为。
**实测**：一次 0x0527 请求后连续两次 `poll()`：传输 A 拿到 16 字节，传输 B 拿到 **0** 字节。
**修法**：给每个链路独立出口，或让 `poll()` 带目标：
```python
def poll(self, sink="tcp"):
    with self.lock:
        self._dispatch()
        out = bytes(self.tx.pop(sink, b""))   # tx = {"tcp": bytearray(), "com": bytearray()}
    return out
```
最小改动：让 `_reply`/`_bl_info_frame` 往 `self.tx_default` 写，`SerialBridge`/`ComBridge` 各自 `set_default_tx()`；banner 插入放到 `with self.radio.lock:` 内。

### P1-4　`generation` 对每一次 256 B 写入都 +1 ⇒ 写频会让 MCU 侧整体重载
**文件**：`radio_device.py:183/197/214`（`erase`/`erase_pages`/`program` 各 `generation += 1`）、`k5tool` 无责；消费方 `mcu_vm.py:601-605`
**现象**：`mcu_vm` 每 50 tick 比较 `space.generation`，一变就 `reload_firmware()`（注释写的是“串口刷机后自动重载固件”）。但 EEPROM 写（0x051D）也走 `program()`，于是**一次写频就让 MCU 全量重载/复位**，应用会话、`session_ts`、UI 状态全丢；刷机时更是每块 +1。
**实测**：单次 `0x051D` 写 64 B → `generation 0 -> 1`。
**修法**：区分两个计数，只让固件区的擦写触发重载：
```python
def _bump(self, n, fw_area):
    self.generation += 1                     # 总代数（诊断用）
    if fw_area:                              # addr >= SPACE_IMG_OFF 才算固件变更
        self.fw_generation += 1
```
并在 `program/erase/erase_pages` 里按地址判断；`mcu_vm` 改看 `fw_generation`。（`mcu_vm.py` 不在本次审查范围，但如果改 `Flash4M`，需同步这一处。）

### P1-5　`--legacy-proto` 命令行开关没有接上 ⇒ `k5tool dump` / `--legacy` 全是死路
**文件**：`radio_device.py:790-791`（定义参数）、`:795-796`（构造 `VirtualRadio` 时**没有**传 `legacy_proto=args.legacy_proto`）
**现象**：`legacy_proto` 只在构造函数里出现（全文件仅 4 处：定义/赋值/判断/main 里的构造），命令行开关解析后被丢弃，旧 `FLSH`/`0x30-0x34` 兼容层永远关闭。于是 `k5tool.py:194-198/243-261`（`boot_info`/`boot_read`/`boot_erase`/`boot_write`/`boot_exit`）、`main` 的 `dump` 与 `--legacy` 分支必然拿不到任何应答。更进一步：`dump` 依赖 `0x31` 读命令，而**真机 BL 的命令表只有 0x0516 / 0x0519 / 0x0530 三条**（`sub_8000204` 只 switch 1302/1305/1328；0x0518 是周期推送，不是命令），所以 `dump` 对真实协议根本不可实现。
**实测**：`VirtualRadio(..., legacy_proto=True)` 时 `FLSH` 有回应、`legacy_proto=False` 时 `FLSH`/`0x30` 均无应答；`k5tool.py` 文档里的 `dump` 走 `ensure_bootloader()`（见 P0-2）直接返回 False。
**修法**：`radio = VirtualRadio(args.flash, log=print, start_in_boot=..., legacy_proto=args.legacy_proto)`；并给 `dump`/`--legacy` 加显式前置检查与提示（“当前设备只支持 stock-bl 真协议，无读命令”），或把 dump 改成“0x0519 回环 + 设备侧新增调试读命令”。

### P1-6　`k5tool` 没有收包缓冲：200 ms 内凑不齐整帧就整帧丢弃，且丢掉已读字节
**文件**：`k5tool.py:106-118`（`recv_frame` 直接按需 `_recv_exact`）、`:299-312`（`_wait_cmd` 设 0.2 s 超时后 `except: continue`）
**现象**：`recv_frame` 每次从 socket 现读，没有缓冲。一次读超时（`_recv_exact` 抛 `IOError`）会把**半个帧**和已经读入的 4 字节“同步头+size”一起扔掉；而 `_wait_cmd` 吞掉异常继续下一轮，于是该块的应答永久丢失 → `RuntimeError("块 N 无应答")`。设备侧只要磁盘落盘（P1-2）或 COM 桥抖动超过 200 ms，就必然踩中。
**实测**：把一帧 0x051A 应答拆成两段、中间停 0.25 s 送达 → `_wait_cmd(0x051A, 1.0)` 返回 `None`（该帧实际已经完整到达）。只送同步头 4 字节同样返回 `None`。
**修法**：`Radio` 增加自缓冲，按 `size+8` 拼帧：
```python
def _fill(self, n):
    while len(self._buf) < n:
        d = self.ser.read(n - len(self._buf)) if self.ser else self.s.recv(n - len(self._buf))
        if not d:
            return False                       # 超时只是"这次没凑齐"，不清缓冲
        self._buf += d
    return True
```
`_wait_cmd` 里对超时只 `continue`，不丢弃 `self._buf`；读超时建议 0.5 s 起。

### P1-7　`boot_write_image_from_bytes` 不校验 `0x051A` 里回显的 cookie
**文件**：`k5tool.py:286-291`（只看 `st = r[10]`）
**现象**：真机在“会话被重置/块不连续”时回的是 **status=0 + 设备自己的 cookie**（`sub_80002A0` 错误分支 `sub_80003A4(a1, 0)`，status 字节其实是寄存器残留），**靠 cookie 不一致来告知错误**。工具不复核 cookie，在真机上会把“会话已作废”当成功继续写。目前只有模拟器会回 `status=1`，所以本地测试看不出来。
**实测**：模拟器发 `cookie=01020304` 的错序块 → 应答 `1a050800 01020304 0100 01 00`（cookie 原样回显、status=1）；真机路径下 status 不可靠。
**修法**：
```python
got = r[4:8]
if got != cookie:
    raise RuntimeError("块 %d cookie 不符 (回 %s), 会话已被设备重置" % (idx, got.hex()))
st = r[10] if len(r) >= 12 else 1
if st != 0:
    raise RuntimeError(...)
```

---

## P2（协议一致性 / 边界 / 健壮性）

### P2-1　应答 pad 常量 `FF DF` 是错的（任何 size 都不对）
**文件**：`radio_device.py:597`
**现象**：`frame = SYNC + size + enc + b"\xFF\xDF" + FOOTER`。真机 `sub_8000AF0` 与 `uv-k5 uart.c:171-177` 都是 `pad0 = ~Obf[size % 16]`、`pad1 = ~Obf[(size+1) % 16]`；表里既没有 `0x00` 也没有 `0x20`，所以 `FF`/`DF` **对所有 size 都不成立**。容忍型解析器（本仓库 `recv_frame`、真机 `sub_80009D8`）不看 pad，所以现在“能跑”；但任何按规范校验 pad 的上位机/固件都会直接拒帧。
**实测**：一条 12 字节 payload 的 0x051A 应答，实发 pad=`ffdf`，正确值 `ecfc`。
**修法**：
```python
pad = bytes([OBFUSCATION[len(payload) % 16] ^ 0xFF,
             OBFUSCATION[(len(payload) + 1) % 16] ^ 0xFF])
frame = SYNC + struct.pack("<H", len(payload)) + enc + pad + FOOTER
```
（同文件 `:29` 的注释写的就是这个正确公式，实现没跟上。）

### P2-2　应答头 `inner size` 语义错（真机 = body 长度），`0x0517` 应答少 3 字节
**文件**：`radio_device.py:594`（默认 `inner = 4 + len(body)`）、`:477`（`_reply(0x0517, b"\x00", inner_size=4)`）
**现象**：真机所有应答的 size 字段 = **body 长度**：`0x0517` inner=4/body=4/payload=8（`sub_8000388`）、`0x051A` inner=8/body=8/payload=12、`0x0518` inner=32/body=32/payload=36。模拟器除显式传了 `inner_size` 的两条外都用了 `4+len(body)`（即 payload 长度）；`0x0517` 的 body 只有 1 字节、却声明 inner=4 ⇒ payload 只有 5 字节，真机是 8 字节。严格按 size 取 body 的客户端会读越界/等超时。
**实测**：`0x0516` 的应答 payload = `1705040000`（5 字节；真机 `1705040000000000`，8 字节）。`0x0515` 应答 inner=28（真机 36）。
**修法**：
```python
def _reply(self, cmd, body, inner_size=None):
    inner = len(body) if inner_size is None else inner_size   # 真机语义
...
self._reply(0x0517, b"\x00\x00\x00\x00", inner_size=4)        # 与 sub_8000388 对齐
```
`0x051B` 应答的 body 由 `off/size/pad + data` 组成（长度 `4+n`）时，inner 会自动变成 `4+n`，与真机 `pCmd->Size + 4` 一致。

### P2-3　`0x0515` 应答体比真机少 12 字节（Challenge 只发了 4 B，真机 16 B）
**文件**：`radio_device.py:612`、`:32`（注释也写成 `challenge[4]`）
**现象**：`REPLY_0514_t`（`uv-k5 uart.c:59-68`）的 body = `Version[16] + hasAes(1) + lock(1) + pad(2) + Challenge[4]*u32(16)` = **36 B**，payload 40、inner 36。模拟器 body = 16 + 4 + **4** = 24 B，payload 28。目前的 `k5tool.handshake()` 只取 `r[4:20]` 所以看不出来，但认 challenge 的客户端会少读 12 字节。
**实测**：`0x0515` 应答 payload = `1505 1c00 42443141484e2d564d20312e30 000000000000 0000 11223344`（28 B）。
**修法**：`body = ver16 + b"\x00\x00" + b"\x00\x00" + bytes(16)`（`self.challenge` 用 16 字节状态）。

### P2-4　周期性 `0x0518` 在会话进行中仍然每 0.5 s 推
**文件**：`radio_device.py:360-362`
**现象**：真机只在 `n2 == 1`（空闲等命令）时才推信息帧；`n2 == 2`（接收中）只 `delay(10000)`。模拟器在接收/待跳转期间照样每 0.5 s 灌一帧，和 `0x051A` 应答交错，放大 P1-6 的整帧丢弃概率，也让日志噪声变大。
**修法**：`if self.bl_state == 0 and now >= self.bl_info_due:`。

### P2-5　`0x0516` 无条件写 104 B + 152 B 补零，`k5tool` 又永远传空参数 ⇒ 抹掉真机参数页
**文件**：`radio_device.py:472-479`（`data = bytes(body[:0x68]).ljust(256, b"\x00")`）、`k5tool.py:275-278`（`pblk = (param or b"").ljust(0x68, b"\x00")`）
**现象**：真机 `sub_8000268` 是把收到的 0x68 字节拷进缓冲后写 256 B，后 152 B 是**缓冲里原有的内容**（不会归零）；而工具侧 `param=None` 时发的是 104 个 0x00。真机上那块是设备参数区（对应 flash 0x08002700），会被整页擦掉再写零 ⇒ **不可逆**。
**实测**：设备 0x0F00 处 `ff...` → 收到 104 个 0 的参数块后变 `00...`。
**修法**：工具端在 `param is None` 时**跳过 0x0516**（或要求显式 `--param`）；设备端保留原页剩余内容：
```python
cur = self.flash.read(SPACE_PARAM_OFF, 256)
data = bytes(body[:0x68]).ljust(256, b"\xff")   # 或 cur[0x68:] 保留旧值
```

### P2-6　`program()` 失败/越界时 `0x0519` 仍回 status=0（无 idx 上界校验）
**文件**：`radio_device.py:512`（忽略返回值）、`:504-521`（idx 无上界）
**现象**：`idx` 是 u16，`SPACE_IMG_OFF + idx*256` 可以远超 472 页（120832 B）甚至超出 4 MB；`program()` 返回 False 后既不回复错误也不改状态，客户端以为成功。真机写的是固定 472 页区域，越界会直接踩到别的 flash。
**实测**：`Flash4M(size=0x800)` 上写 0x1100 → `program()` 返回 `False`，但 `0x0519` 应答 `status=0`。
**修法**：
```python
if idx >= APP_AREA_PAGES:
    self._reply(0x051A, cookie + struct.pack("<HBB", idx, 2, 0), inner_size=8); return
ok = self.flash.program(SPACE_IMG_OFF + idx * 256, data)
...
self._reply(0x051A, cookie + struct.pack("<HBB", idx, 0 if ok else 2, 0), inner_size=8)
```

### P2-7　`go_app()` 清空 `tx`，正在排队的应答/banner 被丢掉
**文件**：`radio_device.py:328`
**现象**：`go_app()` 里 `self.tx.clear()`，而 `go_app()` 会被 `tick()`（窗口到期）、`_try_boot`（FLSH 不匹配）等路径调用。如果此刻 `tx` 里还有没被 `poll()` 取走的 `0x0518`/`0x051A`，直接蒸发。
**实测**：`bl_state=1` + deadline 过期 + `tx` 里放 `PENDING-FRAME` → `tick()` 后 `boot_mode=False` 且 `tx=b''`。
**修法**：删掉 `go_app()` 里的 `tx.clear()`（`power_cycle`/`reset` 里已有显式清空），或改成“只清 banner 标志”。

### P2-8　`k5tool` 的 u8 字段没做范围校验：文档示例 `read 0x0000 256` 直接崩
**文件**：`k5tool.py:134`、`:141`（`struct.pack("<HBB I", ...)`）
**现象**：偏移/长度用 `<HBB` 打包，长度 > 255 直接 `struct.error`；`write-channels` 传大文件同理。崩的是未捕获异常（traceback），而不是给用户提示。
**实测**：`read_eeprom(0, 256)` 与 `write_eeprom(0, b"x"*300)` 均抛 `struct.error: ubyte format requires 0 <= number <= 255`；而 `k5tool.py:10` 的用法示例正是 `read 0x0000 256`。
**修法**：在 `read/write_eeprom` 里按 128 B 分片（真机 `REPLY_051B_t.Data[128]`），并对 >255 抛 `ValueError("单次最多 128 字节")`；示例改成可用的长度。

### P2-9　`recv_frame` 按 2 字节找同步头 + `boot_enter` 的 4 字节裸读 ⇒ 一处错位永久失步
**文件**：`k5tool.py:108-111`、`:179`
**现象**：`while True: b=_recv_exact(2); if b==SYNC` —— 若 `AB` 落在奇数偏移（`boot_enter` 的 `_recv_exact(4)` 造成的偏移正是奇数/偶数皆可），`AB CD` 会被两个字组合并吞掉，后续按偶数步长再也遇不到 `SYNC`，直到超时。
**修法**：字节级扫描 + 缓冲（同 P1-6），并且在 `boot_enter` 里改用 `recv_frame()` 判类型，而不是裸读 4 字节。

### P2-10　`k5tool` 不校验应答命令字（`recv_frame`/`cmd`/`handshake`/`read_eeprom`）
**文件**：`k5tool.py:120-123`、`:126-131`、`:133-138`
**现象**：`read_eeprom` 直接 `return r[8:8+sz]`，`sz` 来自帧内任意字节。收到一个 `0x0518` 信息帧时会把它当 EEPROM 内容返回；`handshake` 收到 `0x0528` 也当握手成功（`main()` 里只打印）。
**实测**：伪造一条 `0x0518` 帧喂 `read_eeprom(0,16)` → 返回 24 字节 `3333...`（把 0x33 当 `sz`）；伪造 `0x0528` 帧 → `handshake()` 返回 `(1320, '4\x12\x10')`。
**修法**：`cmd()` 里断言 `struct.unpack_from("<H", r, 0)[0] == cid + 1`；`read_eeprom` 校验 `cid == 0x051C and sz <= 128 and len(r) >= 8 + sz`。

### P2-11　`ComBridge` 写异常时整段丢弃、且不清输出缓冲（对端收到半帧 + 粘连）
**文件**：`radio_device.py:745`（`write_timeout=1`）、`:757-765`（`except Exception: pass`）
**现象**：`ser.write(out)` 抛 `SerialTimeoutException` 时 `out` 可能已经部分写出；这里直接 `pass`，既不 `reset_output_buffer()` 也不重建，残留数据会和下一帧粘连；而设备侧已经认为“应答已发出”，不会重发。
**修法**：
```python
except Exception:
    try:
        self.ser.reset_output_buffer()
    except Exception:
        pass
    self.log("[COM] 写超时, 丢弃 %d 字节并清空输出缓冲" % len(out))
```

### P2-12　`enter_boot_window` 不清会话状态；三个 `bl_*` 字段是死代码
**文件**：`radio_device.py:268-276`、`:248-250`
**现象**：只重置 `boot_mode`/`deadline`/`bl_unlocked`，`bl_state`（可能是 2=待跳转）、`bl_cookie`、`bl_next_idx`、`bl_total` 全部带进新会话；`bl_total_blocks`/`bl_last_idx`/`bl_crc` 定义了但从未使用（`bl_total` 是动态加的，才真正生效）。
**实测**：`enter_boot_window(3.0)` 之后 `bl_state=2`、`bl_cookie=01020304` 原样保留。
**修法**：进入时统一 `self.bl_state = 0; self.bl_cookie = b""; self.bl_next_idx = 0; self.bl_total = 0; self.bl_finish_at = 0.0`，并删掉三个死字段。

### P2-13　`Flash4M.save()` 的固定 `.tmp` 名 + 兜底原地覆盖；`wlock` 不保护 `data` 的写入
**文件**：`radio_device.py:141-166`（`:147` 固定 tmp、`:155-163` 原地覆盖）、`:202-222`（`program` 不持 `wlock`）
**现象**：`wlock` 只把 `save()` 之间串行化；`program()`/`erase()` 改 `self.data` 时**不持锁**（`mcu_vm` 线程也会调 `space.program`/`space.flush`）。`save()` 在锁内 `bytes(self.data)`，可能拿到“半页写入”的快照并落盘；固定 `.tmp` 名让两个 `Flash4M` 实例（例如桥和 mcu_vm 各建一个同路径实例）互相截断。兜底的原地覆盖一旦中途失败，文件就成残帧。
**修法**：`program/erase/erase_pages/read` 全部 `with self.wlock:`；tmp 名带 pid/线程号或改用 `tempfile.mkstemp(dir=...)`；删掉原地覆盖兜底（宁可报错让上层重试，也不要写半截）。

### P2-14　boot 模式下把非 `0xAB` 输入按字节静默吞掉；app 模式下 boot 帧也静默吞掉
**文件**：`radio_device.py:394-396`、`:658`（`未知命令`）
**现象**：`legacy_proto` 关闭时 `_try_boot` 对任何非 `AB` 起始的字节 `del buf[:1]; return True`，一个字节一个字节地吃——包括完整的应用帧、`FLSH`、误发的 0x05DD；应用模式下收到 `0x0516/0x0519/0x0530` 也只在 `_handle_app` 里打 `未知命令`，客户端只能等超时（P0-1 的失败就是这样被“隐形”的）。
**实测**：app 模式下发一条合法 `0x0519` 帧 → 无任何应答、无错误帧。
**修法**：boot 模式遇到非 `AB` 时，先尝试 `find(SYNC)` 一次性跳过整段垃圾再返回；app 模式识别到 `0x0516/0x0519/0x0530` 时回一个错误帧或至少 `self.log("[APP] 收到 boot 命令 %04X, 当前不在刷机模式" % cmd)`，让故障可见。

---

## P3（文档/一致性/小边界）

1. **文件头协议说明与实现不符**：`radio_device.py:24-29`。请求无 pad、应答无 CRC、pad 有公式——都应改成第 0 节那张表；否则后来者会按注释“修正”出 size+10 的帧。`:27` 的 “`前 size(+2, 仅请求)`” 是全文件唯一正确的描述，建议提到前面当主说明。
2. **注释串行**：`radio_device.py:74` —— `APP_AREA_PAGES = 472  # 真机 sub_800059C(0x08002800, 472)   # 空间里 bootloader 参数块 (对应 flash 0x08002700)`，后半句是 `SPACE_PARAM_OFF` 的注释被粘过来了。
3. **注释与代码相反**：`radio_device.py:304` 写“版本(16B) + UID(16B)”，代码 `:305` 是 UID 在前、版本在后（代码才对，与 `sub_80003DC` 一致）。
4. **`0x0518` 的版本字节**：真机是横幅字符串前 16 字节（`"7.02.02\0\0\0\xC4 \r\n"` + 2 字节 .rodata 尾巴，`sub_80003DC` 的 `memcpy(..., 0x10)`），模拟器是 `b"7.02.02".ljust(16, b"\0")`。工具 `split(b"\0")[0]` 拿到的一样，但严格比对会不同。
5. **`--ptt` 时横幅发两次**：`radio_device.py:795-798`，`VirtualRadio(start_in_boot=True)` 内部已 `hold_boot()` 发一次，`main()` 又 `radio.hold_boot(ptt=True)` 再发一次（实测 tx 里 `7.02.02` 出现 2 次、28 字节），且第二次把 `bl_info_due` 重置。
6. **boot 窗口日志重复**：`radio_device.py:273-276`，`if not already:` 内打印一次、外又无条件打印一次；`already=True` 时只剩一条，`already=False` 时打两条（当前构造路径恰好走不到，但 `reset()` 会）。
7. **`Flash4M.read` 尾部短读**：`radio_device.py:168-173`，`read(0xFF8, 16)` 只返回 8 字节且不补 0xFF；`0x051B` 应答头写的是请求长度而不是实际长度，客户端 `r[8:8+sz]` 会短读。建议 `data = self.data[addr:addr+n]; return bytes(data) + b"\xFF" * (n - len(data))`。
8. **`erase_pages` 跨尾截断但计数照加**：`radio_device.py:188-200`，`erase_pages(0xFF0, 4)` 只擦了 16 字节却 `stat_erases += 4`（实测）；`erase()` 用 4 KB 扇区粒度、`erase_pages` 用 256 B，两者混用会让 `stat_erases` 语义混乱（真机只有 256 B 页擦）。
9. **`0x051D` 缺真机语义**：`radio_device.py:632-643`，未实现 8 字节对齐（`uv-k5 uart.c:289` 只写 `Size/8*8`）、`0x0E98–0x0E9F` 的锁定屏保护与 `bAllowPassword`（`:298`）、以及写 `0x0F30–0x0F40` 后的 `BOARD_EEPROM_Init()` 重载（`:303`）。后者在真机上会导致“写完不生效”。
10. **`0x052D` 的锁定状态永远是 0**：`radio_device.py:651-653`，`self.locked` 除 `reset()` 外从不赋值（`:335`），AES challenge 流程（`uv-k5 uart.c:335-369`）完全没建模；应答体 2 字节（真机 4 字节）。
11. **`0x051B` 读不限制在 EEPROM_SIZE 内**：`radio_device.py:622-630`，`off` 是 u16（≤0xFFFF），会读到固件区；写侧有 `off + len <= EEPROM_SIZE` 检查，读侧没有，不对称。
12. **空镜像不报错**：`k5tool.py:272`，`len(data)==0` ⇒ `total=0`，不发送任何块就返回 0，设备停在会话中；建议 `if not data: raise ValueError`。
13. **`main()` 的早退分支不 `close()`**：`k5tool.py:444/453/459/468/477`（`return` 早于 `:484` 的 `cli.close()`），socket 泄漏到进程退出；建议 `try/finally`。
14. **`SerialBridge.stop()` 边遍历边删**：`radio_device.py:721-731`，`for c in self.clients:` 与工作线程的 `remove` 竞争，关机时可能 `ValueError`；`accept()` 的 `except OSError: break`（`:694-695`）会因任意一次 OSError 直接停掉整条桥。
15. **`selftest` 绕过协议直接看内部**：`k5tool.py:392-404` 用 `radio.flash.read(...)` 校验而不是回读协议，且没 `join` 桥线程就 `getsize`，目录里能看到残留的 `flash_selftest.bin`（以及观察到过的 0 字节 `flash_selftest.bin.tmp`，正是 P2-13 的痕迹）；建议改成走 `boot_wait_info`+回读校验，并在 `finally` 里关桥。
16. **`uv-k5` 的 `bIsEncrypted` 语义未建模**：`ref/uv-k5-firmware/app/uart.c:469-480`，收到 `0x0514` 后关闭混淆、收到 `0x6902` 再打开，且关闭时 pad 变成 `FF FF`。若目标是和真机/原厂 CPS 互通，这一条必须实现（模拟器和 `k5tool` 现在都“永远混淆”，两边自洽、和真机不兼容）。

---

## 最该先修的 5 条

| # | 条目 | 位置 | 为什么先修 | 最小修复 |
|---|---|---|---|---|
| 1 | **P0-1 刷机窗口中途到期** | `radio_device.py:271,343-364,481-521` | 主线功能直接失败，且失败点已经擦掉 472 页 ⇒ 半砖（实测块 1/3 后 `RuntimeError`，应用区只剩块 0） | 解析到有效帧后 `boot_deadline = inf`；`bl_state != 0` 时不 `go_app()` |
| 2 | **P0-2 `ensure_bootloader` 回退顺序 + `boot_enter` 吞字节** | `k5tool.py:153-165,174-185` | 设备在应用模式时 `k5tool flash` 100% 失败（实测 3.07 s 返回 False，而设备其实已进 BL） | `0x05DD` 之后先 `boot_wait_info(3.0)` 再考虑 `FLSH` |
| 3 | **P0-3 写频不擦除 ⇒ 二次写静默损坏** | `radio_device.py:632-643` | 写频是应用模式唯一的核心功能；实测 `A0A1A2A3`+`0F0E0F0E` → `00000202`，工具还报成功 | EEPROM 区改覆盖语义（或写前擦页），只在真正写入后回 `0x051E` |
| 4 | **P1-1 错序块仍然写 flash** | `radio_device.py:504-511` | 与真机相反，会把乱序/串会话数据写进已擦区，配合 #1 放大损坏 | 删掉第 506 行那次 `program` |
| 5 | **P1-4 `generation` 粒度过细 ⇒ 写频即触发 MCU 重载** | `radio_device.py:183/197/214`（消费方 `mcu_vm.py:601-605`） | 一次 EEPROM 写就让仿真的整机复位，写频流程无法连续操作（实测单次 0x051D 即 +1） | 区分 `generation` / `fw_generation`，只有固件区擦写才触发重载 |

紧随其后（修完上面 5 条就应该接着做）：**P1-2 每块整盘 4 MB 落盘**（实测 472 块 ≈ 2 GB，且持锁拖慢应答）→ **P1-6 `_wait_cmd` 无收包缓冲**（200 ms 抖动即丢整帧）→ **P1-7 不校验 0x051A 的 cookie**（真机上会把“会话已作废”当成功）→ **P2-1 应答 pad 常量**（唯一一条“照规范实现才能和真机互通”的低成本修复）。
