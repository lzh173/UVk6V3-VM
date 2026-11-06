import mcu_vm, struct
vm = mcu_vm.VM(mcu_vm.default_firmware())
def r(a): return struct.unpack("<I", vm.uc.mem_read(a,4))[0]
def tap(kc, hold=8, gap=6):
    vm.press(kc)
    for _ in range(hold): vm.step(4000)
    vm.release(kc)
    for _ in range(gap): vm.step(4000)
vm.run(max_ticks=700)
vm.render_png("shot1_pin_gate.png")
tap(10)
for d in (4,6,1,6,1,2,1,4): tap(d)
vm.render_png("shot2_pin_entry.png")
tap(10, hold=10, gap=10)
for _ in range(120): vm.step(4000)
vm.render_png("shot3_authorized.png")
print("state: pin=%d marker=%08X" % (r(0x2000003C), r(0x20000038)))
# 试着进菜单
for _ in range(4):
    tap(10, hold=8, gap=10)
for _ in range(80): vm.step(4000)
vm.render_png("shot4_after_menu.png")
print("ui 12E=%02X 12F=%02X" % (vm.uc.mem_read(0x2000012e,1)[0], vm.uc.mem_read(0x2000012f,1)[0]))
for ln in vm.render_text()[:24]: print(ln)
