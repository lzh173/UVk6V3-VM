# -*- coding: utf-8 -*-
"""统一打包脚本（PyInstaller / Nuitka）

用法:
    python tools/build.py                       # 默认 pyinstaller + 全部工具
    python tools/build.py --backend nuitka      # 用 Nuitka
    python tools/build.py --tool romdumper      # 只打一个
    python tools/build.py --list                # 看有哪些工具

产物都在 dist/ 下。
"""
import argparse
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist")   # 实际输出在 dist/<backend>/，两种打包互不覆盖
BUILD = os.path.join(ROOT, "build")

# 每个工具的打包参数
TOOLS = {
    "romdumper": dict(
        script="rom_dumper_gui.py", name="RomDumper", windowed=True,
        hidden=["serial.tools.list_ports"],
        desc="整片 SPI Flash 导出工具（GUI）",
    ),
    "k5tool": dict(
        script="k5tool.py", name="K5Tool", windowed=False,
        hidden=[],
        desc="PC 侧客户端（握手/读写/刷机/自检）",
    ),
    "mcuvm": dict(
        script="mcu_vm.py", name="MCUVM", windowed=False,   # 保留控制台: --text/--help/日志要能看到
        hidden=["serial.tools.list_ports"],
        # 只收动态库（unicorn/capstone 的 .dll）；--collect-all 会把
        # 48 MB 的 unicorn.lib 静态库卷进来，onefile 解压直接失败
        binaries=["unicorn", "capstone"],
        # unicorn 在运行时才 import 架构模块（unicorn.unicorn_py3.arch.*），
        # 必须显式收集子模块，否则报 ModuleNotFoundError
        submodules=["unicorn", "capstone"],
        # Nuitka 的 --include-package 只带 Python 代码，不带 DLL，
        # 必须显式声明；(包名, 子路径) 会在运行时展开成真实路径
        native=[("unicorn", "lib/unicorn.dll"), ("capstone", "lib/capstone.dll")],
        excludes=["IPython", "pytest", "matplotlib", "numpy", "PIL.ImageQt"],
        desc="固件虚拟机（面板 / 终端 / PNG）",
    ),
}


def run(cmd):
    print("  $", " ".join(cmd))
    r = subprocess.run(cmd, cwd=ROOT)
    if r.returncode != 0:
        raise SystemExit("打包失败: %s" % cmd[0])


def native_paths(tool):
    """把 native=[(包名, 子路径)] 展开成 [(绝对路径, 包内目标路径)]"""
    import importlib
    out = []
    for pkg, rel in TOOLS[tool].get("native", []):
        try:
            mod = importlib.import_module(pkg)
        except ImportError:
            continue
        src = os.path.join(os.path.dirname(mod.__file__), *rel.split("/"))
        if os.path.isfile(src):
            out.append((src, pkg + "/" + rel))
        else:
            print("  [!] 找不到原生库:", src)
    return out


def out_dir(backend):
    d = os.path.join(DIST, backend)
    os.makedirs(d, exist_ok=True)
    return d


def build_pyinstaller(tool):
    cfg = TOOLS[tool]
    args = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
            "-F", "-n", cfg["name"],
            "--distpath", out_dir("pyinstaller"),
            "--workpath", os.path.join(BUILD, "pyinstaller"),
            "--specpath", os.path.join(BUILD, "pyinstaller")]
    if cfg["windowed"]:
        args.append("-w")
    for h in cfg.get("hidden", []):
        args += ["--hidden-import", h]
    for p in cfg.get("binaries", []):
        args += ["--collect-binaries", p]
    for p in cfg.get("submodules", []):
        args += ["--collect-submodules", p]
    for m in cfg.get("excludes", []):
        args += ["--exclude-module", m]
    args.append(os.path.join(ROOT, cfg["script"]))
    run(args)


def build_nuitka(tool):
    cfg = TOOLS[tool]
    exe = cfg["name"] + (".exe" if os.name == "nt" else "")
    args = [sys.executable, "-m", "nuitka", "--onefile",
            "--assume-yes-for-downloads",
            "--remove-output",              # 清掉 .build/.dist/.onefile-build
            "--output-dir=" + out_dir("nuitka"),
            "--output-filename=" + exe,
            "--enable-plugin=tk-inter",
            "--windows-console-mode=" + ("disable" if cfg["windowed"] else "force"),
            "--company-name=firmware_analysis",
            "--product-name=" + cfg["name"],
            "--file-version=0.1.0", "--product-version=0.1.0"]
    for p in cfg.get("binaries", []):
        # Nuitka 自己会跟着 import 收动态库，这里只显式带上包
        args.append("--include-package=" + p)
    for h in cfg.get("hidden", []):
        args.append("--include-module=" + h)
    for src, dst in native_paths(tool):
        args.append("--include-data-file=%s=%s" % (src, dst))
    args.append(os.path.join(ROOT, cfg["script"]))
    run(args)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", choices=["pyinstaller", "nuitka"], default="pyinstaller")
    ap.add_argument("--tool", default="all", help="romdumper / k5tool / mcuvm / all")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--clean", action="store_true", help="只清理 build/dist")
    args = ap.parse_args()

    if args.list:
        for k, v in TOOLS.items():
            print("  %-10s %s" % (k, v["desc"]))
        return

    if args.clean:
        for d in (BUILD, DIST):
            shutil.rmtree(d, ignore_errors=True)
            print("已删除", d)
        return

    tools = list(TOOLS) if args.tool == "all" else [args.tool]
    if any(t not in TOOLS for t in tools):
        raise SystemExit("未知工具: %s（可选 %s）" % (args.tool, ", ".join(TOOLS)))

    os.makedirs(DIST, exist_ok=True)
    for t in tools:
        print("\n=== 打包 %s (%s) ===" % (TOOLS[t]["name"], args.backend))
        (build_pyinstaller if args.backend == "pyinstaller" else build_nuitka)(t)

    print("\n产物:")
    for be in ("pyinstaller", "nuitka"):
        d = os.path.join(DIST, be)
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            p = os.path.join(d, f)
            if os.path.isfile(p):
                print("  %-12s %-22s %8.1f MB" % (be, f, os.path.getsize(p) / 1048576))


if __name__ == "__main__":
    main()
