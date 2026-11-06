@echo off
chcp 65001 >nul
rem ============================================================
rem  一键打包：rom_dumper_gui.py -> dist\RomDumper.exe（单文件、无控制台）
rem  需要：pip install pyserial pyinstaller
rem ============================================================
setlocal
cd /d "%~dp0"

echo [1/3] 检查依赖...
python -c "import serial, tkinter" 2>nul
if errorlevel 1 (
    echo     缺少 pyserial 或 tkinter，正在安装 pyserial...
    python -m pip install --upgrade pyserial || goto :fail
)
python -m PyInstaller --version >nul 2>nul
if errorlevel 1 (
    echo     缺少 PyInstaller，正在安装...
    python -m pip install --upgrade pyinstaller || goto :fail
)

echo [2/3] 清理旧产物...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist RomDumper.spec del /q RomDumper.spec

echo [3/3] 打包（约 1~2 分钟）...
python -m PyInstaller -F -w -n RomDumper ^
    --hidden-import serial.tools.list_ports ^
    --clean --noconfirm ^
    rom_dumper_gui.py || goto :fail

echo.
echo ============================================================
echo  完成： dist\RomDumper.exe
echo  直接双击即可使用；也可命令行调用：
echo    RomDumper.exe --port COM15 --out rom.bin --size 4M
echo    RomDumper.exe --selftest
echo ============================================================
pause
exit /b 0

:fail
echo.
echo [失败] 打包没成功，看上面的报错。
pause
exit /b 1
