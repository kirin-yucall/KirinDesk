@echo off
rem KirinDesk Installer — M14-T002
rem 安装目录布局（与 M1-T002 目录策略一致）：
rem   程序:   %USERPROFILE%\.kirin_desk\bin\KirinDesk.exe
rem   FFmpeg: %USERPROFILE%\.kirin_desk\ffmpeg\bin\*.dll  （dlls.rs 搜索路径 {exe_dir}/../ffmpeg/bin）
rem   配置:   %APPDATA%\kirin_desk\default.toml
rem   身份:   %USERPROFILE%\.kirin_desk\identity\
rem   日志:   %USERPROFILE%\.kirin_desk\logs\
chcp 65001 >nul
title KirinDesk Installer

echo ============================================
echo    KirinDesk v0.1.0
echo    P2P Remote Desktop - IPv6 + Zero Trust
echo ============================================
echo.

set "HOME_DIR=%USERPROFILE%\.kirin_desk"
set "BIN_DIR=%HOME_DIR%\bin"
set "FFMPEG_DIR=%HOME_DIR%\ffmpeg\bin"
set "CFG_DIR=%APPDATA%\kirin_desk"

echo [1/5] Creating directories...
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"
if not exist "%FFMPEG_DIR%" mkdir "%FFMPEG_DIR%"
if not exist "%HOME_DIR%\identity" mkdir "%HOME_DIR%\identity"
if not exist "%HOME_DIR%\logs" mkdir "%HOME_DIR%\logs"
if not exist "%CFG_DIR%" mkdir "%CFG_DIR%"

echo [2/5] Copying program...
copy /Y "%~dp0KirinDesk.exe" "%BIN_DIR%\KirinDesk.exe" >nul
if errorlevel 1 (
    echo ERROR: 未找到 %~dp0KirinDesk.exe（请先运行 package.bat 打包）
    pause
    exit /b 1
)

echo [3/5] Copying FFmpeg DLLs...
copy /Y "%~dp0ffmpeg\bin\*.dll" "%FFMPEG_DIR%\" >nul 2>&1
if not exist "%HOME_DIR%\ffmpeg\LICENSE" copy /Y "%~dp0ffmpeg\LICENSE" "%HOME_DIR%\ffmpeg\LICENSE" >nul 2>&1

echo [4/5] Copying config (keep existing)...
if not exist "%CFG_DIR%\default.toml" (
    if exist "%~dp0default.toml" copy /Y "%~dp0default.toml" "%CFG_DIR%\default.toml" >nul
)

echo [5/5] Creating shortcuts...
PowerShell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$d=[Environment]::GetFolderPath('Desktop');" ^
  "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($d+'\KirinDesk.lnk');" ^
  "$s.TargetPath='%BIN_DIR%\KirinDesk.exe';" ^
  "$s.WorkingDirectory='%BIN_DIR%';" ^
  "$s.Save()" >nul 2>&1
PowerShell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$m=[Environment]::GetFolderPath('Programs')+'\KirinDesk';" ^
  "if(!(Test-Path $m)){New-Item -ItemType Directory $m | Out-Null};" ^
  "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($m+'\KirinDesk.lnk');" ^
  "$s.TargetPath='%BIN_DIR%\KirinDesk.exe';" ^
  "$s.WorkingDirectory='%BIN_DIR%';" ^
  "$s.Save()" >nul 2>&1

echo.
echo Done! KirinDesk installed.
echo.
echo Launch: 桌面/开始菜单快捷方式，或运行 %BIN_DIR%\KirinDesk.exe
echo Config: %CFG_DIR%\default.toml
echo Logs:   %HOME_DIR%\logs
echo.
echo 卸载：删除 %HOME_DIR% 与 %CFG_DIR% 目录即可（本脚本不写入注册表）。
echo.
pause
