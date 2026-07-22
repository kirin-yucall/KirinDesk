@echo off
chcp 65001 >nul
title KirinDesk Installer

echo ============================================
echo    KirinDesk v0.1.0
echo    P2P Remote Desktop - IPv6 + Zero Trust
echo ============================================
echo.

set "INSTALL_DIR=%USERPROFILE%\.kirin_desk"
set "BIN_DIR=%INSTALL_DIR%\bin"

echo [1/3] Creating directories...
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

echo [2/3] Copying files...
copy /Y "%~dp0KirinDesk.exe" "%BIN_DIR%\KirinDesk.exe" >nul
copy /Y "%~dp0default.toml" "%INSTALL_DIR%\default.toml" >nul

echo [3/3] Creating shortcut...
set "DESKTOP=%USERPROFILE%\Desktop"
set "STARTMENU=%APPDATA%\Microsoft\Windows\Start Menu\Programs\KirinDesk"
if not exist "%STARTMENU%" mkdir "%STARTMENU%"
copy /Y "%~dp0KirinDesk.lnk" "%STARTMENU%\KirinDesk.lnk" >nul 2>&1

echo.
echo Done! KirinDesk installed.
echo.
echo Launch from Start Menu or run: KirinDesk
echo Config: %INSTALL_DIR%\default.toml
echo.
pause
