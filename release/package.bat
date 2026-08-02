@echo off
chcp 65001 >nul
title KirinDesk Package

echo ============================================
echo    KirinDesk v0.1.0 - One-Click Package
echo ============================================
echo.

setlocal

set "PROJ_DIR=%~dp0.."
set "TARGET_DIR=%TEMP%\kirin-target"
set "RELEASE_DIR=%~dp0"

echo [1/3] Building release binary...
cd /d "%PROJ_DIR%"
if errorlevel 1 (
    echo ERROR: Cannot find project directory: %PROJ_DIR%
    pause
    exit /b 1
)

set "CARGO_TARGET_DIR=%TARGET_DIR%"
cargo build --release -p kirin-desk-ui
if errorlevel 1 (
    echo ERROR: Build failed!
    pause
    exit /b 1
)
echo Build OK.

echo.
echo [2/3] Copying binary to release...
copy /Y "%TARGET_DIR%\release\kirin-desk-ui.exe" "%RELEASE_DIR%KirinDesk.exe" >nul
if errorlevel 1 (
    echo ERROR: Copy failed!
    pause
    exit /b 1
)

echo.
echo [3/3] Copying runtime dependencies...
:: FFmpeg DLLs
if exist "%RELEASE_DIR%ffmpeg" (
    echo    ffmpeg/ already exists, skipping
) else (
    xcopy /E /I /Y "%PROJ_DIR%\ffmpeg\ffmpeg-8.1.2-full_build-shared" "%RELEASE_DIR%ffmpeg" >nul
    echo    Copied ffmpeg DLLs
)
:: Config
if not exist "%RELEASE_DIR%default.toml" (
    if exist "%PROJ_DIR%\config\default.toml" (
        copy /Y "%PROJ_DIR%\config\default.toml" "%RELEASE_DIR%default.toml" >nul
        echo    Copied default.toml
    )
)

echo.
echo ============================================
echo    Package complete!
echo ============================================
echo.
echo Output: %RELEASE_DIR%KirinDesk.exe
for %%I in ("%RELEASE_DIR%KirinDesk.exe") do echo Size: %%~zI bytes

echo.
echo Release contents:
dir /B "%RELEASE_DIR%"

echo.
echo To deploy: double-click install.bat
echo.
pause
