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
set "LOG_FILE=%RELEASE_DIR%package.log"

:: ==========================================
:: Run all packaging steps, tee output to package.log
:: so errors are visible even if the window closes
:: ==========================================
call :main > "%LOG_FILE%" 2>&1
set "RC=%ERRORLEVEL%"

if not "%RC%"=="0" (
    echo.
    echo ============================================
    echo    Package FAILED!  (code %RC%)
    echo    Full log saved to: %LOG_FILE%
    echo ============================================
    echo.
    type "%LOG_FILE%"
) else (
    echo.
    echo ============================================
    echo    Package complete!
    echo ============================================
    echo.
    echo Output: %RELEASE_DIR%KirinDesk.exe
    echo Size: %PKG_SIZE% bytes
    echo.
    echo To deploy: double-click install.bat
)

echo.
pause
exit /b %RC%

:main
:: ==========================================
:: Limit Cargo parallel build jobs to 8
:: ==========================================
set "CARGO_BUILD_JOBS=8"

echo [1/3] Building release binary...
where cargo >nul 2>&1
if errorlevel 1 (
    echo ERROR: cargo not found in PATH. Install Rust from https://rustup.rs
    exit /b 1
)
cd /d "%PROJ_DIR%"
if errorlevel 1 (
    echo ERROR: Cannot find project directory: %PROJ_DIR%
    exit /b 1
)

set "CARGO_TARGET_DIR=%TARGET_DIR%"
cargo build --release -p kirin-desk-ui
if errorlevel 1 (
    echo ERROR: Build failed!
    exit /b 1
)
echo Build OK.

echo.
echo [2/3] Copying binary to release...
copy /Y "%TARGET_DIR%\release\kirin-desk-ui.exe" "%RELEASE_DIR%KirinDesk.exe" >nul
if errorlevel 1 (
    echo ERROR: Copy failed!
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

set "PKG_SIZE="
for %%I in ("%RELEASE_DIR%KirinDesk.exe") do set "PKG_SIZE=%%~zI"
exit /b 0
