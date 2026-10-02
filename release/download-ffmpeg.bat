@echo off
rem ============================================================
rem
rem  Downloads the FFmpeg 8.1.x shared build from
rem  BtbN/FFmpeg-Builds (a provider recommended on ffmpeg.org),
rem  extracts the 7 runtime DLLs (avcodec-62 / avdevice-62 /
rem  swscale-9) and installs them to release\ffmpeg\bin\.
rem
rem  Sources (reachability verified 2026-08-18):
rem    primary : BtbN GitHub release
rem              ffmpeg-n8.1-latest-win64-gpl-shared-8.1.zip
rem              (FFmpeg 8.1.x -> avcodec-62, matches KirinDesk's
rem              offset snapshot major=62)
rem    fallback: gyan.dev official ffmpeg-release-full-shared.7z
rem              (only the latest is kept; if it is a newer major
rem              such as avcodec-63, the script FAILS with a clear
rem              message instead of silently installing
rem              incompatible DLLs)
rem    NOTE    : the TUNA (Tsinghua) mirror currently hosts NO
rem              FFmpeg builds (verified 404, 2026-08-18), so it
rem              is not in the source list. Add it later if it
rem              becomes available.
rem
rem  Idempotent: skips when the 7 DLLs already exist and are
rem  non-empty (use --force to re-download).
rem  Verified  : sha256 is checked against BtbN's published
rem              checksums.sha256 (fallback: gyan.dev .sha256
rem              sidecar); when no official checksum can be
rem              fetched, a minimal gate (DLL count + exact file
rem              names + non-zero sizes) is enforced instead.
rem  Red line  : no telemetry; downloads only when the user runs
rem              this script explicitly.
rem
rem  Usage:
rem    download-ffmpeg.bat                    -> install into .\ffmpeg\
rem    download-ffmpeg.bat --target DIR       -> install into DIR\bin
rem    download-ffmpeg.bat --url URL          -> custom direct link
rem                                              (zip; 7z needs 7-Zip)
rem    download-ffmpeg.bat --force            -> re-download even if
rem                                              DLLs already exist
rem
rem  NOTE on encoding: this file is pure ASCII so it parses
rem  correctly under ANY Windows console codepage.
rem ============================================================
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "TARGET=%SCRIPT_DIR%ffmpeg"
set "CUSTOM_URL="
set "FORCE=0"

rem ---- argument parsing -------------------------------------
:parse
if "%~1"=="" goto :parse_done
if /i "%~1"=="--url" (
    set "CUSTOM_URL=%~2"
    if "!CUSTOM_URL!"=="" (
        echo [ERROR] --url needs a URL argument
        exit /b 2
    )
    shift
) else if /i "%~1"=="--target" (
    set "TARGET=%~2"
    if "!TARGET!"=="" (
        echo [ERROR] --target needs a directory argument
        exit /b 2
    )
    shift
) else if /i "%~1"=="--force" (
    set "FORCE=1"
) else (
    echo [ERROR] Unknown argument: %~1
    echo Usage: download-ffmpeg.bat [--url URL] [--target DIR] [--force]
    exit /b 2
)
shift
goto :parse
:parse_done

rem ---- required runtime DLLs (same names as ffmpeg\ffmpeg-8.1.1-full_build-shared\bin) --
set "BIN_DIR=%TARGET%\bin"

rem ---- sources -------------------------------------------------
rem primary: BtbN FFmpeg 8.1 branch latest shared build (win64 gpl shared).
set "PRIMARY_URL=https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-n8.1-latest-win64-gpl-shared-8.1.zip"
rem fallback: gyan.dev official full-shared (.7z, needs 7-Zip; may currently be 9.x).
set "FALLBACK_URL=https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-full-shared.7z"

echo ============================================================
echo ============================================================
echo.
echo Target dir: %TARGET%

if not exist "%TARGET%" mkdir "%TARGET%"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

rem ---- idempotency: complete DLL set already present -> skip --
if "%FORCE%"=="0" (
    set "COMPLETE=1"
    for %%D in (%DLLS%) do (
        if not exist "%BIN_DIR%\%%D" (
            set "COMPLETE=0"
        ) else (
            for %%I in ("%BIN_DIR%\%%D") do if "%%~zI"=="0" set "COMPLETE=0"
        )
    )
    if "!COMPLETE!"=="1" (
        echo [SKIP] %BIN_DIR% already has all 7 runtime DLLs, all non-empty.
        echo        Use --force to re-download.
        exit /b 0
    )
)

rem ---- prerequisite: curl (bundled since Windows 10 1803) ------
where curl >nul 2>&1
if errorlevel 1 (
    echo [ERROR] curl not found. This script needs curl - built into Windows 10 1803+.
    exit /b 1
)

set "WORK=%TEMP%\kirin-ffmpeg-dl"
if exist "%WORK%" rmdir /s /q "%WORK%" 2>nul
mkdir "%WORK%"
if errorlevel 1 (
    echo [ERROR] Cannot create temp dir %WORK%
    exit /b 1
)

rem ---- download + verify + extract (custom URL -> primary -> fallback) --
set "OK=0"
if not "%CUSTOM_URL%"=="" (
    echo.
    echo [1/3] Downloading from custom URL...
    call :try_source "%CUSTOM_URL%"
    if errorlevel 1 (
        echo [ERROR] Custom URL download/verify failed: %CUSTOM_URL%
        exit /b 1
    )
    set "OK=1"
)
if "%OK%"=="0" (
    echo.
    echo [1/3] Primary source - BtbN FFmpeg 8.1 shared build...
    call :try_source "%PRIMARY_URL%"
    if errorlevel 1 (
        echo       Primary failed, trying fallback - gyan.dev...
        call :try_source "%FALLBACK_URL%"
        if errorlevel 1 (
            echo [ERROR] Both primary and fallback failed. Check the network,
            echo        or download manually and place the 7 DLLs into:
            echo        %BIN_DIR%
            exit /b 1
        )
    )
)

rem ---- final gate: DLL count + non-zero sizes -------------------
echo.
echo [3/3] Verifying extracted DLLs...
set /a COUNT=0
set "MISSING="
for %%D in (%DLLS%) do (
    if exist "%BIN_DIR%\%%D" (
        for %%I in ("%BIN_DIR%\%%D") do if not "%%~zI"=="0" set /a COUNT+=1
    ) else (
        set "MISSING=!MISSING! %%D"
    )
)
if not "%COUNT%"=="7" (
    echo [ERROR] Incomplete extraction: only %COUNT%/7 DLLs found.
    if not "%MISSING%"=="" echo         Missing:!MISSING!
    echo        This usually means the downloaded build is FFmpeg 9.x
    echo        avcodec-63 - incompatible with KirinDesk's offset
    echo        snapshot - avcodec major=62. Use the default BtbN
    echo        8.1 source or wait for a compatible build.
    exit /b 1
)

rem ---- cleanup ---------------------------------------------------
if exist "%WORK%" rmdir /s /q "%WORK%" 2>nul

echo.
echo ============================================================
echo    Done! 7 FFmpeg runtime DLLs are ready:
echo    %BIN_DIR%
echo ============================================================
echo.
echo To install system-wide, run install.bat which copies them to
echo   %USERPROFILE%\.kirin_desk\ffmpeg\bin\
echo.
exit /b 0

rem ============================================================
rem  Subroutine: try one source (download -> sha256 verify ->
rem  extract -> copy DLLs). Arg %%1 = URL.
rem  Returns errorlevel 0 on success, 1 on failure.
rem ============================================================
:try_source
setlocal enabledelayedexpansion
set "URL=%~1"
for %%F in ("%URL%") do set "ARCHIVE=%%~nxF"
set "ZIP_PATH=%WORK%\%ARCHIVE%"

echo    Downloading %ARCHIVE% ...
rem ---- download: --ssl-no-revoke is required on the Windows schannel
rem      curl backend (revocation checks fail on some networks / GitHub);
rem      without it the TLS handshake aborts with curl error 35.
curl -fL --ssl-no-revoke --retry 2 --connect-timeout 30 -o "%ZIP_PATH%" "%URL%"
if errorlevel 1 (
    echo    [FAIL] curl download failed: %URL%
    endlocal & exit /b 1
)
for %%I in ("%ZIP_PATH%") do echo    Downloaded %%~zI bytes

rem ---- sha256 verification (best effort) -----------------------
set "EXPECTED="
set "CHECKSUM_OK=0"
if "%URL%"=="%PRIMARY_URL%" (
    echo    Fetching BtbN checksums.sha256 ...
    curl -fL --ssl-no-revoke --connect-timeout 30 -s -o "%WORK%\checksums.sha256" "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/checksums.sha256"
    if not errorlevel 1 (
        for /f "tokens=1" %%H in ('findstr /i "%ARCHIVE%" "%WORK%\checksums.sha256"') do set "EXPECTED=%%H"
    )
) else (
    echo    Fetching official sha256 sidecar ...
    curl -fL --ssl-no-revoke --connect-timeout 30 -s -o "%WORK%\sidecar.sha256" "%URL%.sha256"
    if not errorlevel 1 (
        for /f "tokens=1" %%H in (%WORK%\sidecar.sha256) do set "EXPECTED=%%H"
    )
)
if not "%EXPECTED%"=="" (
    for /f "tokens=1" %%H in ('certutil -hashfile "%ZIP_PATH%" SHA256 ^| findstr /r "^[0-9a-fA-F][0-9a-fA-F]*$"') do set "LOCAL=%%H"
    if /i "!LOCAL!"=="!EXPECTED!" (
        echo    [OK] sha256 matches: !LOCAL!
        set "CHECKSUM_OK=1"
    ) else (
        echo    [FAIL] sha256 mismatch!
        echo      expected: !EXPECTED!
        echo      actual  : !LOCAL!
        echo      The source may have been updated between releases, or
        echo      the download is corrupt. Aborting this source.
        endlocal & exit /b 1
    )
) else (
    echo    [WARN] No official checksum available; using the
    echo          DLL-count/file-name gate instead.
)

rem ---- extract --------------------------------------------------
set "EXT=%ARCHIVE:~-4%"
echo    Extracting %ARCHIVE% ...
if /i "%EXT%"==".zip" (
    tar -xf "%ZIP_PATH%" -C "%WORK%" >nul 2>&1
    if errorlevel 1 (
        echo    tar failed, trying PowerShell Expand-Archive ...
        powershell -NoProfile -Command "Expand-Archive -LiteralPath '%ZIP_PATH%' -DestinationPath '%WORK%\zipout' -Force" >nul 2>&1
        if errorlevel 1 (
            echo    [FAIL] zip extraction failed - tar and PowerShell both failed
            endlocal & exit /b 1
        )
    )
) else if /i "%EXT%"==".7z" (
    set "SEVENZIP="
    where 7z.exe >nul 2>&1 && set "SEVENZIP=7z.exe"
    if "!SEVENZIP!"=="" ( where 7za.exe >nul 2>&1 && set "SEVENZIP=7za.exe" )
    if "!SEVENZIP!"=="" (
        echo    [FAIL] 7-Zip [7z.exe or 7za.exe] is required to extract a
        echo          .7z package but was not found. Install 7-Zip and
        echo          retry, or use --url with a .zip link.
        endlocal & exit /b 1
    )
    "!SEVENZIP!" x -y -o"%WORK%\zipout" "%ZIP_PATH%" >nul 2>&1
    if errorlevel 1 (
        echo    [FAIL] 7-Zip extraction failed: %ARCHIVE%
        endlocal & exit /b 1
    )
) else (
    echo    [FAIL] Unsupported archive type: %EXT% - only .zip / .7z supported
    endlocal & exit /b 1
)

rem ---- copy the 7 DLLs to the target -----------------------------
for %%D in (%DLLS%) do (
    if not exist "%BIN_DIR%\%%D" (
        for /r "%WORK%" %%F in ("%%D") do (
            if not exist "%BIN_DIR%\%%D" copy /Y "%%F" "%BIN_DIR%\%%D" >nul 2>&1
        )
    )
)

rem ---- copy LICENSE (best effort) --------------------------------
if not exist "%TARGET%\LICENSE" (
    for /r "%WORK%" %%F in ("LICENSE.txt") do (
        if not exist "%TARGET%\LICENSE" copy /Y "%%F" "%TARGET%\LICENSE" >nul 2>&1
    )
)
if not exist "%TARGET%\LICENSE" (
    for /r "%WORK%" %%F in ("LICENSE") do (
        if not exist "%TARGET%\LICENSE" copy /Y "%%F" "%TARGET%\LICENSE" >nul 2>&1
    )
)

rem ---- per-source gate: need all 7 DLLs for this source ----------
set /a N=0
for %%D in (%DLLS%) do (
    if exist "%BIN_DIR%\%%D" for %%I in ("%BIN_DIR%\%%D") do if not "%%~zI"=="0" set /a N+=1
)
if not "%N%"=="7" (
    echo    [WARN] This source %ARCHIVE% does not contain all 7 required
    echo          DLLs - found %N%. The build major may not match
    echo          avcodec not 62; the main flow will fall back to
    echo          the next source.
    for %%D in (%DLLS%) do (
        if exist "%BIN_DIR%\%%D" del /q "%BIN_DIR%\%%D" >nul 2>&1
    )
    endlocal & exit /b 1
)
endlocal & exit /b 0
