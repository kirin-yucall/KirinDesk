@echo off
rem KirinDesk Installer �� 
rem ��װĿ¼���֣��� Ŀ¼����һ�£���
rem   ����:   %USERPROFILE%\.kirin_desk\bin\KirinDesk.exe
rem   FFmpeg: %USERPROFILE%\.kirin_desk\ffmpeg\bin\*.dll  ��dlls.rs ����·�� {exe_dir}/../ffmpeg/bin��
rem   ����:   %APPDATA%\kirin_desk\default.toml
rem   ���:   %USERPROFILE%\.kirin_desk\identity\
rem   ��־:   %USERPROFILE%\.kirin_desk\logs\
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
    echo ERROR: δ�ҵ� %~dp0KirinDesk.exe���������� package.bat �����
    pause
    exit /b 1
)

echo [3/5] Copying FFmpeg DLLs...
rem ��ʽȷ�Ϻ���� download-ffmpeg.bat �Զ����أ����Զ����������ߣ��û���������
set "FFMPEG_OK=1"
    if not exist "%~dp0ffmpeg\bin\%%D" set "FFMPEG_OK=0"
)
if not "%FFMPEG_OK%"=="1" (
    echo.
    echo WARNING: δ��⵽ FFmpeg ���п⣨ffmpeg\bin �� 7 �� DLL ���룩��
    echo          Զ������Ƶ����뽫�����á�
    echo          �Ƿ������������أ���������ʽȷ�ϣ����ű������Զ�������
    echo          ���п���Դ��BtbN GitHub �ٷ� release��sha256 У�顣
    choice /C YN /N /M "  [Y] �������п�  [N] �������Ժ����� release\download-ffmpeg.bat : "
    if errorlevel 2 (
        echo [SKIP] �������أ�����뽫�����á�
    ) else (
        call "%~dp0download-ffmpeg.bat"
        if errorlevel 1 (
            echo ERROR: FFmpeg ���п�����ʧ�ܡ���������������벻���á�
        )
    )
)
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
echo Launch: ����/��ʼ�˵���ݷ�ʽ�������� %BIN_DIR%\KirinDesk.exe
echo Config: %CFG_DIR%\default.toml
echo Logs:   %HOME_DIR%\logs
echo.
echo ж�أ�ɾ�� %HOME_DIR% �� %CFG_DIR% Ŀ¼���ɣ����ű���д��ע������
echo.
pause
