; KirinDesk Windows Installer — M14-T002
; ----------------------------------------------
; 构建：makensis install.nsi（需 NSIS 3.x，https://nsis.sourceforge.io）
; 输出：KirinDesk-Setup-<VERSION>.exe
; 特点：
;   - 每用户安装（RequestExecutionLevel user，无需管理员权限）
;   - 安装目录：%LOCALAPPDATA%\KirinDesk
;   - 含 FFmpeg DLL（avcodec-62 / avutil-60 / swscale-9 等）
;   - 开始菜单 + 桌面快捷方式，注册表卸载项，卸载器
; 注：安装后应用数据写入 %APPDATA%\kirin_desk（配置）与
;     ~\.kirin_desk（身份/日志/FFmpeg DLL），与 M1-T002 目录策略一致。

Unicode true

!include "MUI2.nsh"
!include "LogicLib.nsh"

!define APP_NAME "KirinDesk"
!define APP_VERSION "0.1.0"
!define APP_PUBLISHER "KirinDesk Team"
!define APP_ID "com.kirindesk.app"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"

Name "${APP_NAME} ${APP_VERSION}"
OutFile "KirinDesk-Setup-${APP_VERSION}.exe"
InstallDir "$LOCALAPPDATA\${APP_NAME}"
InstallDirRegKey HKCU "${UNINST_KEY}" "InstallLocation"
RequestExecutionLevel user
SetCompressor /SOLID lzma

; ---- MUI 页面 ----
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "SimpChinese"
!insertmacro MUI_LANGUAGE "English"

; ---- 安装段 ----
Section "Application" SecMain
  SetOutPath "$INSTDIR"
  File "KirinDesk.exe"
  File "default.toml"
  File "..\LICENSE"

  ; FFmpeg DLL（release/ffmpeg/bin/，dlls.rs 按 {exe_dir}/ffmpeg/bin 搜索）
  SetOutPath "$INSTDIR\ffmpeg\bin"
  File /oname=avcodec-62.dll "ffmpeg\bin\avcodec-62.dll"
  File /oname=avutil-60.dll "ffmpeg\bin\avutil-60.dll"
  File /oname=swscale-9.dll "ffmpeg\bin\swscale-9.dll"
  File /oname=avformat-62.dll "ffmpeg\bin\avformat-62.dll"
  File /oname=avdevice-62.dll "ffmpeg\bin\avdevice-62.dll"
  File /oname=avfilter-11.dll "ffmpeg\bin\avfilter-11.dll"
  File /oname=swresample-6.dll "ffmpeg\bin\swresample-6.dll"
  File /oname=LICENSE "ffmpeg\LICENSE"

  ; 快捷方式
  CreateDirectory "$SMPROGRAMS\${APP_NAME}"
  CreateShortcut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" "$INSTDIR\KirinDesk.exe"
  CreateShortcut "$SMPROGRAMS\${APP_NAME}\卸载 ${APP_NAME}.lnk" "$INSTDIR\uninstall.exe"
  CreateShortcut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\KirinDesk.exe"

  ; 卸载器 + 注册表卸载项
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "${APP_PUBLISHER}"
  WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
SectionEnd

; ---- 卸载段 ----
Section "Uninstall"
  Delete "$DESKTOP\${APP_NAME}.lnk"
  RMDir /r "$SMPROGRAMS\${APP_NAME}"
  DeleteRegKey HKCU "${UNINST_KEY}"

  Delete "$INSTDIR\uninstall.exe"
  RMDir /r "$INSTDIR"
SectionEnd
