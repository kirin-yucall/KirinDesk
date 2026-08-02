# KirinDesk.app 打包骨架（M12-MAC MAC-T005 / M14-T004）

```
KirinDesk.app/
└── Contents/
    ├── Info.plist        ← 本目录（已就绪）
    ├── MacOS/
    │   └── kirindesk    ← 可执行文件（cargo build --release 产物复制至此）
    ├── Resources/
    │   ├── icon.icns    ← 应用图标（未提供时移除 Info.plist 的 CFBundleIconFile）
    │   └── ffmpeg/      ← FFmpeg dylib（libavcodec.62.dylib / libavutil.60.dylib /
    │                       libswscale.9.dylib，与 media/src/ffmpeg/dlls.rs 的
    │                       macOS 库名一致；经 dlopen 动态加载，无需改名）
    └── Frameworks/      ← 可选：第三方 framework（当前无，目录保留）
```

## 制作流程（见 create_dmg.sh）

1. `cargo build --release`（aarch64-apple-darwin 与 x86_64-apple-darwin 各一次）
2. `lipo -create ... -output kirindesk` 合并通用二进制 → 复制到 `Contents/MacOS/`
3. 复制 FFmpeg dylib 到 `Contents/Resources/ffmpeg/`
4. `codesign --force --deep --sign - KirinDesk.app`（开发阶段 ad-hoc 签名）
5. `create_dmg.sh` → `hdiutil` 制作 UDZO 安装镜像

## 权限声明（Info.plist）

- `NSDesktopCaptureUsageDescription`：屏幕录制（zed-scap / ScreenCaptureKit）
- `NSMicrophoneUsageDescription`：麦克风（音频环回通常不需要；可选输入设备预留）
- `LSMinimumSystemVersion` = 12.0（ScreenCaptureKit 最低要求）
