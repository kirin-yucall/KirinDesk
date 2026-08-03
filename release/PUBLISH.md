# KirinDesk 发布流程（Release）

> 目标：让「Settings → 检查更新」链路可用——updater 通过 **GitHub Releases API**
> 检出新版本（tag `vX.Y.Z` 比较），下载 **Windows 资产**后按 **`.sha256` 侧车**
> 强制校验再安装（S-06a/R-07-S1）。发布缺任一步（无 Release / 无侧车 / 命名不匹配）
> 都会导致更新失败，流程末尾有排查表。

## 0. 前置条件

| 项 | 要求 |
|---|---|
| gh CLI | `gh auth login`（需要 repo 权限：创建 Release、上传资产） |
| 工作区 | `git status` 干净（有未提交改动先提交/stash） |
| 本地验证 | `cargo check --workspace --all-targets` 全绿；关键套件 `cargo test -p kirin-desk-ui -p kirin-desk-core -p kirin-desk-utils -p kirin-desk-updater` 通过 |
| 版本规则 | SemVer `X.Y.Z`；workspace 根 `Cargo.toml version`（各 crate `version.workspace = true` 继承，只改根即可） |

## 1. 推荐路径：`release/publish.sh` 一键发布（含 CI 三平台）

```bash
# 工作区干净后：
release/publish.sh 0.2.0          # GPG 签名 tag（需已配置签名 key）
release/publish.sh 0.2.0 --no-sign  # 无签名 key 时降级为普通 annotated tag
```

脚本自动完成：

1. **版本号**：写入 workspace `Cargo.toml`（`0.1.0` → `0.2.0`）+ `cargo check` 刷新 `Cargo.lock`；
2. **CHANGELOG 归档**：`## [Unreleased]` 段整体移入 `## [v0.2.0] - 2026-xx-xx`，顶部重建 Unreleased，并追加版本链接（Keep a Changelog 格式）；
3. **commit + tag**：`release: 0.2.0` 提交；`v0.2.0` tag（GPG 签名失败自动降级）；push 分支 + tag；
4. **CI 触发**：`.github/workflows/ci.yml` 的 release job（`tags: ['v*']`）在三平台打包并上传 artifact：
   - Windows → `KirinDesk-{ver}-windows-x86_64.zip`（exe + FFmpeg DLL + default.toml）**+ 独立 exe** `KirinDesk-{ver}-windows-x86_64.exe`（updater 优先 .exe）；
   - Ubuntu → `.deb`；macOS → `.dmg`；
   - 各平台生成 `checksums.txt`（全资产 SHA-256 汇总）；
5. **下载产物 + 侧车**：`gh run download` 拉取 artifact；对每个资产生成 **`<asset>.sha256` 侧车**（`sha256sum` 输出 hex）与 `checksums.txt`；
6. **创建 Release**：`gh release create v0.2.0 --title "KirinDesk 0.2.0" --notes <CHANGELOG 版本段>`，上传全部资产 + 侧车 + 清单。

> CI 未触发/失败时脚本会告警并跳过下载，需人工确认构建后重跑或走手动路径（§2）。

## 2. 手动路径（无 CI / 仅发 Windows）

```bash
# ① 本地打包（产物 = release/KirinDesk.exe + ffmpeg/ + default.toml）
#    双击 release/package.bat，或：
#    CARGO_BUILD_JOBS=8 CARGO_TARGET_DIR="$TEMP/kirin-target" \
#      cargo build --release -p kirin-desk-ui
#    cp "$TEMP/kirin-target/release/kirin-desk-ui.exe" release/KirinDesk.exe

# ② 版本号 + CHANGELOG（同 §1 第 1-2 步，手改或借用 publish.sh 的 python 段）
# ③ 提交 + 打 tag + 推送
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "release: 0.2.0"
git tag -a v0.2.0 -m "KirinDesk 0.2.0"
git push origin main v0.2.0

# ④ 生成侧车 + 清单（文件名必须与资产完全一致，见 §3）
sha256sum release/KirinDesk.exe > release/KirinDesk.exe.sha256
# ⑤ 创建 Release（asset 名必须含 "windows" 关键字，见 §3）
gh release create v0.2.0 --title "KirinDesk 0.2.0" --notes "<CHANGELOG 版本段>"
gh release upload v0.2.0 release/KirinDesk.exe release/KirinDesk.exe.sha256
```

## 3. 资产命名与侧车规范（updater 依赖，别踩坑）

| 规则 | 说明 |
|---|---|
| Windows 资产名含 `windows` 关键字 | `pick_asset` 按平台关键字打分，无命中则回退第一个资产——**名不含 windows 可能挑错/挑不中** |
| `.exe` 优先 | Windows 平台 `preferred_extension = ".exe"`；exe 与 zip 同时存在时选 exe（独立 exe 即为此设计） |
| 侧车 `<asset>.sha256` 必须同名 | updater 下载后请求 `{download_url}.sha256`；**缺失 → `ChecksumMissing` 拒绝安装**（legacy 通道已 deprecated） |
| 侧车内容格式 | `sha256sum` 输出 `<64hex>  <filename>`；updater 取首个空白分隔 token——`sha256sum <file> | awk '{print $1}' > <file>.sha256` 最稳 |
| tag 格式 | `vX.Y.Z`（`X.Y.Z` 数字点分）；非法 tag（含 `&`/`../` 等）被 `is_valid_version_tag` 白名单拒绝 |
| 版本比较 | updater 取 tag 去 `v` 前缀后与 `APP_VERSION`（Cargo 版本）比较，新版本 > 当前才提示 |

## 4. 发布后验证（必做）

1. 网页确认：`https://github.com/kirin-yucall/KirinDesk/releases/tag/vX.Y.Z` 资产与侧车齐全；
2. 实机（旧版本构建）→ Settings → **Check for updates** → 应提示 `vX.Y.Z` 可用；
3. 点击 Download → 下载完成后按 `.sha256` 侧车校验 → Install & Restart；
4. 重启后 `About` 显示新版本号。

**失败排查表**

| 现象 | 原因 |
|---|---|
| `GitHub 仓库暂无 Release 发布（HTTP 404）` | Release 未创建，或仓库路径大小写不对（应为 `kirin-yucall/KirinDesk`） |
| `No assets in release` | 资产为空，或平台关键字未命中（Windows 资产名需含 `windows`） |
| `Checksum missing: ...` | `.sha256` 侧车未上传或文件名与资产不一致 |
| `Checksum mismatch` | 侧车内容非 64 位 hex（或对错文件） |
| 提示「已是最新」但实际有新版本 | tag 版本 ≤ 当前 `APP_VERSION`；或改版本后未重新构建（`APP_VERSION` 是编译期常量） |

## 5. 注意事项

- **敏感信息**：发布资产（exe/zip）不得内含真实 `api_key` / `api_secret`——`default.toml` 模板字段保持空串，配置加密密钥不入库（R-13）；
- **签名 tag**：`--no-sign` 仅降级为普通 annotated tag，不影响 Release 创建；正式签名在 CI/供应链审计更有利；
- **每资产一个侧车**：只传 `checksums.txt` 不够，updater 只认 `<asset>.sha256`；
- **Windows 本地发布时**：`release/ffmpeg/`（FFmpeg 8.1.1 DLL）与 `release/default.toml` 需随包部署（install.bat 处理；zip 由 CI 打包）；
- **仓库大小写**：全部链路（git remote / updater GITHUB_REPO / publish.sh 链接）统一 `KirinDesk`。
