//! 标识自动生成（Windows 系统盘卷序列号 / Linux machine-id / macOS IOPlatformUUID），
//! 同一卷/系统内稳定；全部失败兜底主机名，再兜底 `kirindesk-local`。
//!
//! 字母混合的，都是hd-开头还不如不要这个hd-，因为没起到作用」）**：新生成格式
//! 三平台统一——稳定源 → SHA-256 → **Crockford base32 前 10 位**（字符集
//! `0-9` + `ABCDEFGHJKMNPQRSTVWXYZ`，无 I/L/O/U，辨识友好），**无前缀**，字母
//! 数字混合。HD- 前缀归因定论 = 纯装饰（全仓非测试代码无 starts_with/
//! strip_prefix("HD-")），直接去掉。
//!
//! **旧 ID 就旧不就新**：已落盘 `[device] id`（旧 `HD-XXXXXXXX` /
//! `MACHINE-<32>` / `MAC-<36>` / 自定义值）**不迁移不动、仍合法**——本模块
//! 不再生成任何旧格式；仅新生成（空配置新机 / 未填写）走新格式
//!
//! **防短码 guard（架构红线 ⑧）**：新生成的 10 位 ID 绝不能落入「10 位全 hex
//! 单一大小写」形态——控制端 `is_short_code_shaped` / `is_short_code_connection_input`
//! 与 relay `is_short_code` 会把 10 位全 hex 误判为 64hex 指纹前缀短码（归一化
//! 重写小写后误走短码连接路径）；亦不得全数字（缺字母数字混合）。
//! [`derive_device_id_v2`] 违例即追加 salt 计数器重 hash，直到谓词
//! [`device_id_v2_shape_ok`] 通过。
//!
//! | 平台 | 稳定源（不变） | 旧格式（仅已落盘存量，不迁移） |
//! |---|---|---|
//! | Windows | kernel32 `GetVolumeInformationW`（dlopen）系统盘卷序列号 | `HD-XXXXXXXX`（8 位大写 HEX） |
//! | Linux | `/etc/machine-id`（前 32 位） | `MACHINE-<前 32 位>` |
//! | macOS | `ioreg -rd1 -c IOPlatformExpertDevice` 解析 `IOPlatformUUID`（前 36 位） | `MAC-<前 36 位>` |
//! | 兜底 | 主机名（COMPUTERNAME / HOSTNAME；失败 → `kirindesk-local`） | 原样 |
//! 新格式（三平台统一）：SHA-256(稳定源) → Crockford base32 前 10 位，无前缀。

/// `[device] id` 是否应视为"未填写"（留空即自动；`default-device` 为旧版
/// 占位符，视为未填写，M8-T031）。
pub fn id_is_auto(id: &str) -> bool {
    let id = id.trim();
    id.is_empty() || id == "default-device"
}

/// 解析生效设备 ID：`id_is_auto` → 系统自动派生；否则**原样**返回显式值。
pub fn effective_device_id(configured: &str) -> String {
    if id_is_auto(configured) {
        system_device_id()
    } else {
        configured.to_string()
    }
}

/// 未填写）优先，否则回落 [`effective_device_id`]（与设备页/分享体系**同源**：
/// 旧格式 ID〔HD- 短码等〕就旧不就新、仍合法）。旧实现回落公钥指纹（128 位
/// hex）是与设备页展示 ID（HD- 短码）并存的第二套 ID 体系——被控端按指纹注册、
/// 控制端按设备页 HD- 短码 resolve → 恒离线（"找不到 ID"）。纯函数可单测。
pub fn registration_device_id(explicit: Option<&str>, device_id: &str) -> String {
    match explicit.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => s.to_string(),
        None => effective_device_id(device_id),
    }
}

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

/// Crockford base32 字符集（0-9 + A-Z 去 I/L/O/U——避免 0/O、1/I 混淆，
/// 辨识友好）。**不含 hex 之外的大写字母 I/L/O/U 也不含任何 `-`**（无前缀
/// 形态由字符集天然保证）。
pub const CROCKFORD_B32: &[u8; 32] = b"0000000089ABCDEFGHJKMNPQRSTVWXYZ";

pub const DEVICE_ID_V2_LEN: usize = 10;

/// 含字母 且 含数字（字母数字混合）且 **非全 hex**（10 位全 hex 单一大小写
/// 形态会被控制端 `is_short_code_shaped`/`is_short_code_connection_input` 与
/// relay `is_short_code` 误判为 64hex 指纹前缀短码 → 归一化重写小写后误走
/// 短码连接路径；全数字形态则缺字母数字混合）。单源违例概率 ≈2.5%
/// （全 hex (17/32)^10≈0.18% ∪ 无数字 (22/32)^10≈2.4%，近似不相交）。
///
/// 仅约束**新生成**的 ID——旧格式 ID（HD-/MACHINE-/MAC-/自定义）不走本谓词
/// （旧 ID 就旧不就新，仍合法）。
pub fn device_id_v2_shape_ok(id: &str) -> bool {
    let has_digit = id.bytes().any(|b| b.is_ascii_digit());
    let has_alpha = id.bytes().any(|b| b.is_ascii_alphabetic());
    let all_hex = !id.is_empty() && id.bytes().all(|b| b.is_ascii_hexdigit());
    has_digit && has_alpha && !all_hex
}

/// 从 SHA-256 摘要取 Crockford base32 前 `len` 位（每字符 5 bit，MSB 先行；
/// 32 字节 = 160 bit ≥ 10×5，取高位前缀即可，纯确定性无随机）。
fn crockford_b32_prefix(digest: &[u8], len: usize) -> String {
    let mut out = String::with_capacity(len);
    for i in 0..len {
        let bit = i * 5;
        let byte = bit / 8;
        let rem = bit % 8;
        let v: u32 = if rem <= 3 {
            // 5 bit 完整落在当前字节内（rem+5 ≤ 8）。
            ((digest[byte] >> (3 - rem)) & 0x1F) as u32
        } else {
            // 跨字节：当前字节低 (8-rem) bit + 次字节高 need bit。
            let hi = digest[byte] & ((1u8 << (8 - rem)) - 1);
            let need = 5 - (8 - rem);
            ((hi as u32) << need) | ((digest[byte + 1] >> (8 - need)) as u32)
        };
        out.push(CROCKFORD_B32[v as usize] as char);
    }
    out
}

/// 计数器）→ Crockford base32 前 [`DEVICE_ID_V2_LEN`] 位（无前缀）。
///
/// **确定性**：同一稳定源 → 同一输出（salt 计数器仅在 guard 违例时递增，
/// 违例与否对该源确定 → 重启/重装重派生可复现）。
/// **防短码 guard（红线 ⑧）**：输出违 [`device_id_v2_shape_ok`]（10 位全 hex
/// 单一大小写 / 全数字 / 无字母数字混合）→ 追加计数器（大端 4 字节）作 salt
/// 重 hash，直到通过。单源违例概率 ≈2.5%（全 hex (17/32)^10≈0.18% ∪ 无数字
/// (22/32)^10≈2.4%，近似不相交），首轮即收敛；计数器带上界断言兜底（防理论性
/// 死循环，fail-fast 优于挂起）。
pub fn derive_device_id_v2(stable_source: &str) -> String {
    let mut counter: u32 = 0;
    loop {
        let id = derive_device_id_v2_once(stable_source, counter);
        if device_id_v2_shape_ok(&id) {
            return id;
        }
        counter += 1;
        assert!(
            counter <= 4096,
            "device id v2 guard 循环未收敛（源 {stable_source:?}）——SHA-256 下理论不可能"
        );
    }
}

/// 单轮纯派生（`derive_device_id_v2` 的一次 hash+编码；抽离供单测构造性
/// 证明 guard 的 salt 重混路径可达）。
fn derive_device_id_v2_once(stable_source: &str, counter: u32) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"kirin-desk/device-id/v2\0");
    hasher.update(stable_source.as_bytes());
    hasher.update([0u8]);
    hasher.update(counter.to_be_bytes());
    let digest = hasher.finalize();
    crockford_b32_prefix(&digest, DEVICE_ID_V2_LEN)
}

///
/// 平台稳定源（Windows 卷序列号 / Linux machine-id / macOS IOPlatformUUID；
/// 失败兜底主机名，源均带平台前缀防跨源碰撞）→ [`derive_device_id_v2`] 统一
/// 10 位派生。旧格式（HD-/MACHINE-/MAC-/裸主机名）仅为已落盘 `[device] id`
/// 存量（旧 ID 就旧不就新），本函数不再生成。
pub fn system_device_id() -> String {
    #[cfg(target_os = "windows")]
    {
        match imp::stable_source() {
            Some(src) => derive_device_id_v2(&src),
            None => derive_from_hostname(),
        }
    }
    #[cfg(target_os = "linux")]
    {
        match imp::stable_source() {
            Some(src) => derive_device_id_v2(&src),
            None => derive_from_hostname(),
        }
    }
    #[cfg(target_os = "macos")]
    {
        match imp::stable_source() {
            Some(src) => derive_device_id_v2(&src),
            None => derive_from_hostname(),
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        derive_from_hostname()
    }
}

/// relay `validate_device_id` 与 DNS label 校验，优于裸主机名原样）；源带
/// `hostname:` 前缀防与同值主源跨源碰撞。
fn derive_from_hostname() -> String {
    let host = fallback_hostname();
    tracing::warn!(
        target: "device",
        "no stable system source; deriving device id from hostname {host:?}"
    );
    derive_device_id_v2(&format!("hostname:{host}"))
}

/// 主机名兜底（Windows COMPUTERNAME / 其余 HOSTNAME；均空 → `kirindesk-local`）。
fn fallback_hostname() -> String {
    #[cfg(target_os = "windows")]
    let host = std::env::var("COMPUTERNAME").unwrap_or_default();
    #[cfg(not(target_os = "windows"))]
    let host = {
        let from_env = std::env::var("HOSTNAME").unwrap_or_default();
        if from_env.is_empty() {
            std::fs::read_to_string("/etc/hostname")
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        } else {
            from_env
        }
    };
    if host.is_empty() {
        "kirindesk-local".to_string()
    } else {
        host
    }
}

// ════════════════════════════════════════════════════════════════
// 平台实现
// ════════════════════════════════════════════════════════════════

/// Windows：kernel32 `GetVolumeInformationW`（dlopen，仿
/// `core/src/crypto/windows_dpapi.rs` 的 `DpapiDlls` 模式，Library 保活），
/// 取系统盘（`SystemDrive` → `C:` → home 盘）卷序列号作稳定源
#[cfg(target_os = "windows")]
mod imp {
    use libloading::{Library, Symbol};
    use std::os::windows::ffi::OsStrExt;
    use std::sync::OnceLock;

    /// `GetVolumeInformationW` 签名（kernel32，Windows SDK 头文件）。
    type GetVolumeInformationWFn = unsafe extern "system" fn(
        root_path: *const u16,
        volume_name: *mut u16,
        volume_name_size: u32,
        serial_number: *mut u32,
        max_component_len: *mut u32,
        file_system_flags: *mut u32,
        file_system_name: *mut u16,
        file_system_name_size: u32,
    ) -> i32;

    /// 已解析的 kernel32 函数表（Library 句柄保活，进程生命周期内不卸载）。
    struct Kernel32Dlls {
        _kernel32: Library,
        get_volume_information: GetVolumeInformationWFn,
    }

    static K32: OnceLock<Result<Kernel32Dlls, String>> = OnceLock::new();

    impl Kernel32Dlls {
        fn get() -> Option<&'static Kernel32Dlls> {
            K32.get_or_init(Self::load).as_ref().ok()
        }

        fn load() -> Result<Self, String> {
            // SAFETY: 系统固定路径 DLL；加载后仅解析符号（与 DpapiDlls 同模式）。
            let kernel32 = unsafe { Library::new("kernel32.dll") }
                .map_err(|e| format!("dlopen kernel32.dll: {e}"))?;

            macro_rules! sym {
                ($lib:expr, $name:literal, $ty:ty) => {
                    // SAFETY: 符号名与类型来自 Windows SDK 头文件。
                    unsafe { $lib.get::<$ty>($name.as_bytes()) }
                        .map(|s: Symbol<'_, $ty>| *s)
                        .map_err(|e| format!("symbol '{}': {e}", $name))?
                        as $ty
                };
            }

            Ok(Self {
                get_volume_information: sym!(
                    &kernel32,
                    "GetVolumeInformationW",
                    GetVolumeInformationWFn
                ),
                _kernel32: kernel32,
            })
        }
    }

    /// 系统盘 root（`GetVolumeInformationW` 需要 `C:\` 形式）。
    fn system_root() -> String {
        if let Ok(sd) = std::env::var("SystemDrive") {
            let sd = sd.trim_end_matches('\\');
            if !sd.is_empty() {
                return sd.to_string();
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            let drive: String = home.chars().take(2).collect();
            if drive.ends_with(':') {
                return drive;
            }
        }
        "C:".to_string()
    }

    /// 取卷序列号（失败 → None，走主机名兜底）。
    fn volume_serial(root: &str) -> Option<u32> {
        let dlls = Kernel32Dlls::get()?;
        let root = format!("{}\\", root.trim_end_matches('\\'));
        let root_wide: Vec<u16> = std::ffi::OsStr::new(&root)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut serial: u32 = 0;
        let mut max_component: u32 = 0;
        let mut fs_flags: u32 = 0;
        let mut volume_name = vec![0u16; 260];
        let mut fs_name = vec![0u16; 260];
        // SAFETY: root_wide NUL 结尾；缓冲区长度与大小参数一致。
        let ok = unsafe {
            (dlls.get_volume_information)(
                root_wide.as_ptr(),
                volume_name.as_mut_ptr(),
                volume_name.len() as u32,
                &mut serial,
                &mut max_component,
                &mut fs_flags,
                fs_name.as_mut_ptr(),
                fs_name.len() as u32,
            )
        };
        (ok != 0).then_some(serial)
    }

    /// 平台稳定源 = 系统盘卷序列号（`windows:volume-serial:<8 位大写 HEX>`；
    /// None = 取源失败 → 顶层走主机名兜底派生）。
    pub(super) fn stable_source() -> Option<String> {
        let root = system_root();
        match volume_serial(&root) {
            Some(serial) => Some(format!("windows:volume-serial:{serial:08X}")),
            None => {
                tracing::warn!(
                    target: "device",
                    "GetVolumeInformationW failed for root {root:?}; falling back to hostname"
                );
                None
            }
        }
    }
}

/// 顶层 `derive_device_id_v2` 派生）；失败 → 顶层主机名兜底派生。
#[cfg(target_os = "linux")]
mod imp {
    /// 平台稳定源 = `/etc/machine-id` 前 32 位（`linux:machine-id:<32>`；
    /// None = 取源失败）。
    pub(super) fn stable_source() -> Option<String> {
        let id = std::fs::read_to_string("/etc/machine-id")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        let first32: String = id.chars().take(32).collect();
        Some(format!("linux:machine-id:{first32}"))
    }
}

/// macOS：`ioreg -rd1 -c IOPlatformExpertDevice` 解析 `IOPlatformUUID` 前
/// 派生）；失败 → 顶层主机名兜底派生。
#[cfg(target_os = "macos")]
mod imp {
    /// 从 ioreg 输出中解析 `"IOPlatformUUID" = "XXXX-...-XXXX"`。
    fn parse_io_platform_uuid(output: &str) -> Option<String> {
        for line in output.lines() {
            let line = line.trim();
            let Some(idx) = line.find("IOPlatformUUID") else {
                continue;
            };
            let rest = &line[idx + "IOPlatformUUID".len()..];
            let Some(eq) = rest.find('=') else {
                continue;
            };
            let value = rest[eq + 1..].trim().trim_matches('"');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
        None
    }

    /// 平台稳定源 = `IOPlatformUUID` 前 36 位（`macos:io-platform-uuid:<36>`；
    /// None = 取源失败）。
    pub(super) fn stable_source() -> Option<String> {
        let uuid = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .ok()
            .map(|out| String::from_utf8_lossy(&out.stdout))
            .and_then(|text| parse_io_platform_uuid(&text))?;
        let first36: String = uuid.chars().take(36).collect();
        Some(format!("macos:io-platform-uuid:{first36}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_is_auto() {
        assert!(id_is_auto(""));
        assert!(id_is_auto("default-device"));
        assert!(id_is_auto("  "));
        assert!(!id_is_auto("my-pc"));
        assert!(!id_is_auto("HD-1234ABCD"));
    }

    #[test]
    fn test_effective_device_id_explicit_preserved() {
        assert_eq!(effective_device_id("my-pc"), "my-pc");
        assert_eq!(effective_device_id("HD-1234ABCD"), "HD-1234ABCD");
    }

    #[test]
    fn test_effective_device_id_auto_non_empty_and_deterministic() {
        let a = effective_device_id("");
        assert!(!a.is_empty(), "auto device id must never be empty");
        let b = effective_device_id("");
        assert_eq!(a, b, "auto device id must be deterministic within a process");
        // 旧占位符视为未填写 → 同样走自动
        assert_eq!(effective_device_id("default-device"), a);
    }

    #[test]
    fn test_system_device_id_never_empty() {
        let id = system_device_id();
        assert!(!id.is_empty());
    }

    /// （替代旧 HD-/MACHINE-/MAC- 前缀断言；主机名兜底路径同走 v2 派生）。
    #[test]
    fn test_system_device_id_v2_format_and_source() {
        let id = system_device_id();
        assert_eq!(id.len(), DEVICE_ID_V2_LEN, "新格式固定 10 位, got {id}");
        assert!(
            id.bytes().all(|b| CROCKFORD_B32.contains(&b)),
            "非 Crockford 字符集: {id}"
        );
        assert!(!id.contains('-'), "无前缀/无连字符: {id}");
        assert!(device_id_v2_shape_ok(&id), "防短码 guard: {id}");
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        {
            // 平台稳定源（或主机名兜底）→ 直派生同值（端到端口径一致）。
            let expected = match imp::stable_source() {
                Some(src) => derive_device_id_v2(&src),
                None => {
                    let host = fallback_hostname();
                    derive_device_id_v2(&format!("hostname:{host}"))
                }
            };
            assert_eq!(id, expected, "system_device_id 与平台稳定源直派生须同值");
        }
    }

    #[test]
    fn test_fallback_hostname_never_empty() {
        assert!(!fallback_hostname().is_empty());
    }


    #[test]
    fn r76c_registration_id_explicit_preserved() {
        // 显式配置（`[tunnel] device_id`）原样使用（trim 归一）。
        assert_eq!(registration_device_id(Some("my-pc"), ""), "my-pc");
        assert_eq!(registration_device_id(Some("HD-62EC5BC9"), ""), "HD-62EC5BC9");
        assert_eq!(registration_device_id(Some("  my-pc  "), ""), "my-pc");
    }

    #[test]
    fn r76c_registration_id_empty_falls_back_to_derived_id() {
        // 未填写（None/空串/空白）→ effective_device_id 同源回落派生 ID
        let a = registration_device_id(None, "");
        assert!(!a.is_empty(), "注册 ID 永不空");
        assert!(!id_is_auto(&a), "派生值不得仍处未填写态");
        assert_eq!(a.len(), DEVICE_ID_V2_LEN, "新格式固定 10 位, got {a}");
        assert!(
            a.bytes().all(|b| CROCKFORD_B32.contains(&b)),
            "非 Crockford 字符集: {a}"
        );
        assert!(device_id_v2_shape_ok(&a), "防短码 guard: {a}");
        assert_eq!(a, system_device_id(), "注册回落与展示同源");
        // 稳定性：同输入同输出（确定性派生，重启不变）。
        assert_eq!(registration_device_id(None, ""), a);
        assert_eq!(registration_device_id(Some(""), ""), a, "空串视为未填写");
        assert_eq!(registration_device_id(Some("   "), ""), a, "空白视为未填写");
        assert_eq!(
            registration_device_id(None, "default-device"),
            a,
            "旧占位符视为未填写"
        );
    }


    /// r86i ①格式：多稳定源样例（三平台主源形态 + 主机名兜底形态）→
    /// 固定 10 位 / Crockford 字符集 / 无前缀（无连字符、无 HD-）。
    #[test]
    fn r86i_v2_format_ten_chars_crockford_no_prefix() {
        let sources = [
            "windows:volume-serial:62EC5BC9",
            "windows:volume-serial:00000001",
            "linux:machine-id:0000000089abcdef0000000089abcdef",
            "macos:io-platform-uuid:8E52B7C4-1D3F-4A6B-9C8D-2F4E6A8B0C1D",
            "hostname:DESKTOP-ABC123",
            "hostname:kirindesk-local",
            "hostname:pc-01",
        ];
        for src in sources {
            let id = derive_device_id_v2(src);
            assert_eq!(id.len(), DEVICE_ID_V2_LEN, "{src} → {id}");
            assert!(
                id.bytes().all(|b| CROCKFORD_B32.contains(&b)),
                "{src} → 非 Crockford 字符集: {id}"
            );
            assert!(!id.contains('-'), "{src} → 无前缀/无连字符: {id}");
            assert!(!id.is_empty() && id != "default-device");
        }
    }

    /// r86i ②格式（混合性）：同一批稳定源样例输出必含字母且含数字、
    /// 非全 hex（防短码 guard 谓词通过）。
    #[test]
    fn r86i_v2_shape_mixed_letter_digit_not_all_hex() {
        let sources = [
            "windows:volume-serial:62EC5BC9",
            "windows:volume-serial:DEADBEEF",
            "linux:machine-id:ffffffffffffffffffffffffffffffff",
            "macos:io-platform-uuid:00000000-0000-0000-0000-000000000000",
            "hostname:kirindesk-local",
            "hostname:WORKSTATION-01",
        ];
        for src in sources {
            let id = derive_device_id_v2(src);
            let has_digit = id.bytes().any(|b| b.is_ascii_digit());
            let has_alpha = id.bytes().any(|b| b.is_ascii_alphabetic());
            let all_hex = id.bytes().all(|b| b.is_ascii_hexdigit());
            assert!(has_digit, "{src} → 缺数字: {id}");
            assert!(has_alpha, "{src} → 缺字母: {id}");
            assert!(!all_hex, "{src} → 全 hex 短码形态: {id}");
            assert!(device_id_v2_shape_ok(&id), "{src} → {id}");
        }
    }

    /// r86i ②防短码 guard（谓词表）：10 位全 hex 单一大小写（会被
    /// `is_short_code_shaped` 误判）/ 全数字（缺字母数字混合）/ 全字母无数字
    /// 一律拒绝；含非 hex 字母 + 数字混合通过。
    #[test]
    fn r86i_v2_shape_ok_predicate_table() {
        // 拒绝：10 位全 hex（大写/小写/混合大小写均算——is_ascii_hexdigit 大小写不敏感）。
        assert!(!device_id_v2_shape_ok("ABCDEF1234"), "全 hex 大写 → 短码形态");
        assert!(!device_id_v2_shape_ok("abcdef1234"), "全 hex 小写 → 短码形态");
        assert!(!device_id_v2_shape_ok("AbCdEf1234"), "全 hex 混合大小写仍全 hex");
        assert!(!device_id_v2_shape_ok("7784CDB912"), "全 hex 无字母");
        // 拒绝：全数字（缺字母）。
        assert!(!device_id_v2_shape_ok("0000000089"), "全数字 → 无字母数字混合");
        // 拒绝：全字母（缺数字）。
        assert!(!device_id_v2_shape_ok("GHIJKMNPQS"), "全字母 → 无字母数字混合");
        assert!(!device_id_v2_shape_ok("AAAAAAAAAA"), "全字母（且恰全 hex 子集）");
        // 通过：含非 hex 字母（G-Z 去 I/L/O/U）+ 数字混合。
        assert!(device_id_v2_shape_ok("G7KJ2MNQ4X"));
        assert!(device_id_v2_shape_ok("7784CDG912"), "仅一个非 hex 字母即破全 hex");
        // 空串/非 10 位：谓词本身不判长度（长度由生成侧保证），但空串缺字母 → 拒绝。
        assert!(!device_id_v2_shape_ok(""));
    }

    /// r86i ②防短码 guard（构造性证明）：探测一个第一轮（salt counter=0）
    /// 派生恰好落入 guard 拒绝形态（全 hex / 全数字等）的稳定源——单源概率
    /// ≈2.5%，有界枚举确定性必中；断言 `derive_device_id_v2` 的输出 ≠
    /// 第一轮值 且 == 第二轮（salt counter=1）值 = guard 的 salt 重混路径
    /// 真实生效，且重混结果稳定可复现。
    #[test]
    fn r86i_v2_guard_reshuffles_short_code_shaped_source() {
        let mut bad_source: Option<String> = None;
        for i in 0..100_000u32 {
            let probe = format!("r86i-guard-probe-{i}");
            if !device_id_v2_shape_ok(&derive_device_id_v2_once(&probe, 0)) {
                bad_source = Some(probe);
                break;
            }
        }
        let bad_source = bad_source.expect(
            "100k 确定性探测内必命中一个第一轮落入 guard 拒绝形态的源（单源概率 ≈2.5%）",
        );
        let first_round = derive_device_id_v2_once(&bad_source, 0);
        assert!(!device_id_v2_shape_ok(&first_round), "探针源第一轮必违 guard: {first_round}");
        // guard 生效：最终输出 ≠ 第一轮被拒值，= 第二轮（salt counter=1）值，且通过谓词。
        let derived = derive_device_id_v2(&bad_source);
        assert_ne!(derived, first_round, "guard 必 salt 重混（输出 ≠ 第一轮被拒值）");
        assert_eq!(derived, derive_device_id_v2_once(&bad_source, 1));
        assert!(device_id_v2_shape_ok(&derived));
        assert_eq!(derived.len(), DEVICE_ID_V2_LEN);
        // 重混结果稳定（重启/重装重派生同值）。
        assert_eq!(derive_device_id_v2(&bad_source), derived);
    }

    /// r86i ④稳定性：同源两次派生同值（确定性；含 guard 触发源亦稳定）。
    #[test]
    fn r86i_v2_stability_same_source_same_id() {
        for src in [
            "windows:volume-serial:62EC5BC9",
            "hostname:DESKTOP-ABC123",
            "linux:machine-id:11111111111111111111111111111111",
        ] {
            assert_eq!(
                derive_device_id_v2(src),
                derive_device_id_v2(src),
                "同源两次派生同值: {src}"
            );
        }
    }

    /// r86i（编码锚点）：Crockford 前缀编码位序钉死——全零摘要 → 全 `0`；
    /// 全 FF → 全 `Z`（0x1F=31 = 字符集末位）；MSB 先行跨字节拼接
    /// （首字节 0b1011_0011 + 次字节 0b0100_0000 → 位流 10110|01101 →
    /// 22='P'、13='D'）。
    #[test]
    fn r86i_v2_crockford_bit_order_anchor() {
        let zero = [0u8; 32];
        assert_eq!(crockford_b32_prefix(&zero, 10), "0000000000");
        let ff = [0xFFu8; 32];
        assert_eq!(crockford_b32_prefix(&ff, 10), "ZZZZZZZZZZ");
        let mut d = [0u8; 32];
        d[0] = 0b1011_0011;
        d[1] = 0b0100_0000;
        assert_eq!(crockford_b32_prefix(&d, 2), "PD");
    }

    #[test]
    fn r76c_registration_id_explicit_configured_no_fallback() {
        // `[device] id` 显式 → 注册携带显式值（与展示同源，不回落）。
        assert_eq!(registration_device_id(None, "my-pc"), "my-pc");
        assert_eq!(registration_device_id(None, "HD-1234ABCD"), "HD-1234ABCD");
    }
}
