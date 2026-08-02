//! 输入校验（S-14：GoDaddy 调用护栏）
//!
//! 审计证据 `安全审计报告_2026-08-02.md`：
//! - **F-17**：`api_url` 无 https 强制 → 由 `GoDaddyClient::try_new` 强制（见 client.rs）
//! - **F-18**：`device_id`/`domain`/SRV `target` 无字符集校验 → 本模块统一校验
//! - **F-19**：响应体/record data 无大小上限 → 长度上限常量 + client.rs 执行点
//!
//! 规则口径：
//! - `validate_hostname` —— **RFC 1123** 主机名（domain / SRV target），容忍单个结尾点
//!   （FQDN 形式，SRV target 以 `.` 结尾）
//! - `validate_record_name` —— DNS 记录名（标签字符集含 `_`，SRV 服务名 `_remote._tcp` 需要）
//! - `validate_device_id` —— 与 relay 侧 `Registry::validate_device_id`（R-01 成果）
//!   规则对齐：非空、≤ 128 字符、仅 `[a-zA-Z0-9:_-]`。拒绝 `.` —— F-18 的核心注入点
//!   （`device_id` 含 `.` 可把记录写到任意子域）。
//!
//! > **走查项（登记，不阻塞）**：relay 侧字符集（含 `:`/`_`）并非严格 RFC 1123；
//! > `:` 型 device_id（如公钥指纹派生 `a1b2:c3d4:eeee`）无法作为 DNS 记录名/主机名，
//! > dns 侧在 `validate_record_name`/`validate_hostname` 处拒绝（上游 GoDaddy 同样 422）。
//! > 待 relay 侧 R-01 改造稳定后统一口径（见任务文档 §7）。

/// 主机名总长上限（RFC 1035 §2.3.4：≤ 253）。
pub const MAX_HOSTNAME_LEN: usize = 253;

/// 单个标签长度上限（RFC 1035：标签 ≤ 63）。
pub const MAX_LABEL_LEN: usize = 63;

/// device_id 长度上限（对齐 relay `MAX_DEVICE_ID_LEN = 128`，registry.rs:47）。
pub const MAX_DEVICE_ID_LEN: usize = 128;

/// GoDaddy API 响应体上限（F-19：`response.json()` 前检查，1 MiB）。
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// 单条 record data 长度上限（F-19；TXT 上游单条 ≤ 255 字节，4 KiB 为宽松上限）。
pub const MAX_RECORD_DATA_LEN: usize = 4096;

/// TXT 公钥（base64，`ed25519:` 前缀之外部分）长度上限（F-19；Ed25519 为 43 字符）。
pub const MAX_PUBLIC_KEY_LEN: usize = 128;

/// RFC 1123 主机名校验：
///
/// - 每个标签 `[a-zA-Z0-9-]`，不以 `-` 开头或结尾，标签长度 ≤ 63；
/// - 总长 ≤ 253；
/// - 允许一个结尾点（FQDN 形式，SRV target `name.` 使用）；
/// - 末标签不得全数字（RFC 1123 §2.1，避免与 IP 字面量歧义）。
pub fn validate_hostname(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > MAX_HOSTNAME_LEN {
        return false;
    }
    let mut last_label_numeric = true;
    let mut has_label = false;
    for label in name.split('.') {
        if !validate_label(label) {
            return false;
        }
        last_label_numeric = label.bytes().all(|b| b.is_ascii_digit());
        has_label = true;
    }
    has_label && !last_label_numeric
}

/// DNS 记录名校验（`{name}.{domain}` 中 `name` 部分）：
/// 点分隔标签，标签字符集 `[a-zA-Z0-9_-]`（SRV 服务名前缀 `_remote._tcp` 含下划线），
/// 标签 ≤ 63、总长 ≤ 253。拒绝 `/ ? # 空白 控制字符` 等 URL 路径注入字符。
pub fn validate_record_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_HOSTNAME_LEN {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    })
}

/// device_id 校验（与 relay 侧 `Registry::validate_device_id` 对齐）：
/// 非空、≤ 128 字符、仅 `[a-zA-Z0-9:_-]`。
///
/// 安全要点：拒绝 `.`（F-18 子域注入）、空格与其它任意字符；
/// `:`/`_` 为 relay 侧合法字符，为互通予以保留（见模块注释走查项）。
pub fn validate_device_id(device_id: &str) -> bool {
    !device_id.is_empty()
        && device_id.len() <= MAX_DEVICE_ID_LEN
        && device_id.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b == b':' || b == b'_' || b == b'-'
        })
}

/// RFC 1035 标签校验：`[a-zA-Z0-9-]`，不以 `-` 开头/结尾，1..=63 字符。
fn validate_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_LEN
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- validate_hostname ----

    #[test]
    fn test_hostname_valid() {
        assert!(validate_hostname("example.com"));
        assert!(validate_hostname("my-pc"));
        assert!(validate_hostname("my-device.example.com"));
        assert!(validate_hostname("my-device.example.com.")); // FQDN 结尾点
        assert!(validate_hostname("a-b.example.com"));
        assert!(validate_hostname("123.example.com")); // 数字标签可在中间/开头
        assert!(validate_hostname("xn--80akhbykjv.xn--p1ai")); // punycode
    }

    #[test]
    fn test_hostname_invalid() {
        assert!(!validate_hostname(""));
        assert!(!validate_hostname("."));
        assert!(!validate_hostname("a..b"));
        assert!(!validate_hostname("-a.com"));
        assert!(!validate_hostname("a-.com"));
        assert!(!validate_hostname("bad id.com")); // 空格
        assert!(!validate_hostname("a/b.com")); // 路径分隔符
        assert!(!validate_hostname("192.168.0.1")); // IP 字面量（末标签全数字）
        assert!(!validate_hostname(&"a".repeat(64))); // 单标签 64 > 63
        // 4 个 63 字符标签 + 3 个点 = 255 > 253
        let too_long = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63)
        );
        assert!(!validate_hostname(&too_long));
    }

    // ---- validate_record_name ----

    #[test]
    fn test_record_name_valid() {
        assert!(validate_record_name("my-pc"));
        assert!(validate_record_name("_remote._tcp.my-pc"));
        assert!(validate_record_name("PC_01"));
    }

    #[test]
    fn test_record_name_invalid() {
        assert!(!validate_record_name(""));
        assert!(!validate_record_name("a.b.")); // 尾点不允许（记录名无 FQDN 形式）
        assert!(!validate_record_name("a1b2:c3d4")); // ':' 非 DNS 记录名合法字符
        assert!(!validate_record_name("bad id"));
        assert!(!validate_record_name("a/b"));
        assert!(!validate_record_name(&"x".repeat(254)));
    }

    // ---- validate_device_id（relay 对齐） ----

    #[test]
    fn test_device_id_valid() {
        assert!(validate_device_id("pc-a"));
        assert!(validate_device_id("PC_01"));
        assert!(validate_device_id("a1b2:c3d4:eeee")); // 公钥指纹派生 ID（relay 合法）
        assert!(validate_device_id("a"));
        assert!(validate_device_id(&"x".repeat(128)));
    }

    #[test]
    fn test_device_id_invalid() {
        assert!(!validate_device_id(""));
        assert!(!validate_device_id("bad id!")); // 空格 + 标点
        assert!(!validate_device_id("a.b.c")); // '.' → F-18 子域注入点，必须拒绝
        assert!(!validate_device_id("a/b"));
        assert!(!validate_device_id("a?b"));
        assert!(!validate_device_id(&"x".repeat(129))); // > 128
    }
}
