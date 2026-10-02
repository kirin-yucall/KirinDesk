//! M9-DNS014: OVH 三要素请求签名
//!
//! 官方格式（WebSearch 复核 ovh/go-ovh 与官方文档）：
//!
//! ```text
//! X-Ovh-Signature = "$1$" + SHA1Hex(AS + "+" + CK + "+" + METHOD + "+" + URL + "+" + BODY + "+" + TIMESTAMP)
//! ```
//!
//! - AS = Application Secret（app_secret）
//! - CK = Consumer Key（consumer_key）
//! - METHOD = 大写 HTTP 方法（GET/POST/PUT/DELETE）
//! - URL = **完整请求 URL（含查询串）**，如 `https://api.ovh.com/1.0/domain/zone?limit=1`
//! - BODY = 请求体**原样字节**（紧凑 JSON，不可重排空白——签名与发送必须一致）
//! - TIMESTAMP = Unix 秒（来自 X-Ovh-Timestamp 头）
//! - 注意：任务摘要中时间戳位于第 3 段，官方与 M9-DNS014 文档均为**末段**，
//!   此处以官方为准（"文档与官方 API 矛盾处：WebSearch 复核再实现"）。

use sha1::{Digest, Sha1};

/// 计算 X-Ovh-Signature 头值（"$1$" + SHA1 hex 小写）。
pub(crate) fn signature(
    app_secret: &str,
    consumer_key: &str,
    method: &str,
    url: &str,
    body: &str,
    timestamp: i64,
) -> String {
    let input = format!("{app_secret}+{consumer_key}+{method}+{url}+{body}+{timestamp}");
    let mut hasher = Sha1::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    format!("$1${}", hex::encode(digest))
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    /// 官方文档示例向量（Stack Overflow "Generating OVH SHA1 signature"）：
    /// appSecret+consKey+PUT+/path/to/api+TEST DATA+123456789 → $1$8336ecc5d03640b976e0b3ba005234a3046ab695
    #[test]
    fn official_example_vector() {
        let sig = signature(
            "appSecret",
            "consKey",
            "PUT",
            "/path/to/api",
            "TEST DATA",
            123456789,
        );
        assert_eq!(sig, "$1$8336ecc5d03640b976e0b3ba005234a3046ab695");
    }

    #[test]
    fn signature_is_deterministic_and_sensitive_to_input() {
        let a = signature("s", "c", "GET", "https://api.ovh.com/1.0/domain/zone", "", 1700000000);
        let b = signature("s", "c", "GET", "https://api.ovh.com/1.0/domain/zone", "", 1700000000);
        assert_eq!(a, b);
        // 时间戳不同 → 签名不同；body 不同 → 签名不同。
        assert_ne!(a, signature("s", "c", "GET", "https://api.ovh.com/1.0/domain/zone", "", 1700000001));
        assert_ne!(a, signature("s", "c", "GET", "https://api.ovh.com/1.0/domain/zone", "{}", 1700000000));
    }
}
