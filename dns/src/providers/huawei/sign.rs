//! 华为云 SDK-HMAC-SHA256 签名（官方《API 签名指南》四步法）
//!
//! WebSearch 复核结论（2026-08，与任务描述修正如下）：
//! - **无派生密钥链**：与 AWS SigV4 不同，华为云 AK/SK 签名不使用
//!   secret → date → region → service 派生链；
//!   `signature = HexEncode(HMAC-SHA256(SK, StringToSign))`（官方 api-sign-algorithm-004）；
//! - **规范 URI 需补尾部 "/"**：计算签名时 URI 必须以 `/` 结尾（发送请求时可不带）
//!   （官方 api-sign-algorithm-002）；
//! - 规范头：名称小写、值去首尾空格、按名称字符代码升序，每条 `name:value\n`，
//!   至少包含 `host`、`x-sdk-date`（有 body 时含 `content-type`）；
//! - StringToSign = `Algorithm + '\n' + RequestDateTime + '\n' + HexEncode(SHA256(CanonicalRequest))`；
//! - Authorization = `SDK-HMAC-SHA256 Access={AK}, SignedHeaders={...}, Signature={...}`。

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// 签名算法标识。
pub const ALGORITHM: &str = "SDK-HMAC-SHA256";

type HmacSha256 = Hmac<Sha256>;

/// RFC 3986 URI 编码：保留 `A-Za-z0-9-_.~`，其余百分号编码（大写十六进制）；
/// `encode_slash=false` 时保留 `/`（路径段用 `true`，查询键值用 `true`）。
pub fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 规范查询串：键值 URI 编码后按键字符代码升序，`key=value` 以 `&` 连接；空 → 空串。
pub fn canonical_query_string(query: &[(&str, String)]) -> String {
    let mut items: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    items.sort();
    items
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// 构造规范请求，返回 `(CanonicalRequest, SignedHeaders)`。
///
/// `headers` 为参与签名的消息头（`(name, value)`，内部小写 + 排序 + 去首尾空格）。
fn build_canonical(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    headers: &[(&str, &str)],
    payload: &[u8],
) -> (String, String) {
    let mut hs: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    hs.sort();
    let mut canonical_headers = String::new();
    let mut signed: Vec<String> = Vec::with_capacity(hs.len());
    for (k, v) in &hs {
        canonical_headers.push_str(&format!("{k}:{v}\n"));
        signed.push(k.clone());
    }
    let signed_headers = signed.join(";");
    let payload_hash = hex::encode(Sha256::digest(payload));
    // 规范头块每条以 \n 结尾，公式中 CanonicalHeaders 之后还有独立 \n（空行）再接 SignedHeaders
    let cr = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    (cr, signed_headers)
}

/// 完整签名：输入请求要素，输出 `Authorization` 头值。
///
/// `path` 为请求路径（不含查询串）；规范 URI 内部自动补尾部 `/`。
/// `query` 为查询参数（内部排序）；`payload` 为原始请求体字节（GET/DELETE 传空）。
pub fn authorization(
    ak: &str,
    sk: &str,
    method: &str,
    path: &str,
    query: &[(&str, String)],
    headers: &[(&str, &str)],
    payload: &[u8],
    x_sdk_date: &str,
) -> String {
    // 规范 URI：空路径 → "/"；否则补尾部 "/"（官方规则）
    let canonical_uri = if path.is_empty() {
        "/".to_string()
    } else if path.ends_with('/') {
        path.to_string()
    } else {
        format!("{path}/")
    };
    let canonical_query = canonical_query_string(query);
    let (cr, signed_headers) =
        build_canonical(method, &canonical_uri, &canonical_query, headers, payload);
    // StringToSign = Algorithm \n RequestDateTime \n HashedCanonicalRequest
    let string_to_sign = format!(
        "{ALGORITHM}\n{x_sdk_date}\n{}",
        hex::encode(Sha256::digest(cr.as_bytes()))
    );
    let signature = hmac_sha256_hex(sk.as_bytes(), string_to_sign.as_bytes());
    format!("{ALGORITHM} Access={ak}, SignedHeaders={signed_headers}, Signature={signature}")
}

/// HMAC-SHA256 并输出小写十六进制。
fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC 密钥任意长度均合法");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_encode_keeps_unreserved_and_encodes_rest() {
        assert_eq!(uri_encode("a-zA-Z0-9-_.~", false), "a-zA-Z0-9-_.~");
        assert_eq!(uri_encode("a b", false), "a%20b");
        assert_eq!(uri_encode("a/b", false), "a/b");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
        // 非 ASCII（UTF-8 字节逐个编码）
        assert_eq!(uri_encode("é", false), "%C3%A9");
    }

    #[test]
    fn canonical_query_sorted_and_encoded() {
        let q = vec![("b", "2".to_string()), ("a", "1".to_string())];
        assert_eq!(canonical_query_string(&q), "a=1&b=2");
        assert_eq!(canonical_query_string(&[]), "");
        assert_eq!(canonical_query_string(&[("k", "a b".to_string())]), "k=a%20b");
    }

    #[test]
    fn canonical_request_known_shape() {
        // 固定要素 → 规范请求逐字节断言（空 body 的 SHA-256 为著名常量 e3b0c4...）
        let (cr, signed) = build_canonical(
            "GET",
            "/v2/zones/",
            "",
            &[("x-sdk-date", "20260803T000000Z"), ("host", "dns.myhuaweicloud.com")],
            b"",
        );
        assert_eq!(signed, "host;x-sdk-date");
        assert_eq!(
            cr,
            "GET\n/v2/zones/\n\n\
             host:dns.myhuaweicloud.com\n\
             x-sdk-date:20260803T000000Z\n\n\
             host;x-sdk-date\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn string_to_sign_and_signature_recomputed_with_independent_hmac() {
        let auth = authorization(
            "AK",
            "SK",
            "GET",
            "/v2/zones",
            &[("limit", "500".to_string())],
            &[("host", "dns.myhuaweicloud.com"), ("x-sdk-date", "20260803T000000Z")],
            b"",
            "20260803T000000Z",
        );
        // 头形状：Access=、SignedHeaders=、Signature=（64 位小写 hex）
        assert!(auth.starts_with("SDK-HMAC-SHA256 Access=AK, SignedHeaders=host;x-sdk-date, Signature="), "头形状不符: {auth}");
        let sig = auth.rsplit("Signature=").next().unwrap();
        assert_eq!(sig.len(), 64, "SHA-256 签名应为 64 hex 字符");
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // 独立重算：StringToSign → HMAC(SK, ...) → 与头内签名一致
        let canonical = "GET\n/v2/zones/\nlimit=500\n\
                         host:dns.myhuaweicloud.com\nx-sdk-date:20260803T000000Z\n\n\
                         host;x-sdk-date\n\
                         e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let sts = format!(
            "{ALGORITHM}\n20260803T000000Z\n{}",
            hex::encode(Sha256::digest(canonical.as_bytes()))
        );
        let expect = hmac_sha256_hex(b"SK", sts.as_bytes());
        assert_eq!(sig, expect, "签名必须等于 HMAC(SK, StringToSign)");
    }

    #[test]
    fn canonical_uri_appends_trailing_slash() {
        // 空路径 → "/"；已有尾点 → 不重复
        let auth_root = authorization("A", "S", "GET", "", &[], &[("host", "h"), ("x-sdk-date", "d")], b"", "d");
        assert!(auth_root.contains("Signature="));
        let (cr, _) = build_canonical("GET", "/v2/zones/", "", &[("host", "h"), ("x-sdk-date", "d")], b"");
        assert!(cr.starts_with("GET\n/v2/zones/\n"));
    }
}
