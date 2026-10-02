//! M9-DNS003: 阿里云云解析（Alidns）RPC 签名（HMAC-SHA1）
//!
//! 官方文档：https://next.api.aliyun.com/document/Alidns/2015-01-09
//! 签名机制（RPC 风格）：
//! 1. 合并公共参数与接口参数，按参数名 **ASCII 字典序** 排序；
//! 2. 每个 key/value 做 **RFC3986 严格百分号编码**（字母数字及 `-_.~` 不编码，
//!    其余字符编码为 `%XX` 大写），以 `=` 连接键值、`&` 连接键值对，
//!    得到规范化查询串 `CanonicalizedQueryString`；
//! 3. `StringToSign = "GET&" + percentEncode("/") + "&" + percentEncode(CanonicalizedQueryString)`；
//! 4. `Signature = Base64( HMAC-SHA1( AccessKeySecret + "&", StringToSign ) )`。
//!
//! 说明：`Signature` 参数本身不参与签名，签名后追加到 URL 末尾。

use base64::Engine as _;
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;

/// RFC3986 严格百分号编码：字母数字及 `-_.~` 不编码，其余字符编码为 `%XX`（十六进制大写）。
pub fn pct_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 规范化查询串：参数按 key ASCII 升序（`BTreeMap` 天然有序），
/// key/value 均做 RFC3986 编码，以 `&` 连接。
pub fn canonical_query(params: &BTreeMap<String, String>) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", pct_encode(k), pct_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// HMAC-SHA1（标准构造：`H((K⊕opad) || H((K⊕ipad) || msg))`，块长 64 字节）。
/// 依赖 workspace 的 `sha1` crate 实现哈希本体；不依赖 `hmac` crate。
pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut key = key.to_vec();
    if key.len() > 64 {
        let mut h = Sha1::new();
        h.update(&key);
        key = h.finalize().to_vec();
    }
    key.resize(64, 0);
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = Sha1::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner_hash = inner.finalize();
    let mut outer = Sha1::new();
    outer.update(&opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

/// 计算阿里云 RPC 签名：`HMAC-SHA1(AccessKeySecret + "&", StringToSign)` 的 Base64。
///
/// `params` 为**不含 Signature** 的全部参数（公共参数 + 接口参数），
/// 函数内部完成排序、编码与签名。
pub fn sign_rpc(params: &BTreeMap<String, String>, access_key_secret: &str) -> String {
    let canonical = canonical_query(params);
    // percentEncode("/") = %2F；canonical 需整体再编码一次。
    let string_to_sign = format!("GET&%2F&{}", pct_encode(&canonical));
    let key = format!("{access_key_secret}&");
    let sig = hmac_sha1(key.as_bytes(), string_to_sign.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 阿里云官方文档示例（RPC 签名）：参数固定 → 签名值固定。
    /// 参考：https://help.aliyun.com/zh/sdk/product-overview/rpc-mechanism
    #[test]
    fn official_rpc_signature_vector() {
        let params = BTreeMap::from([
            ("AccessKeyId".into(), "testid".into()),
            ("Action".into(), "DescribeDedicatedHosts".into()),
            ("Format".into(), "JSON".into()),
            ("RegionId".into(), "cn-beijing".into()),
            ("SignatureMethod".into(), "HMAC-SHA1".into()),
            ("SignatureNonce".into(), "edb2b34af0af9a6d14deaf7c1a5315eb".into()),
            ("SignatureVersion".into(), "1.0".into()),
            ("Timestamp".into(), "2023-03-13T08:34:30Z".into()),
            ("Version".into(), "2014-05-26".into()),
        ]);
        assert_eq!(
            sign_rpc(&params, "testsecret"),
            "9NaGiOspFP5UPcwX8Iwt2YJXXuk="
        );
    }

    /// RFC3986 编码：unreserved 不编码；空格、`+`、`*`、中文均编码且大写。
    #[test]
    fn pct_encode_rfc3986() {
        assert_eq!(pct_encode("AZaz09-_.~"), "AZaz09-_.~");
        assert_eq!(pct_encode("a b+c*"), "a%20b%2Bc%2A");
        assert_eq!(pct_encode("中文"), "%E4%B8%AD%E6%96%87");
        assert_eq!(pct_encode("@"), "%40");
        assert_eq!(pct_encode("/"), "%2F");
    }

    /// 规范化查询串：按键排序 + 编码（Timestamp 的冒号编码为大写 %3A）。
    #[test]
    fn canonical_query_sorted_and_encoded() {
        let params = BTreeMap::from([
            ("b".into(), "2".into()),
            ("a".into(), "1 1".into()),
            ("Timestamp".into(), "2016-01-01T12:00:00Z".into()),
        ]);
        assert_eq!(
            canonical_query(&params),
            "Timestamp=2016-01-01T12%3A00%3A00Z&a=1%201&b=2"
        );
    }

    /// HMAC-SHA1 对照已知向量（RFC 2202 用例 1）：key=0x0b×20, data="Hi There"。
    #[test]
    fn hmac_sha1_rfc2202_case1() {
        let key = [0x0bu8; 20];
        let sig = hmac_sha1(&key, b"Hi There");
        assert_eq!(
            hex::encode(sig),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
    }
}
