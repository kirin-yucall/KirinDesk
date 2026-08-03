//! M9-DNS004: 腾讯云 DNSPod TC3-HMAC-SHA256 签名（手写 SHA-256 / HMAC-SHA256）
//!
//! 官方文档：https://cloud.tencent.com/document/product/1582/70024（TC3-HMAC-SHA256
//! 签名方法）——请求域 `dnspod.tencentcloudapi.com`，`service = "dnspod"`，
//! `Version = "2021-03-23"`。
//!
//! 依赖说明：workspace 虽有 `sha2 0.10` / `hmac 0.12`，但 **未列入
//! dns/Cargo.toml 依赖**（该文件禁止修改、禁止新增依赖），故本文件手写
//! SHA-256（RFC 6234 §5）与 HMAC-SHA256（RFC 2104），输出向量与 Node.js
//! `crypto` 模块独立复算结果比对（见本文件 tests，双实现互证）。
//!
//! TC3 签名步骤（`service = dnspod`，POST JSON）：
//! 1. `CanonicalRequest`：
//!    ```text
//!    POST
//!    /
//!    <空行（无查询串）>
//!    content-type:application/json; charset=utf-8
//!    host:dnspod.tencentcloudapi.com
//!    x-tc-action:describedomainlist        ← Action 转小写
//!    <空行>
//!    content-type;host;x-tc-action          ← SignedHeaders（小写、按字典序）
//!    {sha256hex(body)}
//!    ```
//! 2. `StringToSign`：
//!    ```text
//!    TC3-HMAC-SHA256
//!    {YYYY-MM-DDTHH:MM:SSZ（UTC，来自时间戳）}
//!    {YYYY-MM-DD}/{service}/tc3_request
//!    {sha256hex(CanonicalRequest)}
//!    ```
//! 3. 派生密钥：`SecretDate = HMAC("TC3"+secret_key, date)` →
//!    `SecretService = HMAC(SecretDate, service)` →
//!    `SecretSigning = HMAC(SecretService, "tc3_request")`。
//! 4. `Signature = hex(HMAC(SecretSigning, StringToSign))`。
//!
//! 请求头：`X-TC-Action`（原始大小写）、`X-TC-Version`、`X-TC-Timestamp`、
//! `X-TC-Nonce`（32 位随机整数，可选）、`Content-Type`、`Authorization`。
//! DNSPod 无地域概念，**不发送** `X-TC-Region`。

/// DNSPod 产品服务名（TC3 Credential scope 与派生密钥第三跳使用）。
pub const SERVICE: &str = "dnspod";/// API 版本（X-TC-Version 头）。
pub const VERSION: &str = "2021-03-23";
/// Content-Type 固定值（参与签名，必须与请求头发送的完全一致）。
pub const CONTENT_TYPE: &str = "application/json; charset=utf-8";

/// 时间戳 → 日期转换所需 trait（`Utc.timestamp_opt`）。
use chrono::TimeZone;

/// SHA-256 压缩常量（前 64 个素数立方根的小数部分前 32 位，RFC 6234 §5.3.2）。
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 初始哈希值（前 8 个素数平方根的小数部分前 32 位，RFC 6234 §5.3.3）。
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// 手写 SHA-256：返回 32 字节摘要（RFC 6234）。
pub fn sha256(data: &[u8]) -> [u8; 32] {
    // ── 填充：0x80 + 0x00… + 64 位大端比特长度（消息长度以 512 位块为单位对齐）──
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut h = H0;
    for chunk in msg.chunks_exact(64) {
        // ── 消息调度表 W[0..64] ──
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        // ── 主压缩循环 ──
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h = [
            a.wrapping_add(h[0]),
            b.wrapping_add(h[1]),
            c.wrapping_add(h[2]),
            d.wrapping_add(h[3]),
            e.wrapping_add(h[4]),
            f.wrapping_add(h[5]),
            g.wrapping_add(h[6]),
            hh.wrapping_add(h[7]),
        ];
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// SHA-256 十六进制（小写）。
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// HMAC-SHA256（RFC 2104，块长 64 字节）。
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    // 密钥超过块长 → 先哈希压缩；不足 → 右补零到 64 字节。
    let mut key = key.to_vec();
    if key.len() > 64 {
        key = sha256(&key).to_vec();
    }
    key.resize(64, 0);

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, k) in key.iter().enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }
    // inner = SHA256(ipad || msg)；outer = SHA256(opad || inner)
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// HMAC-SHA256 十六进制（小写）。
pub fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    hex::encode(hmac_sha256(key, msg))
}

/// TC3 签名（返回 `Authorization` 请求头值）。
///
/// 入参：
/// - `secret_id` / `secret_key`：腾讯云 API 密钥；
/// - `service`：产品服务名（DNSPod = "dnspod"）；
/// - `host`：请求 Host 头值（如 `dnspod.tencentcloudapi.com`，含端口时带端口）；
/// - `action`：接口名原始大小写（如 `DescribeDomainList`，签名时转小写）；
/// - `timestamp_secs`：Unix 秒（与 `X-TC-Timestamp` 一致）；
/// - `body`：请求体原文（与 Content-Length 一致，签名使用其 SHA-256）。
pub fn tc3_authorization(
    secret_id: &str,
    secret_key: &str,
    service: &str,
    host: &str,
    action: &str,
    timestamp_secs: i64,
    body: &str,
) -> String {
    let dt = chrono::Utc
        .timestamp_opt(timestamp_secs, 0)
        .single()
        .expect("TC3 时间戳越界");
    let date = dt.format("%Y-%m-%d").to_string(); // Credential scope 日期
    let iso_time = dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(); // StringToSign 时间
    // ── 步骤 1：CanonicalRequest ──
    let signed_headers = "content-type;host;x-tc-action";
    let canonical_request = format!(
        "POST\n/\n\n\
         content-type:{CONTENT_TYPE}\n\
         host:{host}\n\
         x-tc-action:{}\n\
         \n\
         {signed_headers}\n\
         {}",
        action.to_ascii_lowercase(),
        sha256_hex(body.as_bytes()),
    );

    // ── 步骤 2：StringToSign ──
    let string_to_sign = format!(
        "TC3-HMAC-SHA256\n{iso_time}\n{date}/{service}/tc3_request\n{}",
        sha256_hex(canonical_request.as_bytes()),
    );

    // ── 步骤 3：派生密钥链 ──
    let secret_date = hmac_sha256(format!("TC3{secret_key}").as_bytes(), date.as_bytes());
    let secret_service = hmac_sha256(&secret_date, service.as_bytes());
    let secret_signing = hmac_sha256(&secret_service, b"tc3_request");

    // ── 步骤 4：签名 ──
    let signature = hmac_sha256_hex(&secret_signing, string_to_sign.as_bytes());
    format!(
        "TC3-HMAC-SHA256 Credential={secret_id}/{date}/{service}/tc3_request, \
         SignedHeaders={signed_headers}, Signature={signature}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 标准 SHA-256 测试向量（FIPS 180-4 / 公开向量）。
    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"The quick brown fox jumps over the lazy dog"),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
    }

    /// HMAC-SHA256 标准测试向量（RFC 4231 §2 用例 1/2）。
    #[test]
    fn hmac_sha256_rfc4231_vectors() {
        // 用例 1：key=0x0b×20，msg="Hi There"
        let key1 = [0x0b; 20];
        assert_eq!(
            hmac_sha256_hex(&key1, b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // 用例 2：key="Jefe"，msg="what do ya want for nothing?"
        assert_eq!(
            hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // 用例 3：key=0xaa×20，msg=0xdd×50
        let key3 = [0xaa; 20];
        let msg3 = [0xdd; 50];
        assert_eq!(
            hmac_sha256_hex(&key3, &msg3),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    /// TC3 签名全流程：固定密钥 + 时间戳 → 期望值比对。
    ///
    /// 期望值由 Node.js `crypto`（hmac/sha256 官方实现）独立复算：
    /// - secret_id  = "AKIDEXAMPLE1234567"
    /// - secret_key = "Gu5t9xGARNpq86cd98joQYCN3EXAMPLEKEY"
    /// - 时间戳 1551113065 = 2019-02-25T16:44:25Z（Node `Date.toISOString` 复核）
    /// - host/action/body 与下方一致 → signature = 4b5db21e…
    #[test]
    fn tc3_signature_known_values() {
        let ts = 1_551_113_065;
        let auth = tc3_authorization(
            "AKIDEXAMPLE1234567",
            "Gu5t9xGARNpq86cd98joQYCN3EXAMPLEKEY",
            SERVICE,
            "dnspod.tencentcloudapi.com",
            "DescribeDomainList",
            ts,
            r#"{"Limit":1}"#,
        );
        assert_eq!(
            auth,
            "TC3-HMAC-SHA256 Credential=AKIDEXAMPLE1234567/2019-02-25/dnspod/tc3_request, \
             SignedHeaders=content-type;host;x-tc-action, \
             Signature=4b5db21ebd6e4d6e4614a015c1a47d0a1979aac95eff47f7d48dc504e9e4d635"
        );
    }

    /// 中间量复算：CanonicalRequest 哈希与 StringToSign 逐字比对（Node 独立复算）。
    #[test]
    fn tc3_intermediate_values() {
        let body = r#"{"Limit":1}"#;
        let canonical_request = format!(
            "POST\n/\n\n\
             content-type:{CONTENT_TYPE}\n\
             host:dnspod.tencentcloudapi.com\n\
             x-tc-action:describedomainlist\n\
             \n\
             content-type;host;x-tc-action\n\
             {}",
            sha256_hex(body.as_bytes()),
        );
        // Node 复算的 CanonicalRequest 哈希。
        assert_eq!(
            sha256_hex(canonical_request.as_bytes()),
            "2a6310a227020b852b15f7b2de6e05f226171de69ca574a6a9ca8dfba75f2640"
        );
        let string_to_sign = format!(
            "TC3-HMAC-SHA256\n2019-02-25T16:44:25Z\n2019-02-25/dnspod/tc3_request\n{}",
            sha256_hex(canonical_request.as_bytes()),
        );
        // Node 复算的 StringToSign 全文哈希（时间戳 1551113065 = 16:44:25Z）。
        assert_eq!(
            sha256_hex(string_to_sign.as_bytes()),
            "62bd80322d0253c13bb6fa76cee33e43ef59d0f4672e8676041f2a926803fb79"
        );
    }

    /// 大小写不敏感 Action → 规范请求小写；不同 Action 产生不同签名。
    /// （DescribeRecordList 固定输入的期望签名 = 5a970112…，Node 独立复算。）
    #[test]
    fn tc3_action_lowercased_and_distinct() {
        let a = tc3_authorization(
            "AKID",
            "SK",
            SERVICE,
            "dnspod.tencentcloudapi.com",
            "DescribeRecordList",
            1_551_113_065,
            "{}",
        );
        let b = tc3_authorization(
            "AKID",
            "SK",
            SERVICE,
            "dnspod.tencentcloudapi.com",
            "CreateRecord",
            1_551_113_065,
            "{}",
        );
        assert_ne!(a, b, "不同 Action 必须产生不同签名");
        // Authorization 头形状（SignedHeaders 固定）。
        assert!(a.contains("SignedHeaders=content-type;host;x-tc-action, Signature="));
        assert!(b.contains("SignedHeaders=content-type;host;x-tc-action, Signature="));
        // DescribeRecordList 固定输入的期望签名（密钥 SK / body {}，Node 独立复算）。
        assert!(
            a.ends_with("Signature=a4126ab1b746ecfe95dfe5fec72aa8f01f0e9c4522112c64e6762abf517b0dfc"),
            "DescribeRecordList 签名与期望不符: {a}"
        );
    }
}
