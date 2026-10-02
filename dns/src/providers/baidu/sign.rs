//! M9-DNS016: 百度智能云 BCE 签名（bce-auth-v1，HMAC-SHA256）
//!
//! 官方规范：https://cloud.baidu.com/doc/Reference/s/2jxvb6vnf
//! 认证字符串：`bce-auth-v1/{AK}/{timestamp}/{expiration}/{signedHeaders}/{signature}`
//!
//! 计算步骤：
//! 1. `AuthStringPrefix = bce-auth-v1/{ak}/{ts}/{expiration}`；
//! 2. `SigningKey = HMAC-SHA256-HEX(sk, AuthStringPrefix)`（**hex 字符串**，作为下一步 HMAC 的 key）；
//! 3. `CanonicalRequest = Method\nCanonicalURI\nCanonicalQueryString\nCanonicalHeaders`；
//! 4. `Signature = HMAC-SHA256-HEX(SigningKey, CanonicalRequest)`。
//!
//! 依赖说明：workspace 的 `dns` crate 未直接声明 `sha2/hmac`，故本模块内嵌
//! 纯 Rust SHA-256 实现（FIPS 180-4）与 HMAC 构造，并有标准测试向量兜底。

use std::collections::BTreeMap;

/// RFC3986 严格百分号编码（字母数字及 `-_.~` 不编码，其余 `%XX` 大写）。
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

/// 规范化查询串：参数按 key ASCII 升序，key/value 均 RFC3986 编码，`&` 连接。
pub fn canonical_query(params: &BTreeMap<String, String>) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", pct_encode(k), pct_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

// ─────────────────────────── 纯 Rust SHA-256 ───────────────────────────

/// FIPS 180-4 常量 K（前 64 个素数立方根小数部分前 32 位）。
#[rustfmt::skip]
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// 初始链接变量 H0（前 8 个素数平方根小数部分前 32 位）。
#[rustfmt::skip]
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

/// 计算 SHA-256 摘要（FIPS 180-4）。
pub fn sha256(data: &[u8]) -> [u8; 32] {
    // 1. 填充：0x80 + 0x00* + 8 字节大端比特长度，总长 ≡ 0 (mod 64)。
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut h = H0;
    for chunk in msg.chunks_exact(64) {
        // 2. 消息调度。
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let o = i * 4;
            *word = u32::from_be_bytes([chunk[o], chunk[o + 1], chunk[o + 2], chunk[o + 3]]);
        }
        for t in 16..64 {
            let s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3);
            let s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10);
            w[t] = w[t - 16]
                .wrapping_add(s0)
                .wrapping_add(w[t - 7])
                .wrapping_add(s1);
        }
        // 3. 压缩函数。
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for t in 0..64 {
            let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        // 4. 累加。
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// SHA-256 的 hex 形态。
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// HMAC-SHA256（标准构造：`H((K⊕opad) || H((K⊕ipad) || msg))`，块长 64 字节）。
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut key = key.to_vec();
    if key.len() > 64 {
        key = sha256(&key).to_vec();
    }
    key.resize(64, 0);
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner_hash = sha256(&inner);
    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// HMAC-SHA256 的 hex 形态。
pub fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    hex::encode(hmac_sha256(key, msg))
}

// ─────────────────────────── BCE 认证字符串 ───────────────────────────

/// 规范请求：`Method\nCanonicalURI\nCanonicalQueryString\nCanonicalHeaders`。
///
/// `path` 为**已编码**路径（各段 RFC3986 编码、`/` 保留）；
/// `host` 为请求 Host 头（小写）；`x_bce_date` 与请求头一致。
pub fn canonical_request(
    method: &str,
    path: &str,
    query: &BTreeMap<String, String>,
    host: &str,
    x_bce_date: &str,
) -> String {
    let q = canonical_query(query);
    let headers = format!("host:{host}\nx-bce-date:{x_bce_date}\n");
    format!("{method}\n{path}\n{q}\n{headers}")
}

/// 计算完整 Authorization 头。
///
/// 返回 `bce-auth-v1/{ak}/{ts}/{exp}/host;x-bce-date/{signature}`。
pub fn bce_authorization(
    method: &str,
    path: &str,
    query: &BTreeMap<String, String>,
    host: &str,
    x_bce_date: &str,
    access_key_id: &str,
    secret_access_key: &str,
    expiration: u32,
) -> String {
    let auth_prefix = format!("bce-auth-v1/{access_key_id}/{x_bce_date}/{expiration}");
    // SigningKey 为 hex 字符串，作为下一步 HMAC 的 key（BCE 规范）。
    let signing_key = hmac_sha256_hex(secret_access_key.as_bytes(), auth_prefix.as_bytes());
    let canonical = canonical_request(method, path, query, host, x_bce_date);
    let signature = hmac_sha256_hex(signing_key.as_bytes(), canonical.as_bytes());
    format!("{auth_prefix}/host;x-bce-date/{signature}")
}

/// 对 URL 路径做规范化编码（按 `/` 分段，逐段 RFC3986 编码，`/` 保留）。
pub fn encode_path(path: &str) -> String {
    path.split('/')
        .map(|seg| pct_encode(seg))
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 标准测试向量（NIST）。
    #[test]
    fn sha256_nist_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    /// BCE 官方示例（BOS）：AK/SK 固定，验证 SigningKey 与官方值一致。
    /// 参考：https://cloud.baidu.com/doc/Reference/s/njwvz1yfu-intl
    #[test]
    fn bce_official_signing_key_vector() {
        let ak = "a".repeat(32);
        let sk = "b".repeat(32);
        let auth_prefix = format!("bce-auth-v1/{ak}/2015-04-27T08:23:49Z/1800");
        assert_eq!(
            hmac_sha256_hex(sk.as_bytes(), auth_prefix.as_bytes()),
            "1d5ce5f464064cbee060330d973218821825ac6952368a482a592e6615aef479"
        );
    }

    /// BCE 完整认证字符串（固定向量，与独立实现（node crypto）交叉验证）。
    #[test]
    fn bce_full_authorization_vector() {
        let ak = "a".repeat(32);
        let sk = "b".repeat(32);
        let mut query = BTreeMap::new();
        query.insert("maxKeys".into(), "1000".into());
        let auth = bce_authorization(
            "GET",
            "/v1/dns/zone",
            &query,
            "dns.baidubce.com",
            "2015-04-27T08:23:49Z",
            &ak,
            &sk,
            1800,
        );
        assert_eq!(
            auth,
            "bce-auth-v1/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/2015-04-27T08:23:49Z/1800/host;x-bce-date/\
             62302b6547878a6f4dbdbb9866ef20425c2a963e4cd364b6add243a3472e6068"
        );
    }

    /// RFC3986 编码与路径编码。
    #[test]
    fn pct_and_path_encoding() {
        assert_eq!(pct_encode("AZaz09-_.~"), "AZaz09-_.~");
        assert_eq!(pct_encode("a b*"), "a%20b%2A");
        assert_eq!(encode_path("/v1/dns/zone/example.com/record"), "/v1/dns/zone/example.com/record");
        assert_eq!(encode_path("/v1/dns/zone/a b/record"), "/v1/dns/zone/a%20b/record");
    }

    /// HMAC-SHA256 RFC 4231 用例 1：key=0x0b×20, data="Hi There"。
    #[test]
    fn hmac_sha256_rfc4231_case1() {
        let key = [0x0bu8; 20];
        assert_eq!(
            hmac_sha256_hex(&key, b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }
}
