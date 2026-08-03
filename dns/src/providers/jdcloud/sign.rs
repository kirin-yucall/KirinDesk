//! M9-DNS018: 京东云 JDCLOUD2-HMAC-SHA256 签名（手写 SHA-256 / HMAC-SHA256）
//!
//! 官方文档：
//! - 签名算法：https://docs.jdcloud.com/cn/common-declaration/api/authorization-rules
//!   （任务 1~4：规范化请求 → 待签字符串 → 派生密钥 → Authorization 头）；
//! - 云解析产品：`domainservice`（端点 `https://domainservice.jdcloud-api.com`）。
//!
//! 依赖说明：workspace 虽有 `sha2 0.10` / `hmac 0.12`，但 **未列入
//! dns/Cargo.toml 依赖**（该文件禁止修改、禁止新增依赖），故本文件手写
//! SHA-256（RFC 6234 §5）与 HMAC-SHA256（RFC 2104）。官方文档「签名步骤示例」
//! 的完整向量（含 kDate/kRegion/kService/kSigning 中间值与最终 signResult）
//! 已用 Node.js `crypto` 独立复算并固化在本文件 tests（双实现互证）。
//!
//! JDCLOUD2 步骤：
//! 1. `CanonicalRequest`（每行以 `\n` 结尾）：
//!    ```text
//!    {HTTP 方法（大写）}
//!    {规范 URI（RFC3986 逐段编码，保留 /）}
//!    {规范查询串（参数名按字符码点升序，名称/值 RFC3986 编码）}
//!    {规范头（小写名:去首尾空白值\n，按名排序）}
//!    {SignedHeaders（小写、按名排序、; 分隔）}
//!    {hex(sha256(body))，空 body 用空串哈希}
//!    ```
//! 2. `StringToSign`：
//!    ```text
//!    JDCLOUD2-HMAC-SHA256
//!    {YYYYMMDDTHHMMSSZ（= x-jdcloud-date 头）}
//!    {YYYYMMDD}/{region}/{service}/jdcloud2_request
//!    {hex(sha256(CanonicalRequest))}
//!    ```
//! 3. 派生密钥：`kDate = HMAC("JDCLOUD2"+secret_key, YYYYMMDD)` →
//!    `kRegion = HMAC(kDate, region)` → `kService = HMAC(kRegion, service)` →
//!    `kSigning = HMAC(kService, "jdcloud2_request")`。
//! 4. `Signature = hex(HMAC(kSigning, StringToSign))`。
//!
//! 请求头：`x-jdcloud-algorithm` / `x-jdcloud-date` / `x-jdcloud-nonce` /
//! `authorization`；`Authorization` 格式：
//! `JDCLOUD2-HMAC-SHA256 Credential={AK}/{date}/{region}/{service}/jdcloud2_request,
//! SignedHeaders=…, Signature=…`。参与签名的头与官方 SDK 一致：
//! `content-type;x-jdcloud-date;x-jdcloud-nonce`（host 不参与签名）。

/// 签名算法名（同时是 x-jdcloud-algorithm 头值）。
pub const ALGORITHM: &str = "JDCLOUD2-HMAC-SHA256";
/// 派生密钥终止串。
pub const TERMINATOR: &str = "jdcloud2_request";
/// 京东云云解析服务名（端点 `domainservice.jdcloud-api.com` 的子域）。
pub const SERVICE: &str = "domainservice";
/// Content-Type 固定值。
pub const CONTENT_TYPE: &str = "application/json";

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
    // ── 填充：0x80 + 0x00… + 64 位大端比特长度 ──
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

/// RFC3986 严格百分号编码：字母数字及 `-_.~` 不编码，其余 `%XX`（十六进制大写）。
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

/// 规范 URI：RFC3986 逐段编码，保留 `/`；空路径 → `/`。
fn canonical_uri(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if c == '/' {
            out.push('/');
        } else {
            out.push_str(&pct_encode(&c.to_string()));
        }
    }
    out
}

/// 规范查询串：参数按编码名升序（字符码点），名称/值 RFC3986 编码，`&` 连接。
/// 重复键保持传入顺序（本客户端不产生重复键）。
fn canonical_query(params: &[(&str, &str)]) -> String {
    let mut encoded: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (pct_encode(k), pct_encode(v)))
        .collect();
    encoded.sort_by(|a, b| a.0.cmp(&b.0));
    encoded
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// JDCLOUD2 签名（返回 `Authorization` 请求头值）。
///
/// 入参：
/// - `access_key` / `secret_key`：京东云 AK/SK；
/// - `region`：地域（如 `cn-north-1`，同时进 Credential scope 与派生密钥）；
/// - `service`：产品服务名（云解析 = "domainservice"）；
/// - `date_time`：`x-jdcloud-date` 头值 `YYYYMMDDTHHMMSSZ`（UTC）；
/// - `method`：HTTP 方法（大写）；
/// - `path`：请求路径（如 `/v2/regions/cn-north-1/domain`）；
/// - `query`：查询参数（未编码的键值对）；
/// - `headers`：参与签名的头（小写名 + 原值，仅取去首尾空白后的值；
///   须含 `x-jdcloud-date`，`x-jdcloud-nonce` 经此传入并参与签名）；
/// - `body`：请求体字节。
pub fn jdcloud2_authorization(
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str,
    date_time: &str,
    method: &str,
    path: &str,
    query: &[(&str, &str)],
    headers: &[(&str, &str)],
    body: &[u8],
) -> String {
    // ── 步骤 1：CanonicalRequest ──
    let mut sorted_headers: Vec<(&str, &str)> = headers.to_vec();
    sorted_headers.sort_by(|a, b| a.0.cmp(b.0));
    let signed_headers = sorted_headers
        .iter()
        .map(|(k, _)| *k)
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers: String = sorted_headers
        .iter()
        .map(|(k, v)| format!("{k}:{}\n", v.trim()))
        .collect();

    let canonical_request = format!(
        "{method}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{}",
        canonical_uri(path),
        canonical_query(query),
        sha256_hex(body),
    );

    // ── 步骤 2：StringToSign ──
    let date = &date_time[..8]; // YYYYMMDD
    let string_to_sign = format!(
        "{ALGORITHM}\n{date_time}\n{date}/{region}/{service}/{TERMINATOR}\n{}",
        sha256_hex(canonical_request.as_bytes()),
    );

    // ── 步骤 3：派生密钥链（JDCLOUD2 前缀）──
    let k_date = hmac_sha256(format!("JDCLOUD2{secret_key}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, TERMINATOR.as_bytes());

    // ── 步骤 4：签名 ──
    let signature = hmac_sha256_hex(&k_signing, string_to_sign.as_bytes());
    format!(
        "{ALGORITHM} Credential={access_key}/{date}/{region}/{service}/{TERMINATOR}, \
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

    /// HMAC-SHA256 标准测试向量（RFC 4231 §2 用例 1/2/3）。
    #[test]
    fn hmac_sha256_rfc4231_vectors() {
        let key1 = [0x0b; 20];
        assert_eq!(
            hmac_sha256_hex(&key1, b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let key3 = [0xaa; 20];
        let msg3 = [0xdd; 50];
        assert_eq!(
            hmac_sha256_hex(&key3, &msg3),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    /// RFC3986 编码。
    #[test]
    fn pct_encode_works() {
        assert_eq!(pct_encode("code=200"), "code%3D200");
        assert_eq!(pct_encode("o=%"), "o%3D%25");
        assert_eq!(pct_encode("a-b_c.d~Z0"), "a-b_c.d~Z0");
        assert_eq!(pct_encode("资源:action"), "%E8%B5%84%E6%BA%90%3Aaction");
    }

    /// 官方文档「签名步骤示例」完整向量（含全部中间值）：
    /// https://docs.jdcloud.com/cn/common-declaration/api/authorization-rules
    ///
    /// AK=TESTAK / SK=TESTSK / date=20190214T104514Z / region=cn-north-1 /
    /// service=test / POST /v1/resource:action?p1=p1&p0=p0&o=%&u=u /
    /// 签名头 x-jdcloud-date;x-jdcloud-nonce;x-my-header;x-my-header_blank /
    /// body="body data" → signResult=2a98f83c…
    #[test]
    fn official_doc_vector_end_to_end() {
        let headers = [
            ("x-jdcloud-date", "20190214T104514Z"),
            ("x-jdcloud-nonce", "testnonce"),
            ("x-my-header", "test"),
            ("x-my-header_blank", " blank"), // 值含前导空白 → 规范形式去空白
        ];
        let query = [("p1", "p1"), ("p0", "p0"), ("o", "%"), ("u", "u")];
        let auth = jdcloud2_authorization(
            "TESTAK",
            "TESTSK",
            "cn-north-1",
            "test",
            "20190214T104514Z",
            "POST",
            "/v1/resource:action",
            &query,
            &headers,
            b"body data",
        );
        assert_eq!(
            auth,
            "JDCLOUD2-HMAC-SHA256 Credential=TESTAK/20190214/cn-north-1/test/jdcloud2_request, \
             SignedHeaders=x-jdcloud-date;x-jdcloud-nonce;x-my-header;x-my-header_blank, \
             Signature=2a98f83c074e7bee260bfc8ef64f009c07595bd93f7f0c3f4e156bf6479ed9bf"
        );
    }

    /// 官方向量中间值逐项复算（kDate/kRegion/kService/kSigning 与文档一致）。
    #[test]
    fn official_doc_vector_intermediate_keys() {
        let k_date = hmac_sha256(b"JDCLOUD2TESTSK", b"20190214");
        assert_eq!(
            hex::encode(k_date),
            "dbbdee87f18afeedd6456923587f5323b90c3a77fbc6e381b243c90c672d5daf"
        );
        let k_region = hmac_sha256(&k_date, b"cn-north-1");
        assert_eq!(
            hex::encode(k_region),
            "78e1da51757851329da8e31a6bad9f509c4816cacb8d5b2b9d171e49498ce4b6"
        );
        let k_service = hmac_sha256(&k_region, b"test");
        assert_eq!(
            hex::encode(k_service),
            "44050ec21c8e839f36ff5b2d44ec4a5876f4ffd6ef9a7a692a3eba40396bdb68"
        );
        let k_signing = hmac_sha256(&k_service, b"jdcloud2_request");
        assert_eq!(
            hex::encode(k_signing),
            "a4e50bcb6001be0008696b173c30172b5ce22a77db00d21c6a9d69de2ba33b7d"
        );
    }

    /// 官方向量规范请求中间量：URI 冒号编码、查询排序与 % 编码、头值去空白。
    #[test]
    fn official_doc_vector_canonical_request() {
        let headers = [
            ("x-jdcloud-date", "20190214T104514Z"),
            ("x-jdcloud-nonce", "testnonce"),
            ("x-my-header", "test"),
            ("x-my-header_blank", " blank"),
        ];
        let query = [("p1", "p1"), ("p0", "p0"), ("o", "%"), ("u", "u")];
        let mut sorted_headers: Vec<(&str, &str)> = headers.to_vec();
        sorted_headers.sort_by(|a, b| a.0.cmp(b.0));
        let canonical_headers: String = sorted_headers
            .iter()
            .map(|(k, v)| format!("{k}:{}\n", v.trim()))
            .collect();
        let canonical_request = format!(
            "POST\n{}\n{}\n{canonical_headers}\n{}\n{}",
            canonical_uri("/v1/resource:action"),
            canonical_query(&query),
            sorted_headers
                .iter()
                .map(|(k, _)| *k)
                .collect::<Vec<_>>()
                .join(";"),
            sha256_hex(b"body data"),
        );
        assert_eq!(
            canonical_request,
            "POST\n/v1/resource%3Aaction\no=%25&p0=p0&p1=p1&u=u\n\
             x-jdcloud-date:20190214T104514Z\nx-jdcloud-nonce:testnonce\n\
             x-my-header:test\nx-my-header_blank:blank\n\n\
             x-jdcloud-date;x-jdcloud-nonce;x-my-header;x-my-header_blank\n\
             e51832a118eeff7ad976d635b7d04538e362e4c21bd0f6253580b0a83a209074"
        );
        // 文档给出的 HashedCanonicalRequest。
        assert_eq!(
            sha256_hex(canonical_request.as_bytes()),
            "fb2e317056269590681d091f8eb22272967c0b922b2deda887312215ea4eed4c"
        );
    }

    /// 本客户端实际请求形态的签名基准（固定输入，Node.js `crypto` 独立复算）：
    /// GET /v2/regions/cn-north-1/domain?pageNumber=1&pageSize=100，
    /// 签名头 content-type;x-jdcloud-date;x-jdcloud-nonce，空 body。
    #[test]
    fn dns_client_shape_vector() {
        let headers = [
            ("content-type", CONTENT_TYPE),
            ("x-jdcloud-date", "20260803T120000Z"),
            ("x-jdcloud-nonce", "abcdef0123456789"),
        ];
        let query = [("pageNumber", "1"), ("pageSize", "100")];
        let auth = jdcloud2_authorization(
            "TESTAK",
            "TESTSK",
            "cn-north-1",
            SERVICE,
            "20260803T120000Z",
            "GET",
            "/v2/regions/cn-north-1/domain",
            &query,
            &headers,
            b"",
        );
        assert_eq!(
            auth,
            "JDCLOUD2-HMAC-SHA256 Credential=TESTAK/20260803/cn-north-1/domainservice/jdcloud2_request, \
             SignedHeaders=content-type;x-jdcloud-date;x-jdcloud-nonce, \
             Signature=dd557f3b55275447b3b0c65bfbfc8e6133746c331d6ad97d6a0fb9157608ebc4"
        );
    }

    /// POST 带 body 形态（createResourceRecord）签名基准（Node 独立复算）。
    #[test]
    fn dns_client_post_body_vector() {
        let headers = [
            ("content-type", CONTENT_TYPE),
            ("x-jdcloud-date", "20260803T120000Z"),
            ("x-jdcloud-nonce", "abcdef0123456789"),
        ];
        let body = r#"{"hostRecord":"www","hostValue":"1.2.3.4","ttl":600,"type":"A","viewValue":[-1]}"#;
        let auth = jdcloud2_authorization(
            "TESTAK",
            "TESTSK",
            "cn-north-1",
            SERVICE,
            "20260803T120000Z",
            "POST",
            "/v2/regions/cn-north-1/domain/42/ResourceRecord",
            &[],
            &headers,
            body.as_bytes(),
        );
        assert_eq!(
            auth,
            "JDCLOUD2-HMAC-SHA256 Credential=TESTAK/20260803/cn-north-1/domainservice/jdcloud2_request, \
             SignedHeaders=content-type;x-jdcloud-date;x-jdcloud-nonce, \
             Signature=4de8d1f9bde792fe306312957ebf8db56a772144eaa19e99bb236c4afcc78442"
        );
    }
}
