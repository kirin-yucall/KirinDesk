//! AWS SigV4 请求签名（M9-DNS005，手写实现）
//!
//! 组成：
//! - SHA-256（RFC 6234）与 HMAC-SHA256（RFC 2104）：workspace 虽有
//!   `hmac 0.12` / `sha2 0.10`，但 **未列入 dns/Cargo.toml 依赖**（且该文件
//!   禁止修改、禁止新增依赖），故在此手写实现，输出向量与 Node crypto 复算
//!   结果比对（见本文件 tests）。
//! - SigV4 流程：CanonicalRequest → StringToSign → 派生密钥链 →
//!   `Authorization: AWS4-HMAC-SHA256 Credential=..., SignedHeaders=host;x-amz-date, Signature=...`。
//!
//! 签名所需输入：method / canonical URI（已编码路径）/ canonical query /
//! host / x-amz-date（UTC `YYYYMMDDTHHMMSSZ`）/ payload SHA-256 hex。
//! 头部仅 `host;x-amz-date` 两个参与签名（Route53 不需要额外头）。

/// 空 payload 的 SHA-256（GET/DELETE 无 body 时使用）。
pub const EMPTY_PAYLOAD_HASH: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// SHA-256 压缩常量（前 64 个素数的立方根小数部分前 32 位，RFC 6234 §5.3.2）。
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

/// SHA-256 初始哈希值（前 8 个素数平方根小数部分前 32 位，RFC 6234 §5.3.3）。
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// 手写 SHA-256：返回 32 字节摘要。
pub fn sha256(data: &[u8]) -> [u8; 32] {
    // ── 填充：0x80 + 0x00... + 64 位大端比特长度 ──
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
        // ── 主循环 ──
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
    for (i, hv) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&hv.to_be_bytes());
    }
    out
}

/// SHA-256 的 hex 表示（payload 哈希与规范请求哈希用）。
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// HMAC-SHA256（RFC 2104）：返回 32 字节 MAC。
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // 密钥 > 64 字节 → 先哈希压缩；否则右侧补零到 64 字节。
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let h_inner = sha256(&inner);
    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&h_inner);
    sha256(&outer)
}

/// HMAC-SHA256 的 hex 表示（签名输出用）。
pub fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    hex::encode(hmac_sha256(key, data))
}

/// AWS SigV4 URI 编码（https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html）：
/// 保留 unreserved 字符 `A-Za-z0-9-._~`，其余字节（UTF-8）按 `%XX` 大写十六进制编码，
/// 空格必须编码为 `%20`（非 `+`）。
pub fn aws_uri_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*b as char);
            }
            _ => {
                // AWS 要求 %XX 为大写十六进制（%2F 而非 %2f）。
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

/// 构造 CanonicalRequest（供测试与签名复用）。
///
/// 结构（AWS 规范）：`method \n uri \n query \n headers \n \n signedHeaders \n payloadHash`——
/// headers 块后必须空一行再写 signedHeaders。
pub fn canonical_request(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    host: &str,
    amz_date: &str,
    payload_hash: &str,
) -> String {
    format!(
        "{method}\n{canonical_uri}\n{canonical_query}\nhost:{host}\nx-amz-date:{amz_date}\n\nhost;x-amz-date\n{payload_hash}"
    )
}

/// 构造 StringToSign。
pub fn string_to_sign(amz_date: &str, region: &str, service: &str, canonical_request: &str) -> String {
    let date = &amz_date[..8];
    format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{date}/{region}/{service}/aws4_request\n{}",
        sha256_hex(canonical_request.as_bytes())
    )
}

/// SigV4 派生签名密钥链：
/// `HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")`。
pub fn derive_signing_key(
    secret_access_key: &str,
    date: &str, // YYYYMMDD
    region: &str,
    service: &str,
) -> [u8; 32] {
    let k_date = hmac_sha256(format!("AWS4{secret_access_key}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// 最终签名（hex）。
pub fn signature(
    secret_access_key: &str,
    amz_date: &str,
    region: &str,
    service: &str,
    string_to_sign: &str,
) -> String {
    let key = derive_signing_key(secret_access_key, &amz_date[..8], region, service);
    hmac_sha256_hex(&key, string_to_sign.as_bytes())
}

/// 对查询参数对做 SigV4 规范编码并排序：
/// `key=aws_uri_encode(value)`，按 (key, value) 字典序排序，`&` 连接。
/// 返回的字符串同时直接用于请求 URL 的查询串（保证签名与发送一致）。
pub fn canonical_query(pairs: &[(String, String)]) -> String {
    let mut encoded: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| (aws_uri_encode(k), aws_uri_encode(v)))
        .collect();
    encoded.sort();
    encoded
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// 对完整请求做 SigV4 签名，返回 `Authorization` 头值。
///
/// `path` 为已做 URI 编码的请求路径（如 `/2013-04-01/hostedzone`）；
/// `query` 为原始查询参数对（未编码），内部统一编码排序；
/// `host` 为请求 URL 的主机[:端口]（须与发送的 Host 头一致）；
/// `payload_hash` 为 body 的 SHA-256 hex（无 body 用 [`EMPTY_PAYLOAD_HASH`]）；
/// `amz_date` 为 UTC `YYYYMMDDTHHMMSSZ`（测试可注入固定值）。
pub fn authorization_header(
    access_key_id: &str,
    secret_access_key: &str,
    region: &str,
    method: &str,
    path: &str,
    query: &[(String, String)],
    host: &str,
    payload_hash: &str,
    amz_date: &str,
) -> String {
    let service = "route53";
    let q = canonical_query(query);
    let cr = canonical_request(method, path, &q, host, amz_date, payload_hash);
    let sts = string_to_sign(amz_date, region, service, &cr);
    let sig = signature(secret_access_key, amz_date, region, service, &sts);
    let date = &amz_date[..8];
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key_id}/{date}/{region}/{service}/aws4_request, SignedHeaders=host;x-amz-date, Signature={sig}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 已知向量（FIPS 180-4 / 常用样例，与 Node crypto 复算一致）。
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
            sha256_hex(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    /// HMAC-SHA256 已知向量（RFC 4231 test case 1：key=0x0b×20，data="Hi There"）。
    #[test]
    fn hmac_sha256_rfc4231_case1() {
        let key = [0x0bu8; 20];
        assert_eq!(
            hmac_sha256_hex(&key, b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    /// AWS 官方文档示例（"Signature Calculations for the Authorization Header:
    /// Transferring to AWS (HTTP)"）：GET https://example.amazonaws.com/。
    /// 期望值来自 AWS 文档，与 Node crypto 复算一致。
    #[test]
    fn sigv4_classic_aws_docs_vector() {
        let method = "GET";
        let path = "/";
        let host = "example.amazonaws.com";
        let amz_date = "20150830T123600Z";
        let cr = canonical_request(method, path, "", host, amz_date, EMPTY_PAYLOAD_HASH);
        assert_eq!(
            cr,
            "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let sts = string_to_sign(amz_date, "us-east-1", "service", &cr);
        assert_eq!(
            sts,
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nbb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
        );
        let sig = signature(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            amz_date,
            "us-east-1",
            "service",
            &sts,
        );
        assert_eq!(sig, "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
    }

    /// Route53 GET 请求签名（带查询串 maxitems=100），固定密钥/时间戳 → 期望值比对。
    #[test]
    fn sigv4_route53_get_vector() {
        let auth = authorization_header(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "GET",
            "/2013-04-01/hostedzone",
            &[("maxitems".to_string(), "100".to_string())],
            "route53.amazonaws.com",
            EMPTY_PAYLOAD_HASH,
            "20230101T000000Z",
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/route53/aws4_request, \
             SignedHeaders=host;x-amz-date, Signature=e25e87033baaf14cd8c7569b77b19842ec4ef3e16d30e228bdc2fdb3cf0288b3"
        );
    }

    /// Route53 POST 请求签名（ChangeResourceRecordSets body），验证 payload 哈希参与。
    #[test]
    fn sigv4_route53_post_vector() {
        let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ChangeResourceRecordSetsRequest \
            xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\"><ChangeBatch><Changes><Change>\
            <Action>UPSERT</Action><ResourceRecordSet><Name>example.com.</Name><Type>A</Type>\
            <TTL>600</TTL><ResourceRecords><ResourceRecord><Value>192.0.2.1</Value>\
            </ResourceRecord></ResourceRecords></ResourceRecordSet></Change></Changes></ChangeBatch>\
            </ChangeResourceRecordSetsRequest>";
        let payload_hash = sha256_hex(body.as_bytes());
        assert_eq!(
            payload_hash,
            "0a2f0e72ac6ed019463493fea0b7216e12defd8078c3ceca33caf43f18a1e53b"
        );
        let auth = authorization_header(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "POST",
            "/2013-04-01/hostedzone/Z1PA6795UKMFR9/rrset",
            &[],
            "route53.amazonaws.com",
            &payload_hash,
            "20230101T000000Z",
        );
        assert!(auth.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/route53/aws4_request, SignedHeaders=host;x-amz-date, Signature="
        ));
        assert!(auth.ends_with(", Signature=19f3a706de1c22ee1cf48c4183dcdd7a07a6a48bdd4718f06a50d45dabb6ab36"));
    }

    /// URI 编码：unreserved 字符保留；空格/%XX 大写；保留字节编码。
    #[test]
    fn aws_uri_encode_rules() {
        assert_eq!(aws_uri_encode("_sip._tcp.example.com."), "_sip._tcp.example.com.");
        assert_eq!(aws_uri_encode("a b"), "a%20b");
        assert_eq!(aws_uri_encode("a/b:c"), "a%2Fb%3Ac");
        assert_eq!(aws_uri_encode("AKIA-1_2.3~"), "AKIA-1_2.3~");
    }

    /// 规范查询串排序 + 编码：dots/underscores 保留。
    #[test]
    fn canonical_query_sorted_encoded() {
        let q = canonical_query(&[
            ("name".to_string(), "_sip._tcp.example.com.".to_string()),
            ("type".to_string(), "SRV".to_string()),
        ]);
        assert_eq!(q, "name=_sip._tcp.example.com.&type=SRV");
        // 该固定请求的签名向量（Node crypto 复算）。
        let auth = authorization_header(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "GET",
            "/2013-04-01/hostedzone/Z1PA6795UKMFR9/rrset",
            &[
                ("name".to_string(), "_sip._tcp.example.com.".to_string()),
                ("type".to_string(), "SRV".to_string()),
            ],
            "route53.amazonaws.com",
            EMPTY_PAYLOAD_HASH,
            "20230101T000000Z",
        );
        assert!(auth.ends_with(", Signature=291168f2a5fb8ba2ab6b5a84643100e466f31a2ae7c3d89c84d83e2e40793f9c"));
    }
}
