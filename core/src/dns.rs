//! M8-T040 (W2-C / WBS 5.2~5.5): 域名模式加密 DNS 强制。
//!
//! 红线（DDNS-SEC-001 / 需求 §6.2）：**域名模式的连接解析只允许经
//! [`resolve_for_connect`] 此入口**——禁止新增 `to_socket_addrs` /
//! `TcpStream::connect(&str)` 直连调用（字符串形态会触发系统明文 DNS）。
//! 加密 DNS（DoH/DoT）全部端点不可用 → fail-closed 拒连（DDNS-DOH-003），
//! 绝不回退明文。
//!
//! 消费面：客户端域名模式（`resolve_peer`）+ 服务端域名模式启动自检
//! （[`server_dns_self_check`]，DDNS-DOH-002）。

use crate::connection::client::ConnectError;
use kirin_desk_dns::{DeviceMeta, IpFamily, RecordData, RecordType, Resolver, ResolverError};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// 域名模式唯一解析入口（红线）：经加密 DNS 解析 `host`，按地址族策略返回
/// 连接地址列表。
///
/// - `port`：连接端口（域名模式 = SRV 发现端口 / 配置端口）；
/// - 解析失败（全部端点不可用/超时）→ `ConnectError::EncryptedDnsRequired`
///   （fail-closed，DDNS-DOH-003）；其余异常 → `DnsResolveFailed`；
/// - `Auto` 族：IPv6 优先（与 `DeviceInfo::select_connect_addr` 语义一致）。
pub async fn resolve_for_connect(
    host: &str,
    port: u16,
    family: IpFamily,
    r: &dyn Resolver,
) -> Result<Vec<SocketAddr>, ConnectError> {
    // A 与 AAAA 并行查询（任一失败 = 加密 DNS 不可用 → fail-closed）。
    let (v4, v6) = tokio::join!(
        r.resolve(host, RecordType::A),
        r.resolve(host, RecordType::AAAA),
    );
    let v4_records = v4.map_err(|e| map_resolver_error(host, e))?;
    let v6_records = v6.map_err(|e| map_resolver_error(host, e))?;

    let mut v4_addrs: Vec<SocketAddr> = Vec::new();
    let mut v6_addrs: Vec<SocketAddr> = Vec::new();
    for rec in v4_records {
        if let RecordData::Plain(s) = &rec.data {
            if let Ok(ip) = s.parse::<Ipv4Addr>() {
                v4_addrs.push(SocketAddr::new(ip.into(), port));
            }
        }
    }
    for rec in v6_records {
        if let RecordData::Plain(s) = &rec.data {
            if let Ok(ip) = s.parse::<Ipv6Addr>() {
                v6_addrs.push(SocketAddr::new(ip.into(), port));
            }
        }
    }
    let addrs = match family {
        IpFamily::Ipv4 => v4_addrs,
        IpFamily::Ipv6 => v6_addrs,
        IpFamily::Auto => {
            if !v6_addrs.is_empty() {
                v6_addrs
            } else {
                v4_addrs
            }
        }
    };
    Ok(addrs)
}

/// 解析错误 → 连接错误（fail-closed 语义：全端点失败/总超时 = 加密 DNS 不可用）。
fn map_resolver_error(host: &str, e: ResolverError) -> ConnectError {
    match e {
        ResolverError::AllEndpointsFailed { .. } | ResolverError::Timeout => {
            ConnectError::EncryptedDnsRequired(e.to_string())
        }
        other => ConnectError::DnsResolveFailed {
            host: host.to_string(),
            err: other.to_string(),
        },
    }
}

/// 从 utils `[dns.security]` 配置构建加密解析器（CLI/GUI 接线共用，
/// WBS 5.6：mode=off 显式关闭 → `None`，域名模式 fail-closed + 提示）。
pub fn secure_resolver_from_config(
    cfg: &kirin_desk_utils::config::Config,
) -> Option<std::sync::Arc<dyn Resolver>> {
    let sec = &cfg.dns.security;
    if !sec.enforce() {
        return None; // mode=off：仅 IP 模式使用；域名模式不可用并提示（DDNS-DOH-007）
    }
    if sec.doh.is_empty() && sec.dot.is_empty() {
        return None;
    }
    Some(std::sync::Arc::new(kirin_desk_dns::SecureResolver::new_from_parts(
        sec.doh.clone(),
        sec.dot.clone(),
        sec.resolve_timeout_ms,
        sec.cache_ttl_secs,
    )))
}

/// 服务端域名模式启动自检（DDNS-DOH-002）：经加密 DNS 解析本机域名并校验
/// SRV/TXT/A/AAAA 发布一致性；返回告警列表（**空 = 一致**）。
///
/// - SRV：`_remote._tcp.{device_id}.{domain}` → 端口 = 监听端口；
/// - TXT：`{device_id}.{domain}` → `DeviceMeta` 公钥指纹一致；
/// - A：至少一条 A 记录（IPv4 可达性）；AAAA 缺失合法（IPv4-only 设备）。
///
/// 自检依赖的解析同样禁止明文（`r` 必为加密解析器；本函数不做任何回退）。
pub async fn server_dns_self_check(
    host: &str,
    srv_name: &str,
    expected_port: u16,
    expected_pubkey_b64: &str,
    r: &dyn Resolver,
) -> Result<Vec<String>, String> {
    let mut warnings: Vec<String> = Vec::new();

    // SRV：端口一致性。
    match r.resolve(srv_name, RecordType::SRV).await {
        Ok(records) => {
            let consistent = records.iter().any(|rec| {
                matches!(
                    &rec.data,
                    RecordData::Srv { port, .. } if *port == expected_port
                )
            });
            if !consistent {
                warnings.push(format!(
                    "SRV {srv_name} 未发布或端口不一致（期望 {expected_port}）——域名模式发现将不可用"
                ));
            }
        }
        Err(e) => warnings.push(format!("SRV 解析失败: {e}")),
    }

    // TXT：签名/公钥指纹一致性（DeviceMeta 可解析时精确比对）。
    match r.resolve(host, RecordType::TXT).await {
        Ok(records) => {
            let consistent = records.iter().any(|rec| {
                if let RecordData::Plain(s) = &rec.data {
                    match DeviceMeta::from_txt(s) {
                        Some(meta) => meta.raw_public_key() == Some(expected_pubkey_b64),
                        None => s.contains("ed25519:"),
                    }
                } else {
                    false
                }
            });
            if !consistent {
                warnings.push(format!(
                    "TXT {host} 未发布或签名指纹与本地身份不一致（TXT 公钥校验将失败）"
                ));
            }
        }
        Err(e) => warnings.push(format!("TXT 解析失败: {e}")),
    }

    // A：至少一条记录（域名可达性）。
    match r.resolve(host, RecordType::A).await {
        Ok(records) => {
            if records.is_empty() {
                warnings.push(format!("A {host} 无记录——域名模式客户端将无法解析本机"));
            }
        }
        Err(e) => warnings.push(format!("A 解析失败: {e}")),
    }

    // AAAA：可选（IPv4-only 设备合法；解析失败不告警——不阻塞）。
    let _ = r.resolve(host, RecordType::AAAA).await;

    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kirin_desk_dns::Record;
    use std::sync::Mutex;

    /// 可编程 mock 解析器（正常 / 全失败 / 空三路注入）。
    struct MockResolver {
        responses: Mutex<std::collections::HashMap<RecordType, Vec<Record>>>,
        always_fail: Mutex<bool>,
    }

    #[async_trait::async_trait]
    impl Resolver for MockResolver {
        async fn resolve(
            &self,
            _host: &str,
            rt: RecordType,
        ) -> Result<Vec<Record>, ResolverError> {
            if *self.always_fail.lock().unwrap() {
                return Err(ResolverError::AllEndpointsFailed {
                    detail: "mock 全部端点失败".into(),
                });
            }
            Ok(self
                .responses
                .lock()
                .unwrap()
                .get(&rt)
                .cloned()
                .unwrap_or_default())
        }
    }

    fn rec(rt: RecordType, data: RecordData) -> Record {
        Record {
            name: "my-pc.example.com".into(),
            rtype: rt,
            ttl: 300,
            data,
        }
    }

    fn mock_ok(v4: Vec<&str>, v6: Vec<&str>) -> MockResolver {
        MockResolver {
            responses: Mutex::new(std::collections::HashMap::from([
                (
                    RecordType::A,
                    v4.into_iter()
                        .map(|s| rec(RecordType::A, RecordData::Plain(s.into())))
                        .collect(),
                ),
                (
                    RecordType::AAAA,
                    v6.into_iter()
                        .map(|s| rec(RecordType::AAAA, RecordData::Plain(s.into())))
                        .collect(),
                ),
            ])),
            always_fail: Mutex::new(false),
        }
    }

    /// 正常解析：Auto 族 IPv6 优先。
    #[tokio::test]
    async fn test_resolve_for_connect_auto_prefers_v6() {
        let r = mock_ok(vec!["203.0.113.7"], vec!["2001:db8::1"]);
        let addrs = resolve_for_connect("my-pc.example.com", 3389, IpFamily::Auto, &r)
            .await
            .unwrap();
        assert_eq!(
            addrs,
            vec!["[2001:db8::1]:3389".parse::<SocketAddr>().unwrap()]
        );
    }

    /// 强制族：Ipv4 只取 A；Ipv6 只取 AAAA。
    #[tokio::test]
    async fn test_resolve_for_connect_forced_family() {
        let r = mock_ok(vec!["203.0.113.7"], vec!["2001:db8::1"]);
        let v4 = resolve_for_connect("h", 3389, IpFamily::Ipv4, &r).await.unwrap();
        assert_eq!(v4, vec!["203.0.113.7:3389".parse::<SocketAddr>().unwrap()]);
        let v6 = resolve_for_connect("h", 3389, IpFamily::Ipv6, &r).await.unwrap();
        assert_eq!(v6, vec!["[2001:db8::1]:3389".parse::<SocketAddr>().unwrap()]);
    }

    /// Auto 无 v6 → 回退 v4；无任何记录 → 空列表（非错误）。
    #[tokio::test]
    async fn test_resolve_for_connect_fallback_and_empty() {
        let r = mock_ok(vec!["203.0.113.7"], vec![]);
        let addrs = resolve_for_connect("h", 3389, IpFamily::Auto, &r).await.unwrap();
        assert_eq!(addrs, vec!["203.0.113.7:3389".parse::<SocketAddr>().unwrap()]);
        let r2 = mock_ok(vec![], vec![]);
        assert!(resolve_for_connect("h", 3389, IpFamily::Auto, &r2)
            .await
            .unwrap()
            .is_empty());
    }

    /// fail-closed：全部端点失败 → EncryptedDnsRequired（DDNS-DOH-003）。
    #[tokio::test]
    async fn test_resolve_for_connect_fail_closed() {
        let mut r = mock_ok(vec!["203.0.113.7"], vec![]);
        *r.always_fail.lock().unwrap() = true;
        let err = resolve_for_connect("h", 3389, IpFamily::Auto, &r)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ConnectError::EncryptedDnsRequired(_)),
            "全端点失败必须 fail-closed 拒连，got {err:?}"
        );
    }

    /// 非法记录数据（非 IP 字符串）→ 跳过（不产生地址，不报错）。
    #[tokio::test]
    async fn test_resolve_for_connect_skips_garbage() {
        let r = mock_ok(vec!["not-an-ip", "203.0.113.7"], vec![]);
        let addrs = resolve_for_connect("h", 3389, IpFamily::Ipv4, &r).await.unwrap();
        assert_eq!(addrs, vec!["203.0.113.7:3389".parse::<SocketAddr>().unwrap()]);
    }

    /// 服务端自检：一致 → 空告警；SRV 端口不一致 / TXT 指纹不符 / A 缺失 → 告警。
    #[tokio::test]
    async fn test_server_self_check_consistent() {
        let r = MockResolver {
            responses: Mutex::new(std::collections::HashMap::from([
                (
                    RecordType::SRV,
                    vec![rec(
                        RecordType::SRV,
                        RecordData::Srv {
                            priority: 0,
                            weight: 1,
                            port: 3389,
                            target: "my-pc.example.com".into(),
                        },
                    )],
                ),
                (
                    RecordType::TXT,
                    vec![rec(
                        RecordType::TXT,
                        RecordData::Plain(
                            r#"{"key":"ed25519:Ab3...","proto":"ip6desk","ver":"1"}"#.into(),
                        ),
                    )],
                ),
                (
                    RecordType::A,
                    vec![rec(RecordType::A, RecordData::Plain("203.0.113.7".into()))],
                ),
            ])),
            always_fail: Mutex::new(false),
        };
        // TXT 指纹比对：mock 公钥与期望不同 → 告警（精确比对语义）。
        let warns = server_dns_self_check(
            "my-pc.example.com",
            "_remote._tcp.my-pc.example.com",
            3389,
            "Ab3...",
            &r,
        )
        .await
        .unwrap();
        assert!(warns.is_empty(), "SRV 端口 + TXT 指纹 + A 一致 → 无告警，got {warns:?}");
    }

    #[tokio::test]
    async fn test_server_self_check_mismatch_alerts() {
        let r = MockResolver {
            responses: Mutex::new(std::collections::HashMap::from([
                // SRV 端口 ≠ 3389（例如 3390）
                (
                    RecordType::SRV,
                    vec![rec(
                        RecordType::SRV,
                        RecordData::Srv {
                            priority: 0,
                            weight: 1,
                            port: 3390,
                            target: "my-pc.example.com".into(),
                        },
                    )],
                ),
                // TXT 无 ed25519 字段
                (
                    RecordType::TXT,
                    vec![rec(
                        RecordType::TXT,
                        RecordData::Plain("hello".into()),
                    )],
                ),
                // A 缺失
                (RecordType::A, vec![]),
            ])),
            always_fail: Mutex::new(false),
        };
        let warns = server_dns_self_check(
            "my-pc.example.com",
            "_remote._tcp.my-pc.example.com",
            3389,
            "Ab3...",
            &r,
        )
        .await
        .unwrap();
        assert!(
            warns.iter().any(|w| w.contains("SRV")),
            "SRV 端口不一致必须告警: {warns:?}"
        );
        assert!(
            warns.iter().any(|w| w.contains("TXT")),
            "TXT 指纹不符必须告警: {warns:?}"
        );
        assert!(
            warns.iter().any(|w| w.contains("A ")),
            "A 记录缺失必须告警: {warns:?}"
        );
    }
}
