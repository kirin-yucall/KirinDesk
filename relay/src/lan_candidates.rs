//!
//!
//! ## 嵌套 NAT 可达性矩阵（场景 B）
//!
//! | 对端位置 | a1（R1 段）可达 a2 上报的 R2 私网地址？ | 结论 |
//! |---|---|---|
//! | a2 同在 R1 段 | 可达（同子网） | LAN 候选直连（本模块保证上报） |
//! | a2 在 R2 下（R2 挂 R1） | 不可达（R2 子网对 a1 是黑洞） | 并行尝试快速失败 → punch → relay 兜底（现状路径，不回归） |
//! | a2 在 R2 下，a1 也在 R2 下 | 可达（同 R2 子网） | LAN 候选直连（双方都上报 R2 段地址） |
//!
//! a2 额外上报「R2 WAN 侧地址」：**不做**。R2 WAN 地址对 a2 不可知
//! （需 UPnP/STUN 探测）；UPnP 在运营商光猫/路由器上普遍关闭且涉及
//! 网络写操作（开端口映射，超出「候选上报/排序」任务边界与安全口径），
//! STUN 探测得到的映射地址与 relay `observed_addr`（服务器观察地址）
//! 信息重合——而后者已由 registry 兜底附加。投入产出比低且不可靠。
//!
//! ## CGNAT 100.64.0.0/10（场景 A，RFC 6598）——排除
//!
//! 该段是运营商内部共享地址空间（运营商级 NAT 各用户共用），**跨用户
//! 不可路由**：对端连接 100.x 候选必然超时/被运营商网关丢弃。上报只会
//! 占用 `MAX_CANDIDATES`（16）名额、拖慢控制端全失败路径。移动宽带
//! 大局域网场景（跨子网 10.x 互不可达）靠第 1/2 项短超时快速失败。
//!
//! ## IPv6 链路本地 fe80::/10 与 zone-id——排除
//!
//! 跨机 fe80 连接必须携带 scope-id（出接口标识）。`get-if-addrs` 只给
//! `IpAddr`（无 scope），候选 `SocketAddr` 的 scope_id 只能是 0 → 连接
//! 对端 fe80 地址时内核无法选路（Windows/Linux 均报 invalid argument
//! 或路由失败）。故排除 fe80；ULA（fc00::/7）与全局单播 v6 正常上报。
//!
//! ## 优先级设计（registry 按 priority 降序，observed=200 追加后同排）
//!
//! | 候选 | priority | 依据 |
//! |---|---|---|
//! | relay 观察地址（公网 NAT 映射） | 200（既有） | 打洞关键信息（ID-002） |
//! | `[tunnel] extra_candidates`（用户手配） | 150（既有） | 用户显式意图 |
//! | **RFC1918 / ULA（本模块新增 LAN 档）** | **210** | 同网段对端必直通（用户裁定），排序最前 |
//! | 公网 v4 / 全局 v6（普通接口地址） | 100（既有 LOCAL 档） | 可直达但非同网段 |
//!
//! 控制端 `try_direct` 为并行全试（首个成功者胜出），排序不影响成功
//! 时延；priority 210 使 LAN 候选在 DeviceInfo 列表居首（日志/后续
//! 截断场景下同网段优先保留）。
//!
//! ## 控制端尝试超时决策
//!
//! 并行尝试下不可达私网候选**不会拖慢成功路径**（任一候选成功即返回）；
//! 只有全部候选失败（嵌套 NAT/跨子网不可达）时，整体等待 = 最慢单候选
//! 超时。故对私网/CGNAT 类候选用更短超时（1s，[`PRIVATE_DIRECT_ATTEMPT_TIMEOUT`]）
//! 收敛全失败路径，公网保持 2s（[`DIRECT_ATTEMPT_TIMEOUT`] 语义，见
//! `core::connection::id_mode`）。跨子网 RFC1918（10.x 不同段）失败
//! 通常表现为 RST/超时，1s 足够区分。

use std::net::IpAddr;
use std::time::Duration;

/// 同网段对端候选排序最前（见模块级研究结论表）。
pub const LAN_CANDIDATE_PRIORITY: u8 = 210;

/// 下收敛全失败路径（嵌套 NAT / 跨子网场景 1s 内快速失败进 punch/relay）。
pub const PRIVATE_DIRECT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanAddrClass {
    /// RFC1918 私网（10/8、172.16/12、192.168/16）——上报，LAN 档。
    PrivateV4,
    /// IPv6 ULA（fc00::/7，实践为 fd00::/8）——上报，LAN 档。
    UlaV6,
    /// IPv6 全局单播——上报，LOCAL 档（可直达，非同网段）。
    GlobalV6,
    /// 公网 IPv4——上报，LOCAL 档。
    PublicV4,
    /// CGNAT 100.64.0.0/10（RFC 6598）——排除（跨用户不可路由，见模块注释）。
    CgnatV4,
    /// IPv4 链路本地 169.254.0.0/16（APIPA）——排除（无 DHCP 临时地址，不可靠）。
    LinkLocalV4,
    /// IPv6 链路本地 fe80::/10——排除（跨机需 zone-id，候选无法携带，见模块注释）。
    LinkLocalV6,
    /// 回环——排除。
    Loopback,
    /// 多播（v4 224.0.0.0/4、v6 ff00::/8）——排除。
    Multicast,
    /// 未指定地址（0.0.0.0 / ::）——排除。
    Unspecified,
}

pub fn classify_ip(ip: IpAddr) -> LanAddrClass {
    if ip.is_unspecified() {
        return LanAddrClass::Unspecified;
    }
    if ip.is_loopback() {
        return LanAddrClass::Loopback;
    }
    if ip.is_multicast() {
        return LanAddrClass::Multicast;
    }
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_link_local() {
                LanAddrClass::LinkLocalV4
            } else if is_cgnat(v4) {
                LanAddrClass::CgnatV4
            } else if v4.is_private() {
                LanAddrClass::PrivateV4
            } else {
                LanAddrClass::PublicV4
            }
        }
        IpAddr::V6(v6) => {
            if is_link_local_v6(v6) {
                LanAddrClass::LinkLocalV6
            } else if is_ula(v6) {
                LanAddrClass::UlaV6
            } else {
                LanAddrClass::GlobalV6
            }
        }
    }
}

/// CGNAT 100.64.0.0/10：首字节 100 且次字节 ∈ [64,127]（RFC 6598）。
fn is_cgnat(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xC0) == 0x40
}

/// 链路本地 fe80::/10：首 10 位 1111111010（fe80::–febf:…）。
fn is_link_local_v6(v6: std::net::Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xFFC0) == 0xFE80
}

/// ULA fc00::/7：地址首 7 位为 1111110（fc00::–fdff:…）。
fn is_ula(v6: std::net::Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xFE00) == 0xFC00
}

pub fn is_reportable_candidate(ip: IpAddr) -> bool {
    !matches!(
        classify_ip(ip),
        LanAddrClass::CgnatV4
            | LanAddrClass::LinkLocalV4
            | LanAddrClass::LinkLocalV6
            | LanAddrClass::Loopback
            | LanAddrClass::Multicast
            | LanAddrClass::Unspecified
    )
}

pub fn candidate_priority(ip: IpAddr) -> Option<u8> {
    match classify_ip(ip) {
        LanAddrClass::PrivateV4 | LanAddrClass::UlaV6 => Some(LAN_CANDIDATE_PRIORITY),
        LanAddrClass::GlobalV6 | LanAddrClass::PublicV4 => Some(100),
        _ => None,
    }
}

/// 及被控端手动 extra 中的 CGNAT 段）→ 1s；其余（公网 v4 / 全局 v6 /
/// relay 观察地址）→ 2s（与 `DIRECT_ATTEMPT_TIMEOUT` 一致）。
pub fn direct_attempt_timeout(ip: IpAddr) -> Duration {
    match classify_ip(ip) {
        LanAddrClass::PrivateV4
        | LanAddrClass::UlaV6
        | LanAddrClass::CgnatV4
        | LanAddrClass::LinkLocalV4
        | LanAddrClass::LinkLocalV6 => PRIVATE_DIRECT_ATTEMPT_TIMEOUT,
        _ => Duration::from_secs(2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn v6(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_classify_v4() {
        assert_eq!(classify_ip(v4("10.0.0.5")), LanAddrClass::PrivateV4);
        assert_eq!(classify_ip(v4("172.31.255.1")), LanAddrClass::PrivateV4);
        assert_eq!(classify_ip(v4("192.168.1.23")), LanAddrClass::PrivateV4);
        assert_eq!(classify_ip(v4("100.64.0.1")), LanAddrClass::CgnatV4);
        assert_eq!(classify_ip(v4("100.127.255.254")), LanAddrClass::CgnatV4);
        // 边界：100.63.x / 100.128.x 不属于 100.64.0.0/10。
        assert_eq!(classify_ip(v4("100.63.0.1")), LanAddrClass::PublicV4);
        assert_eq!(classify_ip(v4("100.128.0.1")), LanAddrClass::PublicV4);
        assert_eq!(classify_ip(v4("169.254.1.1")), LanAddrClass::LinkLocalV4);
        assert_eq!(classify_ip(v4("127.0.0.1")), LanAddrClass::Loopback);
        assert_eq!(classify_ip(v4("224.0.0.1")), LanAddrClass::Multicast);
        assert_eq!(classify_ip(v4("0.0.0.0")), LanAddrClass::Unspecified);
        assert_eq!(classify_ip(v4("203.0.113.1")), LanAddrClass::PublicV4);
    }

    #[test]
    fn test_classify_v6_zone_id_conclusion() {
        assert_eq!(classify_ip(v6("fe80::1")), LanAddrClass::LinkLocalV6);
        assert_eq!(classify_ip(v6("fd00::1234")), LanAddrClass::UlaV6);
        assert_eq!(classify_ip(v6("fc00::1")), LanAddrClass::UlaV6);
        assert_eq!(classify_ip(v6("2001:db8::1")), LanAddrClass::GlobalV6);
        assert_eq!(classify_ip(v6("::1")), LanAddrClass::Loopback);
        assert_eq!(classify_ip(v6("ff02::1")), LanAddrClass::Multicast);
        assert_eq!(classify_ip(v6("::")), LanAddrClass::Unspecified);
        // fe80 排除依据：候选 SocketAddr 无法携带 scope-id（见模块注释）。
        assert!(!is_reportable_candidate(v6("fe80::1")));
    }

    #[test]
    fn test_reportable_and_priority() {
        assert_eq!(candidate_priority(v4("192.168.1.23")), Some(LAN_CANDIDATE_PRIORITY));
        assert_eq!(candidate_priority(v6("fd12::a")), Some(LAN_CANDIDATE_PRIORITY));
        assert_eq!(candidate_priority(v4("203.0.113.1")), Some(100));
        assert_eq!(candidate_priority(v6("2001:db8::1")), Some(100));
        assert_eq!(candidate_priority(v4("100.64.1.1")), None);
        assert_eq!(candidate_priority(v4("169.254.0.1")), None);
        assert_eq!(candidate_priority(v4("127.0.0.1")), None);
        assert!(LAN_CANDIDATE_PRIORITY > 200);
    }

    #[test]
    fn test_direct_attempt_timeout() {
        assert_eq!(direct_attempt_timeout(v4("10.1.2.3")), PRIVATE_DIRECT_ATTEMPT_TIMEOUT);
        assert_eq!(direct_attempt_timeout(v6("fd00::1")), PRIVATE_DIRECT_ATTEMPT_TIMEOUT);
        assert_eq!(direct_attempt_timeout(v4("100.64.5.5")), PRIVATE_DIRECT_ATTEMPT_TIMEOUT);
        assert_eq!(direct_attempt_timeout(v4("203.0.113.7")), Duration::from_secs(2));
        assert_eq!(direct_attempt_timeout(v6("2001:db8::7")), Duration::from_secs(2));
    }
}
