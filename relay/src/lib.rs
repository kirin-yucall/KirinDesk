//! 内网穿透（通用 TCP 反向代理，FRP 式）。
//!
//! 极轻量级 crate（TNL-NF-004）：仅 tokio / serde / bincode / thiserror /
//! tracing / uuid（追加 ed25519-dalek / rand / base64 /
//! get-if-addrs），不依赖 `core` crate，可独立复用。
//!
//! 模块：
//! - [`protocol`]：控制消息 + 帧编解码（T001，TNL-PROTO-001/007）+ 0x80+
//!   扩展区（设备 ID 模式：解析/候选/设备级中继；P1 打洞预留）；
//! - [`auth`]：挑战-响应认证共用逻辑（：口令永不明文上线，
//!   双向认证、fail-closed，TNL-SEC-006~010）；
//! - [`server`]：隧道服务端（T002，frps 等价； 集成设备在线表；
//!   两阶段挑战-响应握手）；
//! - [`client`]：隧道客户端（T003，frpc 等价； 探测 + 双向认证）；
//! - [`registry`]：设备在线表（ID-001~005 / ID-SEC-001~003）；
//! - [`id_client`]：设备侧 ID 注册客户端 + 控制器解析/中继辅助（；
//!   两条路径同步认证）；
//! - [`rendezvous`]：打洞 rendezvous 服务端（：候选登记/互转/
//!   结果透传/限速/审计；`RendezvousExtension` 供 P2 挂载 Login/ResolveDevice）；
//! - [`audit`]：隧道审计事件（TNL-SEC-003 扩展 + 设备事件 +
//!   打洞事件）；
//! - [`rate_limit`]：控制连接限流（复用 RateLimiter 语义，
//!   零 core 依赖自持实现）。

pub mod audit;
pub mod auth;
pub mod client;
pub mod id_client;
pub mod lan_candidates; // ：LAN 候选分类/优先级/超时纯函数
pub mod protocol;
pub mod rate_limit;
pub mod registry;
pub mod rendezvous; // (P1 in progress, 隔离验证 23 项全绿)
pub mod server;

/// T004: 端到端测试（本机回环 TCP + fake 本地服务）。
#[cfg(test)]
mod tests;
