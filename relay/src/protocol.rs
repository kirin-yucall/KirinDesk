//! M8-T026 T001: 协议层 — 控制消息 + 帧编解码（TNL-PROTO-001/007）。
//!
//! 帧格式：`[type:u8][len:u32 BE][bincode payload]`（对齐 `core/connection/
//! multiplex.rs` 的 `[type:u8][len:u32 BE][payload]` 风格；本模块自持实现以
//! 保持 relay 零 core 依赖，TNL-NF-004）。
//!
//! type 域划分（TNL-PROTO-001）：
//! - `0x01` 控制消息（`ControlMsg`，bincode 枚举自带变体标记）；
//! - `0x10` work 连接首帧（`WorkConnHeader`）；
//! - `0x80+` 中继扩展区（§8）：**M8-T026-P2 设备 ID 模式已启用**
//!   `0x80~0x86`（解析/候选/设备级中继）；`0x87~0x8A` 为 P1 打洞
//!   （`PeerCandidates` / `PunchResult` / `PathProbe` / `PathProbeAck`，
//!   P1 并行开发使用；`PunchProbe` 不经服务器、在打洞 socket 上直发，
//!   不占帧类型，见 PUNCH-PROTO-004，报文结构见 §P1 打洞探测）。
//!
//! 帧上限 16 MiB（对齐 `multiplex.rs` `DEFAULT_MAX_FRAME_LEN`）；超限 /
//! 未知 type / bincode 解码失败 → 连接判死关闭（TNL-PROTO-007）。

use serde::{Deserialize, Serialize};

/// 协议主版本（TNL-PROTO-008：主版本不兼容 → 登录拒绝）。
pub const PROTOCOL_VERSION: &str = "1.0.0";

/// 帧类型：控制消息（`ControlMsg` 的 bincode 负载）。
pub const TYPE_CONTROL: u8 = 0x01;
/// 帧类型：work 连接首帧（`WorkConnHeader`）。
pub const TYPE_WORK_HEADER: u8 = 0x10;
/// 帧类型预留区起点（§8 中继扩展）。
pub const TYPE_RESERVED_BASE: u8 = 0x80;

// ════════════════════════════════════════════════════════════════
// M8-T026-P2 设备 ID 模式 — 0x80+ 扩展区（ID-010/ID-011/ID-005）
// ════════════════════════════════════════════════════════════════

/// 扩展区：设备解析请求（控制器 → 服务器控制连接，ID-010）。
pub const TYPE_RESOLVE_DEVICE: u8 = 0x80;
/// 扩展区：设备解析应答（服务器 → 控制器，服务器 Ed25519 签名，ID-SEC-001）。
pub const TYPE_DEVICE_INFO: u8 = 0x81;
/// 扩展区：候选登记（设备 → 服务器控制连接，ID-005，对齐 P1 PUNCH-PROTO-001）。
pub const TYPE_CANDIDATE_REGISTER: u8 = 0x82;
/// 扩展区：设备级中继请求（控制器 → 服务器**数据连接**首帧，§8.1 / ID-011③）。
pub const TYPE_TUNNEL_CONN: u8 = 0x83;
/// 扩展区：中继牵线通知（服务器 → 设备控制连接，§8.1）。
pub const TYPE_TUNNEL_REQUEST: u8 = 0x84;
/// 扩展区：设备回连首帧（设备 → 服务器数据连接，§8.1）。
pub const TYPE_TUNNEL_HEADER: u8 = 0x85;
/// 扩展区：中继建立结果（服务器 → 控制器数据连接）。
pub const TYPE_TUNNEL_RESP: u8 = 0x86;
/// 扩展区（P1）：对端候选互转（PUNCH-PROTO-003）。
pub const TYPE_PEER_CANDIDATES: u8 = 0x87;
/// 扩展区（P1）：打洞结果上报（PUNCH-PROTO-005）。
pub const TYPE_PUNCH_RESULT: u8 = 0x88;
/// 扩展区（P1）：会话中路径质量探测（PUNCH-PROTO-006；服务器透传）。
pub const TYPE_PATH_PROBE: u8 = 0x89;
/// 扩展区（P1）：路径质量探测应答（PUNCH-PROTO-006；服务器透传）。
pub const TYPE_PATH_PROBE_ACK: u8 = 0x8A;

/// 扩展区消息类型范围终点（含），用于帧类型合法性判定。
pub const TYPE_EXT_END: u8 = TYPE_PATH_PROBE_ACK;

/// 候选地址类型（PUNCH-PROTO-002 / ID-002）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateKind {
    /// UDP 候选（打洞主路径用，P1）。
    Udp,
    /// TCP 候选（直连/打洞 TCP 辅路径用）。
    Tcp,
}

/// 连接候选（PUNCH-PROTO-002；`priority` 数值越大优先级越高）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Candidate {
    pub addr: std::net::SocketAddr,
    pub kind: CandidateKind,
    pub priority: u8,
}

/// 设备解析请求（ID-010）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolveDevice {
    pub device_id: String,
}

/// 设备解析应答的**被签名载荷**（ID-SEC-001：签名覆盖该载荷的 bincode 字节）。
///
/// 未知 ID 与离线 ID 统一返回 `online: false` + 空候选 + 空公钥（ID-SEC-002
/// 防枚举：不泄露设备是否存在）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceInfoPayload {
    pub device_id: String,
    pub candidates: Vec<Candidate>,
    /// 目标设备 Ed25519 公钥（base64）；unknown/offline 时为空串。
    pub ed25519_pub: String,
    pub online: bool,
    /// 服务器应答时间戳（unix 秒）。
    pub ts: u64,
}

/// 设备解析应答（ID-SEC-001：服务器 Ed25519 私钥签名 `payload` 的 bincode 字节）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub payload: DeviceInfoPayload,
    pub signature: Vec<u8>,
}

/// 候选登记（ID-005 候选刷新 / PUNCH-PROTO-001 打洞候选交换共用）。
///
/// `session_id`（P1 字段，`#[serde(default)]` 向后兼容）：打洞会话的 128 位
/// 随机标识（仅双端与服务器知晓，PUNCH-SEC-003）；`Some` = P1 打洞流程
/// （服务器按 session 关联双端并互转候选），`None` = P2 注册表候选刷新
/// （服务器仅按 device_id 存最新候选）。见 `M8-T026_接口交互协调.md` §3.1。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateRegister {
    pub device_id: String,
    #[serde(default)]
    pub session_id: Option<[u8; 16]>,
    pub candidates: Vec<Candidate>,
}

/// 设备级中继请求（控制器 → 服务器数据连接首帧，§8.1 / ID-011③）。
///
/// `from_peer` 为控制端自身设备 ID（目标设备侧身份显示/白名单用）；
/// 服务器登记 pending 后向目标控制连接下发 [`TunnelRequest`]。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelConn {
    pub target_peer_id: String,
    pub from_peer: String,
}

/// 中继牵线通知（服务器 → 设备控制连接，§8.1）。
///
/// 设备收到后须**新开一条** TCP 连接并在首帧回 [`TunnelHeader`]。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelRequest {
    pub from_peer: String,
    pub conn_id: u64,
}

/// 设备回连首帧（设备 → 服务器数据连接，§8.1）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelHeader {
    pub conn_id: u64,
}

/// 中继建立结果（服务器 → 控制器数据连接；`ok=false` 后连接随即关闭）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelResp {
    pub ok: bool,
    pub err: Option<String>,
}

/// 对端候选互转（P1 预留，PUNCH-PROTO-003；本 P2 阶段仅定义不发送）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerCandidates {
    pub session_id: [u8; 16],
    pub candidates: Vec<Candidate>,
}

/// 打洞结果上报（PUNCH-PROTO-005；双端 → 服务器 → 对端，经控制连接）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PunchResult {
    pub session_id: [u8; 16],
    pub ok: bool,
    pub path: Option<CandidateKind>,
}

/// 会话中路径质量探测（PUNCH-PROTO-006，P1；控制连接承载，服务器透传对端）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathProbe {
    /// 路径标识（由调用方分配，如 PathKind 序号）。
    pub path_id: u32,
    /// 发送方 unix 毫秒时间戳；Ack 原样回显。
    pub ts_ms: u64,
}

/// 会话中路径质量探测应答（PUNCH-PROTO-006；`ts_ms` 回显请求值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathProbeAck {
    pub path_id: u32,
    pub ts_ms: u64,
}

// ════════════════════════════════════════════════════════════════
// P1 打洞探测 — 原始 UDP 报文（PUNCH-PROTO-004，不经服务器）
// ════════════════════════════════════════════════════════════════

/// UDP 打洞探测报文（打洞 socket 上直发；固定 32 B ≤ 32 B 上限）。
///
/// 双方**同时互发**（各 NAT 建立映射）；收到对端探测 → 回 [`PunchProbeAck`]
/// （回显其 nonce）。报文判别：收到的 nonce == 我方最后发出探测的 nonce
/// → 是对端对我方探测的 Ack（路径确认）；否则 → 对端探测，回 Ack。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PunchProbe {
    /// 打洞会话标识（128 位随机，PUNCH-SEC-003）。
    pub session_id: [u8; 16],
    /// 探测随机数（识别/回显）。
    pub nonce: [u8; 16],
}

/// UDP 打洞探测应答（回显请求的 `nonce`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PunchProbeAck {
    pub session_id: [u8; 16],
    pub nonce: [u8; 16],
}

/// 编码打洞探测报文（bincode；定长 32 B）。
pub fn encode_probe(p: &PunchProbe) -> Vec<u8> {
    // bincode 对定长数组不附加长度前缀，净载荷恰为 16 + 16 = 32 B。
    bincode::serialize(p).expect("fixed-size probe serialize cannot fail")
}

/// 编码打洞探测应答报文（定长 32 B）。
pub fn encode_probe_ack(a: &PunchProbeAck) -> Vec<u8> {
    bincode::serialize(a).expect("fixed-size probe serialize cannot fail")
}

/// 解码打洞探测报文（长度/校验失败 → 丢弃，不判死连接——打洞 socket 无连接）。
pub fn decode_probe(buf: &[u8]) -> Result<PunchProbe, ProtocolError> {
    if buf.len() > 32 {
        return Err(ProtocolError::FrameTooLarge {
            len: buf.len() as u32,
            max: 32,
        });
    }
    bincode::deserialize(buf).map_err(|e| ProtocolError::Bincode(e.to_string()))
}

/// 帧上限 16 MiB（对齐 `multiplex.rs` `DEFAULT_MAX_FRAME_LEN`）。
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// 帧头长度：1 字节 type + 4 字节大端长度。
pub const FRAME_HEADER_LEN: usize = 5;

/// 控制消息（bincode 序列化；枚举顺序即 wire 变体标记，勿随意重排）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ControlMsg {
    /// frpc → frps：登录（token 认证 + 版本协商，TNL-PROTO-002）。
    ///
    /// M8-T026-P2（ID-001）：`device_id` / `ed25519_pub` 为设备 ID 模式
    /// 注册字段 —— 有 `device_id` 时服务器登记在线表；`None` 为纯控制
    /// 连接（如仅解析）。`device_id` 优先显式配置，否则由公钥指纹派生。
    Login {
        token: String,
        version: String,
        hostname: String,
        #[serde(default)]
        device_id: Option<String>,
        #[serde(default)]
        ed25519_pub: Option<String>,
    },
    /// frps → frpc：登录应答（TNL-PROTO-002）。
    LoginResp {
        ok: bool,
        err: Option<String>,
        server_version: String,
    },
    /// frpc → frps：注册/更新代理（TNL-PROTO-003；`remote_port: 0` = 服务端分配）。
    NewProxy {
        name: String,
        local_addr: String,
        local_port: u16,
        remote_port: u16,
    },
    /// frps → frpc：代理注册应答（TNL-PROTO-003）。
    ProxyResp {
        ok: bool,
        name: String,
        err: Option<String>,
        assigned_port: Option<u16>,
    },
    /// frps → frpc：数据面按需建连信令（TNL-PROTO-004）。
    ///
    /// `conn_id` 由服务端生成并注册 pending 表，frpc 回连后须在
    /// `WorkConnHeader` 中原样带回 —— 服务端按
    /// `(client_session, proxy_name, conn_id)` 精确配对（TNL-SERVER-005）。
    StartWorkConn { proxy_name: String, conn_id: u64 },
    /// frpc → frps：解绑代理端口（TNL-PROTO-006）。
    CloseProxy { name: String },
    /// frpc → frps：优雅下线（TNL-PROTO-006）。
    Logout,
    /// 双向心跳（TNL-PROTO-005；Pong 回显 Ping 的 ts）。
    Ping { ts: u64 },
    /// 双向心跳应答（TNL-PROTO-005）。
    Pong { ts: u64 },
}

/// work 连接首帧（frpc 回连后第一条消息，TNL-PROTO-004）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkConnHeader {
    pub proxy_name: String,
    pub conn_id: u64,
}

/// 协议错误。
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// 帧长度头超限（TNL-PROTO-007）。
    #[error("frame too large: {len} > {max}")]
    FrameTooLarge { len: u32, max: u32 },
    /// 未知帧类型（TNL-PROTO-007）。
    #[error("unknown frame type: 0x{0:02x}")]
    UnknownType(u8),
    /// bincode 编解码失败（TNL-PROTO-007）。
    #[error("bincode error: {0}")]
    Bincode(String),
    /// I/O 错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// 编码控制消息为一帧（[type:u8][len:u32 BE][bincode]）。
pub fn encode_control(msg: &ControlMsg) -> Result<Vec<u8>, ProtocolError> {
    let payload = bincode::serialize(msg)
        .map_err(|e| ProtocolError::Bincode(e.to_string()))?;
    Ok(wrap_frame(TYPE_CONTROL, &payload))
}

/// 编码 work 连接首帧。
pub fn encode_work_header(h: &WorkConnHeader) -> Result<Vec<u8>, ProtocolError> {
    let payload = bincode::serialize(h)
        .map_err(|e| ProtocolError::Bincode(e.to_string()))?;
    Ok(wrap_frame(TYPE_WORK_HEADER, &payload))
}

/// 用 `[type:u8][len:u32 BE][payload]` 封装负载（不校验长度，由解码侧负责）。
pub fn wrap_frame(ty: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    out.push(ty);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// 帧类型是否已知（TNL-PROTO-007 判死依据）。
///
/// 已知：控制消息 / work 首帧 / 0x80+ 扩展区消息（P2 已启用 0x80~0x86，
/// 0x87~0x88 为 P1 预留 —— 预留位**不判死**，保证 P1 上线不破坏兼容）。
pub fn is_known_type(ty: u8) -> bool {
    ty == TYPE_CONTROL
        || ty == TYPE_WORK_HEADER
        || (TYPE_RESERVED_BASE..=TYPE_EXT_END).contains(&ty)
}

/// 解析一帧，返回 `(type, payload)`。
///
/// 超限 / 未知 type → 错误（调用方据此判死关闭，TNL-PROTO-007）。
pub fn decode_frame(buf: &[u8]) -> Result<(u8, &[u8]), ProtocolError> {
    if buf.len() < FRAME_HEADER_LEN {
        return Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "frame shorter than header",
        )));
    }
    let ty = buf[0];
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len as u32 > MAX_FRAME_LEN {
        return Err(ProtocolError::FrameTooLarge {
            len: len as u32,
            max: MAX_FRAME_LEN,
        });
    }
    if buf.len() < FRAME_HEADER_LEN + len {
        return Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "frame truncated",
        )));
    }
    if !is_known_type(ty) {
        return Err(ProtocolError::UnknownType(ty));
    }
    Ok((ty, &buf[FRAME_HEADER_LEN..FRAME_HEADER_LEN + len]))
}

/// 从负载解析控制消息（type 必须为 `TYPE_CONTROL`）。
pub fn decode_control(ty: u8, payload: &[u8]) -> Result<ControlMsg, ProtocolError> {
    if ty != TYPE_CONTROL {
        return Err(ProtocolError::UnknownType(ty));
    }
    bincode::deserialize(payload).map_err(|e| ProtocolError::Bincode(e.to_string()))
}

/// 从负载解析 work 连接首帧（type 必须为 `TYPE_WORK_HEADER`）。
pub fn decode_work_header(ty: u8, payload: &[u8]) -> Result<WorkConnHeader, ProtocolError> {
    if ty != TYPE_WORK_HEADER {
        return Err(ProtocolError::UnknownType(ty));
    }
    bincode::deserialize(payload).map_err(|e| ProtocolError::Bincode(e.to_string()))
}

/// 编码 0x80+ 扩展区消息（M8-T026-P2：解析/候选/中继；P1：候选互转/打洞结果）。
pub fn encode_extension<T: Serialize>(ty: u8, msg: &T) -> Result<Vec<u8>, ProtocolError> {
    debug_assert!(ty >= TYPE_RESERVED_BASE && ty <= TYPE_EXT_END, "type out of extension range");
    let payload = bincode::serialize(msg)
        .map_err(|e| ProtocolError::Bincode(e.to_string()))?;
    Ok(wrap_frame(ty, &payload))
}

/// 解码 0x80+ 扩展区消息（type 必须为 `expected`）。
pub fn decode_extension<T: for<'de> Deserialize<'de>>(
    ty: u8,
    payload: &[u8],
    expected: u8,
) -> Result<T, ProtocolError> {
    if ty != expected {
        return Err(ProtocolError::UnknownType(ty));
    }
    bincode::deserialize(payload).map_err(|e| ProtocolError::Bincode(e.to_string()))
}

/// 解码 0x80+ 扩展区消息（不校验 type，由调用方在已知合法 type 下使用）。
pub fn decode_extension_any<T: for<'de> Deserialize<'de>>(
    payload: &[u8],
) -> Result<T, ProtocolError> {
    bincode::deserialize(payload).map_err(|e| ProtocolError::Bincode(e.to_string()))
}

/// 从异步读流读取一帧（带 16 MiB 上限校验）。
pub async fn read_frame<R>(reader: &mut R) -> Result<(u8, Vec<u8>), ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header).await?;
    let ty = header[0];
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    if len > MAX_FRAME_LEN {
        return Err(ProtocolError::FrameTooLarge { len, max: MAX_FRAME_LEN });
    }
    if !is_known_type(ty) {
        return Err(ProtocolError::UnknownType(ty));
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    Ok((ty, payload))
}

/// 向异步写流写入一帧（整帧 + flush）。
pub async fn write_frame<W>(writer: &mut W, ty: u8, payload: &[u8]) -> Result<(), ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let frame = wrap_frame(ty, payload);
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

/// 协议版本主版本号（"1.0.0" → "1"）；协商不兼容判定用（TNL-PROTO-008）。
pub fn major_version(version: &str) -> u64 {
    version
        .split('.')
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn sample_msgs() -> Vec<ControlMsg> {
        vec![
            ControlMsg::Login {
                token: "tok-123".into(),
                version: PROTOCOL_VERSION.into(),
                hostname: "pc-a".into(),
                device_id: Some("pc-a-id".into()),
                ed25519_pub: Some("pub-a".into()),
            },
            ControlMsg::Login {
                token: "tok-123".into(),
                version: PROTOCOL_VERSION.into(),
                hostname: "resolver".into(),
                device_id: None,
                ed25519_pub: None,
            },
            ControlMsg::LoginResp {
                ok: true,
                err: None,
                server_version: PROTOCOL_VERSION.into(),
            },
            ControlMsg::LoginResp {
                ok: false,
                err: Some("bad token".into()),
                server_version: PROTOCOL_VERSION.into(),
            },
            ControlMsg::NewProxy {
                name: "ssh".into(),
                local_addr: "127.0.0.1".into(),
                local_port: 22,
                remote_port: 60022,
            },
            ControlMsg::ProxyResp {
                ok: true,
                name: "ssh".into(),
                err: None,
                assigned_port: Some(60022),
            },
            ControlMsg::StartWorkConn {
                proxy_name: "ssh".into(),
                conn_id: 42,
            },
            ControlMsg::CloseProxy { name: "ssh".into() },
            ControlMsg::Logout,
            ControlMsg::Ping { ts: 12345 },
            ControlMsg::Pong { ts: 12345 },
        ]
    }

    #[test]
    fn test_all_messages_roundtrip() {
        // 全部消息类型 round-trip（TNL-PROTO-007 验收）
        for msg in sample_msgs() {
            let frame = encode_control(&msg).unwrap();
            assert_eq!(frame[0], TYPE_CONTROL);
            let (ty, payload) = decode_frame(&frame).unwrap();
            assert_eq!(ty, TYPE_CONTROL);
            assert_eq!(decode_control(ty, payload).unwrap(), msg);
        }
    }

    #[test]
    fn test_work_header_roundtrip() {
        let h = WorkConnHeader {
            proxy_name: "rdp".into(),
            conn_id: 7,
        };
        let frame = encode_work_header(&h).unwrap();
        assert_eq!(frame[0], TYPE_WORK_HEADER);
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(decode_work_header(ty, payload).unwrap(), h);
    }

    #[test]
    fn test_frame_too_large_rejected() {
        // 超限帧拒绝（TNL-PROTO-007）
        let mut frame = vec![TYPE_CONTROL];
        frame.extend_from_slice(&(MAX_FRAME_LEN + 1).to_be_bytes());
        frame.extend_from_slice(&[0u8; 8]);
        let err = decode_frame(&frame).unwrap_err();
        assert!(matches!(err, ProtocolError::FrameTooLarge { .. }));
    }

    #[test]
    fn test_unknown_type_kills_connection() {
        // 未知 type → 判死（TNL-PROTO-007）；0x80~0x88 扩展区为已知类型。
        for ty in [0x05u8, 0x7f, 0x8b, 0xff, TYPE_EXT_END + 1] {
            let frame = wrap_frame(ty, b"x");
            let err = decode_frame(&frame).unwrap_err();
            assert!(matches!(err, ProtocolError::UnknownType(t) if t == ty));
        }
        // 扩展区类型（含 P1 预留位）全部为已知类型，不判死。
        for ty in TYPE_RESERVED_BASE..=TYPE_EXT_END {
            assert!(is_known_type(ty), "0x{ty:02x} should be known");
            let frame = wrap_frame(ty, b"x");
            assert!(decode_frame(&frame).is_ok());
        }
    }

    #[test]
    fn test_bad_bincode_rejected() {
        // bincode 解码失败 → 判死（TNL-PROTO-007）
        let frame = wrap_frame(TYPE_CONTROL, b"not-bincode");
        let (ty, payload) = decode_frame(&frame).unwrap();
        let err = decode_control(ty, payload).unwrap_err();
        assert!(matches!(err, ProtocolError::Bincode(_)));
    }

    #[test]
    fn test_truncated_frame_rejected() {
        let frame = wrap_frame(TYPE_CONTROL, b"hello");
        let err = decode_frame(&frame[..frame.len() - 2]).unwrap_err();
        assert!(err.to_string().contains("truncated"));
        // 不足帧头
        assert!(decode_frame(&[0x01, 0x00]).is_err());
    }

    #[test]
    fn test_major_version_parse() {
        assert_eq!(major_version("1.0.0"), 1);
        assert_eq!(major_version("2.3"), 2);
        assert_eq!(major_version("junk"), 0);
    }

    #[tokio::test]
    async fn test_read_write_frame_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(65536);
        let msg = ControlMsg::NewProxy {
            name: "http".into(),
            local_addr: "127.0.0.1".into(),
            local_port: 8080,
            remote_port: 0,
        };
        let frame = encode_control(&msg).unwrap();
        let writer = tokio::spawn(async move {
            // 拆开类型/负载写入，验证 read_frame 的重组逻辑
            write_frame(&mut a, frame[0], &frame[5..]).await.unwrap();
        });
        let (ty, payload) = read_frame(&mut b).await.unwrap();
        assert_eq!(decode_control(ty, &payload).unwrap(), msg);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn test_read_frame_rejects_oversize() {
        let (mut a, mut b) = tokio::io::duplex(65536);
        let writer = tokio::spawn(async move {
            let mut header = [0u8; 5];
            header[0] = TYPE_CONTROL;
            header[1..5].copy_from_slice(&(MAX_FRAME_LEN + 1).to_be_bytes());
            a.write_all(&header).await.unwrap();
        });
        let err = read_frame(&mut b).await.unwrap_err();
        assert!(matches!(err, ProtocolError::FrameTooLarge { .. }));
        writer.await.unwrap();
    }

    // ════════════════════════════════════════════════════════════
    // M8-T026-P2：0x80+ 扩展区消息 round-trip
    // ════════════════════════════════════════════════════════════

    fn sample_candidates() -> Vec<Candidate> {
        vec![
            Candidate {
                addr: "[2001:db8::1]:3389".parse().unwrap(),
                kind: CandidateKind::Tcp,
                priority: 100,
            },
            Candidate {
                addr: "203.0.113.5:9000".parse().unwrap(),
                kind: CandidateKind::Udp,
                priority: 50,
            },
        ]
    }

    #[test]
    fn test_extension_messages_roundtrip() {
        // ResolveDevice（ID-010）
        let msg = ResolveDevice { device_id: "pc-a".into() };
        let frame = encode_extension(TYPE_RESOLVE_DEVICE, &msg).unwrap();
        assert_eq!(frame[0], TYPE_RESOLVE_DEVICE);
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(decode_extension::<ResolveDevice>(ty, payload, TYPE_RESOLVE_DEVICE).unwrap(), msg);

        // CandidateRegister（ID-005；session_id=None = 注册表候选刷新）
        let msg = CandidateRegister {
            device_id: "pc-a".into(),
            session_id: None,
            candidates: sample_candidates(),
        };
        let frame = encode_extension(TYPE_CANDIDATE_REGISTER, &msg).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(decode_extension::<CandidateRegister>(ty, payload, TYPE_CANDIDATE_REGISTER).unwrap(), msg);

        // DeviceInfo（ID-SEC-001：载荷 + 签名）
        let msg = DeviceInfo {
            payload: DeviceInfoPayload {
                device_id: "pc-a".into(),
                candidates: sample_candidates(),
                ed25519_pub: "pub-a".into(),
                online: true,
                ts: 1_752_000_000,
            },
            signature: vec![1, 2, 3, 4],
        };
        let frame = encode_extension(TYPE_DEVICE_INFO, &msg).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(decode_extension::<DeviceInfo>(ty, payload, TYPE_DEVICE_INFO).unwrap(), msg);

        // TunnelConn / TunnelRequest / TunnelHeader / TunnelResp（§8.1）
        let msg = TunnelConn { target_peer_id: "pc-b".into(), from_peer: "pc-a".into() };
        let frame = encode_extension(TYPE_TUNNEL_CONN, &msg).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(decode_extension::<TunnelConn>(ty, payload, TYPE_TUNNEL_CONN).unwrap(), msg);

        let msg = TunnelRequest { from_peer: "pc-a".into(), conn_id: 7 };
        let frame = encode_extension(TYPE_TUNNEL_REQUEST, &msg).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(decode_extension::<TunnelRequest>(ty, payload, TYPE_TUNNEL_REQUEST).unwrap(), msg);

        let msg = TunnelHeader { conn_id: 7 };
        let frame = encode_extension(TYPE_TUNNEL_HEADER, &msg).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(decode_extension::<TunnelHeader>(ty, payload, TYPE_TUNNEL_HEADER).unwrap(), msg);

        let msg = TunnelResp { ok: true, err: None };
        let frame = encode_extension(TYPE_TUNNEL_RESP, &msg).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(decode_extension::<TunnelResp>(ty, payload, TYPE_TUNNEL_RESP).unwrap(), msg);

        // P1 预留：PeerCandidates / PunchResult 仅定义 + 编解码可用
        let msg = PeerCandidates { session_id: [9; 16], candidates: sample_candidates() };
        let frame = encode_extension(TYPE_PEER_CANDIDATES, &msg).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(decode_extension::<PeerCandidates>(ty, payload, TYPE_PEER_CANDIDATES).unwrap(), msg);

        let msg = PunchResult { session_id: [9; 16], ok: true, path: Some(CandidateKind::Udp) };
        let frame = encode_extension(TYPE_PUNCH_RESULT, &msg).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(decode_extension::<PunchResult>(ty, payload, TYPE_PUNCH_RESULT).unwrap(), msg);
    }

    #[test]
    fn test_extension_type_mismatch_rejected() {
        // type 与消息不匹配 → 判死（防错帧注入）
        let msg = ResolveDevice { device_id: "pc-a".into() };
        let frame = encode_extension(TYPE_RESOLVE_DEVICE, &msg).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        let err = decode_extension::<CandidateRegister>(ty, payload, TYPE_CANDIDATE_REGISTER)
            .unwrap_err();
        assert!(matches!(err, ProtocolError::UnknownType(t) if t == TYPE_RESOLVE_DEVICE));
    }

    #[test]
    fn test_login_device_id_defaults() {
        // 旧式 Login（无 device_id 字段）→ serde 默认 None，向后兼容
        let frame = wrap_frame(
            TYPE_CONTROL,
            &bincode::serialize(&ControlMsg::Login {
                token: "t".into(),
                version: PROTOCOL_VERSION.into(),
                hostname: "h".into(),
                device_id: None,
                ed25519_pub: None,
            })
            .unwrap(),
        );
        let (ty, payload) = decode_frame(&frame).unwrap();
        match decode_control(ty, payload).unwrap() {
            ControlMsg::Login { device_id, ed25519_pub, .. } => {
                assert_eq!(device_id, None);
                assert_eq!(ed25519_pub, None);
            }
            other => panic!("unexpected msg: {other:?}"),
        }
    }

    // ════════════════════════════════════════════════════════════
    // M8-T026-P1：PathProbe/PathProbeAck + 打洞探测报文（0x89/0x8A）
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_path_probe_roundtrip() {
        // PathProbe / PathProbeAck（PUNCH-PROTO-006）
        let msg = PathProbe { path_id: 2, ts_ms: 1_752_000_000_123 };
        let frame = encode_extension(TYPE_PATH_PROBE, &msg).unwrap();
        assert_eq!(frame[0], TYPE_PATH_PROBE);
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(decode_extension::<PathProbe>(ty, payload, TYPE_PATH_PROBE).unwrap(), msg);

        let ack = PathProbeAck { path_id: 2, ts_ms: 1_752_000_000_123 };
        let frame = encode_extension(TYPE_PATH_PROBE_ACK, &ack).unwrap();
        assert_eq!(frame[0], TYPE_PATH_PROBE_ACK);
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(decode_extension::<PathProbeAck>(ty, payload, TYPE_PATH_PROBE_ACK).unwrap(), ack);
    }

    #[test]
    fn test_probe_payload_roundtrip_and_size() {
        // 打洞探测报文定长 32 B（PUNCH-PROTO-004：≤32 B）
        let probe = PunchProbe {
            session_id: [7; 16],
            nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        };
        let buf = encode_probe(&probe);
        assert_eq!(buf.len(), 32);
        assert_eq!(decode_probe(&buf).unwrap(), probe);

        let ack = PunchProbeAck { session_id: [7; 16], nonce: probe.nonce };
        let buf = encode_probe_ack(&ack);
        assert_eq!(buf.len(), 32);
        assert_eq!(decode_probe(&buf).unwrap().session_id, ack.session_id);
    }

    #[test]
    fn test_probe_oversize_rejected() {
        // 超 32 B 的探测报文 → 丢弃（不判死；打洞 socket 无连接）
        let err = decode_probe(&[0u8; 33]).unwrap_err();
        assert!(matches!(err, ProtocolError::FrameTooLarge { .. }));
    }

    #[test]
    fn test_candidate_register_session_id_compat() {
        // session_id 为 P1 追加字段：旧载荷（无该字段）→ 默认 None，向后兼容
        let old = CandidateRegister {
            device_id: "pc-b".into(),
            session_id: None,
            candidates: sample_candidates(),
        };
        let frame = encode_extension(TYPE_CANDIDATE_REGISTER, &old).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(
            decode_extension::<CandidateRegister>(ty, payload, TYPE_CANDIDATE_REGISTER).unwrap(),
            old
        );

        // 打洞流程：session_id = Some
        let punch = CandidateRegister {
            device_id: "pc-b".into(),
            session_id: Some([9; 16]),
            candidates: sample_candidates(),
        };
        let frame = encode_extension(TYPE_CANDIDATE_REGISTER, &punch).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(
            decode_extension::<CandidateRegister>(ty, payload, TYPE_CANDIDATE_REGISTER).unwrap(),
            punch
        );
    }

    #[test]
    fn test_ext_end_covers_p1_types() {
        // TYPE_EXT_END 已扩展至 0x8A：0x80~0x8A 全部已知，0x8B 仍未知
        for ty in TYPE_RESERVED_BASE..=TYPE_EXT_END {
            assert!(is_known_type(ty), "0x{ty:02x} should be known");
        }
        assert!(!is_known_type(0x8B));
    }
}
