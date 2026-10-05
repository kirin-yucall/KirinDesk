//! T001: 协议层 — 控制消息 + 帧编解码（TNL-PROTO-001/007）。
//!
//! 帧格式：`[type:u8][len:u32 BE][bincode payload]`（对齐 `core/connection/
//! multiplex.rs` 的 `[type:u8][len:u32 BE][payload]` 风格；本模块自持实现以
//! 保持 relay 零 core 依赖，TNL-NF-004）。
//!
//! type 域划分（TNL-PROTO-001）：
//! - `0x01` 控制消息（`ControlMsg`，bincode 枚举自带变体标记）；
//! - `0x10` work 连接首帧（`WorkConnHeader`）；
//! - `0x80+` 中继扩展区（§8）：** 设备 ID 模式已启用**
//!   `0x80~0x86`（解析/候选/设备级中继）；`0x87~0x8A` 为 P1 打洞
//!   （`PeerCandidates` / `PunchResult` / `PathProbe` / `PathProbeAck`，
//!   P1 并行开发使用；`PunchProbe` 不经服务器、在打洞 socket 上直发，
//!   不占帧类型，见 PUNCH-PROTO-004，报文结构见 §P1 打洞探测）。
//!
//! 帧上限 16 MiB（对齐 `multiplex.rs` `DEFAULT_MAX_FRAME_LEN`）；超限 /
//! 未知 type / bincode 解码失败 → 连接判死关闭（TNL-PROTO-007）。

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// HMAC-SHA256 别名（挑战-响应认证，TNL-PROTO-013）。
type HmacSha256 = Hmac<Sha256>;

/// 协议主版本（TNL-PROTO-008：主版本不兼容 → 登录拒绝）。
///
/// TNL-PROTO-009：1.0.0 → 1.1.0 —— `Login`/`LoginResp` 追加
/// auth 字段（serde default 向后兼容）+ 枚举末尾追加 `AuthChallenge` 变体
/// （不影响既有 wire 变体索引）；major 仍为 1，版本协商不受影响。
///
/// 新增目录信令扩展帧 0x8B~0x94 十帧（`DirList`/`DirListResp`/`DirUpsert`/
/// `DirDelete`/`DirError` + `PeerList`/`PeerListResp`/`PeerUpsert`/
/// `PeerDelete`/`PeerToggle`，见下「目录信令区」）。**既有 wire
/// 变体零变化**：`ControlMsg` 枚举零追加（变体索引逐位不变）、既有扩展帧
/// 类型号/字段逐位不变。
///
/// **1.3.0** —— 同步模型 v2 重冻（设计修订 §2，冻结面见
/// - C 面五帧改 v2（字段序 = 结构体声明序即冻结面）：`DirList` 尾部追加
///   `filter_device` + `DirScope` 变体语义改废（wire 形状零变 = 变体索引
///   不变）/ `DirEntry` 6→7 字段（+`target_domain`；`domain`→`device_domain`
///   、`peer_fp`→`source_fp` 更名）/ `DirUpsert`+`DirDelete` +`target_domain` /
///   `DirError` 码一换一（`limit_exceeded` 废 → `quota_exceeded` 入，码位不
///   回收，wire 出现 `limit_exceeded` = 协议违规）；
/// - **废帧保留不复用**：`0x90~0x94`（Peer* 同步源五帧，同步模型整体废除）
///   型号保留，v2 服务端按未知帧处置（结构校验 + 丢弃 + 审计，不按旧语义
///   处理，升级窗口行为）；`TYPE_EXT_END` 维持 0x94（v2 零新增 C 侧型号）；
/// - 10k 容量上限冻结废除（`MAX_DIRECTORY_ENTRIES` 删除），改单 IP 注册
///
/// 三平面独立演进：relay 面 1.3.0 / 设备面 `core` `PROTOCOL_VERSION=3`
/// （零改）/ 互识版本串 `RELAY-DIR/2`（v2 定值，interconnect.rs）。
///
/// 1.3.0 → **2.0.0**（主版本 +1 = 断代显性化，**无兼容包袱**：旧对端互连
/// 允许失败 fail-closed，README/CHANGELOG 注明需两端升级）：
/// - **C-1 设备注册私钥挑战签名**（R176 ZD-01 治本）：`ControlMsg` **末尾**
///   追加 [`ControlMsg::RegChallenge`] / [`ControlMsg::RegProof`] 两变体
///   （既有变体索引逐位不变）——设备注册/重注册前服务器下发 32B CSPRNG
///   nonce，设备以**设备私钥** Ed25519 签名应答（[`registration_proof_payload`]），
///   服务器以目录公钥验签通过才接受注册/替换条目；验签失败 = 拒 + 审计；
/// - 主版本协商门（`major_version` 相等）即旧客户端断代第一道：v1 客户端
///   对 v2 服务器 = `incompatible protocol version` 结构化拒绝；v2 客户端
///   对 v1 服务器同被拒（fail-closed 双向）。
pub const PROTOCOL_VERSION: &str = "2.0.0";

/// 帧类型：控制消息（`ControlMsg` 的 bincode 负载）。
pub const TYPE_CONTROL: u8 = 0x01;
/// 帧类型：work 连接首帧（`WorkConnHeader`）。
pub const TYPE_WORK_HEADER: u8 = 0x10;
/// 帧类型预留区起点（§8 中继扩展）。
pub const TYPE_RESERVED_BASE: u8 = 0x80;

// ════════════════════════════════════════════════════════════════
// 设备 ID 模式 — 0x80+ 扩展区（ID-010/ID-011/ID-005）
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

// ════════════════════════════════════════════════════════════════
// 客户端 ↔ 选中 relay 的设备域名目录（device_directory v2）管理帧。
// wire 定稿冻结：类型号段 + bincode 字段序即冻结面，后续版本只允许
// **追加**新类型号。v2 语义锚（设计修订 §0.3/§2.2）：UI 允许列表只写
// **当前已连接中继 A**（home），A 按其定向推送给被允许的中继（R→R
// IxPush，互识面，interconnect.rs）；DirUpsert/DirDelete = 在 A 上
// 授权/撤销「target_domain 中继可发现当前远控服务端」的
// (device_id, target_domain) 行（source=manual）。成功响应 = 静默
// （无应答帧），失败 = `DirError` 显式错误帧（不静默，fail-closed）。
// **废帧保留不复用**（v2）：0x90~0x94 Peer* 五帧 = 旧 pull 同步源
// 机制整体废除（UI 同步源面板从未建设，零消费端）；型号保留，v2 服务
// 端按未知帧处置（结构校验 + 丢弃 + 审计，**不**按旧语义处理）。
// ════════════════════════════════════════════════════════════════

/// 目录区 v2：查表（C→R；查询 = CRUD 的读）。
pub const TYPE_DIR_LIST: u8 = 0x8B;
/// 目录区 v2：查表应答（R→C；空表 = 空数组，非错）。
pub const TYPE_DIR_LIST_RESP: u8 = 0x8C;
/// 目录区 v2：条目 upsert（C→R；增 + 改同帧，source=manual；
/// +target_domain = 被允许发现本设备的目标中继域）。
pub const TYPE_DIR_UPSERT: u8 = 0x8D;
/// 目录区 v2：条目删除（C→R；只删本中继自持行 (device_id, target_domain)；
/// 目标仅以 pushed 形态存在 = `not_found`，不跨源删）。
pub const TYPE_DIR_DELETE: u8 = 0x8E;
/// 目录区 v2：显式错误帧（R→C；`DirError`，统一错误态；六码含
/// `quota_exceeded`，`limit_exceeded` 废）。
pub const TYPE_DIR_ERROR: u8 = 0x8F;
/// 整体废除；v2 服务端按未知帧处置（结构校验 + 丢弃 + 审计）。
pub const TYPE_PEER_LIST: u8 = 0x90;
/// 【废帧保留不复用】v1 同步源列表应答（R→C）。
pub const TYPE_PEER_LIST_RESP: u8 = 0x91;
/// 【废帧保留不复用】v1 同步源 upsert（C→R）。
pub const TYPE_PEER_UPSERT: u8 = 0x92;
/// 【废帧保留不复用】v1 同步源移除（C→R）。
pub const TYPE_PEER_DELETE: u8 = 0x93;
/// 【废帧保留不复用】v1 同步源暂停/启用（C→R）。
pub const TYPE_PEER_TOGGLE: u8 = 0x94;

/// 扩展区消息类型范围终点（含），用于帧类型合法性判定。
/// 不变**（v2 零新增 C 侧型号；0x90~0x94 废保留在扩展区范围内，
/// 不判死连接 = 旧客户端升级窗口 fail-closed 自限，设计 §7.3）。
pub const TYPE_EXT_END: u8 = TYPE_PEER_TOGGLE;

pub const DIRECTORY_FRAME_TYPES: &[u8] = &[
    TYPE_DIR_LIST,
    TYPE_DIR_LIST_RESP,
    TYPE_DIR_UPSERT,
    TYPE_DIR_DELETE,
    TYPE_DIR_ERROR,
];

/// 不复用——不得新增任何复用这些型号的定义）。v2 服务端到达 = 结构校验
/// + 丢弃 + `DirFrameDropped` 审计（不按旧语义处理，设计 §5 点位 18）。
pub const DEPRECATED_DIRECTORY_FRAME_TYPES: &[u8] = &[
    TYPE_PEER_LIST,
    TYPE_PEER_LIST_RESP,
    TYPE_PEER_UPSERT,
    TYPE_PEER_DELETE,
    TYPE_PEER_TOGGLE,
];

pub fn is_directory_frame_type(ty: u8) -> bool {
    DIRECTORY_FRAME_TYPES.contains(&ty)
}

pub fn is_deprecated_directory_frame_type(ty: u8) -> bool {
    DEPRECATED_DIRECTORY_FRAME_TYPES.contains(&ty)
}

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
///
/// 显式 ID），也可携带 **10 hex 短码**（`is_short_code` 形态）——服务器侧
/// 按前缀唯一命中解析（见 `Registry::resolve`），多义/未命中统一防枚举响应。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolveDevice {
    pub device_id: String,
}


/// 短码长度：10 个十六进制字符（40 bit；在线表前缀唯一命中才解析）。
pub const DEVICE_SHORT_CODE_LEN: usize = 10;

/// 64 个 ASCII 十六进制字符（即 79 字符冒号分组的 canonical 指纹 ID）。
pub fn is_fingerprint_device_id(device_id: &str) -> bool {
    let stripped: String = device_id
        .chars()
        .filter(|c| !matches!(c, ':' | ' ' | '\t' | '\r' | '\n'))
        .collect();
    stripped.len() == 64 && stripped.chars().all(|c| c.is_ascii_hexdigit())
}

/// ASCII 小写十六进制字符（冒号/空白/大写均不算：canonical 短码本身即
/// 小写指纹前缀；大写由客户端归一化后再来）。
pub fn is_short_code(s: &str) -> bool {
    s.len() == DEVICE_SHORT_CODE_LEN
        && s.chars()
            .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

/// sha256 指纹十六进制串的**前 10 个字符**（小写）；非指纹形态（自定义
/// 显式 ID）无短码（返回 `None`，不参与前缀解析）。
pub fn device_id_short_code(device_id: &str) -> Option<String> {
    if !is_fingerprint_device_id(device_id) {
        return None;
    }
    let flat: String = device_id
        .chars()
        .filter(|c| *c != ':')
        .flat_map(|c| c.to_lowercase())
        .take(DEVICE_SHORT_CODE_LEN)
        .collect();
    Some(flat)
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
/// （服务器仅按 device_id 存最新候选）。见 `_接口交互协调.md` §3.1。
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

// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════

///
/// **变体 wire 形态不变**（变体索引零变 = 1.2.0/1.3.0 混版自限面）；
/// v2 语义改废：`All` = 全表（本地 + pushed）/ `Local` = 本中继自持行
/// （source≠pushed）/ `Peer(fp)` = 来源 fp 的 pushed 行（v1 同步源语义
/// 废除，改读推送条目视图）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirScope {
    /// 全部条目（本地自持 + pushed 全集）。
    All,
    /// 仅本中继自持行（`manual` / `registered`，不含 pushed）。
    Local,
    /// 指定来源 relay（79 字符指纹精确匹配）的 pushed 行。
    Peer(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirList {
    /// 缺省 = [`DirScope::All`]（基线全表；v2 语义见 [`DirScope`]）。
    #[serde(default)]
    pub scope: DirScope,
    /// v2 语义（设计 §2.2）：`true` = 触发本中继立即对其**全部 targets**
    #[serde(default)]
    pub refresh: bool,
    /// v2 新增（尾部追加，default None）：Some(归一化 device_id) = 仅该
    /// 设备的行（登录对账回读 `DirList{scope:Local, filter_device:self}`）。
    #[serde(default)]
    pub filter_device: Option<String>,
}

impl Default for DirScope {
    fn default() -> Self {
        DirScope::All
    }
}

impl Default for DirList {
    fn default() -> Self {
        Self {
            scope: DirScope::default(),
            refresh: false,
            filter_device: None,
        }
    }
}

/// **7 字段（+target_domain；字段序即冻结面）**。
///
/// `source_fp` 空串 = 本中继自持行（`manual`/`registered`）；`sig_verified`
/// 为**写时验口径**（manual/registered/pushed 全部 = 验签通过恒 `true`，
/// wire 信任凭据。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirEntry {
    /// 设备 ID（存储/展示归一化完整形态；短码不可展开 = 拒写）。
    pub device_id: String,
    /// 设备自身 DNS 域（纯 FQDN，不含 `:port`——端口恒走 SRV；
    /// v1 `domain` 更名语义）。
    pub device_domain: String,
    /// v2 新增：本行服务的目标中继域（纯 FQDN）。本中继自持 manual 行 =
    /// 被允许发现本设备的中继域；pushed 行 = 本中继自身域（接收方，隐式）。
    pub target_domain: String,
    /// 来源：`manual` | `registered` | `pushed`（v1 `peer` 值废，v2 不产生）。
    pub source: String,
    /// 源 relay 79 字符指纹（`source=pushed` 必填；自持行 = 空串；
    /// v1 `peer_fp` 更名）。
    pub source_fp: String,
    /// Unix 秒（写入方时钟；冲突裁决用）。
    pub updated_at: u64,
    /// 签名验签是否通过（写时验口径，见结构体注）。
    pub sig_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirListResp {
    pub entries: Vec<DirEntry>,
    /// 服务器时间戳（unix 秒）。
    pub server_ts: u64,
    /// 目录 epoch（本域每次成功写入 +1；客户端刷新/缓存比对用）。
    pub epoch: u64,
}

///
/// 服务端执法（设计 §2.2/§5 点位 8-10）：`device_id` 必须 == 会话登录
/// 身份（不符 = `auth_failed` + 会话判死，协议违规判死口径不放宽）+
/// ID 形态（短码归一失败 = `invalid_device_id`）+ **双** FQDN 校验
/// （domain / target_domain 非纯 FQDN = `invalid_domain`）+ **单 IP 注册
/// 配额**（超限 = `quota_exceeded`，不清存量；10k 容量上限冻结已废）。
/// 成功 = 静默（无应答帧），客户端「超时内无 DirError = 成功」+ UI 侧
/// `DirList{scope:Local, filter_device:self}` 回读双保险。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirUpsert {
    pub device_id: String,
    /// 设备自身 DNS 域（纯 FQDN）。
    pub domain: String,
    /// v2 新增：被允许发现本机的目标中继域（纯 FQDN；= 用户 UI 允许列表行）。
    pub target_domain: String,
    /// 备注（v2 起**落库**——schema v2 note 列）。
    #[serde(default)]
    pub note: Option<String>,
    /// （用户「允许中继服务器发现」表单高级区填入，home 中继缓存为
    /// `ix_tokens(source='device')` 转发凭证，推送目标中继时 AEAD 体内
    /// 携带；**非**客户端登录 token）。旧 4 字段帧对新 build 服务端解码
    /// 必败 → `handle_dir_upsert` decode 先试 5 字段、失败回退旧 4 字段
    /// 结构（`ix_token` = 空 = 不更新凭证缓存）。
    #[serde(default)]
    pub ix_token: String,
}

///
/// 只删本中继**自持行**（source∈manual/registered）的
/// (device_id, target_domain)；目标仅以 pushed 形态存在 = `not_found`
/// （**不跨源删**——B 上的 (D,B) pushed 行只能由 A 的推送批次删除）；
/// 不存在 = `DirError{not_found}`。`device_id` ≠ 会话登录身份 =
/// `auth_failed` + 判死（同 upsert 口径）。成功（删除生效）= 静默。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirDelete {
    pub device_id: String,
    /// v2 新增：被撤销的目标中继域（纯 FQDN）。
    pub target_domain: String,
}

/// 客户端 i18n 映射键，勿改值）。
///
/// v1→v2：`limit_exceeded`（10k 容量上限）**废**——码位不回收，wire 上
/// 出现该串 = 协议违规（调用方按未知值判死，不猜语义）；`quota_exceeded`
/// （单 IP 注册配额超限）入位。未知值 = 协议违规，调用方判死。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirErrorCode {
    /// 认证失败（v2 实义化：C→R 写帧 `device_id` ≠ 会话登录身份 = 本码
    /// + 会话判死，协议违规判死口径不放宽；客户端映射须覆盖）。
    AuthFailed,
    /// 条目不存在（删除命中空 / 目标仅 pushed 形态存在〔不跨源删〕）。
    NotFound,
    /// 设备 ID 形态非法（短码不可展开 / 不可归一化完整形态）。
    InvalidDeviceId,
    /// 域名非纯 FQDN（domain / target_domain 含 `:port` / 单标签 / 超长 /
    /// 非法字符）。
    InvalidDomain,
    /// v2 新：单 IP 注册配额超限（distinct device 数 ≥ 配额，拒新增、
    /// 不清存量；v1 `limit_exceeded` 位入）。
    QuotaExceeded,
    /// 服务暂时不可用（DB 锁竞争 / 损坏重建中 / 并发超限）。
    Busy,
}

impl DirErrorCode {
    /// wire / 日志 / UI 映射键（v2 冻结字符串，勿改值）。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthFailed => "auth_failed",
            Self::NotFound => "not_found",
            Self::InvalidDeviceId => "invalid_device_id",
            Self::InvalidDomain => "invalid_domain",
            Self::QuotaExceeded => "quota_exceeded",
            Self::Busy => "busy",
        }
    }

    /// 解析 wire 字符串（未知值 = `None`，调用方按协议违规处理；
    /// `limit_exceeded` 为 v1 废码 = 不识别，恒 `None`）。
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auth_failed" => Some(Self::AuthFailed),
            "not_found" => Some(Self::NotFound),
            "invalid_device_id" => Some(Self::InvalidDeviceId),
            "invalid_domain" => Some(Self::InvalidDomain),
            "quota_exceeded" => Some(Self::QuotaExceeded),
            "busy" => Some(Self::Busy),
            _ => None,
        }
    }
}

///
/// `msg` = 人话细节（零凭据：只可含 device_id/domain/配额数值/错误语义，
/// 禁 token/挑战码/密钥材料）；UI 按 `code` 映射 i18n 人话文案
/// （fail-closed 不静默）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirError {
    pub code: DirErrorCode,
    pub msg: String,
}

// 冻结零改；v2 生产分发面不消费）──────────────────────────────────────

/// 【废帧保留】v1 同步源条目（`PeerListResp` 元素）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerInfo {
    /// 同步源 relay 域（纯 FQDN）。
    pub domain: String,
    /// 79 字符指纹（精确匹配键；UI 拒绝通配，fail-closed）。
    pub fp: String,
    /// `false` = 暂停同步（数据保留，增量面跳过）。
    pub enabled: bool,
    pub note: String,
    /// 最近一次成功同步（unix 秒；从未同步 = `None`）。
    pub last_sync: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerListResp {
    pub peers: Vec<PeerInfo>,
    /// 服务器时间戳（unix 秒）。
    pub server_ts: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerList {}

///
/// **TOFU 在用户侧**：客户端先对域名做 DNS 三件套解析（SRV/TXT/AAAA+A）
/// + UI 指纹确认模态过目，再把已确认公钥提交本帧；relay 不代确认。
/// 落库 `fp` 由 relay 依 `pubkey` 派生（79 字符口径，与客户端确认值
/// 一致性由客户端 UI 保证）。成功 = 静默（无应答帧）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerUpsert {
    pub domain: String,
    /// 该 relay Ed25519 公钥（raw 32 字节）。
    pub pubkey: [u8; 32],
    #[serde(default)]
    pub note: String,
}

///
/// 撤销 = 彻底断信：增量即时停 + **存量连带清理**（该源 peer 条目全删，
/// 设计默认，P10 记录表在案）。成功 = 静默（无应答帧）；源不存在 =
/// `DirError{not_found}`。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerDelete {
    pub domain: String,
}

///
/// 按 `fp`（79 字符精确）定位；不存在 = `DirError{not_found}`。
/// 成功 = 静默（无应答帧）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerToggle {
    pub fp: String,
    pub enabled: bool,
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
    /// ID-001：`device_id` / `ed25519_pub` 为设备 ID 模式
    /// 注册字段 —— 有 `device_id` 时服务器登记在线表；`None` 为纯控制
    /// 连接（如仅解析）。`device_id` 优先显式配置，否则由公钥指纹派生。
    ///
    /// TNL-PROTO-011：`auth_nonce` / `auth_digest` 为挑战-
    /// 响应认证字段（TNL-SEC-006，口令永不明文上线）—— 探测帧携带
    /// `auth_nonce`（客户端随机数，token 恒为空串），证明帧携带
    /// `auth_digest`（HMAC-SHA256 证明）；旧载荷（无此二字段）serde
    /// default 补缺，向后兼容。
    Login {
        token: String,
        version: String,
        hostname: String,
        #[serde(default)]
        device_id: Option<String>,
        #[serde(default)]
        ed25519_pub: Option<String>,
        #[serde(default)]
        auth_nonce: Option<[u8; 16]>,
        #[serde(default)]
        auth_digest: Option<Vec<u8>>,
    },
    /// frps → frpc：登录应答（TNL-PROTO-002）。
    ///
    /// TNL-PROTO-012：`auth_digest` 为服务端回执（双向认证，
    /// TNL-SEC-007），仅 `ok=true` 时携带。
    LoginResp {
        ok: bool,
        err: Option<String>,
        server_version: String,
        #[serde(default)]
        auth_digest: Option<Vec<u8>>,
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
    StartWorkConn { proxy_name: String, conn_id: u64 },
    /// frpc → frps：解绑代理端口（TNL-PROTO-006）。
    CloseProxy { name: String },
    /// frpc → frps：优雅下线（TNL-PROTO-006）。
    Logout,
    /// 双向心跳（TNL-PROTO-005；Pong 回显 Ping 的 ts）。
    Ping { ts: u64 },
    /// 双向心跳应答（TNL-PROTO-005）。
    Pong { ts: u64 },
    /// TNL-PROTO-010：服务端挑战（口令模式两阶段握手，
    /// TNL-SEC-006）—— `nonce` 为每次连接全新随机数（16 字节 CSPRNG，
    /// TNL-NF-006 防重放，无需服务端 nonce 去重缓存）。
    ///
    /// ⚠️ 枚举**末尾**追加（追加不影响既有 wire 变体索引；后续变体继续
    /// 追加，勿插入中间）。
    AuthChallenge { nonce: [u8; 16] },
    ///
    /// 认证（口令挑战-响应）通过后、`LoginResp` 之前，凡 `Login` 携带
    /// `device_id` 必经本挑战：服务器下发 32B CSPRNG nonce（每连接全新，
    /// 防重放），设备须以**设备私钥** Ed25519 签名
    /// [`registration_proof_payload`] 回 [`ControlMsg::RegProof`]；验签通过
    /// 才登记/替换在线条目（堵 ZD-01「无持钥证明的重注册接管」）。验签
    /// 失败 = `LoginResp{ok:false}` + `DeviceRejected` 审计。
    ///
    /// ⚠️ 枚举**末尾**追加（既有变体索引逐位不变）。
    RegChallenge { nonce: [u8; 32] },
    /// [`ControlMsg::RegChallenge`]）。`device_id` / `ed25519_pub` 须与
    /// `Login` 一致；`signature` = 设备私钥对 [`registration_proof_payload`]
    /// 的 Ed25519 签名。服务器侧验签 + 指纹形态 ID 的 (pubkey→ID) 一致性
    /// 双校验（见 registry `register_with_proof`）。
    ///
    /// ⚠️ 枚举**末尾**追加。
    RegProof {
        device_id: String,
        ed25519_pub: String,
        signature: Vec<u8>,
    },
}

///
/// `payload = "KIRIN-REG1" ‖ nonce(32B) ‖ device_id ‖ ed25519_pub`——域分隔
/// 前缀防跨协议重放（注册挑战 ≠ 其他挑战面）；绑定 device_id + 公钥防
/// 证明挪用至其他条目。
pub fn registration_proof_payload(nonce: &[u8; 32], device_id: &str, ed25519_pub: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(11 + 32 + device_id.len() + ed25519_pub.len());
    payload.extend_from_slice(b"KIRIN-REG1");
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(device_id.as_bytes());
    payload.extend_from_slice(ed25519_pub.as_bytes());
    payload
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

/// 编码 0x80+ 扩展区消息（解析/候选/中继；P1：候选互转/打洞结果）。
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

/// 宣称长度只先按此上限小额分配，随实际到达数据分块扩容。宣称 16 MiB 的
/// 恶意/半开连接不再一次性 `vec![0u8; 16MiB]` 吃满内存（慢连接 × 16 MiB
/// 内存放大面封堵；合法大帧功能不变，只是按需增长）。
pub const FRAME_PREALLOC_CAP: usize = 64 * 1024;
const FRAME_READ_CHUNK: usize = 16 * 1024;

/// 先按 [`FRAME_PREALLOC_CAP`] 小额分配、随实际到达数据扩容）。
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
    let mut payload = Vec::with_capacity((len as usize).min(FRAME_PREALLOC_CAP));
    let mut buf = [0u8; FRAME_READ_CHUNK];
    let mut remaining = len as usize;
    while remaining > 0 {
        let n = remaining.min(buf.len());
        reader.read_exact(&mut buf[..n]).await?;
        payload.extend_from_slice(&buf[..n]);
        remaining -= n;
    }
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

/// 旧版 Login 载荷（v1.0，5 字段：token/version/hostname/device_id/ed25519_pub）。
///
/// bincode 对结构体按字段序定长读取、**不支持** `#[serde(default)]` 补缺
/// （缺字段 → 越界读 "io error"），因此 TNL-PROTO-011 的旧载荷兼容需
/// 显式回退解码：剥离变体标记后按旧结构重解（见 [`decode_legacy_login`]）。
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct LegacyLogin {
    pub token: String,
    pub version: String,
    pub hostname: String,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub ed25519_pub: Option<String>,
}

/// 兼容解码旧版 Login 载荷（TNL-PROTO-011 / T6）：
/// `[variant:u32 LE][5 字段]` → [`LegacyLogin`]。失败 = 非旧版载荷。
pub fn decode_legacy_login(payload: &[u8]) -> Result<LegacyLogin, ProtocolError> {
    if payload.len() < 4 {
        return Err(ProtocolError::Bincode("payload too short for variant tag".to_string()));
    }
    // bincode 枚举变体标记：u32 小端（ControlMsg::Login = 0）。
    let variant = u32::from_le_bytes(payload[..4].try_into().unwrap());
    if variant != 0 {
        return Err(ProtocolError::Bincode(format!(
            "not a Login payload (variant {variant})"
        )));
    }
    bincode::deserialize(&payload[4..]).map_err(|e| ProtocolError::Bincode(e.to_string()))
}

/// 协议版本主版本号（"1.0.0" → "1"）；协商不兼容判定用（TNL-PROTO-008）。
pub fn major_version(version: &str) -> u64 {
    version
        .split('.')
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

/// HMAC-SHA256 摘要（TNL-PROTO-013）：挑战-响应认证的证明/回执原语。
///
/// - 客户端证明：`client_digest = HMAC-SHA256(token, server_nonce ‖ client_nonce)`；
/// - 服务端回执：`server_digest = HMAC-SHA256(token, client_nonce)`；
/// - 两端均常数时间比较（防时序侧信道，TNL-SEC-001 延续）。
///
/// HMAC 接受任意长度密钥，`new_from_slice` 不会失败（RFC 2104 §2）。
pub fn auth_digest(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn test_short_code_derivation_and_shapes() {
        let full = "a1b2:c3d4:e5f6:a7b8:c9d0:e1f2:a3b4:c5d6:e7f8:a9b0:c1d2:e3f4:a5b6:c7d8:e9f0:a1b2";
        // 确定性：同 ID 重复派生一致；= 指纹前 10 hex 小写。
        assert_eq!(device_id_short_code(full).as_deref(), Some("a1b2c3d4e5"));
        assert_eq!(device_id_short_code(full), device_id_short_code(full));
        // 大写指纹同样派生小写短码（形态判定忽略大小写）。
        let upper = "A1B2:C3D4:E5F6:A7B8:C9D0:E1F2:A3B4:C5D6:E7F8:A9B0:C1D2:E3F4:A5B6:C7D8:E9F0:A1B2";
        assert_eq!(device_id_short_code(upper).as_deref(), Some("a1b2c3d4e5"));
        // 非指纹形态（自定义 ID）无短码。
        assert_eq!(device_id_short_code("pc-a"), None);
        assert_eq!(device_id_short_code(""), None);
        assert_eq!(device_id_short_code(&"a".repeat(63)), None);
        assert_eq!(device_id_short_code(&"z".repeat(64)), None); // 64 字符但非 hex
        // 短码形态判定：恰 10 小写 hex；大写/带冒号/长度不符均否。
        assert!(is_short_code("a1b2c3d4e5"));
        assert!(!is_short_code("A1B2C3D4E5"));
        assert!(!is_short_code("a1b2:c3d4"));
        assert!(!is_short_code("a1b2c3d4e"));
        assert!(!is_short_code("a1b2c3d4e5f"));
        assert!(is_short_code("0000000000"));
        // 指纹形态判定。
        assert!(is_fingerprint_device_id(full));
        assert!(is_fingerprint_device_id(&flat_hex(full)));
        assert!(!is_fingerprint_device_id("pc-a"));
    }

    /// 去冒号展平指纹（测试辅助）。
    fn flat_hex(s: &str) -> String {
        s.chars().filter(|c| *c != ':').collect()
    }

    #[test]
    fn test_resolve_device_short_code_roundtrip() {
        let msg = ResolveDevice { device_id: "a1b2c3d4e5".into() };
        let frame = encode_extension(TYPE_RESOLVE_DEVICE, &msg).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(decode_extension::<ResolveDevice>(ty, payload, TYPE_RESOLVE_DEVICE).unwrap(), msg);
    }


    fn sample_msgs() -> Vec<ControlMsg> {
        vec![
            ControlMsg::Login {
                token: "tok-123".into(),
                version: PROTOCOL_VERSION.into(),
                hostname: "pc-a".into(),
                device_id: Some("pc-a-id".into()),
                ed25519_pub: Some("pub-a".into()),
                auth_nonce: None,
                auth_digest: None,
            },
            ControlMsg::Login {
                token: "tok-123".into(),
                version: PROTOCOL_VERSION.into(),
                hostname: "resolver".into(),
                device_id: None,
                ed25519_pub: None,
                auth_nonce: None,
                auth_digest: None,
            },
            ControlMsg::LoginResp {
                ok: true,
                err: None,
                server_version: PROTOCOL_VERSION.into(),
                auth_digest: None,
            },
            ControlMsg::LoginResp {
                ok: false,
                err: Some("bad token".into()),
                server_version: PROTOCOL_VERSION.into(),
                auth_digest: None,
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
            // 挑战帧 + 带 auth 字段的登录消息。
            ControlMsg::Login {
                token: String::new(),
                version: PROTOCOL_VERSION.into(),
                hostname: "pc-a".into(),
                device_id: Some("pc-a-id".into()),
                ed25519_pub: Some("pub-a".into()),
                auth_nonce: Some([7; 16]),
                auth_digest: Some(vec![1, 2, 3, 4]),
            },
            ControlMsg::LoginResp {
                ok: true,
                err: None,
                server_version: PROTOCOL_VERSION.into(),
                auth_digest: Some(vec![9, 8, 7, 6]),
            },
            ControlMsg::AuthChallenge { nonce: [3; 16] },
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
        // 未知 type → 判死（TNL-PROTO-007）；0x80~0x94 扩展区为已知类型
        for ty in [0x05u8, 0x7f, 0x96, 0xff, TYPE_EXT_END + 1] {
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
    // 0x80+ 扩展区消息 round-trip
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
                auth_nonce: None,
                auth_digest: None,
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
    // 挑战-响应认证（TNL-PROTO-009~013）
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_old_login_payload_auth_fields_default() {
        // 旧载荷（5 字段 Login，无 auth_nonce/auth_digest）兼容解码
        // （TNL-PROTO-011 / T6）：bincode 不支持 serde(default) 补缺，
        // 走显式回退 [`decode_legacy_login`]（剥离变体标记 + 旧结构重解）。
        #[derive(serde::Serialize)]
        struct OldLogin<'a> {
            token: &'a str,
            version: &'a str,
            hostname: &'a str,
            device_id: Option<&'a str>,
            ed25519_pub: Option<&'a str>,
        }
        let old_bytes = bincode::serialize(&OldLogin {
            token: "t",
            version: "1.0.0",
            hostname: "h",
            device_id: Some("pc-a-id"),
            ed25519_pub: Some("pub-a"),
        })
        .unwrap();
        // 旧客户端 wire 载荷 = 枚举变体标记 u32(Login=0) + 5 字段。
        let mut wire = 0u32.to_le_bytes().to_vec();
        wire.extend_from_slice(&old_bytes);
        // 完整帧 = [type][len][payload]；decode_control 对旧载荷越界失败
        // （预期），回退解码成功。
        let frame = wrap_frame(TYPE_CONTROL, &wire);
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert!(decode_control(ty, payload).is_err(), "7 字段结构无法读 5 字段旧载荷");
        let legacy = decode_legacy_login(payload).unwrap();
        assert_eq!(legacy.token, "t");
        assert_eq!(legacy.version, "1.0.0");
        assert_eq!(legacy.hostname, "h");
        assert_eq!(legacy.device_id.as_deref(), Some("pc-a-id"));
        assert_eq!(legacy.ed25519_pub.as_deref(), Some("pub-a"));

        // 非 Login 变体 / 垃圾 → 拒绝。
        let mut not_login = wire.clone();
        not_login[..4].copy_from_slice(&3u32.to_le_bytes()); // NewProxy 变体标记
        let frame = wrap_frame(TYPE_CONTROL, &not_login);
        let (_, payload) = decode_frame(&frame).unwrap();
        assert!(decode_legacy_login(payload).is_err());
        assert!(decode_legacy_login(&[0u8; 2]).is_err());
        assert!(decode_legacy_login(b"garbage-data-here").is_err());
    }

    #[test]
    fn test_auth_digest_rfc4231_vectors() {
        // HMAC-SHA256 已知向量（RFC 4231 §4.2/4.3，TNL-PROTO-013 验收）。
        // 测试用例 1：key = 0x0b × 20，data = "Hi There"。
        let key = [0x0bu8; 20];
        let digest = auth_digest(&key, b"Hi There");
        let expect: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(digest, expect.to_vec(), "RFC 4231 TC1");
        // 测试用例 2：key = "Jefe"，data = "what do ya want for nothing?"。
        let digest = auth_digest(b"Jefe", b"what do ya want for nothing?");
        let expect: [u8; 32] = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(digest, expect.to_vec(), "RFC 4231 TC2");
        // 长度恒为 32 字节（HMAC-SHA256 输出）。
        assert_eq!(auth_digest(b"", b"").len(), 32);
        assert_eq!(auth_digest(&[0u8; 64], &[0u8; 100]).len(), 32);
    }

    #[test]
    fn test_auth_digest_deterministic() {
        // 同输入 → 同输出；不同 nonce 组合 → 不同输出（防重放语义基础）。
        let token = b"super-secret-token";
        let s1 = [1u8; 16];
        let s2 = [2u8; 16];
        let c = [3u8; 16];
        let d1 = auth_digest(token, &[s1, c].concat());
        assert_eq!(d1, auth_digest(token, &[s1, c].concat()));
        // 服务器 nonce 变化 → digest 变化（旧对重放必然失败）。
        assert_ne!(d1, auth_digest(token, &[s2, c].concat()));
        // 客户端 nonce 变化 → digest 变化（回执也随 client_nonce 变）。
        assert_ne!(d1, auth_digest(token, &[s1, [4u8; 16]].concat()));
        assert_ne!(
            auth_digest(token, &c),
            auth_digest(token, &[c, [5u8; 16]].concat())
        );
    }

    // ════════════════════════════════════════════════════════════
    // PathProbe/PathProbeAck + 打洞探测报文（0x89/0x8A）
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
        // 0x80~0x94 全部已知，0x95 仍未知；既有 0x80~0x8A 逐位不变。
        for ty in TYPE_RESERVED_BASE..=TYPE_EXT_END {
            assert!(is_known_type(ty), "0x{ty:02x} should be known");
        }
        assert_eq!(TYPE_EXT_END, 0x94);
        assert!(!is_known_type(0x95));
    }

    // ════════════════════════════════════════════════════════════════
    // ════════════════════════════════════════════════════════════════

    /// 类型号段冻结核（v2）：在役五帧号段 + 废帧保留清单 + 版本串定值。
    #[test]
    fn test_r140_1_frame_type_numbers_frozen() {
        // 在役五帧号位零变（1.2.0 → 1.3.0 型号逐位不变）。
        assert_eq!(TYPE_DIR_LIST, 0x8B);
        assert_eq!(TYPE_DIR_LIST_RESP, 0x8C);
        assert_eq!(TYPE_DIR_UPSERT, 0x8D);
        assert_eq!(TYPE_DIR_DELETE, 0x8E);
        assert_eq!(TYPE_DIR_ERROR, 0x8F);
        // 废帧保留位（型号保留不复用；不得挪作他义）。
        assert_eq!(TYPE_PEER_LIST, 0x90);
        assert_eq!(TYPE_PEER_LIST_RESP, 0x91);
        assert_eq!(TYPE_PEER_UPSERT, 0x92);
        assert_eq!(TYPE_PEER_DELETE, 0x93);
        assert_eq!(TYPE_PEER_TOGGLE, 0x94);
        assert_eq!(DIRECTORY_FRAME_TYPES.len(), 5);
        for &ty in DIRECTORY_FRAME_TYPES {
            assert!(is_directory_frame_type(ty), "0x{ty:02x} 属在役目录区");
            assert!(!is_deprecated_directory_frame_type(ty));
        }
        assert_eq!(DEPRECATED_DIRECTORY_FRAME_TYPES.len(), 5);
        for &ty in DEPRECATED_DIRECTORY_FRAME_TYPES {
            assert!(is_deprecated_directory_frame_type(ty), "0x{ty:02x} 属废保留区");
            assert!(!is_directory_frame_type(ty), "废帧不得留在役判定面");
        }
        // TYPE_EXT_END 维持 0x94（v2 零新增 C 侧型号；废保留位在扩展区
        // 范围内 = 不判死连接，升级窗口 fail-closed 自限）。
        assert_eq!(TYPE_EXT_END, 0x94);
        // 区外类型不属目录区（0x8A 打洞区 / 0x95 未分配 / 0x01 控制）。
        assert!(!is_directory_frame_type(0x8A));
        assert!(!is_directory_frame_type(0x95));
        assert!(!is_directory_frame_type(TYPE_CONTROL));
        assert!(!is_deprecated_directory_frame_type(0x8A));
        assert!(!is_deprecated_directory_frame_type(0x95));
        // PROTOCOL_VERSION=4）。
        assert_eq!(PROTOCOL_VERSION, "2.0.0");
        assert_eq!(major_version(PROTOCOL_VERSION), 2);
        // C-1 注册挑战双变体在枚举**末尾**（既有变体索引逐位不变——
        // AuthChallenge 序列化字节与 1.3.0 期一致，前缀形状钉死）。
        let auth = bincode::serialize(&ControlMsg::AuthChallenge { nonce: [3u8; 16] }).unwrap();
        assert_eq!(auth[..4], 9u32.to_le_bytes(), "AuthChallenge 变体索引不变");
        let regc = bincode::serialize(&ControlMsg::RegChallenge { nonce: [3u8; 32] }).unwrap();
        assert_eq!(regc[..4], 10u32.to_le_bytes(), "RegChallenge = 末尾追加位 10");
        let regp = bincode::serialize(&ControlMsg::RegProof {
            device_id: "d".into(),
            ed25519_pub: "k".into(),
            signature: vec![1, 2],
        })
        .unwrap();
        assert_eq!(regp[..4], 11u32.to_le_bytes(), "RegProof = 末尾追加位 11");
        // 注册证明载荷钉死：域分隔前缀 + nonce + 身份字段（跨端实现锚）。
        let payload = registration_proof_payload(&[7u8; 32], "dev-a", "pub-b");
        let expect: Vec<u8> = b"KIRIN-REG1"
            .iter()
            .copied()
            .chain([7u8; 32])
            .chain(b"dev-a".iter().copied())
            .chain(b"pub-b".iter().copied())
            .collect();
        assert_eq!(payload, expect);
    }

    /// DirErrorCode 六码重冻双向映射（`quota_exceeded` 入 /
    /// `limit_exceeded` 废 = 解析必 `None`，wire 出现 = 协议违规）。
    #[test]
    fn test_r140_1_dir_error_codes_frozen() {
        let cases: [(DirErrorCode, &str); 6] = [
            (DirErrorCode::AuthFailed, "auth_failed"),
            (DirErrorCode::NotFound, "not_found"),
            (DirErrorCode::InvalidDeviceId, "invalid_device_id"),
            (DirErrorCode::InvalidDomain, "invalid_domain"),
            (DirErrorCode::QuotaExceeded, "quota_exceeded"),
            (DirErrorCode::Busy, "busy"),
        ];
        for (code, s) in cases {
            assert_eq!(code.as_str(), s);
            assert_eq!(DirErrorCode::parse(s), Some(code));
        }
        assert_eq!(DirErrorCode::parse("unknown_code"), None);
        assert_eq!(DirErrorCode::parse(""), None);
        // v1 废码 = 不识别（码位不回收；出现即协议违规判死口径的数据面）。
        assert_eq!(DirErrorCode::parse("limit_exceeded"), None);
    }

    /// 对照锚）：DirList(+filter_device 三值/default) / DirListResp(7 字段
    /// DirEntry) / DirUpsert / DirDelete / DirError(六码)。
    #[test]
    fn test_r140_1_dir_frames_roundtrip() {
        // DirList（默认 scope = All + filter_device = None）。
        let dl = DirList::default();
        assert_eq!(dl.scope, DirScope::All);
        assert_eq!(dl.filter_device, None);
        let frame = encode_extension(TYPE_DIR_LIST, &dl).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(
            decode_extension::<DirList>(ty, payload, TYPE_DIR_LIST).unwrap(),
            dl
        );
        // DirScope 三形态（变体 wire 形态不变 = 变体索引零变）。
        for scope in [
            DirScope::All,
            DirScope::Local,
            DirScope::Peer("aa:bb".into()),
        ] {
            let dl = DirList {
                scope: scope.clone(),
                ..Default::default()
            };
            let bytes = bincode::serialize(&dl).unwrap();
            assert_eq!(bincode::deserialize::<DirList>(&bytes).unwrap(), dl);
        }
        // filter_device 三值矩阵（None / Some(自定义) / Some(79 字符指纹)）。
        for fd in [
            None,
            Some("dev-x".to_string()),
            Some(
                "a1b2:c3d4:e5f6:0718:293a:4b5c:6d7e:8f90:a1b2:c3d4:e5f6:0718:293a:4b5c:6d7e:8f90"
                    .to_string(),
            ),
        ] {
            let dl = DirList { filter_device: fd.clone(), ..Default::default() };
            assert_eq!(
                bincode::deserialize::<DirList>(&bincode::serialize(&dl).unwrap()).unwrap(),
                dl
            );
        }
        // refresh=true 形态（v2 = 触发全量重推，运维面）。
        let dl = DirList {
            refresh: true,
            ..Default::default()
        };
        assert_eq!(
            bincode::deserialize::<DirList>(&bincode::serialize(&dl).unwrap()).unwrap(),
            dl
        );
        // DirUpsert（5 字段：device_id/domain/target_domain/note/ix_token）。
        let up = DirUpsert {
            device_id: "a1b2:c3d4".into(),
            domain: "dev.kirin.example".into(),
            target_domain: "relay-b.kirin.example".into(),
            note: Some("note".into()),
            ix_token: "tok-abc".into(),
        };
        let frame = encode_extension(TYPE_DIR_UPSERT, &up).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(
            decode_extension::<DirUpsert>(ty, payload, TYPE_DIR_UPSERT).unwrap(),
            up
        );
        let up0 = DirUpsert {
            device_id: "a1b2:c3d4".into(),
            domain: "dev.kirin.example".into(),
            target_domain: "relay-b.kirin.example".into(),
            note: None,
            ix_token: String::new(),
        };
        assert_eq!(
            bincode::deserialize::<DirUpsert>(&bincode::serialize(&up0).unwrap()).unwrap(),
            up0
        );
        // DirDelete（2 字段：device_id/target_domain）。
        let del = DirDelete {
            device_id: "x".into(),
            target_domain: "relay-b.kirin.example".into(),
        };
        let frame = encode_extension(TYPE_DIR_DELETE, &del).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(
            decode_extension::<DirDelete>(ty, payload, TYPE_DIR_DELETE).unwrap(),
            del
        );
        // DirError（v2 六码枚举 + 人话 msg）。
        for code in [
            DirErrorCode::AuthFailed,
            DirErrorCode::NotFound,
            DirErrorCode::InvalidDeviceId,
            DirErrorCode::InvalidDomain,
            DirErrorCode::QuotaExceeded,
            DirErrorCode::Busy,
        ] {
            let e = DirError { code, msg: "detail".into() };
            let bytes = bincode::serialize(&e).unwrap();
            assert_eq!(bincode::deserialize::<DirError>(&bytes).unwrap(), e);
        }
        // DirListResp（外壳零改 + 7 字段 DirEntry；空表 = 空数组非错；
        // 自持行 source_fp=空串 / pushed 行 source_fp=79 字符；
        // sig_verified 写时验口径 = 全来源恒 true，双态可表达）。
        let resp = DirListResp {
            entries: vec![
                DirEntry {
                    device_id: "a1".into(),
                    device_domain: "a.kirin.example".into(),
                    target_domain: "relay-b.kirin.example".into(),
                    source: "manual".into(),
                    source_fp: String::new(),
                    updated_at: 111,
                    sig_verified: true,
                },
                DirEntry {
                    device_id: "a2".into(),
                    device_domain: "b.kirin.example".into(),
                    target_domain: "relay-self.kirin.example".into(),
                    source: "pushed".into(),
                    source_fp: "bb:cc".into(),
                    updated_at: 222,
                    sig_verified: true,
                },
            ],
            server_ts: 123,
            epoch: 7,
        };
        let frame = encode_extension(TYPE_DIR_LIST_RESP, &resp).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(
            decode_extension::<DirListResp>(ty, payload, TYPE_DIR_LIST_RESP).unwrap(),
            resp
        );
        let empty = DirListResp { entries: vec![], server_ts: 1, epoch: 0 };
        assert_eq!(
            bincode::deserialize::<DirListResp>(&bincode::serialize(&empty).unwrap()).unwrap(),
            empty
        );
    }

    /// v1↔v2 新旧字段矩阵（升级窗口 fail-closed 自限钉死，设计 §7.3）：
    /// 旧客户端（1.2.0 三/单/双字段载荷）对 v2 解码**必败**（字段数不符
    /// = 越界读 io error → 坏帧判死/丢弃，不半信）；反之 v2 载荷对 v1
    /// 形状解码亦必败（多字段尾读越界）。测试侧内联 v1 形状结构体
    /// （仅测试面，非生产类型——生产废帧面不复用 v1 语义）。
    #[test]
    fn test_r140_1_v1_v2_field_matrix_refused() {
        #[derive(Serialize)]
        struct V1DirUpsert<'a> {
            device_id: &'a str,
            domain: &'a str,
            note: Option<&'a str>,
        }
        #[derive(Serialize)]
        struct V1DirDelete<'a> {
            device_id: &'a str,
        }
        #[derive(Serialize)]
        struct V1DirList {
            scope: DirScope, // 变体 wire 形态不变，直接复用
            refresh: bool,
        }
        #[derive(Serialize)]
        struct V1DirEntry<'a> {
            device_id: &'a str,
            domain: &'a str,
            source: &'a str,
            peer_fp: &'a str,
            updated_at: u64,
            sig_verified: bool,
        }
        #[derive(Serialize)]
        struct V1DirListResp<'a> {
            entries: Vec<V1DirEntry<'a>>,
            server_ts: u64,
            epoch: u64,
        }

        // ① v1 DirUpsert（3 字段，note=None 与 note=Some 两态）→ v2 解码必败。
        for note in [None, Some("legacy")] {
            let v1 = bincode::serialize(&V1DirUpsert {
                device_id: "dev-x",
                domain: "a.example.com",
                note,
            })
            .unwrap();
            assert!(
                bincode::deserialize::<DirUpsert>(&v1).is_err(),
                "v1 3 字段 DirUpsert 载荷不得被 v2 4 字段结构接受（fail-closed）"
            );
        }
        // ② v1 DirDelete（1 字段）→ v2 解码必败。
        let v1 = bincode::serialize(&V1DirDelete { device_id: "dev-x" }).unwrap();
        assert!(bincode::deserialize::<DirDelete>(&v1).is_err());
        // ③ v1 DirList（2 字段）→ v2 解码必败（尾部 filter_device 越界）。
        let v1 = bincode::serialize(&V1DirList { scope: DirScope::All, refresh: false }).unwrap();
        assert!(bincode::deserialize::<DirList>(&v1).is_err());
        // ④ v1 DirListResp（6 字段 DirEntry）→ v2 解码必败（entries 内嵌 7 字段）。
        let v1 = bincode::serialize(&V1DirListResp {
            entries: vec![V1DirEntry {
                device_id: "dev-x",
                domain: "a.example.com",
                source: "manual",
                peer_fp: "",
                updated_at: 1_700_000_000,
                sig_verified: true,
            }],
            server_ts: 1,
            epoch: 1,
        })
        .unwrap();
        assert!(bincode::deserialize::<DirListResp>(&v1).is_err());
        // ⑤ 反向：v2 载荷 → v1 形状解码必败（v2 5 字段 DirUpsert 对 v1 3 字段结构
        // 尾读 target_domain/note/ix_token 越界或错位——双向都不半信）。
        let v2 = bincode::serialize(&DirUpsert {
            device_id: "dev-x".into(),
            domain: "a.example.com".into(),
            target_domain: "b.example.com".into(),
            note: None,
            ix_token: String::new(),
        })
        .unwrap();
        #[derive(Deserialize)]
        #[allow(dead_code)] // 字段仅经 bincode 映射消费（矩阵拒收断言不读值）
        struct V1DirUpsertDec {
            device_id: String,
            domain: String,
            note: Option<String>,
        }
        assert!(bincode::deserialize::<V1DirUpsertDec>(&v2).is_err());
        let v2 = bincode::serialize(&DirDelete {
            device_id: "dev-x".into(),
            target_domain: "b.example.com".into(),
        })
        .unwrap();
        #[derive(Deserialize)]
        #[allow(dead_code)] // 字段仅经 bincode 映射消费（矩阵拒收断言不读值）
        struct V1DirDeleteDec {
            device_id: String,
        }
        // v2 DirDelete → v1 形状解码：bincode 只消费 device_id 前缀（尾部
        // target_domain 字节不读）= 裸形状解码**不**硬败。本方向的混版
        // 互拒主屏障 = Login 版本串（1.2.0 vs 1.3.0）协议级门禁（§7.3），
        // 不靠本帧形状。此处钉死可检测面 = 读游标止于帧中（尾部残留
        // 非空 = 形状长度失配，升级窗口取证可判）。
        let mut cursor = std::io::Cursor::new(&v2[..]);
        let _v1d: V1DirDeleteDec = bincode::deserialize_from(&mut cursor).unwrap();
        assert!(
            (cursor.position() as usize) < v2.len(),
            "v2 DirDelete 帧尾部对 v1 形状必须非空（长度失配可检测）"
        );
    }

    /// 【废帧保留】Peer* 帧 v1 载荷 bincode 往返（wire 形状冻结零改——
    /// 型号 0x90~0x94 保留不复用，结构仅供升级窗口结构校验/取证；
    #[test]
    fn test_r140_1_peer_frames_deprecated_shape_pinned() {
        // PeerList（单元结构体）。
        let pl = PeerList {};
        let frame = encode_extension(TYPE_PEER_LIST, &pl).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(
            decode_extension::<PeerList>(ty, payload, TYPE_PEER_LIST).unwrap(),
            pl
        );
        // PeerUpsert（32B 公钥）。
        let mut key = [0u8; 32];
        key[0] = 0xAB;
        let up = PeerUpsert {
            domain: "relay.kirin.example".into(),
            pubkey: key,
            note: "peer note".into(),
        };
        let frame = encode_extension(TYPE_PEER_UPSERT, &up).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(
            decode_extension::<PeerUpsert>(ty, payload, TYPE_PEER_UPSERT).unwrap(),
            up
        );
        // PeerDelete / PeerToggle。
        let del = PeerDelete { domain: "relay.kirin.example".into() };
        let frame = encode_extension(TYPE_PEER_DELETE, &del).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(
            decode_extension::<PeerDelete>(ty, payload, TYPE_PEER_DELETE).unwrap(),
            del
        );
        for enabled in [true, false] {
            let tg = PeerToggle { fp: "cc:dd".into(), enabled };
            let frame = encode_extension(TYPE_PEER_TOGGLE, &tg).unwrap();
            let (ty, payload) = decode_frame(&frame).unwrap();
            assert_eq!(
                decode_extension::<PeerToggle>(ty, payload, TYPE_PEER_TOGGLE).unwrap(),
                tg
            );
        }
        // PeerListResp（last_sync 双态）。
        let resp = PeerListResp {
            peers: vec![
                PeerInfo {
                    domain: "r1.kirin.example".into(),
                    fp: "aa:bb".into(),
                    enabled: true,
                    note: String::new(),
                    last_sync: Some(42),
                },
                PeerInfo {
                    domain: "r2.kirin.example".into(),
                    fp: "cc:dd".into(),
                    enabled: false,
                    note: "n".into(),
                    last_sync: None,
                },
            ],
            server_ts: 99,
        };
        let frame = encode_extension(TYPE_PEER_LIST_RESP, &resp).unwrap();
        let (ty, payload) = decode_frame(&frame).unwrap();
        assert_eq!(
            decode_extension::<PeerListResp>(ty, payload, TYPE_PEER_LIST_RESP).unwrap(),
            resp
        );
    }
}
