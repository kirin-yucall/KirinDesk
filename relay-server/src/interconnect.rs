//! （B 侧）+ v1 pull 链拆除（设计 §3 全八时序 / §2.3 / §7）。
//!
//! **发布约定**（与设备三件套同记录类型、**不同 key 空间**，零新发现机制）：
//! - SRV `_kirin-relay._tcp.<relay 域>` = 互联端口（本端口）；
//! - TXT `<relay 域>` = JSON `{"node_type":"relay","public_key":"<base64 Ed25519 32B>"}`
//!   （`node_type` 与设备 `DeviceMeta` 区分，设备面解析零影响）；
//! - AAAA/A `<relay 域>` = 寻址。
//! relay 进程自身**不发布** DNS（无 DNS 写入依赖）。
//!
//! 拒连〔`--ix-legacy-grace` on 时旧 `/2` 按旧五门宽限受理，默认关〕；
//! 每次互访新建连接、无持久互联态、无会话恢复 = 简化 fail-closed）：
//! ```text
//! A ── HelloA { ver, nonce_a, eph_pub_a, id_pub_a, id_domain_a, sig_a }（明文 bincode）──► B
//!     sig_a = Ed25519(id_priv_a, ver_bytes ‖ nonce_a ‖ id_pub_a ‖ id_domain_a)
//! B：ver == RELAY-DIR/2 且 id_domain 纯 FQDN 且 id_pub 可解析 且 sig 验签
//!     （握手受理门；信任锚 = 数据帧阶段 DNS-TXT **现场解析**互证——
//!     设计风险① 缓解：TOFU 现场解析为准，§2.3 门①）
//! B ── HelloB（同构，id_domain_b = B 自身 FQDN，来自 --relay-domain）──► A
//! A：对称同法（B 必须以**拨号域**自认 + id_pub == **预解析 TXT 公钥**）
//! 会话密钥 = HKDF-SHA256(X25519(eph_a, eph_b))（core EphemeralSession，
//!     零新原语 P3）；后续帧 AES-256-GCM（core AeadCipher），AAD = [type]‖ver_bytes，
//!     **nonce 每帧全新 12B 随机**（同构 TNL-NF-006 口径）。
//! A ── IxPush{epoch, entries[PushEntry], batch_sig}（AEAD）──► B
//!     PushEntry{device_id, domain, updated_at, sig}（sig = **推送时逐条新签**）；
//!     entries = B 的**声明式全量子集**（空数组合法 = 全撤销态，无 ACK 帧）；
//!     逐条 sig 覆盖域 = entry_sig_message_v2（接收方 fp 绑定 = 防改道重放）；
//!     batch_sig 覆盖域 = batch_sig_message_v2（前缀 RELAY-DIR-PUSH/1）。
//! ```
//!
//! **A 侧推送引擎**（§3 T1/T2/T3/T4/T6/T8）：
//! - 变更即推：`DirUpsert`/`DirDelete`（target ≠ 自域）同事务写 `push_outbox`
//!   触发记录后异步（非阻塞）`push_to(target)`——用户操作成功判据 = A 侧
//!   写入确认，B 可达性不影响用户操作成败；
//! - 周期重推：`run_push_cycle`（`--push-repush-interval` 默认 1h ± 60s
//!   抖动）对全部已知 targets（自持行 distinct target ∪ outbox targets）
//!   各推一份声明式全量子集（声明式 = 天然对账，收敛上界 = 1 个周期）；
//! - 失败重试：`run_sweep`（30s tick）outbox 退避重试（30s→2min→10min cap）
//!   + 行 TTL 24h 剪除；**任意一次成功推送 = 该 target 全部 outbox 行
//!   superseded 剪除**；
//! - liveness 清扫（T8）：慢扫（300s 间隔）devlast 超龄且不在注册表
//!   （探针）的自持行 = 删行 + epoch+1 + 立即重推（推撤销）+ 审计；
//!   （`push_to`/`trigger_target`）同界排队（ZD-03 放大面封堵）。
//!
//! （TOFU 现场解析为准）+ HELLO id_pub 互证 → `batch_sig_v2`（现场解析
//! 源公钥）→ per-source cap（批次 distinct device 数）→ 形态复检
//! （`normalize_device_id` + `is_pure_fqdn` = malformed_entry）→ 逐条
//! sig（recipient_fp = 本方 fp；改道批次在此必败）→ epoch 水位（`<` last
//! token**：AEAD 帧体内 `ix_token` 与本机 `ix_tokens(source='cli')` 活跃
//! = hex(sha256(token))，比较对象变为哈希值，常时语义与三态 reason 零
//! 变化）——无 token / 不匹配 / 已撤销 = 整批拒收 + `push rejected`
//! 审计（fail-closed 不半信；A 侧查无 device token 的 target = 整轮跳过
//! 推送 + WARN 审计）。
//! 吃满门②验签 CPU 再拒收。）
//! **任一失败 = 整批拒收 + 本地表零变化**
//! （fail-closed 不半信）+ `push rejected` 审计。应用 = `apply_push_batch`
//! 单事务（upsert + PK 本地权威遮蔽 + 同源幂等 + 跨源 P10 裁决 +
//! revocation-by-absence + 水位续约）。
//!
//! **旧 pull 链拆除**（§7）：`pull_from`/`sync_all_once`/`run_cycle`/
//! `SyncTrigger`/`PULL_INTERVAL`/`IxListReq`/`IxEntry`/`IxListResp`/
//! `batch_sig_message`("RELAY-DIR-BATCH/1") 全拆；废帧保留位 0x02/0x03
//! 到达 = 结构校验（帧头 + 长度界）+ 丢弃 + 审计，不解析不复用。
//!
//! **凭据零上链**（红线）：互联帧只携 device_id/domain/公钥/签名/ts/nonce/
//! FQDN——绝不携挑战码、relay token、设备会话密钥；审计零凭据。

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, Verifier};
use kirin_desk_core::crypto::aead::AeadCipher;
use kirin_desk_core::crypto::x25519::EphemeralSession;
use kirin_desk_dns::{Record, RecordData, RecordType, Resolver, ResolverError};
use kirin_desk_relay::audit::{AuditSink, TunnelAuditEvent};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::dir_backend::{is_pure_fqdn, normalize_device_id};
use crate::dir_store::{now_unix_secs, DirStore, PushApplyResult};


/// 互认版本串 v3（独立于 relay 面 1.3.0 与设备面 PROTOCOL_VERSION=3）。
/// **重冻**；旧串 = 握手拒连，§2.3；`--ix-legacy-grace` on 时旧 `/2` 对端
/// 按旧五门宽限受理——迁移期通道，默认关 = fail-closed）。
pub const INTERCONNECT_VERSION: &str = "RELAY-DIR/3";

/// 受理口径参与比较，本 build 自身**永不**以此串发起/应答握手）。
pub const INTERCONNECT_VERSION_LEGACY: &str = "RELAY-DIR/2";

/// 互认帧类型（`[type:u8][len:u32 BE][body]` 线形，同构 relay 帧头）。
pub const IX_FRAME_HELLO: u8 = 0x01;
pub const IX_FRAME_PUSH: u8 = 0x04;

/// 互认帧上限（16 MiB，同构 relay MAX_FRAME_LEN 口径）。
pub const IX_MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// 握手/读帧超时（fail-closed 有界）。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

const MAX_CONCURRENT_CONNS: usize = 16;

/// batch_sig_v2 消息前缀（冻结，§2.3）。
const PUSH_SIG_PREFIX: &str = "RELAY-DIR-PUSH/1";

/// entry_sig_message_v2 的分隔符（␟ = 0x1F US，冻结，§2.3）。
const SIG_FIELD_SEP: u8 = 0x1F;


/// 后台清扫 tick（30s；每 tick = outbox 退避重试 + ttl 剪除）。
const SWEEP_TICK: Duration = Duration::from_secs(30);

/// 慢扫间隔 = 每 10 tick（10×30s = 300s：B 侧 TTL 清扫 + A 侧 liveness 清扫，§T5/T8）。
const SLOW_SWEEP_EVERY: u64 = 10;

/// outbox 行 TTL（24h；周期重推是真正恢复通道，队列只服务短离线，§T4）。
pub const OUTBOX_TTL_SECS: u64 = 86400;

/// 周期重推抖动上限（±60s，打散重推风暴）。
const REPUSH_JITTER_MAX: u64 = 60;

// ── 帧载荷（bincode；字段序 = 冻结合同③） ────────────────────────────

/// 互认握手帧 v2（明文，ECDH 前必须明文以便验身份）。
/// （v1 = 前 3 项 + sig；v1 帧对本 build = 解码必败 = fail-closed 混合版本
/// 自限制，设计 §7.3）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IxHello {
    /// 版本串（`RELAY-DIR/3`；不符 = 拒——`/2` 仅宽限开关 on 时受理）。
    pub ver: String,
    /// 16B 随机 nonce（每次全新；重放防护 = 单次会话无恢复态）。
    pub nonce: [u8; 16],
    /// X25519 临时公钥（每会话生成不落盘，core EphemeralSession）。
    pub eph_pub: [u8; 32],
    /// Ed25519 长期公钥（relay `--server-key`；零新增密钥对）。
    pub id_pub: [u8; 32],
    /// 来自 `--relay-domain`；受理侧现场解析其三件套作信任锚，§2.3）。
    pub id_domain: String,
    /// `Ed25519(id_priv, ver_bytes ‖ nonce ‖ id_pub ‖ id_domain)`
    /// （v2 签名覆盖域冻结；v1 = 前三段，对新验签器必败）。
    /// wire = bincode `Vec<u8>`（u64 LE 长 ‖ 字节；长度恒 64，非 64 = 拒）。
    pub sig: Vec<u8>,
}

/// outbox 清理靠成功推送 superseded，§3.4）。载荷形状同构旧 IxListResp
/// 三字段（骨架复用），语义单向。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IxPush {
    /// 源 relay 目录 epoch（本域每次成功写入 +1，单调增）。
    pub epoch: u64,
    /// = 接收方 target 的**声明式全量子集**（空数组合法 = 「本接收方无
    /// 任何授权条目」= 全撤销态）。
    pub entries: Vec<PushEntry>,
    /// 整批签名（覆盖域 = [`batch_sig_message_v2`] 冻结格式；恒 64B）。
    pub batch_sig: Vec<u8>,
    /// 中继互联 token（AEAD 体内携带，**禁入明文 HELLO**——架构红线）。
    /// A 侧 = 从本机 `ix_tokens(source='device', target_domain=B)` 取出的
    /// 转发凭证（查无 = 该 target 整轮跳过推送 + WARN 审计，fail-closed
    /// 不推裸批）；B 侧门⑥ = 与本机 `ix_tokens(source='cli')` 活跃行
    /// hex(sha256(token))，库内零明文），无 token / 不匹配 / 已撤销 =
    /// 整批拒收 + PushRejected 审计。旧 `/2` 3 字段帧对新 build 解码必败
    /// （`decode_ix_push` 宽限路径专用旧结构承接，非本结构半信）。
    pub ix_token: String,
}

/// 零派生 = 本 build 永不产生旧格式帧；测试构串经 cfg(test) 派生）。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct IxPushLegacy {
    pub epoch: u64,
    pub entries: Vec<PushEntry>,
    pub batch_sig: Vec<u8>,
}

/// 冻结：epoch, entries, batch_sig, ix_token）；`legacy`（宽限路径）= 旧
/// 3 字段 `IxPushLegacy`（`ix_token` 置空，门⑥跳过——旧五门受理）。
/// 两形态互斥：`/3` 帧缺 token（空串）= 门⑥拒；`/2` 旧帧对 current 解码
/// 必败 = 混合版本 fail-closed 自限制先例继承。
pub fn decode_ix_push(pt: &[u8], legacy: bool) -> Result<IxPush, String> {
    if legacy {
        let old: IxPushLegacy =
            bincode::deserialize(pt).map_err(|e| format!("push decode (legacy /2): {e}"))?;
        return Ok(IxPush {
            epoch: old.epoch,
            entries: old.entries,
            batch_sig: old.batch_sig,
            ix_token: String::new(),
        });
    }
    bincode::deserialize(pt).map_err(|e| format!("push decode: {e}"))
}

/// - `/3`（本 build）= 受理（含门⑥ token 强制）；
/// - `/2`（旧版）= `legacy_grace` on → 宽限受理（旧五门，无 token 门）；
///   off（**默认**）→ Err(`legacy_no_token`)——拒 + 审计 reason 与卡面
///   矩阵一致；
/// - 其余串 = Err(`version mismatch (expected RELAY-DIR/3)`)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IxVersionAdmission {
    /// 当前版本（`/3`；门⑥ token 校验强制）。
    Current,
    /// 旧版宽限（`/2`；仅 `--ix-legacy-grace` on；门⑥跳过）。
    LegacyGrace,
}

pub fn version_admission(ver: &str, legacy_grace: bool) -> Result<IxVersionAdmission, String> {
    version_admission_at(ver, legacy_grace, None, now_unix_secs())
}

/// 生产消费点 = [`Self::handle_conn`] 握手版本门，现取墙钟时间）。
/// 语义：
/// - `/3`（本 build）= 受理（含门⑥ token 强制），与宽限态无关；
/// - `/2`（旧版）= 仅当 [`legacy_grace_active`]（`legacy_grace` on **且**
///   `until=None` 或 `now < until`）= 宽限受理（旧五门，无 token 门）；
///   逐位不变）；到期臂 = [`legacy_grace_expired_reason`]（含 `expired`，
///   运维/告警面可辨「到期自动收紧」与「人工关断」）；
/// - 其余串 = Err(`version mismatch (expected RELAY-DIR/3)`)。
pub fn version_admission_at(
    ver: &str,
    legacy_grace: bool,
    until: Option<u64>,
    now: u64,
) -> Result<IxVersionAdmission, String> {
    if ver == INTERCONNECT_VERSION {
        return Ok(IxVersionAdmission::Current);
    }
    if ver == INTERCONNECT_VERSION_LEGACY {
        if legacy_grace_active(legacy_grace, until, now) {
            return Ok(IxVersionAdmission::LegacyGrace);
        }
        return match legacy_grace_expired_reason(legacy_grace, until, now) {
            Some(r) => Err(r),
            None => Err("legacy_no_token".to_string()),
        };
    }
    Err("version mismatch (expected RELAY-DIR/3)".to_string())
}

/// - off（`legacy_grace=false`，默认）= 恒 off；
/// - on 无界（`until=None`，纯手工 `--ix-legacy-grace`）= on（保留形态）；
/// - on 有界（`--ix-legacy-grace-until`）= 仅 `now < until` 为 on——**过点
///   （含等界）宽限自动失效**（到期自动 fail-closed，忘关自愈收紧）。
pub fn legacy_grace_active(legacy_grace: bool, until: Option<u64>, now: u64) -> bool {
    if !legacy_grace {
        return false;
    }
    match until {
        None => true,
        Some(t) => now < t,
    }
}

/// `legacy_no_token` 逐位不变）。到期臂拒因 =
/// `legacy_no_token (grace expired at unix <ts>)`（`InterconnectRejected`
/// 审计 reason 含 `expired`；控制台行经既有 esc 转义面，ts 代码派生零注入面）。
pub fn legacy_grace_expired_reason(legacy_grace: bool, until: Option<u64>, now: u64) -> Option<String> {
    match until {
        Some(t) if legacy_grace && now >= t => Some(format!(
            "legacy_no_token (grace expired at unix {t})"
        )),
        _ => None,
    }
}

/// sig；sig 覆盖域含接收方 fp = 防批次改道/跨接收方重放）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushEntry {
    pub device_id: String,
    /// 设备自身 DNS 域（纯 FQDN）。
    pub domain: String,
    pub updated_at: u64,
    /// A 推送时 Ed25519 逐条新签（覆盖域 = [`entry_sig_message_v2`]；恒 64B）。
    pub sig: Vec<u8>,
}

// ── 纯函数（冻结合同/单测钉死；零 IO） ───────────────────────────────

/// `ver_bytes ‖ nonce ‖ id_pub ‖ id_domain`（v1 = 前三段；域扩展后
/// v1 签名对新验签器必败 = 旧 HELLO 不可重放进 RELAY-DIR/2，版本串双保险）。
pub fn hello_sig_message(
    ver: &str,
    nonce: &[u8; 16],
    id_pub: &[u8; 32],
    id_domain: &str,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(ver.len() + 48 + id_domain.len());
    m.extend_from_slice(ver.as_bytes());
    m.extend_from_slice(nonce);
    m.extend_from_slice(id_pub);
    m.extend_from_slice(id_domain.as_bytes());
    m
}

/// 推送逐条签名覆盖域（§2.3 冻结，␟ = 0x1F US）：
/// `device_id ␟ domain ␟ updated_at_be64 ␟ "pushed" ␟ recipient_fp`。
/// recipient_fp = **接收方** relay 79 字符指纹（接收方绑定 = 防 A 对 B 的
/// 批次被改道/重放给 C）；ts = 8 字节大端（非十进制串）。
pub fn entry_sig_message_v2(
    device_id: &str,
    domain: &str,
    updated_at: u64,
    recipient_fp: &str,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(device_id.len() + domain.len() + recipient_fp.len() + 26);
    m.extend_from_slice(device_id.as_bytes());
    m.push(SIG_FIELD_SEP);
    m.extend_from_slice(domain.as_bytes());
    m.push(SIG_FIELD_SEP);
    m.extend_from_slice(&updated_at.to_be_bytes());
    m.push(SIG_FIELD_SEP);
    m.extend_from_slice(b"pushed");
    m.push(SIG_FIELD_SEP);
    m.extend_from_slice(recipient_fp.as_bytes());
    m
}

/// batch_sig_v2 覆盖域（§2.3 冻结）：
/// `PUSH_SIG_PREFIX ‖ epoch_be64 ‖ recipient_fp ‖
///  concat(entries 按 device_id 升序: bincode(PushEntry))`。
pub fn batch_sig_message_v2(epoch: u64, recipient_fp: &str, entries_sorted: &[PushEntry]) -> Vec<u8> {
    let mut m =
        Vec::with_capacity(PUSH_SIG_PREFIX.len() + 8 + recipient_fp.len() + entries_sorted.len() * 64);
    m.extend_from_slice(PUSH_SIG_PREFIX.as_bytes());
    m.extend_from_slice(&epoch.to_be_bytes());
    m.extend_from_slice(recipient_fp.as_bytes());
    for e in entries_sorted {
        // bincode 确定性（同结构同版本同字节序）；entries 已按 device_id 升序。
        m.extend_from_slice(&bincode::serialize(e).expect("PushEntry serialize cannot fail"));
    }
    m
}

/// AEAD 帧体编码（冻结：body = [nonce:12 随机][ct+tag]，AAD = [type]‖ver_bytes）。
pub fn aead_frame_body(
    cipher: &AeadCipher,
    ty: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>, kirin_desk_core::crypto::aead::AeadError> {
    let aad = aad_for(ty);
    let (nonce, ct) = cipher.encrypt(plaintext, &aad)?;
    let mut body = Vec::with_capacity(nonce.len() + ct.len());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&ct);
    Ok(body)
}

/// AEAD 帧体解码（nonce 推进口径：每帧全新，无计数器状态）。
pub fn aead_unframe_body(
    cipher: &AeadCipher,
    ty: u8,
    body: &[u8],
) -> Result<Vec<u8>, kirin_desk_core::crypto::aead::AeadError> {
    if body.len() < 12 + 16 {
        return Err(kirin_desk_core::crypto::aead::AeadError::DecryptionFailed);
    }
    let (nonce, ct) = body.split_at(12);
    let mut ct = ct.to_vec();
    cipher.decrypt(nonce, &mut ct, &aad_for(ty))
}

fn aad_for(ty: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + INTERCONNECT_VERSION.len());
    aad.push(ty);
    aad.extend_from_slice(INTERCONNECT_VERSION.as_bytes());
    aad
}

/// TXT 解析（冻结形态 `{"node_type":"relay","public_key":"<base64 32B>"}`）。
/// `node_type != "relay"` = None（与设备 `DeviceMeta` 不同 key 空间）；
/// base64 非恰 32B = None（fail-closed）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTxtInfo {
    pub node_type: String,
    pub pubkey: [u8; 32],
}

pub fn parse_relay_txt(record: &str) -> Option<RelayTxtInfo> {
    #[derive(Deserialize)]
    struct T {
        node_type: String,
        public_key: String,
    }
    let t: T = serde_json::from_str(record).ok()?;
    if t.node_type != "relay" {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(t.public_key.trim())
        .ok()?;
    let bytes: [u8; 32] = bytes.try_into().ok()?;
    Some(RelayTxtInfo {
        node_type: t.node_type,
        pubkey: bytes,
    })
}

/// SRV 记录集 → 互联端口（冻结口径：priority 最小者，RFC 2782 序；
/// 同 priority 取记录序首个；port=0 = 无效记录跳过；无有效 = None）。
pub fn select_srv_port(records: &[Record]) -> Option<u16> {
    let mut best: Option<(u16 /*priority*/, u16 /*port*/)> = None;
    for r in records {
        if let RecordData::Srv { priority, port, .. } = &r.data {
            if *port == 0 {
                continue;
            }
            match best {
                None => best = Some((*priority, *port)),
                Some((bp, _)) => {
                    if *priority < bp {
                        best = Some((*priority, *port));
                    }
                }
            }
        }
    }
    best.map(|(_, p)| p)
}

/// A/AAAA 记录集 → 连接地址列表（A 在前、AAAA 在后，去重；端口 = SRV 端口）。
pub fn merge_addrs(
    a_recs: &Result<Vec<Record>, ResolverError>,
    aaaa_recs: &Result<Vec<Record>, ResolverError>,
    port: u16,
) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    let push = |out: &mut Vec<SocketAddr>, s: &str, port: u16| {
        if let Ok(ip) = s.trim().parse::<IpAddr>() {
            let a = SocketAddr::new(ip, port);
            if !out.contains(&a) {
                out.push(a);
            }
        }
    };
    if let Ok(recs) = a_recs {
        for r in recs {
            if let RecordData::Plain(s) = &r.data {
                push(&mut out, s, port);
            }
        }
    }
    if let Ok(recs) = aaaa_recs {
        for r in recs {
            if let RecordData::Plain(s) = &r.data {
                push(&mut out, s, port);
            }
        }
    }
    out
}

/// 32B 公钥 → 79 字符指纹（fp 派生**单源**：my_fp / 接收方 fp / B 侧
/// source_fp 同一口径，零分歧）。
pub fn fp_of_pubkey(pub_bytes: &[u8; 32]) -> String {
    kirin_desk_core::crypto::ed25519::fingerprint(
        &base64::engine::general_purpose::STANDARD.encode(pub_bytes),
    )
}

// ── 帧 IO（`[type:u8][len:u32 BE][body]`，同构 relay 帧头） ─────────

async fn write_frame(w: &mut (impl AsyncWrite + Unpin), ty: u8, body: &[u8]) -> std::io::Result<()> {
    if body.len() > IX_MAX_FRAME_LEN as usize {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("frame too large: {}", body.len()),
        ));
    }
    let mut hdr = [ty, 0, 0, 0, 0];
    hdr[1..5].copy_from_slice(&(body.len() as u32).to_be_bytes());
    w.write_all(&hdr).await?;
    w.write_all(body).await?;
    w.flush().await
}

/// 与 relay 面 `FRAME_PREALLOC_CAP` 同值同口径）——宣称长度只先按此上限
/// 小额分配，随实际到达数据 16 KiB 块扩容。慢连接 × 16 MiB 宣称头的内存
/// 放大面封堵（读失败先于大额分配；EOF 语义与 `read_exact` 一致）。
const IX_FRAME_PREALLOC_CAP: usize = 64 * 1024;
const IX_FRAME_READ_CHUNK: usize = 16 * 1024;

async fn read_frame(r: &mut (impl AsyncRead + Unpin), max_len: u32) -> std::io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    r.read_exact(&mut hdr).await?;
    let ty = hdr[0];
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    if len > max_len as usize {
        return Err(std::io::Error::new(ErrorKind::InvalidData, format!("frame too large: {len}")));
    }
    let mut body = Vec::with_capacity(len.min(IX_FRAME_PREALLOC_CAP));
    let mut buf = [0u8; IX_FRAME_READ_CHUNK];
    let mut remaining = len;
    while remaining > 0 {
        let n = remaining.min(buf.len());
        r.read_exact(&mut buf[..n]).await?;
        body.extend_from_slice(&buf[..n]);
        remaining -= n;
    }
    Ok((ty, body))
}

// ── 引擎配置 / 触发契约 ──────────────────────────────────────────────

/// A 侧设备活体探针（T8 liveness 清扫判据「且 D 不在当前注册表」）。
/// 实现 = main.rs 审计桥（DeviceRegistered/Offline 事件族旁路）；
/// `None`（未挂载）= 不跑 liveness 清扫（无活体信号不删行，fail-safe）。
pub trait DirLivenessProbe: Send + Sync + std::fmt::Debug {
    /// 设备是否当前在线（registry 活体口径）。
    fn is_online(&self, device_id: &str) -> bool;
}

/// A 侧设备活体探针，T8）。
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// A 侧周期重推间隔秒（`--push-repush-interval`，默认 3600；±60s 抖动）。
    pub repush_interval: u64,
    /// B 侧 pushed 行 TTL 秒（`--push-entry-ttl`，默认 86400；per-source 续约）。
    pub entry_ttl: u64,
    /// A 侧 manual 行 liveness TTL 秒（`--dir-liveness-ttl`，默认 86400）。
    pub liveness_ttl: u64,
    /// B 侧单源 pushed 行上限（`--push-per-source-cap`，默认 10000）。
    pub per_source_cap: usize,
    /// A 侧设备活体探针（None = 不跑 liveness 清扫）。
    pub liveness: Option<Arc<dyn DirLivenessProbe>>,
    /// fail-closed 拒收**旧 `/2` 对端 + 审计 reason=`legacy_no_token`；
    /// on = 旧五门受理迁移期放行）。
    pub legacy_grace: bool,
    /// <unix_ts>`，unix 秒 UTC；None = 无界纯手工形态）。Some(ts) 时
    /// `now >= ts`（含等界）宽限自动失效 = 到期自动 fail-closed。
    pub legacy_grace_until: Option<u64>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            repush_interval: 3600,
            entry_ttl: 86400,
            liveness_ttl: 86400,
            per_source_cap: 10000,
            liveness: None,
            legacy_grace: false,
            legacy_grace_until: None,
        }
    }
}

/// - [`Self::trigger_target`] = 单 target 变更即推（T1/T2，异步非阻塞）；
/// - [`Self::trigger_all`] = `DirList{refresh:true}` 运维手动触发 = 一轮
///   全量重推（T3 中继层）。
#[async_trait]
pub trait PushTrigger: Send + Sync + std::fmt::Debug {
    /// 一轮全量重推 → 成功 target 数。
    async fn trigger_all(&self) -> usize;
    /// 单 target 立即推送 → 是否成功。
    async fn trigger_target(&self, target_domain: &str) -> bool;
}

/// 单 target 推送结果（A 侧；`fp` = 接收方〔现场解析 TXT 公钥〕指纹）。
#[derive(Debug, Clone)]
pub struct PushSummary {
    pub entries: usize,
    pub epoch: u64,
    pub fp: String,
}

/// 单 target 推送失败（`fp` = 接收方指纹；解析前失败 = 空串）。
/// finish_push_audit 走 **WARN 审计 + outbox 零触碰**（区别于真失败：
/// 真失败入 outbox 退避，跳过 = 本轮不动、token 到位后自然恢复推送）。
#[derive(Debug, Clone)]
pub struct PushFail {
    pub reason: String,
    pub fp: String,
    pub skip: bool,
}

// ── 单 target 推送数据路径（组件 Arc 自由函数形；spawn 任务复用） ─────

/// 对单 target 执行一次完整定向推送（§3 T1 ⑤-⑧；任一阶段失败 = Err，
/// 本地表零变化，fail-closed）：
/// ⑤ 现场解析三件套（SRV→端口 / TXT→公钥〔TOFU 锚〕/ A+AAAA→寻址）→
/// ⑥ TCP connect（逐址有界）+ HELLO v2 双向互证（B 以拨号域自认 +
///    id_pub == 预解析 TXT 公钥）→ ⑦ IxPush（逐条新签 + 整批签 + AEAD）→
/// ⑧ 帧写完成 = 交付（**无 ACK 帧**，冻结合同；B 应用结果 A 不可知 =
///    声明式 + 周期重推兜底）。
async fn push_one(
    store: &DirStore,
    server_key: &SigningKey,
    resolver: &Arc<dyn Resolver>,
    my_domain: &str,
    target_domain: &str,
) -> Result<PushSummary, PushFail> {
    // 转发凭证缓存；查无 = 该 target 本轮**跳过推送** + WARN 审计
    // （fail-closed：无 token 不推裸批——推了 B 侧门⑥也必拒）。
    let ix_token = match store.ix_lookup_device_token(target_domain).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            tracing::warn!(
                "interconnect: no ix_token for target {target_domain} — push skipped (fail-closed)"
            );
            return Err(PushFail {
                reason: "no ix_token for target (device cache empty) — push skipped (fail-closed)"
                    .to_string(),
                fp: String::new(),
                skip: true,
            });
        }
        Err(e) => {
            return Err(PushFail {
                reason: e.to_string(),
                fp: String::new(),
                skip: false,
            })
        }
    };
    // ⑤ 现场解析三件套（失败 = 调用方 finish_push 入 outbox + WARN 口径）。
    let (addrs, txt_pubkey) = match resolve_relay(resolver, target_domain).await {
        Ok(v) => v,
        Err(reason) => {
            return Err(PushFail {
                reason,
                fp: String::new(),
                skip: false,
            })
        }
    };
    let fp = fp_of_pubkey(&txt_pubkey);
    // 声明式全量子集（pushed 行永不外推；ORDER BY device_id = 冻结签名序）。
    let rows = store
        .list_push_subset(target_domain)
        .await
        .map_err(|e| PushFail { reason: e.to_string(), fp: fp.clone(), skip: false })?;
    // epoch 读取在子集取数**之后**（单调性：批次 epoch ≥ 子集快照期）。
    let epoch = store
        .get_epoch()
        .await
        .map_err(|e| PushFail { reason: e.to_string(), fp: fp.clone(), skip: false })?;
    // 逐条新签（接收方 fp 绑定 = 防改道）+ 整批签（device_id 升序冻结序）。
    let mut entries: Vec<PushEntry> = rows
        .iter()
        .map(|r| PushEntry {
            device_id: r.device_id.clone(),
            domain: r.device_domain.clone(),
            updated_at: r.updated_at,
            sig: server_key
                .sign(&entry_sig_message_v2(
                    &r.device_id,
                    &r.device_domain,
                    r.updated_at,
                    &fp,
                ))
                .to_bytes()
                .to_vec(),
        })
        .collect();
    entries.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    let batch_sig = server_key
        .sign(&batch_sig_message_v2(epoch, &fp, &entries))
        .to_bytes()
        .to_vec();
    // ⑥ TCP 连接（逐址尝试，有界超时）。
    let mut stream = None;
    let mut last_err = String::new();
    for a in &addrs {
        match timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(*a)).await {
            Ok(Ok(s)) => {
                stream = Some(s);
                break;
            }
            Ok(Err(e)) => last_err = format!("{a}: {e}"),
            Err(_) => last_err = format!("{a}: timeout"),
        }
    }
    let mut stream = match stream {
        Some(s) => s,
        None => {
            return Err(PushFail {
                reason: format!("connect failed (all addrs tried): {last_err}"),
                fp,
                skip: false,
            })
        }
    };
    let _ = stream.set_nodelay(true);
    // HELLO v3 双向互证（A 侧口径：B 以拨号域自认 + 预解析 TXT 公钥互证）。
    let cipher = match push_handshake(server_key, my_domain, &mut stream, target_domain, &txt_pubkey).await {
        Ok(c) => c,
        Err(reason) => {
            return Err(PushFail {
                reason,
                fp,
                skip: false,
            })
        }
    };
    // ix_token 转发凭证，禁入明文 HELLO）。
    let pt = bincode::serialize(&IxPush {
        epoch,
        entries: entries.clone(),
        batch_sig,
        ix_token,
    })
    .map_err(|e| PushFail { reason: e.to_string(), fp: fp.clone(), skip: false })?;
    let body = match aead_frame_body(&cipher, IX_FRAME_PUSH, &pt) {
        Ok(b) => b,
        Err(e) => return Err(PushFail { reason: format!("push encrypt: {e}"), fp, skip: false }),
    };
    if let Err(e) = write_frame(&mut stream, IX_FRAME_PUSH, &body).await {
        return Err(PushFail { reason: format!("push write: {e}"), fp, skip: false });
    }
    // ⑧ 无 ACK（冻结）：帧写完成 = 交付；B 应用结果 A 不可知
    // （声明式幂等 + 周期重推兜底，§3 T1⑧/§3.4）。
    Ok(PushSummary {
        entries: entries.len(),
        epoch,
        fp,
    })
}

/// 接收方三件套现场解析（SRV 端口 + TXT 公钥 + A/AAAA 寻址；任一失败 =
/// Err，零副作用）。
async fn resolve_relay(
    resolver: &Arc<dyn Resolver>,
    domain: &str,
) -> Result<(Vec<SocketAddr>, [u8; 32]), String> {
    let srv_name = format!("_kirin-relay._tcp.{domain}");
    let srv_recs = resolver
        .resolve(&srv_name, RecordType::SRV)
        .await
        .map_err(|e| format!("SRV resolve failed: {e}"))?;
    let port = select_srv_port(&srv_recs)
        .ok_or_else(|| format!("no valid SRV record ({srv_name})"))?;
    let txt_pubkey = resolve_txt_pubkey(resolver, domain).await?;
    let (a_recs, aaaa_recs) = tokio::join!(
        resolver.resolve(domain, RecordType::A),
        resolver.resolve(domain, RecordType::AAAA),
    );
    let addrs = merge_addrs(&a_recs, &aaaa_recs, port);
    if addrs.is_empty() {
        return Err("no A/AAAA record for addressing".into());
    }
    Ok((addrs, txt_pubkey))
}

/// 域 relay TXT 公钥现场解析（node_type=relay + 32B base64，fail-closed）。
async fn resolve_txt_pubkey(resolver: &Arc<dyn Resolver>, domain: &str) -> Result<[u8; 32], String> {
    let txt_recs = resolver
        .resolve(domain, RecordType::TXT)
        .await
        .map_err(|e| format!("TXT resolve failed: {e}"))?;
    let txt = txt_recs
        .iter()
        .find_map(|r| match &r.data {
            RecordData::Plain(s) => parse_relay_txt(s),
            _ => None,
        })
        .ok_or_else(|| "no relay TXT record (node_type=relay + public_key)".to_string())?;
    Ok(txt.pubkey)
}

/// HELLO v2 双向交换 + 对方验签（A 侧：对方必须以**拨号域**自认 +
/// id_pub == **预解析 TXT 公钥**，TOFU 交叉一致；fail-closed）。
/// 返回 AEAD 会话。
async fn push_handshake(
    server_key: &SigningKey,
    my_domain: &str,
    stream: &mut TcpStream,
    target_domain: &str,
    txt_pubkey: &[u8; 32],
) -> Result<AeadCipher, String> {
    let eph_a = EphemeralSession::new();
    let mut nonce_a = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce_a);
    let id_pub_a = server_key.verifying_key().to_bytes();
    let sig_a = server_key.sign(&hello_sig_message(
        INTERCONNECT_VERSION,
        &nonce_a,
        &id_pub_a,
        my_domain,
    ));
    let hello_a = IxHello {
        ver: INTERCONNECT_VERSION.to_string(),
        nonce: nonce_a,
        eph_pub: eph_a.public_key_bytes(),
        id_pub: id_pub_a,
        id_domain: my_domain.to_string(),
        sig: sig_a.to_bytes().to_vec(),
    };
    let body = bincode::serialize(&hello_a).map_err(|e| e.to_string())?;
    write_frame(stream, IX_FRAME_HELLO, &body)
        .await
        .map_err(|e| format!("hello write: {e}"))?;
    let (ty, body) = match timeout(HANDSHAKE_TIMEOUT, read_frame(stream, IX_MAX_FRAME_LEN)).await {
        Err(_) => return Err("hello timeout (peer closed?)".to_string()),
        Ok(Err(e)) => return Err(format!("hello read: {e} (peer refused?)")),
        Ok(Ok(v)) => v,
    };
    if ty != IX_FRAME_HELLO {
        return Err(format!("frame type 0x{ty:02x} != hello"));
    }
    let hello_b: IxHello = bincode::deserialize(&body).map_err(|e| format!("hello decode: {e}"))?;
    if hello_b.ver != INTERCONNECT_VERSION {
        return Err("version mismatch (expected RELAY-DIR/3)".into());
    }
    if !is_pure_fqdn(&hello_b.id_domain) {
        return Err(format!("peer id_domain not a pure FQDN: {}", hello_b.id_domain));
    }
    // 接收方绑定：对端必须以本方拨号域自认（防改道/中间人换域）。
    if hello_b.id_domain != target_domain {
        return Err("peer id_domain != dialed domain — refuse (fail-closed)".into());
    }
    // TOFU 交叉一致：HELLO id_pub == 预解析 DNS TXT 公钥。
    if hello_b.id_pub != *txt_pubkey {
        return Err("peer id_pub != DNS TXT pubkey — refuse (fail-closed)".into());
    }
    let vk_b = VerifyingKey::try_from(&hello_b.id_pub[..])
        .map_err(|_| "invalid peer pubkey".to_string())?;
    let msg_b = hello_sig_message(
        INTERCONNECT_VERSION,
        &hello_b.nonce,
        &hello_b.id_pub,
        &hello_b.id_domain,
    );
    let sig_b = Signature::from_slice(&hello_b.sig).map_err(|_| "bad peer sig len".to_string())?;
    if vk_b.verify(&msg_b, &sig_b).is_err() {
        return Err("peer hello sig failed".into());
    }
    // ECDH → AEAD 会话。
    let peer_eph =
        EphemeralSession::parse_public_key(&hello_b.eph_pub).map_err(|e| e.to_string())?;
    let session_key = eph_a.compute_session_key(&peer_eph).map_err(|e| e.to_string())?;
    Ok(AeadCipher::new(&session_key))
}

/// 推送结果处置（**单一审计源**，§2.5 行表）：
/// - 成功 = `push ok` + 该 target 全部 outbox 行剪除（superseded）；
/// - 失败 = `push failed` + outbox 退避登记（T4：已存在只刷 next_retry_at，
///   不存在新入队 + `push outbox enqueued`）。
/// 返回是否成功（触发计数口径）。
async fn finish_push_audit(
    store: &DirStore,
    audit: &Arc<dyn AuditSink>,
    target_domain: &str,
    result: Result<PushSummary, PushFail>,
) -> bool {
    match result {
        Ok(s) => {
            audit.record(TunnelAuditEvent::PushOk {
                target_domain: target_domain.to_string(),
                fp: s.fp,
                entries: s.entries,
                epoch: s.epoch,
            });
            if let Ok(n) = store.outbox_clear(target_domain).await {
                if n > 0 {
                    audit.record(TunnelAuditEvent::PushOutboxPruned {
                        target_domain: target_domain.to_string(),
                        n,
                        reason: "superseded".to_string(),
                    });
                }
            }
            true
        }
        Err(f) => {
            // （本轮跳过，token 到位后自然恢复推送；真失败才入退避队），
            // WARN 审计独立 reason 行（审计 reason 串 = 内部面）。
            if f.skip {
                tracing::warn!(
                    "interconnect: push to {target_domain} skipped: {}",
                    f.reason
                );
                audit.record(TunnelAuditEvent::PushSkippedNoToken {
                    target_domain: target_domain.to_string(),
                    reason: f.reason,
                });
                return false;
            }
            let now = now_unix_secs();
            let inserted = match store.outbox_register_failure(target_domain, now).await {
                Ok((_, inserted)) => inserted,
                Err(e) => {
                    tracing::error!(
                        "interconnect: outbox register_failure({target_domain}) failed: {e}"
                    );
                    false
                }
            };
            if inserted {
                audit.record(TunnelAuditEvent::PushOutboxEnqueued {
                    target_domain: target_domain.to_string(),
                });
            }
            audit.record(TunnelAuditEvent::PushFailed {
                target_domain: target_domain.to_string(),
                fp: f.fp,
                reason: f.reason,
            });
            false
        }
    }
}

// ── 服务 ─────────────────────────────────────────────────────────────

/// 中继定向推送服务（单 relay 进程内单实例；store/密钥/审计/解析器/
/// 引擎参数注入；A 侧推送引擎 + B 侧接收面同实例）。
pub struct InterconnectService {
    store: Arc<DirStore>,
    server_key: Arc<SigningKey>,
    audit: Arc<dyn AuditSink>,
    resolver: Arc<dyn Resolver>,
    my_fp: String,
    /// fail-closed 必给；HELLO v2 `id_domain` 字段 + 接收方绑定素材）。
    my_domain: String,
    engine: EngineConfig,
    active: AtomicUsize,
    /// 单实例）。公开推送路径（`push_to`/`trigger_target` 变更即推）与
    /// 收敛面（`push_all_once`/`sweep_outbox`）共用同一实例——已认证客户
    /// 端高频 DirUpsert/Delete 制造的变更即推风暴在此排队，不再绕过并发
    /// 上限制造无界出站 TCP + DNS 解析。
    push_sem: Arc<tokio::sync::Semaphore>,
}

impl std::fmt::Debug for InterconnectService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterconnectService")
            .field("my_fp", &self.my_fp)
            .field("my_domain", &self.my_domain)
            .finish()
    }
}

impl InterconnectService {
    pub fn new(
        store: Arc<DirStore>,
        server_key: Arc<SigningKey>,
        audit: Arc<dyn AuditSink>,
        resolver: Arc<dyn Resolver>,
        my_domain: &str,
        engine: EngineConfig,
    ) -> Self {
        let my_fp = fp_of_pubkey(&server_key.verifying_key().to_bytes());
        Self {
            store,
            server_key,
            audit,
            resolver,
            my_fp,
            my_domain: my_domain.to_string(),
            engine,
            active: AtomicUsize::new(0),
            push_sem: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNS)),
        }
    }

    /// 本 relay 指纹（79 字符；banner/审计展示）。
    pub fn my_fp(&self) -> &str {
        &self.my_fp
    }

    /// 本 relay 自身 FQDN（`--relay-domain`；冻结接口面）。
    pub fn my_domain(&self) -> &str {
        &self.my_domain
    }

    // ── serve 侧（B 接收面） ───────────────────────────────────────────

    /// 双栈绑定（`[::]` 优先 + `0.0.0.0` 回退；[::] 双栈已覆盖 v4 时
    /// 0.0.0.0 的 AddrInUse 非错误）。全失败 = Err（调用方 fail-closed
    /// 拒启动，main.rs 单一审计/退出源）。
    pub async fn bind_listeners(port: u16) -> std::io::Result<Vec<(String, TcpListener)>> {
        let mut listeners: Vec<(String, TcpListener)> = Vec::new();
        match TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)).await {
            Ok(l) => listeners.push(("dual-stack [::]".to_string(), l)),
            Err(e) => tracing::warn!("interconnect: [::]:{port} bind failed: {e}"),
        }
        match TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)).await {
            Ok(l) => listeners.push(("0.0.0.0".to_string(), l)),
            Err(e) => {
                tracing::debug!("interconnect: 0.0.0.0:{port} bind skipped: {e}");
            }
        }
        if listeners.is_empty() {
            return Err(std::io::Error::new(
                ErrorKind::AddrInUse,
                format!("interconnect bind failed on port {port} (both stacks)"),
            ));
        }
        Ok(listeners)
    }

    /// 在给定监听器上 serve（测试注入回环监听器用）。
    pub(crate) async fn serve_listeners(self: &Arc<Self>, listeners: Vec<(String, TcpListener)>) {
        let mut handles = Vec::new();
        for (name, listener) in listeners {
            let me = Arc::clone(self);
            handles.push(tokio::spawn(async move {
                me.accept_loop(name, listener).await;
            }));
        }
        for h in handles {
            let _ = h.await;
        }
    }

    async fn accept_loop(self: &Arc<Self>, name: String, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let cur = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                    if cur > MAX_CONCURRENT_CONNS {
                        self.active.fetch_sub(1, Ordering::SeqCst);
                        tracing::warn!(
                            "interconnect: concurrency cap ({MAX_CONCURRENT_CONNS}) reached, refusing {addr}"
                        );
                        continue;
                    }
                    let me = Arc::clone(self);
                    tokio::spawn(async move {
                        me.handle_conn(stream, addr).await;
                        me.active.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(e) => {
                    if e.kind() == ErrorKind::AddrInUse {
                        break; // 双栈重叠场景的良性终止
                    }
                    tracing::error!("interconnect accept error ({name}): {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    }

    /// 单会话处理（B 侧：验 A → 回 HelloB → ECDH → 服务 IxPush 声明式
    /// 批次〔受理门 5 项 + 单事务应用〕；废帧保留位 0x02/0x03 及未知帧
    /// = 结构校验 + 丢弃 + 审计，不解析）。
    async fn handle_conn(&self, mut stream: TcpStream, peer: SocketAddr) {
        let _ = stream.set_nodelay(true);
        #[derive(Debug)]
        enum ConnError {
            /// 握手层/废帧拒（`interconnect rejected` 行）。
            Handshake(String),
            /// 数据帧阶段推送整批拒收（`push rejected` 行，独立审计源）。
            Push {
                peer_domain: String,
                fp: String,
                reason: String,
            },
        }
        let mut fp_known: Option<String> = None;
        let outcome: Result<(), ConnError> = async {
            let (ty, body) = match timeout(
                HANDSHAKE_TIMEOUT,
                read_frame(&mut stream, IX_MAX_FRAME_LEN),
            )
            .await
            {
                Err(_) => return Err(ConnError::Handshake("hello timeout".to_string())),
                Ok(Err(e)) => return Err(ConnError::Handshake(format!("hello read: {e}"))),
                Ok(Ok(v)) => v,
            };
            if ty != IX_FRAME_HELLO {
                return Err(ConnError::Handshake(format!(
                    "first frame type 0x{ty:02x} != hello"
                )));
            }
            let hello: IxHello = bincode::deserialize(&body)
                .map_err(|e| ConnError::Handshake(format!("hello decode: {e}")))?;
            // 强制）；`/2` = 宽限开关 on **且未到期**（`now < until`，
            // until=None = 无界）时旧五门受理；off（默认）= 拒 +
            // reason=`legacy_no_token`；到期（含等界）= 拒 +
            // reason 含 `expired`（到期自动 fail-closed，忘关自愈收紧）；
            // 其余串 = 版本不符拒连。
            let admission = version_admission_at(
                &hello.ver,
                self.engine.legacy_grace,
                self.engine.legacy_grace_until,
                now_unix_secs(),
            )
            .map_err(ConnError::Handshake)?;
            let legacy = admission == IxVersionAdmission::LegacyGrace;
            // ② 验证 A（v2 握手受理门，§2.3/§5 点位 1-2）：id_domain 纯
            // FQDN + id_pub 可解析 + 四段覆盖域验签（持私钥证明）。信任
            // 锚 = 数据帧阶段 DNS-TXT 现场解析（§2.3 门①，风险① 缓解：
            // TOFU 现场解析为准）。
            if !is_pure_fqdn(&hello.id_domain) {
                return Err(ConnError::Handshake(format!(
                    "A id_domain not a pure FQDN: {}",
                    hello.id_domain
                )));
            }
            let fp = fp_of_pubkey(&hello.id_pub);
            fp_known = Some(fp.clone());
            let vk = VerifyingKey::try_from(&hello.id_pub[..])
                .map_err(|_| ConnError::Handshake("invalid A id_pub".to_string()))?;
            // 签名覆盖域以**对端自报版本串**为素材（/3 正常路径与 /2 宽限
            // 路径同构；版本串已过受理裁决门 = 集合有界，fail-closed）。
            let msg = hello_sig_message(
                &hello.ver,
                &hello.nonce,
                &hello.id_pub,
                &hello.id_domain,
            );
            let sig = Signature::from_slice(&hello.sig)
                .map_err(|_| ConnError::Handshake("bad A sig len".to_string()))?;
            if vk.verify(&msg, &sig).is_err() {
                return Err(ConnError::Handshake("A hello sig failed".into()));
            }
            // ③ 回 HelloB（id_domain_b = 本 relay 自身 FQDN，--relay-domain）。
            let eph_b = EphemeralSession::new();
            let mut nonce_b = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut nonce_b);
            let id_pub_b = self.server_key.verifying_key().to_bytes();
            let sig_b = self
                .server_key
                .sign(&hello_sig_message(
                    INTERCONNECT_VERSION,
                    &nonce_b,
                    &id_pub_b,
                    &self.my_domain,
                ));
            let hello_b = IxHello {
                ver: INTERCONNECT_VERSION.to_string(),
                nonce: nonce_b,
                eph_pub: eph_b.public_key_bytes(),
                id_pub: id_pub_b,
                id_domain: self.my_domain.clone(),
                sig: sig_b.to_bytes().to_vec(),
            };
            let body = bincode::serialize(&hello_b)
                .map_err(|e| ConnError::Handshake(format!("hello encode: {e}")))?;
            write_frame(&mut stream, IX_FRAME_HELLO, &body)
                .await
                .map_err(|e| ConnError::Handshake(format!("hello write: {e}")))?;
            // ④ ECDH → AEAD。
            let peer_eph = EphemeralSession::parse_public_key(&hello.eph_pub)
                .map_err(|e| ConnError::Handshake(format!("peer eph parse: {e}")))?;
            let session_key = eph_b
                .compute_session_key(&peer_eph)
                .map_err(|e| ConnError::Handshake(format!("ecdh: {e}")))?;
            let cipher = AeadCipher::new(&session_key);
            // ⑤ 数据帧：0x04 = 定向推送；其余型号（含废帧保留位
            // 0x02/0x03）= 结构校验（帧头 + 长度界，read_frame 已完成）
            // + 丢弃 + 审计，不解析（§7 不复用）。
            let (ty, body) = match timeout(
                HANDSHAKE_TIMEOUT,
                read_frame(&mut stream, IX_MAX_FRAME_LEN),
            )
            .await
            {
                Err(_) => {
                    return Err(ConnError::Handshake(
                        "data frame timeout (peer closed after handshake)".to_string(),
                    ))
                }
                Ok(Err(e)) => return Err(ConnError::Handshake(format!("data frame read: {e}"))),
                Ok(Ok(v)) => v,
            };
            if ty != IX_FRAME_PUSH {
                return Err(ConnError::Handshake(format!(
                    "deprecated frame 0x{ty:02x} (structure-checked, dropped, not parsed)"
                )));
            }
            let pt = aead_unframe_body(&cipher, IX_FRAME_PUSH, &body).map_err(|e| {
                ConnError::Push {
                    peer_domain: hello.id_domain.clone(),
                    fp: fp.clone(),
                    reason: format!("push decrypt failed (session key/AAD): {e}"),
                }
            })?;
            let push: IxPush = decode_ix_push(&pt, legacy).map_err(|reason| ConnError::Push {
                peer_domain: hello.id_domain.clone(),
                fp: fp.clone(),
                reason,
            })?;
            // 受理门①：DNS-TXT **现场解析**锚（TOFU 现场解析为准）+
            // HELLO id_pub 互证（防改道/防 MITM 换钥）。
            let txt_pubkey = match resolve_txt_pubkey(&self.resolver, &hello.id_domain).await {
                Ok(k) => k,
                Err(e) => {
                    return Err(ConnError::Push {
                        peer_domain: hello.id_domain.clone(),
                        fp: String::new(),
                        reason: e,
                    })
                }
            };
            if hello.id_pub != txt_pubkey {
                return Err(ConnError::Push {
                    peer_domain: hello.id_domain.clone(),
                    fp: fp.clone(),
                    reason: "A id_pub != live DNS TXT pubkey (TOFU mismatch) — refuse"
                        .to_string(),
                });
            }
            let source_fp = fp_of_pubkey(&txt_pubkey);
            let source_vk = VerifyingKey::try_from(&txt_pubkey[..]).map_err(|e| ConnError::Push {
                peer_domain: hello.id_domain.clone(),
                fp: source_fp.clone(),
                reason: format!("invalid source pubkey: {e}"),
            })?;
            // 单事务应用（任一失败 = 整批拒收 + 本地表零变化，fail-closed
            // 不半信）；`/2` 宽限路径 = 旧五门受理（无 token 门，迁移期）。
            let gate_result = if legacy {
                self.verify_and_apply_push_gated(&push, &source_vk, &source_fp, false)
                    .await
            } else {
                self.verify_and_apply_push(&push, &source_vk, &source_fp).await
            };
            let applied = match gate_result {
                Ok(r) => r,
                    Err(reason) => {
                        return Err(ConnError::Push {
                            peer_domain: hello.id_domain,
                            fp: source_fp,
                            reason,
                        })
                    }
                };
            self.audit.record(TunnelAuditEvent::PushApplied {
                source_fp,
                entries: applied.entries_in,
                removed: applied.removed,
                epoch: push.epoch,
            });
            Ok(())
        }
        .await;
        match outcome {
            Ok(()) => {
                tracing::debug!("interconnect: push session from {peer} applied");
            }
            Err(ConnError::Handshake(reason)) => {
                tracing::warn!("interconnect: session from {peer} ended: {reason}");
                self.audit.record(TunnelAuditEvent::InterconnectRejected {
                    peer,
                    fp: fp_known.unwrap_or_default(),
                    reason,
                });
            }
            Err(ConnError::Push { peer_domain, fp, reason }) => {
                tracing::warn!("interconnect: push from {peer_domain} ({peer}) rejected: {reason}");
                self.audit.record(TunnelAuditEvent::PushRejected {
                    peer_domain,
                    fp,
                    reason,
                });
            }
        }
    }

    /// B 侧受理门 + 声明式单事务应用（**纯数据路径，无 socket**——
    /// ①`batch_sig_v2`（现场解析源公钥；整批篡改/重放防护）→
    /// ⑤per-source cap（批次 distinct device 数；应用后行集 ⊆ 批次
    /// device 集 = 等价判据）→ ④形态复检（`normalize_device_id` +
    /// `is_pure_fqdn` = malformed_entry）→ ②逐条 sig（recipient_fp =
    /// **本方** fp；改道批次在此必败）→ ③epoch 水位（`<` last =
    /// token**（`/3` 帧强制）：
    /// `ix_token` 与本机 `ix_tokens(source='cli')` 活跃行（revoked_at IS
    /// cli 行库内只存 `token_hash`，认证语义零变化〕——缺 token / 不匹配 /
    /// 已撤销 = 整批拒收 + PushRejected
    /// 审计（fail-closed 不半信）；`/2` 宽限路径 = 本门跳过（旧五门受理）。
    /// **任一失败 = Err(reason)，本地表零变化**（不半信）。
    /// （公开入口恒 `token_required = true`；宽限路径仅经
    /// `handle_conn` `/2` 受理裁决臂进入。）
    pub async fn verify_and_apply_push(
        &self,
        push: &IxPush,
        source_vk: &VerifyingKey,
        source_fp: &str,
    ) -> Result<PushApplyResult, String> {
        self.verify_and_apply_push_gated(push, source_vk, source_fp, true)
            .await
    }

    async fn verify_and_apply_push_gated(
        &self,
        push: &IxPush,
        source_vk: &VerifyingKey,
        source_fp: &str,
        token_required: bool,
    ) -> Result<PushApplyResult, String> {
        // 门①：整批签名（device_id 升序确定性序）。
        let mut sorted = push.entries.clone();
        sorted.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        let msg = batch_sig_message_v2(push.epoch, &self.my_fp, &sorted);
        let sig =
            Signature::from_slice(&push.batch_sig).map_err(|_| "batch sig len != 64".to_string())?;
        if source_vk.verify(&msg, &sig).is_err() {
            return Err(format!(
                "batch sig failed ({} entries) — whole batch rejected",
                push.entries.len()
            ));
        }
        // distinct device 集——revocation 删其余——= 批次 distinct 判据）。
        // 零签名开销的批次级快检先行：超大批在逐条验签 CPU 前即拒。
        let distinct = push
            .entries
            .iter()
            .map(|e| e.device_id.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len();
        if distinct > self.engine.per_source_cap {
            return Err(format!(
                "per-source cap exceeded: {distinct} distinct > {} — whole batch rejected",
                self.engine.per_source_cap
            ));
        }
        // 整拒 = fail-closed 不猜）。`normalize_device_id`/`is_pure_fqdn`
        // 零签名开销，先于门②逐条验签（16MiB 批不再先吃满验签 CPU 再拒收）。
        let mut norm: Vec<(String, String, u64, Vec<u8>)> = Vec::with_capacity(push.entries.len());
        for e in &push.entries {
            let id = normalize_device_id(&e.device_id).map_err(|_| {
                format!(
                    "malformed device_id '{}' — whole batch rejected",
                    e.device_id
                )
            })?;
            if !is_pure_fqdn(&e.domain) {
                return Err(format!(
                    "malformed domain '{}' — whole batch rejected",
                    e.domain
                ));
            }
            norm.push((id, e.domain.clone(), e.updated_at, e.sig.clone()));
        }
        // 门②：逐条签名（源 relay 推送时新签；接收方 fp 绑定）。
        for e in &push.entries {
            let m = entry_sig_message_v2(&e.device_id, &e.domain, e.updated_at, &self.my_fp);
            let sig =
                Signature::from_slice(&e.sig).map_err(|_| "entry sig len != 64".to_string())?;
            if source_vk.verify(&m, &sig).is_err() {
                return Err(format!(
                    "entry sig failed for '{}' — whole batch rejected",
                    e.device_id
                ));
            }
        }
        // 门③：epoch 水位（`<` last = 陈旧批拒收；`==/>` = 声明式幂等
        // 受理，无重放序问题）。
        if let Some(last) = self
            .store
            .get_push_last_epoch(source_fp)
            .await
            .map_err(|e| e.to_string())?
        {
            if push.epoch < last {
                return Err(format!(
                    "stale epoch {} < last {} — whole batch rejected",
                    push.epoch, last
                ));
            }
        }
        // 三态：缺 token（空串）= 拒；命中本机 cli 活跃行 = 受理；命中但
        // 已撤销 = 拒（独立 reason）；未知串 = 拒。device 行不作门⑥凭据
        // （本机 device 行 = 他中继签发的转发凭证，非本机签发凭据）。
        // 审计 reason 串 = 卡面矩阵口径（内部面）。
        if token_required {
            if push.ix_token.is_empty() {
                return Err(
                    "ix_token missing (RELAY-DIR/3 requires an interconnect token) — whole batch rejected"
                        .to_string(),
                );
            }
            match self
                .store
                .ix_token_cli_state(&push.ix_token)
                .await
                .map_err(|e| e.to_string())?
            {
                Some(true) => {}
                Some(false) => {
                    return Err(format!(
                        "ix_token revoked (prefix '{}') — whole batch rejected",
                        &push.ix_token.chars().take(8).collect::<String>()
                    ));
                }
                None => {
                    return Err(format!(
                        "ix_token mismatch (prefix '{}') — whole batch rejected",
                        &push.ix_token.chars().take(8).collect::<String>()
                    ));
                }
            }
        }
        // 声明式单事务应用（upsert + PK 遮蔽 + 同源幂等 + 跨源裁决 +
        // revocation-by-absence + 水位续约，§2.3 应用步）。
        self.store
            .apply_push_batch(source_fp, &self.my_domain, push.epoch, &norm)
            .await
            .map_err(|e| e.to_string())
    }

    // ── A 侧推送引擎 ───────────────────────────────────────────────────

    /// 对单 target 执行一次定向推送（公开入口：`trigger_target`/补推/
    /// 测试诊断面；数据路径 = [`push_one`]）。
    /// `push_all_once`/`sweep_outbox` 同一实例）——变更即推（T1/T2）自此
    /// 有界，超并发排队等待而非无界放大（信号量不关闭，acquire 恒成功；
    /// 失败臂 = fail-closed 拒推）。
    pub async fn push_to(&self, target_domain: &str) -> Result<PushSummary, PushFail> {
        let _permit = self.push_sem.acquire().await.map_err(|_| PushFail {
            reason: "interconnect: push semaphore closed (unreachable)".to_string(),
            fp: String::new(),
            skip: false,
        })?;
        push_one(
            &self.store,
            &self.server_key,
            &self.resolver,
            &self.my_domain,
            target_domain,
        )
        .await
    }

    /// 推送结果处置（服务面包装；单一审计源，见 [`finish_push_audit`]）。
    pub async fn finish_push(
        &self,
        target_domain: &str,
        result: Result<PushSummary, PushFail>,
    ) -> bool {
        finish_push_audit(&self.store, &self.audit, target_domain, result).await
    }

    /// 一轮全量重推（T3：全部已知 targets = 自持行 distinct target ∪
    /// outbox targets；单 target 失败 = 该 target 跳过 + WARN 审计，不
    /// 返回成功 target 数（手动触发口径 = `trigger_all`）。
    pub async fn push_all_once(&self) -> usize {
        let targets = self.store.push_targets().await.unwrap_or_default();
        let n = targets.len();
        if n == 0 {
            return 0;
        }
        let sem = Arc::clone(&self.push_sem);
        let mut handles = Vec::with_capacity(n);
        for target in targets {
            let store = Arc::clone(&self.store);
            let server_key = Arc::clone(&self.server_key);
            let audit = Arc::clone(&self.audit);
            let resolver = Arc::clone(&self.resolver);
            let my_domain = self.my_domain.clone();
            let sem = Arc::clone(&sem);
            handles.push(tokio::spawn(async move {
                // 有界并发（>16 targets 时排队；本 relay 对端数个位数 = 恒并发）。
                let _permit = match sem.acquire().await {
                    Ok(p) => p,
                    Err(_) => return false,
                };
                let r =
                    push_one(store.as_ref(), server_key.as_ref(), &resolver, &my_domain, &target)
                        .await;
                finish_push_audit(store.as_ref(), &audit, &target, r).await
            }));
        }
        let mut ok = 0usize;
        for h in handles {
            match h.await {
                Ok(true) => ok += 1,
                Ok(false) => {
                    tracing::warn!("interconnect: push target failed (see push failed audit)");
                }
                Err(e) => {
                    tracing::warn!("interconnect: push task panicked: {e}");
                }
            }
        }
        ok
    }

    /// 周期重推任务（`repush_interval` ± 0..=60s 抖动，打散重推风暴；
    /// `stop` 置 true 优雅退出）。
    pub async fn run_push_cycle(self: &Arc<Self>, mut stop: tokio::sync::watch::Receiver<bool>) {
        loop {
            let jitter_ms =
                rand::thread_rng().gen_range(0..=REPUSH_JITTER_MAX * 1000 + 1);
            let delay = Duration::from_secs(self.engine.repush_interval)
                + Duration::from_millis(jitter_ms);
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = stop.changed() => {
                    if *stop.borrow() {
                        tracing::info!("interconnect: push cycle stopped");
                        return;
                    }
                }
            }
            let t0 = Instant::now();
            let ok = self.push_all_once().await;
            tracing::info!(
                "interconnect: push cycle done ({}s, {ok} targets ok)",
                t0.elapsed().as_secs()
            );
        }
    }

    /// 后台清扫任务（30s tick：outbox 退避重试 + ttl 剪除；每 10 tick =
    /// 300s 间隔：B 侧 pushed 行 TTL 清扫 + A 侧 liveness 清扫，§T5/T8；
    /// `stop` 置 true 优雅退出）。
    pub async fn run_sweep(self: &Arc<Self>, mut stop: tokio::sync::watch::Receiver<bool>) {
        let mut tick: u64 = 0;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(SWEEP_TICK) => {}
                _ = stop.changed() => {
                    if *stop.borrow() {
                        tracing::info!("interconnect: sweep task stopped");
                        return;
                    }
                }
            }
            tick += 1;
            self.sweep_outbox().await;
            if tick % SLOW_SWEEP_EVERY == 0 {
                self.sweep_slow().await;
            }
        }
    }

    /// outbox 退避重试（`next_retry_at <= now` 行；并行 ≤16）+ 行 TTL
    /// 剪除（age > 24h，`reason=ttl`）。
    async fn sweep_outbox(&self) {
        let now = now_unix_secs();
        let due = self.store.outbox_due(now).await.unwrap_or_default();
        if !due.is_empty() {
        let sem = Arc::clone(&self.push_sem);
            let mut handles = Vec::with_capacity(due.len());
            for row in due {
                let store = Arc::clone(&self.store);
                let server_key = Arc::clone(&self.server_key);
                let audit = Arc::clone(&self.audit);
                let resolver = Arc::clone(&self.resolver);
                let my_domain = self.my_domain.clone();
                let sem = Arc::clone(&sem);
                handles.push(tokio::spawn(async move {
                    let _permit = sem.acquire().await.ok();
                    let r = push_one(
                        store.as_ref(),
                        server_key.as_ref(),
                        &resolver,
                        &my_domain,
                        &row.target_domain,
                    )
                    .await;
                    finish_push_audit(store.as_ref(), &audit, &row.target_domain, r).await
                }));
            }
            for h in handles {
                let _ = h.await;
            }
        }
        // 行 TTL 剪除（24h；周期重推是真正恢复通道，队列只服务短离线）。
        for (target, n) in self
            .store
            .outbox_prune_expired(now, OUTBOX_TTL_SECS)
            .await
            .unwrap_or_default()
        {
            self.audit.record(TunnelAuditEvent::PushOutboxPruned {
                target_domain: target,
                n,
                reason: "ttl".to_string(),
            });
        }
    }

    /// 慢扫（300s 间隔）：B 侧 pushed 行 TTL 超龄源清理（§T5；存续策略
    /// 在案，**不**视为错误）+ A 侧 liveness 超龄行清理 + 推撤销（§T8）。
    async fn sweep_slow(&self) {
        let now = now_unix_secs();
        // B 侧：source 在 TTL 内无续约 = 清该 source 全部行 + meta 水位键。
        for (fp, rows) in self
            .store
            .expired_push_sources(now.saturating_sub(self.engine.entry_ttl))
            .await
            .unwrap_or_default()
        {
            let n = self.store.delete_pushed_by_source(&fp).await.unwrap_or(rows);
            self.audit.record(TunnelAuditEvent::PushSourceExpired { fp, rows: n });
        }
        // A 侧：devlast 超龄 **且** 不在注册表（活体探针）= 删行 +
        // epoch+1 + 立即重推（推撤销）+ `dir row expired` 审计。探针未
        // 挂载 = 不跑（无活体信号不删行，fail-safe）。
        let Some(probe) = &self.engine.liveness else {
            return;
        };
        let stale = self
            .store
            .liveness_stale_devices(now.saturating_sub(self.engine.liveness_ttl))
            .await
            .unwrap_or_default();
        for dev in stale {
            // 瞬断（< TTL）= 行保留：仍在注册表 = 活体。
            if probe.is_online(&dev) {
                continue;
            }
            let targets = self.store.delete_device_rows(&dev).await.unwrap_or_default();
            for t in &targets {
                self.audit.record(TunnelAuditEvent::DirRowExpired {
                    device_id: dev.clone(),
                    target_domain: t.clone(),
                });
            }
            // 推撤销（immediate 重推；失败 = outbox 同态重试，声明式幂等）。
            for t in targets {
                let r = self.push_to(&t).await;
                let _ = self.finish_push(&t, r).await;
            }
        }
    }
}

#[async_trait]
impl PushTrigger for InterconnectService {
    /// `DirList{refresh:true}` = 一轮全量重推（T3 中继层；UI 不消费）。
    async fn trigger_all(&self) -> usize {
        self.push_all_once().await
    }

    /// 变更即推（T1/T2：调用方 dir_backend 已 spawn，本方法异步执行）。
    async fn trigger_target(&self, target_domain: &str) -> bool {
        let r = self.push_to(target_domain).await;
        self.finish_push(target_domain, r).await
    }
}

// ────────────────────────────────────────────────────────────────────────
// v2 签名覆盖域逐字节向量 / HELLO v2 回环握手 / 零凭据核〔冻结面复用〕+
// 受理门拒收矩阵 / 声明式应用语义 / TTL+liveness 清扫 / 双中继回环 e2e /
// TOFU 不符拒 / 离线补推 / 废帧结构校验丢弃）
// ────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::dir_store::SOURCE_PUSHED;
    use rand::rngs::OsRng;
    use std::collections::HashMap;
    use std::sync::Mutex;

    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn tmp_db(name: &str) -> std::path::PathBuf {
        let i = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "kirin_r1403_ix_{}_{}_{}",
            std::process::id(),
            i,
            name
        ));
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        p
    }

    fn test_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn b64_vk(vk: &VerifyingKey) -> String {
        base64::engine::general_purpose::STANDARD.encode(vk.to_bytes())
    }

    #[derive(Debug, Default)]
    struct CollectAudit(Mutex<Vec<TunnelAuditEvent>>);
    impl CollectAudit {
        fn events(&self) -> Vec<TunnelAuditEvent> {
            self.0.lock().unwrap().clone()
        }
    }
    impl AuditSink for CollectAudit {
        fn record(&self, e: TunnelAuditEvent) {
            self.0.lock().unwrap().push(e);
        }
    }

    /// mock 加密解析器（DNS 面离线可测：SRV/TXT/A/AAAA 注入）。
    #[derive(Debug, Clone, Default)]
    struct MockResolver {
        data: HashMap<String, Vec<(RecordType, Vec<Record>)>>,
    }
    impl MockResolver {
        fn with(mut self, host: &str, rtype: RecordType, recs: Vec<Record>) -> Self {
            self.data
                .entry(host.to_string())
                .or_default()
                .push((rtype, recs));
            self
        }
        /// 为 relay 域 `domain` 生成标准三件套记录（SRV 端口 + TXT 公钥 + A 回环）。
        fn for_relay(domain: &str, port: u16, vk: &VerifyingKey) -> Self {
            let srv = Record {
                name: String::new(),
                rtype: RecordType::SRV,
                ttl: 60,
                data: RecordData::Srv {
                    priority: 0,
                    weight: 1,
                    port,
                    target: format!("{domain}."),
                },
            };
            let txt = Record {
                name: String::new(),
                rtype: RecordType::TXT,
                ttl: 60,
                data: RecordData::Plain(format!(
                    "{{\"node_type\":\"relay\",\"public_key\":\"{}\"}}",
                    b64_vk(vk)
                )),
            };
            let a = Record {
                name: String::new(),
                rtype: RecordType::A,
                ttl: 60,
                data: RecordData::Plain("127.0.0.1".into()),
            };
            Self::default()
                .with(&format!("_kirin-relay._tcp.{domain}"), RecordType::SRV, vec![srv])
                .with(domain, RecordType::TXT, vec![txt])
                .with(domain, RecordType::A, vec![a])
        }

        /// 多 relay 三件套集（双/三 relay 回环 e2e 夹具）。
        fn for_relays(mut self, specs: &[(String, u16, &VerifyingKey)]) -> Self {
            for (domain, port, vk) in specs {
                let srv = Record {
                    name: String::new(),
                    rtype: RecordType::SRV,
                    ttl: 60,
                    data: RecordData::Srv {
                        priority: 0,
                        weight: 1,
                        port: *port,
                        target: format!("{domain}."),
                    },
                };
                let txt = Record {
                    name: String::new(),
                    rtype: RecordType::TXT,
                    ttl: 60,
                    data: RecordData::Plain(format!(
                        "{{\"node_type\":\"relay\",\"public_key\":\"{}\"}}",
                        b64_vk(vk)
                    )),
                };
                let a = Record {
                    name: String::new(),
                    rtype: RecordType::A,
                    ttl: 60,
                    data: RecordData::Plain("127.0.0.1".into()),
                };
                self = self
                    .with(&format!("_kirin-relay._tcp.{domain}"), RecordType::SRV, vec![srv])
                    .with(domain, RecordType::TXT, vec![txt])
                    .with(domain, RecordType::A, vec![a]);
            }
            self
        }
    }
    #[async_trait::async_trait]
    impl Resolver for MockResolver {
        async fn resolve(
            &self,
            host: &str,
            rt: RecordType,
        ) -> Result<Vec<Record>, ResolverError> {
            for (r, recs) in self.data.get(host).into_iter().flatten() {
                if *r == rt {
                    return Ok(recs.clone());
                }
            }
            Err(ResolverError::AllEndpointsFailed {
                detail: format!("mock: no {rt:?} records for {host}"),
            })
        }
    }

    /// 测试辅助：活体探针桩（T8 清扫单测）。
    #[derive(Debug)]
    struct FakeProbe(Mutex<bool>);
    impl FakeProbe {
        fn new(online: bool) -> Arc<Self> {
            Arc::new(Self(Mutex::new(online)))
        }
        fn set(&self, online: bool) {
            *self.0.lock().unwrap() = online;
        }
    }
    impl DirLivenessProbe for FakeProbe {
        fn is_online(&self, _id: &str) -> bool {
            *self.0.lock().unwrap()
        }
    }

    // ── DNS 纯函数（SRV/TXT 解析结果注入离线可测 = 量化验收项） ───────

    #[test]
    fn test_r137_12_parse_relay_txt_frozen() {
        let key = test_key();
        let good = format!(
            "{{\"node_type\":\"relay\",\"public_key\":\"{}\"}}",
            b64_vk(&key.verifying_key())
        );
        let info = parse_relay_txt(&good).unwrap();
        assert_eq!(info.node_type, "relay");
        assert_eq!(info.pubkey, key.verifying_key().to_bytes());
        // node_type 不同 key 空间（设备 DeviceMeta = 拒）。
        assert!(parse_relay_txt(&format!(
            "{{\"node_type\":\"device\",\"public_key\":\"{}\"}}",
            b64_vk(&key.verifying_key())
        ))
        .is_none());
        // base64 非 32B / 坏 JSON = 拒。
        assert!(parse_relay_txt(&format!(
            "{{\"node_type\":\"relay\",\"public_key\":\"{}\"}}",
            base64::engine::general_purpose::STANDARD.encode([1u8; 31])
        ))
        .is_none());
        assert!(parse_relay_txt("not json").is_none());
        assert!(parse_relay_txt(&format!(
            "{{\"node_type\":\"relay\",\"public_key\":\"!!\"}}"
        ))
        .is_none());
    }

    #[test]
    fn test_r137_12_select_srv_port_frozen() {
        use RecordData::Srv;
        let mk = |priority: u16, port: u16| Record {
            name: String::new(),
            rtype: RecordType::SRV,
            ttl: 60,
            data: Srv {
                priority,
                weight: 1,
                port,
                target: "t".into(),
            },
        };
        // priority 最小者胜（RFC 2782 序）。
        assert_eq!(
            select_srv_port(&[mk(10, 7002), mk(1, 7003), mk(0, 7001)]),
            Some(7001)
        );
        // port=0 无效跳过。
        assert_eq!(select_srv_port(&[mk(0, 0), mk(1, 9000)]), Some(9000));
        // 无 SRV / 全无效 = None。
        assert_eq!(select_srv_port(&[]), None);
        assert_eq!(select_srv_port(&[mk(0, 0)]), None);
        // 非 SRV 记录忽略。
        let txt = Record {
            name: String::new(),
            rtype: RecordType::TXT,
            ttl: 60,
            data: RecordData::Plain("x".into()),
        };
        assert_eq!(select_srv_port(&[txt]), None);
    }

    #[test]
    fn test_r137_12_merge_addrs_frozen() {
        let ok_a = Ok(vec![Record {
            name: String::new(),
            rtype: RecordType::A,
            ttl: 60,
            data: RecordData::Plain("127.0.0.1".into()),
        }]);
        let ok_aaaa = Ok(vec![Record {
            name: String::new(),
            rtype: RecordType::AAAA,
            ttl: 60,
            data: RecordData::Plain("::1".into()),
        }]);
        let v: Vec<SocketAddr> = merge_addrs(&ok_a, &ok_aaaa, 7002);
        assert_eq!(v, vec![
            "127.0.0.1:7002".parse().unwrap(),
            "[::1]:7002".parse().unwrap(),
        ]);
        // A 失败 AAAA 可用（混合 fail 语义：可用者仍返回）。
        let v = merge_addrs(&Err(ResolverError::Timeout), &ok_aaaa, 7002);
        assert_eq!(v, vec!["[::1]:7002".parse().unwrap()]);
        // 全失败 = 空。
        assert!(merge_addrs(
            &Err(ResolverError::Timeout),
            &Err(ResolverError::Timeout),
            7002
        )
        .is_empty());
    }
    // ── Hello 签名覆盖域 / AEAD / fp 派生向量 ─────────────────────────

    #[test]
    fn test_r140_1_hello_sig_vectors_v2() {
        let key = test_key();
        let vk = key.verifying_key();
        let nonce = [7u8; 16];
        let id_pub = vk.to_bytes();
        let domain = "a.relay.example.com";
        let msg = hello_sig_message(INTERCONNECT_VERSION, &nonce, &id_pub, domain);
        let sig = key.sign(&msg);
        let ok = Signature::from_slice(&sig.to_bytes()).unwrap();
        assert!(vk.verify(&msg, &ok).is_ok());
        // nonce 篡改 = 败。
        let msg2 = hello_sig_message(INTERCONNECT_VERSION, &[8u8; 16], &id_pub, domain);
        assert!(vk.verify(&msg2, &ok).is_err());
        // 版本串篡改 = 败。
        let msg3 = hello_sig_message("RELAY-DIR/1", &nonce, &id_pub, domain);
        assert!(vk.verify(&msg3, &ok).is_err());
        // id_pub 篡改 = 败。
        let mut bad_pub = id_pub;
        bad_pub[0] ^= 1;
        let msg4 = hello_sig_message(INTERCONNECT_VERSION, &nonce, &bad_pub, domain);
        assert!(vk.verify(&msg4, &ok).is_err());
        // id_domain 篡改 = 败（v2 新增签名域）。
        let msg5 = hello_sig_message(INTERCONNECT_VERSION, &nonce, &id_pub, "evil.other.com");
        assert!(vk.verify(&msg5, &ok).is_err());
        // 覆盖域冻结：ver ‖ nonce ‖ id_pub ‖ id_domain（逐字节向量钉死）。
        let mut expect = Vec::new();
        expect.extend_from_slice(INTERCONNECT_VERSION.as_bytes());
        expect.extend_from_slice(&nonce);
        expect.extend_from_slice(&id_pub);
        expect.extend_from_slice(domain.as_bytes());
        assert_eq!(msg, expect, "hello v2 覆盖域逐字节冻结");
        assert_eq!(msg.len(), INTERCONNECT_VERSION.len() + 48 + domain.len());
        // v1 域签名（前三段）对新验签器必败（旧 HELLO 不可重放进 RELAY-DIR/2）。
        let mut v1_msg = Vec::new();
        v1_msg.extend_from_slice(INTERCONNECT_VERSION.as_bytes());
        v1_msg.extend_from_slice(&nonce);
        v1_msg.extend_from_slice(&id_pub);
        assert!(
            vk.verify(&v1_msg, &ok).is_err(),
            "v1 三段域签名对 v2 验签器必须失败"
        );
    }

    #[test]
    fn test_r137_12_aead_roundtrip_and_tamper() {
        let key = [3u8; 32];
        let cipher = AeadCipher::new(&key);
        let pt = b"secret-payload";
        let body = aead_frame_body(&cipher, IX_FRAME_PUSH, pt).unwrap();
        // 往返。
        assert_eq!(
            aead_unframe_body(&cipher, IX_FRAME_PUSH, &body).unwrap(),
            pt
        );
        // 篡改 ct 一字节 = 败（GCM tag）。
        let mut bad = body.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(aead_unframe_body(&cipher, IX_FRAME_PUSH, &bad).is_err());
        // AAD 类型不符 = 败（帧类型绑定）。
        assert!(aead_unframe_body(&cipher, IX_FRAME_HELLO, &body).is_err());
        // 短于 nonce+tag = 败。
        assert!(aead_unframe_body(&cipher, IX_FRAME_PUSH, &[0u8; 8]).is_err());
    }

    #[test]
    fn test_r140_3_fp_of_pubkey_single_sourced() {
        let key = test_key();
        let vk = key.verifying_key();
        // fp 派生单源：与 core fingerprint(b64) 逐字一致（my_fp / 接收方
        // fp / source_fp 零分歧口径）。
        let fp = fp_of_pubkey(&vk.to_bytes());
        assert_eq!(fp, kirin_desk_core::crypto::ed25519::fingerprint(&b64_vk(&vk)));
        assert_eq!(fp.len(), 79, "79 字符 canonical 形态");
    }

    // ── HELLO v2 回环握手（B 受理面 + A 验签面） ───────────────────────

    async fn start_serve(svc: Arc<InterconnectService>) -> (tokio::task::JoinHandle<()>, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            svc.serve_listeners(vec![("loopback".to_string(), listener)])
                .await;
        });
        // 接受循环就绪（回环绑定已完成，bind 先于 spawn；小 sleep 兜底调度）。
        tokio::time::sleep(Duration::from_millis(50)).await;
        (handle, port)
    }

    /// 测试辅助：客户端侧 HELLO v2 握手（返回 AEAD 会话；负向量/废帧驱动）。
    async fn client_handshake(
        stream: &mut TcpStream,
        key: &SigningKey,
        domain: &str,
    ) -> Result<AeadCipher, String> {
        let eph = EphemeralSession::new();
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let id_pub = key.verifying_key().to_bytes();
        let hello = IxHello {
            ver: INTERCONNECT_VERSION.to_string(),
            nonce,
            eph_pub: eph.public_key_bytes(),
            id_pub,
            id_domain: domain.to_string(),
            sig: key
                .sign(&hello_sig_message(INTERCONNECT_VERSION, &nonce, &id_pub, domain))
                .to_bytes()
                .to_vec(),
        };
        write_frame(stream, IX_FRAME_HELLO, &bincode::serialize(&hello).unwrap())
            .await
            .map_err(|e| e.to_string())?;
        let (ty, body) = timeout(HANDSHAKE_TIMEOUT, read_frame(stream, IX_MAX_FRAME_LEN))
            .await
            .map_err(|_| "hello timeout".to_string())?
            .map_err(|e| e.to_string())?;
        if ty != IX_FRAME_HELLO {
            return Err(format!("frame 0x{ty:02x} != hello"));
        }
        let hello_b: IxHello = bincode::deserialize(&body).map_err(|e| e.to_string())?;
        let peer_eph =
            EphemeralSession::parse_public_key(&hello_b.eph_pub).map_err(|e| e.to_string())?;
        let session_key = eph.compute_session_key(&peer_eph).map_err(|e| e.to_string())?;
        Ok(AeadCipher::new(&session_key))
    }

    /// v1 形状 HELLO（test-only：混合版本 fail-closed 负向量构造）。
    #[derive(Serialize)]
    struct V1IxHello {
        ver: String,
        nonce: [u8; 16],
        eph_pub: [u8; 32],
        id_pub: [u8; 32],
        sig: Vec<u8>,
    }

    #[tokio::test]
    async fn test_r140_1_hello_v2_loopback_handshake() {
        // ── B 侧（受理方，serve）──
        let p_b = tmp_db("hellov2_b");
        let store_b = Arc::new(DirStore::open(&p_b).unwrap());
        let key_b = test_key();
        let vk_b = key_b.verifying_key();
        let audit_b = Arc::new(CollectAudit::default());
        let svc_b = Arc::new(InterconnectService::new(
            store_b,
            Arc::new(key_b),
            audit_b.clone(),
            Arc::new(MockResolver::default()),
            "b.relay.example.com",
            EngineConfig::default(),
        ));
        let (task_b, port) = start_serve(svc_b).await;

        // ── A 侧：发 HELLO v2 → 收 HELLO v2 → 验签 ──
        let key_a = test_key();
        let eph_a = EphemeralSession::new();
        let mut nonce_a = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce_a);
        let id_pub_a = key_a.verifying_key().to_bytes();
        let hello_a = IxHello {
            ver: INTERCONNECT_VERSION.to_string(),
            nonce: nonce_a,
            eph_pub: eph_a.public_key_bytes(),
            id_pub: id_pub_a,
            id_domain: "a.relay.example.com".into(),
            sig: key_a
                .sign(&hello_sig_message(
                    INTERCONNECT_VERSION,
                    &nonce_a,
                    &id_pub_a,
                    "a.relay.example.com",
                ))
                .to_bytes()
                .to_vec(),
        };
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        write_frame(
            &mut stream,
            IX_FRAME_HELLO,
            &bincode::serialize(&hello_a).unwrap(),
        )
        .await
        .unwrap();
        let (ty, body) = read_frame(&mut stream, IX_MAX_FRAME_LEN).await.unwrap();
        assert_eq!(ty, IX_FRAME_HELLO, "B 必须回 HELLO");
        let hello_b: IxHello = bincode::deserialize(&body).unwrap();
        assert_eq!(hello_b.ver, INTERCONNECT_VERSION);
        assert_eq!(hello_b.id_domain, "b.relay.example.com", "id_domain = --relay-domain");
        assert_eq!(hello_b.id_pub, vk_b.to_bytes());
        let msg_b = hello_sig_message(
            INTERCONNECT_VERSION,
            &hello_b.nonce,
            &hello_b.id_pub,
            &hello_b.id_domain,
        );
        let sig_b = Signature::from_slice(&hello_b.sig).unwrap();
        assert!(vk_b.verify(&msg_b, &sig_b).is_ok(), "B HELLO v2 验签必过");
        // 客户端不发数据帧即断开（B 数据帧读 = EOF 快拒，无 15s 悬挂）。
        drop(stream);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 负向量①：id_domain 非纯 FQDN = B 断连 + 审计。
        let mut bad = hello_a.clone();
        bad.id_domain = "not-an-fqdn".into();
        let bad_a = IxHello {
            sig: key_a
                .sign(&hello_sig_message(
                    INTERCONNECT_VERSION,
                    &bad.nonce,
                    &bad.id_pub,
                    &bad.id_domain,
                ))
                .to_bytes()
                .to_vec(),
            ..bad
        };
        let mut s2 = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        write_frame(&mut s2, IX_FRAME_HELLO, &bincode::serialize(&bad_a).unwrap())
            .await
            .unwrap();
        let _ = s2.read(&mut [0u8; 8]).await; // B 断连 = EOF/错
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            audit_b.events().iter().any(|e| matches!(
                e,
                TunnelAuditEvent::InterconnectRejected { reason, .. }
                    if reason.contains("FQDN")
            )),
            "B 侧必须审计 id_domain 拒: {:?}",
            audit_b.events()
        );

        // 负向量②：v1 五字段 HELLO 对 v2 解码器 = 解码必败（混合版本
        // 自限制，设计 §7.3）= 断连 + 审计。
        let v1 = V1IxHello {
            ver: INTERCONNECT_VERSION.to_string(),
            nonce: nonce_a,
            eph_pub: eph_a.public_key_bytes(),
            id_pub: id_pub_a,
            sig: key_a
                .sign(&hello_sig_message(
                    INTERCONNECT_VERSION,
                    &nonce_a,
                    &id_pub_a,
                    "a.relay.example.com",
                ))
                .to_bytes()
                .to_vec(),
        };
        let mut s3 = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        write_frame(&mut s3, IX_FRAME_HELLO, &bincode::serialize(&v1).unwrap())
            .await
            .unwrap();
        let _ = s3.read(&mut [0u8; 8]).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            audit_b.events().iter().any(|e| matches!(
                e,
                TunnelAuditEvent::InterconnectRejected { reason, .. }
                    if reason.contains("hello decode")
            )),
            "v1 形状 HELLO 必须解码败拒: {:?}",
            audit_b.events()
        );

        task_b.abort();
        let _ = std::fs::remove_dir_all(p_b.parent().unwrap().join(p_b.file_name().unwrap()));
    }

    // ── 零凭据核（红线：互联帧字节零 token/挑战码/私钥/会话密钥） ────

    #[test]
    fn test_r140_1_interconnect_frames_v2_zero_credentials() {
        let token = "TOP-SECRET-RELAY-TOKEN-0f997cb3";
        let key = test_key();
        let eph = EphemeralSession::new();
        let nonce = [1u8; 16];
        let id_pub = key.verifying_key().to_bytes();
        let hello = IxHello {
            ver: INTERCONNECT_VERSION.into(),
            nonce,
            eph_pub: eph.public_key_bytes(),
            id_pub,
            id_domain: "a.relay.example.com".into(),
            sig: key
                .sign(&hello_sig_message(
                    INTERCONNECT_VERSION,
                    &nonce,
                    &id_pub,
                    "a.relay.example.com",
                ))
                .to_bytes()
                .into(),
        };
        let mut bytes = bincode::serialize(&hello).unwrap();
        // v2 推送面（IxPush/PushEntry）字节同样零凭据。
        let entry = PushEntry {
            device_id: "dev-1".into(),
            domain: "a.example.com".into(),
            updated_at: 1,
            sig: vec![2u8; 64],
        };
        let push = IxPush {
            epoch: 3,
            entries: vec![entry],
            batch_sig: vec![3u8; 64],
            ix_token: String::new(),
        };
        bytes.extend(bincode::serialize(&push).unwrap());
        let as_str = String::from_utf8_lossy(&bytes);
        assert!(!as_str.contains(token), "凭据零上链");
        // 帧型号/版本串冻结钉（0x02/0x03 = 废帧保留位，常量不复用）。
        assert_eq!(INTERCONNECT_VERSION, "RELAY-DIR/3");
        assert_eq!(INTERCONNECT_VERSION_LEGACY, "RELAY-DIR/2");
        assert_eq!(IX_FRAME_HELLO, 0x01);
        assert_eq!(IX_FRAME_PUSH, 0x04);
    }


    #[test]
    fn test_r140_1_ixpush_roundtrip() {
        let e1 = PushEntry {
            device_id: "dev-1".into(),
            domain: "a.example.com".into(),
            updated_at: 1700000000,
            sig: vec![9u8; 64],
        };
        let e2 = PushEntry {
            device_id: "dev-2".into(),
            domain: "b.example.com".into(),
            updated_at: 1700000001,
            sig: vec![10u8; 64],
        };
        let push = IxPush {
            epoch: 42,
            entries: vec![e1.clone(), e2.clone()],
            batch_sig: vec![7u8; 64],
            ix_token: "tok-r168-roundtrip".into(),
        };
        let bytes = bincode::serialize(&push).unwrap();
        let back: IxPush = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back, push);
        assert_eq!(back.ix_token, "tok-r168-roundtrip");
        // 空 entries 合法（声明式全撤销态，§2.3）。
        let empty = IxPush {
            epoch: 43,
            entries: Vec::new(),
            batch_sig: vec![8u8; 64],
            ix_token: String::new(),
        };
        let back: IxPush =
            bincode::deserialize(&bincode::serialize(&empty).unwrap()).unwrap();
        assert_eq!(back, empty);
        assert!(back.entries.is_empty());
        // 声明序 = wire 序）。
        let mut epoch_le = [0u8; 8];
        epoch_le.copy_from_slice(&bincode::serialize(&42u64).unwrap());
        assert!(bytes.starts_with(&epoch_le), "epoch 必须 wire 首字段");
        // 长 ‖ 内容，末 18 字节 = "tok-r168-roundtrip" 内容，其前 8 字节
        // = 长度前缀。
        let tok_len = u64::from_le_bytes(
            bytes[bytes.len() - 26..bytes.len() - 18]
                .try_into()
                .unwrap(),
        );
        assert_eq!(tok_len, 18, "ix_token 必须 wire 尾字段（长度前缀可读）");
        assert_eq!(&bytes[bytes.len() - 18..], b"tok-r168-roundtrip");
        // batch_sig 长度前缀位于 ix_token 域之前再退 64B 内容：
        // [len-8-18-8-64-8 .. +8] = bincode Vec<u8>（u64 LE 长 ‖ 64B）。
        let sig_len_prefix = u64::from_le_bytes(
            bytes[bytes.len() - 98..bytes.len() - 90]
                .try_into()
                .unwrap(),
        );
        assert_eq!(sig_len_prefix, 64, "batch_sig 恒 64B");
    }

    #[test]
    fn test_r140_1_v2_sig_messages_byte_vectors() {
        // entry_sig_message_v2 逐字节钉死：
        // device_id ␟(0x1F) domain ␟ ts_be64 ␟ "pushed" ␟ recipient_fp
        let fp = "a1b2:c3d4:e5f6:0718:293a:4b5c:6d7e:8f90:a1b2:c3d4:e5f6:0718:293a:4b5c:6d7e:8f90";
        let m = entry_sig_message_v2("dev-1", "a.example.com", 0x0102_0304_0506_0708, fp);
        let mut expect = Vec::new();
        expect.extend_from_slice(b"dev-1");
        expect.push(0x1F);
        expect.extend_from_slice(b"a.example.com");
        expect.push(0x1F);
        expect.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        expect.push(0x1F);
        expect.extend_from_slice(b"pushed");
        expect.push(0x1F);
        expect.extend_from_slice(fp.as_bytes());
        assert_eq!(m, expect, "entry_sig_message_v2 逐字节冻结");
        // 长度钉死 = id + 1 + domain + 1 + 8 + 1 + 6 + 1 + fp。
        assert_eq!(m.len(), 5 + 1 + 13 + 1 + 8 + 1 + 6 + 1 + fp.len());

        // batch_sig_message_v2 逐字节钉死：
        // "RELAY-DIR-PUSH/1" ‖ epoch_be64 ‖ recipient_fp ‖ concat(sorted bincode)
        let key = test_key();
        let e = PushEntry {
            device_id: "dev-1".into(),
            domain: "a.example.com".into(),
            updated_at: 5,
            sig: key
                .sign(&entry_sig_message_v2("dev-1", "a.example.com", 5, fp))
                .to_bytes()
                .to_vec(),
        };
        let m = batch_sig_message_v2(9, fp, &[e.clone()]);
        let mut expect = Vec::new();
        expect.extend_from_slice(b"RELAY-DIR-PUSH/1");
        expect.extend_from_slice(&9u64.to_be_bytes());
        expect.extend_from_slice(fp.as_bytes());
        expect.extend_from_slice(&bincode::serialize(&e).unwrap());
        assert_eq!(m, expect, "batch_sig_message_v2 逐字节冻结");

        // 排序敏感性：entries 未升序时覆盖域不同（device_id 升序 = 冻结序）。
        let e_a = PushEntry {
            device_id: "a".into(),
            domain: "d.example.com".into(),
            updated_at: 1,
            sig: vec![1u8; 64],
        };
        let e_b = PushEntry {
            device_id: "b".into(),
            domain: "e.example.com".into(),
            updated_at: 2,
            sig: vec![2u8; 64],
        };
        let m_ab = batch_sig_message_v2(1, fp, &[e_a.clone(), e_b.clone()]);
        let m_ba = batch_sig_message_v2(1, fp, &[e_b, e_a]);
        assert_ne!(m_ab, m_ba, "批次序 = 签名域，乱序必败");

        // 完整签验链（A 逐条新签 + 整批签 → B 侧验签纯函数面）：
        let vk = key.verifying_key();
        let sorted = vec![e];
        let batch_sig = key
            .sign(&batch_sig_message_v2(9, fp, &sorted))
            .to_bytes()
            .to_vec();
        let sig_check = Signature::from_slice(&batch_sig).unwrap();
        assert!(
            vk.verify(&batch_sig_message_v2(9, fp, &sorted), &sig_check)
                .is_ok()
        );
        let entry_sig = Signature::from_slice(&sorted[0].sig).unwrap();
        assert!(vk
            .verify(
                &entry_sig_message_v2(&sorted[0].device_id, &sorted[0].domain, 5, fp),
                &entry_sig
            )
            .is_ok());
        // 接收方改道重放 = recipient_fp 换 = 逐条 sig 必败：
        let evil_fp = "dead:beef:dead:beef:dead:beef:dead:beef:dead:beef:dead:beef:dead:beef:dead";
        assert!(
            vk.verify(
                &entry_sig_message_v2(&sorted[0].device_id, &sorted[0].domain, 5, evil_fp),
                &entry_sig
            )
            .is_err(),
            "recipient_fp 绑定：改道批次必须验签败"
        );
    }


    const IX_TEST_TOKEN: &str = "r168-ix-gate-token-001";
    /// 第二枚（同一 store 内 device 缓存分 target 用——token UNIQUE 全局）。
    const IX_TEST_TOKEN_B: &str = "r168-ix-gate-token-002";

    /// 测试夹具：构造 IxPush（entries 以 `entry_fp` 逐条新签、整批以
    /// `batch_fp` 签〔device_id 升序冻结序〕；`key` = 源 relay 私钥；
    /// ix_token = [`IX_TEST_TOKEN`]，svc store 需预登记同名活跃 cli 行）。
    fn make_batch(
        key: &SigningKey,
        epoch: u64,
        entry_fp: &str,
        batch_fp: &str,
        entries: &[(&str, &str, u64)],
    ) -> IxPush {
        let mut list: Vec<PushEntry> = entries
            .iter()
            .map(|(id, domain, ts)| PushEntry {
                device_id: (*id).to_string(),
                domain: (*domain).to_string(),
                updated_at: *ts,
                sig: key
                    .sign(&entry_sig_message_v2(id, domain, *ts, entry_fp))
                    .to_bytes()
                    .to_vec(),
            })
            .collect();
        list.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        let batch_sig = key
            .sign(&batch_sig_message_v2(epoch, batch_fp, &list))
            .to_bytes()
            .to_vec();
        IxPush {
            epoch,
            entries: list,
            batch_sig,
            ix_token: IX_TEST_TOKEN.to_string(),
        }
    }

    fn svc_for(
        store: Arc<DirStore>,
        key: Arc<SigningKey>,
        audit: Arc<CollectAudit>,
        domain: &str,
        engine: EngineConfig,
    ) -> Arc<InterconnectService> {
        Arc::new(InterconnectService::new(
            store,
            key,
            audit,
            Arc::new(MockResolver::default()),
            domain,
            engine,
        ))
    }

    fn clean_db(p: &std::path::Path) {
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(std::path::Path::new(&format!(
            "{}-wal",
            p.to_string_lossy()
        )));
        let _ = std::fs::remove_file(std::path::Path::new(&format!(
            "{}-shm",
            p.to_string_lossy()
        )));
    }


    /// 观测点；resolve 恒败 = 推送速败，只测并发面零测数据面）。
    #[derive(Debug)]
    struct SlowResolver {
        cur: AtomicUsize,
        peak: AtomicUsize,
        ms: u64,
    }
    impl SlowResolver {
        fn new(ms: u64) -> Arc<Self> {
            Arc::new(Self {
                cur: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                ms,
            })
        }
        fn peak(&self) -> usize {
            self.peak.load(Ordering::SeqCst)
        }
    }
    #[async_trait::async_trait]
    impl Resolver for SlowResolver {
        async fn resolve(
            &self,
            _host: &str,
            _rt: RecordType,
        ) -> Result<Vec<Record>, ResolverError> {
            let c = self.cur.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(c, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(self.ms)).await;
            self.cur.fetch_sub(1, Ordering::SeqCst);
            Err(ResolverError::AllEndpointsFailed {
                detail: "r177: slow resolver fail".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn test_r177_trigger_bounded_by_global_sem() {
        let p = tmp_db("r177_sem");
        let store = Arc::new(DirStore::open(&p).unwrap());
        let key = Arc::new(test_key());
        let audit = Arc::new(CollectAudit::default());
        let resolver = SlowResolver::new(120);
        let svc = Arc::new(InterconnectService::new(
            store.clone(),
            key,
            audit,
            Arc::clone(&resolver) as Arc<dyn Resolver>,
            "a.relay.example.com",
            EngineConfig::default(),
        ));
        // A 侧须持有 target 转发凭证缓存——否则 push_one 在解析前
        store
            .ix_upsert_device_token("b.relay.example.com", "r177-dev-tok", "r177", 1)
            .await
            .unwrap();
        // 连发 N=64 次 trigger_target（变更即推公开路径）。
        let mut handles = Vec::new();
        for _ in 0..64 {
            let svc = Arc::clone(&svc);
            handles.push(tokio::spawn(async move {
                let _ = svc.trigger_target("b.relay.example.com").await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let peak = resolver.peak();
        assert!(
            peak <= MAX_CONCURRENT_CONNS,
            "任一时刻进行中 push_one ≤{MAX_CONCURRENT_CONNS}（探针 peak={peak}）"
        );
        assert!(peak >= 8, "探针须观测到显著并行（peak={peak}）");
        clean_db(&p);
    }

    #[tokio::test]
    async fn test_r177_gate_order_cheap_gates_before_entry_sigs() {
        let p = tmp_db("r177_gate");
        let store = Arc::new(DirStore::open(&p).unwrap());
        let key_b = Arc::new(test_key());
        let vk_b = key_b.verifying_key();
        let fp_b = fp_of_pubkey(&vk_b.to_bytes());
        let audit = Arc::new(CollectAudit::default());
        let svc = svc_for(
            store.clone(),
            Arc::clone(&key_b),
            audit.clone(),
            "b.relay.example.com",
            EngineConfig::default(),
        );
        store
            .ix_add_cli_token(IX_TEST_TOKEN, "gate-test", 1)
            .await
            .unwrap();
        let key_a = test_key();
        let vk_a = key_a.verifying_key();

        // 门⑤ cap 前置：20 万条目批（合法自定义 device_id；distinct 超默认
        // cap 10000），门①整批签有效、逐条 sig 全废 → 拒因必须是 cap 而非
        // 门② entry sig，且发生在逐条 Ed25519 验签 CPU 之前（耗时断言）。
        let mut list: Vec<PushEntry> = (0..200_000u32)
            .map(|i| PushEntry {
                device_id: format!("r177-cap-{i:06}"),
                domain: "dev.example.com".to_string(),
                updated_at: 1,
                sig: vec![0xab; 64],
            })
            .collect();
        list.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        let batch_sig = key_a
            .sign(&batch_sig_message_v2(1, &fp_b, &list))
            .to_bytes()
            .to_vec();
        let push = IxPush {
            epoch: 1,
            entries: list,
            batch_sig,
            ix_token: IX_TEST_TOKEN.to_string(),
        };
        let t0 = std::time::Instant::now();
        let r = svc
            .verify_and_apply_push(&push, &vk_a, &fp_b)
            .await
            .unwrap_err();
        let dt = t0.elapsed();
        assert!(
            r.starts_with("per-source cap exceeded"),
            "拒因 = 门⑤ cap 而非门②逐条 sig：{r}"
        );
        assert!(
            dt < std::time::Duration::from_secs(30),
            "cap 快拒须在 20 万次逐条验签前（实测 {dt:?}）"
        );
        drop(push);

        // 门④ 形态前置：20 万空 device_id（distinct=1 ≤ cap），逐条 sig 全废
        // → 拒因 = malformed device_id（非 entry sig）。
        let list2: Vec<PushEntry> = (0..200_000u32)
            .map(|_| PushEntry {
                device_id: String::new(),
                domain: "dev.example.com".to_string(),
                updated_at: 1,
                sig: vec![0xab; 64],
            })
            .collect();
        let batch_sig2 = key_a
            .sign(&batch_sig_message_v2(2, &fp_b, &list2))
            .to_bytes()
            .to_vec();
        let push2 = IxPush {
            epoch: 2,
            entries: list2,
            batch_sig: batch_sig2,
            ix_token: IX_TEST_TOKEN.to_string(),
        };
        let r2 = svc
            .verify_and_apply_push(&push2, &vk_a, &fp_b)
            .await
            .unwrap_err();
        assert!(
            r2.starts_with("malformed device_id"),
            "拒因 = 门④形态 而非门②逐条 sig：{r2}"
        );
        clean_db(&p);
    }


    #[tokio::test]
    async fn test_r182_push_gate4_control_char_device_id_whole_batch_rejected() {
        // 收紧自动同步（零额外改动面）：含 <0x20 控制字符的自定义 ID 批 =
        // malformed device_id 整批拒（fail-closed 不猜；门④先于门⑥，
        // token 面不参与本拒因）。
        let p = tmp_db("r182gate4");
        let store = Arc::new(DirStore::open(&p).unwrap());
        let key_b = Arc::new(test_key());
        let vk_b = key_b.verifying_key();
        let fp_b = fp_of_pubkey(&vk_b.to_bytes());
        let svc = svc_for(
            store.clone(),
            Arc::clone(&key_b),
            Arc::new(CollectAudit::default()),
            "b.relay.example.com",
            EngineConfig::default(),
        );
        let key_a = test_key();
        let vk_a = key_a.verifying_key();
        for evil in ["dev\n1", "dev\tx", "dev\u{1b}esc"] {
            let batch = make_batch(&key_a, 1, &fp_b, &fp_b, &[(evil, "d1.example.com", 1000)]);
            let e = svc
                .verify_and_apply_push(&batch, &vk_a, &fp_b)
                .await
                .unwrap_err();
            assert!(e.starts_with("malformed device_id"), "{evil:?} → {e}");
            // 整批拒 = 本地表零变化（无半信）。
            assert_eq!(store.count().await.unwrap(), 0, "{evil:?} 零落库");
        }
        clean_db(&p);
    }

    #[tokio::test]
    async fn test_r140_3_accept_gate_reject_matrix() {
        let p = tmp_db("gates_b");
        let store = Arc::new(DirStore::open(&p).unwrap());
        let key_b = Arc::new(test_key());
        let vk_b = key_b.verifying_key();
        let fp_b = fp_of_pubkey(&vk_b.to_bytes());
        let audit = Arc::new(CollectAudit::default());
        let svc = svc_for(
            store.clone(),
            Arc::clone(&key_b),
            audit.clone(),
            "b.relay.example.com",
            EngineConfig::default(),
        );
        let key_a = test_key();
        let vk_a = key_a.verifying_key();
        const FP_EVIL: &str = "ab12:cd34:ef56:7890:1234:5678:9abc:def0:1234:5678:9abc:def0:1234:5678:9abc";
        store.ix_add_cli_token(IX_TEST_TOKEN, "gate-test", 1).await.unwrap();

        // 门①：整批签名坏 = 整批拒收（其余各门不评估）。
        let mut p1 = make_batch(&key_a, 1, &fp_b, &fp_b, &[("dev-1", "d1.example.com", 1000)]);
        p1.batch_sig = vec![0u8; 64];
        let e = svc
            .verify_and_apply_push(&p1, &vk_a, &fp_b)
            .await
            .unwrap_err();
        assert!(e.contains("batch sig"), "{e}");
        // 门②：逐条 sig 接收方 fp 绑定 = 改道批次必败（批次签过、条目签
        // 用他人 fp）。
        let p2 = make_batch(&key_a, 1, FP_EVIL, &fp_b, &[("dev-1", "d1.example.com", 1000)]);
        let e = svc
            .verify_and_apply_push(&p2, &vk_a, &fp_b)
            .await
            .unwrap_err();
        assert!(e.contains("entry sig"), "{e}");
        // 门④：形态复检（短码不可展开 = 拒；非 FQDN = 拒；批级整拒不猜）。
        let p3 = make_batch(&key_a, 1, &fp_b, &fp_b, &[("a1b2c3d4e5", "d1.example.com", 1000)]);
        let e = svc
            .verify_and_apply_push(&p3, &vk_a, &fp_b)
            .await
            .unwrap_err();
        assert!(e.contains("malformed device_id"), "{e}");
        let p4 = make_batch(&key_a, 1, &fp_b, &fp_b, &[("dev-1", "not-a-fqdn", 1000)]);
        let e = svc
            .verify_and_apply_push(&p4, &vk_a, &fp_b)
            .await
            .unwrap_err();
        assert!(e.contains("malformed domain"), "{e}");
        // 门⑤：per-source cap（批次 distinct device 数 > cap = 整批拒收）。
        let pc = tmp_db("gates_cap");
        let store_cap = Arc::new(DirStore::open(&pc).unwrap());
        store_cap.ix_add_cli_token(IX_TEST_TOKEN, "gate-test", 1).await.unwrap();
        let svc_cap = svc_for(
            store_cap.clone(),
            Arc::clone(&key_b),
            audit.clone(),
            "b.relay.example.com",
            EngineConfig {
                per_source_cap: 2,
                ..Default::default()
            },
        );
        let p5 = make_batch(
            &key_a,
            1,
            &fp_b,
            &fp_b,
            &[
                ("dev-1", "d1.example.com", 1),
                ("dev-2", "d2.example.com", 2),
                ("dev-3", "d3.example.com", 3),
            ],
        );
        let e = svc_cap
            .verify_and_apply_push(&p5, &vk_a, &fp_b)
            .await
            .unwrap_err();
        assert!(e.contains("per-source cap"), "{e}");
        // 全部拒收 = 本地表零变化（fail-closed 不半信）。
        assert_eq!(store.count().await.unwrap(), 0);
        assert_eq!(store_cap.count().await.unwrap(), 0);

        // 门③：epoch 水位（< last = stale_epoch 拒；== 重放 = 声明式幂等）。
        let p10 = make_batch(&key_a, 10, &fp_b, &fp_b, &[("dev-1", "d1.example.com", 1000)]);
        let r = svc
            .verify_and_apply_push(&p10, &vk_a, &fp_b)
            .await
            .unwrap();
        assert_eq!((r.entries_in, r.applied, r.removed, r.skipped), (1, 1, 0, 0));
        let p9 = make_batch(&key_a, 9, &fp_b, &fp_b, &[("dev-1", "d1.example.com", 1000)]);
        let e = svc
            .verify_and_apply_push(&p9, &vk_a, &fp_b)
            .await
            .unwrap_err();
        assert!(e.contains("stale epoch"), "{e}");
        let r = svc
            .verify_and_apply_push(&p10, &vk_a, &fp_b)
            .await
            .unwrap();
        assert_eq!((r.applied, r.removed, r.skipped), (0, 0, 0), "逐字节重放 = 幂等 no-op");
        clean_db(&p);
        clean_db(&pc);
    }

    #[tokio::test]
    async fn test_r140_3_apply_semantics() {
        use crate::dir_store::SOURCE_MANUAL;
        let dom = "b.relay.example.com";
        let key = test_key();
        let vk = key.verifying_key();
        let fp = fp_of_pubkey(&vk.to_bytes());

        // ── 基础：应用 / 幂等重放 / ts 刷新 / 缺行撤销 / 空批全撤销 ──
        let p1 = tmp_db("app_basic");
        let store = Arc::new(DirStore::open(&p1).unwrap());
        let r = store
            .apply_push_batch(
                &fp,
                dom,
                1,
                &[
                    ("dev-1".into(), "d1.example.com".into(), 1000, vec![1u8; 64]),
                    ("dev-2".into(), "d2.example.com".into(), 1001, vec![2u8; 64]),
                ],
            )
            .await
            .unwrap();
        assert_eq!((r.entries_in, r.applied, r.removed, r.skipped), (2, 2, 0, 0));
        assert_eq!(
            store.get_push_last_epoch(&fp).await.unwrap(),
            Some(1),
            "水位同事务续约"
        );
        // 同源逐字节等价重放 = 幂等 no-op（applied/skipped 均不计）。
        let r = store
            .apply_push_batch(
                &fp,
                dom,
                1,
                &[
                    ("dev-1".into(), "d1.example.com".into(), 1000, vec![1u8; 64]),
                    ("dev-2".into(), "d2.example.com".into(), 1001, vec![2u8; 64]),
                ],
            )
            .await
            .unwrap();
        assert_eq!((r.entries_in, r.applied, r.removed, r.skipped), (2, 0, 0, 0));
        // ts 刷新 = 覆盖（source/source_fp/target=本域）。
        let r = store
            .apply_push_batch(
                &fp,
                dom,
                2,
                &[
                    ("dev-1".into(), "d1.example.com".into(), 2000, vec![1u8; 64]),
                    ("dev-2".into(), "d2.example.com".into(), 1001, vec![2u8; 64]),
                ],
            )
            .await
            .unwrap();
        assert_eq!(r.applied, 1, "仅变更条目计入 applied");
        let row = store.get("dev-1", dom).await.unwrap().unwrap();
        assert_eq!(
            (
                row.updated_at,
                row.source.as_str(),
                row.source_fp.as_deref()
            ),
            (2000, SOURCE_PUSHED, Some(fp.as_str()))
        );
        // revocation-by-absence：批次缺行 = 删（只触本源行）。
        let r = store
            .apply_push_batch(
                &fp,
                dom,
                3,
                &[("dev-1".into(), "d1.example.com".into(), 2000, vec![1u8; 64])],
            )
            .await
            .unwrap();
        assert_eq!((r.applied, r.removed), (0, 1));
        assert!(store.get("dev-2", dom).await.unwrap().is_none());
        // 空批 = 全撤销态（合法声明式形态，§2.3）。
        let r = store
            .apply_push_batch(&fp, dom, 4, &[])
            .await
            .unwrap();
        assert_eq!(r.removed, 1);
        assert!(store.get("dev-1", dom).await.unwrap().is_none());

        // ── PK 本地权威遮蔽（manual 恒胜 pushed，与 ts 无关） ──
        let p2 = tmp_db("app_mask");
        let store2 = Arc::new(DirStore::open(&p2).unwrap());
        store2
            .upsert_manual(
                "dev-9",
                dom,
                "d9.example.com",
                "",
                "10.0.0.9",
                100,
                vec![9u8; 64],
                0,
                None,
            )
            .await
            .unwrap();
        let r = store2
            .apply_push_batch(
                &fp,
                dom,
                1,
                &[("dev-9".into(), "evil.example.com".into(), 9999, vec![9u8; 64])],
            )
            .await
            .unwrap();
        assert_eq!((r.applied, r.skipped), (0, 1), "manual 行遮蔽 pushed");
        let row = store2.get("dev-9", dom).await.unwrap().unwrap();
        assert_eq!(row.source.as_str(), SOURCE_MANUAL);
        assert_eq!(row.device_domain, "d9.example.com", "存量行零变化");

        // ── 跨源 P10 裁决（ts-LWW；ts 相等 fp 字典序小者胜） ──
        const FP_A: &str = "aa11:bb22:cc33:dd44:ee55:ff66:0011:2233:4455:6677:8899:aabb:ccdd:eeff:0011:2233";
        const FP_C: &str = "1111:2222:3333:4444:5555:6666:7777:8888:9999:0000:aaaa:bbbb:cccc:dddd:eeee:ffff";
        let p3 = tmp_db("app_xsrc");
        let store3 = Arc::new(DirStore::open(&p3).unwrap());
        store3
            .apply_push_batch(
                FP_A,
                dom,
                1,
                &[("dev-3".into(), "d3.example.com".into(), 100, vec![1u8; 64])],
            )
            .await
            .unwrap();
        let r = store3
            .apply_push_batch(
                FP_C,
                dom,
                1,
                &[("dev-3".into(), "d3.example.com".into(), 200, vec![2u8; 64])],
            )
            .await
            .unwrap();
        assert_eq!(r.applied, 1, "ts-LWW：新者胜");
        assert_eq!(
            store3
                .get("dev-3", dom)
                .await
                .unwrap()
                .unwrap()
                .source_fp
                .as_deref(),
            Some(FP_C)
        );
        // A 旧 ts 重推 = 裁决败 → 跳过（行保持 C 源）。
        let r = store3
            .apply_push_batch(
                FP_A,
                dom,
                2,
                &[("dev-3".into(), "d3.example.com".into(), 100, vec![1u8; 64])],
            )
            .await
            .unwrap();
        assert_eq!((r.applied, r.skipped), (0, 1));
        assert_eq!(
            store3
                .get("dev-3", dom)
                .await
                .unwrap()
                .unwrap()
                .source_fp
                .as_deref(),
            Some(FP_C)
        );
        // ts 相等 = fp 字典序小者胜（FP_C < FP_A；确定性）。
        let p4 = tmp_db("app_tie");
        let store4 = Arc::new(DirStore::open(&p4).unwrap());
        store4
            .apply_push_batch(
                FP_A,
                dom,
                1,
                &[("dev-4".into(), "d4.example.com".into(), 100, vec![1u8; 64])],
            )
            .await
            .unwrap();
        store4
            .apply_push_batch(
                FP_C,
                dom,
                1,
                &[("dev-4".into(), "d4.example.com".into(), 100, vec![2u8; 64])],
            )
            .await
            .unwrap();
        assert_eq!(
            store4
                .get("dev-4", dom)
                .await
                .unwrap()
                .unwrap()
                .source_fp
                .as_deref(),
            Some(FP_C),
            "ts 相等：fp 字典序小者胜"
        );
        let r = store4
            .apply_push_batch(
                FP_A,
                dom,
                2,
                &[("dev-4".into(), "d4.example.com".into(), 100, vec![1u8; 64])],
            )
            .await
            .unwrap();
        assert_eq!((r.applied, r.skipped), (0, 1));
        clean_db(&p1);
        clean_db(&p2);
        clean_db(&p3);
        clean_db(&p4);
    }

    // ── 清扫（T5 TTL / T8 liveness） ───────────────────────────────────

    #[tokio::test]
    async fn test_r140_3_ttl_sweep() {
        let p = tmp_db("ttl_b");
        let store = Arc::new(DirStore::open(&p).unwrap());
        let audit = Arc::new(CollectAudit::default());
        let svc = svc_for(
            store.clone(),
            Arc::new(test_key()),
            audit.clone(),
            "b.relay.example.com",
            EngineConfig::default(),
        );
        let key_a = test_key();
        let fp_a = fp_of_pubkey(&key_a.verifying_key().to_bytes());
        let key_c = test_key();
        let fp_c = fp_of_pubkey(&key_c.verifying_key().to_bytes());
        store
            .insert_pushed_test("dev-a", "b.relay.example.com", "da.example.com", &fp_a, 1000, vec![1u8; 64])
            .await
            .unwrap();
        store
            .insert_pushed_test("dev-c", "b.relay.example.com", "dc.example.com", &fp_c, 1000, vec![2u8; 64])
            .await
            .unwrap();
        store.set_meta(&format!("push:{fp_a}:last_epoch"), "5").await.unwrap();
        store.set_meta(&format!("push:{fp_a}:last_push"), "1").await.unwrap(); // 超龄
        let now = now_unix_secs();
        store.set_meta(&format!("push:{fp_c}:last_epoch"), "5").await.unwrap();
        store.set_meta(&format!("push:{fp_c}:last_push"), &now.to_string()).await.unwrap(); // 续约中
        svc.sweep_slow().await;
        assert!(
            store.get("dev-a", "b.relay.example.com").await.unwrap().is_none(),
            "超龄源行 = 清"
        );
        assert!(
            store.get_push_last_push(&fp_a).await.unwrap().is_none(),
            "超龄源水位键 = 清"
        );
        let row_c = store.get("dev-c", "b.relay.example.com").await.unwrap().unwrap();
        assert_eq!(row_c.source_fp.as_deref(), Some(fp_c.as_str()), "TTL 内源 = 保留");
        assert!(
            store.get_push_last_push(&fp_c).await.unwrap().is_some(),
            "TTL 内源水位 = 保留"
        );
        assert!(
            audit.events().iter().any(|e| matches!(
                e,
                TunnelAuditEvent::PushSourceExpired { fp, rows }
                    if fp == &fp_a && *rows == 1
            )),
            "push source expired 审计: {:?}",
            audit.events()
        );
        clean_db(&p);
    }

    #[tokio::test]
    async fn test_r140_3_liveness_sweep() {
        let p = tmp_db("lv_a");
        let store = Arc::new(DirStore::open(&p).unwrap());
        let audit = Arc::new(CollectAudit::default());
        let probe = FakeProbe::new(false);
        let probe_ref = Arc::clone(&probe); // 测试侧 set() 句柄（引擎持另一份）。
        let engine = EngineConfig {
            liveness: Some(probe),
            ..Default::default()
        };
        let svc = svc_for(
            store.clone(),
            Arc::new(test_key()),
            audit.clone(),
            "a.relay.example.com",
            engine,
        );
        // dev-x：自持行 + devlast 超龄 + 不在注册表 = 删行 + epoch+1 + 推撤销。
        let (used, enq) = store
            .upsert_manual("dev-x", "b.relay.example.com", "dx.example.com", "", "10.0.0.1", 1000, vec![9u8; 64], 0, None)
            .await
            .unwrap();
        assert_eq!((used, enq), (1, false));
        store.set_meta("devlast:dev-x", "1").await.unwrap();
        // 缺失 = skip 臂而非 DNS 败臂，本测改写前夹具）。
        store
            .ix_upsert_device_token("b.relay.example.com", IX_TEST_TOKEN, "dev-x", 1)
            .await
            .unwrap();
        let epoch_before = store.get_epoch().await.unwrap();
        svc.sweep_slow().await;
        assert!(store.get("dev-x", "b.relay.example.com").await.unwrap().is_none());
        assert!(
            store.get_epoch().await.unwrap() > epoch_before,
            "删行同事务 epoch+1"
        );
        // dev-y：同超龄但在注册表（探针 online = 瞬断）= 行保留。
        store
            .upsert_manual("dev-y", "b.relay.example.com", "dy.example.com", "", "10.0.0.1", 1000, vec![9u8; 64], 0, None)
            .await
            .unwrap();
        store.set_meta("devlast:dev-y", "1").await.unwrap();
        probe_ref.set(true);
        svc.sweep_slow().await;
        assert!(
            store.get("dev-y", "b.relay.example.com").await.unwrap().is_some(),
            "在线（注册表活体）= 行保留"
        );
        assert!(
            audit.events().iter().any(|e| matches!(
                e,
                TunnelAuditEvent::DirRowExpired { device_id, target_domain }
                    if device_id == "dev-x" && target_domain == "b.relay.example.com"
            )),
            "dir row expired 审计: {:?}",
            audit.events()
        );
        // 推撤销 = 立即重推（resolver 空 = 败）→ 失败同态审计 + outbox 入队。
        assert!(
            audit.events().iter().any(|e| matches!(
                e,
                TunnelAuditEvent::PushFailed { target_domain, reason, .. }
                    if target_domain == "b.relay.example.com" && reason.contains("SRV resolve failed")
            )),
            "推撤销失败同态（声明式幂等重试）: {:?}",
            audit.events()
        );
        // 探针未挂载 = 不跑 liveness 清扫（fail-safe 不删行）。
        let p2 = tmp_db("lv2_a");
        let store2 = Arc::new(DirStore::open(&p2).unwrap());
        let svc2 = svc_for(
            store2.clone(),
            Arc::new(test_key()),
            Arc::new(CollectAudit::default()),
            "a.relay.example.com",
            EngineConfig::default(),
        );
        store2
            .upsert_manual("dev-z", "b.relay.example.com", "dz.example.com", "", "10.0.0.1", 1000, vec![9u8; 64], 0, None)
            .await
            .unwrap();
        store2.set_meta("devlast:dev-z", "1").await.unwrap();
        svc2.sweep_slow().await;
        assert!(store2.get("dev-z", "b.relay.example.com").await.unwrap().is_some());
        clean_db(&p);
        clean_db(&p2);
    }

    // ── 双中继回环 e2e（A 添加 → B 可见 pushed 行；撤销 → 消失） ──────

    #[tokio::test]
    async fn test_r140_3_dual_relay_loopback_e2e() {
        // B 侧（接收方）：真监听器 + A 域 TXT 锚（TOFU 现场解析素材）。
        let pb = tmp_db("e2e_b");
        let store_b = Arc::new(DirStore::open(&pb).unwrap());
        let key_b = test_key();
        let vk_b = key_b.verifying_key();
        let fp_b = fp_of_pubkey(&vk_b.to_bytes());
        let audit_b = Arc::new(CollectAudit::default());
        let key_a = test_key();
        let vk_a = key_a.verifying_key();
        let fp_a = fp_of_pubkey(&vk_a.to_bytes());
        let svc_b = Arc::new(InterconnectService::new(
            store_b.clone(),
            Arc::new(key_b),
            audit_b.clone(),
            Arc::new(MockResolver::for_relay("a.relay.example.com", 1, &vk_a)),
            "b.relay.example.com",
            EngineConfig::default(),
        ));
        let (task_b, port_b) = start_serve(svc_b).await;
        // A 侧（推送方）：resolver 指 B 回环端口。
        let pa = tmp_db("e2e_a");
        let store_a = Arc::new(DirStore::open(&pa).unwrap());
        let audit_a = Arc::new(CollectAudit::default());
        let svc_a = Arc::new(InterconnectService::new(
            store_a.clone(),
            Arc::new(key_a),
            audit_a.clone(),
            Arc::new(MockResolver::for_relay("b.relay.example.com", port_b, &vk_b)),
            "a.relay.example.com",
            EngineConfig::default(),
        ));
        // ① DirUpsert（target ≠ 自域）→ 同事务 outbox 入队。
        // token → 门⑥命中受理；缺任一 = skip/拒，e2e 全链路在案）。
        store_a
            .ix_upsert_device_token("b.relay.example.com", IX_TEST_TOKEN, "dev-1", 1)
            .await
            .unwrap();
        store_b
            .ix_add_cli_token(IX_TEST_TOKEN, "e2e-b", 1)
            .await
            .unwrap();
        let (used, enq) = store_a
            .upsert_manual("dev-1", "b.relay.example.com", "d1.example.com", "note", "10.0.0.7", 1000, vec![3u8; 64], 0, Some("a.relay.example.com"))
            .await
            .unwrap();
        assert_eq!((used, enq), (1, true), "target ≠ 自域 = 同事务 outbox 入队");
        // 变更即推（触发面 = push_to + finish_push 单审计源）。
        let r = svc_a.push_to("b.relay.example.com").await;
        assert!(svc_a.finish_push("b.relay.example.com", r).await);
        tokio::time::sleep(Duration::from_millis(100)).await;
        // B 侧 pushed 行可见（source=pushed / source_fp=fp_a / 本域 target）。
        let row = store_b
            .get("dev-1", "b.relay.example.com")
            .await
            .unwrap()
            .expect("B 侧必须落 pushed 行");
        assert_eq!(
            (
                row.source.as_str(),
                row.source_fp.as_deref(),
                row.device_domain.as_str(),
                row.updated_at
            ),
            (SOURCE_PUSHED, Some(fp_a.as_str()), "d1.example.com", 1000)
        );
        // A 侧审计：push ok + outbox superseded 剪除（写入时入队的 1 行）。
        assert!(
            audit_a.events().iter().any(|e| matches!(
                e,
                TunnelAuditEvent::PushOk { target_domain, fp, entries, epoch }
                    if target_domain == "b.relay.example.com" && fp == &fp_b
                        && *entries == 1 && *epoch >= 1
            )),
            "push ok 审计: {:?}",
            audit_a.events()
        );
        assert!(
            audit_a.events().iter().any(|e| matches!(
                e,
                TunnelAuditEvent::PushOutboxPruned { target_domain, n, reason }
                    if target_domain == "b.relay.example.com" && *n == 1
                        && reason == "superseded"
            )),
            "superseded 剪除审计: {:?}",
            audit_a.events()
        );
        // B 侧审计：push applied。
        assert!(
            audit_b.events().iter().any(|e| matches!(
                e,
                TunnelAuditEvent::PushApplied { source_fp, entries, removed, .. }
                    if source_fp == &fp_a && *entries == 1 && *removed == 0
            )),
            "push applied 审计: {:?}",
            audit_b.events()
        );
        // ② ts 刷新 = 覆盖。
        store_a
            .upsert_manual("dev-1", "b.relay.example.com", "d1.example.com", "note", "10.0.0.7", 2000, vec![3u8; 64], 0, Some("a.relay.example.com"))
            .await
            .unwrap();
        let r = svc_a.push_to("b.relay.example.com").await;
        assert!(svc_a.finish_push("b.relay.example.com", r).await);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            store_b
                .get("dev-1", "b.relay.example.com")
                .await
                .unwrap()
                .unwrap()
                .updated_at,
            2000
        );
        // ③ DirDelete → 声明式缺行批次 → B 侧行消失（撤销 = 缺席）。
        let (deleted, _) = store_a
            .delete_manual("dev-1", "b.relay.example.com", Some("a.relay.example.com"))
            .await
            .unwrap();
        assert!(deleted);
        let r = svc_a.push_to("b.relay.example.com").await;
        assert!(svc_a.finish_push("b.relay.example.com", r).await);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(store_b.get("dev-1", "b.relay.example.com").await.unwrap().is_none());
        assert!(
            audit_b.events().iter().any(|e| matches!(
                e,
                TunnelAuditEvent::PushApplied { entries, removed, .. }
                    if *entries == 0 && *removed == 1
            )),
            "撤销批（空批 removed=1）审计: {:?}",
            audit_b.events()
        );
        task_b.abort();
        clean_db(&pb);
        clean_db(&pa);
    }

    // ── TOFU 不符 = 整批拒收（A 不可知；无 ACK 冻结语义） ──────────────

    #[tokio::test]
    async fn test_r140_3_tofu_mismatch_rejected_e2e() {
        let pb = tmp_db("tofu_b");
        let store_b = Arc::new(DirStore::open(&pb).unwrap());
        let key_b = test_key();
        let vk_b = key_b.verifying_key();
        let audit_b = Arc::new(CollectAudit::default());
        let evil = test_key(); // B 侧 TXT 锚 ≠ A 真实公钥（TOFU 不符）。
        let svc_b = Arc::new(InterconnectService::new(
            store_b.clone(),
            Arc::new(key_b),
            audit_b.clone(),
            Arc::new(MockResolver::for_relay("a.relay.example.com", 1, &evil.verifying_key())),
            "b.relay.example.com",
            EngineConfig::default(),
        ));
        let (task_b, port_b) = start_serve(svc_b).await;
        let key_a = test_key();
        let pa = tmp_db("tofu_a");
        let store_a = Arc::new(DirStore::open(&pa).unwrap());
        let audit_a = Arc::new(CollectAudit::default());
        let svc_a = Arc::new(InterconnectService::new(
            store_a.clone(),
            Arc::new(key_a),
            audit_a.clone(),
            Arc::new(MockResolver::for_relay("b.relay.example.com", port_b, &vk_b)),
            "a.relay.example.com",
            EngineConfig::default(),
        ));
        store_a
            .upsert_manual("dev-1", "b.relay.example.com", "d1.example.com", "", "10.0.0.7", 1000, vec![3u8; 64], 0, Some("a.relay.example.com"))
            .await
            .unwrap();
        // TOFU 门在门⑥之前，B 侧 cli 行可不登记）。
        store_a
            .ix_upsert_device_token("b.relay.example.com", IX_TEST_TOKEN, "dev-1", 1)
            .await
            .unwrap();
        // A 侧口径 = 帧写完成（无 ACK 冻结）：B 侧拒收对 A 不可见。
        let r = svc_a.push_to("b.relay.example.com").await;
        assert!(
            svc_a.finish_push("b.relay.example.com", r).await,
            "A 侧成功判据 = 帧写完成"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
        // B 侧：TOFU 不符 = 整批拒收 + push rejected 审计 + 本地表零变化。
        assert!(
            audit_b.events().iter().any(|e| matches!(
                e,
                TunnelAuditEvent::PushRejected { peer_domain, reason, .. }
                    if peer_domain == "a.relay.example.com" && reason.contains("TOFU")
            )),
            "TOFU 拒收审计: {:?}",
            audit_b.events()
        );
        assert_eq!(store_b.count().await.unwrap(), 0, "fail-closed 零变化");
        task_b.abort();
        clean_db(&pb);
        clean_db(&pa);
    }

    // ── 离线补推（T4：退避登记 → 对端上线 → sweep 补推 → superseded） ─

    #[tokio::test]
    async fn test_r140_3_offline_catchup_push() {
        // 死端口（bind 后 drop = connect refused 快败，无 15s 握手超时）。
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let pa = tmp_db("off_a");
        let store_a = Arc::new(DirStore::open(&pa).unwrap());
        let key_a = test_key();
        let vk_a = key_a.verifying_key();
        let audit_a = Arc::new(CollectAudit::default());
        let key_c = test_key();
        let svc_a = Arc::new(InterconnectService::new(
            store_a.clone(),
            Arc::new(key_a),
            audit_a.clone(),
            Arc::new(MockResolver::for_relay("c.relay.example.com", dead_port, &key_c.verifying_key())),
            "a.relay.example.com",
            EngineConfig::default(),
        ));
        let (used, enq) = store_a
            .upsert_manual("dev-1", "c.relay.example.com", "d1.example.com", "", "10.0.0.7", 1000, vec![3u8; 64], 0, Some("a.relay.example.com"))
            .await
            .unwrap();
        assert_eq!((used, enq), (1, true));
        // 缺失 = skip 而非 connect failed，本测改写前夹具）。
        store_a
            .ix_upsert_device_token("c.relay.example.com", IX_TEST_TOKEN, "dev-1", 1)
            .await
            .unwrap();
        // 即时推败（connect refused）→ 退避登记（attempts 1，+30s）。
        let r = svc_a.push_to("c.relay.example.com").await;
        assert!(!svc_a.finish_push("c.relay.example.com", r).await);
        let now = now_unix_secs();
        assert!(
            audit_a.events().iter().any(|e| matches!(
                e,
                TunnelAuditEvent::PushFailed { target_domain, reason, .. }
                    if target_domain == "c.relay.example.com"
                        && reason.contains("connect failed")
            )),
            "push failed 审计: {:?}",
            audit_a.events()
        );
        assert!(
            store_a.outbox_due(now).await.unwrap().is_empty(),
            "退避 30s 内不重推"
        );
        let due = store_a.outbox_due(now + 60).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].attempts, 1, "T4 退避态：首败 = attempts 1");
        // C 上线（同端口）→ 强制到期 → sweep_outbox 补推成功。
        let pc = tmp_db("off_c");
        let store_c = Arc::new(DirStore::open(&pc).unwrap());
        store_c
            .ix_add_cli_token(IX_TEST_TOKEN, "e2e-c", 1)
            .await
            .unwrap();
        let audit_c = Arc::new(CollectAudit::default());
        let svc_c = Arc::new(InterconnectService::new(
            store_c.clone(),
            Arc::new(key_c),
            audit_c.clone(),
            Arc::new(MockResolver::for_relay("a.relay.example.com", 1, &vk_a)),
            "c.relay.example.com",
            EngineConfig::default(),
        ));
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), dead_port))
            .await
            .unwrap();
        let task_c = tokio::spawn({
            let svc = Arc::clone(&svc_c);
            async move {
                svc.serve_listeners(vec![("c".to_string(), listener)])
                    .await;
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        store_a
            .outbox_force_next_retry_test("c.relay.example.com", now_unix_secs())
            .await
            .unwrap();
        svc_a.sweep_outbox().await;
        // 无 ACK 冻结口径：A 帧写完成即交付；C 侧 handle_conn 异步应用
        // （解密 + TXT 现场解析 + 单事务落库）→ 小睡兜底对账。
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            store_a.outbox_due(i64::MAX as u64).await.unwrap().is_empty(),
            "成功推送 = outbox superseded 剪除"
        );
        assert!(
            audit_a.events().iter().any(|e| matches!(
                e,
                TunnelAuditEvent::PushOk { target_domain, .. }
                    if target_domain == "c.relay.example.com"
            ))
        );
        assert!(
            audit_a.events().iter().any(|e| matches!(
                e,
                TunnelAuditEvent::PushOutboxPruned { target_domain, reason, .. }
                    if target_domain == "c.relay.example.com" && reason == "superseded"
            ))
        );
        assert_eq!(store_c.count().await.unwrap(), 1, "离线补推后 C 侧落行");
        assert!(
            audit_c.events().iter().any(|e| matches!(
                e,
                TunnelAuditEvent::PushApplied { entries, .. } if *entries == 1
            ))
        );
        task_c.abort();
        clean_db(&pa);
        clean_db(&pc);
    }

    // ── 废帧保留位（0x02/0x03/0x90~0x94）= 结构校验 + 丢弃 + 审计 ─────

    #[tokio::test]
    async fn test_r140_3_deprecated_frames_structure_dropped() {
        let pb = tmp_db("dep_b");
        let store_b = Arc::new(DirStore::open(&pb).unwrap());
        let audit_b = Arc::new(CollectAudit::default());
        let svc_b = Arc::new(InterconnectService::new(
            store_b.clone(),
            Arc::new(test_key()),
            audit_b.clone(),
            Arc::new(MockResolver::default()),
            "b.relay.example.com",
            EngineConfig::default(),
        ));
        let (task_b, port) = start_serve(svc_b).await;
        let key_a = test_key();
        for ty in [0x02u8, 0x03, 0x90, 0x94] {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let cipher = client_handshake(&mut stream, &key_a, "a.relay.example.com")
                .await
                .unwrap();
            let body = aead_frame_body(&cipher, ty, b"legacy-payload").unwrap();
            write_frame(&mut stream, ty, &body).await.unwrap();
            drop(stream);
            tokio::time::sleep(Duration::from_millis(80)).await;
            assert!(
                audit_b.events().iter().any(|e| matches!(
                    e,
                    TunnelAuditEvent::InterconnectRejected { reason, .. }
                        if reason.contains(&format!("0x{ty:02x}"))
                )),
                "废帧 0x{ty:02x} 必须结构校验 + 审计: {:?}",
                audit_b.events()
            );
        }
        assert_eq!(store_b.count().await.unwrap(), 0, "废帧不解析不落表");
        task_b.abort();
        clean_db(&pb);
    }

    // ── push_all_once 多 target（单 target 败不影响其余） ──────────────

    #[tokio::test]
    async fn test_r140_3_push_all_once_multi_target() {
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let key_a = test_key();
        let vk_a = key_a.verifying_key();
        let key_b = test_key();
        let vk_b = key_b.verifying_key();
        let key_c = test_key();
        let pb = tmp_db("pm_b");
        let store_b = Arc::new(DirStore::open(&pb).unwrap());
        let svc_b = Arc::new(InterconnectService::new(
            store_b.clone(),
            Arc::new(key_b),
            Arc::new(CollectAudit::default()),
            Arc::new(MockResolver::for_relay("a.relay.example.com", 1, &vk_a)),
            "b.relay.example.com",
            EngineConfig::default(),
        ));
        let (task_b, port_b) = start_serve(svc_b).await;
        let pa = tmp_db("pm_a");
        let store_a = Arc::new(DirStore::open(&pa).unwrap());
        let audit_a = Arc::new(CollectAudit::default());
        let svc_a = Arc::new(InterconnectService::new(
            store_a.clone(),
            Arc::new(key_a),
            audit_a.clone(),
            Arc::new(
                MockResolver::default().for_relays(&[
                    ("b.relay.example.com".to_string(), port_b, &vk_b),
                    ("c.relay.example.com".to_string(), dead_port, &key_c.verifying_key()),
                ])
            ),
            "a.relay.example.com",
            EngineConfig::default(),
        ));
        store_a
            .upsert_manual("dev-1", "b.relay.example.com", "d1.example.com", "", "10.0.0.7", 1000, vec![1u8; 64], 0, Some("a.relay.example.com"))
            .await
            .unwrap();
        store_a
            .upsert_manual("dev-2", "c.relay.example.com", "d2.example.com", "", "10.0.0.7", 1000, vec![2u8; 64], 0, Some("a.relay.example.com"))
            .await
            .unwrap();
        // （b 成功 / c 死端口 connect failed 两态都要真发起连接）。
        store_a
            .ix_upsert_device_token("b.relay.example.com", IX_TEST_TOKEN, "dev-1", 1)
            .await
            .unwrap();
        store_a
            .ix_upsert_device_token("c.relay.example.com", IX_TEST_TOKEN_B, "dev-2", 1)
            .await
            .unwrap();
        store_b
            .ix_add_cli_token(IX_TEST_TOKEN, "e2e-b", 1)
            .await
            .unwrap();
        let ok = svc_a.push_all_once().await;
        assert_eq!(ok, 1, "b 成功 / c 败（单 target 败不影响其余）");
        assert!(
            store_b.get("dev-1", "b.relay.example.com").await.unwrap().is_some(),
            "B 侧落行"
        );
        assert!(
            audit_a.events().iter().any(|e| matches!(
                e,
                TunnelAuditEvent::PushOk { target_domain, .. }
                    if target_domain == "b.relay.example.com"
            ))
        );
        assert!(
            audit_a.events().iter().any(|e| matches!(
                e,
                TunnelAuditEvent::PushFailed { target_domain, .. }
                    if target_domain == "c.relay.example.com"
            ))
        );
        // b 的 outbox 行 superseded 剪除；c 的行留队（退避登记）。
        let due = store_a.outbox_due(i64::MAX as u64).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].target_domain, "c.relay.example.com");
        task_b.abort();
        clean_db(&pb);
        clean_db(&pa);
    }

    // socket）+ 版本受理裁决 + 宽限路径 + A 侧跳过 + decode 兜底回归 ──

    #[test]
    fn test_r168_version_admission_matrix() {
        // /3 = Current（宽限开关取值无关）。
        assert_eq!(
            version_admission(INTERCONNECT_VERSION, false),
            Ok(IxVersionAdmission::Current)
        );
        assert_eq!(
            version_admission(INTERCONNECT_VERSION, true),
            Ok(IxVersionAdmission::Current)
        );
        // /2：宽限 off（默认）= 拒 + reason=legacy_no_token（矩阵⑥）；on =
        // LegacyGrace（矩阵⑤）。
        assert_eq!(
            version_admission(INTERCONNECT_VERSION_LEGACY, false),
            Err("legacy_no_token".to_string())
        );
        assert_eq!(
            version_admission(INTERCONNECT_VERSION_LEGACY, true),
            Ok(IxVersionAdmission::LegacyGrace)
        );
        // 其余串（v1 / 垃圾）= 版本不符拒连。
        assert_eq!(
            version_admission("RELAY-DIR/1", false),
            Err("version mismatch (expected RELAY-DIR/3)".to_string())
        );
        assert_eq!(
            version_admission("RELAY-DIR/1", true),
            Err("version mismatch (expected RELAY-DIR/3)".to_string())
        );
        // 默认 fail-closed：EngineConfig::default().legacy_grace == false。
        assert!(!EngineConfig::default().legacy_grace);
    }

    /// 门⑥矩阵①②③④⑧（token 命中/不匹配/缺 token/已撤销/多活跃任一命中）。
    #[tokio::test]
    async fn test_r168_gate6_token_matrix() {
        let p = tmp_db("g6");
        let store = Arc::new(DirStore::open(&p).unwrap());
        let key_b = Arc::new(test_key());
        let vk_b = key_b.verifying_key();
        let fp_b = fp_of_pubkey(&vk_b.to_bytes());
        let audit = Arc::new(CollectAudit::default());
        let svc = svc_for(
            store.clone(),
            Arc::clone(&key_b),
            audit.clone(),
            "b.relay.example.com",
            EngineConfig::default(),
        );
        let key_a = test_key();
        let vk_a = key_a.verifying_key();

        // ③ `/3` 帧缺 ix_token（空串）= 拒（store 零变化）。
        let mut p_missing = make_batch(&key_a, 1, &fp_b, &fp_b, &[("dev-1", "d1.example.com", 1000)]);
        p_missing.ix_token = String::new();
        let e = svc
            .verify_and_apply_push(&p_missing, &vk_a, &fp_b)
            .await
            .unwrap_err();
        assert!(e.contains("ix_token missing"), "{e}");
        assert_eq!(store.count().await.unwrap(), 0, "整批拒收 = 本地表零变化");

        // ② token 不匹配 = 整批拒 + reason 口径（audit 由 handle_conn Push
        // 臂统一发射，reason 串在此钉死）。
        let p_wrong = {
            let mut b = make_batch(&key_a, 1, &fp_b, &fp_b, &[("dev-1", "d1.example.com", 1000)]);
            b.ix_token = "no-such-registered-token".to_string();
            b
        };
        let e = svc
            .verify_and_apply_push(&p_wrong, &vk_a, &fp_b)
            .await
            .unwrap_err();
        assert!(e.contains("ix_token mismatch"), "{e}");
        assert_eq!(store.count().await.unwrap(), 0);

        // ① B 有活跃 token + 推送携同 token = 受理（条目落库）。
        store.ix_add_cli_token(IX_TEST_TOKEN, "admin-of-b", 1).await.unwrap();
        let p_ok = make_batch(&key_a, 1, &fp_b, &fp_b, &[("dev-1", "d1.example.com", 1000)]);
        let r = svc.verify_and_apply_push(&p_ok, &vk_a, &fp_b).await.unwrap();
        assert_eq!((r.entries_in, r.applied, r.removed), (1, 1, 0));
        assert_eq!(store.count().await.unwrap(), 1);

        // ④ revoked token = 拒（撤销即时生效 = 下次推送被拒）。
        let row = store.ix_list_tokens().await.unwrap().remove(0);
        assert!(store.ix_revoke_token(row.id, 99).await.unwrap());
        let p_revoked = make_batch(&key_a, 2, &fp_b, &fp_b, &[("dev-1", "d1.example.com", 2000)]);
        let e = svc
            .verify_and_apply_push(&p_revoked, &vk_a, &fp_b)
            .await
            .unwrap_err();
        assert!(e.contains("ix_token revoked"), "{e}");
        assert_eq!(store.count().await.unwrap(), 1, "拒收 = 零变化（既有行保留）");

        // ⑧ 多活跃 token 命中任一 = 受理。
        store.ix_add_cli_token("second-active-token-xyz", "peer-admin", 2).await.unwrap();
        let p_second = {
            let mut b = make_batch(&key_a, 3, &fp_b, &fp_b, &[("dev-1", "d1.example.com", 3000)]);
            b.ix_token = "second-active-token-xyz".to_string();
            b
        };
        let r = svc.verify_and_apply_push(&p_second, &vk_a, &fp_b).await.unwrap();
        assert_eq!(r.applied, 1);
        clean_db(&p);
    }

    /// 门⑥矩阵⑦：对向推送（B→A）校验 A 自己的表——A 只认 A 自己登记的
    /// cli 行，B 侧 token 对 A 零意义（每中继只校验「推给自己」的 token）。
    #[tokio::test]
    async fn test_r168_gate6_reverse_direction_uses_own_table() {
        let pa = tmp_db("g6_a");
        let store_a = Arc::new(DirStore::open(&pa).unwrap());
        let key_a = Arc::new(test_key());
        let audit_a = Arc::new(CollectAudit::default());
        let svc_a = svc_for(
            store_a.clone(),
            Arc::clone(&key_a),
            audit_a.clone(),
            "a.relay.example.com",
            EngineConfig::default(),
        );
        let key_b = test_key();
        let vk_b = key_b.verifying_key();
        let fp_a = fp_of_pubkey(&key_a.verifying_key().to_bytes());
        // A 自己的表：登记 A_TOKEN；B_TOKEN（B 侧权威）对 A = 未知串。
        store_a.ix_add_cli_token("a-own-token-aaaa", "admin-of-a", 1).await.unwrap();
        // B 以 B_TOKEN 推 A（无 ACK；此处直接数据路径）= 拒。
        let p_b2a = {
            let mut b = make_batch(&key_b, 1, &fp_a, &fp_a, &[("dev-9", "d9.example.com", 1000)]);
            b.ix_token = IX_TEST_TOKEN.to_string();
            b
        };
        let e = svc_a
            .verify_and_apply_push(&p_b2a, &vk_b, &fp_a)
            .await
            .unwrap_err();
        assert!(e.contains("ix_token mismatch"), "{e}");
        assert_eq!(store_a.count().await.unwrap(), 0);
        // B 以 A_TOKEN 推 A = 受理（对称执法：A 校验自己的表）。
        let mut p_b2a_ok = make_batch(&key_b, 1, &fp_a, &fp_a, &[("dev-9", "d9.example.com", 1000)]);
        p_b2a_ok.ix_token = "a-own-token-aaaa".to_string();
        let r = svc_a
            .verify_and_apply_push(&p_b2a_ok, &vk_b, &fp_a)
            .await
            .unwrap();
        assert_eq!(r.applied, 1);
        clean_db(&pa);
    }

    /// 门⑥矩阵⑤⑥：宽限开关两态对旧 `/2` 3 字段推送（数据路径等价覆盖，
    /// 禁 socket——wire 解码 + 五门受理 / 版本门拒双臂）。
    #[tokio::test]
    async fn test_r168_legacy_grace_two_states() {
        let key_b = Arc::new(test_key());
        let vk_b = key_b.verifying_key();
        let fp_b = fp_of_pubkey(&vk_b.to_bytes());
        let key_a = test_key();
        let vk_a = key_a.verifying_key();
        // 旧 build 推送帧 = 3 字段 IxPushLegacy（epoch/entries/batch_sig）。
        let legacy_bytes = {
            let entries = vec![PushEntry {
                device_id: "dev-1".into(),
                domain: "d1.example.com".into(),
                updated_at: 1000,
                sig: key_a
                    .sign(&entry_sig_message_v2("dev-1", "d1.example.com", 1000, &fp_b))
                    .to_bytes()
                    .to_vec(),
            }];
            let batch = vec![PushEntry {
                device_id: "dev-1".into(),
                domain: "d1.example.com".into(),
                updated_at: 1000,
                sig: entries[0].sig.clone(),
            }];
            bincode::serialize(&IxPushLegacy {
                epoch: 1,
                entries: batch,
                batch_sig: key_a
                    .sign(&batch_sig_message_v2(1, &fp_b, &entries))
                    .to_bytes()
                    .to_vec(),
            })
            .unwrap()
        };
        // ⑤ 宽限 on：旧帧经 legacy 解码 → 五门受理（无 token 门）。
        {
            let p = tmp_db("g6_legacy_on");
            let store = Arc::new(DirStore::open(&p).unwrap());
            let audit = Arc::new(CollectAudit::default());
            let svc = svc_for(
                store.clone(),
                Arc::clone(&key_b),
                audit.clone(),
                "b.relay.example.com",
                EngineConfig {
                    legacy_grace: true,
                    ..Default::default()
                },
            );
            let old = decode_ix_push(&legacy_bytes, true).expect("legacy decode");
            assert!(old.ix_token.is_empty(), "legacy 帧无 token 字段");
            let r = svc
                .verify_and_apply_push_gated(&old, &vk_a, &fp_b, false)
                .await
                .unwrap();
            assert_eq!((r.entries_in, r.applied), (1, 1));
            clean_db(&p);
        }
        // ⑥ 宽限 off（默认）：版本门即拒 + reason=legacy_no_token（审计行
        // 由 handle_conn Handshake 臂发射，reason 串矩阵钉死）。
        {
            let p = tmp_db("g6_legacy_off");
            let store = Arc::new(DirStore::open(&p).unwrap());
            let audit = Arc::new(CollectAudit::default());
            let svc = svc_for(
                store.clone(),
                Arc::clone(&key_b),
                audit.clone(),
                "b.relay.example.com",
                EngineConfig::default(),
            );
            let e = version_admission(INTERCONNECT_VERSION_LEGACY, svc.engine.legacy_grace)
                .unwrap_err();
            assert_eq!(e, "legacy_no_token");
            // fail-closed：本地表零变化 + 零受理审计。
            assert_eq!(store.count().await.unwrap(), 0);
            assert!(audit.events().iter().all(|e| !matches!(
                e,
                TunnelAuditEvent::PushApplied { .. }
            )));
            clean_db(&p);
        }
    }

    /// 门⑥矩阵⑨：A 侧无 device token 的 target = 跳过推送 + WARN 审计
    /// （fail-closed 不推裸批；outbox 零触碰）。
    #[tokio::test]
    async fn test_r168_push_skipped_without_device_token() {
        let pa = tmp_db("g6_skip_a");
        let store_a = Arc::new(DirStore::open(&pa).unwrap());
        let key_a = Arc::new(test_key());
        let audit_a = Arc::new(CollectAudit::default());
        // resolver 未配 target 三件套：若误发推送会先败 DNS（区分面）；
        // 跳过判定在解析之前 = 本测恒走 skip 臂。
        let svc_a = svc_for(
            store_a.clone(),
            Arc::clone(&key_a),
            audit_a.clone(),
            "a.relay.example.com",
            EngineConfig::default(),
        );
        store_a
            .upsert_manual("dev-1", "b.relay.example.com", "d1.example.com", "", "10.0.0.7", 1000, vec![3u8; 64], 0, Some("a.relay.example.com"))
            .await
            .unwrap();
        // upsert 自身入队的 outbox 基线（skip 判据 = skip 不改队列态）。
        let outbox_before = store_a.outbox_due(now_unix_secs() + 3600).await.unwrap();
        assert_eq!(outbox_before.len(), 1, "upsert 同事务入队基线");
        // 无 ix_upsert_device_token = 无转发凭证。
        let r = svc_a.push_to("b.relay.example.com").await;
        assert!(r.is_err(), "无 token = 不推送（skip 臂）");
        assert!(!svc_a.finish_push("b.relay.example.com", r).await);
        // WARN 审计行（PushSkippedNoToken）在案 + reason 口径钉死。
        assert!(
            audit_a.events().iter().any(|e| matches!(
                e,
                TunnelAuditEvent::PushSkippedNoToken { target_domain, reason }
                    if target_domain == "b.relay.example.com"
                        && reason.contains("no ix_token")
            )),
            "skip 审计: {:?}",
            audit_a.events()
        );
        // outbox 零触碰（skip ≠ 失败：行原样留队，attempts 不增、不重排）。
        let outbox_after = store_a.outbox_due(now_unix_secs() + 3600).await.unwrap();
        assert_eq!(
            outbox_after.len(), outbox_before.len(),
            "skip 不得新增/剪除 outbox 行"
        );
        assert_eq!(outbox_after[0].attempts, outbox_before[0].attempts, "skip 不累计 attempts");
        clean_db(&pa);
    }

    /// 门⑥矩阵⑩：DirUpsert decode 兜底回归（新 5 字段先试 / 旧 4 字段
    /// 回退 / v1 3 字段必败）。
    #[test]
    fn test_r168_dir_upsert_decode_fallback() {
        use kirin_desk_relay::protocol::DirUpsert;
        let new5 = DirUpsert {
            device_id: "dev-1".into(),
            domain: "d1.example.com".into(),
            target_domain: "b.relay.example.com".into(),
            note: Some("n".into()),
            ix_token: "form-token-xyz".into(),
        };
        let bytes5 = bincode::serialize(&new5).unwrap();
        let got = crate::dir_backend::decode_dir_upsert_flex(&bytes5).unwrap();
        assert_eq!(got, new5);
        assert_eq!(got.ix_token, "form-token-xyz");
        #[derive(serde::Serialize)]
        struct Old4 {
            device_id: String,
            domain: String,
            target_domain: String,
            note: Option<String>,
        }
        let old4 = bincode::serialize(&Old4 {
            device_id: "dev-1".into(),
            domain: "d1.example.com".into(),
            target_domain: "b.relay.example.com".into(),
            note: None,
        })
        .unwrap();
        let got = crate::dir_backend::decode_dir_upsert_flex(&old4).unwrap();
        assert_eq!(got.device_id, "dev-1");
        assert!(got.ix_token.is_empty(), "旧帧 token = 空 = 不更新凭证缓存");
        #[derive(serde::Serialize)]
        struct V1 {
            device_id: String,
            domain: String,
            note: Option<String>,
        }
        let v1 = bincode::serialize(&V1 {
            device_id: "dev-1".into(),
            domain: "d1.example.com".into(),
            note: None,
        })
        .unwrap();
        assert!(crate::dir_backend::decode_dir_upsert_flex(&v1).is_none());
    }


    #[test]
    fn test_r201_legacy_grace_expiry_matrix() {
        use super::{
            version_admission, version_admission_at, IxVersionAdmission,
            INTERCONNECT_VERSION, INTERCONNECT_VERSION_LEGACY,
        };
        let now = now_unix_secs();
        // ① `/3` 恒受理（与宽限态无关）。
        assert_eq!(
            version_admission_at(INTERCONNECT_VERSION, false, Some(now), now),
            Ok(IxVersionAdmission::Current)
        );
        // ② off（默认）= 恒拒 legacy_no_token（无 until 语义）。
        for (grace, until, now_) in [
            (false, None, now),
            (false, Some(now + 3600), now),
            (false, Some(now - 60), now),
        ] {
            let e = version_admission_at(INTERCONNECT_VERSION_LEGACY, grace, until, now_)
                .unwrap_err();
            assert_eq!(e, "legacy_no_token", "off 臂逐位不变");
        }
        // ③ on 无界（纯手工形态）= 宽限受理。
        assert_eq!(
            version_admission_at(INTERCONNECT_VERSION_LEGACY, true, None, now),
            Ok(IxVersionAdmission::LegacyGrace)
        );
        // ④ on 有界：期内 = 受理；**等界 = 已到期拒**；过点 = 拒。
        let until = now + 3600;
        assert_eq!(
            version_admission_at(INTERCONNECT_VERSION_LEGACY, true, Some(until), now),
            Ok(IxVersionAdmission::LegacyGrace)
        );
        let e_eq = version_admission_at(INTERCONNECT_VERSION_LEGACY, true, Some(until), until)
            .unwrap_err();
        assert!(e_eq.contains("expired"), "{e_eq}");
        let e_late = version_admission_at(INTERCONNECT_VERSION_LEGACY, true, Some(until), until + 1)
            .unwrap_err();
        assert!(e_late.contains("expired"), "{e_late}");
        assert_eq!(
            version_admission(INTERCONNECT_VERSION_LEGACY, true),
            Ok(IxVersionAdmission::LegacyGrace)
        );
        assert_eq!(
            version_admission(INTERCONNECT_VERSION_LEGACY, false).unwrap_err(),
            "legacy_no_token"
        );
        assert!(version_admission("RELAY-DIR/1", false).unwrap_err().contains("version mismatch"));
    }

    #[test]
    fn test_r201_grace_expired_reason_matrix() {
        use super::legacy_grace_expired_reason;
        let now = now_unix_secs();
        let until = now + 3600;
        // 到期臂（on + 有界 + 过点/等界）= Some（含 expired + ts 钉死）。
        assert_eq!(
            legacy_grace_expired_reason(true, Some(until), until),
            Some(format!("legacy_no_token (grace expired at unix {until})"))
        );
        assert_eq!(
            legacy_grace_expired_reason(true, Some(until), until + 42),
            Some(format!("legacy_no_token (grace expired at unix {until})"))
        );
        // 期内 / 无界 / off = None（调用方沿用既有 legacy_no_token 逐位不变）。
        assert_eq!(legacy_grace_expired_reason(true, Some(until), now), None);
        assert_eq!(legacy_grace_expired_reason(true, None, now), None);
        assert_eq!(legacy_grace_expired_reason(false, Some(until), until + 42), None);
        assert_eq!(legacy_grace_expired_reason(false, None, now), None);
    }

    /// 审计 reason 含 `expired` + 本地表零受理。
    #[tokio::test]
    async fn test_r201_grace_expired_legacy_handshake_rejected_audits_expired() {
        use super::{EphemeralSession, IxHello};
        use std::io::ErrorKind as IoKind;
        use kirin_desk_relay::audit::TunnelAuditEvent::InterconnectRejected;
        let p = tmp_db("r201_expired_b");
        let store_b = Arc::new(DirStore::open(&p).unwrap());
        let key_b = Arc::new(test_key());
        let audit_b = Arc::new(CollectAudit::default());
        let svc_b = svc_for(
            store_b.clone(),
            Arc::clone(&key_b),
            audit_b.clone(),
            "b.relay.example.com",
            EngineConfig {
                // 已过去时刻的显式到期界（「到期时刻已在过去」形态）。
                legacy_grace: true,
                legacy_grace_until: Some(1),
                ..Default::default()
            },
        );
        let (task, port) = start_serve(svc_b).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let key_a = test_key();
        let eph_a = EphemeralSession::new();
        let mut nonce_a = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce_a);
        let id_pub_a = key_a.verifying_key().to_bytes();
        // 旧 `/2` HELLO（签名覆盖域 = 对端自报版本串，与 handle_conn 对称）。
        let hello = IxHello {
            ver: INTERCONNECT_VERSION_LEGACY.to_string(),
            nonce: nonce_a,
            eph_pub: eph_a.public_key_bytes(),
            id_pub: id_pub_a,
            id_domain: "a.relay.example.com".to_string(),
            sig: key_a
                .sign(&hello_sig_message(
                    INTERCONNECT_VERSION_LEGACY,
                    &nonce_a,
                    &id_pub_a,
                    "a.relay.example.com",
                ))
                .to_bytes()
                .to_vec(),
        };
        write_frame(&mut stream, IX_FRAME_HELLO, &bincode::serialize(&hello).unwrap())
            .await
            .unwrap();
        // 断连：版本门在回 HelloB 之前即拒（读帧必败/超时/EOF）。
        let r = timeout(Duration::from_secs(10), read_frame(&mut stream, IX_MAX_FRAME_LEN)).await;
        let rejected = match r {
            Ok(Ok((_ty, _body))) => {
                panic!("到期臂不应回任何 HELLO 帧（版本门先于回帧）")
            }
            Ok(Err(e)) => matches!(e.kind(), IoKind::UnexpectedEof | IoKind::TimedOut),
            Err(_t) => false,
        };
        assert!(rejected, "到期后旧 /2 HELLO 必须断连");
        // 审计：InterconnectRejected reason 含 expired（「到期自动收紧」可辨）。
        let evts = audit_b.events();
        let rej: Vec<&TunnelAuditEvent> = evts
            .iter()
            .filter(|e| matches!(
                e,
                InterconnectRejected { .. }
            ))
            .collect();
        assert_eq!(rej.len(), 1, "恰好一行拒绝审计: {evts:?}");
        if let InterconnectRejected { reason, .. } = rej[0] {
            assert!(reason.contains("expired"), "{reason}");
            assert!(reason.contains("grace expired at unix 1"), "{reason}");
            assert!(reason.starts_with("legacy_no_token"), "{reason}");
        }
        // 本地表零受理。
        assert_eq!(store_b.count().await.unwrap(), 0);
        let _ = stream.shutdown().await;
        task.abort();
        clean_db(&p);
    }
}
