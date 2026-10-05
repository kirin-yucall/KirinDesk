//! 服务端共享策略层（SEC-PATCH / SRV-SEC-KH-001）—— CLI serve / shell 服务器
//! 与 GUI 服务器共用的握手策略：
//!
//! 1. **客户端公钥解析**（[`resolve_expected_client_key`]）：known_hosts 优先 →
//!    DNS TXT 兜底（当前激活 DNS 服务商；设备域为 `[godaddy] domain`，未配置
//!    则跳过）→ 未知走白名单/审批；
//! 2. **完整两阶段握手**（[`server_accept_handshake`]）：预读 init → 公钥解析与
//!    pin → 白名单（temp 可绕过）→ 校验 → 应答，服务端**不再信任网络上来的
//!    自报公钥**（对称于客户端 known_hosts/DNS-TXT 绑定）。

use kirin_desk_core::connection::temp_mode::TempModeManager;
use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_core::crypto::handshake::{
    domain_matches_whitelist, handshake_error_reject_code, id_matches_whitelist,
    id_whitelist_enforce_violation, negotiate_codec_by_server_priority, send_handshake_reject,
    server_handshake_respond_generic, server_read_init, verify_server_init_with_temp,
    HandshakeError, SecureChannel, VerifiedDecision, REJECT_CODE_APPROVAL_DECLINED,
    REJECT_CODE_CHALLENGE_MISMATCH, REJECT_CODE_CREDENTIALS_REQUIRED, REJECT_CODE_ID_WHITELIST,
    REJECT_CODE_UNATTENDED_UNKNOWN,
};
use kirin_desk_dns::txt::TxtManager;
use kirin_desk_utils::config::Config;
use kirin_desk_utils::known_hosts::KnownClientsStore;
// (P6): 连接失败引导提示（用户可见，拼入连接状态与日志）走 t!()。
use crate::t;
use std::time::Duration;

/// 客户端公钥解析来源（供审计/日志区分信任路径）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKeyResolution {
    /// known_hosts 命中（本地已信任客户端）。
    KnownHosts,
    /// DNS TXT 兜底命中（设备注册公钥）。
    DnsTxt,
    /// 未知 → 走白名单/审批（首次连接场景）。
    Unknown,
}

/// 解析期望的客户端公钥（SRV-SEC-KH-001）。
///
/// - `known_hosts` 命中 → 直接返回记录公钥（调用方用 [`verify_server_init`] pin，
///   不一致即拒绝）；
/// - 未命中 → DNS TXT 兜底（`{client_id}.{domain}` TXT 记录的 Ed25519 公钥，
///   经当前激活 DNS 服务商查询；设备域为 `[godaddy] domain`，未配置或查询
///   失败则跳过）；
/// - 都未命中 → `None`，由白名单/审批流程决定。
pub async fn resolve_expected_client_key(
    known: &KnownClientsStore,
    cfg: &Config,
    client_id: &str,
) -> (Option<String>, ClientKeyResolution) {
    if let Some(kc) = known.lookup(client_id) {
        return (
            Some(kc.public_key_base64.clone()),
            ClientKeyResolution::KnownHosts,
        );
    }

    // M9-DNS022 (UI-DNS-004): DNS TXT 兜底走当前激活服务商（provider 化，
    // `default_provider` 从 `[dns] provider` + `[dns.providers.*]` 构建）。
    // 设备域仅 godaddy 兼容字段（`[godaddy] domain`）可用；其他服务商无独立
    // 设备域字段 → 跳过 TXT 兜底（与未配置同语义，不影响握手主路径）。
    if cfg.dns.provider != "godaddy" || cfg.godaddy.domain.trim().is_empty() {
        return (None, ClientKeyResolution::Unknown);
    }
    let Ok(provider) = kirin_desk_dns::default_provider(&cfg.dns.provider, &cfg.dns.providers)
    else {
        return (None, ClientKeyResolution::Unknown);
    };
    match TxtManager::new(&*provider, cfg.godaddy.domain.trim())
        .query(client_id)
        .await
    {
        Ok(meta) => match meta.raw_public_key() {
            Some(key) => (Some(key.to_string()), ClientKeyResolution::DnsTxt),
            None => (None, ClientKeyResolution::Unknown),
        },
        Err(_) => (None, ClientKeyResolution::Unknown),
    }
}

/// 临时连接窗口是否生效（SRV-TMP-006 统一判断点）。
///
/// GUI / CLI 服务器共用此实现（不再各自读时间戳文件），仅需在
/// 白名单跳过判定上 OR 本结果；窗口判定实现（状态文件读取/过期）唯一
/// 存在于 [`TempModeManager`]。
pub fn temp_mode_window_active() -> bool {
    TempModeManager::new()
        .map(|mgr| mgr.is_active())
        .unwrap_or(false)
}

/// 激活中的临时连接窗口管理器（SRV-TMP-HK-001 统一构造点）。
///
/// 窗口激活 → `Some(manager)`（供握手二态校验 / 白名单跳过）；未激活/不可用
/// → `None`。调用方（CLI/GUI 服务器）**逐连接**获取并传入
/// [`server_accept_handshake`]（窗口中途开启/过期即时生效）；无人值守下由
/// 调用方按 UA-ACCEPT-004 置 `None`。
pub fn temp_mode_window_manager() -> Option<TempModeManager> {
    TempModeManager::new().ok().filter(|mgr| mgr.is_active())
}

/// 判定点——GUI `handle_incoming_connection` 与 headless/relay 隧道
/// `server_accept_handshake` 共用，杜绝两调用点再次分叉）。
///
///   空域名）：绑定**本端设备 ID**（`registration_device_id`——与 relay
///   注册键 / 自连接判定 / 打洞内握手**单一来源同函数同口径**）。ID 模式
///   客户端以**被拨设备 ID** 验签响应（`client_handshake_*(server_id=拨号
///   ID)`）→ 拨号 ID == 本设备 ID 才通过；拨号 ID ≠ 本设备 ID → 验签失败
///   （fail-closed：身份绑定正是 ID 模式语义，不放宽）。
/// - **非空域名**（IP/域名模式）：维持既有**昵称绑定**（`nickname` 即该
///   模式凭据语义，客户端以用户填写的目标昵称验签，零行为变化）。
///
/// 设备 ID 验签）**必然** `Peer signature verification failed`。
pub fn response_signature_bind_id(
    client_domain: &str,
    explicit_tunnel_device_id: Option<&str>,
    config_device_id: &str,
    nickname: &str,
) -> String {
    if client_domain.is_empty() {
        kirin_desk_utils::device::registration_device_id(
            explicit_tunnel_device_id,
            config_device_id,
        )
    } else {
        nickname.to_string()
    }
}

/// 完整服务端握手（两阶段）：预读 init → 公钥解析/pin → 白名单 → 校验 → 应答。
///
/// 与 `server_handshake_with_whitelist` 的差异：本函数在**应答前**解析客户端
/// 公钥（known_hosts → DNS TXT）并强制 pin，杜绝服务端信任网络自报公钥
/// （SRV-SEC-KH-001/002）；白名单在验证之前判定（headless：不泄露服务器
/// X25519 公钥/响应签名），`temp_mode` / `temp_window` 可绕过。
///
/// (SRV-IDWL-020)：`allowed_ids` 为设备 ID 白名单（调用方从
/// `cfg.id_whitelist_active_ids(Utc::now())` 取得）；访问控制公式为
/// **`domain_match || id_match`**（双白名单 OR 语义，域名维度既有行为不变），
/// temp_mode / temp_window 跳过时两维一并跳过（SRV-IDWL-024）。
///
/// UA-ACCEPT-001/002：`unattended = true` 时访问控制切换为
/// 「自动接受」策略——白名单命中（域名 **或** ID，SRV-IDWL-003）或
/// known_clients 命中 → 自动允许（无弹窗、无需 temp mode）；两者均未命中 →
/// 直接拒绝（`Rejected("unattended: ...")`），不存在人工审批路径。调用方应
/// 保证无人值守下 `temp_mode` 已置 false（UA-ACCEPT-004）。
///
/// SRV-TMP-HK-001/003：`temp_window` 为激活中的临时连接窗口时，
/// 挑战码按二态校验（固定 **或** 临时），且与 `temp_mode` 共同跳过白名单；
/// `None` = 窗口期外，临时码一律失败，不产生任何旁路。
///
/// S-01b（F-1）：**零凭据 fail-closed** —— 客户端未知（`expected_key` 解析为
/// None，无 known_clients/DNS pin）+ 无固定挑战码 + 无激活临时窗口 →
/// 拒绝（白名单命中不再等于放行：白名单只匹配自报域名，与身份绑定解耦）。
///
/// 返回 `VerifiedDecision`（与白名单握手一致）：`Accepted` 建立安全通道；
/// `Rejected` 为策略拒绝（白名单/无人值守/零凭据）；`Err` 为验证失败（签名/pin/nickname 等）。
///
///（薄封装 [`server_accept_handshake_ex`]：`AcceptedEx` → `Accepted`，版本
/// 丢弃——既有调用方/测试零变化）；需对端 `proto_ver` 的调用方（headless
/// shell 会话文件臂门控，`cli.rs`）改用 `_ex` 入口。
pub async fn server_accept_handshake(
    stream: tokio::net::TcpStream,
    identity: &IdentityManager,
    server_id: &str,
    allowed_domains: &[String],
    allowed_ids: &[String],
    temp_mode: bool,
    unattended: bool,
    temp_window: Option<TempModeManager>,
    expected_nickname: Option<&str>,
    expected_challenge: Option<&str>,
    known: &KnownClientsStore,
    cfg: &Config,
) -> Result<VerifiedDecision, HandshakeError> {
    match server_accept_handshake_ex(
        stream,
        identity,
        server_id,
        allowed_domains,
        allowed_ids,
        temp_mode,
        unattended,
        temp_window,
        expected_nickname,
        expected_challenge,
        known,
        cfg,
    )
    .await?
    {
        VerifiedDecision::AcceptedEx { channel, peer_proto_ver: _ } => {
            Ok(VerifiedDecision::Accepted(channel))
        }
        other => Ok(other),
    }
}

/// 的**对端版本透出**变体（纯加性，原函数体全量内移）。
///
/// 唯一差异 = 成功路径产 `VerifiedDecision::AcceptedEx { channel,
/// peer_proto_ver }`（`peer_proto_ver` = 客户端 `init.proto_ver`，握手链
/// 内已消费于版本闸门，此处透出供会话分发消费）——headless shell 会话
/// per-连接 FileSession 据此门控：服务端发起的文件帧（re-Offer 臂等）仅对
/// peer `proto_ver == PROTOCOL_VERSION(3)` 发送，legacy-0 放行端不发送
///（fail-closed，§12.3-3/§12.5 混版矩阵）。
///
/// 返回 `VerifiedDecision`：`AcceptedEx` 建立安全通道 + 对端版本；
/// `Rejected` 为策略拒绝（白名单/无人值守/零凭据）；`Err` 为验证失败
///（签名/pin/nickname 等）。
pub async fn server_accept_handshake_ex(
    mut stream: tokio::net::TcpStream,
    identity: &IdentityManager,
    server_id: &str,
    allowed_domains: &[String],
    allowed_ids: &[String],
    temp_mode: bool,
    unattended: bool,
    temp_window: Option<TempModeManager>,
    expected_nickname: Option<&str>,
    expected_challenge: Option<&str>,
    known: &KnownClientsStore,
    cfg: &Config,
) -> Result<VerifiedDecision, HandshakeError> {
    // 1. 预读握手初始化消息（不应答）。
    let init = server_read_init(&mut stream).await?;

    // skew 可读化；旧端 proto_ver=0 永远放行，向后兼容）。
    if kirin_desk_core::crypto::handshake::reject_if_client_too_new(&mut stream, &init).await {
        return Ok(VerifiedDecision::Rejected(format!(
            "client protocol version {} too new (server supports <= {})",
            init.proto_ver,
            kirin_desk_core::crypto::handshake::PROTOCOL_VERSION
        )));
    }

    //     函数 + 服务端握手链路接入点）。`[network] id_whitelist_enforce`
    //     开启时：控制端设备 ID 必须在 `allowed_ids` 内（精确 / `*` 前缀通配，
    //     过期条目由调用方 `id_whitelist_active_ids(now)` 预滤），即使昵称和
    //     挑战码正确也拒绝；关闭 → 不生效（现状保持）。temp_mode / 激活临时
    //     窗口沿用 M15「临时连接跳过白名单」语义一并跳过（SRV-IDWL-024 对齐）。
    //     拒绝时下发结构化拒绝码（控制端 i18n 文案），不泄露服务器公钥/签名。
    //     旁路（temp_mode/temp_window 均关，即被控端非 IP/临时模式）下 ID 白名单
    //     准入体制对**所有**入站生效（统一判定点 `id_whitelist_enforce_violation`，
    //     非空域名（GUI IP 模式客户端，client_id 为自报昵称）对 ID 白名单一律
    //     不命中（弱凭据消灭）→ 无硬拒，流入域名白名单/pin/后续判定（用户矩阵：
    //     GUI 客户端 + ID 白名单开 → NeedsApproval，GUI 侧即进审批弹窗；headless
    //     无审批通道走既有「未命中白名单」拒绝）。
    if let Some(denied_id) = id_whitelist_enforce_violation(
        cfg.network.id_whitelist_enforce,
        temp_mode || temp_window.is_some(),
        &init.client_domain,
        &init.client_id,
        allowed_ids,
    ) {
        send_handshake_reject(&mut stream, REJECT_CODE_ID_WHITELIST, &denied_id).await;
        return Ok(VerifiedDecision::Rejected(format!(
            denied_id
        )));
    }

    // 2. 访问控制（headless：先白名单后验证，非白名单不泄露信息）。
    // 双白名单 OR —— 域名命中 **或** 设备 ID 命中即视为白名单命中。
    // ① 域名维显式排除 GUI 客户端固定魔值 `gui-client.local`（防用户误加
    //    魔值/能命中它的通配后，任意 IP 客户端凭魔值即免审批）；
    //    域名客户端的 client_id 是自报昵称（弱凭据），对 ID 白名单一律不命中。
    let is_whitelisted = (init.client_domain != crate::GUI_CLIENT_DOMAIN_MAGIC
            && allowed_domains
                .iter()
                .any(|allowed| domain_matches_whitelist(&init.client_domain, allowed)))
        || (init.client_domain.is_empty()
            && allowed_ids
                .iter()
                .any(|id| id_matches_whitelist(&init.client_id, id)));
    if unattended {
        // UA-ACCEPT-001/002：白名单命中 → 自动允许；未命中但 known_clients
        // 已信任 → 自动允许；完全未知 → 自动拒绝（无人值守无人工审批）。
        if !is_whitelisted && known.lookup(&init.client_id).is_none() {
            // 控制端按码下发可操作提示（让对端加白名单/已知设备），区别于
            // 用户主动拒绝（`approval_declined`）/审批超时。准入语义零放宽
            // （UA-ACCEPT-002 自动拒不变；与 GUI accept 链 unattended 分支同码）。
            send_handshake_reject(
                &mut stream,
                REJECT_CODE_UNATTENDED_UNKNOWN,
                &init.client_id,
            )
            .await;
            return Ok(VerifiedDecision::Rejected(format!(
                "unattended: client '{}' unknown (whitelist or known_clients required)",
                init.client_id
            )));
        }
    } else if !temp_mode && temp_window.is_none() && !is_whitelisted {
        send_handshake_reject(
            &mut stream,
            REJECT_CODE_APPROVAL_DECLINED,
            &init.client_id,
        )
        .await;
        return Ok(VerifiedDecision::Rejected(format!(
            "domain '{}' and id '{}' not in whitelist (headless: no GUI approval)",
            init.client_domain, init.client_id
        )));
    }

    // 3. 客户端公钥解析（known_hosts → DNS TXT）+ 校验（pin/nickname/challenge/签名）。
    let (expected_key, _resolution) =
        resolve_expected_client_key(known, cfg, &init.client_id).await;

    // S-01b (F-1): 零凭据 fail-closed —— 客户端未知（无 pin）+ 无固定挑战码 +
    // 无激活临时窗口 → 拒绝（含无人值守下白名单命中但零凭据的路径；「白名单
    // 命中」只证明自报域名匹配，不再是放行依据）。
    let challenge_configured = expected_challenge.map_or(false, |c| !c.is_empty());
    if expected_key.is_none() && !challenge_configured && temp_window.is_none() {
        send_handshake_reject(
            &mut stream,
            REJECT_CODE_CREDENTIALS_REQUIRED,
            &init.client_id,
        )
        .await;
        return Ok(VerifiedDecision::Rejected(format!(
            "no credentials: client '{}' is unknown (no pinned key), and server has \
             no challenge code and no temp window — zero-credential connection rejected (F-1)",
            init.client_id
        )));
    }

    // S-01a (F-1)：生产路径零凭据 → 拒绝（verify 层兜底，防调用方遗漏）。
    // → 挑战-响应轮（下发 nonce、限时收应答；失败/超时 = 结构化拒绝 +
    // Err 路径，与 verify 失败同处置面）。
    let challenge_answer =
        if kirin_desk_core::crypto::handshake::challenge_round_required(
            expected_key.as_deref().unwrap_or(""),
            &init.client_ed25519_pub_base64,
            expected_challenge,
            temp_window.as_ref(),
        ) {
            match kirin_desk_core::crypto::handshake::server_challenge_round(&mut stream).await {
                Ok(a) => Some(a),
                Err(e) => {
                    send_handshake_reject(
                        &mut stream,
                        REJECT_CODE_CHALLENGE_MISMATCH,
                        &init.client_id,
                    )
                    .await;
                    return Err(e);
                }
            }
        } else {
            None
        };
    if let Err(e) = verify_server_init_with_temp(
        &init,
        expected_key.as_deref().unwrap_or(""),
        expected_nickname,
        expected_challenge,
        temp_window.as_ref(),
        false,
        challenge_answer.as_ref(),
    ) {
        if let Some(code) = handshake_error_reject_code(&e) {
            send_handshake_reject(&mut stream, code, &init.client_id).await;
        }
        return Err(e);
    }

    // 消费窗口（删状态文件），杜绝同一临时码跨连接复用 / 长挂起槽劣化准入
    // （固定码场景不消费；固定码+窗口双凭据无法归因 → 保守不消费，至 TTL
    // 自然过期回收——见 `TempModeManager::consume` 语义边界）。
    if expected_challenge.is_none() {
        if let Some(w) = temp_window.as_ref() {
            if w.consume() {
                tracing::info!(
                    init.client_id
                );
            }
        }
    }

    // 4. 应答 + 建立安全通道。
    // （AV1 → H.265 → H.264）从客户端可解码列表（握手 supported_codecs）中
    // 挑选；交集为空（旧客户端未广告 / 无交集）→ 空串 → 客户端按 H.264 兜底
    // （与既有行为一致）。服务端编码能力缓存自 media 探测（避免每连接创建
    // 编码器）。
    let selected_codec = {
        let server_caps: Vec<String> =
            kirin_desk_media::encoder::detect_supported_codecs_cached()
                .into_iter()
                .map(|s| s.to_string())
                .collect();
        negotiate_codec_by_server_priority(&server_caps, &init.supported_codecs)
    };
    // 与 GUI accept 链同口径，见 [`response_signature_bind_id`]）。
    let bind_id = response_signature_bind_id(
        &init.client_domain,
        cfg.tunnel.device_id.as_deref(),
        &cfg.device.id,
        server_id,
    );
    let g = server_handshake_respond_generic(stream, identity, &bind_id, &init, &selected_codec)
        .await?;
    // 消费点（headless shell 会话 per-连接 FileSession，cli.rs）；既有
    // `server_accept_handshake` 薄封装丢弃版本 = 行为零变化。
    Ok(VerifiedDecision::AcceptedEx {
        channel: SecureChannel {
            stream: g.stream,
            cipher: g.cipher,
            peer_id: g.peer_id,
            peer_domain: g.peer_domain,
            peer_device_type: g.peer_device_type,
            selected_codec: g.selected_codec,
            peer_os: g.peer_os,
        },
        peer_proto_ver: init.proto_ver,
    })
}

/// 握手成功后刷新 known_hosts 记录（`last_seen`），已存在才更新并保存。
pub fn record_successful_handshake(known: &mut KnownClientsStore, client_id: &str) {
    if known.lookup(client_id).is_some() {
        known.touch(client_id);
        let _ = known.save();
    }
}

/// (CLI-TMP-003): 连接失败引导提示。
///
/// 安全约束：不泄露服务端窗口状态（HK-002/SRV-SEC-WL）——文案对
/// 「固定码错误 / 临时码过期 / 临时码错误」统一覆盖，不做线上区分；
/// 仅当本次连接确实携带了挑战码时输出（无码失败不误导）。
/// `temp_code_like` 为尽力而为的格式提示（方案 B）：10 位且全部字符
/// 属于临时码字符集（不含 0/O/1/I）时，优先提示临时码场景（S-20 / F-25：
/// 码长 8 → 10）。
///
/// 字符集与 `core/src/connection/temp_mode.rs` 的 `CODE_CHARSET`
/// 保持一致（跨 crate 无法直接引用私有常量，单测固定断言）。
pub fn connect_failure_challenge_hint(challenge: &str) -> Option<String> {
    if challenge.is_empty() {
        return None;
    }
    let temp_like = challenge.len() == 10
        && challenge
            .chars()
            .all(|c| "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".contains(c));
    // (P6): 文案走 t!()——zh 模板保持现语义逐字（单测断言
    // 「固定挑战码错误」「临时连接码格式」等子串），en 补翻译。
    let hint = if temp_like {
        t!("policy.challenge_hint.temp")
    } else {
        t!("policy.challenge_hint.fixed")
    };
    Some(hint.to_string())
}

/// 双语文案；未识别码 / 非结构化拒绝返回 `None`，调用方回退原始错误串）。
///
/// 不匹配/需凭据/审批拒绝/限流/版本不匹配（此前这些路径裸 close，控制端
/// 只能报 `early eof`，用户无法定位）。
pub fn handshake_rejected_hint(
    err: &kirin_desk_core::crypto::handshake::HandshakeError,
) -> Option<String> {
    use kirin_desk_core::crypto::handshake::{
        HandshakeError as He, REJECT_CODE_APPROVAL_DECLINED, REJECT_CODE_APPROVAL_TIMEOUT,
        REJECT_CODE_CHALLENGE_MISMATCH, REJECT_CODE_CLIENT_KEY_MISMATCH,
        REJECT_CODE_CREDENTIALS_REQUIRED, REJECT_CODE_MUTUAL_CONTROL,
        REJECT_CODE_NICKNAME_MISMATCH, REJECT_CODE_RATE_LIMITED,
        REJECT_CODE_UNATTENDED_UNKNOWN, REJECT_CODE_VERSION_MISMATCH,
    };
    // 客户端本地判定的版本过新（服务端高于本端）同码映射。
    if let He::ServerTooNew { .. } = err {
        return Some(t!("connect.error.version_mismatch").to_string());
    }
    match err.reject_code() {
        Some(code) if code == REJECT_CODE_ID_WHITELIST => {
            Some(t!("connect.id.error_whitelist_denied").to_string())
        }
        Some(code) if code == REJECT_CODE_CHALLENGE_MISMATCH => {
            Some(t!("connect.error.challenge_mismatch").to_string())
        }
        Some(code) if code == REJECT_CODE_NICKNAME_MISMATCH => {
            Some(t!("connect.error.nickname_mismatch").to_string())
        }
        Some(code) if code == REJECT_CODE_CLIENT_KEY_MISMATCH => {
            Some(t!("connect.error.client_key_mismatch").to_string())
        }
        Some(code) if code == REJECT_CODE_CREDENTIALS_REQUIRED => {
            Some(t!("connect.error.credentials_required").to_string())
        }
        Some(code) if code == REJECT_CODE_APPROVAL_DECLINED => {
            Some(t!("connect.error.approval_declined").to_string())
        }
        Some(code) if code == REJECT_CODE_APPROVAL_TIMEOUT => {
            Some(t!("connect.error.approval_timeout").to_string())
        }
        // 已知设备；准入语义零放宽——服务端仍秒拒，仅文案分类细化）。
        Some(code) if code == REJECT_CODE_UNATTENDED_UNKNOWN => {
            Some(t!("connect.error.unattended_unknown").to_string())
        }
        Some(code) if code == REJECT_CODE_RATE_LIMITED => {
            Some(t!("connect.error.rate_limited").to_string())
        }
        // 申请方 = 对端正作为本端控制端存在活跃桌面会话）。可操作提示：
        // 反向控制被按策略拒绝，待对端会话结束后重试。
        Some(code) if code == REJECT_CODE_MUTUAL_CONTROL => {
            Some(t!("connect.error.mutual_control_denied").to_string())
        }
        Some(code) if code == REJECT_CODE_VERSION_MISMATCH => {
            Some(t!("connect.error.version_mismatch").to_string())
        }
        _ => None,
    }
}

/// 离线」分类**纯判定——`None` = 非传输类错误（调用方回退原文案/走结构化
/// 拒绝码文案）。
///
/// 口径（PM 裁定 c：四类状态分类呈现，不得再呈现裸 "TCP early eof" 式传输
/// 错误）：
/// - 服务端已下发**结构化拒绝码** → `None`（[`handshake_rejected_hint`]
///   的按码文案优先——「被拒绝/审批超时」语义更精确，不归「离线」）；
/// - 传输层连接类失败 → 离线类文案（`connect.error.peer_offline`）：
///   对端 EOF（early eof——服务端审批中停止/切模式即此形态）/连接被重置/
///   管道断开/连接超时/连接拒绝（不可达）；
/// - 协议层/信任类错误（签名失败、指纹不匹配、序列化、消息损坏等）→
///   `None`（非「传输错误」类，原文案即其语义，不误分类）。
pub fn handshake_offline_hint(
    err: &kirin_desk_core::crypto::handshake::HandshakeError,
) -> Option<String> {
    use kirin_desk_core::crypto::handshake::HandshakeError as He;
    use kirin_desk_core::network::tcp::TcpError;
    use std::io::ErrorKind as K;
    // 结构化拒绝码在手 → 归「被拒绝/超时」类，不归离线。
    if err.reject_code().is_some() {
        return None;
    }
    let offline = match err {
        He::Tcp(t) => match t {
            TcpError::Io(e) => matches!(
                e.kind(),
                K::UnexpectedEof
                    | K::ConnectionAborted
                    | K::ConnectionReset
                    | K::BrokenPipe
                    | K::TimedOut
                    | K::NotConnected
            ),
            // 拨号失败（拒绝/不可达）= 对方离线/关机。
            TcpError::Connect { .. } => true,
            // 拨号限时到（服务端不可达）。
            TcpError::Timeout { .. } => true,
            // 本地错误（bind 失败/帧超长）——非对端离线，不误分类。
            TcpError::Bind { .. } | TcpError::MessageTooLarge { .. } => false,
        },
        He::Io(e) => matches!(
            e.kind(),
            K::UnexpectedEof | K::ConnectionAborted | K::ConnectionReset | K::BrokenPipe | K::TimedOut
        ),
        // 握手等待超时（服务端无任何应答）。
        He::Timeout => true,
        _ => false,
    };
    offline.then(|| t!("connect.error.peer_offline").to_string())
}

///
/// PM 裁定 c：等待审批（进行态 `connect.status.waiting_approval`）/ 审批
/// 超时（`approval_timeout` 码）/ 被拒绝（`approval_declined` 等码）/ 对方
/// 离线（传输层错误）四类分类呈现，**不再呈现裸 "TCP error: I/O error:
/// early eof" 式传输错误**（原始错误串仍进日志供取证，仅 UI 状态串分类）。
///
/// 优先级：① 服务端结构化拒绝码 → 按码本地化文案（`handshake_rejected_hint`）；
/// ② 传输层连接类失败 → 「对方离线」类文案（`handshake_offline_hint`）；
/// ③ 其余（协议/信任/序列化类，文案即语义）→ 原始错误串。
pub fn handshake_failure_status(
    err: &kirin_desk_core::crypto::handshake::HandshakeError,
) -> String {
    if let Some(h) = handshake_rejected_hint(err) {
        format!("Handshake FAILED\n{h}")
    } else if let Some(h) = handshake_offline_hint(err) {
        format!("Handshake FAILED\n{h}")
    } else {
        format!("Handshake FAILED: {err}")
    }
}

///
/// 分类文案固定句式「现象：说明——对策/重试提示」（zh 断点 `——` / en
/// 断点 ` — `）；短状态取断点前首句（保证内联 ≤2 行）。无断点（既有
/// 单句文案，如 approval_declined）取全句；断点前为空回落全句（不产空串）。
pub fn first_sentence(text: &str) -> String {
    let t = text.trim();
    for sep in ["——", " — "] {
        if let Some(idx) = t.find(sep) {
            let head = t[..idx].trim();
            if !head.is_empty() {
                return head.to_string();
            }
        }
    }
    t.to_string()
}

/// 指认 6+ 行长块内联渲染把连接表单挤出可视区；内联只留短状态，详提示
/// 进「查看详情」弹窗）。
///
/// - [`HandshakeFailureParts::short`]：`Handshake FAILED` + 分类文案首句
///   （≤2 行，红色内联状态行语义/视觉不变）；协议/信任类（无分类文案）=
///   原单行状态串（[`handshake_failure_status`] 第③类行为）。
/// - [`HandshakeFailureParts::detail`]：完整分类文案 + 3 条排查提示
///   （携带挑战码 = [`connect_failure_challenge_hint`] 的 1)/2)/3) 三条；
///   分类文案本身已含「请……重试」对策，提示三条按挑战码存在与否追加）；
///   `None` = 无详情（无分类文案且未携带挑战码 → 弹窗入口不渲染）。
///
/// 分类优先级与 [`handshake_failure_status`] 同口径：① 服务端结构化拒绝码
/// → ② 传输层「对方离线」 → ③ 原始错误串（纯函数，可单测）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeFailureParts {
    /// 短状态（内联状态行，≤2 行）。
    pub short: String,
    /// 详提示（弹窗多行）；`None` = 无详情。
    pub detail: Option<String>,
}

///
/// `challenge` = 本次连接携带的挑战码（空串 = 未携带 → 无排查提示段，
/// 语义与既有组装点「仅 `ConnectError::Handshake` 且带码才追加提示」一致）。
///
/// 分类**单一来源** = [`handshake_failure_status`]（① 结构化拒绝码 /
/// ② 对方离线 → `Handshake FAILED\n{分类文案}`；③ 协议/信任类 →
/// `Handshake FAILED: {原始错误串}`——前缀形态互斥无歧义）：短状态 =
/// 分类文案首句（≤2 行），详情 = 完整分类文案 + 挑战提示。
pub fn handshake_failure_parts(
    err: &kirin_desk_core::crypto::handshake::HandshakeError,
    challenge: &str,
) -> HandshakeFailureParts {
    let hint = connect_failure_challenge_hint(challenge);
    let full = handshake_failure_status(err);
    if let Some(h) = full.strip_prefix("Handshake FAILED\n") {
        let short = format!("Handshake FAILED\n{}", first_sentence(h));
        let mut detail = h.to_string();
        if let Some(hc) = &hint {
            detail.push('\n');
            detail.push_str(hc);
        }
        return HandshakeFailureParts {
            short,
            detail: Some(detail),
        };
    }
    // ③ 协议/信任/序列化类：原文案即语义（短状态 = 原单行串，既有行为零
    // 变化；详情仅挑战提示，`None` = 无弹窗入口）。
    HandshakeFailureParts {
        short: full,
        detail: hint,
    }
}


///
/// 参数口径（按服务端限流默认 `core/src/network/rate_limit.rs` 反推）：
/// SRV-SEC-RL-001 30s 滑窗最多 3 次连接尝试 / SRV-SEC-RL-002 握手失败累计
/// 5 次 → 临时封禁 15 分钟。2× 指数 + 60s 上限 + ±20% 抖动下，客户端最坏
/// 间隔（×0.8）= 8/16/32/48s → 任意 30s 窗内至多 3 次尝试（0/8/24s 恰 3
/// 次，第 4 次 ≥56s）→ 按退避重试的客户端**永不**打穿对端 `rate_limited`
/// 与 10054 重置风暴（09-18 复测 19:28 本机→179 一分钟 11 连点 → 8×
/// id_whitelist_denied + 4× rate_limited + /24 封禁 15 分钟的根因）。
pub const CONNECT_RETRY_BACKOFF_BASE: Duration = Duration::from_secs(10);
pub const CONNECT_RETRY_BACKOFF_CAP: Duration = Duration::from_secs(60);

///
/// `attempt` = 已发生的失败次数（0 = 首次失败 → 首次重试前等待）；
/// `nominal = min(base × 2^attempt, cap)`；抖动 = xorshift32 从 `(seed,
/// attempt)` 确定性派生的 ±20% 整数百分比（同输入恒同输出：生产传时间
/// 种、测试传固定种复算）。返回区间 = [0.8, 1.2] × nominal（指数步长 ×2
/// 大于抖动比 ×1.2 → 序列在触顶前严格单调不减）。
pub fn connect_retry_backoff(attempt: u32, seed: u32) -> Duration {
    const JITTER_PCT: u64 = 20;
    let base_ms = CONNECT_RETRY_BACKOFF_BASE.as_millis() as u64;
    let cap_ms = CONNECT_RETRY_BACKOFF_CAP.as_millis() as u64;
    let nominal_ms = base_ms.saturating_mul(1u64 << attempt.min(32)).min(cap_ms);
    // xorshift32(seed ^ attempt·黄金比) → 0..=40 → 百分比偏移 -20..+20。
    let mut s = seed ^ attempt.wrapping_mul(0x9E37_79B9);
    if s == 0 {
        s = 0x853B_9A93;
    }
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    let pct = (s % 41) as u64;
    let signed = pct.saturating_sub(JITTER_PCT); // 0..=20（即 -20%..+20%）
    Duration::from_millis(nominal_ms * (100 + signed) / 100)
}

#[cfg(test)]
mod r132_2_backoff_tests {
    use super::*;

    fn nominal(attempt: u32) -> Duration {
        let base = CONNECT_RETRY_BACKOFF_BASE.as_millis() as u64;
        let cap = CONNECT_RETRY_BACKOFF_CAP.as_millis() as u64;
        Duration::from_millis(base.saturating_mul(1u64 << attempt.min(32)).min(cap))
    }

    #[test]
    fn r132_2_backoff_bounds_and_determinism() {
        for attempt in 0..=8u32 {
            let n = nominal(attempt).as_millis() as u64;
            for &seed in &[0u32, 1, 7, 0xDEAD_BEEF, 0x1234_5678] {
                let d = connect_retry_backoff(attempt, seed).as_millis() as u64;
                assert!(
                    d >= n * 80 / 100 && d <= n * 120 / 100,
                    "attempt={attempt} seed={seed:#x}: {d}ms ∉ [0.8,1.2]×nominal({n}ms)"
                );
                // 可复算：同输入恒同输出。
                assert_eq!(
                    d,
                    connect_retry_backoff(attempt, seed).as_millis() as u64,
                    "attempt={attempt} seed={seed:#x}: 同输入不同输出"
                );
            }
        }
    }

    #[test]
    fn r132_2_backoff_exponential_then_cap() {
        // nominal 序列钉死：10s → 20s → 40s → 60s（上限）→ 60s…
        assert_eq!(nominal(0), Duration::from_secs(10));
        assert_eq!(nominal(1), Duration::from_secs(20));
        assert_eq!(nominal(2), Duration::from_secs(40));
        assert_eq!(nominal(3), Duration::from_secs(60), "cap");
        assert_eq!(nominal(4), Duration::from_secs(60), "cap 保持");
        // 实际序列（固定种复算）单调不减（×0.8 下界 > 上一级 ×1.2 上界，
        // 唯 cap 衔接处 48s 可能相等——断言用 ≥）。
        let mut prev = 0u128;
        for attempt in 0..=6u32 {
            let d = u128::from(connect_retry_backoff(attempt, 0xC0FFEE).as_millis());
            assert!(d >= prev, "attempt={attempt}: {d} < prev {prev}（单调性破）");
            prev = d;
        }
    }

    #[test]
    fn r132_2_backoff_never_exceeds_peer_rate_limit_window() {
        // 09-18 根因回归钉死：以区间两端（×0.8 最小间隔 / ×1.2 最大间隔）
        // 模拟客户端尝试时刻（t=0 首次点击 + 后续退避重试），任意 30s 滑窗
        // 内尝试次数 ≤ 3（服务端 SRV-SEC-RL-001 放行上限）→ 不再出现
        // rate_limited 打穿。
        for jitter in [80u64, 120] {
            let base = CONNECT_RETRY_BACKOFF_BASE.as_millis() as u64;
            let cap = CONNECT_RETRY_BACKOFF_CAP.as_millis() as u64;
            let mut t = 0u128; // 首次尝试（无退避）
            let mut times = vec![t];
            for attempt in 0..8u32 {
                let nominal = base.saturating_mul(1u64 << attempt.min(32)).min(cap) as u128;
                t += nominal * jitter as u128 / 100;
                times.push(t);
            }
            for &end in &times {
                // 以每次尝试为窗右端点的 30s 滑窗（若任意窗内 >3 次，则以第
                // 4 次尝试为右端的窗亦必含之 → 逐右端点检查充分）。
                let count = times
                    .iter()
                    .filter(|&&s| s <= end && end - s <= 30_000)
                    .count();
                assert!(
                    count <= 3,
                    "jitter={jitter}‰ 窗 end={end}ms: {count} 次尝试 > 3（30s 窗）"
                );
            }
        }
    }
}


/// 取中值 2.5s——点连接后 2-3s 内状态行必须出现等待提示）。
pub const CONNECT_WAIT_HINT_DELAY: std::time::Duration = std::time::Duration::from_millis(2500);

/// 本地化写入 `connection_status`（zh「等待对方审批中…」/ en「Waiting for
/// 匹配本地化串，zh 下**必然失配** → 按钮不置灰、可重复点击（用户感知=没
/// 反应的一半根因）。此处对 zh/en 两个规范值取前缀（经 `tr_lang` 查表，零
/// 硬编码），任何当前语言下判定一致）。
pub fn is_waiting_approval_status(status: &str) -> bool {
    let s = status.strip_prefix("[shell] ").unwrap_or(status);
    let zh = crate::i18n::tr_lang(crate::i18n::Lang::Zh, "connect.status.waiting_approval");
    let en = crate::i18n::tr_lang(crate::i18n::Lang::En, "connect.status.waiting_approval");
    s.starts_with(zh) || s.starts_with(en)
}

/// 计时/状态行共用）。busy = 英文进度前缀（Discovering/Resolving/Connecting/
/// Handshaking，线程写入的进度快照约定，`[shell] ` 前缀剥离）或
/// waiting_approval 进行态（本地化串，见 [`is_waiting_approval_status`]）。
///
/// 预算）分工不同：看门狗按**字符串 episode** 计时（同串才累计，防多阶段
/// 连接误触发 30s 兜底），本判定只回答「是否处于进行态」。
pub fn is_connect_status_busy(status: &str) -> bool {
    let s = status.strip_prefix("[shell] ").unwrap_or(status);
    s.starts_with("Discovering")
        || s.starts_with("Resolving")
        || s.starts_with("Connecting")
        || s.starts_with("Handshaking")
        || is_waiting_approval_status(status)
}

/// 无 IO/wire——PM 裁定：本波不做协议级「审批中」信号，用超时态+既有文案）。
///
/// 用户原话：「主控端看起来点连接后没反应，要把连接的状态修改为灰色并提示
/// 等待受控端允许受控」。输入：
/// - `busy`：进行中 episode（[`is_connect_status_busy`]）；
/// - `elapsed`：episode 已用时（None = 未计时/刚进入，按安全侧早相位处理）；
/// - `responded`：握手响应已收到（确认回调被调 = 服务端公钥已取到，进入
///   验签/指纹确认子相位）；
/// - `first_connect`：首次连接（响应后预期弹指纹确认窗——安全红线不可免，
///   等待提示需预告）。
///
/// 输出：
/// - `controls_enabled`：false → 连接按钮/相关输入置灰禁用（防重复点击；
///   进行态全程置灰直到终态覆盖）；
/// - `status_key`：状态区**主文案** i18n key——`None` = 呈现原进度串
///   （`Connecting: …`，早期相位信息更具体）；`Some` = 呈现该 key 文案
///   （显著等待提示/验签中）；
/// - `show_timer`：主文案模板含 `{0}` 等待计时占位（秒，向上取整）；
/// - `hint_key`：次级提示行 key（中性文案：若对方开启审批需其确认后继续；
///   首连追加指纹确认预告）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectWaitDecision {
    pub controls_enabled: bool,
    pub status_key: Option<&'static str>,
    pub show_timer: bool,
    pub hint_key: Option<&'static str>,
}

///
/// | busy | responded | elapsed            | controls | status_key                | timer | hint                       |
/// |------|-----------|--------------------|----------|---------------------------|-------|----------------------------|
/// | 否   | –         | –                  | 启用     | None（不覆盖）             | –     | –                          |
/// | 是   | 是        | 任意               | 禁用     | `connect.status.verifying`| 否    | –（指纹窗为主呈现）         |
/// | 是   | 否        | ≥2.5s              | 禁用     | `connect.status.waiting_peer` | 是 | 首连 `_hint_first` 否则 `_hint` |
/// | 是   | 否        | <2.5s 或 None      | 禁用     | None（原进度串）           | 否    | –                          |
pub fn connect_wait_decision(
    busy: bool,
    elapsed: Option<std::time::Duration>,
    responded: bool,
    first_connect: bool,
) -> ConnectWaitDecision {
    if !busy {
        // 文案 / Connected 绿）。
        return ConnectWaitDecision {
            controls_enabled: true,
            status_key: None,
            show_timer: false,
            hint_key: None,
        };
    }
    if responded {
        // 响应已收到：验签 +（首连）指纹确认——短暂相位，确认框是主呈现，
        // 不再计等待计时（避免「已收到响应却仍显示等待批准」的误导）。
        return ConnectWaitDecision {
            controls_enabled: false,
            status_key: Some("connect.status.verifying"),
            show_timer: false,
            hint_key: None,
        };
    }
    match elapsed {
        Some(e) if e >= CONNECT_WAIT_HINT_DELAY => ConnectWaitDecision {
            controls_enabled: false,
            status_key: Some("connect.status.waiting_peer"),
            show_timer: true,
            hint_key: Some(if first_connect {
                "connect.status.waiting_peer_hint_first"
            } else {
                "connect.status.waiting_peer_hint"
            }),
        },
        // 早期相位（<2.5s 或尚未计时）：原进度串（Connecting: …）即最具体的
        // 信息，保持置灰防重复点击。
        _ => ConnectWaitDecision {
            controls_enabled: false,
            status_key: None,
            show_timer: false,
            hint_key: None,
        },
    }
}

/// 按字符串 episode 计时独立——本时钟跨 busy 串变化持续累计，只在进行态
/// 结束〔终态覆盖〕时清零）。
/// - `busy=true` 且 `prev=None` → 记 `now`（episode 起点）；
/// - `busy=true` 且 `prev=Some` → 保持（Connecting: … → 等待审批中… 串变化
///   不重置，否则 5.75s 盲区被拆成三个短 episode）；
/// - `busy=false` → 清零（终态/空闲；下一次点击重新起算）。
pub fn connect_episode_clock_tick(
    prev: Option<std::time::Instant>,
    busy: bool,
    now: std::time::Instant,
) -> Option<std::time::Instant> {
    if busy {
        prev.or(Some(now))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kirin_desk_core::crypto::ed25519::IdentityManager;
    use kirin_desk_core::crypto::handshake::{
        client_handshake_with_confirm_generic, PinExpectation, SecureChannelGeneric,
    };
    use tokio::net::TcpListener;

    fn gen_identity(dir: &std::path::Path, name: &str) -> IdentityManager {
        IdentityManager::generate(dir.join(name)).expect("generate identity")
    }

    /// 本地 TCP 对连执行一次服务端握手：
    /// 客户端 alice（domain 由参数给定，类型 desktop）→ 服务端 bob（自生成），
    /// 按参数给定无人值守标志 / known_clients / 域名白名单 / ID 白名单 / 挑战码 /
    /// alice 身份由调用方传入（known_clients 预置的公钥必须与握手客户端一致）。
    /// `challenge` 非空时服务端以该固定挑战码校验（S-01b：零凭据测试显式配置）。
    async fn run_pair(
        tag: &str,
        unattended: bool,
        known: &KnownClientsStore,
        allowed: &[String],
        allowed_ids: &[String],
        alice: &IdentityManager,
        challenge: &str,
        client_domain: &str,
    ) -> (
        Result<SecureChannelGeneric<tokio::net::TcpStream>, HandshakeError>,
        Result<VerifiedDecision, HandshakeError>,
    ) {
        let dir = std::env::temp_dir().join(format!("kirin_policy_{}", tag));
        let bob = gen_identity(&dir, "bob");
        let bob_pub = bob.public_key_base64();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();

        // = relay 注册键）——ID 形态时把测试服务端 `device.id` 钉为拨号值
        // "bob"（harness 客户端验签值），不让空配置的卷序列号自动派生
        // （本机真实设备 ID）进入断言面。
        let domain_empty = client_domain.is_empty();
        let server_fut = async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut cfg = Config::default();
            if domain_empty {
                cfg.device.id = "bob".to_string();
            }
            let expected_challenge = if challenge.is_empty() {
                None
            } else {
                Some(challenge)
            };
            server_accept_handshake(
                stream,
                &bob,
                "bob",
                allowed,
                allowed_ids,
                false,
                unattended,
                None,
                None,
                expected_challenge,
                known,
                &cfg,
            )
            .await
        };
        let client_domain = client_domain.to_string();
        let client_fut = async move {
            let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            client_handshake_with_confirm_generic(
                stream,
                alice,
                "alice",
                &client_domain,
                "desktop",
                "bob",
                PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"),
                None,
                challenge,
            )
            .await
        };
        let (client_res, decision) = tokio::join!(client_fut, server_fut);
        let _ = std::fs::remove_dir_all(&dir);
        (client_res, decision)
    }

    /// UA-ACCEPT-002: 无人值守下完全未知设备（无 known_clients、无白名单）
    /// → 自动拒绝，客户端无法建立安全通道。
    /// 映射可操作文案；准入语义零放宽——仍秒拒）。
    #[tokio::test]
    async fn test_unattended_unknown_rejected() {
        let dir = std::env::temp_dir().join("kirin_policy_unknown");
        let alice = gen_identity(&dir, "alice");
        let known = KnownClientsStore::empty();
        let (client_res, decision) =
            run_pair("unknown", true, &known, &[], &[], &alice, "", "alice.local").await;
        match decision {
            Ok(VerifiedDecision::Rejected(reason)) => {
                assert!(reason.contains("unattended"), "reason: {}", reason);
            }
            Ok(_) => panic!("expected Rejected(unattended)"),
            Err(e) => panic!("server handshake error: {}", e),
        }
        match client_res {
            Err(e) => {
                assert_eq!(
                    e.reject_code(),
                    Some(kirin_desk_core::crypto::handshake::REJECT_CODE_UNATTENDED_UNKNOWN),
                    "unattended+unknown must send the dedicated reject code"
                );
            }
            Ok(_) => panic!("channel must not be established"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// UA-ACCEPT-001: 无人值守下 known_clients 命中（无白名单）→ 自动允许。
    #[tokio::test]
    async fn test_unattended_known_client_accepted() {
        let dir = std::env::temp_dir().join("kirin_policy_known_accepted");
        let alice = gen_identity(&dir, "alice");
        let alice_pub = alice.public_key_base64();
        let mut known = KnownClientsStore::empty();
        known.upsert("alice", &alice_pub);

        let (client_res, decision) =
            run_pair("known", true, &known, &[], &[], &alice, "", "alice.local").await;
        assert!(
            matches!(decision, Ok(VerifiedDecision::Accepted(_))),
            "expected Accepted, got {:?}",
            decision.is_err()
        );
        assert!(client_res.is_ok(), "client handshake should succeed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// UA-ACCEPT-001: 无人值守下白名单命中（无 known_clients）→ 自动允许。
    #[tokio::test]
    async fn test_unattended_whitelist_accepted() {
        let dir = std::env::temp_dir().join("kirin_policy_whitelist");
        let alice = gen_identity(&dir, "alice");
        let known = KnownClientsStore::empty();
        let allowed = vec!["*.local".to_string()];
        // S-01b (F-1)：无人值守白名单命中但零凭据 → 拒绝；本用例配置挑战码
        // 验证「白名单 + 凭据齐备」仍自动放行（UA-ACCEPT-001 语义不变）。
        let (client_res, decision) = run_pair(
            "whitelist",
            true,
            &known,
            &allowed,
            &[],
            &alice,
            "TEST-CODE",
            "alice.local",
        )
        .await;
        assert!(
            matches!(decision, Ok(VerifiedDecision::Accepted(_))),
            "expected Accepted, got {:?}",
            decision.is_err()
        );
        assert!(client_res.is_ok(), "client handshake should succeed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S-01b (F-1): 零凭据 fail-closed —— 自签客户端自报白名单域名 + 客户端
    /// 未知（无 pin）+ 空挑战码 + 无临时窗口 → 拒绝（白名单命中只证明自报
    /// 域名匹配，不再等于放行）。常规与无人值守两路径均验证。
    #[tokio::test]
    async fn test_zero_credentials_whitelisted_rejected() {
        let dir = std::env::temp_dir().join("kirin_policy_zero_cred");
        let alice = gen_identity(&dir, "alice");
        let known = KnownClientsStore::empty();
        let allowed = vec!["*.local".to_string()]; // 域名白名单命中（自报）

        // 常规模式：白名单命中 + 零凭据 → Rejected(no credentials)。
        let (client_res, decision) =
            run_pair("zero_cred", false, &known, &allowed, &[], &alice, "", "alice.local").await;
        match decision {
            Ok(VerifiedDecision::Rejected(reason)) => {
                assert!(reason.contains("no credentials"), "reason: {}", reason);
            }
            Ok(_) => panic!("zero-credential whitelist hit must be rejected (F-1)"),
            Err(e) => panic!("server handshake error: {}", e),
        }
        assert!(client_res.is_err(), "channel must not be established");

        // 无人值守：白名单命中 + 零凭据 → 同样拒绝（UA-ACCEPT-001 的自动放行
        // 不再覆盖零凭据；凭据齐备用例见 test_unattended_whitelist_accepted）。
        let (client_res, decision) = run_pair(
            "zero_cred_unattended",
            true,
            &known,
            &allowed,
            &[],
            &alice,
            "",
            "alice.local",
        )
        .await;
        match decision {
            Ok(VerifiedDecision::Rejected(reason)) => {
                assert!(reason.contains("no credentials"), "reason: {}", reason);
            }
            Ok(_) => panic!("unattended zero-credential whitelist hit must be rejected (F-1)"),
            Err(e) => panic!("server handshake error: {}", e),
        }
        assert!(client_res.is_err(), "channel must not be established");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 常规模式（unattended=false）行为不变：known_clients 命中但不在白名单
    /// → 仍拒绝（known_clients 是身份校验来源，白名单是访问控制，角色不变）。
    #[tokio::test]
    async fn test_normal_known_not_whitelisted_still_rejected() {
        let dir = std::env::temp_dir().join("kirin_policy_normal_rejected");
        let alice = gen_identity(&dir, "alice");
        let alice_pub = alice.public_key_base64();
        let mut known = KnownClientsStore::empty();
        known.upsert("alice", &alice_pub);

        let (client_res, decision) =
            run_pair("normal", false, &known, &[], &[], &alice, "", "alice.local").await;
        match decision {
            Ok(VerifiedDecision::Rejected(reason)) => {
                assert!(reason.contains("whitelist"), "reason: {}", reason);
            }
            Ok(_) => panic!("expected Rejected(whitelist)"),
            Err(e) => panic!("server handshake error: {}", e),
        }
        assert!(client_res.is_err(), "channel must not be established");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// (SRV-TMP-HK-001/002 + SRV-TMP-006): 临时连接窗口端到端——
    /// 窗口激活（注入隔离状态文件）+ 无白名单：客户端携带临时挑战码 → 握手
    /// 成功（白名单跳过 + 二态校验通过）；携带错码 → 验证失败被拒。
    ///
    /// 窗口**（一码一连接，杜绝跨连接复用/长挂起槽）——故错码场景需**重新
    /// 开窗**复现「窗口激活 + 错码」状态（失败尝试不消费）。
    #[tokio::test]
    async fn test_temp_window_accepts_temp_code_e2e() {
        use kirin_desk_core::connection::temp_mode::TempModeManager;
        let dir = std::env::temp_dir().join("kirin_policy_temp_window");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");
        let state_path = dir.join("temp_mode.json");
        let tm = TempModeManager::with_state_file(state_path.clone());
        let code = tm.enable(300).expect("enable");

        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let bob_pub = bob.public_key_base64();
        let known = KnownClientsStore::empty();
        let allowed: Vec<String> = Vec::new();

        /// 一次「服务端窗口激活 + 客户端给定挑战码」的完整握手往返。
        async fn run_window_pair(
            dir: &std::path::Path,
            alice: &IdentityManager,
            bob: &IdentityManager,
            bob_pub: &str,
            known: &KnownClientsStore,
            allowed: &[String],
            allowed_ids: &[String],
            tm: Option<TempModeManager>,
            challenge: &str,
        ) -> (
            Result<SecureChannelGeneric<tokio::net::TcpStream>, HandshakeError>,
            Result<VerifiedDecision, HandshakeError>,
        ) {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().unwrap();
            let server_fut = async move {
                let (stream, _) = listener.accept().await.expect("accept");
                let cfg = Config::default();
                // temp_mode=false（无配置静态旁路）→ 白名单跳过仅靠窗口维度。
                server_accept_handshake(
                    stream,
                    bob,
                    "bob",
                    allowed,
                    allowed_ids,
                    false,
                    false,
                    tm,
                    None,
                    None,
                    known,
                    &cfg,
                )
                .await
            };
            let client_fut = async move {
                let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
                client_handshake_with_confirm_generic(
                    stream,
                    alice,
                    "alice",
                    "alice.local",
                    "desktop",
                    "bob",
                    PinExpectation::exact_from_base64(bob_pub).expect("bob pubkey"),
                    None,
                    challenge,
                )
                .await
            };
            tokio::join!(client_fut, server_fut)
        }

        // 窗口激活 + 临时码 → Accepted（白名单为空也放行）。
        let (client_res, decision) = run_window_pair(
            &dir,
            &alice,
            &bob,
            &bob_pub,
            &known,
            &allowed,
            &[],
            Some(tm.clone()),
            &code,
        )
        .await;
        match decision {
            Ok(VerifiedDecision::Accepted(_)) => {}
            // 穷举保编译）。
            Ok(VerifiedDecision::AcceptedEx { .. }) => {}
            Ok(VerifiedDecision::Rejected(reason)) => {
                panic!("expected Accepted with temp code, got Rejected({})", reason)
            }
            Err(e) => panic!("expected Accepted with temp code, got Err({})", e),
        }
        assert!(client_res.is_ok(), "client must connect with temp code");
        assert!(
            !tm.is_active(),
        );

        // 窗口激活 + 错码 → 拒绝（InvalidMessage(challenge mismatch)，计入握手失败路径）。
        // 失败尝试不消费（窗口仍激活供正确码者使用）。
        let _code2 = tm.enable(300).expect("re-enable for wrong-code case");
        let (client_res, decision) = run_window_pair(
            &dir,
            &alice,
            &bob,
            &bob_pub,
            &known,
            &allowed,
            &[],
            Some(tm.clone()),
            "WRONGCODE",
        )
        .await;
        match decision {
            Err(HandshakeError::InvalidMessage(msg)) => {
                assert_eq!(msg, "challenge mismatch");
            }
            Ok(VerifiedDecision::Rejected(reason)) => {
                panic!(
                    "expected InvalidMessage(challenge mismatch), got Rejected({})",
                    reason
                )
            }
            Ok(VerifiedDecision::AcceptedEx { .. }) => {
                panic!("expected InvalidMessage(challenge mismatch), got AcceptedEx")
            }
            Ok(VerifiedDecision::Accepted(_)) => {
                panic!("expected InvalidMessage(challenge mismatch), got Accepted")
            }
            Err(e) => panic!(
                "expected InvalidMessage(challenge mismatch), got Err({})",
                e
            ),
        }
        assert!(client_res.is_err(), "client must fail with wrong temp code");

        // 窗口期外（None）→ 临时码一律失败，不产生旁路（SRV-TMP-HK-003）。
        let (client_res, decision) = run_window_pair(
            &dir,
            &alice,
            &bob,
            &bob_pub,
            &known,
            &allowed,
            &[],
            None,
            &code,
        )
        .await;
        match decision {
            Ok(VerifiedDecision::Rejected(reason)) => {
                assert!(reason.contains("whitelist"), "reason: {}", reason);
            }
            Ok(VerifiedDecision::AcceptedEx { .. }) => {
                panic!("expected Rejected(whitelist) outside window, got AcceptedEx")
            }
            Ok(VerifiedDecision::Accepted(_)) => {
                panic!("expected Rejected(whitelist) outside window, got Accepted")
            }
            Err(e) => panic!(
                "expected Rejected(whitelist) outside window, got Err({})",
                e
            ),
        }
        assert!(client_res.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// (CLI-TMP-003): 10 位且全字符属于临时码字符集
    /// （A-Z 去 O/I + 2-9 去 0/1）→ 优先提示临时码场景（方案 B 格式判定；
    /// S-20 / F-25：码长 8 → 10）。
    #[test]
    fn test_hint_temp_code_like_uses_temp_wording() {
        let hint =
            connect_failure_challenge_hint("A2B3C4D5E6").expect("hint for 10-char code");
        assert!(hint.contains("临时连接码格式"), "hint: {}", hint);
        assert!(hint.contains("temp-mode"), "hint: {}", hint);
        assert!(hint.contains("0/O/1/I"), "hint: {}", hint);
        assert!(hint.contains("Temp Mode: ACTIVE"), "hint: {}", hint);
        // 全数字/字母混合且长度 10 → 同样命中格式（尽力而为的猜测）。
        let hint2 = connect_failure_challenge_hint("ABCD2345E6").expect("hint");
        assert!(hint2.contains("临时连接码格式"), "hint: {}", hint2);
    }

    /// (CLI-TMP-003): 长度非 10 或含 0/1/O/I 的码 →
    /// 走通用文案（不误判为临时码）。
    #[test]
    fn test_hint_non_temp_format_uses_generic_wording() {
        let hint = connect_failure_challenge_hint("WRONGCODE1").expect("hint");
        assert!(!hint.contains("临时连接码格式"), "hint: {}", hint);
        assert!(hint.contains("固定挑战码错误"), "hint: {}", hint);
        assert!(hint.contains("challenge_code"), "hint: {}", hint);
        // 长度 10 但含被排除字符 0/1 → 通用文案。
        let hint2 = connect_failure_challenge_hint("ABC01234E5").expect("hint");
        assert!(!hint2.contains("临时连接码格式"), "hint: {}", hint2);
        assert!(hint2.contains("固定挑战码错误"), "hint: {}", hint2);
        // 长度 8（旧版临时码长度）→ 通用文案（新码为 10 位，S-20）。
        let hint3 = connect_failure_challenge_hint("A2B3C4D5").expect("hint");
        assert!(!hint3.contains("临时连接码格式"), "hint: {}", hint3);
        assert!(hint3.contains("固定挑战码错误"), "hint: {}", hint3);
    }

    /// (CLI-TMP-003): 未提供挑战码 → 无提示（固定码未配置的
    /// 免校验连接失败多为网络/白名单问题，不误导）。
    #[test]
    fn test_hint_empty_challenge_returns_none() {
        assert!(connect_failure_challenge_hint("").is_none());
    }

    // ---- : 设备 ID 白名单决策表（SRV-IDWL-020/021/023/024） ----


    /// ID 白名单 / 挑战码（挑战码正确与否由调用方控制）。
    async fn run_r59_pair(
        tag: &str,
        enforce: bool,
        allowed_ids: &[String],
        alice: &IdentityManager,
        challenge: &str,
    ) -> (
        Result<SecureChannelGeneric<tokio::net::TcpStream>, HandshakeError>,
        Result<VerifiedDecision, HandshakeError>,
    ) {
        let dir = std::env::temp_dir().join(format!("kirin_policy_r59_{}", tag));
        let bob = gen_identity(&dir, "bob");
        let bob_pub = bob.public_key_base64();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        let expected_challenge = if challenge.is_empty() { None } else { Some(challenge) };
        let server_fut = async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut cfg = Config::default();
            cfg.set_id_whitelist_enforce(enforce);
            // 客户端验签值 "bob"。
            cfg.device.id = "bob".to_string();
            server_accept_handshake(
                stream,
                &bob,
                "bob",
                &[],
                allowed_ids,
                false,
                false,
                None,
                None,
                expected_challenge,
                &KnownClientsStore::empty(),
                &cfg,
            )
            .await
        };
        let client_fut = async move {
            let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            client_handshake_with_confirm_generic(
                stream,
                alice,
                "alice-device",
                "",
                "desktop",
                "bob",
                PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"),
                None,
                challenge,
            )
            .await
        };
        let (client_res, decision) = tokio::join!(client_fut, server_fut);
        let _ = std::fs::remove_dir_all(&dir);
        (client_res, decision)
    }

    /// 挑战码正确即放行；强制维度不生效（同 ID 命中下开/关结果一致，差异只在
    /// 名单外 ID：关=按既有维度判定，开=一律拒）。
    #[tokio::test]
    async fn test_r59_enforce_off_challenge_only_accepted() {
        let dir = std::env::temp_dir().join("kirin_policy_r59_off");
        let alice = gen_identity(&dir, "alice");
        let allowed = vec!["alice-device".to_string()];
        let (client_res, decision) =
            run_r59_pair("off", false, &allowed, &alice, "TEST-CODE").await;
        assert!(
            matches!(decision, Ok(VerifiedDecision::Accepted(_))),
            "enforce off must keep current behavior, got {:?}",
            decision.as_ref().err()
        );
        assert!(client_res.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 收到结构化拒绝码（i18n 文案映射依据）。
    #[tokio::test]
    async fn test_r59_enforce_on_correct_challenge_but_id_denied() {
        let dir = std::env::temp_dir().join("kirin_policy_r59_deny");
        let alice = gen_identity(&dir, "alice");
        let allowed = vec!["other-device".to_string()];
        let (client_res, decision) =
            run_r59_pair("deny", true, &allowed, &alice, "TEST-CODE").await;
        match decision {
            Ok(VerifiedDecision::Rejected(reason)) => {
                assert!(reason.contains("id whitelist enforced"), "reason: {reason}");
            }
            other => panic!("expected Rejected(id whitelist), got {:?}", other.is_err()),
        }
        match &client_res {
            Err(e) => {
                assert_eq!(
                    e.reject_code(),
                    Some(kirin_desk_core::crypto::handshake::REJECT_CODE_ID_WHITELIST),
                    "controller must receive structured reject code, got {e}"
                );
                assert!(
                    handshake_rejected_hint(e).is_some(),
                    "i18n hint must map the reject code"
                );
            }
            Ok(_) => panic!("channel must not be established"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_r59_enforce_on_whitelisted_id_accepted() {
        let dir = std::env::temp_dir().join("kirin_policy_r59_allow");
        let alice = gen_identity(&dir, "alice");
        let allowed = vec!["alice-device".to_string()];
        let (client_res, decision) =
            run_r59_pair("allow", true, &allowed, &alice, "TEST-CODE").await;
        assert!(
            matches!(decision, Ok(VerifiedDecision::Accepted(_))),
            "whitelisted id + correct challenge must be accepted, got {:?}",
            decision.as_ref().err()
        );
        assert!(client_res.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 决策表行「仅 ID 命中」：域名维度未命中但设备 ID 命中 → 放行（新增维度，
    /// 域名行为不变）；GUI/CLI 常规模式与 headless 一致。
    #[tokio::test]
    async fn test_id_whitelist_only_hit_accepted() {
        let dir = std::env::temp_dir().join("kirin_policy_idwl_hit");
        let alice = gen_identity(&dir, "alice");
        let known = KnownClientsStore::empty();
        let allowed_ids = vec!["alice".to_string()];
        // S-01b (F-1)：ID 白名单命中但零凭据 → 拒绝；本用例配置挑战码验证
        // 「ID 白名单 + 凭据齐备」仍放行（SRV-IDWL-020 语义不变）。
        let (client_res, decision) = run_pair(
            "idwl_hit",
            false,
            &known,
            &[],
            &allowed_ids,
            &alice,
            "TEST-CODE",
            // 命中」，客户端必须是 ID 形态自报（此前误用域名形态仍能命中，正是
            // 昵称弱凭据路径，已收紧）。
            "",
        )
        .await;
        assert!(
            matches!(decision, Ok(VerifiedDecision::Accepted(_))),
            "ID whitelist hit must be accepted, got {:?}",
            decision.as_ref().err()
        );
        assert!(client_res.is_ok(), "client handshake should succeed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 决策表行「无人值守 + 仅 ID 命中」：ID 白名单命中 → 自动允许
    /// （UA-ACCEPT-001 扩展至 ID 维度，SRV-IDWL-003）。
    #[tokio::test]
    async fn test_unattended_id_whitelist_accepted() {
        let dir = std::env::temp_dir().join("kirin_policy_unattended_idwl");
        let alice = gen_identity(&dir, "alice");
        let known = KnownClientsStore::empty();
        let allowed_ids = vec!["alice".to_string()];
        // S-01b (F-1)：无人值守 + 仅 ID 白名单命中 + 零凭据 → 拒绝；本用例
        // 配置挑战码验证「白名单 + 凭据齐备」仍自动放行（SRV-IDWL-003 不变）。
        let (client_res, decision) = run_pair(
            "unattended_idwl",
            true,
            &known,
            &[],
            &allowed_ids,
            &alice,
            "TEST-CODE",
            "",
        )
        .await;
        assert!(
            matches!(decision, Ok(VerifiedDecision::Accepted(_))),
            "unattended + ID whitelist hit must auto-accept, got {:?}",
            decision.as_ref().err()
        );
        assert!(client_res.is_ok(), "client handshake should succeed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// IDWL-SEC-001（公钥绑定兜底）: ID 白名单命中**不**跳过 known_clients
    /// 公钥 pin —— known_clients 记录的公钥与网络自报公钥不一致 → 仍拒绝
    /// （`ClientKeyMismatch`），防 ID 伪造冒用。
    #[tokio::test]
    async fn test_id_whitelist_pin_not_bypassed() {
        let dir = std::env::temp_dir().join("kirin_policy_idwl_pin");
        let alice = gen_identity(&dir, "alice");
        let mallory = gen_identity(&dir, "mallory"); // 冒充 alice 的恶意密钥
                                                     // known_clients 记录 alice 的**真实**公钥 → 与网络上来的冒充公钥不一致。
        let mut known = KnownClientsStore::empty();
        known.upsert("alice", &alice.public_key_base64());
        let allowed_ids = vec!["alice".to_string()]; // ID 白名单命中 alice

        let (client_res, decision) =
            run_pair("idwl_pin", false, &known, &[], &allowed_ids, &mallory, "", "").await;
        // 白名单门 → 到达 pin 校验（known 公钥 vs 网络冒充公钥）→ 不匹配拒。
        match decision {
            Err(HandshakeError::ClientKeyMismatch { .. }) => {}
            Ok(_) => panic!("ID whitelist must not bypass public key pin"),
            Err(e) => panic!("expected ClientKeyMismatch, got Err({})", e),
        }
        assert!(
            !matches!(client_res, Ok(_)),
            "channel must not be established"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 决策表行「临时窗口（持临时码）」：窗口激活时跳过域名 + ID 全部白名单
    /// 维度（SRV-TMP-006 扩展，SRV-IDWL-024）——客户端 ID 不在白名单内，持
    /// 临时码仍放行；窗口期外（无 temp_mode）→ 两维白名单恢复强制 → 拒绝。
    #[tokio::test]
    async fn test_temp_window_skips_id_whitelist() {
        use kirin_desk_core::connection::temp_mode::TempModeManager;
        let dir = std::env::temp_dir().join("kirin_policy_temp_skip_idwl");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");
        let tm = TempModeManager::with_state_file(dir.join("temp_mode.json"));
        let code = tm.enable(300).expect("enable");

        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let bob_pub = bob.public_key_base64();
        let known = KnownClientsStore::empty();
        // ID 白名单只放行其他设备 —— alice 不在其中（用于验证"跳过 ID 维度"）。
        let allowed_ids = vec!["other-device".to_string()];
        let allowed: Vec<String> = Vec::new();

        /// 一次「窗口 + ID 白名单（不含 alice）+ 给定挑战码」的握手往返。
        async fn run_skip_pair(
            alice: &IdentityManager,
            bob: &IdentityManager,
            bob_pub: &str,
            known: &KnownClientsStore,
            allowed: &[String],
            allowed_ids: &[String],
            tm: Option<TempModeManager>,
            challenge: &str,
        ) -> (
            Result<SecureChannelGeneric<tokio::net::TcpStream>, HandshakeError>,
            Result<VerifiedDecision, HandshakeError>,
        ) {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().unwrap();
            let server_fut = async move {
                let (stream, _) = listener.accept().await.expect("accept");
                let cfg = Config::default();
                server_accept_handshake(
                    stream,
                    bob,
                    "bob",
                    allowed,
                    allowed_ids,
                    false,
                    false,
                    tm,
                    None,
                    None,
                    known,
                    &cfg,
                )
                .await
            };
            let client_fut = async move {
                let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
                client_handshake_with_confirm_generic(
                    stream,
                    alice,
                    "alice",
                    "alice.local",
                    "desktop",
                    "bob",
                    PinExpectation::exact_from_base64(bob_pub).expect("bob pubkey"),
                    None,
                    challenge,
                )
                .await
            };
            tokio::join!(client_fut, server_fut)
        }

        // 窗口激活 + 临时码 → 放行（ID 维度被跳过）。
        let (client_res, decision) = run_skip_pair(
            &alice,
            &bob,
            &bob_pub,
            &known,
            &allowed,
            &allowed_ids,
            Some(tm.clone()),
            &code,
        )
        .await;
        match decision {
            Ok(VerifiedDecision::Accepted(_)) => {}
            Ok(VerifiedDecision::AcceptedEx { .. }) => {}
            Ok(VerifiedDecision::Rejected(reason)) => {
                panic!(
                    "temp window must skip ID whitelist, got Rejected({})",
                    reason
                )
            }
            Err(e) => panic!("expected Accepted inside window, got Err({})", e),
        }
        assert!(client_res.is_ok(), "client must connect with temp code");

        // 窗口期外（None）→ 两维白名单恢复强制：ID 未命中 → 拒绝。
        let (client_res, decision) = run_skip_pair(
            &alice,
            &bob,
            &bob_pub,
            &known,
            &allowed,
            &allowed_ids,
            None,
            &code,
        )
        .await;
        match decision {
            Ok(VerifiedDecision::Rejected(reason)) => {
                assert!(reason.contains("whitelist"), "reason: {}", reason);
            }
            Ok(VerifiedDecision::AcceptedEx { .. }) => {
                panic!("outside window, ID whitelist must be enforced")
            }
            Ok(VerifiedDecision::Accepted(_)) => {
                panic!("outside window, ID whitelist must be enforced")
            }
            Err(e) => panic!("expected Rejected outside window, got Err({})", e),
        }
        assert!(client_res.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }


    /// enforce 开关 + 双白名单（`run_pair` 的固定 "alice"/"alice.local" 自报
    /// 不适用于矩阵行）。
    async fn run_r74e_pair(
        tag: &str,
        enforce: bool,
        client_id: &str,
        client_domain: &str,
        allowed: &[String],
        allowed_ids: &[String],
        alice: &IdentityManager,
        challenge: &str,
    ) -> (
        Result<SecureChannelGeneric<tokio::net::TcpStream>, HandshakeError>,
        Result<VerifiedDecision, HandshakeError>,
    ) {
        let dir = std::env::temp_dir().join(format!("kirin_policy_r74e_{tag}"));
        let bob = gen_identity(&dir, "bob");
        let bob_pub = bob.public_key_base64();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        let expected_challenge = if challenge.is_empty() { None } else { Some(challenge) };
        // ID 形态时把测试服务端 `device.id` 钉为客户端验签值 "bob"。
        let domain_empty = client_domain.is_empty();
        let client_id = client_id.to_string();
        let client_domain = client_domain.to_string();
        let server_fut = async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut cfg = Config::default();
            cfg.set_id_whitelist_enforce(enforce);
            if domain_empty {
                cfg.device.id = "bob".to_string();
            }
            server_accept_handshake(
                stream,
                &bob,
                "bob",
                allowed,
                allowed_ids,
                false,
                false,
                None,
                None,
                expected_challenge,
                &KnownClientsStore::empty(),
                &cfg,
            )
            .await
        };
        let client_fut = async move {
            let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            client_handshake_with_confirm_generic(
                stream,
                alice,
                &client_id,
                &client_domain,
                "desktop",
                "bob",
                PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"),
                None,
                challenge,
            )
            .await
        };
        let (client_res, decision) = tokio::join!(client_fut, server_fut);
        let _ = std::fs::remove_dir_all(&dir);
        (client_res, decision)
    }

    /// 昵称弱凭据匹配）——域名形态客户端即使 client_id 与 ID 白名单条目精确
    /// 相等也不得视为白名单命中（修复前：ID 维命中 → 免审批放行，昵称是
    /// 连接方自报弱凭据）。
    #[tokio::test]
    async fn test_r74e_nonempty_domain_never_matches_id_whitelist() {
        let dir = std::env::temp_dir().join("kirin_policy_r74e_idform");
        let alice = gen_identity(&dir, "alice");
        let allowed_ids = vec!["alice".to_string()]; // 与客户端自报 client_id 精确相等
        let (client_res, decision) = run_r74e_pair(
            "idform",
            false,
            "alice",
            "alice.local",
            &[],
            &allowed_ids,
            &alice,
            "TEST-CODE",
        )
        .await;
        match decision {
            Ok(VerifiedDecision::Rejected(reason)) => {
                assert!(reason.contains("whitelist"), "reason: {reason}");
            }
            Ok(VerifiedDecision::AcceptedEx { .. }) => {
                panic!("domain-form client must NOT match the ID whitelist (weak-credential path)")
            }
            Ok(VerifiedDecision::Accepted(_)) => {
                panic!("domain-form client must NOT match the ID whitelist (weak-credential path)")
            }
            Err(e) => panic!("expected Rejected(whitelist), got Err({e})"),
        }
        assert!(client_res.is_err(), "channel must not be established");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 魔值本身或 `*.local` 通配后，自报魔值的任意 IP 客户端仍不得视为
    /// 白名单命中（修复前：域名维命中 → 免审批；魔值不是凭据）。
    #[tokio::test]
    async fn test_r74e_gui_magic_domain_excluded_from_whitelist() {
        let dir = std::env::temp_dir().join("kirin_policy_r74e_magic");
        let alice = gen_identity(&dir, "alice");
        let allowed = vec!["*.local".to_string(), "gui-client.local".to_string()];
        let (client_res, decision) = run_r74e_pair(
            "magic",
            false,
            "nick",
            "gui-client.local",
            &allowed,
            &[],
            &alice,
            "TEST-CODE",
        )
        .await;
        match decision {
            Ok(VerifiedDecision::Rejected(reason)) => {
                // reason 必为「白名单未命中」（headless 无审批），而非
                // 「no credentials」——证明魔值未命中域名维。
                assert!(reason.contains("whitelist"), "reason: {reason}");
            }
            Ok(VerifiedDecision::AcceptedEx { .. }) => panic!("magic value must NOT match domain whitelist"),
            Ok(VerifiedDecision::Accepted(_)) => panic!("magic value must NOT match domain whitelist"),
            Err(e) => panic!("expected Rejected(whitelist), got Err({e})"),
        }
        assert!(client_res.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 不命中**（弱凭据消灭）→ enforce 硬拒（`REJECT_CODE_ID_WHITELIST`）
    /// 不得作用于该形态——非旁路下其拒绝只能来自「未命中白名单」路径
    /// （headless 无审批通道 → `REJECT_CODE_APPROVAL_DECLINED`；GUI 侧则进
    /// 审批弹窗 = 用户矩阵「ID 模式被控端 + GUI 客户端 + ID 白名单开 →
    /// NeedsApproval」）。修复前：非空域名整体豁免准入体制，且昵称可命中
    /// ID 维自动免审批（认证强度降级，用户实测确认）。
    #[tokio::test]
    async fn test_r74e_enforce_domain_form_not_hard_rejected() {
        let dir = std::env::temp_dir().join("kirin_policy_r74e_enforce");
        let alice = gen_identity(&dir, "alice");
        let allowed_ids = vec!["other-device".to_string()];
        let (client_res, decision) = run_r74e_pair(
            "enforce",
            true,
            "nick",
            "gui-client.local",
            &[],
            &allowed_ids,
            &alice,
            "TEST-CODE",
        )
        .await;
        match decision {
            Ok(VerifiedDecision::Rejected(reason)) => {
                assert!(
                    !reason.contains("id whitelist enforced"),
                    "domain-form client must NOT be hard-rejected by the ID whitelist \
                     enforce (it can never match it), reason: {reason}"
                );
                assert!(
                    reason.contains("not in whitelist"),
                    "expected the generic not-in-whitelist path, reason: {reason}"
                );
            }
            Ok(VerifiedDecision::AcceptedEx { .. }) => {
                panic!("domain-form client must NOT be auto-accepted")
            }
            Ok(VerifiedDecision::Accepted(_)) => {
                panic!("domain-form client must NOT be auto-accepted")
            }
            Err(e) => panic!("expected Rejected, got Err({e})"),
        }
        match &client_res {
            Err(e) => {
                assert_ne!(
                    e.reject_code(),
                    Some(REJECT_CODE_ID_WHITELIST),
                    "domain-form client must NOT receive the ID-whitelist reject code, got {e}"
                );
                assert_eq!(
                    e.reject_code(),
                    Some(REJECT_CODE_APPROVAL_DECLINED),
                    "headless no-approval path code, got {e}"
                );
            }
            Ok(_) => panic!("channel must not be established"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod r67_tests {
    use super::*;
    use kirin_desk_core::crypto::ed25519::IdentityManager;
    use kirin_desk_core::crypto::handshake::{
        client_handshake_with_confirm_generic, PinExpectation, SecureChannelGeneric,
    };

    fn gen_identity(dir: &std::path::Path, name: &str) -> IdentityManager {
        IdentityManager::generate(dir.join(name)).expect("generate identity")
    }

    // 可读化——此前裸 close → 客户端只报 early eof）。矩阵：错挑战码 /
    // 昵称不匹配 / 零凭据 / headless 无审批。

    /// run_pair 变体：客户端与服务端挑战码可不同（制造 mismatch），且服务端
    /// 可带期望昵称（客户端固定自报 "alice"）。
    async fn run_pair_r67(
        tag: &str,
        known: &KnownClientsStore,
        allowed: &[String],
        client_challenge: &str,
        server_challenge: Option<&str>,
        expected_nickname: Option<&str>,
    ) -> Result<SecureChannelGeneric<tokio::net::TcpStream>, HandshakeError> {
        let dir = std::env::temp_dir().join(format!("kirin_policy_r67_{tag}"));
        let alice = gen_identity(&dir, "alice");
        let bob = gen_identity(&dir, "bob");
        let bob_pub = bob.public_key_base64();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();

        let server_fut = async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let cfg = Config::default();
            server_accept_handshake(
                stream, &bob, "bob", allowed, &[], false, false, None,
                expected_nickname, server_challenge, known, &cfg,
            )
            .await
        };
        let client_fut = async move {
            let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            client_handshake_with_confirm_generic(
                stream, &alice, "alice", "alice.local", "desktop", "bob",
                PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"),
                None, client_challenge,
            )
            .await
        };
        let (client_res, _decision) = tokio::join!(client_fut, server_fut);
        let _ = std::fs::remove_dir_all(&dir);
        client_res
    }

    /// （而非 early eof），且 `handshake_rejected_hint` 映射出可读文案。
    #[tokio::test]
    async fn test_r67_challenge_mismatch_structured_reject() {
        let known = KnownClientsStore::empty();
        let allowed = vec!["alice.local".to_string()];
        let res = run_pair_r67(
            "chal", &known, &allowed, "WRONG-CODE", Some("RIGHT-CODE"), None,
        )
        .await;
        match res {
            Err(e) => {
                assert_eq!(e.reject_code(), Some("challenge_mismatch"), "err: {e}");
                assert!(handshake_rejected_hint(&e).is_some(), "must map to readable hint");
            }
            Ok(_) => panic!("channel must not be established on wrong challenge"),
        }
    }

    #[tokio::test]
    async fn test_r67_nickname_mismatch_structured_reject() {
        let known = KnownClientsStore::empty();
        let allowed = vec!["alice.local".to_string()];
        let res = run_pair_r67(
            "nick", &known, &allowed, "CODE", Some("CODE"), Some("expected-nick"),
        )
        .await;
        match res {
            Err(e) => {
                assert_eq!(e.reject_code(), Some("nickname_mismatch"), "err: {e}");
                assert!(handshake_rejected_hint(&e).is_some());
            }
            Ok(_) => panic!("channel must not be established on nickname mismatch"),
        }
    }

    /// 结构化拒绝码 `credentials_required`（fail-closed 路径同样可读）。
    #[tokio::test]
    async fn test_r67_zero_credentials_structured_reject() {
        let known = KnownClientsStore::empty();
        let allowed = vec!["alice.local".to_string()];
        let res = run_pair_r67("nocred", &known, &allowed, "", None, None).await;
        match res {
            Err(e) => {
                assert_eq!(e.reject_code(), Some("credentials_required"), "err: {e}");
                assert!(handshake_rejected_hint(&e).is_some());
            }
            Ok(_) => panic!("zero-credential channel must not be established"),
        }
    }

    /// 结构化拒绝码 `approval_declined`（此前裸 close → early eof）。
    #[tokio::test]
    async fn test_r67_headless_no_approval_structured_reject() {
        let known = KnownClientsStore::empty();
        let res = run_pair_r67("noappr", &known, &[], "", None, None).await;
        match res {
            Err(e) => {
                assert_eq!(e.reject_code(), Some("approval_declined"), "err: {e}");
                assert!(handshake_rejected_hint(&e).is_some());
            }
            Ok(_) => panic!("non-whitelisted headless channel must not be established"),
        }
    }


    use kirin_desk_core::crypto::handshake::{
        HandshakeError as He, REJECT_CODE_APPROVAL_DECLINED, REJECT_CODE_APPROVAL_TIMEOUT,
    };
    use kirin_desk_core::network::tcp::TcpError;
    use std::io::{Error as IoErr, ErrorKind as K};

    /// 超时 → 离线类；本地错误/协议错误/结构化拒绝码 → 不归类（原文案/按码
    /// 文案优先）。
    #[test]
    fn test_r78a_handshake_offline_hint_classification() {
        // 对端 EOF（early eof——B③ 实测形态：服务端审批中停止/切模式）。
        let eof = He::Tcp(TcpError::Io(IoErr::from(K::UnexpectedEof)));
        assert!(handshake_offline_hint(&eof).is_some(), "early eof must classify as peer offline");
        let reset = He::Tcp(TcpError::Io(IoErr::from(K::ConnectionReset)));
        assert!(handshake_offline_hint(&reset).is_some(), "connection reset must classify as offline");
        let refused = He::Tcp(TcpError::Connect {
            remote: "10.0.0.1:59990".parse().unwrap(),
            source: IoErr::from(K::ConnectionRefused),
        });
        assert!(handshake_offline_hint(&refused).is_some(), "dial refused = offline/unreachable");
        let dial_timeout = He::Tcp(TcpError::Timeout {
            remote: "10.0.0.1:59990".parse().unwrap(),
        });
        assert!(handshake_offline_hint(&dial_timeout).is_some(), "dial timeout = unreachable");
        let hs_timeout = He::Timeout;
        assert!(handshake_offline_hint(&hs_timeout).is_some(), "handshake timeout = no response");
        // 本地帧超长（非对端离线，不误分类）。
        let too_large = He::Tcp(TcpError::MessageTooLarge {
            len: 1 << 32,
            max: 16 << 20,
        });
        assert!(handshake_offline_hint(&too_large).is_none(), "local frame-limit error must not be offline");
        // 协议/信任类（签名失败）——非传输错误，原文案即语义。
        let sig = He::SignatureVerificationFailed;
        assert!(handshake_offline_hint(&sig).is_none(), "protocol error must not be classified as offline");
        // 结构化拒绝码 → 不归离线（「被拒/超时」按码文案更精确）。
        let rejected = He::Rejected(format!("{}|x", REJECT_CODE_APPROVAL_TIMEOUT));
        assert!(handshake_offline_hint(&rejected).is_none(), "reject code takes priority over offline");
    }

    /// 超时/拒绝走按码文案；协议类保留原文案。
    #[test]
    fn test_r78a_handshake_failure_status_classification() {
        let eof = He::Tcp(TcpError::Io(IoErr::from(K::UnexpectedEof)));
        let s = handshake_failure_status(&eof);
        assert!(s.starts_with("Handshake FAILED\n"), "{s}");
        assert!(s.contains(&t!("connect.error.peer_offline")), "peer offline text expected: {s}");
        assert!(
            !s.to_lowercase().contains("early eof") && !s.contains("I/O error"),
            "raw transport error must not surface: {s}"
        );
        let timeout = He::Rejected(format!("{}|x", REJECT_CODE_APPROVAL_TIMEOUT));
        assert!(
            handshake_failure_status(&timeout).contains(&t!("connect.error.approval_timeout")),
            "approval_timeout code must map to its i18n text"
        );
        let declined = He::Rejected(format!("{}|x", REJECT_CODE_APPROVAL_DECLINED));
        assert!(
            handshake_failure_status(&declined).contains(&t!("connect.error.approval_declined")),
            "approval_declined code must map to its i18n text"
        );
        let sig = He::SignatureVerificationFailed;
        assert_eq!(
            handshake_failure_status(&sig),
            "Handshake FAILED: Peer signature verification failed"
        );
    }

    /// 泄漏进状态行）；②详提示 = 完整分类文案 + 3 条排查提示（1)/2)/3)
    /// 全在）；③「对方离线」类同构拆分。
    ///
    /// 语言卫生：`t!` 走进程级 CURRENT（并行测试可切语言）→ 持
    /// `r92ti_global_lock` 同锁域 + 钉中文基线（泄漏 = 进程默认态，无害）。
    #[test]
    fn test_r109_handshake_failure_parts_split() {
        let _g = crate::cli::r92ti_global_lock::lock_global();
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        // approval_timeout（用户 2026-09-11 指认形态）+ 固定挑战码。
        let timeout = He::Rejected(format!("{}|x", REJECT_CODE_APPROVAL_TIMEOUT));
        let full = t!("connect.error.approval_timeout").to_string();
        let hint = connect_failure_challenge_hint("A2B3C4D5E6").expect("fixed-code hint");
        let p = handshake_failure_parts(&timeout, "A2B3C4D5E6");

        // ① 短状态 = "Handshake FAILED" + 分类文案首句：≤2 行、不含排查
        //    提示段（1)/2)/3) 与提示正文均不得进内联状态行）。
        assert!(p.short.starts_with("Handshake FAILED\n"), "{:?}", p.short);
        assert_eq!(p.short.lines().count(), 2, "short must be <=2 lines: {:?}", p.short);
        for probe in ["1)", "2)", "3)", "temp-mode", "无人值守"] {
            assert!(!p.short.contains(probe), "short must not carry hint {probe:?}: {:?}", p.short);
        }
        assert_eq!(
            p.short,
            format!("Handshake FAILED\n{}", first_sentence(&full)),
            "short = FAILED + first sentence: {:?}",
            p.short
        );
        // 首句严格短于全句（「——对策」后半截断）。
        assert!(
            first_sentence(&full).len() < full.len(),
            "first sentence must be shorter than full: {}",
            first_sentence(&full)
        );

        // ② 详提示 = 完整分类文案 + 3 条排查提示（1)/2)/3) 全在；完整后半
        //    （对策句「审批提示音」）在详情中保留。
        let d = p.detail.as_deref().expect("detail expected");
        assert!(d.starts_with(&full), "detail must start with full classification: {d}");
        assert!(d.contains(&hint), "detail must carry the challenge hint: {d}");
        for probe in ["1)", "2)", "3)"] {
            assert!(d.contains(probe), "detail must contain item {probe}: {d}");
        }
        assert!(d.contains("审批提示音"), "detail must keep full countermeasure: {d}");

        // ③ 对方离线类同构拆分（临时码形态 → 临时提示三条）。
        let eof = He::Tcp(TcpError::Io(IoErr::from(K::UnexpectedEof)));
        let p2 = handshake_failure_parts(&eof, "ABCD2345E6");
        assert_eq!(p2.short.lines().count(), 2, "{:?}", p2.short);
        assert!(!p2.short.contains("1)"), "short must not carry hint: {:?}", p2.short);
        let d2 = p2.detail.as_deref().expect("detail expected");
        assert!(d2.starts_with(t!("connect.error.peer_offline")), "{d2}");
        assert!(d2.contains("temp-mode"), "temp-like code hint expected: {d2}");
        crate::i18n::set_lang(crate::i18n::Lang::Zh); // 复位（=进程默认态）
    }

    /// 原单行串（既有行为零变化）；无挑战码 → 无详情（弹窗入口不渲染）；
    /// 带挑战码 → 详情 = 3 条排查提示（短状态不变）。
    #[test]
    fn test_r109_handshake_failure_parts_uncategorized_fallback() {
        let sig = He::SignatureVerificationFailed;
        // 无挑战码：short = 原文案，detail = None。
        let p = handshake_failure_parts(&sig, "");
        assert_eq!(
            p.short, "Handshake FAILED: Peer signature verification failed",
            "{:?}", p.short
        );
        assert!(p.detail.is_none(), "no classification + no code → no detail: {:?}", p.detail);
        // 带挑战码：详情 = 3 条排查提示（短状态与无码时一致）。
        let p2 = handshake_failure_parts(&sig, "WRONGCODE1");
        assert_eq!(p2.short, p.short, "short must not change with challenge");
        let d = p2.detail.as_deref().expect("challenge hint expected");
        for probe in ["1)", "2)", "3)"] {
            assert!(d.contains(probe), "hint items expected: {d}");
        }
        assert!(!d.contains("Handshake FAILED"), "detail = hint only: {d}");
    }

    /// 断点前为空回落全句）。
    #[test]
    fn test_r109_first_sentence_matrix() {
        // zh 双破折号断点。
        assert_eq!(
            first_sentence("对方审批超时：限时内无人审批——请重试"),
            "对方审批超时：限时内无人审批"
        );
        // en ` — ` 断点。
        assert_eq!(
            first_sentence("Approval timed out on the target: it closed — verify, then retry"),
            "Approval timed out on the target: it closed"
        );
        // 无断点 → 全句（trim）。
        assert_eq!(
            first_sentence("  对方拒绝了连接请求  "),
            "对方拒绝了连接请求"
        );
        // 断点前为空 → 回落全句（绝不产空串）。
        assert_eq!(first_sentence("——请重试"), "——请重试");
        assert_eq!(first_sentence("  "), "");
        // 真实键：zh/en 两语 approval_timeout 均截到现象前半（断点不残留）。
        let _g = crate::cli::r92ti_global_lock::lock_global();
        for lang in [crate::i18n::Lang::Zh, crate::i18n::Lang::En] {
            let full = crate::i18n::tr_lang(lang, "connect.error.approval_timeout");
            let first = first_sentence(full);
            assert!(
                first.len() < full.len() && !first.is_empty(),
                "{lang:?} first sentence expected shorter: {first}"
            );
            assert!(!first.contains("——") && !first.contains(" — "), "{lang:?} separator residue: {first}");
        }
    }

    #[test]
    fn test_r78a_approval_timeout_hint_and_i18n_paired() {
        let err = He::Rejected(format!("{}|detail-x", REJECT_CODE_APPROVAL_TIMEOUT));
        let h = handshake_rejected_hint(&err).expect("approval_timeout must map to localized text");
        assert_eq!(h, t!("connect.error.approval_timeout").to_string());
        for key in ["connect.error.approval_timeout", "connect.error.peer_offline"] {
            let entry = crate::i18n::ALL
                .iter()
                .flat_map(|table| table.iter())
                .find(|e| e.0 == key)
                .unwrap_or_else(|| panic!("{key} key missing from i18n tables"));
            assert!(
                !entry.1.is_empty() && !entry.2.is_empty(),
                "{key} must be zh/en paired"
            );
        }
    }


    /// （i18n 零硬编码锁）+ 与既有拒绝码分类互不串扰（仍属「被拒」类、
    /// 不归「离线」类）。
    #[test]
    fn test_r87_unattended_unknown_hint_and_i18n_paired() {
        let err = He::Rejected(format!(
            "{}|{}",
            REJECT_CODE_UNATTENDED_UNKNOWN, "detail-x"
        ));
        let h = handshake_rejected_hint(&err)
            .expect("unattended_unknown must map to localized text");
        assert_eq!(h, t!("connect.error.unattended_unknown").to_string());
        // 分类互斥：独立码不得落入离线类（「被拒」语义优先）。
        assert!(
            handshake_offline_hint(&err).is_none(),
            "unattended_unknown must not classify as peer-offline"
        );
        // i18n 键存在性 + zh/en 成对（含可操作提示关键信息）。
        for key in [
            "connect.error.unattended_unknown",
            "session.reconnect.lost_no_frame",
            "dashboard.temp.single_use_note",
        ] {
            let entry = crate::i18n::ALL
                .iter()
                .flat_map(|table| table.iter())
                .find(|e| e.0 == key)
                .unwrap_or_else(|| panic!("{key} key missing from i18n tables"));
            assert!(!entry.1.is_empty() && !entry.2.is_empty(), "{key} must be zh/en paired");
        }
        let zh = crate::i18n::tr_lang(crate::i18n::Lang::Zh, "connect.error.unattended_unknown");
        assert!(
            zh.contains("无人值守") && zh.contains("白名单"),
            "zh text must be actionable (unattended + whitelist hint): {zh}"
        );
    }


    ///
    /// - ID 模式（空域名）：绑定**本端设备 ID**（`registration_device_id`
    ///   单一来源——显式 `[tunnel] device_id`（空白视为未填写）优先，否则
    ///   `[device] id`）；
    /// - 非空域名（IP/域名模式）：维持昵称绑定（零行为变化，不受设备 ID /
    ///   tunnel 配置影响）。
    #[test]
    fn test_r81a_response_signature_bind_id_decision() {
        // ID 模式：显式 [tunnel] device_id 优先。
        assert_eq!(
            response_signature_bind_id("", Some("EXPLICIT-1"), "CFG-2", "nick"),
            "EXPLICIT-1"
        );
        // 显式值纯空白 = 未填写 → 回落 [device] id。
        assert_eq!(
            response_signature_bind_id("", Some("  "), "CFG-2", "nick"),
            "CFG-2"
        );
        assert_eq!(
            response_signature_bind_id("", None, "CFG-2", "nick"),
            "CFG-2"
        );
        // 非空域名：昵称绑定（ID 模式语义不越界到 IP/域名模式）。
        assert_eq!(
            response_signature_bind_id("gui-client.local", None, "CFG-2", "nick"),
            "nick"
        );
        assert_eq!(
            response_signature_bind_id("example.com", Some("EXPLICIT-1"), "CFG-2", "nick"),
            "nick"
        );
    }

    /// 的昵称参数 `server_nickname` 可故意 ≠ 设备 ID（修复前失败形态）；
    /// `cfg` 为服务端磁盘配置快照（`device.id` / `tunnel.device_id`）。
    /// 返回 (客户端握手结果, 服务端策略决策)。
    async fn run_pair_r81a(
        tag: &str,
        cfg: &Config,
        server_nickname: &str,
        client_server_id: &str,
        client_domain: &str,
        alice: &IdentityManager,
    ) -> (
        Result<SecureChannelGeneric<tokio::net::TcpStream>, HandshakeError>,
        Result<VerifiedDecision, HandshakeError>,
    ) {
        let dir = std::env::temp_dir().join(format!("kirin_policy_r81a_{}", tag));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bob = gen_identity(&dir, "bob");
        let bob_pub = bob.public_key_base64();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();

        let cfg = cfg.clone();
        let server_nickname = server_nickname.to_string();
        let alice_pub = alice.public_key_base64();
        let server_fut = async move {
            let (stream, _) = listener.accept().await.expect("accept");
            // UA-ACCEPT-001：known_clients 命中 → 自动允许——穿过 headless
            // payload 的 bind_id，白名单层非本测试对象）。
            let mut known = KnownClientsStore::empty();
            known.upsert("alice", &alice_pub);
            server_accept_handshake(
                stream,
                &bob,
                &server_nickname,
                &[],
                &[],
                false,
                true,
                None,
                None,
                Some("R81A-CODE"),
                &known,
                &cfg,
            )
            .await
        };
        let client_domain = client_domain.to_string();
        let client_server_id = client_server_id.to_string();
        let client_fut = async move {
            let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            client_handshake_with_confirm_generic(
                stream,
                alice,
                "alice",
                &client_domain,
                "desktop",
                &client_server_id,
                // pin/注册密钥源同源断言（同一 bob 身份）。
                PinExpectation::exact_from_base64(&bob_pub).expect("bob pubkey"),
                None,
                "R81A-CODE",
            )
            .await
        };
        let (client_res, decision) = tokio::join!(client_fut, server_fut);
        let _ = std::fs::remove_dir_all(&dir);
        (client_res, decision)
    }

    /// 验签通过。修复前服务端恒绑昵称、客户端以拨号 ID 验签 →
    /// ID 模式失败 + IP 模式 4ms 成功即此形态）。
    #[tokio::test]
    async fn test_r81a_id_mode_bind_device_id_e2e() {
        let dir = std::env::temp_dir().join("kirin_policy_r81a_match");
        let alice = gen_identity(&dir, "alice");
        let mut cfg = Config::default();
        cfg.device.id = "HD-TEST1234".to_string();
        cfg.tunnel.device_id = None;
        // 昵称刻意 ≠ 设备 ID（修复前失败条件）。
        let (client_res, decision) =
            run_pair_r81a("match", &cfg, "bob-nick", "HD-TEST1234", "", &alice).await;
        assert!(
            matches!(decision, Ok(VerifiedDecision::Accepted(_))),
            "server should accept: {:?}",
            decision
        );
        assert!(
            client_res.is_ok(),
            "ID 模式（拨号 ID == 本设备 ID）验签必须通过: {:?}",
            client_res.err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 客户端验签失败（身份绑定不放宽；服务端照常完成应答，错误在客户端
    /// 侧显性化——不产生任何放行路径）。
    #[tokio::test]
    async fn test_r81a_id_mode_mismatched_id_fail_closed() {
        let dir = std::env::temp_dir().join("kirin_policy_r81a_mismatch");
        let alice = gen_identity(&dir, "alice");
        let mut cfg = Config::default();
        cfg.device.id = "HD-TEST1234".to_string();
        cfg.tunnel.device_id = None;
        let (client_res, decision) =
            run_pair_r81a("mismatch", &cfg, "bob-nick", "HD-OTHER9999", "", &alice).await;
        assert!(
            matches!(decision, Ok(VerifiedDecision::Accepted(_))),
            "server side completes respond: {:?}",
            decision
        );
        assert!(
            matches!(client_res, Err(HandshakeError::SignatureVerificationFailed)),
            "拨号 ID != 本设备 ID 必须 fail-closed 验签失败: {:?}",
            client_res.err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 昵称验签通过；以设备 ID 验签则失败（绑定面未被扩大）。
    #[tokio::test]
    async fn test_r81a_ip_mode_nickname_binding_unchanged() {
        let dir = std::env::temp_dir().join("kirin_policy_r81a_ipmode");
        let alice = gen_identity(&dir, "alice");
        let mut cfg = Config::default();
        cfg.device.id = "HD-TEST1234".to_string();
        cfg.tunnel.device_id = None;
        // 正向：昵称对昵称 → 通过（既有 IP 模式行为零变化）。
        let (client_res, decision) =
            run_pair_r81a("ipmode", &cfg, "bob-nick", "bob-nick", "gui-client.local", &alice).await;
        assert!(matches!(decision, Ok(VerifiedDecision::Accepted(_))));
        assert!(
            client_res.is_ok(),
            "IP 模式昵称绑定应不受影响: {:?}",
            client_res.err()
        );
        // 负向对照：IP 模式客户端若以设备 ID 验签 → 必败（绑定仍是昵称，
        // 未被设备 ID 越界覆盖）。
        let (client_res, _decision) =
            run_pair_r81a("ipmode_neg", &cfg, "bob-nick", "HD-TEST1234", "gui-client.local", &alice).await;
        assert!(
            matches!(client_res, Err(HandshakeError::SignatureVerificationFailed)),
            "IP 模式绑定仍为昵称（拨号 ID 不一致 → 验签失败）: {:?}",
            client_res.err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }


    /// 2.5s 点火等待提示、首连提示分叉、响应已收→验签相位优先、终态恢复
    /// 控件可用。
    #[test]
    fn r81h_connect_wait_decision_table() {
        use crate::policy::{
            connect_wait_decision, ConnectWaitDecision, CONNECT_WAIT_HINT_DELAY,
        };
        let d = connect_wait_decision(false, Some(CONNECT_WAIT_HINT_DELAY * 2), true, true);
        assert_eq!(
            d,
            ConnectWaitDecision {
                controls_enabled: true,
                status_key: None,
                show_timer: false,
                hint_key: None,
            }
        );
        // ② 进行态早期（<2.5s）→ 置灰 + 原进度串（status_key=None）+ 无提示。
        let d = connect_wait_decision(
            true,
            Some(std::time::Duration::from_millis(1500)),
            false,
            false,
        );
        assert_eq!(
            d,
            ConnectWaitDecision {
                controls_enabled: false,
                status_key: None,
                show_timer: false,
                hint_key: None,
            }
        );
        // ③ 进行态 + 未计时（elapsed=None，刚进入）→ 安全侧按早相位：置灰不点火。
        let d = connect_wait_decision(true, None, false, false);
        assert!(!d.controls_enabled);
        assert_eq!(d.status_key, None);
        assert!(!d.show_timer);
        assert_eq!(d.hint_key, None);
        // ④ 进行态 ≥2.5s + 未收到响应（非首连）→ 等待提示 + 计时 + 通用提示。
        let d = connect_wait_decision(true, Some(CONNECT_WAIT_HINT_DELAY), false, false);
        assert!(!d.controls_enabled);
        assert_eq!(d.status_key, Some("connect.status.waiting_peer"));
        assert!(d.show_timer);
        assert_eq!(d.hint_key, Some("connect.status.waiting_peer_hint"));
        // ⑤ 同相位 + 首连 → 提示行追加指纹确认预告（安全红线不可免的预告）。
        let d = connect_wait_decision(true, Some(CONNECT_WAIT_HINT_DELAY * 10), false, true);
        assert_eq!(d.status_key, Some("connect.status.waiting_peer"));
        assert!(d.show_timer);
        assert_eq!(d.hint_key, Some("connect.status.waiting_peer_hint_first"));
        // ⑥ 响应已收到（任意 elapsed，哪怕未到 2.5s）→ 验签相位优先于等待
        //    提示（确认框是主呈现，不再误导「等待批准」）。
        let d = connect_wait_decision(true, Some(CONNECT_WAIT_HINT_DELAY * 5), true, true);
        assert!(!d.controls_enabled);
        assert_eq!(d.status_key, Some("connect.status.verifying"));
        assert!(!d.show_timer);
        assert_eq!(d.hint_key, None);
        // ⑦ 边界：恰好 2.5s = 点火（≥ 语义）。
        let d = connect_wait_decision(true, Some(CONNECT_WAIT_HINT_DELAY), false, false);
        assert_eq!(d.status_key, Some("connect.status.waiting_peer"));
    }

    /// waiting_approval **双语**串均判 busy（旧英文前缀匹配在 zh 下失配=
    /// 按钮不置灰根因）；终态/空串不判 busy。
    #[test]
    fn r81h_is_connect_status_busy_matrix() {
        use crate::policy::is_connect_status_busy;
        // busy 前缀（英文进度快照约定，线程写入）。
        for s in [
            "Connecting: 192.168.1.79 ...",
            "Connecting: 192.168.1.79:59990 ...",
            "Resolving: HD-62EC5BC9 (relay 8.133.174.128:7000) ...",
            "Discovering: my-pc.example.com ...",
            "Handshaking: ...",
            "[shell] Connecting: 192.168.1.79 ...",
        ] {
            assert!(is_connect_status_busy(s), "should be busy: {s:?}");
        }
        // 命中（语言无关：写入时语言 ≠ 当前语言亦不误判）。
        let zh = crate::i18n::tr_lang(crate::i18n::Lang::Zh, "connect.status.waiting_approval");
        let en = crate::i18n::tr_lang(crate::i18n::Lang::En, "connect.status.waiting_approval");
        assert!(!zh.is_empty() && !en.is_empty());
        assert!(is_connect_status_busy(zh), "zh waiting_approval should be busy");
        assert!(is_connect_status_busy(en), "en waiting_approval should be busy");
        // 终态/错误/空串 → 非 busy（按钮恢复可用）。
        for s in [
            "",
            "Connected to bob@192.168.1.79 (transport: TCP)",
            "TCP connect FAILED: 192.168.1.79\n对方离线：…",
            "Handshake FAILED\n对方审批超时：…",
            "等待对方审批超时（长时间无响应）——按钮已恢复，请重试",
        ] {
            assert!(!is_connect_status_busy(s), "should NOT be busy: {s:?}");
        }
    }

    /// 串变化保持（不重置）/终态清零。
    #[test]
    fn r81h_connect_episode_clock_tick() {
        use crate::policy::connect_episode_clock_tick;
        let t0 = std::time::Instant::now();
        // 空闲 → busy：记起点。
        let s = connect_episode_clock_tick(None, true, t0);
        assert!(s == Some(t0));
        // 持续 busy（状态串 Connecting: … → 等待审批中… 变化）：保持原起点
        // （elapsed 跨串累计，防 5.75s 盲区被拆成短 episode）。
        let t1 = t0 + std::time::Duration::from_millis(1500);
        let s = connect_episode_clock_tick(s, true, t1);
        assert!(s == Some(t0), "episode start must survive busy-string changes");
        // 终态覆盖：清零（下次点击重新起算）。
        let t2 = t1 + std::time::Duration::from_millis(4000);
        let s = connect_episode_clock_tick(s, false, t2);
        assert!(s.is_none());
        // 重新点击：重新起算。
        let t3 = t2 + std::time::Duration::from_millis(1000);
        let s = connect_episode_clock_tick(s, true, t3);
        assert!(s == Some(t3));
    }
}
