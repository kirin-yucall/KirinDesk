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
    domain_matches_whitelist, id_matches_whitelist, negotiate_codec_by_server_priority,
    server_handshake_respond_generic, server_read_init, verify_server_init_with_temp,
    HandshakeError, SecureChannel, VerifiedDecision,
};
use kirin_desk_dns::txt::TxtManager;
use kirin_desk_utils::config::Config;
use kirin_desk_utils::known_hosts::KnownClientsStore;
// M8-T038 (P6): 连接失败引导提示（用户可见，拼入连接状态与日志）走 t!()。
use crate::t;

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

/// 临时连接窗口是否生效（M8-T017 / SRV-TMP-006 统一判断点）。
///
/// GUI / CLI 服务器共用此实现（不再各自读时间戳文件），仅需在
/// 白名单跳过判定上 OR 本结果；窗口判定实现（状态文件读取/过期）唯一
/// 存在于 [`TempModeManager`]。
pub fn temp_mode_window_active() -> bool {
    TempModeManager::new()
        .map(|mgr| mgr.is_active())
        .unwrap_or(false)
}

/// 激活中的临时连接窗口管理器（M8-T017 / SRV-TMP-HK-001 统一构造点）。
///
/// 窗口激活 → `Some(manager)`（供握手二态校验 / 白名单跳过）；未激活/不可用
/// → `None`。调用方（CLI/GUI 服务器）**逐连接**获取并传入
/// [`server_accept_handshake`]（窗口中途开启/过期即时生效）；无人值守下由
/// 调用方按 UA-ACCEPT-004 置 `None`。
pub fn temp_mode_window_manager() -> Option<TempModeManager> {
    TempModeManager::new().ok().filter(|mgr| mgr.is_active())
}

/// 完整服务端握手（两阶段）：预读 init → 公钥解析/pin → 白名单 → 校验 → 应答。
///
/// 与 `server_handshake_with_whitelist` 的差异：本函数在**应答前**解析客户端
/// 公钥（known_hosts → DNS TXT）并强制 pin，杜绝服务端信任网络自报公钥
/// （SRV-SEC-KH-001/002）；白名单在验证之前判定（headless：不泄露服务器
/// X25519 公钥/响应签名），`temp_mode` / `temp_window` 可绕过。
///
/// M8-T027 (SRV-IDWL-020)：`allowed_ids` 为设备 ID 白名单（调用方从
/// `cfg.id_whitelist_active_ids(Utc::now())` 取得）；访问控制公式为
/// **`domain_match || id_match`**（双白名单 OR 语义，域名维度既有行为不变），
/// temp_mode / temp_window 跳过时两维一并跳过（SRV-IDWL-024）。
///
/// M13-T005（UA-ACCEPT-001/002）：`unattended = true` 时访问控制切换为
/// 「自动接受」策略——白名单命中（域名 **或** ID，SRV-IDWL-003）或
/// known_clients 命中 → 自动允许（无弹窗、无需 temp mode）；两者均未命中 →
/// 直接拒绝（`Rejected("unattended: ...")`），不存在人工审批路径。调用方应
/// 保证无人值守下 `temp_mode` 已置 false（UA-ACCEPT-004）。
///
/// M8-T017（SRV-TMP-HK-001/003）：`temp_window` 为激活中的临时连接窗口时，
/// 挑战码按二态校验（固定 **或** 临时），且与 `temp_mode` 共同跳过白名单；
/// `None` = 窗口期外，临时码一律失败，不产生任何旁路。
///
/// S-01b（F-1）：**零凭据 fail-closed** —— 客户端未知（`expected_key` 解析为
/// None，无 known_clients/DNS pin）+ 无固定挑战码 + 无激活临时窗口 →
/// 拒绝（白名单命中不再等于放行：白名单只匹配自报域名，与身份绑定解耦）。
/// 已 pin 客户端（身份绑定）不受影响（首次连接确认 / R-02 pin 路径不回归）。
///
/// 返回 `VerifiedDecision`（与白名单握手一致）：`Accepted` 建立安全通道；
/// `Rejected` 为策略拒绝（白名单/无人值守/零凭据）；`Err` 为验证失败（签名/pin/nickname 等）。
pub async fn server_accept_handshake(
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

    // 2. 访问控制（headless：先白名单后验证，非白名单不泄露信息）。
    // M8-T027: 双白名单 OR —— 域名命中 **或** 设备 ID 命中即视为白名单命中。
    let is_whitelisted = allowed_domains
        .iter()
        .any(|allowed| domain_matches_whitelist(&init.client_domain, allowed))
        || allowed_ids
            .iter()
            .any(|id| id_matches_whitelist(&init.client_id, id));
    if unattended {
        // UA-ACCEPT-001/002：白名单命中 → 自动允许；未命中但 known_clients
        // 已信任 → 自动允许；完全未知 → 自动拒绝（无人值守无人工审批）。
        if !is_whitelisted && known.lookup(&init.client_id).is_none() {
            return Ok(VerifiedDecision::Rejected(format!(
                "unattended: client '{}' unknown (whitelist or known_clients required)",
                init.client_id
            )));
        }
    } else if !temp_mode && temp_window.is_none() && !is_whitelisted {
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
        return Ok(VerifiedDecision::Rejected(format!(
            "no credentials: client '{}' is unknown (no pinned key), and server has \
             no challenge code and no temp window — zero-credential connection rejected (F-1)",
            init.client_id
        )));
    }

    // S-01a (F-1)：生产路径零凭据 → 拒绝（verify 层兜底，防调用方遗漏）。
    verify_server_init_with_temp(
        &init,
        expected_key.as_deref().unwrap_or(""),
        expected_nickname,
        expected_challenge,
        temp_window.as_ref(),
        false,
    )?;

    // 4. 应答 + 建立安全通道。
    // R-32（M13-T002 阶段 B）：编码能力协商——服务端按**自身编码优先级**
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
    let g = server_handshake_respond_generic(stream, identity, server_id, &init, &selected_codec)
        .await?;
    Ok(VerifiedDecision::Accepted(SecureChannel {
        stream: g.stream,
        cipher: g.cipher,
        peer_id: g.peer_id,
        peer_domain: g.peer_domain,
        peer_device_type: g.peer_device_type,
        selected_codec: g.selected_codec,
    }))
}

/// 握手成功后刷新 known_hosts 记录（`last_seen`），已存在才更新并保存。
pub fn record_successful_handshake(known: &mut KnownClientsStore, client_id: &str) {
    if known.lookup(client_id).is_some() {
        known.touch(client_id);
        let _ = known.save();
    }
}

/// M8-T017-P2 (CLI-TMP-003): 连接失败引导提示。
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
    // M8-T038 (P6): 文案走 t!()——zh 模板保持现语义逐字（单测断言
    // 「固定挑战码错误」「临时连接码格式」等子串），en 补翻译。
    let hint = if temp_like {
        t!("policy.challenge_hint.temp")
    } else {
        t!("policy.challenge_hint.fixed")
    };
    Some(hint.to_string())
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
    /// 客户端 alice（domain "alice.local"，类型 desktop）→ 服务端 bob（自生成），
    /// 按参数给定无人值守标志 / known_clients / 域名白名单 / ID 白名单 / 挑战码。
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
    ) -> (
        Result<SecureChannelGeneric<tokio::net::TcpStream>, HandshakeError>,
        Result<VerifiedDecision, HandshakeError>,
    ) {
        let dir = std::env::temp_dir().join(format!("kirin_policy_{}", tag));
        let bob = gen_identity(&dir, "bob");
        let bob_pub = bob.public_key_base64();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();

        let server_fut = async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let cfg = Config::default();
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
        let client_fut = async move {
            let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            client_handshake_with_confirm_generic(
                stream,
                alice,
                "alice",
                "alice.local",
                "desktop",
                "bob",
                // R-02：真实 pin 比对（`Exact` 强类型）。
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
    #[tokio::test]
    async fn test_unattended_unknown_rejected() {
        let dir = std::env::temp_dir().join("kirin_policy_unknown");
        let alice = gen_identity(&dir, "alice");
        let known = KnownClientsStore::empty();
        let (client_res, decision) = run_pair("unknown", true, &known, &[], &[], &alice, "").await;
        match decision {
            Ok(VerifiedDecision::Rejected(reason)) => {
                assert!(reason.contains("unattended"), "reason: {}", reason);
            }
            Ok(_) => panic!("expected Rejected(unattended)"),
            Err(e) => panic!("server handshake error: {}", e),
        }
        assert!(client_res.is_err(), "channel must not be established");
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

        let (client_res, decision) = run_pair("known", true, &known, &[], &[], &alice, "").await;
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
            run_pair("zero_cred", false, &known, &allowed, &[], &alice, "").await;
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

        let (client_res, decision) = run_pair("normal", false, &known, &[], &[], &alice, "").await;
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

    /// M8-T017 (SRV-TMP-HK-001/002 + SRV-TMP-006): 临时连接窗口端到端——
    /// 窗口激活（注入隔离状态文件）+ 无白名单：客户端携带临时挑战码 → 握手
    /// 成功（白名单跳过 + 二态校验通过）；携带错码 → 验证失败被拒。
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
                    // R-02：真实 pin 比对（`Exact` 强类型）。
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
            Ok(VerifiedDecision::Rejected(reason)) => {
                panic!("expected Accepted with temp code, got Rejected({})", reason)
            }
            Err(e) => panic!("expected Accepted with temp code, got Err({})", e),
        }
        assert!(client_res.is_ok(), "client must connect with temp code");

        // 窗口激活 + 错码 → 拒绝（InvalidMessage(challenge mismatch)，计入握手失败路径）。
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

    /// M8-T017-P2 (CLI-TMP-003): 10 位且全字符属于临时码字符集
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

    /// M8-T017-P2 (CLI-TMP-003): 长度非 10 或含 0/1/O/I 的码 →
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

    /// M8-T017-P2 (CLI-TMP-003): 未提供挑战码 → 无提示（固定码未配置的
    /// 免校验连接失败多为网络/白名单问题，不误导）。
    #[test]
    fn test_hint_empty_challenge_returns_none() {
        assert!(connect_failure_challenge_hint("").is_none());
    }

    // ---- M8-T027: 设备 ID 白名单决策表（SRV-IDWL-020/021/023/024） ----

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
            run_pair("idwl_pin", false, &known, &[], &allowed_ids, &mallory, "").await;
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
            Ok(VerifiedDecision::Accepted(_)) => {
                panic!("outside window, ID whitelist must be enforced")
            }
            Err(e) => panic!("expected Rejected outside window, got Err({})", e),
        }
        assert!(client_res.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
