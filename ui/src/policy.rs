//! 服务端共享策略层（SEC-PATCH / SRV-SEC-KH-001）—— CLI serve / shell 服务器
//! 与 GUI 服务器共用的握手策略：
//!
//! 1. **客户端公钥解析**（[`resolve_expected_client_key`]）：known_hosts 优先 →
//!    DNS TXT 兜底（需 GoDaddy 配置，未配置则跳过）→ 未知走白名单/审批；
//! 2. **完整两阶段握手**（[`server_accept_handshake`]）：预读 init → 公钥解析与
//!    pin → 白名单（temp 可绕过）→ 校验 → 应答，服务端**不再信任网络上来的
//!    自报公钥**（对称于客户端 known_hosts/DNS-TXT 绑定）。

use kirin_desk_core::connection::temp_mode::TempModeManager;
use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_core::crypto::handshake::{
    domain_matches_whitelist, server_handshake_respond_generic, server_read_init,
    verify_server_init_with_temp, HandshakeError, SecureChannel, VerifiedDecision,
};
use kirin_desk_dns::godaddy::GoDaddyClient;
use kirin_desk_dns::txt::TxtManager;
use kirin_desk_utils::config::Config;
use kirin_desk_utils::known_hosts::KnownClientsStore;

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
///   需 GoDaddy API 配置，未配置或查询失败则跳过）；
/// - 都未命中 → `None`，由白名单/审批流程决定。
pub async fn resolve_expected_client_key(
    known: &KnownClientsStore,
    cfg: &Config,
    client_id: &str,
) -> (Option<String>, ClientKeyResolution) {
    if let Some(kc) = known.lookup(client_id) {
        return (Some(kc.public_key_base64.clone()), ClientKeyResolution::KnownHosts);
    }

    if cfg.godaddy.api_key.is_empty() || cfg.godaddy.domain.is_empty() {
        return (None, ClientKeyResolution::Unknown);
    }
    let client = GoDaddyClient::new(
        &cfg.godaddy.api_key,
        &cfg.godaddy.api_secret,
        &cfg.godaddy.api_url,
    );
    match TxtManager::new(&client, &cfg.godaddy.domain)
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
/// M13-T005（UA-ACCEPT-001/002）：`unattended = true` 时访问控制切换为
/// 「自动接受」策略——白名单命中或 known_clients 命中 → 自动允许（无弹窗、
/// 无需 temp mode）；两者均未命中 → 直接拒绝（`Rejected("unattended: ...")`），
/// 不存在人工审批路径。调用方应保证无人值守下 `temp_mode` 已置 false
/// （UA-ACCEPT-004）。
///
/// M8-T017（SRV-TMP-HK-001/003）：`temp_window` 为激活中的临时连接窗口时，
/// 挑战码按二态校验（固定 **或** 临时），且与 `temp_mode` 共同跳过白名单；
/// `None` = 窗口期外，临时码一律失败，不产生任何旁路。
///
/// 返回 `VerifiedDecision`（与白名单握手一致）：`Accepted` 建立安全通道；
/// `Rejected` 为策略拒绝（白名单/无人值守）；`Err` 为验证失败（签名/pin/nickname 等）。
pub async fn server_accept_handshake(
    mut stream: tokio::net::TcpStream,
    identity: &IdentityManager,
    server_id: &str,
    allowed_domains: &[String],
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
    let is_whitelisted = allowed_domains
        .iter()
        .any(|allowed| domain_matches_whitelist(&init.client_domain, allowed));
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
            "domain '{}' not in whitelist (headless: no GUI approval)",
            init.client_domain
        )));
    }

    // 3. 客户端公钥解析（known_hosts → DNS TXT）+ 校验（pin/nickname/challenge/签名）。
    let (expected_key, _resolution) =
        resolve_expected_client_key(known, cfg, &init.client_id).await;
    verify_server_init_with_temp(
        &init,
        expected_key.as_deref().unwrap_or(""),
        expected_nickname,
        expected_challenge,
        temp_window.as_ref(),
    )?;

    // 4. 应答 + 建立安全通道。
    let selected_codec = String::new();
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
/// `temp_code_like` 为尽力而为的格式提示（方案 B）：8 位且全部字符
/// 属于临时码字符集（不含 0/O/1/I）时，优先提示临时码场景。
///
/// 字符集与 `core/src/connection/temp_mode.rs` 的 `CODE_CHARSET`
/// 保持一致（跨 crate 无法直接引用私有常量，单测固定断言）。
pub fn connect_failure_challenge_hint(challenge: &str) -> Option<String> {
    if challenge.is_empty() {
        return None;
    }
    let temp_like = challenge.len() == 8
        && challenge
            .chars()
            .all(|c| "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".contains(c));
    let hint = if temp_like {
        "提示：此挑战码符合临时连接码格式。连接被拒通常是：\n  \
         1) 临时窗口已过期或未开启 —— 请服务端执行 `kirin_desk status` 确认（Temp Mode: ACTIVE）；\n  \
         2) 窗口已过期 —— 请服务端重新执行 `kirin_desk temp-mode` 获取新码；\n  \
         3) 码输入有误 —— 逐字符核对（临时码不含 0/O/1/I）。"
    } else {
        "提示：连接被拒通常是对端挑战码/凭据校验未通过：\n  \
         1) 固定挑战码错误 —— 与服务端 `challenge_code` 配置核对；\n  \
         2) 若使用临时连接码 —— 窗口可能已过期，请服务端重新执行 `kirin_desk temp-mode`；\n  \
         3) 确认服务端未处于无人值守模式（该模式下无临时放行路径）。"
    };
    Some(hint.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kirin_desk_core::crypto::ed25519::IdentityManager;
    use kirin_desk_core::crypto::handshake::{
        client_handshake_with_confirm_generic, SecureChannelGeneric,
    };
    use tokio::net::TcpListener;

    fn gen_identity(dir: &std::path::Path, name: &str) -> IdentityManager {
        IdentityManager::generate(dir.join(name)).expect("generate identity")
    }

    /// 本地 TCP 对连执行一次服务端握手：
    /// 客户端 alice（domain "alice.local"，类型 desktop）→ 服务端 bob（自生成），
    /// 按参数给定无人值守标志 / known_clients / 白名单。alice 身份由调用方
    /// 传入（known_clients 预置的公钥必须与握手客户端一致）。
    async fn run_pair(
        tag: &str,
        unattended: bool,
        known: &KnownClientsStore,
        allowed: &[String],
        alice: &IdentityManager,
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
            server_accept_handshake(
                stream, &bob, "bob", allowed, false, unattended, None, None, None, known, &cfg,
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
                Some(bob_pub),
                None,
                "",
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
        let (client_res, decision) = run_pair("unknown", true, &known, &[], &alice).await;
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

        let (client_res, decision) = run_pair("known", true, &known, &[], &alice).await;
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
        let (client_res, decision) = run_pair("whitelist", true, &known, &allowed, &alice).await;
        assert!(
            matches!(decision, Ok(VerifiedDecision::Accepted(_))),
            "expected Accepted, got {:?}",
            decision.is_err()
        );
        assert!(client_res.is_ok(), "client handshake should succeed");
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

        let (client_res, decision) = run_pair("normal", false, &known, &[], &alice).await;
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
                    stream, bob, "bob", allowed, false, false, tm, None, None, known, &cfg,
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
                    Some(bob_pub.to_string()),
                    None,
                    challenge,
                )
                .await
            };
            tokio::join!(client_fut, server_fut)
        }

        // 窗口激活 + 临时码 → Accepted（白名单为空也放行）。
        let (client_res, decision) = run_window_pair(
            &dir, &alice, &bob, &bob_pub, &known, &allowed, Some(tm.clone()), &code,
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
            &dir, &alice, &bob, &bob_pub, &known, &allowed, Some(tm.clone()), "WRONGCODE",
        )
        .await;
        match decision {
            Err(HandshakeError::InvalidMessage(msg)) => {
                assert_eq!(msg, "challenge mismatch");
            }
            Ok(VerifiedDecision::Rejected(reason)) => {
                panic!("expected InvalidMessage(challenge mismatch), got Rejected({})", reason)
            }
            Ok(VerifiedDecision::Accepted(_)) => {
                panic!("expected InvalidMessage(challenge mismatch), got Accepted")
            }
            Err(e) => panic!("expected InvalidMessage(challenge mismatch), got Err({})", e),
        }
        assert!(client_res.is_err(), "client must fail with wrong temp code");

        // 窗口期外（None）→ 临时码一律失败，不产生旁路（SRV-TMP-HK-003）。
        let (client_res, decision) = run_window_pair(
            &dir, &alice, &bob, &bob_pub, &known, &allowed, None, &code,
        )
        .await;
        match decision {
            Ok(VerifiedDecision::Rejected(reason)) => {
                assert!(reason.contains("whitelist"), "reason: {}", reason);
            }
            Ok(VerifiedDecision::Accepted(_)) => {
                panic!("expected Rejected(whitelist) outside window, got Accepted")
            }
            Err(e) => panic!("expected Rejected(whitelist) outside window, got Err({})", e),
        }
        assert!(client_res.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M8-T017-P2 (CLI-TMP-003): 8 位且全字符属于临时码字符集
    /// （A-Z 去 O/I + 2-9 去 0/1）→ 优先提示临时码场景（方案 B 格式判定）。
    #[test]
    fn test_hint_temp_code_like_uses_temp_wording() {
        let hint = connect_failure_challenge_hint("A2B3C4D5").expect("hint for 8-char code");
        assert!(hint.contains("临时连接码格式"), "hint: {}", hint);
        assert!(hint.contains("temp-mode"), "hint: {}", hint);
        assert!(hint.contains("0/O/1/I"), "hint: {}", hint);
        assert!(hint.contains("Temp Mode: ACTIVE"), "hint: {}", hint);
        // 全数字/字母混合且长度 8 → 同样命中格式（尽力而为的猜测）。
        let hint2 = connect_failure_challenge_hint("ABCD2345").expect("hint");
        assert!(hint2.contains("临时连接码格式"), "hint: {}", hint2);
    }

    /// M8-T017-P2 (CLI-TMP-003): 长度非 8 或含 0/1/O/I 的码 →
    /// 走通用文案（不误判为临时码）。
    #[test]
    fn test_hint_non_temp_format_uses_generic_wording() {
        let hint = connect_failure_challenge_hint("WRONGCODE1").expect("hint");
        assert!(!hint.contains("临时连接码格式"), "hint: {}", hint);
        assert!(hint.contains("固定挑战码错误"), "hint: {}", hint);
        assert!(hint.contains("challenge_code"), "hint: {}", hint);
        // 长度 8 但含被排除字符 0/1 → 通用文案。
        let hint2 = connect_failure_challenge_hint("ABC01234").expect("hint");
        assert!(!hint2.contains("临时连接码格式"), "hint: {}", hint2);
        assert!(hint2.contains("固定挑战码错误"), "hint: {}", hint2);
    }

    /// M8-T017-P2 (CLI-TMP-003): 未提供挑战码 → 无提示（固定码未配置的
    /// 免校验连接失败多为网络/白名单问题，不误导）。
    #[test]
    fn test_hint_empty_challenge_returns_none() {
        assert!(connect_failure_challenge_hint("").is_none());
    }
}
