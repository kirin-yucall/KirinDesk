//! M11: 远程 Shell (PTY 模式) 端到端集成测试
//!
//! 全链路验证（验收标准）：
//! - 客户端输入 → 服务端 shell 执行（echo 命令输出回传）
//! - 服务端输出 → 客户端显示（ShellStdout 消息）
//! - 白名单强制（headless：非白名单直接拒绝，无 GUI 审批弹窗；域名 + ID 两维）
//! - PTY 会话生命周期（子进程退出 → 会话结束）

// deprecated（新代码用 ui::policy::server_accept_handshake），本文件保留
// 其 headless 白名单语义的 e2e 回归。
#![allow(deprecated)]

use kirin_desk_core::connection::{run_shell_bridge, ShellMessage};
use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_core::crypto::handshake::{
    client_handshake, server_handshake_with_whitelist, VerifiedDecision,
};
use tokio::net::TcpListener;

/// S-01f (F-1): e2e 用固定挑战码 —— 服务端握手已 fail-closed（空挑战码 +
/// 未知客户端 = 零凭据 → 拒绝），e2e 显式配置挑战码验证「凭据齐备」路径。
const E2E_CHALLENGE: &str = "E2E-TEST-CODE";

/// 测试用交互 shell 命令（Windows: cmd.exe；Unix: bash）。
fn interactive_shell() -> portable_pty::CommandBuilder {
    #[cfg(windows)]
    {
        portable_pty::CommandBuilder::new("cmd.exe")
    }
    #[cfg(not(windows))]
    {
        let mut cmd = portable_pty::CommandBuilder::new("/bin/bash");
        cmd.env("TERM", "xterm-256color");
        cmd
    }
}

/// 服务端 shell 会话：白名单握手 → PTY 桥接。
async fn run_server(
    listener: TcpListener,
    identity: &IdentityManager,
    server_id: &str,
    allowed: Vec<String>,
    allowed_ids: Vec<String>,
    temp_mode: bool,
) {
    let (stream, _addr) = listener.accept().await.expect("accept");
    match server_handshake_with_whitelist(
        stream,
        identity,
        server_id,
        &allowed,
        &allowed_ids,
        temp_mode,
        "",
        None,
        // S-01f (F-1): fail-closed 后显式配置挑战码（空码零凭据会被拒）。
        Some(E2E_CHALLENGE),
    )
    .await
    {
        Ok(VerifiedDecision::Accepted(ch)) => {
            // 纯 PTY 语义 = `None`（harness 零行为变化，§12.6 回归不变式）。
            let _ = run_shell_bridge(ch, 120, 30, Some(interactive_shell()), None).await;
        }
        //（`AcceptedEx` 仅 `ui::policy` `_ex` 入口产出）——防御臂保穷举。
        Ok(VerifiedDecision::AcceptedEx { .. }) => {
            panic!("legacy handshake must not produce AcceptedEx")
        }
        Ok(VerifiedDecision::Rejected(reason)) => panic!("unexpected rejection: {reason}"),
        Err(e) => panic!("server handshake failed: {e}"),
    }
}

/// 客户端 shell 会话：握手 → 发送命令 → 收集输出 → 应答 DSR（Windows cmd.exe）。
///
/// 返回收集到的全部输出；服务端会话结束（EOF）视为正常完成。
async fn run_client(
    addr: std::net::SocketAddr,
    identity: &IdentityManager,
    client_id: &str,
    domain: &str,
    server_id: &str,
    server_pub: &str,
    commands: &str,
) -> Result<Vec<u8>, kirin_desk_core::crypto::handshake::HandshakeError> {
    use kirin_desk_core::crypto::handshake::HandshakeError;

    let stream = tokio::net::TcpStream::connect(addr).await.map_err(HandshakeError::Io)?;
    let mut ch = client_handshake(
        stream,
        identity,
        client_id,
        domain,
        "shell",
        server_id,
        kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(server_pub)?,
        // S-01f (F-1): 与服务端固定挑战码配对。
        E2E_CHALLENGE,
    )
    .await?;

    // 发送测试命令（echo + exit）。
    let msg = ShellMessage::ShellStdin(commands.as_bytes().to_vec())
        .encode()
        .map_err(|e| HandshakeError::InvalidMessage(e.to_string()))?;
    ch.send(&msg).await?;

    // 接收循环：收集输出；应答 DSR 查询（cmd.exe 启动时等待光标位置响应）。
    let mut output = Vec::new();
    let mut responded_dsr = false;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if std::time::Instant::now() > deadline {
            return Err(HandshakeError::Timeout);
        }
        match tokio::time::timeout(std::time::Duration::from_secs(30), ch.receive()).await {
            Ok(Ok(bytes)) => match ShellMessage::decode(&bytes)
                .map_err(|e| HandshakeError::InvalidMessage(e.to_string()))?
            {
                ShellMessage::ShellStdout(data) => {
                    output.extend_from_slice(&data);
                    if !responded_dsr
                        && output.windows(4).any(|w| w == b"\x1b[6n")
                    {
                        let reply = ShellMessage::ShellStdin(b"\x1b[1;1R".to_vec())
                            .encode()
                            .map_err(|e| HandshakeError::InvalidMessage(e.to_string()))?;
                        ch.send(&reply).await?;
                        responded_dsr = true;
                    }
                }
                _ => {}
            },
            // EOF / 解密失败 = 服务端会话结束 → 正常返回已收集输出。
            Ok(Err(_)) => return Ok(output),
            Err(_) => return Err(HandshakeError::Timeout),
        }
    }
}

/// 端到端：客户端输入 → 服务端 shell 执行 → 输出回传（含 ANSI 回显）。
#[tokio::test]
async fn test_shell_e2e_echo_and_exit() {
    let tmp = std::env::temp_dir().join("kirin_e2e_shell");
    let server_id = IdentityManager::generate(tmp.join("server")).expect("server identity");
    let client_id = IdentityManager::generate(tmp.join("client")).expect("client identity");

    let listener = TcpListener::bind("[::1]:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let server_pub = server_id.public_key_base64();

    let server_identity = server_id;
    let client_identity = client_id;
    let server_task = tokio::spawn(async move {
        run_server(
            listener,
            &server_identity,
            "shell-server",
            vec!["kirin.local".to_string()],
            Vec::new(),
            false,
        )
        .await;
    });
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        run_client(
            addr,
            &client_identity,
            "alice",
            "alice.kirin.local",
            "shell-server",
            &server_pub,
            "echo KIRIN_E2E\r\nexit\r\n",
        ),
    )
    .await;

    let output = match result {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => panic!("client error: {e}"),
        Err(_) => panic!("e2e shell test timed out"),
    };
    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("KIRIN_E2E"),
        "shell output missing command result: {text:?}"
    );

    server_task.await.expect("server task");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// `FsRequest::List` 经 `ShellMessage::File`（判别值 3）客户端 → 服务端
/// `run_shell_bridge` 分派臂 → per-连接 FileSession（测试侧 handler 任务
/// 经 `ShellFileBridgeIo` mpsc 汇入）→ `FsResponse` → 客户端接收臂；
/// **PTY（echo）同通道并发** = 单写者帧边界零破验证（§12.3-4）。
///
/// 仿 `test_shell_e2e_echo_and_exit` 形态（harness run_server/run_client
/// 零改动——本用例自带 server/client 闭包；既有 4 例 = 回归不变式）。
#[tokio::test]
async fn test_r92s2_shell_file_frame_roundtrip() {
    use kirin_desk_core::connection::file_transfer::{
        FileOp, FileTransferFrame, FsEntry, FsErrCode, FsListPayload, FsOp,
        FsRequestPayload, FsResponsePayload,
    };
    use kirin_desk_core::connection::ShellFileBridgeIo;
    use kirin_desk_core::crypto::handshake::PROTOCOL_VERSION;

    let tmp = std::env::temp_dir().join("kirin_e2e_shell_file");
    let server_identity = IdentityManager::generate(tmp.join("server")).expect("server identity");
    let client_identity = IdentityManager::generate(tmp.join("client")).expect("client identity");

    let listener = TcpListener::bind("[::1]:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let server_pub = server_identity.public_key_base64();

    // S-2 版本 bump 前置断言（本用例前提 = v4 ↔ v4 对，文件臂全活）。
    //（peer_proto_ver == PROTOCOL_VERSION 才建 FileSession）。

    // 测试侧 per-连接 FileSession handler：FsRequest → FsResponse（List）。
    // 帧 = 不透明字节（handler 自行 decode，模拟引擎侧 handle_frame 语义）。
    let (file_in_tx, mut file_in_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (file_out_tx, file_out_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let file_handler = tokio::spawn(async move {
        while let Some(payload) = file_in_rx.recv().await {
            let Ok(frame) = FileTransferFrame::decode(&payload) else {
                continue; // 单帧解码失败 = 丢帧（引擎侧同语义）
            };
            if frame.op != FileOp::FsRequest {
                continue;
            }
            let Ok(req) = bincode::deserialize::<FsRequestPayload>(&frame.data) else {
                continue;
            };
            let (ok, resp_payload) = match req.op {
                FsOp::List { path, .. } => {
                    let entries = if path.is_empty() {
                        vec![FsEntry {
                            name: "e2e-file.txt".into(),
                            size: 12,
                            mtime: 0,
                            is_dir: false,
                            is_symlink: false,
                        }]
                    } else {
                        Vec::new()
                    };
                    (
                        true,
                        bincode::serialize(&FsListPayload {
                            entries,
                            has_more: false,
                            root_display: "root".into(),
                        })
                        .unwrap(),
                    )
                }
                _ => (true, Vec::new()),
            };
            let resp = FileTransferFrame {
                transfer_id: frame.transfer_id, // = 对应请求 req_id（§1.2 口径）
                op: FileOp::FsResponse,
                seq: 0,
                total_blocks: 0,
                data: bincode::serialize(&FsResponsePayload {
                    ok,
                    err: if ok { FsErrCode::Ok } else { FsErrCode::Io },
                    payload: resp_payload,
                })
                .unwrap(),
                sha256: [0u8; 32],
            };
            if file_out_tx.send(resp.encode().unwrap()).is_err() {
                break; // 桥已退（会话拆除）
            }
        }
    });

    let server_task = tokio::spawn(async move {
        let (stream, _addr) = listener.accept().await.expect("accept");
        match server_handshake_with_whitelist(
            stream,
            &server_identity,
            "shell-server",
            &["kirin.local".to_string()],
            &[],
            false,
            "",
            None,
            Some(E2E_CHALLENGE),
        )
        .await
        {
            Ok(VerifiedDecision::Accepted(ch)) => {
                // §12.3：per-连接 FileSession 接线（mpsc 汇入桥，单写者）。
                let io = ShellFileBridgeIo::new(file_in_tx, file_out_rx);
                let _ =
                    run_shell_bridge(ch, 120, 30, Some(interactive_shell()), Some(io)).await;
            }
            Ok(VerifiedDecision::AcceptedEx { .. }) => {
                panic!("legacy handshake must not produce AcceptedEx")
            }
            Ok(VerifiedDecision::Rejected(reason)) => panic!("unexpected rejection: {reason}"),
            Err(e) => panic!("server handshake failed: {e}"),
        }
    });

    // 客户端：v3 握手（client_handshake 实发 proto_ver = PROTOCOL_VERSION = 3）
    // → 发 FsRequest::List（req_id = 7 置于 transfer_id 字段，D1 口径）+ PTY echo
    // → 断言 FsResponse 往返 + PTY 输出共存（单写者验证）。
    let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut ch = client_handshake(
        stream,
        &client_identity,
        "alice",
        "alice.kirin.local",
        "shell",
        "shell-server",
        kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(&server_pub)
            .expect("pin"),
        E2E_CHALLENGE,
    )
    .await
    .expect("v3 ↔ v3 handshake must succeed（混版对才会被双向拒绝）");

    let req = FileTransferFrame {
        transfer_id: 7,
        op: FileOp::FsRequest,
        seq: 0,
        total_blocks: 0,
        data: bincode::serialize(&FsRequestPayload {
            op: FsOp::List {
                path: String::new(),
                offset: 0,
                limit: 500,
            },
        })
        .unwrap(),
        sha256: [0u8; 32],
    };
    ch.send(&ShellMessage::File(req.encode().unwrap()).encode().unwrap())
        .await
        .expect("send FsRequest via ShellMessage::File");
    // PTY 命令同通道并发（文件帧与 PTY 帧共用单写者 = 帧边界零破验证）。
    ch.send(&ShellMessage::ShellStdin(b"echo KIRIN_S2_PTY\r\nexit\r\n".to_vec())
        .encode()
        .unwrap())
        .await
        .expect("send PTY echo");

    let mut output = Vec::new();
    let mut responded_dsr = false;
    let mut fs_resp: Option<FsResponsePayload> = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if std::time::Instant::now() > deadline {
            panic!("e2e file frame roundtrip timed out");
        }
        match tokio::time::timeout(std::time::Duration::from_secs(30), ch.receive()).await {
            Ok(Ok(bytes)) => match ShellMessage::decode(&bytes) {
                Ok(ShellMessage::ShellStdout(data)) => {
                    output.extend_from_slice(&data);
                    if !responded_dsr && output.windows(4).any(|w| w == b"\x1b[6n") {
                        ch.send(&ShellMessage::ShellStdin(b"\x1b[1;1R".to_vec()).encode().unwrap())
                            .await
                            .expect("DSR reply");
                        responded_dsr = true;
                    }
                    if fs_resp.is_some() && output.windows(12).any(|w| w == b"KIRIN_S2_PTY") {
                        break; // 双断言齐备 → 提前收口
                    }
                }
                // §12.1 E0004 客户端接收臂：File → FileSession（此处测试侧
                // 直接消费 FsResponse；引擎侧 = handle_frame 分派）。
                Ok(ShellMessage::File(payload)) => {
                    if let Ok(frame) = FileTransferFrame::decode(&payload) {
                        if frame.op == FileOp::FsResponse && frame.transfer_id == 7 {
                            fs_resp =
                                Some(bincode::deserialize::<FsResponsePayload>(&frame.data)
                                    .expect("FsResponse payload"));
                        }
                    }
                }
                _ => {}
            },
            Ok(Err(_)) => break, // 服务端会话结束（PTY exit → 桥退出）
            Err(_) => panic!("e2e receive timeout"),
        }
    }
    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("KIRIN_S2_PTY"),
        "PTY echo missing（文件帧与 PTY 帧单写者共存被破坏）: {text:?}"
    );
    let resp = fs_resp.expect("FsResponse 未到达（分派臂/接收臂链路断）");
    assert!(resp.ok, "FsResponse 必须 ok: {resp:?}");
    let list: FsListPayload = bincode::deserialize(&resp.payload).expect("FsListPayload");
    assert_eq!(list.entries.len(), 1, "List 响应必须携带 1 条目");
    assert_eq!(list.entries[0].name, "e2e-file.txt");

    drop(ch);
    server_task.await.expect("server task");
    file_handler.await.expect("file handler task");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// 白名单强制：非白名单域名必须被拒绝（headless 无审批弹窗）。
#[tokio::test]
async fn test_shell_e2e_whitelist_rejects_evil_domain() {
    let tmp = std::env::temp_dir().join("kirin_e2e_shell_wl");
    let server_identity = IdentityManager::generate(tmp.join("server")).expect("server identity");
    let client_identity = IdentityManager::generate(tmp.join("client")).expect("client identity");

    let listener = TcpListener::bind("[::1]:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let server_pub = server_identity.public_key_base64();

    let server_task = tokio::spawn(async move {
        let (stream, _addr) = listener.accept().await.expect("accept");
        let decision = server_handshake_with_whitelist(
            stream,
            &server_identity,
            "shell-server",
            &["kirin.local".to_string()],
            &[],
            false,
            "",
            None,
            None,
        )
        .await
        .expect("handshake completes");
        match decision {
            VerifiedDecision::Accepted(_) => panic!("evil domain must be rejected"),
            VerifiedDecision::AcceptedEx { .. } => panic!("evil domain must be rejected"),
            VerifiedDecision::Rejected(reason) => {
                assert!(reason.contains("not in whitelist"), "reason: {reason}");
            }
        }
    });

    let client_result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client_handshake(
            tokio::net::TcpStream::connect(addr).await.expect("connect"),
            &client_identity,
            "mallory",
            "evil.com",
            "shell",
            "shell-server",
            kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(&server_pub)
                .expect("server pubkey"),
            "",
        ),
    )
    .await;

    // 客户端应收到 EOF（服务器在白名单拒绝后直接断开，不响应握手）。
    assert!(client_result.is_ok(), "client handshake should terminate");
    match client_result.unwrap() {
        Ok(_ch) => panic!("client must not establish channel with rejected domain"),
        Err(e) => {
            // 具体错误取决于平台（early eof / connection reset），
            // 关键断言：白名单外的域名**无法**建立安全通道。
            let _ = e;
        }
    }

    server_task.await.expect("server task");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// (SRV-IDWL-020 旧接口): 双白名单 OR 语义——域名未命中但设备 ID
/// 命中 → 放行；两维均未命中 → 拒绝（headless 无审批）。
#[tokio::test]
async fn test_shell_e2e_id_whitelist_semantics() {
    let tmp = std::env::temp_dir().join("kirin_e2e_shell_idwl");
    let server_identity = IdentityManager::generate(tmp.join("server")).expect("server identity");
    let client_identity = IdentityManager::generate(tmp.join("client")).expect("client identity");
    let server_pub = server_identity.public_key_base64();
    let allowed_ids = vec!["alice".to_string()];

    // 场景 1：域名不在白名单（evil.org），但 client_id 命中 ID 白名单 → Accepted。
    let listener = TcpListener::bind("[::1]:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let (server_identity_ref, allowed_ids_ref) = (server_identity.clone(), allowed_ids.clone());
    let server_task = tokio::spawn(async move {
        let (stream, _addr) = listener.accept().await.expect("accept");
        let decision = server_handshake_with_whitelist(
            stream,
            &server_identity_ref,
            "shell-server",
            &[],
            &allowed_ids_ref,
            false,
            "",
            None,
            // S-01f (F-1): fail-closed 后显式配置挑战码（凭据齐备路径）。
            Some(E2E_CHALLENGE),
        )
        .await
        .expect("handshake completes");
        assert!(
            matches!(decision, VerifiedDecision::Accepted(_)),
            "ID whitelist hit must be accepted despite domain miss"
        );
    });
    let client_result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client_handshake(
            tokio::net::TcpStream::connect(addr).await.expect("connect"),
            &client_identity,
            "alice",
            "evil.org",
            "shell",
            "shell-server",
            kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(&server_pub)
                .expect("server pubkey"),
            // S-01f (F-1): 与服务端固定挑战码配对。
            E2E_CHALLENGE,
        ),
    )
    .await
    .expect("no timeout")
    .expect("client handshake ok");
    drop(client_result); // 仅验证通道建立成功
    server_task.await.expect("server task");

    // 场景 2：两维均未命中（域名 miss + ID miss）→ Rejected。
    let listener = TcpListener::bind("[::1]:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let (server_identity_ref, allowed_ids_ref) = (server_identity, allowed_ids);
    let server_task = tokio::spawn(async move {
        let (stream, _addr) = listener.accept().await.expect("accept");
        let decision = server_handshake_with_whitelist(
            stream,
            &server_identity_ref,
            "shell-server",
            &[],
            &allowed_ids_ref,
            false,
            "",
            None,
            None,
        )
        .await
        .expect("handshake completes");
        match decision {
            VerifiedDecision::Accepted(_) => panic!("unknown ID must be rejected"),
            VerifiedDecision::AcceptedEx { .. } => panic!("unknown ID must be rejected"),
            VerifiedDecision::Rejected(reason) => {
                assert!(reason.contains("not in whitelist"), "reason: {reason}");
            }
        }
    });
    let client_result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client_handshake(
            tokio::net::TcpStream::connect(addr).await.expect("connect"),
            &client_identity,
            "mallory",
            "evil.org",
            "shell",
            "shell-server",
            kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(&server_pub)
                .expect("server pubkey"),
            "",
        ),
    )
    .await;
    // 客户端应收到 EOF（白名单拒绝后服务端直接断开）。
    assert!(client_result.is_ok(), "client handshake should terminate");
    assert!(
        client_result.unwrap().is_err(),
        "client must not establish channel with unknown ID"
    );
    server_task.await.expect("server task");

    let _ = std::fs::remove_dir_all(&tmp);
}

/// Temp mode：白名单绕过（域名 + ID 两维一并跳过，SRV-TMP-006 / SRV-IDWL-024）。
#[tokio::test]
async fn test_shell_e2e_temp_mode_bypasses_whitelist() {
    let tmp = std::env::temp_dir().join("kirin_e2e_shell_temp");
    let server_identity = IdentityManager::generate(tmp.join("server")).expect("server identity");
    let client_identity = IdentityManager::generate(tmp.join("client")).expect("client identity");

    let listener = TcpListener::bind("[::1]:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let server_pub = server_identity.public_key_base64();

    let server_task = tokio::spawn(async move {
        let (stream, _addr) = listener.accept().await.expect("accept");
        let decision = server_handshake_with_whitelist(
            stream,
            &server_identity,
            "shell-server",
            &["kirin.local".to_string()],
            &[],
            true, // temp mode → 绕过白名单
            "",
            None,
            // S-01f (F-1): fail-closed 后显式配置挑战码（凭据齐备路径）。
            Some(E2E_CHALLENGE),
        )
        .await
        .expect("handshake completes");
        assert!(
            matches!(decision, VerifiedDecision::Accepted(_)),
            "temp mode must bypass whitelist"
        );
    });

    let client_result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client_handshake(
            tokio::net::TcpStream::connect(addr).await.expect("connect"),
            &client_identity,
            "guest",
            "guest.example.org",
            "shell",
            "shell-server",
            kirin_desk_core::crypto::handshake::PinExpectation::exact_from_base64(&server_pub)
                .expect("server pubkey"),
            // S-01f (F-1): 与服务端固定挑战码配对。
            E2E_CHALLENGE,
        ),
    )
    .await
    .expect("no timeout")
    .expect("client handshake ok");
    drop(client_result); // 仅验证通道建立成功

    server_task.await.expect("server task");
    let _ = std::fs::remove_dir_all(&tmp);
}
