//! M11: 远程 Shell (PTY 模式) 端到端集成测试
//!
//! 全链路验证（验收标准）：
//! - 客户端输入 → 服务端 shell 执行（echo 命令输出回传）
//! - 服务端输出 → 客户端显示（ShellStdout 消息）
//! - 域名白名单强制（headless：非白名单域名直接拒绝，无 GUI 审批弹窗）
//! - PTY 会话生命周期（子进程退出 → 会话结束）

use kirin_desk_core::connection::{run_shell_bridge, ShellMessage};
use kirin_desk_core::crypto::ed25519::IdentityManager;
use kirin_desk_core::crypto::handshake::{
    client_handshake, server_handshake_with_whitelist, VerifiedDecision,
};
use tokio::net::TcpListener;

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
    temp_mode: bool,
) {
    let (stream, _addr) = listener.accept().await.expect("accept");
    match server_handshake_with_whitelist(
        stream,
        identity,
        server_id,
        &allowed,
        temp_mode,
        "",
        None,
        None,
    )
    .await
    {
        Ok(VerifiedDecision::Accepted(ch)) => {
            let _ = run_shell_bridge(ch, 120, 30, Some(interactive_shell())).await;
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
        server_pub,
        "",
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
            false,
            "",
            None,
            None,
        )
        .await
        .expect("handshake completes");
        match decision {
            VerifiedDecision::Accepted(_) => panic!("evil domain must be rejected"),
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
            &server_pub,
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

/// Temp mode：白名单绕过。
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
            true, // temp mode → 绕过白名单
            "",
            None,
            None,
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
            &server_pub,
            "",
        ),
    )
    .await
    .expect("no timeout")
    .expect("client handshake ok");
    drop(client_result); // 仅验证通道建立成功

    server_task.await.expect("server task");
    let _ = std::fs::remove_dir_all(&tmp);
}
