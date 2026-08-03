//! R-08b (S3)：relay-server 二进制部署形态 e2e —— "relay-server 进程 →
//! 打洞候选交换" 路径。
//!
//! 真实启动 `relay-server` 二进制（`CARGO_BIN_EXE_relay-server`，cargo 自动
//! 构建），验证：
//! - `--rendezvous-port` 打洞端口：双端候选登记 → 互转 `PeerCandidates`
//!   （含服务器观察地址）→ `PunchResult` 透传对端；
//! - 隧道控制端口（S1）：双端设备登录 → 打洞候选登记（session_id=Some）
//!   → 互转 → `PunchResult` 透传 —— 打洞帧不再落入 `_ =>` 忽略分支；
//! - 审计事件（`PunchCandidateRegistered` / `PunchForwarded`）实时输出
//!   stdout（ConsoleAudit）。
//!
//! 全部本机回环（`[::1]`），CI 可移植；交换限时包裹防挂起。

use kirin_desk_relay::auth::{client_digest, random_nonce};
use kirin_desk_relay::protocol::{
    decode_control, decode_extension, encode_control, encode_extension, read_frame, Candidate,
    CandidateKind, CandidateRegister, ControlMsg, PeerCandidates, PunchResult, PROTOCOL_VERSION,
    TYPE_CANDIDATE_REGISTER, TYPE_PEER_CANDIDATES, TYPE_PUNCH_RESULT,
};
use std::io::BufRead;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// 取一个空闲端口（测试用；drop 后可能被并发测试复用，仅用于同批次内）。
fn pick_free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// 轮询等待端口可连接（`[::1]`；双栈监听回环可达）。
async fn wait_port_ready(port: u16, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if tokio::time::timeout(
            Duration::from_millis(200),
            TcpStream::connect(("::1", port)),
        )
        .await
        .is_ok()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// 启动 relay-server（独立进程，stdout 管道捕获审计行）。
/// 返回 (child, stdout 读线程句柄)。
fn spawn_relay_server(bind_port: u16, rendezvous_port: u16) -> (Child, std::thread::JoinHandle<Vec<String>>) {
    let bin = env!("CARGO_BIN_EXE_relay-server");
    let mut child = Command::new(bin)
        .args([
            "--bind-port",
            &bind_port.to_string(),
            "--rendezvous-port",
            &rendezvous_port.to_string(),
            "--token",
            "smoke-token",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("relay-server 应可启动");
    let stdout = child.stdout.take().expect("stdout 应可捕获");
    // 读线程：持续收集审计输出行（进程退出后管道 EOF 结束）。
    let collector = std::thread::spawn(move || {
        std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
            .collect::<Vec<String>>()
    });
    (child, collector)
}

/// 与 rendezvous 端口建立一条打洞控制连接。
async fn connect_rendezvous(port: u16) -> TcpStream {
    TcpStream::connect(("::1", port))
        .await
        .expect("rendezvous 端口应可连接")
}

/// 手工登录（设备 ID 模式，挑战-响应两阶段），返回登录流。
async fn login_device(port: u16, device_id: &str) -> TcpStream {
    let mut stream = TcpStream::connect(("::1", port))
        .await
        .expect("控制端口应可连接");
    let client_nonce = random_nonce();
    let probe = ControlMsg::Login {
        token: String::new(),
        version: PROTOCOL_VERSION.to_string(),
        hostname: "smoke-device".to_string(),
        device_id: Some(device_id.to_string()),
        ed25519_pub: Some("pub-smoke".to_string()),
        auth_nonce: Some(client_nonce),
        auth_digest: None,
    };
    stream
        .write_all(&encode_control(&probe).unwrap())
        .await
        .unwrap();
    let (ty, payload) = read_frame(&mut stream).await.unwrap();
    let server_nonce = match decode_control(ty, &payload).unwrap() {
        ControlMsg::AuthChallenge { nonce } => nonce,
        other => panic!("预期 AuthChallenge，收到 {other:?}"),
    };
    let digest = client_digest(b"smoke-token", &server_nonce, &client_nonce);
    let proof = ControlMsg::Login {
        token: String::new(),
        version: PROTOCOL_VERSION.to_string(),
        hostname: "smoke-device".to_string(),
        device_id: Some(device_id.to_string()),
        ed25519_pub: Some("pub-smoke".to_string()),
        auth_nonce: Some(client_nonce),
        auth_digest: Some(digest),
    };
    stream
        .write_all(&encode_control(&proof).unwrap())
        .await
        .unwrap();
    let (ty, payload) = read_frame(&mut stream).await.unwrap();
    match decode_control(ty, &payload).unwrap() {
        ControlMsg::LoginResp { ok: true, .. } => stream,
        other => panic!("登录应成功，收到 {other:?}"),
    }
}

/// 发送打洞候选登记（session_id=Some），返回写入是否成功。
async fn send_punch_register(
    stream: &mut TcpStream,
    device_id: &str,
    session_id: [u8; 16],
) {
    let reg = CandidateRegister {
        device_id: device_id.to_string(),
        session_id: Some(session_id),
        candidates: vec![Candidate {
            addr: "10.1.2.3:4444".parse().unwrap(),
            kind: CandidateKind::Udp,
            priority: 120,
        }],
    };
    stream
        .write_all(&encode_extension(TYPE_CANDIDATE_REGISTER, &reg).unwrap())
        .await
        .unwrap();
}

/// 读一帧并断言类型，返回解码负载。
async fn read_expect<T: for<'de> serde::Deserialize<'de>>(
    stream: &mut TcpStream,
    ty_expect: u8,
) -> T {
    let (ty, payload) = tokio::time::timeout(Duration::from_secs(3), read_frame(stream))
        .await
        .expect("等待帧超时")
        .expect("连接被关闭");
    assert_eq!(ty, ty_expect, "帧类型应为 0x{ty_expect:02x}");
    decode_extension(ty, &payload, ty_expect).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_server_process_punch_exchange() {
    // R-08b 验收：relay-server 进程启动后，打洞候选注册/互转可用、
    // 审计事件正常输出。全程限时 30s 防挂起。
    let bind_port = pick_free_port();
    let rendezvous_port = pick_free_port();
    assert_ne!(bind_port, rendezvous_port, "两端口必须不同（冲突校验语义）");
    let (mut child, stdout_collector) = spawn_relay_server(bind_port, rendezvous_port);

    // 等待两个端口就绪。
    assert!(
        wait_port_ready(bind_port, Duration::from_secs(10)).await,
        "控制端口 {bind_port} 应在 10s 内就绪"
    );
    assert!(
        wait_port_ready(rendezvous_port, Duration::from_secs(10)).await,
        "rendezvous 端口 {rendezvous_port} 应在 10s 内就绪"
    );

    let exchange = async {
        // ── 打洞端口路径（R-08b S2 部署形态）──
        let mut rz_a = connect_rendezvous(rendezvous_port).await;
        let mut rz_b = connect_rendezvous(rendezvous_port).await;
        let sid = [1; 16];
        send_punch_register(&mut rz_a, "dev-a", sid).await;
        send_punch_register(&mut rz_b, "dev-b", sid).await;
        let pc_a: PeerCandidates = read_expect(&mut rz_a, TYPE_PEER_CANDIDATES).await;
        let pc_b: PeerCandidates = read_expect(&mut rz_b, TYPE_PEER_CANDIDATES).await;
        assert_eq!(pc_a.session_id, sid);
        assert_eq!(pc_b.session_id, sid);
        // 服务器观察地址互转（PUNCH-PROTO-001 关键信息）。
        let b_peer = rz_b.local_addr().unwrap();
        assert!(
            pc_a.candidates.iter().any(|c| c.addr == b_peer),
            "A 应收到 B 的服务器观察地址"
        );
        // PunchResult 透传。
        let result = PunchResult {
            session_id: sid,
            ok: true,
            path: Some(CandidateKind::Udp),
        };
        rz_a
            .write_all(&encode_extension(TYPE_PUNCH_RESULT, &result).unwrap())
            .await
            .unwrap();
        let got: PunchResult = read_expect(&mut rz_b, TYPE_PUNCH_RESULT).await;
        assert_eq!(got, result);
        drop(rz_a);
        drop(rz_b);

        // ── 隧道控制端口路径（R-08b S1：打洞帧不再 `_ =>` 忽略）──
        let mut ta = login_device(bind_port, "smoke-a").await;
        let mut tb = login_device(bind_port, "smoke-b").await;
        let sid2 = [2; 16];
        send_punch_register(&mut ta, "smoke-a", sid2).await;
        send_punch_register(&mut tb, "smoke-b", sid2).await;
        let pc_a2: PeerCandidates = read_expect(&mut ta, TYPE_PEER_CANDIDATES).await;
        let pc_b2: PeerCandidates = read_expect(&mut tb, TYPE_PEER_CANDIDATES).await;
        assert_eq!(pc_a2.session_id, sid2);
        assert_eq!(pc_b2.session_id, sid2);
        let result2 = PunchResult {
            session_id: sid2,
            ok: false,
            path: None,
        };
        ta.write_all(&encode_extension(TYPE_PUNCH_RESULT, &result2).unwrap())
            .await
            .unwrap();
        let got2: PunchResult = read_expect(&mut tb, TYPE_PUNCH_RESULT).await;
        assert_eq!(got2, result2);
        drop(ta);
        drop(tb);
    };
    let result = tokio::time::timeout(Duration::from_secs(30), exchange).await;
    if let Err(e) = &result {
        // 失败时先终止进程再 panic，避免残留子进程锁死 exe。
        let _ = child.kill();
        let _ = child.wait();
        panic!("打洞候选交换失败: {e}");
    }
    result.unwrap();

    // 终止进程（测试环境无信号投递；优雅关闭语义由库内 serve-stop 用例覆盖）。
    let _ = child.kill();
    let _ = child.wait();
    // 审计事件 stdout 输出（ConsoleAudit，TNL-SEC-003 口径）。
    let lines = stdout_collector.join().expect("stdout 收集线程应结束");
    assert!(
        lines.iter().any(|l| l.contains("[audit] punch candidate registered")),
        "stdout 应含候选登记审计: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("[audit] punch forwarded")),
        "stdout 应含互转/透传审计: {lines:?}"
    );
}
