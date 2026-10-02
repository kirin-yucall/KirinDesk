//! 最小 quinn DATAGRAM 回环隔离测试（排查端到端 datagram 丢失）。

use std::net::SocketAddr;
use std::sync::Arc;

use kirin_desk_media::transport::{generate_quic_cert, QuicConnection, QuicEndpoint};

#[tokio::test(flavor = "multi_thread")]
async fn raw_datagram_loopback() {
    let (cert, key) = generate_quic_cert("min-server").unwrap();
    let endpoint = Arc::new(QuicEndpoint::bind(0, cert, key).await.unwrap());
    let port = endpoint.local_addr().unwrap().port();
    let addr: SocketAddr = ([0, 0, 0, 0, 0, 0, 0, 1], port).into();

    let ep2 = Arc::clone(&endpoint);
    let server = tokio::spawn(async move {
        let (conn, _remote) = ep2.accept().await.unwrap();
        // 50 个 ~700B datagram（总 ~35KB > 初始 cwnd 12KB → 触发拥塞控制恢复路径）
        for i in 0..50u32 {
            let payload = format!("dg-{i}-{}", "x".repeat(680));
            conn.send_datagram(payload.as_bytes()).await.unwrap();
        }
        // 发送后保持连接活跃 6s（等待客户端读完），期间驱动继续运行
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
        conn
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let conn: QuicConnection = QuicEndpoint::connect(addr, "min-server").await.unwrap();
    let server_conn = server.await.unwrap();

    // 收满 50 个（8s 超时）
    let mut got = 0u32;
    for _ in 0..50 {
        match tokio::time::timeout(std::time::Duration::from_secs(8), conn.recv_datagram()).await {
            Ok(Ok(_)) => got += 1,
            Ok(Err(e)) => {
                eprintln!("RECV ERR at {got}: {e}");
                break;
            }
            Err(_) => {
                eprintln!("RECV TIMEOUT at {got}");
                break;
            }
        }
    }
    eprintln!("RECEIVED {got}/50 datagrams");
    let s = conn.udp_stats();
    eprintln!("client: udp_tx={} dg/{}B udp_rx={} dg/{}B", s.0, s.1, s.2, s.3);
    server_conn.close("done");
    conn.close("done");
    assert_eq!(got, 50, "all datagrams should arrive");
}
