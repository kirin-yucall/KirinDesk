//! 公钥/指纹/候选，与本机现役身份指纹对账（「relay 记录陈旧」假设坐实/证伪）。
//!
//! 仅在设置 `R81A_RELAY_ADDR`（如 `8.133.174.128:7000`）时实连网络；默认
//! 测试套件中跳过（ok）——常态 CI/全测不依赖外网。
//!
//! 只读语义（轻手轻脚，一次即止）：Login 为纯控制连接（`device_id=None`，
//! 不注册本机、不上报候选、不建隧道）+ 一次 `ResolveDevice`——与控制器
//! ID 模式解析完全同路径（`id_client::resolve_device`）。
//!
//! 用法：
//! ```text
//! R81A_RELAY_ADDR=8.133.174.128:7000 \
//! R81A_EXPECT_FP=ecb8:d62f:... \
//! cargo test -p kirin-desk-relay --test r81a_relay_probe -- --nocapture
//! ```
//! `R81A_RELAY_DEVICE` 默认 `HD-62EC5BC9`；`R81A_EXPECT_FP` 提供时对账
//! MATCH/MISMATCH（对账口径 = 客户端 known_hosts / 指纹确认框所见现役指纹）。

#[tokio::test]
async fn r81a_relay_probe_hd_62ec5bc9() {
    let addr = match std::env::var("R81A_RELAY_ADDR") {
        Ok(a) if !a.trim().is_empty() => a,
        _ => {
            eprintln!(
                "R81A probe: R81A_RELAY_ADDR not set — skipped \
                 (read-only forensics tool, set e.g. 8.133.174.128:7000 to run)"
            );
            return;
        }
    };
    let device = std::env::var("R81A_RELAY_DEVICE")
        .unwrap_or_else(|_| "HD-62EC5BC9".to_string());
    // 本地配置（tunnel.token 密文 `{v:...}` 由 Config::load 自动解密）。
    // token 为空亦放行：公网 relay 未配口令（legacy 无挑战模式）时空口令
    // 即正确客户端形态；relay 若挑战 → 认证层 fail-closed（NoTokenForChallenge）。
    let cfg = match kirin_desk_utils::config::Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("R81A probe: config load failed: {e} — skipped");
            return;
        }
    };
    let info = match kirin_desk_relay::id_client::resolve_device(
        &addr,
        &cfg.tunnel.token,
        &device,
        std::time::Duration::from_secs(10),
    )
    .await
    {
        Ok(i) => i,
        Err(e) => {
            eprintln!("R81A probe: resolve failed for {device} on {addr}: {e}");
            return;
        }
    };
    let p = &info.payload;
    let fp = if p.ed25519_pub.is_empty() {
        String::new()
    } else {
        kirin_desk_utils::known_hosts::fingerprint(&p.ed25519_pub)
    };
    println!(
        "R81A probe: device='{}' online={} candidates={} pub={}... fingerprint={}",
        p.device_id,
        p.online,
        p.candidates.len(),
        &p.ed25519_pub[..p.ed25519_pub.len().min(16)],
        fp
    );
    for c in &p.candidates {
        println!(
            "R81A probe:   candidate {} kind={:?} priority={}",
            c.addr, c.kind, c.priority
        );
    }
    if let Ok(expect) = std::env::var("R81A_EXPECT_FP") {
        if fp == expect {
            println!("R81A probe: fingerprint MATCH expected — relay record is CURRENT");
        } else {
            println!(
                "R81A probe: fingerprint MISMATCH expected={} got={} — relay record STALE",
                expect, fp
            );
        }
    }
}
