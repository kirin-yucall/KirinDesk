//! M8-T039: Tunnel 独立页分区表（P3 创建骨架键；P4 追加 `tunnel.server.*`
//! 键、P5 追加 `tunnel.run.*` / `tunnel.status.*` 键——表尾追加 + 分节注释）。
//!
//! zh 为基线语言包；en 全量翻译（不得留空串）。
//! 动态文案模板使用 `{0}`/`{1}` 位置参数，zh/en 占位符一一对应。

pub static TABLE: &[(&str, &str, &str)] = &[
    ("tunnel.tab", "内网穿透", "Tunnel"),
    ("tunnel.title", "内网穿透 · 通用 TCP 反向代理", "Tunnel · Generic TCP Reverse Proxy"),
    ("tunnel.desc",
     "内网穿透 = 通用 TCP 反向代理工具，不限于远控：\n  · 穿透客户端（Client）：把本机任意 TCP 服务（HTTP 网站 / SSH / RDP / 数据库 / 自定义端口）映射到公网服务器的指定端口；\n  · 穿透服务端（Server）：部署在公网服务器，接收客户端注册、对外提供映射端口（如发布个人网站：公网访问 http://你的域名:端口 → 内网网站）。\n  · 远控仅是用途之一；两端可独立使用、也可与远控并存（tunnel 开关默认关闭）。\n穿透明文协议时流量裸露，敏感场景请自备 HTTPS/TLS。",
     "Intranet traversal = a generic TCP reverse proxy tool, not limited to remote control:\n  · Client: map any local TCP service (HTTP site / SSH / RDP / database / custom port) to a public port on your server.\n  · Server: runs on your public server; accepts client registration and exposes mapped ports (e.g. publish a website: http://your-domain:port → intranet site).\n  · Remote control is just one use case; the two ends work independently or alongside it (tunnel is off by default).\nPlain-text protocols are exposed in transit — use HTTPS/TLS for sensitive traffic."),
    ("tunnel.enable", "开启", "Enable"),
    ("tunnel.enable_hint_on",
     "已开启（内存态；实际运行由 ▶ 启动 / ■ 停止控制）",
     "Enabled (in-memory; actual operation is controlled by Start / Stop)"),
    ("tunnel.enable_hint_off",
     "点击开启（内存态；实际运行由 ▶ 启动 / ■ 停止控制）",
     "Click to enable (in-memory; actual operation is controlled by Start / Stop)"),
    ("tunnel.client.title", "Client（穿透客户端 · 部署在内网机器）", "Client (client · runs on the intranet machine)"),
    ("tunnel.server.title", "Server（穿透服务端 · 部署在公网服务器）", "Server (server · runs on the public machine)"),
    ("tunnel.server.placeholder", "（Server 配置项待接入）", "(Server configuration fields pending)"),
    ("tunnel.server_address", "服务器地址：", "Server Address:"),
    ("tunnel.token", "令牌：", "Token:"),
    ("tunnel.proxies_label", "Proxies（每行一个）：", "Proxies (one per line):"),
    ("tunnel.proxies_format",
     "格式：name|本地地址:端口|远端端口（远端端口留空 = 服务端自动分配）\ne.g. ssh|127.0.0.1:22|6022  /  web|127.0.0.1:80|8080（发布个人网站）",
     "Format: name|local_addr:port|remote_port (empty remote_port = auto-assigned by server)\ne.g. ssh|127.0.0.1:22|6022  /  web|127.0.0.1:80|8080 (publish a website)"),
    ("tunnel.save", "保存", "Save"),
    ("tunnel.saved", "已保存", "Saved"),
    ("tunnel.save_failed", "保存失败：{0}", "Save failed: {0}"),
];
