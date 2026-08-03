//! M8-T038 (P5): Domain 页（domain_panel.rs）键值表（zh 基线 + en 全量）。
//! 本分区文件由 M8-T038_P5 独占认领。
//!
//! zh 为基线语言包；en 全量翻译（不得留空串）。
//! 动态文案模板使用 `{0}`/`{1}` 位置参数，zh/en 占位符一一对应。
//!
//! M9-DNS022（UI-DNS-004）：文案全面泛化——不再出现 GoDaddy 字样，
//! 未配置引导指向 Domain 页「服务商」卡。

pub static TABLE: &[(&str, &str, &str)] = &[
    // ── 页面 / 卡标题 ──
    ("domain.title", "DNS 域名维护", "DNS Domain Maintenance"),
    ("domain.provider.title", "服务商", "Provider"),
    ("domain.list.title", "域名列表", "Domain list"),
    ("domain.record.title", "解析记录", "DNS records"),

    // ── 错误（provider_from_config / fmt_provider_error）──
    ("domain.error.config_load", "配置读取失败: {0}", "Failed to read config: {0}"),
    ("domain.error.provider_unsupported",
     "服务商「{0}」的客户端适配尚未实现，暂无法在此维护域名",
     "Client adapter for provider \"{0}\" is not implemented yet; domain maintenance is unavailable"),
    ("domain.error.not_configured",
     "DNS 服务商未配置 — 请到 Domain 页「服务商」卡填写凭据后保存",
     "DNS provider not configured — fill in the credentials in the Provider card on the Domain tab and save"),
    ("domain.error.client_init", "服务商初始化失败: {0}", "Provider initialization failed: {0}"),
    ("domain.error.rate_limited", "限流：请求过于频繁，请稍后重试", "Rate limited: too many requests, please retry later"),
    ("domain.error.invalid_params", "参数错误: {0}", "Invalid parameters: {0}"),
    ("domain.error.auth_failed", "认证失败：API 凭据无效或无权限", "Authentication failed: API credentials invalid or unauthorized"),
    ("domain.error.server_error", "服务商服务异常（HTTP {0}），请稍后重试", "Provider service error (HTTP {0}), please retry later"),
    ("domain.error.network", "网络错误：无法连接服务商 API（超时/连接失败）", "Network error: cannot reach the provider API (timeout/connection failed)"),
    ("domain.error.config", "配置错误: {0}", "Configuration error: {0}"),
    ("domain.error.json", "服务商返回数据格式异常", "Provider returned malformed data"),
    ("domain.error.not_found", "未找到（域名不可管理或记录不存在）", "Not found (domain not manageable or record does not exist)"),
    ("domain.error.unsupported_type",
     "该服务商不支持此记录类型 {0}",
     "This provider does not support record type {0}"),

    // ── 凭据（UI-DNS-002，动态字段表单）──
    ("domain.cred.required_field", "{0} 必填", "{0} is required"),
    ("domain.cred.domain_invalid", "Domain 格式无效（需为 RFC 1123 主机名，如 example.com）", "Invalid domain (must be an RFC 1123 hostname, e.g. example.com)"),
    ("domain.cred.config_load_failed", "配置读取失败", "Failed to read config"),
    ("domain.cred.saved", "已保存（服务商与凭据即时生效）", "Saved (provider and credentials take effect immediately)"),
    ("domain.cred.save_failed", "保存失败: {0}", "Save failed: {0}"),

    // ── 测试连接（DNS-MNT-003）──
    ("domain.test.ok", "连接成功 — 服务商 API 可用", "Connected — provider API is reachable"),
    ("domain.test.failed", "测试失败: {0}", "Test failed: {0}"),
    ("domain.test.testing", "测试连接中…", "Testing connection…"),

    // ── 状态行 ──
    ("domain.status.domains_loaded", "已获取 {0} 个域名", "Fetched {0} domain(s)"),
    ("domain.status.records_loaded", "{0} — {1} 条记录", "{0} — {1} record(s)"),
    ("domain.status.records_error", "{0}: {1}", "{0}: {1}"),
    ("domain.status.saved_refresh", "已保存（刷新记录列表）", "Saved (refreshing the record list)"),
    ("domain.status.fetching_domains", "正在获取域名列表…", "Fetching the domain list…"),
    ("domain.status.loading_records", "正在加载 {0} 的记录…", "Loading records of {0}…"),
    ("domain.status.domain_added", "已添加（选择后可拉取解析记录验证可管理性）", "Added (select it to fetch DNS records and verify manageability)"),
    ("domain.status.deleting", "删除 {0} {1} 中…", "Deleting {0} {1}…"),

    // ── 服务商卡 ──
    ("domain.provider.configured", "凭据已配置", "Credentials configured"),
    ("domain.provider.not_configured", "未配置", "Not configured"),
    ("domain.provider.hint",
     "服务商与凭据在此维护（保存即时生效）；保存后可用「测试连接」验证。",
     "Maintain the provider and credentials here (saved immediately); then verify with \"Test connection\"."),
    ("domain.provider.label", "域名服务商：", "Domain provider:"),
    ("domain.provider.switched",
     "已切换服务商 — 填写凭据后点「保存凭据」（该服务商未适配时提示开发中）",
     "Provider switched — fill in the credentials and click \"Save credentials\" (an unadapted provider shows an under-development notice)"),
    ("domain.provider.unsupported",
     "该服务商的客户端适配尚未实现 — 暂不支持域名维护，可先行保存凭据备后续版本。",
     "Client adapter for this provider is not implemented yet — domain maintenance is unavailable for now; you may still save the credentials for a later version."),
    ("domain.provider.save_credentials", "保存凭据", "Save credentials"),
    ("domain.provider.test_connection", "测试连接", "Test connection"),
    // UI-DNS-009：能力降级警示（记录卡顶部 / 编辑弹窗）。
    ("domain.provider.caps_srv_warning",
     "该服务商不支持 SRV 记录——设备注册将降级为 A/AAAA+TXT",
     "This provider does not support SRV records — device registration will degrade to A/AAAA+TXT"),
    ("domain.provider.caps_ns_warning",
     "该服务商不支持 NS 记录",
     "This provider does not support NS records"),
    ("domain.provider.srv_degraded",
     "SRV 记录已禁用 — 设备注册将降级为 A/AAAA+TXT",
     "SRV records are disabled — device registration will degrade to A/AAAA+TXT"),
    // Connect 页域名模式未配置引导（UI-DNS-004 泛化，不再出现 GoDaddy 字样）。
    ("domain.provider.connect_guide",
     "请先到 Domain 页「服务商」卡配置 DNS 服务商与凭据，再使用域名发现连接。",
     "Configure the DNS provider and credentials in the Provider card on the Domain tab first, then use domain discovery to connect."),
    ("domain.provider.goto_domain", "前往 Domain 页配置", "Go to the Domain tab to configure"),

    // ── 域名列表卡 ──
    ("domain.list.refresh", "刷新域名", "Refresh domains"),
    ("domain.list.add_label", "添加域名：", "Add domain:"),
    ("domain.list.add_placeholder", "example.com（可维护列表之外手动指定）", "example.com (manually specified outside the maintainable list)"),
    ("domain.list.add_button", "添加域名", "Add domain"),
    ("domain.list.empty",
     "暂无域名 — 点击「刷新域名」从服务商拉取，或手动「添加域名」。",
     "No domains yet — click \"Refresh domains\" to fetch from the provider, or add one manually."),
    ("domain.list.load_hint", "点击加载该域名的解析记录", "Click to load this domain's DNS records"),

    // ── 解析记录卡 ──
    ("domain.record.select_hint",
     "先在左侧「域名列表」选择一个域名（未拉取过请先点「刷新域名」）。",
     "First select a domain in the domain list above (refresh the list first if it was never fetched)."),
    ("domain.record.filter_label", "类型筛选：", "Type filter:"),
    ("domain.record.filter_all", "全部", "All"),
    ("domain.record.add", "添加记录", "Add record"),
    ("domain.record.edit", "编辑记录", "Edit record"),
    ("domain.record.delete", "删除", "Delete"),
    ("domain.record.loading", "加载记录中…", "Loading records…"),
    ("domain.record.empty",
     "该域名暂无记录（或筛选无匹配）— 点击「添加记录」创建。",
     "No records for this domain (or no match for the filter) — click \"Add record\" to create one."),
    ("domain.record.table.type", "类型", "Type"),
    ("domain.record.table.name", "名称", "Name"),
    ("domain.record.table.data", "数据", "Data"),
    ("domain.record.table.actions", "操作", "Actions"),
    ("domain.record.ttl_hint", "TTL 秒（最低 600）", "TTL seconds (minimum 600)"),

    // ── 编辑弹窗（UI-DNS-007）──
    ("domain.edit.domain_label", "域名: {0}", "Domain: {0}"),
    ("domain.edit.type_label", "类型：", "Type:"),
    ("domain.edit.name_label", "名称：", "Name:"),
    ("domain.edit.name_placeholder", "@（根记录）或 my-pc / _remote._tcp", "@ (root record) or my-pc / _remote._tcp"),
    ("domain.edit.srv_priority", "优先级：", "Priority:"),
    ("domain.edit.srv_weight", "权重：", "Weight:"),
    ("domain.edit.srv_port", "端口：", "Port:"),
    ("domain.edit.srv_target", "目标：", "Target:"),
    ("domain.edit.ph_a", "1.2.3.4（IPv4）", "1.2.3.4 (IPv4)"),
    ("domain.edit.ph_aaaa", "2001:db8::1（IPv6）", "2001:db8::1 (IPv6)"),
    ("domain.edit.ph_mx", "10 mail.example.com（优先级 主机）", "10 mail.example.com (priority host)"),
    ("domain.edit.ph_data", "记录数据", "record data"),
    ("domain.edit.data_label", "数据：", "Data:"),
    ("domain.edit.ttl_label", "TTL：", "TTL:"),
    ("domain.edit.save", "保存", "Save"),
    ("domain.edit.name_invalid", "记录名无效（允许 @ 根记录或合法记录名，如 my-pc、_remote._tcp）", "Invalid record name (allowed: @ root record or a valid name like my-pc, _remote._tcp)"),
    ("domain.edit.ttl_invalid", "TTL 需为 ≥ 600 的整数秒", "TTL must be an integer ≥ 600 seconds"),
    ("domain.edit.srv_priority_invalid", "SRV priority 需为整数", "SRV priority must be an integer"),
    ("domain.edit.srv_weight_invalid", "SRV weight 需为整数", "SRV weight must be an integer"),
    ("domain.edit.srv_port_invalid", "SRV port 需为 1–65535", "SRV port must be 1-65535"),
    ("domain.edit.srv_target_invalid", "SRV target 需为合法主机名", "SRV target must be a valid hostname"),
    ("domain.edit.data_empty", "记录数据不能为空", "Record data must not be empty"),
    ("domain.edit.busy", "有任务进行中，请稍候", "A task is running, please wait"),
    ("domain.edit.adding", "添加 {0} {1} …", "Adding {0} {1} …"),
    ("domain.edit.updating", "更新 {0} {1} …", "Updating {0} {1} …"),
];
