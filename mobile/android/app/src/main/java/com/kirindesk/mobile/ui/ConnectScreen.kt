package com.kirindesk.mobile.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kirindesk.mobile.NativeBridge
import com.kirindesk.mobile.R
import java.text.DateFormat
import java.util.Date

/**
 * - **IP 连接**（Tab 0）：服务器地址:端口 + 昵称 + 挑战码——无设备 ID 字段、
 *   无 relay 字段（P1-A「token 非空隐式切 ID 模式」废除，模式由用户显式选择）；
 * - **ID 连接**（Tab 1）：设备 ID（历史下拉回填）+ 昵称 + 挑战码 + 折叠
 *   relay 区（server_addr / token / server_pubkey——与设置页读写同一
 *   SharedPreferences("relay")，单一数据源；取值来自被控端 Tunnel 页）；
 *   被控端昵称 + 挑战码（凭据口径对齐桌面域名模式）——SRV/TXT/A|AAAA
 *   三件套经加密 DNS（DoH/DoT）发现，解析失败按码给中英可读文案；
 * - 模式与各字段 SharedPreferences 持久化（模式键 connect.mode；IP 字段
 *   connect.*；域名 connect.domain_host；relay 三件套 relay.*）；
 * - 右上角齿轮 → 设置页（relay 服务器/分辨率档位/语言/关于 集中管理）；
 *   （本机作被控端：MediaProjection 屏幕共享，电脑看手机）；
 * - TOFU 首连：指纹确认对话框（与挑战码同屏；短码发起加额外警示）。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectScreen(
    state: SessionState,
    onConnected: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenServer: () -> Unit,
) {
    val context = LocalContext.current
    var version by remember { mutableStateOf("") }
    var historyExpanded by remember { mutableStateOf(false) }

    val connectPrefs = remember {
        context.getSharedPreferences("connect", android.content.Context.MODE_PRIVATE)
    }
    var mode by remember {
        mutableStateOf(connectPrefs.getInt("mode", MODE_IP).coerceIn(MODE_IP, MODE_DOMAIN))
    }
    var serverAddr by remember {
        mutableStateOf(connectPrefs.getString("server_addr", "") ?: "")
    }
    var deviceId by remember {
        mutableStateOf(connectPrefs.getString("device_id", "") ?: "")
    }
    var domainHost by remember {
        mutableStateOf(connectPrefs.getString("domain_host", "") ?: "")
    }
    var nickname by remember {
        mutableStateOf(connectPrefs.getString("nickname", "") ?: "")
    }
    var challenge by remember {
        mutableStateOf(connectPrefs.getString("challenge", "") ?: "")
    }

    // relay 配置（ID 模式三件套；SharedPreferences("relay") 本机持久化——
    // 与设置页同一存储（单一数据源），设置页改动返回本页后重读生效）。
    val relayPrefs = remember { context.getSharedPreferences("relay", android.content.Context.MODE_PRIVATE) }
    var relayAddr by remember { mutableStateOf(relayPrefs.getString("server_addr", "") ?: "") }
    var relayToken by remember { mutableStateOf(relayPrefs.getString("token", "") ?: "") }
    var relayPubkey by remember { mutableStateOf(relayPrefs.getString("server_pubkey", "") ?: "") }
    var showRelay by remember { mutableStateOf(false) }

    fun persistConnect(key: String, value: String) {
        connectPrefs.edit().putString(key, value.trim()).apply()
    }

    // 连接校验 + 发起（必填随模式；错误文案本地化）。
    val validateAndConnect: () -> Unit = {
        val err = when {
            mode == MODE_IP && serverAddr.isBlank() -> context.getString(R.string.err_server_addr_empty)
            mode == MODE_IP && nickname.isBlank() -> context.getString(R.string.err_nickname_empty)
            mode == MODE_ID && deviceId.isBlank() -> context.getString(R.string.err_device_id_empty)
            mode == MODE_ID && relayAddr.isBlank() -> context.getString(R.string.err_relay_addr_empty)
            mode == MODE_ID && relayToken.isBlank() -> context.getString(R.string.err_relay_token_empty)
            mode == MODE_ID && relayPubkey.isBlank() -> context.getString(R.string.err_relay_pubkey_empty)
            mode == MODE_ID && nickname.isBlank() -> context.getString(R.string.err_nickname_empty)
            mode == MODE_DOMAIN && domainHost.isBlank() -> context.getString(R.string.err_domain_empty)
            mode == MODE_DOMAIN && nickname.isBlank() -> context.getString(R.string.err_nickname_empty)
            challenge.isBlank() -> context.getString(R.string.err_challenge_empty)
            else -> null
        }
        if (err != null) {
            state.error = err
        } else if (mode == MODE_IP) {
            // 配置值，与挑战码成对的握手凭据——服务端按 init.client_id 比对，
            // mobile/src/orchestration.rs connect_and_run_address）——以 id
            // 参数传入（→ server_id → client_id）；token/relay 不用（Rust 侧
            // 再强制清 token，双保险）。
            state.connect(NativeBridge.CONNECT_MODE_IP, nickname, nickname, challenge,
                serverAddr, "", "") { onConnected() }
        } else if (mode == MODE_DOMAIN) {
            // 昵称（凭据口径对齐桌面域名/IP 模式）；token/pubkey 不用（信任
            // 锚 = DNS TXT 公钥 + TOFU，Rust 侧清空双保险）。
            state.connect(NativeBridge.CONNECT_MODE_DOMAIN, nickname, nickname, challenge,
                domainHost, "", "") { onConnected() }
        } else {
            state.connect(NativeBridge.CONNECT_MODE_ID, deviceId, nickname, challenge,
                relayAddr, relayToken, relayPubkey) { onConnected() }
        }
    }

    LaunchedEffect(Unit) {
        runCatching { version = NativeBridge.nativeVersion() }
        state.reloadHistory()
    }

    // TOFU 轮询：nativeConnect 阻塞期间每 200ms 读待确认指纹（两段式）。
    LaunchedEffect(state.connecting) {
        while (state.connecting) {
            state.pollPendingTrust()
            kotlinx.coroutines.delay(200)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                "KirinDesk",
                style = MaterialTheme.typography.headlineMedium,
                modifier = Modifier.weight(1f),
            )
            IconButton(onClick = onOpenSettings) {
                Icon(
                    Icons.Filled.Settings,
                    contentDescription = stringResource(R.string.settings_title),
                )
            }
        }

        TabRow(selectedTabIndex = mode) {
            Tab(
                selected = mode == MODE_IP,
                onClick = {
                    mode = MODE_IP
                    connectPrefs.edit().putInt("mode", MODE_IP).apply()
                },
                text = { Text(stringResource(R.string.tab_ip_mode)) },
            )
            Tab(
                selected = mode == MODE_ID,
                onClick = {
                    mode = MODE_ID
                    connectPrefs.edit().putInt("mode", MODE_ID).apply()
                },
                text = { Text(stringResource(R.string.tab_id_mode)) },
            )
            Tab(
                selected = mode == MODE_DOMAIN,
                onClick = {
                    mode = MODE_DOMAIN
                    connectPrefs.edit().putInt("mode", MODE_DOMAIN).apply()
                },
                text = { Text(stringResource(R.string.tab_domain_mode)) },
            )
        }
        Text(
            stringResource(
                when (mode) {
                    MODE_IP -> R.string.subtitle_direct
                    MODE_ID -> R.string.subtitle_id_mode
                    else -> R.string.subtitle_domain_mode
                },
            ),
            style = MaterialTheme.typography.bodySmall,
            textAlign = TextAlign.Center,
        )

        if (mode == MODE_IP) {
            // ── IP 模式：地址:端口 + 昵称 + 挑战码（无 ID 字段） ──
            OutlinedTextField(
                value = serverAddr,
                onValueChange = {
                    serverAddr = it
                    persistConnect("server_addr", it)
                },
                label = { Text(stringResource(R.string.field_server_addr)) },
                placeholder = { Text(stringResource(R.string.server_addr_hint)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                modifier = Modifier.fillMaxWidth(),
            )
        } else if (mode == MODE_DOMAIN) {
            OutlinedTextField(
                value = domainHost,
                onValueChange = {
                    domainHost = it
                    persistConnect("domain_host", it)
                },
                label = { Text(stringResource(R.string.field_domain_host)) },
                placeholder = { Text(stringResource(R.string.domain_host_hint)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                stringResource(R.string.domain_mode_hint),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            // ── ID 模式：设备 ID（历史下拉）+ 折叠 relay 区 ──
            if (state.history.isNotEmpty()) {
                ExposedDropdownMenuBox(
                    expanded = historyExpanded,
                    onExpandedChange = { historyExpanded = it },
                ) {
                    OutlinedTextField(
                        value = deviceId,
                        onValueChange = {
                            deviceId = it
                            persistConnect("device_id", it)
                        },
                        label = { Text(stringResource(R.string.field_device_id)) },
                        placeholder = { Text(stringResource(R.string.device_id_hint)) },
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .menuAnchor(MenuAnchorType.PrimaryEditable),
                    )
                    ExposedDropdownMenu(
                        expanded = historyExpanded,
                        onDismissRequest = { historyExpanded = false },
                    ) {
                        state.history.take(10).forEach { entry ->
                            DropdownMenuItem(
                                text = {
                                    Column {
                                        Text(entry.label, style = MaterialTheme.typography.bodyMedium)
                                        Text(
                                            formatLastSeen(entry.lastSeen),
                                            style = MaterialTheme.typography.labelSmall,
                                        )
                                    }
                                },
                                onClick = {
                                    deviceId = entry.id
                                    persistConnect("device_id", entry.id)
                                    historyExpanded = false
                                },
                            )
                        }
                    }
                }
            } else {
                OutlinedTextField(
                    value = deviceId,
                    onValueChange = {
                        deviceId = it
                        persistConnect("device_id", it)
                    },
                    label = { Text(stringResource(R.string.field_device_id)) },
                    placeholder = { Text(stringResource(R.string.device_id_hint)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            TextButton(onClick = { showRelay = !showRelay }) {
                Text(
                    stringResource(
                        if (showRelay) R.string.advanced_hide else R.string.advanced_show,
                    ),
                )
            }
            if (showRelay) {
                OutlinedTextField(
                    value = relayAddr,
                    onValueChange = {
                        relayAddr = it
                        relayPrefs.edit().putString("server_addr", it.trim()).apply()
                    },
                    label = { Text(stringResource(R.string.relay_addr)) },
                    placeholder = { Text(stringResource(R.string.relay_addr_hint)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = relayToken,
                    onValueChange = {
                        relayToken = it
                        relayPrefs.edit().putString("token", it.trim()).apply()
                    },
                    label = { Text(stringResource(R.string.relay_token)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = relayPubkey,
                    onValueChange = {
                        relayPubkey = it
                        relayPrefs.edit().putString("server_pubkey", it.trim()).apply()
                    },
                    label = { Text(stringResource(R.string.relay_pubkey)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(
                    stringResource(R.string.relay_hint),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        // ── 公共字段（各模式同构）：昵称 + 挑战码 ──
        // IP/域名模式昵称 = 被控端昵称（握手凭据，须与 Dashboard 配置一致）；
        // ID 模式昵称 = 本端备注（ID 模式握手不校验昵称，仅历史标签）。
        OutlinedTextField(
            value = nickname,
            onValueChange = {
                nickname = it
                persistConnect("nickname", it)
            },
            label = {
                Text(
                    stringResource(
                        when (mode) {
                            MODE_ID -> R.string.field_nickname
                            else -> R.string.field_server_nickname
                        },
                    ),
                )
            },
            supportingText = {
                if (mode != MODE_ID) {
                    Text(stringResource(R.string.server_nickname_hint))
                }
            },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = challenge,
            onValueChange = {
                challenge = it
                persistConnect("challenge", it)
            },
            label = { Text(stringResource(R.string.field_challenge)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        state.error?.let { raw ->
            // DNS 不可用等中英）；未知错误回退原始串（与既有行为一致）。
            val localized = NativeBridge.domainErrorRes(raw)?.let { context.getString(it) }
            Text(
                localized ?: raw,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }

        Button(
            onClick = validateAndConnect,
            enabled = !state.connecting,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                stringResource(
                    if (state.connecting) R.string.connecting else R.string.connect,
                ),
            )
        }

        OutlinedButton(
            onClick = onOpenServer,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(stringResource(R.string.server_entry))
        }

        Text(
            stringResource(R.string.footer_tofu),
            style = MaterialTheme.typography.labelSmall,
        )
        Text(
            "nativeVersion: ${version.ifBlank { "—" }}",
            style = MaterialTheme.typography.labelSmall,
        )
    }

    // ── TOFU 首连指纹确认对话框（known_hosts 未命中时出现） ──
    state.pendingFingerprint?.let { fingerprint ->
        AlertDialog(
            onDismissRequest = { state.resolveTrust(false) },
            title = { Text(stringResource(R.string.trust_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.trust_body))
                    if (challenge.isNotBlank()) {
                        Text(
                            stringResource(R.string.trust_challenge_label, challenge),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    if (mode == MODE_ID && isShortCodeInput(deviceId)) {
                        Text(
                            stringResource(R.string.trust_short_code_warning),
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    Text(
                        stringResource(R.string.trust_fingerprint_label),
                        style = MaterialTheme.typography.labelSmall,
                    )
                    Text(
                        fingerprint,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 13.sp,
                    )
                    Text(
                        stringResource(R.string.trust_mitm_warning),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = { state.resolveTrust(true) }) {
                    Text(stringResource(R.string.trust_accept))
                }
            },
            dismissButton = {
                TextButton(onClick = { state.resolveTrust(false) }) {
                    Text(stringResource(R.string.trust_decline))
                }
            },
        )
    }
}

/** 连接模式常量（与 Rust nativeConnect2 的 mode 枚举 int 对齐）。 */
private const val MODE_IP = 0
private const val MODE_ID = 1
private const val MODE_DOMAIN = 2

/** 短码形态判定（对话框警示置位用；canonical 判定在 Rust 侧，此处仅 UI 提示）。 */
private fun isShortCodeInput(id: String): Boolean {
    val t = id.trim()
    return t.length == 10 && t.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' } &&
        (t == t.lowercase() || t == t.uppercase())
}

/** RFC3339 → 本地化短显示（chrono `+00:00` 后缀归一为 `Z`；失败 → 空串）。 */
private fun formatLastSeen(lastSeen: String?): String =
    runCatching {
        lastSeen?.let {
            val normalized = it.replace("+00:00", "Z")
            val t = runCatching { java.time.Instant.parse(normalized) }
                .getOrElse { _ -> java.time.OffsetDateTime.parse(it).toInstant() }
            DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
                .format(Date.from(t))
        } ?: ""
    }.getOrDefault("")
