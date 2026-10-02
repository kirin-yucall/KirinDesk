package com.kirindesk.mobile.ui

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kirindesk.mobile.MainActivity
import com.kirindesk.mobile.NativeBridge
import com.kirindesk.mobile.R
import com.kirindesk.mobile.server.AccessibilityInputService
import com.kirindesk.mobile.server.ScreenShareService

/**
 *
 * - **凭据字段**（fail-closed，必填校验齐才允许启动）：昵称（必填，连接
 *   凭据，大小写敏感）/ 挑战码（必填，密文样式——缺失时 Rust 侧全连接
 *   拒绝）/ 端口（默认 59990，0 = 临时端口）/ relay 三件套折叠区（选填，
 *   与连接页 ID Tab、设置页读写同一 `SharedPreferences("relay")` = 单一
 *   数据源；任一非空即须三件齐全，server_pubkey 缺失 fail-closed 拒注册）；
 * - **本机信息区**：设备 ID + 79 位指纹（`nativeServerStatus`——未运行时
 *   identity 字段亦可得，device_id 未启动为空串显示占位）；
 * - **运行态**：状态点 + 端口/观众/ID 注册（1s 轮询 `nativeServerStatus`）
 *   +「停止共享」；启动失败原因（系统授权拒绝 / nativeServerStart 异常）
 *   由服务记入 SharedPreferences("server").start_error，轮询拾取展示；
 * - **启动流**：校验 → 字段落盘 → [MainActivity.launchScreenShareFlow]
 *  （API 33+ 先链式请求 POST_NOTIFICATIONS，再 MediaProjection 系统授权
 *   弹窗）→ 授权成功 → [ScreenShareService]（startForeground →
 *   nativeServerStart → 捕获启动，顺序纪律在服务内固定）；
 *   同一组件复用——对 `nativeServerStatus.viewer_ids` 每个观众 1s 纯拉
 *   `nativeGetFileTransfers`（**并入本既有 1s 轮询循环**，viewerId 即
 *   sessionHandle）合并条目；Offer 弹窗/列表/分享/取消同控制端口径
 *   （弹窗经条目来源标注展示来源观众——首次见序友好编号）；每观众行
 *   「发送文件」= 同一 SAF + 暂存流程（该观众 viewerId 作目标会话）。
 *
 * 生命周期：退后台/转屏共享不断（前台服务保活）；通知栏停止 / 系统撤销
 * 授权 → 服务 onDestroy → nativeServerStop → 本页轮询发现 running=false
 * 自动回「未共享」。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ServerScreen(fileTransfer: FileTransferManager, onBack: () -> Unit) {
    val context = LocalContext.current
    // Compose Activity 的 LocalContext 即 Activity 本身（同模块直取，不依赖
    // activity-compose 版本 API 面）。
    val activity = context as? MainActivity
    val serverPrefs = remember { context.getSharedPreferences("server", Context.MODE_PRIVATE) }
    val relayPrefs = remember { context.getSharedPreferences("relay", Context.MODE_PRIVATE) }

    var nickname by remember { mutableStateOf(serverPrefs.getString("nickname", "") ?: "") }
    var challenge by remember { mutableStateOf(serverPrefs.getString("challenge", "") ?: "") }
    var portText by remember { mutableStateOf(serverPrefs.getString("port", "59990") ?: "59990") }
    var relayAddr by remember { mutableStateOf(relayPrefs.getString("server_addr", "") ?: "") }
    var relayToken by remember { mutableStateOf(relayPrefs.getString("token", "") ?: "") }
    var relayPubkey by remember { mutableStateOf(relayPrefs.getString("server_pubkey", "") ?: "") }
    var showRelay by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var starting by remember { mutableStateOf(false) }
    var startRequestedAt by remember { mutableStateOf(0L) }
    var status by remember { mutableStateOf(NativeBridge.parseServerStatus("")) }
    // 设置返回后随 1s 轮询自动刷新状态点）。
    var remoteInputEnabled by remember { mutableStateOf(isInputServiceEnabled(context)) }
    // 展示用；viewerId 仅注册表键，不直接上屏）。
    val viewerOrdinal = remember { HashMap<Long, Int>() }

    // 1s 轮询：运行态展示 + 启动错误拾取（服务侧失败落 start_error）+
    LaunchedEffect(Unit) {
        while (true) {
            runCatching { status = NativeBridge.parseServerStatus(NativeBridge.nativeServerStatus()) }
            remoteInputEnabled = isInputServiceEnabled(context)
            // 合并（viewerId 基址 2^48 = sessionHandle，与控制端句柄空间
            // 不相交）；未运行/观众消失 → poll 差集自动清簿记与暂存。
            runCatching {
                if (status.running) {
                    for (vid in status.viewerIds) {
                        if (viewerOrdinal[vid] == null) {
                            viewerOrdinal[vid] = viewerOrdinal.size + 1
                        }
                    }
                    fileTransfer.poll(
                        status.viewerIds.map { vid ->
                            vid to context.getString(
                                R.string.ft_viewer,
                                viewerOrdinal.getValue(vid),
                            )
                        },
                    )
                } else {
                    fileTransfer.poll(emptyList())
                }
            }
            if (status.running) {
                starting = false
                error = null
            } else if (starting) {
                val savedErr = serverPrefs.getString("start_error", null)
                if (savedErr != null) {
                    serverPrefs.edit().remove("start_error").apply()
                    error = savedErr
                    starting = false
                } else if (System.currentTimeMillis() - startRequestedAt > START_TIMEOUT_MS) {
                    // 授权弹窗期间轮询保持等待；超时 = 授权未完成或服务未起。
                    error = context.getString(R.string.server_err_timeout)
                    starting = false
                }
            }
            kotlinx.coroutines.delay(1000)
        }
    }

    /** 页面停止：stopService → 服务 onDestroy → teardown（nativeServerStop
     *  + projection.stop）；状态经轮询同步（running=false）。 */
    fun stopSharing() {
        context.stopService(Intent(context, ScreenShareService::class.java))
        starting = false
    }

    /** 打开系统无障碍设置（引导用户启用 [AccessibilityInputService]；
     *  返回后状态点随轮询刷新）。 */
    fun openAccessibilitySettings() {
        runCatching {
            context.startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
        }
    }

    val startSharing: () -> Unit = {
        // fail-closed：必填校验齐（昵称/挑战码/合法端口；relay 三件全有或全无）
        // 才允许启动。
        val port = portText.trim().toIntOrNull()
        val relayAny = relayAddr.isNotBlank() || relayToken.isNotBlank() || relayPubkey.isNotBlank()
        val err = when {
            nickname.isBlank() -> context.getString(R.string.server_err_nickname_empty)
            challenge.isBlank() -> context.getString(R.string.err_challenge_empty)
            port == null || port !in 0..65535 -> context.getString(R.string.server_err_port_invalid)
            relayAny && (relayAddr.isBlank() || relayToken.isBlank() || relayPubkey.isBlank())
                -> context.getString(R.string.server_err_relay_partial)
            else -> null
        }
        if (err != null) {
            error = err
        } else {
            // 落盘（服务启动前读同一存储，单一数据源；relay 三件随输入即时持久化）。
            serverPrefs.edit()
                .putString("nickname", nickname.trim())
                .putString("challenge", challenge.trim())
                .putString("port", portText.trim())
                .apply()
            error = null
            starting = true
            startRequestedAt = System.currentTimeMillis()
            // 非 Activity 宿主（预览等）时不发起；真实页面 LocalContext 恒为
            // MainActivity。
            activity?.launchScreenShareFlow()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(
                    Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = stringResource(R.string.settings_back),
                )
            }
            Text(
                stringResource(R.string.server_title),
                style = MaterialTheme.typography.headlineSmall,
            )
        }
        Text(
            stringResource(R.string.server_subtitle),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // ── 运行态（1s 轮询 nativeServerStatus） ──
        Surface(tonalElevation = 2.dp, shape = MaterialTheme.shapes.medium) {
            Column(
                Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        Modifier
                            .size(10.dp)
                            .clip(CircleShape)
                            .background(
                                if (status.running) Color(0xFF4CAF50) else Color(0xFF757575),
                            ),
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        if (status.running) {
                            stringResource(R.string.server_status_running, status.port, status.viewers)
                        } else {
                            stringResource(R.string.server_status_idle)
                        },
                        style = MaterialTheme.typography.titleSmall,
                    )
                }
                if (status.running && status.idModeEnabled) {
                    Text(
                        stringResource(
                            if (status.idRegistered) R.string.server_id_registered
                            else R.string.server_id_pending,
                        ),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (status.running) {
                    OutlinedButton(onClick = ::stopSharing, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.server_stop))
                    }
                }
            }
        }

        //    分享/取消同控制端口径，弹窗标注来源观众） ──
        if (status.running) {
            SectionHeader(stringResource(R.string.ft_title))
            status.viewerIds.forEach { vid ->
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        stringResource(R.string.ft_viewer, viewerOrdinal.getValue(vid)),
                        style = MaterialTheme.typography.titleSmall,
                    )
                    Spacer(Modifier.weight(1f))
                    OutlinedButton(
                        onClick = {
                            fileTransfer.prepareSend(vid)
                            activity?.pickTransferFile()
                        },
                        enabled = !fileTransfer.stagingBusy,
                    ) {
                        Text(
                            stringResource(R.string.ft_send),
                            style = MaterialTheme.typography.labelMedium,
                        )
                    }
                }
            }
            FileTransferList(fileTransfer, lazy = false)
        }

        HorizontalDivider()

        // ── 本机信息（nativeServerStatus；未运行时 identity 字段亦可得） ──
        SectionHeader(stringResource(R.string.settings_section_device))
        Text(
            stringResource(R.string.settings_device_id_label),
            style = MaterialTheme.typography.labelSmall,
        )
        Text(
            status.deviceId.ifBlank { "—" },
            fontFamily = FontFamily.Monospace,
            fontSize = 13.sp,
        )
        Text(
            stringResource(R.string.trust_fingerprint_label),
            style = MaterialTheme.typography.labelSmall,
        )
        Text(
            status.fingerprint.ifBlank { "—" },
            fontFamily = FontFamily.Monospace,
            fontSize = 13.sp,
        )

        HorizontalDivider()

        //    未启用 → 系统无障碍设置跳转引导） ──
        SectionHeader(stringResource(R.string.server_section_remote))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier
                    .size(10.dp)
                    .clip(CircleShape)
                    .background(
                        if (remoteInputEnabled) Color(0xFF4CAF50) else Color(0xFF757575),
                    ),
            )
            Spacer(Modifier.width(8.dp))
            Text(
                stringResource(
                    if (remoteInputEnabled) R.string.server_remote_enabled
                    else R.string.server_remote_disabled,
                ),
                style = MaterialTheme.typography.titleSmall,
            )
        }
        if (!remoteInputEnabled) {
            Text(
                stringResource(R.string.server_remote_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(
                onClick = { openAccessibilitySettings() },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.server_remote_open_settings))
            }
        }

        HorizontalDivider()

        // ── 共享设置（凭据；服务启动前读同一存储） ──
        SectionHeader(stringResource(R.string.server_section_config))
        OutlinedTextField(
            value = nickname,
            onValueChange = { nickname = it },
            label = { Text(stringResource(R.string.server_field_nickname)) },
            supportingText = { Text(stringResource(R.string.server_viewers_hint)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = challenge,
            onValueChange = { challenge = it },
            label = { Text(stringResource(R.string.server_field_challenge)) },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = portText,
            onValueChange = { portText = it },
            label = { Text(stringResource(R.string.server_field_port)) },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        TextButton(onClick = { showRelay = !showRelay }) {
            Text(
                stringResource(
                    if (showRelay) R.string.server_advanced_hide else R.string.server_advanced_show,
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
                stringResource(R.string.server_relay_hint),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        error?.let {
            Text(
                it,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }

        Button(
            onClick = startSharing,
            enabled = !status.running && !starting,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                stringResource(
                    if (starting) R.string.server_starting else R.string.server_start,
                ),
            )
        }
    }

    // 条目 sourceLabel 标注来源观众）。
    FileTransferOfferDialog(fileTransfer)
}

@Composable
private fun SectionHeader(title: String) {
    Text(
        title,
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.padding(top = 4.dp),
    )
}

/**
 * 探测 [AccessibilityInputService] 是否已在系统无障碍已启用列表
 * （`Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES` 组件串逐条比对
 * `ComponentName.flattenToString`）。探测异常 → false（fail-soft，显示
 * 未启用引导，不阻塞页面）。
 */
private fun isInputServiceEnabled(context: Context): Boolean {
    return runCatching {
        val enabled = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
        ) ?: return false
        val target = ComponentName(context, AccessibilityInputService::class.java)
            .flattenToString()
        enabled.split(':').any { it.trim() == target }
    }.getOrDefault(false)
}

/** 启动超时（授权弹窗期间轮询等待；超时提示用户重试）。 */
private const val START_TIMEOUT_MS = 60_000L
