package com.kirindesk.mobile.ui

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import com.kirindesk.mobile.NativeBridge
import com.kirindesk.mobile.R
import java.io.File

/**
 *
 * - **relay 服务器**（ID 模式三件套）：与连接页 ID Tab 折叠区读写同一
 *   `SharedPreferences("relay")`（单一数据源，两处编辑互通）；
 * - **连接偏好**：分辨率上报档位 720p(1280)/1080p(1920)/原生(0)——
 *   `nativeSetRequestedWidth` 驱动握手 requested_max_width（下次连接生效）；
 * - **设备信息**：本机身份（设备 ID + 79 位指纹，`nativeIdentity`）；
 * - **语言**：随系统 / 中文 / English（attachBaseContext 应用，切换即重建）；
 * - **关于**：nativeVersion / 应用版本 / 日志导出（files/kirin_mobile.log
 *   经 FileProvider 分享——系统分享面板可选保存到云端/文件管理器）。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val settingsPrefs = remember {
        context.getSharedPreferences("settings", Context.MODE_PRIVATE)
    }
    // relay 三件套：与 ConnectScreen 同一存储（单一数据源）。
    val relayPrefs = remember { context.getSharedPreferences("relay", Context.MODE_PRIVATE) }
    var relayAddr by remember { mutableStateOf(relayPrefs.getString("server_addr", "") ?: "") }
    var relayToken by remember { mutableStateOf(relayPrefs.getString("token", "") ?: "") }
    var relayPubkey by remember { mutableStateOf(relayPrefs.getString("server_pubkey", "") ?: "") }

    // 分辨率档位：Rust 全局槽位为准（App 启动时已回放持久化值）。
    var widthTier by remember { mutableStateOf(runCatching { NativeBridge.nativeRequestedWidth() }.getOrDefault(1280)) }
    var language by remember { mutableStateOf(settingsPrefs.getString("language", LANG_SYSTEM) ?: LANG_SYSTEM) }
    var identity by remember { mutableStateOf(NativeBridge.parseIdentity("")) }
    var version by remember { mutableStateOf("") }
    var appVersion by remember { mutableStateOf("") }
    var logStatus by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        runCatching { version = NativeBridge.nativeVersion() }
        runCatching {
            identity = NativeBridge.parseIdentity(NativeBridge.nativeIdentity())
        }
        runCatching {
            appVersion = context.packageManager
                .getPackageInfo(context.packageName, 0).versionName ?: ""
        }
    }

    fun setWidthTier(w: Int) {
        widthTier = w
        settingsPrefs.edit().putInt("requested_width", w).apply()
        runCatching { NativeBridge.nativeSetRequestedWidth(w) }
    }

    fun setLanguage(tag: String) {
        if (tag == language) return
        language = tag
        settingsPrefs.edit().putString("language", tag).apply()
        // 语言经 attachBaseContext 应用——重建 Activity 生效（Compose
        // 资源随 Activity locale 解析）。
        (context as? android.app.Activity)?.recreate()
    }

    fun exportLog() {
        val log = File(context.filesDir, "kirin_mobile.log")
        if (!log.exists()) {
            logStatus = context.getString(R.string.settings_log_missing)
            return
        }
        runCatching {
            val uri = FileProvider.getUriForFile(
                context, "${context.packageName}.fileprovider", log,
            )
            val send = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(
                Intent.createChooser(send, context.getString(R.string.settings_log_export)),
            )
            logStatus = context.getString(R.string.settings_log_shared, log.length())
        }.onFailure {
            logStatus = context.getString(R.string.settings_log_missing)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 16.dp),
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
                stringResource(R.string.settings_title),
                style = MaterialTheme.typography.headlineSmall,
            )
        }

        // ── relay 服务器（ID 模式三件套；与连接页折叠区同一存储） ──
        SectionHeader(stringResource(R.string.settings_section_relay))
        OutlinedTextField(
            value = relayAddr,
            onValueChange = {
                relayAddr = it
                relayPrefs.edit().putString("server_addr", it.trim()).apply()
            },
            label = { Text(stringResource(R.string.relay_addr)) },
            placeholder = { Text(stringResource(R.string.relay_addr_hint)) },
            singleLine = true,
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
            stringResource(R.string.settings_relay_hint),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        HorizontalDivider()

        // ── 连接偏好：分辨率上报档位 ──
        SectionHeader(stringResource(R.string.settings_section_prefs))
        Text(
            stringResource(R.string.settings_resolution_hint),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        ResolutionTierRow(
            selected = widthTier,
            onSelect = ::setWidthTier,
        )

        HorizontalDivider()

        // ── 设备信息（本机 identity 展示项） ──
        SectionHeader(stringResource(R.string.settings_section_device))
        if (identity.fingerprint.isNotBlank()) {
            Text(
                stringResource(R.string.settings_device_id_label),
                style = MaterialTheme.typography.labelSmall,
            )
            Text(identity.deviceId, style = MaterialTheme.typography.bodyMedium)
            Text(
                stringResource(R.string.trust_fingerprint_label),
                style = MaterialTheme.typography.labelSmall,
            )
            Text(
                identity.fingerprint,
                fontFamily = FontFamily.Monospace,
                fontSize = 13.sp,
            )
        } else {
            Text(
                stringResource(R.string.settings_device_unavailable),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        HorizontalDivider()

        // ── 语言 ──
        SectionHeader(stringResource(R.string.settings_section_language))
        LanguageRow(
            selected = language,
            onSelect = ::setLanguage,
        )

        HorizontalDivider()

        // ── 关于 ──
        SectionHeader(stringResource(R.string.settings_section_about))
        Text(
            stringResource(R.string.settings_about_version, appVersion.ifBlank { "—" }, version.ifBlank { "—" }),
            style = MaterialTheme.typography.bodySmall,
        )
        OutlinedButton(onClick = ::exportLog, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.settings_log_export))
        }
        logStatus?.let {
            Text(
                it,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun SectionHeader(title: String) {
    Text(
        title,
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.padding(top = 4.dp),
    )
}

/** 分辨率档位三选（0 = 原生 / 1280 = 720p 级 / 1920 = 1080p 级）。 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ResolutionTierRow(selected: Int, onSelect: (Int) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
        val tiers = listOf(
            1280 to R.string.settings_resolution_720,
            1920 to R.string.settings_resolution_1080,
            0 to R.string.settings_resolution_native,
        )
        tiers.forEach { (value, label) ->
            FilterChip(
                selected = selected == value,
                onClick = { onSelect(value) },
                label = { Text(stringResource(label)) },
            )
        }
    }
}

/** 语言三选（system / zh / en）。 */
@Composable
private fun LanguageRow(selected: String, onSelect: (String) -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        listOf(
            LANG_SYSTEM to R.string.settings_language_system,
            LANG_ZH to R.string.settings_language_zh,
            LANG_EN to R.string.settings_language_en,
        ).forEach { (tag, label) ->
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth(),
            ) {
                RadioButton(selected = selected == tag, onClick = { onSelect(tag) })
                Text(stringResource(label), style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

/** 语言偏好键值（settings SharedPreferences；attachBaseContext 消费）。 */
const val LANG_SYSTEM = "system"
const val LANG_ZH = "zh"
const val LANG_EN = "en"
