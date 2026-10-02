package com.kirindesk.mobile.ui

import android.Manifest
import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import android.util.Log
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.kirindesk.mobile.MainActivity
import com.kirindesk.mobile.NativeBridge
import com.kirindesk.mobile.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.io.File
import java.io.IOException

const val FT_DIR_SEND = "send"
const val FT_DIR_RECV = "recv"
const val FT_STATE_QUEUED = "queued"
const val FT_STATE_WAITING_ACCEPT = "waiting_accept"
const val FT_STATE_OFFER_PENDING = "offer_pending"
const val FT_STATE_SENDING = "sending"
const val FT_STATE_RECEIVING = "receiving"
const val FT_STATE_COMPLETED = "completed"
const val FT_STATE_FAILED = "failed"
const val FT_STATE_CANCELLED = "cancelled"

/** 活跃（可取消）状态集。 */
private val FT_ACTIVE_STATES = setOf(
    FT_STATE_QUEUED, FT_STATE_WAITING_ACCEPT, FT_STATE_SENDING, FT_STATE_RECEIVING,
)

/** 终态集（跃迁触发通知 + 暂存清理）。 */
private val FT_TERMINAL_STATES = setOf(FT_STATE_COMPLETED, FT_STATE_FAILED, FT_STATE_CANCELLED)

/** 合并条目（某会话 snapshot 的一条 + 来源标注，双角色同构）。 */
data class FileTransferItem(
    /** 来源会话句柄（控制端 = nativeConnect2 返回值；被控端 = viewerId，基址 2^48）。 */
    val handle: Long,
    /** 来源标注（被控端 = 观众友好名；控制端 = 远端设备；仅展示用）。 */
    val sourceLabel: String,
    val tid: Long,
    val direction: String,
    val name: String,
    val size: Long,
    val done: Long,
    val speed: Double,
    val state: String,
    val reason: String,
    /** 接收侧落盘绝对路径（完成后非 null；发送侧恒 null）。 */
    val path: String?,
)

/**
 * `mutableStateOf` 状态模式——无 ViewModel 自创）。
 *
 * （内部 `nativeGetFileTransfers` 逐会话拉 snapshot）；进度/完成/失败/
 * 入向 Offer 一律经 snapshot 呈现。
 *
 * - **入向 Offer 信号** = 出现新的 `state=offer_pending && direction=recv`
 *   条目（[offered] 按 (handle,tid) 去重）→ [pendingOffer] 弹窗队列 →
 *   [respondOffer]（accept 前先 `mkdirs` 接收目录——Rust 不自动建目录，
 *   非法目录返回 false 且 Offer 保持 pending 可重试 → 弹窗不关留人话错误）；
 * - **终态跃迁通知**（→completed/failed/cancelled）：[notified] 同 tid 内存
 *   去重不重发；接收完成 = 文件名+大小+分享 action（FileProvider
 *   ACTION_SEND，复用日志导出管线）；POST_NOTIFICATIONS 未授予（API 33+）
 *   → 复用 [MainActivity.requestNotifPermissionThen] 既有链式请求；
 * - **暂存生命周期**：SAF 选文件 → [onFilePicked] → `filesDir/upload_tmp/<基名>`
 *   流式拷贝（Dispatchers.IO，4GiB 上限 fail-closed，进度 [stagingProgress]）
 *   → 拷贝**完成后再** `nativeFileTransferStart` → 该 tid 终态时删暂存
 *   （会话句柄消失时兜底全删；冷启动清孤儿）；
 * - **fail-closed**：SAF 无选择/拷贝失败/超限/启动失败/分享失败 → 人话
 *   [error]（中英资源）；snapshot 解析失败按无传输处理 + log warn。
 */
class FileTransferManager(private val host: MainActivity) {

    // ── UI 状态（Compose 快照态，任意线程写安全——对齐 SessionState 帧写入口径）──
    var entries by mutableStateOf<List<FileTransferItem>>(emptyList())
        private set
    var pendingOffer by mutableStateOf<FileTransferItem?>(null)
        private set
    var offerError by mutableStateOf<String?>(null)
        private set
    var stagingBusy by mutableStateOf(false)
        private set
    var stagingName by mutableStateOf<String?>(null)
        private set
    var stagingProgress by mutableStateOf(0f)
        private set
    var error by mutableStateOf<String?>(null)
        private set

    /** SAF 选定文件的目标会话句柄（[prepareSend] 写入，[onFilePicked] 消费）。 */
    private var pendingSendHandle: Long? = null

    /** handle → 来源标注（每轮 [poll] 入参同步）。 */
    private val sources = LinkedHashMap<Long, String>()
    /** handle → (tid → 末次 state)。 */
    private val lastSeen = HashMap<Long, MutableMap<Long, String>>()
    /** handle → 已发通知 tid 集（同 tid 不重发）。 */
    private val notified = HashMap<Long, MutableSet<Long>>()
    /** handle → 已弹窗决断 tid 集（防同 Offer 重复弹窗）。 */
    private val offered = HashMap<Long, MutableSet<Long>>()
    /** handle → (tid → 暂存文件)（终态/句柄消失时删除）。 */
    private val stagedByHandle = HashMap<Long, MutableMap<Long, File>>()
    /** Offer 弹窗队列（pendingOffer = 队头；弹窗一次一个，答完出下一个）。 */
    private val offerQueue = ArrayDeque<FileTransferItem>()

    /** 拷贝专用 IO 作用域（裁定 6：拷贝 IO 放 Dispatchers.IO）。 */
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    init {
        // 冷启动清理：进程重启后旧进程暂存孤儿（传输不跨进程）→ 全删。
        runCatching {
            File(host.filesDir, STAGING_DIR_NAME).listFiles()
                ?.forEach { f -> runCatching { f.delete() } }
        }
    }

    // ── 轮询（UI 线程 1s 驱动；控制端 SessionScreen / 被控端并入 ServerScreen 既有循环）──

    /**
     * 拉取一轮全量 snapshot 并推进状态机（纯拉模型唯一入口）。
     * `sources` = 当前活跃 (句柄, 来源标注) 列表——不在列表中的旧句柄
     * （观众掉线/断连）→ 清其暂存文件与全部簿记（兜底防孤儿）。
     */
    fun poll(sourceList: List<Pair<Long, String>>) {
        val newHandles = sourceList.map { it.first }.toHashSet()
        for (h in sources.keys.toList()) {
            if (h !in newHandles) {
                stagedByHandle.remove(h)?.values?.forEach { f -> runCatching { f.delete() } }
                lastSeen.remove(h)
                notified.remove(h)
                offered.remove(h)
                sources.remove(h)
            }
        }
        for ((h, label) in sourceList) sources[h] = label

        val merged = ArrayList<FileTransferItem>(sourceList.size * 4)
        for ((h, label) in sourceList) {
            val json = runCatching { NativeBridge.nativeGetFileTransfers(h) }
                .getOrNull() ?: "[]"
            merged.addAll(parseTransfers(h, label, json))
        }

        // 入向 Offer：新的 offer_pending && recv 条目 → 弹窗队列。
        for (item in merged) {
            if (item.state == FT_STATE_OFFER_PENDING && item.direction == FT_DIR_RECV) {
                val set = offered.getOrPut(item.handle) { mutableSetOf() }
                if (set.add(item.tid)) enqueueOffer(item)
            }
        }

        // 终态跃迁（首次观测到该 tid 终态）→ 通知（去重）+ 暂存清理。
        for (item in merged) {
            lastSeen.getOrPut(item.handle) { HashMap() }[item.tid] = item.state
            if (item.state in FT_TERMINAL_STATES &&
                item.tid !in (notified[item.handle] ?: emptySet())
            ) {
                notified.getOrPut(item.handle) { HashSet() }.add(item.tid)
                stagedByHandle[item.handle]?.remove(item.tid)?.let { f ->
                    runCatching { f.delete() }
                }
                postTerminalNotification(item)
            }
        }

        // 内容不变不写（免每秒无谓重组）。
        if (entries != merged) entries = merged
    }

    // ── 出向发送（SAF → 暂存 → nativeFileTransferStart）──────────────────

    /** SAF 选择前指定目标会话（控制端 = 会话句柄；被控端 = 该观众 viewerId）。 */
    fun prepareSend(handle: Long) {
        pendingSendHandle = handle
    }

    /**
     * SAF `ACTION_OPEN_DOCUMENT` 结果（MainActivity launcher 回调，可 null =
     * 用户取消 → 人话提示 fail-closed）。4GiB 上限 fail-closed；拷贝 IO 走
     * [ioScope]（Dispatchers.IO），进度经 [stagingName]/[stagingProgress] 上屏。
     */
    fun onFilePicked(uri: Uri?) {
        if (uri == null) {
            error = host.getString(R.string.ft_error_no_file)
            return
        }
        val handle = pendingSendHandle
            ?: run {
                error = host.getString(R.string.ft_error_start)
                return
            }
        if (stagingBusy) {
            error = host.getString(R.string.ft_error_start)
            return
        }
        // 基名 + 大小（fail-soft：查询失败 → 名 "file"、大小未知 → 拷贝中再查上限）。
        var name = "file"
        var size: Long? = null
        runCatching {
            host.contentResolver.query(
                uri,
                arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
                null, null, null,
            )?.use { c ->
                if (c.moveToFirst()) {
                    val sizeIdx = c.getColumnIndex(OpenableColumns.SIZE)
                    name = c.getString(0).trim()
                        .replace('/', '_').replace('\\', '_').ifBlank { "file" }
                    size = if (sizeIdx >= 0 && !c.isNull(sizeIdx)) c.getLong(sizeIdx) else null
                }
            }
        }
        if (size != null && size > MAX_STAGING_BYTES) {
            error = host.getString(R.string.ft_error_too_large)
            return
        }
        stagingBusy = true
        stagingName = name
        stagingProgress = 0f
        error = null
        val tmp = File(File(host.filesDir, STAGING_DIR_NAME), name)
        ioScope.launch {
            var copied = 0L
            try {
                host.contentResolver.openInputStream(uri).use { input ->
                    if (input == null) throw IOException("SAF input stream null")
                    runCatching { tmp.parentFile?.mkdirs() }
                    tmp.outputStream().use { out ->
                        val buf = ByteArray(64 * 1024)
                        var lastEmit = 0L
                        while (true) {
                            val n = input.read(buf)
                            if (n < 0) break
                            copied += n
                            if (copied > MAX_STAGING_BYTES) {
                                throw IOException("max file size exceeded")
                            }
                            out.write(buf, 0, n)
                            val now = System.currentTimeMillis()
                            if (size != null && size > 0 && now - lastEmit >= 100L) {
                                stagingProgress =
                                    (copied.toDouble() / size).toFloat().coerceIn(0f, 1f)
                                lastEmit = now
                            }
                        }
                    }
                }
            } catch (e: IOException) {
                // 超限 vs 普通拷贝失败 → 不同人话；删半成品。
                runCatching { tmp.delete() }
                stagingBusy = false
                stagingName = null
                error = host.getString(
                    if (copied > MAX_STAGING_BYTES) R.string.ft_error_too_large
                    else R.string.ft_error_copy,
                )
                return@launch
            }
            // 拷贝**完成后**再交 Rust 引擎（裁定 1①：先暂存后 start）。
            stagingProgress = 1f
            val tid = runCatching {
                NativeBridge.nativeFileTransferStart(handle, tmp.absolutePath)
            }.getOrElse {
                Log.w(TAG, "nativeFileTransferStart failed: $it")
                runCatching { tmp.delete() }
                -1L
            }
            if (tid == -1L) {
                runCatching { tmp.delete() }
                error = host.getString(R.string.ft_error_start)
            } else {
                // tid = u64 位模式（高位 1 时本端见负 Long 属正常，仅 -1L 已排除）。
                stagedByHandle.getOrPut(handle) { HashMap() }[tid] = tmp
            }
            stagingBusy = false
            stagingName = null
        }
    }

    // ── Offer 决断 / 取消 / 分享 ──────────────────────────────────────────

    /**
     * Offer 弹窗决断回调。accept = true：先 `mkdirs` 接收目录
     * （`getExternalFilesDir(null)/Kirindesk/`，免权限）再 respond；
     * false = Reject（targetDir 传 ""）。respond 返回 false（目录不可用/
     * 会话已关）且为 accept → 弹窗**不关**（Offer 在 Rust 侧保持 pending
     * 可重试），显示人话错误供用户重试接受或改拒绝。
     */
    fun respondOffer(accept: Boolean) {
        val item = pendingOffer ?: return
        val ok = runCatching {
            if (accept) {
                val dir = File(host.getExternalFilesDir(null), RECV_DIR_NAME).apply { mkdirs() }
                if (dir.isDirectory) {
                    NativeBridge.nativeFileOfferRespond(item.handle, item.tid, true, dir.absolutePath)
                } else {
                    false
                }
            } else {
                NativeBridge.nativeFileOfferRespond(item.handle, item.tid, false, "")
            }
        }.getOrDefault(false)
        if (!ok && accept) {
            offerError = host.getString(R.string.ft_offer_dir_error)
        } else {
            dequeueOffer()
        }
    }

    /** 活跃条目取消（受理即返回，snapshot 下轮反映 cancelled；未知 tid 无操作）。 */
    fun cancel(item: FileTransferItem) {
        runCatching {
            NativeBridge.nativeFileTransferCancel(item.handle, item.tid)
        }.onFailure { Log.w(TAG, "nativeFileTransferCancel failed: $it") }
    }

    /** 完成条目分享（FileProvider ACTION_SEND，复用设置页日志导出管线）。 */
    fun share(item: FileTransferItem) {
        val path = item.path
        if (path.isNullOrBlank()) {
            error = host.getString(R.string.ft_error_share)
            return
        }
        val f = File(path)
        if (!f.isFile) {
            error = host.getString(R.string.ft_error_share)
            return
        }
        runCatching {
            val uri = FileProvider.getUriForFile(
                host, "${host.packageName}.fileprovider", f,
            )
            val send = Intent(Intent.ACTION_SEND).apply {
                type = host.contentResolver.getType(uri) ?: "application/octet-stream"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            host.startActivity(
                Intent.createChooser(send, host.getString(R.string.ft_share)),
            )
        }.onFailure {
            Log.w(TAG, "share failed: $it")
            error = host.getString(R.string.ft_error_share)
        }
    }

    // ── snapshot 解析（fail-closed：非 [] 解析失败 → 无传输 + log warn）──

    fun parseTransfers(handle: Long, label: String, json: String): List<FileTransferItem> {
        if (json.isEmpty() || json == "[]") return emptyList()
        return runCatching {
            val arr = org.json.JSONArray(json)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                FileTransferItem(
                    handle = handle,
                    sourceLabel = label,
                    tid = o.optLong("transfer_id", -1L),
                    direction = o.optString("direction", ""),
                    name = o.optString("name", ""),
                    size = o.optLong("size", 0L),
                    done = o.optLong("done", 0L),
                    speed = o.optDouble("speed", 0.0),
                    state = o.optString("state", ""),
                    reason = o.optString("reason", ""),
                    path = if (o.isNull("path")) null else o.optString("path", "").ifBlank { null },
                )
            }.filter { it.tid >= 0 }
        }.getOrElse {
            Log.w(TAG, "nativeGetFileTransfers parse failed, treated as empty " +
                "(len=${json.length}): $it")
            emptyList()
        }
    }

    // ── 终态通知（file_transfer 渠道；同 tid 内存去重）────────────────────

    private fun postTerminalNotification(item: FileTransferItem) {
        if (Build.VERSION.SDK_INT >= 33 &&
            host.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            // 复用既有链式请求（与屏幕共享启动流同一 launcher；拒绝 = 通知不可见，
            // 功能不受影响；去重集已记，不重发）。
            host.requestNotifPermissionThen { postTerminalNow(host, item) }
            return
        }
        postTerminalNow(host, item)
    }

    private fun postTerminalNow(ctx: Context, item: FileTransferItem) {
        runCatching {
            val nm = ctx.getSystemService(NotificationManager::class.java)
            val title: String
            val smallIcon: Int
            when {
                item.direction == FT_DIR_RECV -> {
                    title = ctx.getString(R.string.ft_notif_recv)
                    smallIcon = android.R.drawable.stat_sys_download
                }
                else -> {
                    title = when (item.state) {
                        FT_STATE_COMPLETED -> ctx.getString(R.string.ft_notif_sent)
                        FT_STATE_FAILED -> ctx.getString(R.string.ft_notif_failed)
                        else -> ctx.getString(R.string.ft_notif_cancelled)
                    }
                    smallIcon = android.R.drawable.stat_sys_upload
                }
            }
            val text = buildString {
                append(item.name)
                if (item.direction == FT_DIR_RECV && item.state == FT_STATE_COMPLETED &&
                    item.size > 0
                ) {
                    append(" (").append(formatSize(ctx, item.size)).append(")")
                }
                if (item.reason.isNotBlank()) append(" · ").append(item.reason)
            }
            val builder = Notification.Builder(ctx, NOTIF_CHANNEL_ID)
                .setSmallIcon(smallIcon)
                .setContentTitle(title)
                .setContentText(text)
                .setAutoCancel(true)
                .setContentIntent(
                    PendingIntent.getActivity(
                        ctx, 0,
                        Intent(ctx, MainActivity::class.java),
                        PendingIntent.FLAG_IMMUTABLE,
                    ),
                )
            // 接收完成 = 文件名+大小+分享 action（落盘 path 经 FileProvider）。
            if (item.direction == FT_DIR_RECV && item.state == FT_STATE_COMPLETED &&
                item.path != null
            ) {
                val f = File(item.path)
                if (f.isFile) {
                    val uri = FileProvider.getUriForFile(
                        ctx, "${ctx.packageName}.fileprovider", f,
                    )
                    val send = Intent(Intent.ACTION_SEND).apply {
                        type = ctx.contentResolver.getType(uri) ?: "application/octet-stream"
                        putExtra(Intent.EXTRA_STREAM, uri)
                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    }
                    builder.addAction(
                        Notification.Action.Builder(
                            android.R.drawable.ic_menu_share,
                            ctx.getString(R.string.ft_notif_action_share),
                            PendingIntent.getActivity(
                                ctx, 0,
                                Intent.createChooser(send, null),
                                PendingIntent.FLAG_IMMUTABLE,
                            ),
                        ).build(),
                    )
                }
            }
            nm.notify(notificationIdFor(item), builder.build())
        }.onFailure { Log.w(TAG, "file transfer notification failed: $it") }
    }

    /** tid → 稳定通知 id（u64 位模式取模折叠；send/recv 分区防覆盖）。 */
    private fun notificationIdFor(item: FileTransferItem): Int {
        val base = (kotlin.math.abs(item.tid) % 1_900_000_000L).toInt()
        return base + if (item.direction == FT_DIR_SEND) 1_000_000 else 0
    }

    // ── Offer 弹窗队列 ────────────────────────────────────────────────────

    private fun enqueueOffer(item: FileTransferItem) {
        offerQueue.addLast(item)
        if (pendingOffer == null) pendingOffer = offerQueue.firstOrNull()
    }

    private fun dequeueOffer() {
        offerQueue.removeFirstOrNull()
        pendingOffer = offerQueue.firstOrNull()
        offerError = null
    }

    companion object {
        /** 文件传输通知渠道（importance 对齐既有屏幕共享 FGS 口径：LOW）。 */
        const val NOTIF_CHANNEL_ID = "file_transfer"

        private const val TAG = "FileTransfer"
        /** 暂存目录（app 私有 filesDir 下，免存储权限）。 */
        private const val STAGING_DIR_NAME = "upload_tmp"
        /** 接收落盘目录（getExternalFilesDir(null) 下；accept 前 mkdirs 保证存在）。 */
        const val RECV_DIR_NAME = "Kirindesk"
        /** 4GiB 上限（对齐引擎 DEFAULT_MAX_FILE_SIZE；超限 fail-closed 人话）。 */
        private const val MAX_STAGING_BYTES = 4L * 1024 * 1024 * 1024
    }
}

/**
 * 尺寸人话（1024 进制，1 位小数手工格式化——locale 无关，零硬编码：
 * 数值串 + 资源单位键拼接，zh/en 间隔差异由 ft_size 承载）。
 */
fun formatSize(ctx: Context, bytes: Long): String {
    val units = intArrayOf(R.string.ft_u_b, R.string.ft_u_kb, R.string.ft_u_mb, R.string.ft_u_gb)
    var v = bytes.toDouble()
    var i = 0
    while (v >= 1024.0 && i < units.lastIndex) {
        v /= 1024.0
        i++
    }
    val num = if (i == 0) {
        bytes.toString()
    } else {
        val scaled = (v * 10.0).toLong()
        "${scaled / 10}.${scaled % 10}"
    }
    return ctx.getString(R.string.ft_size, num, ctx.getString(units[i]))
}

/** 速度人话（同 formatSize 口径；≤0/非有限 → "—" 占位，非文案）。 */
fun formatSpeed(ctx: Context, bps: Double): String {
    if (bps <= 0.0 || !bps.isFinite()) return "—"
    val units = intArrayOf(R.string.ft_u_bps, R.string.ft_u_kbps, R.string.ft_u_mbps, R.string.ft_u_gbps)
    var v = bps
    var i = 0
    while (v >= 1024.0 && i < units.lastIndex) {
        v /= 1024.0
        i++
    }
    val num = if (i == 0) {
        bps.toLong().toString()
    } else {
        val scaled = (v * 10.0).toLong()
        "${scaled / 10}.${scaled % 10}"
    }
    return ctx.getString(R.string.ft_speed, num, ctx.getString(units[i]))
}

/**
 * 暂存进度行 + [FileTransferList] + 错误行。控制端 = ModalBottomSheet 内
 * 全面板；被控端 = 共享页区块（发送入口在每观众行，此处不重复）。
 */
@Composable
fun FileTransferPanel(
    manager: FileTransferManager,
    onSendClick: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                stringResource(R.string.ft_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(Modifier.weight(1f))
            if (onSendClick != null && !manager.stagingBusy) {
                Button(onClick = onSendClick) {
                    Icon(
                        Icons.AutoMirrored.Filled.Send,
                        contentDescription = stringResource(R.string.ft_send),
                        modifier = Modifier.size(16.dp),
                    )
                    Spacer(Modifier.width(4.dp))
                    Text(stringResource(R.string.ft_send))
                }
            }
        }
        if (manager.stagingBusy) {
            Column(Modifier.padding(top = 8.dp)) {
                Text(
                    stringResource(R.string.ft_staging, manager.stagingName.orEmpty()),
                    style = MaterialTheme.typography.labelSmall,
                )
                LinearProgressIndicator(
                    progress = { manager.stagingProgress },
                    modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                )
            }
        }
        FileTransferList(manager)
        manager.error?.let {
            Text(
                it,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 8.dp),
            )
        }
    }
}

/**
 * 传输列表（双角色共用）：方向图标/name/进度(done/size)/速度/state 人话/
 * reason；完成条目「分享」（path 非空时）、活跃条目「取消」。
 *
 * `lazy = true`（默认）= LazyColumn（控制端底部面板，有界高度）；
 * `lazy = false` = 普通 Column（被控端共享页——外层已是 verticalScroll，
 * 不嵌套滚动容器；条目上限 64 无需虚拟化）。
 */
@Composable
fun FileTransferList(
    manager: FileTransferManager,
    modifier: Modifier = Modifier,
    lazy: Boolean = true,
) {
    val entries = manager.entries
    if (entries.isEmpty()) {
        Text(
            stringResource(R.string.ft_empty),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodySmall,
            modifier = modifier.padding(vertical = 8.dp),
        )
        return
    }
    if (lazy) {
        LazyColumn(
            modifier = modifier,
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            items(entries, key = { "${it.handle}:${it.tid}" }) { item ->
                FileTransferRow(
                    item = item,
                    onShare = { manager.share(item) },
                    onCancel = { manager.cancel(item) },
                )
            }
        }
    } else {
        Column(
            modifier = modifier,
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            entries.forEach { item ->
                FileTransferRow(
                    item = item,
                    onShare = { manager.share(item) },
                    onCancel = { manager.cancel(item) },
                )
            }
        }
    }
}

/** 单条传输行：[方向图标] name …… [分享?] [取消?] + 进度条 + 详情行 + reason。 */
@Composable
fun FileTransferRow(
    item: FileTransferItem,
    onShare: () -> Unit,
    onCancel: () -> Unit,
) {
    val context = LocalContext.current
    val isSend = item.direction == FT_DIR_SEND
    val active = item.state in FT_ACTIVE_STATES
    val frac = if (item.size > 0) {
        (item.done.toDouble() / item.size).coerceIn(0.0, 1.0)
    } else {
        0.0
    }
    // state 枚举 → 人话（未知值 fail-closed：原样展示数据串，非 UI 文案）。
    val stateLabel = when (item.state) {
        FT_STATE_QUEUED -> stringResource(R.string.ft_state_queued)
        FT_STATE_WAITING_ACCEPT -> stringResource(R.string.ft_state_waiting_accept)
        FT_STATE_OFFER_PENDING -> stringResource(R.string.ft_state_offer_pending)
        FT_STATE_SENDING -> stringResource(R.string.ft_state_sending)
        FT_STATE_RECEIVING -> stringResource(R.string.ft_state_receiving)
        FT_STATE_COMPLETED -> stringResource(R.string.ft_state_completed)
        FT_STATE_FAILED -> stringResource(R.string.ft_state_failed)
        FT_STATE_CANCELLED -> stringResource(R.string.ft_state_cancelled)
        else -> item.state
    }
    Column(Modifier.padding(horizontal = 12.dp, vertical = 6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                if (isSend) Icons.AutoMirrored.Filled.Send else Icons.Filled.ArrowDropDown,
                contentDescription = stringResource(
                    if (isSend) R.string.ft_dir_send else R.string.ft_dir_recv,
                ),
                modifier = Modifier.size(16.dp),
            )
            Spacer(Modifier.width(6.dp))
            Text(
                item.name,
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            if (item.state == FT_STATE_COMPLETED && item.path != null) {
                TextButton(
                    onClick = onShare,
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                ) {
                    Text(
                        stringResource(R.string.ft_share),
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            }
            if (active) {
                TextButton(
                    onClick = onCancel,
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                ) {
                    Text(
                        stringResource(R.string.ft_cancel),
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            }
        }
        if (active && item.size > 0) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                LinearProgressIndicator(
                    progress = { frac.toFloat() },
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    stringResource(R.string.ft_progress, (frac * 100).toInt()),
                    style = MaterialTheme.typography.labelSmall,
                )
            }
        }
        Text(
            buildString {
                append(stateLabel)
                if (item.size > 0) append(" · ").append(formatSize(context, item.size))
                if (active && item.speed > 0.0) {
                    append(" · ").append(formatSpeed(context, item.speed))
                }
                if (item.sourceLabel.isNotBlank()) {
                    append(" · ").append(item.sourceLabel)
                }
            },
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        if (item.reason.isNotBlank()) {
            Text(
                item.reason,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.error,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

/**
 * 入向 Offer 决断弹窗（双角色共用；`pendingOffer` 非空即显示）。
 * 对齐 TOFU 指纹确认弹窗口径：关闭（返回/点外）= 拒绝——必须显式决断，
 * 不静默丢弃 Offer（Rust 侧 pending 可重试，拒绝即发送方 Failed）。
 * 被控端经条目 sourceLabel 标注来源观众。
 */
@Composable
fun FileTransferOfferDialog(manager: FileTransferManager) {
    val context = LocalContext.current
    val offer = manager.pendingOffer
    if (offer == null) return
    AlertDialog(
        onDismissRequest = { manager.respondOffer(false) },
        title = { Text(stringResource(R.string.ft_offer_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(offer.name, style = MaterialTheme.typography.bodyLarge)
                Text(
                    formatSize(context, offer.size),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (offer.sourceLabel.isNotBlank()) {
                    Text(
                        stringResource(R.string.ft_source, offer.sourceLabel),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                manager.offerError?.let {
                    Text(
                        it,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { manager.respondOffer(true) }) {
                Text(stringResource(R.string.ft_offer_accept))
            }
        },
        dismissButton = {
            TextButton(onClick = { manager.respondOffer(false) }) {
                Text(stringResource(R.string.ft_offer_reject))
            }
        },
    )
}
