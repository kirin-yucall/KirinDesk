package com.kirindesk.mobile

import com.kirindesk.mobile.server.AccessibilityInputService

/**
 * Rust `kirin-desk-mobile` JNI 桥（契约 = mobile/src/jni.rs，符号名不得改动）。
 *
 * 库加载顺序（波 2 对接口径）：avutil → swscale → avcodec → kirin_desk_mobile。
 * FFmpeg 三件 vendored 于 `mobile/ffmpeg-android/prebuilt/arm64-v8a/`，构建时
 * 拷入本工程 jniLibs 与主 .so 同目录；Rust 侧 media::ffmpeg::dlls 以裸
 * soname dlopen 命中 System.loadLibrary 预载实例。
 */
object NativeBridge {
    const val INPUT_MOVE = 0
    const val INPUT_BUTTON = 1
    const val INPUT_WHEEL = 2

    const val BUTTON_LEFT = 0
    const val BUTTON_RIGHT = 1
    const val BUTTON_MIDDLE = 2

    const val CONNECT_MODE_IP = 0
    const val CONNECT_MODE_ID = 1
    const val CONNECT_MODE_DOMAIN = 2

    init {
        System.loadLibrary("avutil")
        System.loadLibrary("swscale")
        System.loadLibrary("avcodec")
        System.loadLibrary("kirin_desk_mobile")
    }

    /** onFrame 回调接口（解码后台线程上调用；实现方须自行切线程）。 */
    fun interface FrameCallback {
        fun onFrame(width: Int, height: Int, isKey: Int, rgba: ByteArray)
    }

    /**
     * onAudio 回调接口（P1-B；音频解码后台线程上调用）：
     * pcm = interleaved stereo float32（48kHz，20ms/帧 = 1920 样本）。
     */
    fun interface AudioCallback {
        fun onAudio(pcm: FloatArray, sampleRate: Int, channels: Int)
    }

    /** 历史条目（nativeHistory JSON 解析产物）。 */
    data class HistoryEntry(val id: String, val label: String, val lastSeen: String?)

    /** 外部 JNI 函数名与 Rust Java_com_kirindesk_mobile_NativeBridge_* 符号
     *  一一对应，不得重命名/加中转层。 */
    @JvmStatic external fun nativeInit(configDir: String)

    /**
     * 建链（总超时 180s，含 TOFU 指纹确认等待上限 120s），返回会话句柄 > 0；
     * 失败抛 RuntimeException。
     *
     * 模式语义（P1-A）：token 非空 ⇒ ID 模式（serverAddr = relay 地址，
     * serverPubkey = relay Ed25519 公钥，缺失 fail-closed）；token 空 ⇒ 地址
     * 直连（serverAddr = 目标 host:port，serverPubkey 可选目标公钥 pin）。
     *
     * [nativeConnect2]（显式模式参数）。
     */
    @JvmStatic external fun nativeConnect(
        id: String, nickname: String, challenge: String,
        serverAddr: String, token: String, serverPubkey: String,
    ): Long

    /**
     *
     * - mode 0（IP 直连）：serverAddr = 目标 host:port；id = **被控端昵称**
     *   （Dashboard 配置值——握手凭据，服务端按 init.client_id 比对，
     *   token 双保险）；
     * - mode 1（ID 模式）：id + serverAddr(relay) + token + serverPubkey
     *   四项必填（缺一 fail-fast 抛 RuntimeException，其中 serverPubkey
     *   由编排层 fail-closed 再兜底）；目标由 id 指定（指纹/短码/自定义，
     *   归一化在 Rust 侧）；
     *   （device.example.com；SRV/TXT/A|AAAA 三件套经加密 DNS DoH/DoT
     *   发现）+ id（被控端昵称，凭据口径对齐桌面域名模式）+ 挑战码；
     *   token/serverPubkey 忽略（信任锚 = TXT 公钥 + TOFU，Rust 侧清空）；
     * - 其余 mode 值 → 立即抛异常（fail-fast，不静默回退）。
     */
    @JvmStatic external fun nativeConnect2(
        mode: Int, id: String, nickname: String, challenge: String,
        serverAddr: String, token: String, serverPubkey: String,
    ): Long

    @JvmStatic external fun nativeOnFrameCallback(handle: Long, cb: FrameCallback)

    /**
     * 注册音频 PCM 回调（P1-B；可重复注册换回调）。onAudio 在音频解码
     * 后台线程上调用——实现方内部写 AudioTrack 流缓冲（阻塞写可接受）。
     */
    @JvmStatic external fun nativeOnAudioCallback(handle: Long, cb: AudioCallback)

    /** type 0 移动（x/y 归一化 0-1）/ 1 按键 / 2 滚轮（keyFlags=格数，正=上；
    @JvmStatic external fun nativeSendInput(
        handle: Long, type: Int, x: Double, y: Double, button: Int, keyFlags: Int,
    )

    /** 键盘：keyCode = Windows VK（Rust 侧映射 wire HID 判别式，
     *  修饰键/OEM 标点不可映射——走 [nativeSendKey2] / [nativeSendText]）。 */
    @JvmStatic external fun nativeSendKey(handle: Long, keyCode: Int, down: Boolean)

     *  逐位对齐：Ctrl=1/Shift=2/Alt=4/Win=8，可组合）。 */
    const val MOD_CTRL = 1
    const val MOD_SHIFT = 2
    const val MOD_ALT = 4
    const val MOD_SUPER = 8

    /**
     * 锁定态）以位标志附带在每次按键上——wire 键空间无独立修饰键（修饰语义
     * = 事件 modifiers 字段，对齐桌面 viewer mod_flags 口径）。
     */
    @JvmStatic external fun nativeSendKey2(
        handle: Long, keyCode: Int, down: Boolean, modifiers: Int,
    )

    /**
     * Unicode 文本注入（P1-B；中文/emoji 等软键盘无法 VK 映射的字符）——
     * 服务端 KEYEVENTF_UNICODE 逐码元注入，与桌面同语义。
     */
    @JvmStatic external fun nativeSendText(handle: Long, text: String)

    /** 幂等：句柄不存在时静默返回。 */
    @JvmStatic external fun nativeDisconnect(handle: Long)

    @JvmStatic external fun nativeVersion(): String

    // ── P1-A：TOFU 首连指纹确认（两段式） + 连接历史 ─────────────────────

    /**
     * 两段式·读：当前待确认指纹（79 字符完整指纹）或 null。nativeConnect
     * 阻塞期间轮询（建议 200ms）；非空 → 弹指纹确认对话框。
     */
    @JvmStatic external fun nativePeekPendingTrust(): String?

    /**
     * 两段式·写：回传用户决策。返回 true = 已送达；false = 无待确认请求
     * （迟到/已清理，忽略即可）。拒绝 = 连接以 fail-closed 中止。
     */
    @JvmStatic external fun nativeResolveTrust(accept: Boolean): Boolean

    /**
     * 连接历史 JSON：`[{"id":…,"label":…,"last_seen":…|null}]`
     * （devices.json + known_hosts 合并去重，桌面同数据格式；空 = "[]"）。
     */
    @JvmStatic external fun nativeHistory(): String


    /**
     * 1080p 级；非法值 Rust 侧清洗回退 1280 档。App 启动回放持久化值 +
     * 设置页保存时调用；下次连接握手生效（对已建链会话无效）。
     */
    @JvmStatic external fun nativeSetRequestedWidth(width: Int)

    /** 当前分辨率档位（设置页回显；与 [nativeSetRequestedWidth] 同源）。 */
    @JvmStatic external fun nativeRequestedWidth(): Int

    /**
     * 本机身份 JSON：`{"device_id":…,"fingerprint":…,"public_key":…}`
     * （configDir/identity/ed25519.json，与握手同一身份；加载失败 → 空串
     * fail-soft）。设置页「设备信息」区展示。
     */
    @JvmStatic external fun nativeIdentity(): String

    /** nativeIdentity JSON 解析产物（损坏 → 全空字段，fail-soft）。 */
    data class IdentityInfo(val deviceId: String, val fingerprint: String, val publicKey: String)

    /** nativeIdentity JSON 解析（空串/损坏 → 全空字段，不阻塞设置页）。 */
    fun parseIdentity(json: String): IdentityInfo = runCatching {
        val o = org.json.JSONObject(json)
        IdentityInfo(
            deviceId = o.optString("device_id", ""),
            fingerprint = o.optString("fingerprint", ""),
            publicKey = o.optString("public_key", ""),
        )
    }.getOrDefault(IdentityInfo("", "", ""))

    /**
     * ——已知码 → 本地化文案资源 id（values/values-zh 双语）；未知/无前缀
     * → null（调用方回退显示原始串）。
     */
    fun domainErrorRes(message: String?): Int? {
        val m = message ?: return null
        return when {
            m.startsWith("domain:invalid_host:") -> R.string.domain_err_invalid_host
            m.startsWith("domain:nxdomain:") -> R.string.domain_err_nxdomain
            m.startsWith("domain:no_records:") -> R.string.domain_err_no_records
            m.startsWith("domain:no_srv:") -> R.string.domain_err_no_srv
            m.startsWith("domain:no_txt:") -> R.string.domain_err_no_txt
            m.startsWith("domain:timeout:") -> R.string.domain_err_timeout
            m.startsWith("domain:dns_unavailable:") -> R.string.domain_err_dns_unavailable
            else -> null
        }
    }

    //    契约 = mobile/src/jni.rs :39-73 注释，符号名不得改动）─────────────

    /**
     * 启动被控端服务端（本机被控，「电脑看手机」）。
     *
     * - `nickname`：**必填**——被控端昵称 = 控制端连接凭据（字面 trim 比对，
     *   大小写敏感）；
     * - `challenge`：**必填**——挑战码（空 = 未配置 → 全部连接 fail-closed
     *   拒绝，不静默放行）；
     * - relay 三件（`relayServerAddr`/`relayToken`/`relayServerPubkey`）：
     *   addr+token 双非空 ⇒ 启用 ID 模式注册；**`relayServerPubkey` 缺失
     *   fail-closed 拒注册**（ID-SEC-001）；
     * - `deviceId`：空 = 公钥指纹派生（服务端身份由 Rust IdentityManager
     *   自管，Kotlin 侧统一传空）。
     *
     * 失败抛 RuntimeException（人话原因），调用方须 catch 展示。
     */
    @JvmStatic external fun nativeServerStart(
        port: Int, nickname: String, challenge: String,
        relayServerAddr: String, relayToken: String,
        relayServerPubkey: String, deviceId: String,
    ): Boolean

    /**
     * 停止服务端（停监听/帧泵/ID 注册/清观众）。幂等；true = 确有运行实例
     * 被停，false = 未在运行。
     */
    @JvmStatic external fun nativeServerStop(): Boolean

    /**
     * 喂一帧屏幕画面（MediaProjection ImageReader 回调；RGBA
     * `width*height*4` 字节，`timestampMs` = epoch 毫秒，0 = now）。
     *
     * 高频热路径：Rust 侧槽内只留最新帧（丢旧保新）、**不抛异常**；返回
     * false = 未运行/参数非法。
     */
    @JvmStatic external fun nativeServerFeedFrame(
        rgba: ByteArray, width: Int, height: Int, timestampMs: Long,
    ): Boolean

    /**
     * 状态 JSON 快照：`{"running", "port", "nickname", "device_id",
     * "fingerprint"（79 字符，控制端 TOFU 配对核对）, "public_key"（带外
     * 文件传输寻址用）, "pump_active", "id_mode_enabled",
     * "id_registered"}`。未运行时 nickname/device_id 为空串、viewer_ids 为
     * 空数组；identity 字段（fingerprint/public_key）在 nativeInit 后即可用。
     */
    @JvmStatic external fun nativeServerStatus(): String


    /**
     * 文件传输**轮询协议**（Kotlin 侧照此接线，零回调）：
     *
     * 1. **sessionHandle 双角色寻址**（同一 Long，ID 空间不相交无歧义）：
     *    - 控制端 = [nativeConnect2] 返回值（句柄表，自 1 起）；
     *    - 被控端 = [nativeServerStatus] JSON 的 `viewer_ids` 数组元素
     *      （观众 id，基址 2^48——永不与控制端句柄撞值）。
     * 2. **轮询**：会话存续期间以 **500ms~1s** 周期调
     *    [nativeGetFileTransfers]（纯拉模型——进度/完成/失败/入向 Offer 一律
     *    经 snapshot 呈现，Rust 侧零回调）。句柄无效/断连 = `[]`（不抛
     *    异常，轮询幂等安全）。
     * 3. **入向 Offer 信号** = snapshot 中出现**新的**
     *    `state = "offer_pending" && direction = "recv"` 条目 → 弹窗请用户
     *    决断 → [nativeFileOfferRespond]（accept=true 时目录建议
     *    `context.getExternalFilesDir(null).absolutePath`——app 外部私有
     *    目录免存储权限；**必须是已存在目录**，Rust 侧不自动建目录不静默
     *    换目录，非法目录返回 false 且 Offer 保持 pending 可重试；
     *    accept=false 时 targetDir 传 `""`）。
     * 4. **出向发送** = [nativeFileTransferStart] 返回 tid（u64 位模式：
     *    Kotlin 侧见负 Long 属正常，**仅 -1L = 失败**），之后在 snapshot
     *    中跟踪该 tid 进度（queued → waiting_accept → sending → 终态）。
     * 5. **state 枚举值**（snapshot `state` 字段）：
     *    `queued` / `waiting_accept` / `offer_pending` / `sending` /
     *    `receiving` / `completed` / `failed` / `cancelled`；
     *    `direction`：`send`（本端发出）/ `recv`（对端推来）。
     * 6. **snapshot JSON 条目**（字段集与键序定稿——键序 = serde_json 确定性
     *    字母序，org.json 解析与键序无关但字段集不得变）：`{"direction":
     *    "send|recv","done":<Long>,"name":<String>,"path":<String|null>
     *    （仅接收侧完成后非 null）,"reason":<String>（failed/cancelled
     *    人话原因，其余空串）,"size":<Long>,"speed":<Double>,"state":
     *    <String>,"transfer_id":<Long>}`；空表/句柄无效 = `[]`。
     */

    /**
     * 发送本地文件（双角色均可）。path = 本地文件绝对路径。
     *
     * @return transfer_id（u64 **位模式**——高位为 1 时本端见负 Long 属
     *   正常，**仅 -1L = 失败**：句柄无效/路径空/非常规文件/元数据不可读/
     *   会话已关，Rust 侧 tracing warn 人话原因）。Rust 侧先按 B1 口径
     *   预派生 tid（文件基名 + metadata 长度 + 会话盐，与引擎内部确定性
     *   一致）再排队。
     */
    @JvmStatic external fun nativeFileTransferStart(
        sessionHandle: Long, path: String,
    ): Long

    /**
     * 入向 Offer 决断（snapshot `state = "offer_pending" && direction =
     * "recv"` 条目的 transfer_id）。accept = true 时 targetDir **必须已存
     * 在**（建议 `context.getExternalFilesDir(null).absolutePath`；不存在/
     * 非目录 → false，Offer 保持 pending 可换目录重试）；accept = false =
     * Reject（targetDir 忽略，传 `""`）。
     *
     * @return true = 受理成功；false = 句柄无效/会话已关/目录不可用。
     */
    @JvmStatic external fun nativeFileOfferRespond(
        sessionHandle: Long, transferId: Long, accept: Boolean, targetDir: String,
    ): Boolean

    /**
     * 本地取消（发送侧 = Cancel 帧 + 回滚；接收侧 = Cancel 帧 + 删
     * `.part`）。未知 tid（已完成/已清理）= 无操作返回 true（以
     * [nativeGetFileTransfers] snapshot 为准）。
     *
     * @return true = 受理成功；false = 句柄无效/会话已关。
     */
    @JvmStatic external fun nativeFileTransferCancel(
        sessionHandle: Long, transferId: Long,
    ): Boolean

    /**
     * 任务表快照 JSON 数组（轮询唯一数据源，见上方「文件传输轮询协议」第
     * 6 条字段集/键序定稿）；空表/句柄无效 = `"[]"`（不抛异常）。
     */
    @JvmStatic external fun nativeGetFileTransfers(sessionHandle: Long): String

    //    「被控端输入上抛」节；签名逐位定死，改动 = 断链）────────────────

    /** `onServerInputEvent` kind 判别式（= `injector::InputKind` 变体声明序，
     *  wire 判别式空间）。 */
    const val SERVER_EV_MOUSE_MOVE = 0
    const val SERVER_EV_MOUSE_BUTTON = 1
    const val SERVER_EV_MOUSE_WHEEL = 2
    const val SERVER_EV_KEY_DOWN = 3
    const val SERVER_EV_KEY_UP = 4
    const val SERVER_EV_KEY_REPEAT = 5
    const val SERVER_EV_TEXT = 6
    const val SERVER_EV_SPECIAL_KEY = 7

    /**
     * 被控端输入上抛回调（Rust viewer 会话 tokio 任务线程上调用，**非**主
     * 线程）。**签名逐位定死**（JNI 签名 `(IIFFLjava/lang/String;II)V`；
     * Rust 侧 `get_static_method_id` 按此签名查找，改参=断链）：
     *
     * - `kind`：事件种类（[SERVER_EV_MOUSE_MOVE] 0 … [SERVER_EV_SPECIAL_KEY] 7，
     *   参数表见 jni.rs 契约注释）；
     * - `key`：语义槽（kind=1 时 wire 按钮位 1=左 2=右 4=中 bit7=抬起；
     *   kind=2 时 wheel_delta ±120/格 正=上；kind=3-5 时 HID 用途码；
     *   kind=7 时 SpecialCombo 判别式）；
     * - `nx/ny`：归一化坐标 0.0–1.0（仅鼠标位事件有效；按屏幕真实尺寸
     *   换算 `screenPx = (nx * screenWidth).toInt()`）；
     * - `modifiers`：1=Ctrl 2=Shift 4=Alt 8=Super（键事件有效）；
     * - `text`：仅 kind=6 非空，其余恒为 ""（永不为 null）；
     * - `baseW/baseH`：编码分辨率基数（0 = 服务端尚无一帧；归一化换算不
     *   需要它，仅诊断备用）。
     *
     * **回调纪律**（jni.rs 契约）：不阻塞 >50ms；异常不回传（Rust 侧
     * `exception_clear` + 仅首次 warn 后静默丢弃，会话不断）——本方法整体
     * try-catch 吞异常。
     */
    @JvmStatic
    fun onServerInputEvent(
        kind: Int, key: Int, nx: Float, ny: Float,
        modifiers: Int, text: String, baseW: Int, baseH: Int,
    ) {
        try {
            // 未就绪（无障碍服务未连接/已销毁）= 单例 null → 静默丢，
            // 与 Rust 侧 enabled=false 语义同构（fail-soft）。
            AccessibilityInputService.instance?.onInputEvent(
                kind, key, nx, ny, modifiers, text, baseW, baseH,
            )
        } catch (_: Exception) {
            // 回调纪律：异常不回传 Rust（不 panic、不重抛）。
        }
    }

    /**
     * 被控端输入上抛开关（Rust 侧已导出）：无障碍服务**真正就绪**
     * （onServiceConnected）时置 true；onUnbind/onDestroy 时置 false。
     * false（含默认值）= Rust 侧静默丢弃全部输入事件（不 warn、不缓存
     * 回调、会话照常——fail-soft 红线⑤）。true 幂等（类引用+静态方法句柄
     * 一次性缓存，不重建、无泄漏）。
     */
    @JvmStatic external fun nativeSetInputCallbackEnabled(enabled: Boolean)

    /** nativeServerStatus JSON 解析产物（损坏/空 → 未运行空态，fail-soft）。
     *  sessionHandle 来源。 */
    data class ServerStatus(
        val running: Boolean,
        val port: Int,
        val nickname: String,
        val deviceId: String,
        val fingerprint: String,
        val publicKey: String,
        val viewers: Int,
        val viewerIds: List<Long>,
        val pumpActive: Boolean,
        val idModeEnabled: Boolean,
        val idRegistered: Boolean,
    )

    /** nativeServerStatus JSON 解析（损坏/空 → 未运行空态，不阻塞轮询；
     *  `viewer_ids` 缺失/损坏 → 空列表 fail-soft，旧 Rust 产物兼容）。 */
    fun parseServerStatus(json: String): ServerStatus = runCatching {
        val o = org.json.JSONObject(json)
        val ids = o.optJSONArray("viewer_ids")
        ServerStatus(
            running = o.optBoolean("running", false),
            port = o.optInt("port", 0),
            nickname = o.optString("nickname", ""),
            deviceId = o.optString("device_id", ""),
            fingerprint = o.optString("fingerprint", ""),
            publicKey = o.optString("public_key", ""),
            viewers = o.optInt("viewers", 0),
            viewerIds = if (ids == null) emptyList()
            else (0 until ids.length()).map { ids.optLong(it) },
            pumpActive = o.optBoolean("pump_active", false),
            idModeEnabled = o.optBoolean("id_mode_enabled", false),
            idRegistered = o.optBoolean("id_registered", false),
        )
    }.getOrDefault(ServerStatus(false, 0, "", "", "", "", 0, emptyList(), false, false, false))

    /** nativeHistory JSON 解析（损坏/异常 → 空列表，fail-soft 不阻塞连接页）。 */
    fun parseHistory(json: String): List<HistoryEntry> = runCatching {
        val arr = org.json.JSONArray(json)
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            HistoryEntry(
                id = o.getString("id"),
                label = o.optString("label", o.getString("id")),
                lastSeen = if (o.isNull("last_seen")) null else o.getString("last_seen"),
            )
        }
    }.getOrDefault(emptyList())
}
