//! 单 GPU 适配器选择 + 虚拟设备过滤（M8-T030 / 修复任务 R-06）。
//!
//! # 定位
//!
//! 运行时枚举本机真实 GPU（Windows 经 DXGI `EnumAdapters1`），过滤向日葵等
//! 虚拟驱动，按偏好（auto/intel/nvidia/amd/luid:0x…）选出**一个** GPU，
//! 供编码 / 解码 / GPU 内核统一绑定；虚拟显示器过滤与索引一致性见
//! [`crate::capture::windows_capture`]。
//!
//! # 模块结构（设计文档 §3.1）
//!
//! ```text
//! media/src/gpu/
//! ├── mod.rs        # 类型定义 + 纯逻辑（分类/过滤/选择）+ 全局偏好 + 平台分发 + 单测
//! └── windows.rs    # cfg(windows)：DXGI 枚举 + 选定适配器上创建 D3D11 设备
//! ```
//!
//! # 关键设计（M8-T030 需求设计）
//!
//! - **设备无关**（GPU-NF-001）：产品逻辑不出现具体 GPU 型号/设备 ID，仅测试
//!   样例与验证节出现（Intel 0x8086 / NVIDIA 0x10DE 等厂商 ID 常量除外）。
//! - **单 GPU 策略**（GPU-FR-003）：偏好是类别不是型号；无匹配回退 auto；
//!   全虚拟 / 无可用 → `None`（调用方回退 FFmpeg 默认设备，GPU-NF-002）。
//! - **首用缓存**（GPU-NF-006）：`OnceLock` 首用枚举一次，编码/解码创建路径
//!   不重复枚举。
//! - **env 覆盖**（GPU-NF-005）：`KIRIN_GPU_PREFER` > config > 默认 auto。

#[cfg(target_os = "windows")]
pub mod windows;

use std::sync::OnceLock;

// ════════════════════════════════════════════════════════════════
// 厂商 ID 常量（设计文档 §3.2；仅分类用，非"型号"硬编码）
// ════════════════════════════════════════════════════════════════

/// Intel（iGPU / Arc）。
pub const VENDOR_INTEL: u32 = 0x8086;
/// NVIDIA（GeForce/Quadro/RTX）。
pub const VENDOR_NVIDIA: u32 = 0x10DE;
/// AMD（Radeon/Ryzen iGPU）。
pub const VENDOR_AMD: u32 = 0x1002;
/// Microsoft（WARP / Basic Render Driver——虚拟/软件适配器）。
pub const VENDOR_MICROSOFT: u32 = 0x1414;

// ════════════════════════════════════════════════════════════════
// 数据模型（设计文档 §3.2）
// ════════════════════════════════════════════════════════════════

/// 适配器类别（vendor 动态分类；`Virtual` 由虚拟过滤规则单独标记）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterKind {
    Intel,
    Nvidia,
    Amd,
    Other,
    Virtual,
}

/// 单个 GPU 适配器信息（DXGI 枚举产物 / 合成数据单测输入）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterInfo {
    /// DXGI 枚举索引（0-based；**FFmpeg 8.1.1 d3d11va 设备串唯一有效格式**，
    /// 见 [`device_strings`] 实测注记）。
    pub index: u32,
    /// DXGI LUID（唯一标识；调试/日志用）。
    pub luid: i64,
    /// PCI vendor（Intel 0x8086 / NVIDIA 0x10DE / AMD 0x1002 / MS 0x1414）。
    pub vendor_id: u32,
    pub device_id: u32,
    /// GetDesc1 Description（过滤 / 调试；如 "Intel(R) UHD Graphics 770"）。
    pub description: String,
    /// 虚拟驱动标记（SOFTWARE flag / vendor 0x1414 / 关键词命中任一即 true）。
    pub is_virtual: bool,
    pub kind: AdapterKind,
}

/// GPU 偏好（`GpuPreference`，配置字符串解析见 [`FromStr`] impl）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuPreference {
    /// 自动：第一个真实（非虚拟）硬件适配器。
    Auto,
    Intel,
    Nvidia,
    Amd,
    /// 显式 LUID（调试；如 `luid:0x1000000-1` 或十进制）。含虚拟也选中（显式意图）。
    Luid(u64),
}

impl Default for GpuPreference {
    fn default() -> Self {
        Self::Auto
    }
}

impl GpuPreference {
    /// 解析偏好字符串（配置 `[media.gpu] prefer` / env `KIRIN_GPU_PREFER`）。
    ///
    /// 接受：`auto` | `intel` | `nvidia` | `amd` | `luid:0x…` | `luid:十进制`。
    /// 未知/空串 → `Auto`（容错，不阻断启动）。
    pub fn parse_str(s: &str) -> Self {
        let s = s.trim().to_ascii_lowercase();
        match s.as_str() {
            "" | "auto" => Self::Auto,
            "intel" => Self::Intel,
            "nvidia" => Self::Nvidia,
            "amd" => Self::Amd,
            _ => {
                if let Some(hex) = s.strip_prefix("luid:0x") {
                    u64::from_str_radix(hex, 16)
                        .ok()
                        .map(Self::Luid)
                        .unwrap_or(Self::Auto)
                } else if let Some(dec) = s.strip_prefix("luid:") {
                    dec.parse::<u64>().ok().map(Self::Luid).unwrap_or(Self::Auto)
                } else {
                    Self::Auto
                }
            }
        }
    }
}

/// 全局偏好集合（UI 启动时经 [`apply_preferences`] 注入；media 不依赖 utils）。
#[derive(Debug, Clone)]
pub struct GpuPreferences {
    /// 偏好 GPU 类别（默认 Auto）。
    pub prefer: GpuPreference,
    /// 过滤虚拟驱动开关（适配器 + 显示器共用；默认 true）。
    pub filter_virtual: bool,
    /// 覆盖默认黑名单关键词（空 = 用 [`default_virtual_keywords`] 默认表）。
    pub virtual_keywords: Vec<String>,
}

impl Default for GpuPreferences {
    fn default() -> Self {
        Self {
            prefer: GpuPreference::Auto,
            filter_virtual: true,
            virtual_keywords: Vec::new(),
        }
    }
}

// ════════════════════════════════════════════════════════════════
// 虚拟设备过滤规则（设计文档 §3.3）
// ════════════════════════════════════════════════════════════════

/// 默认适配器黑名单关键词（大小写不敏感，子串匹配；可被配置覆盖）。
///
/// 覆盖范围：向日葵（Sunlogin/Oray）虚拟显卡、IddCx 间接显示器、
/// 镜像驱动（DisplayMirage 等）、VM 虚拟显卡、WARP/微软基础显示。
/// 真实 GPU 描述名（"Intel(R) UHD Graphics 770"、"NVIDIA GeForce RTX 2080 Ti"）
/// 均不命中。
pub const DEFAULT_ADAPTER_KEYWORDS: &[&str] = &[
    "sunlogin",
    "oray",
    "向日葵",
    "virtual",
    "mirror",
    "idd",
    "indirect",
    "parsec",
    "spacedesk",
    "vmware",
    "virtualbox",
    "microsoft basic",
    "basic render",
    "warp",
];

/// 默认显示器黑名单关键词（`enumerate_monitors` 过滤用）。
///
/// 覆盖：向日葵虚拟显示器（"Sunlogin Virtual Display"/"Oray Virtual Display"）、
/// IddCx 间接显示器、镜像驱动、spacedesk/parsec 虚拟屏、usbmmidd 驱动。
/// 真实显示器名（"Generic PnP Monitor"、"DELL U2720Q"）不命中。
pub const DEFAULT_MONITOR_KEYWORDS: &[&str] = &[
    "sunlogin",
    "oray",
    "向日葵",
    "virtual",
    "mirror",
    "idd",
    "parsec",
    "spacedesk",
    "usbmmidd",
    "basic display",
];

/// 大小写不敏感子串匹配（过滤规则核心；纯函数）。
pub fn matches_keywords(s: &str, keywords: &[&str]) -> bool {
    let lower = s.to_ascii_lowercase();
    keywords.iter().any(|k| lower.contains(&k.to_ascii_lowercase()))
}

/// 适配器是否虚拟（设计文档 §3.3 两重兜底，任一命中即 true）：
///
/// 1. `software_flag`：DXGI `DXGI_ADAPTER_FLAG_SOFTWARE` 置位（WARP 等）；
/// 2. vendor == 0x1414（Microsoft Basic Render / WARP）；
/// 3. 描述名命中关键词表（`keywords` 为空 → 用默认表）。
///
/// 纯函数，合成数据可单测（GPU-NF-007）。
pub fn is_virtual_adapter(
    vendor_id: u32,
    description: &str,
    software_flag: bool,
    keywords: &[&str],
) -> bool {
    if software_flag || vendor_id == VENDOR_MICROSOFT {
        return true;
    }
    let table = if keywords.is_empty() {
        DEFAULT_ADAPTER_KEYWORDS
    } else {
        keywords
    };
    matches_keywords(description, table)
}

/// vendor → [`AdapterKind`] 分类（0x1414 归 Virtual；虚拟标记由
/// [`is_virtual_adapter`] 判定，本函数仅按 vendor 分类）。
pub fn classify_vendor(vendor_id: u32) -> AdapterKind {
    match vendor_id {
        VENDOR_INTEL => AdapterKind::Intel,
        VENDOR_NVIDIA => AdapterKind::Nvidia,
        VENDOR_AMD => AdapterKind::Amd,
        VENDOR_MICROSOFT => AdapterKind::Virtual,
        _ => AdapterKind::Other,
    }
}

// ════════════════════════════════════════════════════════════════
// 单 GPU 选择策略（设计文档 §3.4）
// ════════════════════════════════════════════════════════════════

/// 按偏好从适配器列表选出一个（设计文档 §3.4 决策表）：
///
/// 1. 显式 LUID（调试）：`prefer = Luid(n)` 且本机存在 → 直接选中（含虚拟）；
/// 2. 过滤：`filter_virtual` 时剔除 `is_virtual` 的适配器；
/// 3. 类别匹配：`prefer = Intel/Nvidia/Amd` → 该类 vendor 的第一个真实适配器；
///    无匹配 → 回退步骤 4；
/// 4. auto 兜底：第一个真实（非 Virtual）硬件适配器；
/// 5. 全部虚拟 / 无可用 → `None`（调用方回退 FFmpeg 默认设备行为）。
///
/// 纯函数，合成数据可单测（GPU-NF-007）。
pub fn select_adapter<'a>(
    adapters: &'a [AdapterInfo],
    prefs: &GpuPreferences,
) -> Option<&'a AdapterInfo> {
    // 1. 显式 LUID：本机存在即选中（含虚拟，显式意图）。
    if let GpuPreference::Luid(luid) = prefs.prefer {
        return adapters
            .iter()
            .find(|a| (a.luid as u64) == luid)
            .or_else(|| adapters.first());
    }
    // 2. 过滤虚拟适配器（可配置关闭）。
    let real: Vec<&AdapterInfo> = if prefs.filter_virtual {
        adapters.iter().filter(|a| !a.is_virtual).collect()
    } else {
        adapters.iter().collect()
    };
    // 3. 类别匹配；无匹配回退 auto。
    let kind = match prefs.prefer {
        GpuPreference::Intel => Some(AdapterKind::Intel),
        GpuPreference::Nvidia => Some(AdapterKind::Nvidia),
        GpuPreference::Amd => Some(AdapterKind::Amd),
        _ => None,
    };
    if let Some(kind) = kind {
        if let Some(a) = real.iter().find(|a| a.kind == kind) {
            return Some(a);
        }
    }
    // 4. auto 兜底：第一个真实硬件适配器。
    real.first().copied()
}

/// FFmpeg 设备串候选（**实测定案：十进制适配器索引**）。
///
/// FFmpeg 8.1.1（GyanD full shared，开发机 2026-08-02 实测）的
/// `hwcontext_d3d11va.c::d3d11va_device_parse` 对 device 串仅做 `atoi` 解析
/// ——**只接受十进制适配器索引**（枚举序，0 = 第一个）；LUID 十六进制
/// （`0x{high}-{low}` 等）会被静默解析为 0 → 恒选中第一个适配器，无效。
/// 实测记录：`'0'`→Intel UHD 770、`'1'`→NVIDIA 2080Ti、`'3'`（Microsoft
/// Basic Render）创建失败。
///
/// 返回 `[索引]` 单候选（索引由 DXGI 枚举缓存，会话内稳定）；后续 FFmpeg
/// 版本若支持 vendor_id 选项可在此追加候选。全部失败 → 调用方走 `None`
/// （现状默认设备，GPU-NF-002）。
pub fn device_strings(a: &AdapterInfo) -> Vec<String> {
    vec![a.index.to_string()]
}

// ════════════════════════════════════════════════════════════════
// 全局偏好 + 首用缓存（GPU-NF-006）
// ════════════════════════════════════════════════════════════════

/// 环境变量名（GPU-NF-005：`KIRIN_GPU_PREFER=intel|nvidia|...` 调试切换）。
pub const ENV_GPU_PREFER: &str = "KIRIN_GPU_PREFER";

/// 全局偏好（`apply_preferences` 写入；枚举 / 显示器过滤读取）。
static GLOBAL_PREFERENCES: OnceLock<GpuPreferences> = OnceLock::new();

/// 选定适配器缓存（首用枚举一次；`None` = 无可用真实 GPU）。
static SELECTED_ADAPTER: OnceLock<Option<AdapterInfo>> = OnceLock::new();

/// 当前全局偏好（未注入 → 默认值：auto + 过滤虚拟）。
pub fn preferences() -> &'static GpuPreferences {
    GLOBAL_PREFERENCES.get_or_init(GpuPreferences::default)
}

/// env 覆盖偏好解析（优先级：env > config > 默认 auto；GPU-NF-005）。
///
/// 纯函数（env 值由调用方传入），便于单测 env 切换路径。
pub fn preference_from_env(env: Option<String>, cfg_prefer: GpuPreference) -> GpuPreference {
    match env {
        Some(v) if !v.trim().is_empty() => GpuPreference::parse_str(&v),
        _ => cfg_prefer,
    }
}

/// 注入偏好并枚举选定适配器（UI 启动时调用；幂等——首用缓存一次）。
///
/// `KIRIN_GPU_PREFER` 环境变量覆盖 `prefs.prefer`（env > config > auto）。
/// 返回选定适配器（`None` = 无可用真实 GPU，调用方回退 FFmpeg 默认设备）。
/// 非 Windows 平台枚举桩返回空 → `None`（GPU-NF-003，行为不变）。
pub fn apply_preferences(prefs: GpuPreferences) -> Option<&'static AdapterInfo> {
    let prefs = GpuPreferences {
        prefer: preference_from_env(std::env::var(ENV_GPU_PREFER).ok(), prefs.prefer),
        ..prefs
    };
    let _ = GLOBAL_PREFERENCES.set(prefs);
    selected_adapter()
}

/// 当前选定适配器（未调用 [`apply_preferences`] 或首用缓存未触发时执行枚举；
/// 编码/解码创建路径经此取设备串候选，不重复枚举）。
///
/// **注意（R-06 实测修复）**：不可经 `apply_preferences(preferences().clone())`
/// 实现——`preferences()` 会先把全局初始化成默认 Auto，导致随后的 `set`
/// 失败、`KIRIN_GPU_PREFER` env 覆盖丢失（实机：`KIRIN_GPU_PREFER=nvidia`
/// 仍选中 Intel）。本实现直接读已注入偏好；未注入（CLI/测试直连）时用
/// 默认偏好 + env 覆盖（GPU-NF-005）。
pub fn selected_adapter() -> Option<&'static AdapterInfo> {
    SELECTED_ADAPTER.get_or_init(|| {
        let prefs = GLOBAL_PREFERENCES.get().cloned().unwrap_or_else(|| GpuPreferences {
            prefer: preference_from_env(std::env::var(ENV_GPU_PREFER).ok(), GpuPreference::Auto),
            ..GpuPreferences::default()
        });
        enumerate_and_select_with(&prefs)
    })
    .as_ref()
}

/// 编码/解码设备串候选（选定适配器 → 候选顺序见 [`device_strings`]）。
///
/// 无选定（无真实 GPU / 未调用 apply_preferences / 非 Windows）→
/// [`platform_default_candidates`]（Linux 为 VAAPI render 节点；其余空，
/// 调用方直接走 `None` 默认设备，GPU-NF-002）。
pub fn hwdevice_candidates() -> Vec<String> {
    match selected_adapter() {
        Some(a) => device_strings(a),
        None => platform_default_candidates(),
    }
}

/// 无选定适配器时的平台默认候选。
///
/// - Linux（M12-T002 / R-14-S3）：VAAPI render 节点（`/dev/dri/renderD128…`），
///   供 `h264_vaapi`/`hevc_vaapi` 与 vaapi 解码的 `av_hwdevice_ctx_create`
///   绑定真实渲染设备（无头/无 DRM 主设备时 render 节点是唯一选择）。
/// - Windows/macOS：空（调用方走 `None`，现状默认设备）。
#[cfg(target_os = "linux")]
fn platform_default_candidates() -> Vec<String> {
    vaapi_render_nodes()
}

#[cfg(not(target_os = "linux"))]
fn platform_default_candidates() -> Vec<String> {
    Vec::new()
}

/// Linux VAAPI render 节点枚举（M12-T002 / R-14-S3）。
///
/// 现代内核 render 节点自 minor 128 起连续编号；仅把**可打开**（存在且有
/// 读写权限）的节点作为候选——FFmpeg `av_hwdevice_ctx_create(VAAPI, 路径)`
/// 会按候选顺序逐个尝试，全部失败由调用方兜底 `None`（GPU-NF-002）。
#[cfg(target_os = "linux")]
fn vaapi_render_nodes() -> Vec<String> {
    let mut out = Vec::new();
    for minor in 128..=255 {
        let p = format!("/dev/dri/renderD{minor}");
        if std::path::Path::new(&p).exists()
            && std::fs::OpenOptions::new().read(true).open(&p).is_ok()
        {
            out.push(p);
        }
    }
    out
}

/// D3D11 设备句柄（供 `KgpuKernel::init` 复用选定适配器上创建的 device，
/// GPU-FR-006）。非 Windows / 未枚举 → `None`（内核自建设备，保持现状）。
#[cfg(target_os = "windows")]
pub fn d3d11_device_handle() -> Option<*mut core::ffi::c_void> {
    windows::selected_device_handle()
}

#[cfg(not(target_os = "windows"))]
pub fn d3d11_device_handle() -> Option<*mut core::ffi::c_void> {
    None
}

/// 枚举 + 选择（`SELECTED_ADAPTER` 首用缓存入口；偏好显式传入，避免依赖
/// 可能未初始化的全局状态——见 [`selected_adapter`] 的求值顺序注记）。
fn enumerate_and_select_with(prefs: &GpuPreferences) -> Option<AdapterInfo> {
    let adapters = enumerate_adapters();
    if adapters.is_empty() {
        return None;
    }
    let selected = select_adapter(&adapters, prefs).cloned();
    if let Some(a) = &selected {
        tracing::info!(
            "gpu: selected adapter vendor=0x{:04x} device=0x{:04x} virtual={} kind={:?} '{}'",
            a.vendor_id,
            a.device_id,
            a.is_virtual,
            a.kind,
            a.description
        );
    } else {
        tracing::info!("gpu: no real adapter, using FFmpeg default device");
    }
    selected
}

/// 平台分发：枚举本机全部 GPU 适配器（GPU-FR-001）。
///
/// Windows → DXGI `EnumAdapters1`；Linux/macOS 桩返回空（GPU-NF-003，
/// 与现有平台桩惯例一致，不影响编译与运行）。
#[cfg(target_os = "windows")]
fn enumerate_adapters() -> Vec<AdapterInfo> {
    windows::enumerate_adapters()
}

#[cfg(not(target_os = "windows"))]
fn enumerate_adapters() -> Vec<AdapterInfo> {
    Vec::new()
}

// ════════════════════════════════════════════════════════════════
// Tests（环境无关：合成数据，GPU-NF-007）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// 合成适配器工厂（Intel UHD 770 / NVIDIA 2080Ti 仅作测试样例，GPU-NF-001）。
    fn intel(luid: i64) -> AdapterInfo {
        AdapterInfo {
            index: 0,
            luid,
            vendor_id: VENDOR_INTEL,
            device_id: 0x4680,
            description: "Intel(R) UHD Graphics 770".into(),
            is_virtual: false,
            kind: AdapterKind::Intel,
        }
    }

    fn nvidia(luid: i64) -> AdapterInfo {
        AdapterInfo {
            index: 1,
            luid,
            vendor_id: VENDOR_NVIDIA,
            device_id: 0x1E87,
            description: "NVIDIA GeForce RTX 2080 Ti".into(),
            is_virtual: false,
            kind: AdapterKind::Nvidia,
        }
    }

    fn virtual_adapter(luid: i64) -> AdapterInfo {
        AdapterInfo {
            index: 2,
            luid,
            vendor_id: 0x0,
            device_id: 0x0,
            description: "Sunlogin Virtual Display Adapter".into(),
            is_virtual: true,
            kind: AdapterKind::Other,
        }
    }

    // ---------- 过滤规则（GPU-FR-002） ----------

    #[test]
    fn test_keyword_match_case_insensitive_substring() {
        assert!(matches_keywords("Sunlogin Virtual Display", DEFAULT_ADAPTER_KEYWORDS));
        assert!(matches_keywords("Oray 虚拟显示器", DEFAULT_ADAPTER_KEYWORDS));
        assert!(matches_keywords("nvidia virtual adapter", DEFAULT_ADAPTER_KEYWORDS));
        assert!(!matches_keywords("Intel(R) UHD Graphics 770", DEFAULT_ADAPTER_KEYWORDS));
        assert!(!matches_keywords("Generic PnP Monitor", DEFAULT_MONITOR_KEYWORDS));
        assert!(!matches_keywords("DELL U2720Q", DEFAULT_MONITOR_KEYWORDS));
    }

    #[test]
    fn test_software_flag_and_vendor_1414_always_virtual() {
        // SOFTWARE flag → 虚拟（描述名再真实也无效）。
        assert!(is_virtual_adapter(
            VENDOR_INTEL,
            "Intel(R) UHD Graphics 770",
            true,
            &[]
        ));
        // vendor 0x1414（WARP / Microsoft Basic Render）→ 虚拟。
        assert!(is_virtual_adapter(VENDOR_MICROSOFT, "Microsoft Basic Render Driver", false, &[]));
        assert!(is_virtual_adapter(VENDOR_MICROSOFT, "WARP", false, &[]));
    }

    #[test]
    fn test_keyword_table_covers_common_virtual_drivers() {
        // 关键词表覆盖：sunlogin / oray / 向日葵 / virtual / idd / parsec / spacedesk。
        for desc in [
            "Sunlogin Virtual Display",
            "Oray Virtual Display",
            "向日葵虚拟显示器",
            "IddCx Indirect Display Driver",
            "Parsec Virtual Display",
            "Spacedesk Virtual Display",
            "usbmmidd virtual display",
            "VMware SVGA 3D",
            "VirtualBox Graphics Adapter",
        ] {
            assert!(
                matches_keywords(desc, DEFAULT_ADAPTER_KEYWORDS),
                "应命中: {desc}"
            );
        }
    }

    #[test]
    fn test_user_keywords_override_default_table() {
        // 配置 virtual_keywords 非空 → 用自定义表（"sunlogin" 不再命中）。
        assert!(!is_virtual_adapter(0x0, "Sunlogin Virtual Display", false, &["custom"]));
        assert!(is_virtual_adapter(0x0, "my custom virtual", false, &["custom"]));
    }

    #[test]
    fn test_real_gpu_not_filtered() {
        assert!(!is_virtual_adapter(VENDOR_INTEL, "Intel(R) UHD Graphics 770", false, &[]));
        assert!(!is_virtual_adapter(VENDOR_NVIDIA, "NVIDIA GeForce RTX 2080 Ti", false, &[]));
        assert!(!is_virtual_adapter(VENDOR_AMD, "AMD Radeon RX 6800 XT", false, &[]));
    }

    // ---------- 厂商分类（GPU-FR-001） ----------

    #[test]
    fn test_classify_vendor() {
        assert_eq!(classify_vendor(VENDOR_INTEL), AdapterKind::Intel);
        assert_eq!(classify_vendor(VENDOR_NVIDIA), AdapterKind::Nvidia);
        assert_eq!(classify_vendor(VENDOR_AMD), AdapterKind::Amd);
        assert_eq!(classify_vendor(VENDOR_MICROSOFT), AdapterKind::Virtual);
        assert_eq!(classify_vendor(0x1234), AdapterKind::Other);
    }

    // ---------- 选择策略（GPU-FR-003） ----------

    #[test]
    fn test_select_auto_first_real() {
        let adapters = vec![nvidia(1), virtual_adapter(2), intel(3)];
        let prefs = GpuPreferences::default(); // Auto + 过滤虚拟
        let sel = select_adapter(&adapters, &prefs).expect("应选中");
        assert_eq!(sel.luid, 1, "auto 应选第一个真实适配器");
    }

    #[test]
    fn test_select_vendor_category() {
        let adapters = vec![nvidia(1), intel(2)];
        // intel → 选 Intel 类别。
        let prefs = GpuPreferences {
            prefer: GpuPreference::Intel,
            ..Default::default()
        };
        let sel = select_adapter(&adapters, &prefs).expect("应选中 Intel");
        assert_eq!(sel.luid, 2);
        // nvidia → 选 NVIDIA 类别。
        let prefs = GpuPreferences {
            prefer: GpuPreference::Nvidia,
            ..Default::default()
        };
        let sel = select_adapter(&adapters, &prefs).expect("应选中 NVIDIA");
        assert_eq!(sel.luid, 1);
    }

    #[test]
    fn test_select_category_missing_falls_back_auto() {
        // 偏好 AMD 但本机无 AMD → 回退 auto（第一个真实适配器）。
        let adapters = vec![nvidia(1), intel(2)];
        let prefs = GpuPreferences {
            prefer: GpuPreference::Amd,
            ..Default::default()
        };
        let sel = select_adapter(&adapters, &prefs).expect("应回退选中");
        assert_eq!(sel.luid, 1);
    }

    #[test]
    fn test_select_all_virtual_none() {
        let adapters = vec![virtual_adapter(1), virtual_adapter(2)];
        let prefs = GpuPreferences::default();
        assert!(select_adapter(&adapters, &prefs).is_none(), "全虚拟 → None");
    }

    #[test]
    fn test_select_empty_none() {
        assert!(select_adapter(&[], &GpuPreferences::default()).is_none());
    }

    #[test]
    fn test_select_luid_explicit_hits_virtual() {
        // 显式 LUID → 直接选中（含虚拟，显式意图）。
        let adapters = vec![nvidia(1), virtual_adapter(7)];
        let prefs = GpuPreferences {
            prefer: GpuPreference::Luid(7),
            ..Default::default()
        };
        let sel = select_adapter(&adapters, &prefs).expect("显式 LUID 应命中");
        assert_eq!(sel.luid, 7);
        assert!(sel.is_virtual);
    }

    #[test]
    fn test_select_filter_virtual_disabled() {
        // filter_virtual = false → 虚拟适配器也参与候选（auto 选第一个）。
        let adapters = vec![virtual_adapter(5), intel(6)];
        let prefs = GpuPreferences {
            filter_virtual: false,
            ..Default::default()
        };
        let sel = select_adapter(&adapters, &prefs).expect("不过滤 → 有选中");
        assert_eq!(sel.luid, 5);
    }

    // ---------- 偏好解析 / env 覆盖（GPU-FR-009 / GPU-NF-005） ----------

    #[test]
    fn test_parse_preference() {
        assert_eq!(GpuPreference::parse_str("auto"), GpuPreference::Auto);
        assert_eq!(GpuPreference::parse_str(""), GpuPreference::Auto);
        assert_eq!(GpuPreference::parse_str("intel"), GpuPreference::Intel);
        assert_eq!(GpuPreference::parse_str("NVIDIA"), GpuPreference::Nvidia);
        assert_eq!(GpuPreference::parse_str("amd"), GpuPreference::Amd);
        assert_eq!(GpuPreference::parse_str("luid:0x100"), GpuPreference::Luid(0x100));
        assert_eq!(GpuPreference::parse_str("luid:1234"), GpuPreference::Luid(1234));
        // 未知值容错 → Auto。
        assert_eq!(GpuPreference::parse_str("bogus"), GpuPreference::Auto);
        assert_eq!(GpuPreference::parse_str("luid:notanumber"), GpuPreference::Auto);
    }

    #[test]
    fn test_preference_from_env_override() {
        // env 存在 → 覆盖 config；env 空/缺失 → 用 config。
        assert_eq!(
            preference_from_env(Some("nvidia".into()), GpuPreference::Auto),
            GpuPreference::Nvidia
        );
        assert_eq!(
            preference_from_env(Some("luid:0x1234".into()), GpuPreference::Auto),
            GpuPreference::Luid(0x1234)
        );
        assert_eq!(
            preference_from_env(None, GpuPreference::Intel),
            GpuPreference::Intel
        );
        assert_eq!(
            preference_from_env(Some("  ".into()), GpuPreference::Auto),
            GpuPreference::Auto
        );
    }

    // ---------- 设备串候选（§3.5，R-06 实测定案：十进制适配器索引） ----------

    #[test]
    fn test_device_strings_is_adapter_index() {
        // FFmpeg 8.1.1 d3d11va 设备串只接受十进制适配器索引（atoi 解析；
        // LUID 十六进制静默变 0 → 恒选第一个适配器，无效——开发机实测）。
        let a = AdapterInfo {
            index: 1,
            luid: 0x00000001_00000002i64,
            vendor_id: VENDOR_NVIDIA,
            device_id: 0x1E87,
            description: "NVIDIA GeForce RTX 2080 Ti".into(),
            is_virtual: false,
            kind: AdapterKind::Nvidia,
        };
        assert_eq!(device_strings(&a), vec!["1"]);
        // 索引 0（第一个适配器）同样正确表达。
        let a0 = AdapterInfo {
            index: 0,
            ..a
        };
        assert_eq!(device_strings(&a0), vec!["0"]);
    }

    // ---------- 平台默认候选（M12-T002 / R-14-S3） ----------

    /// 非 Linux：无选定适配器 → 空候选（调用方走 None 默认设备，GPU-NF-002）。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_platform_default_candidates_empty_off_linux() {
        assert!(platform_default_candidates().is_empty());
    }

    /// Linux：候选为 /dev/dri/renderD* 形式（环境无关断言：前缀与升序）；
    /// 本机有 render 节点时数量 ≥ 1 且每个都以 renderD 前缀。
    #[cfg(target_os = "linux")]
    #[test]
    fn test_vaapi_render_nodes_shape() {
        let nodes = vaapi_render_nodes();
        for n in &nodes {
            assert!(
                n.starts_with("/dev/dri/renderD"),
                "VAAPI 候选应为 render 节点，实际 {n}"
            );
        }
        // 升序（128 起）且无重复。
        let mut sorted = nodes.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), nodes.len(), "候选不应重复");
        if nodes.len() > 1 {
            assert_eq!(nodes, sorted, "候选应按 minor 升序");
        }
    }
}
