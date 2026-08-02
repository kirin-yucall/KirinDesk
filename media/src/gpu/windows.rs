//! Windows GPU 枚举与设备创建（M8-T030 / 修复任务 R-06，R06-S2）。
//!
//! - [`enumerate_adapters`]：DXGI `EnumAdapters1` 枚举本机全部 GPU 适配器
//!   （GPU-FR-001），产出 [`AdapterInfo`]（含 SOFTWARE flag / 0x1414 /
//!   关键词虚拟标记，GPU-FR-002）。
//! - [`selected_device_handle`]：在**选定适配器**上创建 D3D11 设备
//!   （GPU-FR-006 内核复用入口；`KgpuKernel::init` 传此句柄）。
//!
//! # 平台桩
//!
//! 本文件 `cfg(target_os = "windows")` 门控；Linux/macOS 由
//! [`super::enumerate_adapters`] 桩返回空（GPU-NF-003）。

#![cfg(target_os = "windows")]

use std::sync::OnceLock;

use windows::core::Interface;
use windows::Win32::Foundation::{HMODULE, LUID};
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_UNKNOWN;
use windows::Win32::Graphics::Direct3D11::{D3D11CreateDevice, D3D11_SDK_VERSION, ID3D11Device};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, DXGI_ADAPTER_DESC1, DXGI_ADAPTER_FLAG_SOFTWARE, IDXGIAdapter,
    IDXGIAdapter1, IDXGIFactory1,
};

use super::{AdapterInfo, AdapterKind, is_virtual_adapter};

/// DXGI 枚举越界错误码（NOT_FOUND 表示枚举到结尾）。
const DXGI_ERROR_NOT_FOUND: i32 = 0x887A0002u32 as i32;

/// DXGI `EnumAdapters1` 枚举本机全部 GPU 适配器（GPU-FR-001）。
///
/// - 描述名 `Description[128]` UTF-16 → UTF-8（截断到 NUL）；
/// - LUID → i64（`(HighPart << 32) | LowPart`）；
/// - 虚拟标记（GPU-FR-002）：SOFTWARE flag / vendor 0x1414 / 关键词命中。
///
/// 无 GPU / 工厂创建失败 → 空 Vec（不 panic，GPU-NF-002）。
pub fn enumerate_adapters() -> Vec<AdapterInfo> {
    let factory: IDXGIFactory1 = match unsafe { CreateDXGIFactory1() } {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!("gpu: CreateDXGIFactory1 failed: {e}");
            return Vec::new();
        }
    };

    let mut out = Vec::new();
    for index in 0.. {
        let adapter: IDXGIAdapter1 = match unsafe { factory.EnumAdapters1(index) } {
            Ok(a) => a,
            Err(e) if e.code().0 == DXGI_ERROR_NOT_FOUND => break, // 枚举到结尾。
            Err(e) => {
                tracing::warn!("gpu: EnumAdapters1({index}) failed: {e}");
                break;
            }
        };
        let desc: DXGI_ADAPTER_DESC1 = match unsafe { adapter.GetDesc1() } {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("gpu: GetDesc1({index}) failed: {e}");
                continue;
            }
        };
        // Description: UTF-16 数组（可能含尾随 NUL）。
        let raw = &desc.Description[..];
        let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
        let description =
            String::from_utf16_lossy(&raw[..end]).trim().to_string();
        let software_flag = (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE.0 as u32) != 0;
        let is_virtual = is_virtual_adapter(desc.VendorId, &description, software_flag, &[]);
        let luid = luid_to_i64(desc.AdapterLuid);
        out.push(AdapterInfo {
            index,
            luid,
            vendor_id: desc.VendorId,
            device_id: desc.DeviceId,
            description,
            is_virtual,
            kind: classify(desc.VendorId, is_virtual),
        });
        tracing::info!(
            "gpu: enumerated adapter[{}] luid=0x{:016x} vendor=0x{:04x} device=0x{:04x} \
             virtual={} '{}'",
            index,
            luid as u64,
            desc.VendorId,
            desc.DeviceId,
            is_virtual,
            out.last().map(|a| a.description.as_str()).unwrap_or("")
        );
    }
    tracing::info!(
        "gpu: enumerated {n} adapters (virtual filtered: {v})",
        n = out.len(),
        v = out.iter().filter(|a| a.is_virtual).count()
    );
    out
}

/// LUID（HighPart: i32, LowPart: u32）→ i64（唯一标识；`selected_device_handle`
/// 按 LUID 匹配回 DXGI 适配器；设计文档 §3.2 数据模型）。
fn luid_to_i64(luid: LUID) -> i64 {
    ((luid.HighPart as i64) << 32) | (luid.LowPart as i64)
}

/// vendor 分类；虚拟适配器统一归 [`AdapterKind::Virtual`]（分类仅服务选择策略）。
fn classify(vendor_id: u32, is_virtual: bool) -> AdapterKind {
    if is_virtual {
        return AdapterKind::Virtual;
    }
    super::classify_vendor(vendor_id)
}

/// 选定适配器上创建的 D3D11 设备（进程级缓存；`None` = 无真实 GPU）。
///
/// 供 `KgpuKernel::init(Some(handle))` 复用（GPU-FR-006）：C++ 侧
/// `device_handle` 已支持传入，无需改动 libkirin_gpu。
/// 返回的指针借用自进程级 `OnceLock`（首用创建一次，进程内常驻），
/// 内核生命周期短于本缓存，借用安全。
static SELECTED_DEVICE: OnceLock<Option<ID3D11Device>> = OnceLock::new();

/// 在选定适配器上创建 D3D11 设备，返回原始句柄（`*mut c_void`）。
///
/// - 未调用 [`super::apply_preferences`] / 无选定适配器 → `None`
///   （`KgpuKernel::init(None)` 保持现状自建设备）；
/// - 创建失败（驱动异常）→ `None` + warn 日志，不阻断。
pub fn selected_device_handle() -> Option<*mut core::ffi::c_void> {
    let device = SELECTED_DEVICE.get_or_init(create_device_on_selected);
    device.as_ref().map(|d| d.as_raw() as *mut core::ffi::c_void)
}

/// 在选定适配器（`super::selected_adapter`）上创建 D3D11 设备。
///
/// `D3D11CreateDevice(padapter, D3D_DRIVER_TYPE_UNKNOWN, ...)`：指定适配器时
/// driver type 必须为 UNKNOWN（MSDN）。Feature levels 置空 → 自动选最高支持。
fn create_device_on_selected() -> Option<ID3D11Device> {
    let adapter = super::selected_adapter()?;
    // 枚举缓存里按 LUID 找对应 DXGI 适配器并 cast 到 IDXGIAdapter。
    let factory: IDXGIFactory1 = unsafe { CreateDXGIFactory1() }.ok()?;
    for index in 0.. {
        let a1: IDXGIAdapter1 = match unsafe { factory.EnumAdapters1(index) } {
            Ok(a) => a,
            Err(e) if e.code().0 == DXGI_ERROR_NOT_FOUND => break,
            Err(_) => break,
        };
        let Ok(desc) = (unsafe { a1.GetDesc1() }) else {
            continue;
        };
        if luid_to_i64(desc.AdapterLuid) != adapter.luid {
            continue;
        }
        let a = match a1.cast::<IDXGIAdapter>() {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("gpu: adapter cast to IDXGIAdapter failed: {e}");
                return None;
            }
        };
        let mut device: Option<ID3D11Device> = None;
        let hr = unsafe {
            D3D11CreateDevice(
                Some(&a),
                D3D_DRIVER_TYPE_UNKNOWN,
                HMODULE(std::ptr::null_mut()),
                Default::default(),
                None,
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                None, // ppImmediateContext：不需要。
            )
        };
        match hr {
            Ok(()) => {
                tracing::info!(
                    "gpu: D3D11 device created on selected adapter (luid=0x{:016x})",
                    adapter.luid as u64
                );
                return device;
            }
            Err(e) => {
                tracing::warn!("gpu: D3D11CreateDevice on selected adapter failed: {e}");
                return None;
            }
        }
    }
    None
}
