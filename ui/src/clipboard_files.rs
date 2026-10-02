//!
//! arboard 3.4 公开 API 无文件接口（`get_text/set_text/get_image/set_html`，
//! winapi 直读（非可选优化）。
//!
//! **读面只读不写板**：`has_cf_hdrop`/`has_cf_unicode_text`/`read_cf_hdrop`/
//! `read_local_files` 全程不调用 `SetClipboardData`/`EmptyClipboard`——
//! `CloseClipboard` 即复原，不碰既有格式（设计 §2.4 口径）。
//!
//! 文件路径写本机 CF_HDROP，Explorer 可粘贴；仅 `FileSession::on_finish`
//! 经剪贴板 epoch 门控调用——面板拉取零写板）。写板纪律见该函数 doc。
//!
//! ×3，1/2/3 文件均败且 Empty 后 Set 失败=板被清空）**：
//! ①[`write_cf_hdrop`] 重试+回滚：OpenClipboard 失败重试 ≤5 次（退避
//! 10~20ms，日志含 GetLastError 码）；整序列 Open→Empty→Set 失败重试 ≤2 轮；
//! 已 Empty 后 Set/Alloc 失败=回滚（进入函数先读旧板留底 CF_HDROP 路径集，
//! 重 Set 回去；旧板读不到/回滚失败=ERROR 如实暴露「板空+文件未上」）；
//! ②**进程内访问串行化 gate**：全局 Mutex [`CLIPBOARD_ACCESS_GATE`]——
//! 写面全程持锁、读面 [`read_cf_hdrop`] 短暂持锁（`get_file_meta`/
//! `read_local_files` 经既有桥自动受益，`clipboard.rs` 零逻辑改动）；
//! arboard 面（`get_text`/`set_text`）无法经既有桥挂 gate=仅写侧串行+
//!
//! ①**根因=GMEM_MOVEABLE 生命周期错误（嫌疑②成立，实机 100% 复现 err=6
//! 逐位吻合）**：`GlobalAlloc(GMEM_MOVEABLE)` 块**初态 UNLOCKED**（MSDN 口径；
//! handle≠`GlobalLock` 返回指针）。旧码以裸句柄 `from_raw_parts_mut` 写载荷
//! =写到错误地址、损坏内存对象头→`SetClipboardData` 以
//! `ERROR_INVALID_HANDLE(6)` 拒绝该句柄（嫌疑①「传指针给 Set」形态不成立——
//! Set 的第二参本来就是句柄，错在**写数据**这一步；嫌疑③ DROPFILES 布局
//! 不成立——回读存储字节逐位吻合；嫌疑④ 残留错误码不成立——err=6 为 Set
//! 真实返回，但 `GlobalFree` 先于 `GetLastError` 的捕获顺序隐患一并修）。
//! 修复=**GlobalAlloc→GlobalLock→写→GlobalUnlock→SetClipboardData(句柄)**
//! 正确生命周期（实机验证：Set 成功、存储字节逐位吻合、
//! `IsFormatAvailable(CF_HDROP)`=true）。
//! 退避=用户实测「3 轮仅隔 2ms」；Open 重试 10~20ms 口径保留）；**每轮重建
//! HGLOBAL**（每轮全新 `GlobalAlloc`；失败即 `GlobalFree`，绝不跨轮复用句柄）。
//! ③**写后回读验证（用户复测定案线）**：Set 成功后**立即重开板回读
//! CF_HDROP**（不取锁内部读，复用 `DragQueryFileW` 读面）——路径一致→
//! 诚实暴露（返回 `false`）。**24H2 读面特性记档**：本机 build 22631 实测
//! `DragQueryFileW` 对任何应用自建经典布局 HDROP 解析 0 条（同/跨进程、
//! 若用户机亦此形态，回读行将如实报 ERROR 而 Explorer 粘贴行为为准
//! （记档，复测定案）。
//! ④**幽灵 meta 读面收口**（用户 09-16 伴证：写板失败报「board left EMPTY」
//! 后 500ms 轮询仍持续上报 entries=1 文件 meta 4 分钟 473 条）：定案=
//! 推送源即**活板实读**（`clip_poll_tick_roots` 每 tick 现读现推，无元数据
//! 缓存；epoch/落盘批队列只喂写路径、不进推送链）——板真空不可能凭空推
//! 文件条目；代码级鬼条通道=本文件读面「`metadata` 失败→条目保留 size=0」
//! 宽容性把**陈旧 HDROP 句柄的幽灵读取**（失败写残留/第三方持板陈旧对象）
//! 变成可推条目（entries=1, size=0）。修复=`read_cf_hdrop` 单条路径
//! `\\?\` 长路径探针二次判存：不可解析=**鬼条丢弃**（fail-closed 不推
//! （真实 size 回填）。失败写本身修复后不再产生板面残留（实证：失败后
//! 板面干净 IsFormatAvailable=false/GetClipboardData=null，3×300ms 探针）。
//!
//! failed` 30s 持续 = `IsClipboardFormatAvailable(CF_HDROP)`=true 而
//! `DragQueryFileW` 解析 0 条的读侧 quirk 形态）**：
//! ⑤[`write_cf_hdrop`] 读回未 `Verified`（`Mismatch`/`Unreadable`）=
//! **重开剪贴板重设**（下一轮整序列 `Open→Empty→新 HGLOBAL→Set` 重跑，
//! 真实落板——旧码检出后仅记档零兜底 = 本修复点）：与整序列失败**共享**
//! 轮预算 [`CLIP_SEQ_RETRY_LIMIT`]（至多 3 次 `SetClipboardData`，**有界
//! 未 `Verified` = 诚实 `false`）；读回 `got>0`（第三方在 Set 与读回窗口
//! 内换板）= **零覆盖**不重设（覆盖用户新复制 = 更坏）；兜底动作行 WARN
//! 暴露；兜底退避 [`readback_fallback_delay_ms`]（200ms 口径）。**候选
//! 决策记档**（岗内定，三选一）：重开剪贴板重设 = **选定**（真实落板、
//! 单点在本文件写路径、零协议/零依赖/零新警告）；保活 handle 重试 =
//! 弃（Set 成功后 HGLOBAL 所有权已转移剪贴板，无合法「同 handle 重试」
//! 形态，拉长持板只增争用）；降级 temp 文件+自定义格式随路 = 弃（wire
//! 协议变更 + 消费侧为原生粘贴无法消费自定义格式，超出本岗文件所有权）。
//!
//! ⑥[`write_cf_hdrop`] 写路径**改为 OLE 形态写入优先**（卡口径：ole32 raw FFI
//! **零新依赖**）：新增 [`ole_write_ffi`]（ole32 `CoInitializeEx`/
//! `OleSetClipboard` raw extern，同 [`hdrop_write_ffi`] 先例）+ [`ole_hdrop`]
//! （**手工 7 方法 `IDataObject`** COM 对象：vtable 按 objidl 顺序
//! QueryInterface/AddRef/Release/GetData/SetData/QueryGetData/GetFormatSize/
//! DAdvise/Unadvise/GetAdviseCount——`GetDataHere` 属 IRenderObject **非**
//! IDataObject（取证期 5 方法 vtable 错误形态教训，正确 7 方法 vtable 经
//! v3y 实验排除）；x64 `FORMATETC`=24B/`STGMEDIUM`=16B 布局钉单测；
//! `GetData` 每次经新 `GlobalAlloc` HGLOBAL 供**与经典形态同源的**
//! 轮首：**未降级轮 OLE 臂先行**（线程幂等 `CoInitializeEx(ATA)` →
//! 全新对象 → `OleSetClipboard` ≤10×100ms 有界重试——.NET
//! `ClipboardCore.SetData` 源码同口径重试环 `while (OleSetClipboard).Failed
//! 未 `Verified` = 诚实 `false`——**未读回验证不得宣称成功** = 卡
//! fail-closed 红线）。OLE 臂与经典臂**共享** [`CLIP_SEQ_RETRY_LIMIT`]
//! 轮预算（总轮数 = 3；OLE 单轮 ≤10 次 `OleSetClipboard` 调用 → 全调用
//! OLE ≤30 次 / 经典 `SetClipboardData` ≤3 次，**全有界防死循环**）。
//! **24H2 实测定案（build 22631 = 179 同系，九点证据链全文见交付
//! 报告）**：raw-FFI 进程的 `OleSetClipboard` 被确定性拒绝
//! `OLEOBJ_E_CANTCONVERT(0x800401F0)`、板不修改——手工正确 vtable C#
//! 对象 / 真 CLR CCW 直接 P/Invoke / 干净 native 进程（本实现同形态）
//! 10/10×2 写全拒、30×500ms（15s 跨度）全拒（排除时序竞态）；
//! `OleFlushClipboard`/`OleInitialize`(E_INVALIDARG)/`OleGetClipboard`/
//! 各 `CoInitializeEx` 变体皆**无法 prime**；shell32
//! `SHCreateItemFromParsingName`（含 notepad.exe 对照 + IShellItem/
//! IShellItem2 双 IID）E_NOINTERFACE = shell 原生路线亦第一步被封；
//! 唯 **CLR 内建** `Clipboard.SetDataObject` 可造好板（每进程 OLE 板
//! 状态，同进程一次 CLR 成功后直接调用始工作 = CLR 专属 bootstrap）
//! ——**卡前提「ole32 raw FFI 在本机可造 OLE 好板」于本机证伪**：本
//! build 的 OLE 板写入被门控于 CLR bootstrap 状态，不向任意 raw-FFI
//! 进程开放。
//! **遗留②收口（卡改动要求 2：「OLE 验证通过后自然消除，否则说明」）**：
//! 24H2 OLE 验证**不能**通过（上段定案）→ 末轮耗尽后板持最后一次经典
//! 同源）——**未自然消除**（自然消除以 OLE 读回 `Verified` 为前提）；
//! 验证写入永不宣称成功**（诚实 `false` + ERROR 行）。该遗留的真修复
//! = 本进程于 24H2 造出 OLE 好板，零新依赖路线在本 build 不可达（需
//! CLR/.NET 辅助面 = 用户新增决策，见交付报告升级选项），列遗留。
//!
//! **fail-closed**：任何失败（格式缺失 / OpenClipboard 争用 / Winlogon 锁 /
//! session 0）= `None`（本 tick 无变化）；读面 tick 内**不重试风暴**——
//! 500ms 轮询下一 tick 自然再读（服务端 tick 单一点 `clip_poll_tick`；
//! 客户端粘贴时刻新鲜读 [`read_local_files`] 短重试 ≤1 次）。写面
//! [`write_cf_hdrop`] 的重试是**调用时刻一次性**（文件落盘后唯一写板点），
//! 与读面 tick 不重试纪律不冲突。
//!
//! unix = 空实现（`None`）保 unix 构建绿（v1 范围 Win-only，设计 §1.3）。
//! 绝对路径仅本端内存，**永不出 wire**（wire 面 = root 相对路径，§2.2/§7.4）。

use super::OsFileBoard;

/// CF_HDROP 条目上限：>255 截断（设计 §2.4；与元数据条目上限 255 同口径）。
#[cfg_attr(not(windows), allow(dead_code))]
const MAX_CF_HDROP_ENTRIES: usize = 255;

/// 单条路径缓冲区上限（32 KiB，覆盖 >MAX_PATH 长路径）。
#[cfg_attr(not(windows), allow(dead_code))]
const PATH_BUF_CAP: usize = 32 * 1024;

#[cfg(windows)]
use winapi::um::shellapi::{DragQueryFileW, HDROP}; // winapi 0.3.9：shellapi feature（设计「shell32」勘误点；HDROP 亦在此模块）
#[cfg(windows)]
use winapi::um::winuser::{
    CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber,
    IsClipboardFormatAvailable, OpenClipboard, SetClipboardData, CF_HDROP, CF_UNICODETEXT,
};

/// 0 = 不可用（unix 恒 0 / Win 异常态）——调用方把 0 当「基线不可用」
/// 回落纯阳性证据判据（fail-safe）。
/// tick 读板序号 = 基线 → 板自置位后**未变**（含占位写板失败残留旧文本形态）
/// → 不判「新复制」→ 保守保留 pending。
#[cfg(windows)]
pub fn clipboard_sequence_number() -> u32 {
    unsafe { GetClipboardSequenceNumber() }
}
#[cfg(not(windows))]
pub fn clipboard_sequence_number() -> u32 {
    0
}

#[cfg(windows)]
mod hdrop_write_ffi {
    //! `winuser`+`shellapi`（ui/Cargo.toml 冻结写集外），不新增 feature，
    //! 零新依赖（Cargo.toml/Cargo.lock 零 diff）。
    #[link(name = "kernel32")]
    extern "system" {
        /// 「初态 locked 句柄直用」注释=事实错误，实机探针证伪）——写数据前
        /// 必须 [`GlobalLock`]，写完 [`GlobalUnlock`]，`SetClipboardData`
        /// 传**句柄**（非锁指针）。
        pub fn GlobalAlloc(uFlags: u32, dwBytes: u32) -> *mut std::ffi::c_void;
        /// 释放 GlobalAlloc 块——**仅失败路径调用**：`SetClipboardData` 成功 =
        /// 剪贴板接管所有权，**不得**再 free（double free = 堆破坏）。
        pub fn GlobalFree(hMem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
        /// 锁定 moveable 堆块 → 数据区**真指针**（失败 = NULL；块已被
        /// `SetClipboardData` 接管所有权后仍可锁读）。
        pub fn GlobalLock(hMem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
        /// 解锁 moveable 堆块（返回新锁计数；`Set` 前必须解锁——
        /// MSDN CF_HDROP 直写模式）。
        pub fn GlobalUnlock(hMem: *mut std::ffi::c_void) -> u32;
        /// 块同口，零新依赖）。
        pub fn GetLastError() -> u32;
    }
    /// GMEM_MOVEABLE（winnt.h 常量；winapi winnt feature 未启用 → 直书值）。
    pub const GMEM_MOVEABLE: u32 = 0x0002;
}

/// `winapi` 0.3.9 启用特性不含 ole32 → 走本文件 [`hdrop_write_ffi`] 既有
/// Cargo.toml/Cargo.lock 零 diff）。
#[cfg(windows)]
mod ole_write_ffi {
    #[link(name = "ole32")]
    extern "system" {
        /// 线程 COM 初始化（`OleSetClipboard` 前置；**线程幂等**——首调
        /// S_OK，同线程后续 S_FALSE/`RPC_E_CHANGED_MODE`，一律继续，码仅
        pub fn CoInitializeEx(pv_reserved: *const std::ffi::c_void, dw_co_init: u32) -> i32;
        /// OLE 形态剪贴板写入（现代剪贴板协议；成功 = OLE 自持
        /// `IDataObject` 引用——调用方初引用仍须**单独**释放，不 double
        /// free；失败 = OLE 不持引用，调用方自释放）。24H2（build 22631）
        /// raw-FFI 进程确定性拒绝 `OLEOBJ_E_CANTCONVERT`（模块 doc ⑥
        /// 取证记档）。
        pub fn OleSetClipboard(data_object: *const std::ffi::c_void) -> i32;
    }
    /// COINIT_APARTMENTTHREADED（0x2；0x1 = MTA——.NET 剪贴板路径要求 STA
    /// 口径，取 ATA）。
    pub const COINIT_APARTMENTTHREADED: u32 = 0x2;
    // ── HRESULT（i32 补码；0x80xx_xxxx 字面量超 i32::MAX → 由 LE 字节构造）──
    pub const HRESULT_S_OK: i32 = 0;
    /// 24H2 raw-FFI `OleSetClipboard` 确定性拒绝码（模块 doc ⑥ 取证定案；
    /// 降级 WARN 行以此特判注记「24H2 门控形态」）。
    pub const OLEOBJ_E_CANTCONVERT: i32 = i32::from_ne_bytes([0xF0, 0x01, 0x04, 0x80]); // 0x800401F0
    /// 请求格式未提供（`GetData`/`QueryGetData` 非目标格式）。
    pub const DV_E_CLIPFORMAT: i32 = i32::from_ne_bytes([0x02, 0x00, 0x04, 0x80]); // 0x80040002
    pub const E_INVALIDARG: i32 = i32::from_ne_bytes([0x05, 0x40, 0x00, 0x80]); // 0x80004005
    pub const E_NOINTERFACE: i32 = i32::from_ne_bytes([0x02, 0x40, 0x00, 0x80]); // 0x80004002
    pub const E_NOTIMPL: i32 = i32::from_ne_bytes([0x01, 0x40, 0x00, 0x80]); // 0x80004001
    pub const E_OUTOFMEMORY: i32 = i32::from_ne_bytes([0x0E, 0x00, 0x07, 0x80]); // 0x8007000E
    /// CF_HDROP（= winapi `winuser::CF_HDROP` 同值；本 OLE 臂直书值，
    /// 口径同 [`super::hdrop_write_ffi`] `GMEM_MOVEABLE` 直书记档）。
    pub const CF_HDROP: u32 = 15;
    /// TYMED_HGLOBAL（`STGMEDIUM::tymed` 取值）。
    pub const TYMED_HGLOBAL: u32 = 1;
}

///
/// 布局钉（x64；单测 `r132_3b_com_layout_nail`）：`FORMATETC`=24B
/// {cfFormat u32, dwAspect u32, lindex i32, _pad u32, ptid ptr}；
/// `STGMEDIUM`=16B {tymed u32, _pad u32, u ptr}。vtable = IUnknown 后
/// **7 方法** objidl 顺序（GetData/SetData/QueryGetData/GetFormatSize/
/// DAdvise/Unadvise/GetAdviseCount）。
/// 生命周期：`new` rc=1（调用方初引用）；OLE 接受（S_OK）= OLE 自持其
/// 引（板替换/过期时经 vtable `Release` 释放），调用方初引用由调用方
/// 单独释放；OLE 拒绝 = OLE 不持引，调用方释放初引用 → rc→0 **自释**
/// （`Box::from_raw`，无泄漏、绝不跨轮复用）。`GetData` 每次供新
/// `GlobalAlloc(GMEM_MOVEABLE)` HGLOBAL（所有权 → OLE/消费者；写纪律
/// `E_OUTOFMEMORY` 不供部分内容）。
#[cfg(windows)]
mod ole_hdrop {
    use super::hdrop_write_ffi;
    use super::ole_write_ffi as ffi;
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// COM GUID（16B）。
    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    pub(super) const IID_IUNKNOWN: Guid = Guid {
        data1: 0x0000_0000,
        data2: 0x0000,
        data3: 0x0000,
        data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x00],
    };
    pub(super) const IID_IDATAOBJECT: Guid = Guid {
        data1: 0x0000_010E,
        data2: 0x0000,
        data3: 0x0000,
        data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x00],
    };

    /// x64 FORMATETC（24B；取证期 16B 错误形态教训见模块 doc ⑥）。
    #[repr(C)]
    pub(super) struct Formatetc {
        pub(super) cf_format: u32,
        pub(super) dw_aspect: u32,
        pub(super) lindex: i32,
        pub(super) _pad: u32,
        pub(super) ptid: *mut c_void,
    }

    /// x64 STGMEDIUM（16B）；TYMED_HGLOBAL → `u` = HGLOBAL。
    #[repr(C)]
    pub(super) struct Stgmedium {
        pub(super) tymed: u32,
        pub(super) _pad: u32,
        pub(super) u: *mut c_void,
    }

    /// IDataObject vtable（x64：10 槽 × 8B = IUnknown 3 + 数据方法 7）。
    #[repr(C)]
    struct Vtbl {
        query_interface: usize,
        add_ref: usize,
        release: usize,
        get_data: usize,
        set_data: usize,
        query_get_data: usize,
        get_format_size: usize,
        dadvise: usize,
        unadvise: usize,
        get_advise_count: usize,
    }

    /// OLE 对象体（vtable 指针 + 引计数 + 唯一内容源）。
    pub(super) struct Obj {
        _vt: *const Vtbl,
        rc: AtomicUsize,
        payload: Vec<u8>,
    }

    // ── COM 方法实现（OLE 层经 vtable 调用；x64 标准调用约定 = Rust 默认 ABI）──

    unsafe fn add_ref(this: *mut Obj) -> u32 {
        // COM `AddRef` 返回 ULONG（u32）；AtomicUsize 为指针宽度——
        // 引计数现实量级 ≤个位，`as u32` 截断不可达。
        ((*this).rc.fetch_add(1, Ordering::AcqRel) + 1) as u32
    }

    unsafe fn release(this: *mut Obj) -> u32 {
        let prev = (*this).rc.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            drop(Box::from_raw(this)); // rc→0 = 自释（对象生命周期终结）
            0
        } else {
            (prev - 1) as u32
        }
    }

    unsafe fn query_interface(this: *mut Obj, riid: *const Guid, ppv: *mut *mut c_void) -> i32 {
        if ppv.is_null() {
            return ffi::E_INVALIDARG;
        }
        *ppv = std::ptr::null_mut();
        if (*riid == IID_IUNKNOWN) || (*riid == IID_IDATAOBJECT) {
            *ppv = this as *mut c_void;
            add_ref(this);
            ffi::HRESULT_S_OK
        } else {
            ffi::E_NOINTERFACE
        }
    }

    /// CF_HDROP 数据供给：每次新 `GlobalAlloc(GMEM_MOVEABLE)` HGLOBAL 供
    /// `payload` 字节串（与经典臂 [`super::build_hdrop_payload`] 同源同
    /// GMEM_MOVEABLE 初态 UNLOCKED，裸句柄直写 = 损坏内存对象）；分配
    /// 失败 = `E_OUTOFMEMORY`（不供部分内容）。
    unsafe fn get_data(this: *mut Obj, fmt: *const Formatetc, med: *mut Stgmedium) -> i32 {
        if fmt.is_null() || med.is_null() {
            return ffi::E_INVALIDARG;
        }
        if (*fmt).cf_format != ffi::CF_HDROP {
            return ffi::DV_E_CLIPFORMAT;
        }
        let payload: &[u8] = &(*this).payload;
        let h = hdrop_write_ffi::GlobalAlloc(hdrop_write_ffi::GMEM_MOVEABLE, payload.len() as u32);
        if h.is_null() {
            return ffi::E_OUTOFMEMORY;
        }
        let mem = hdrop_write_ffi::GlobalLock(h);
        if mem.is_null() {
            let _err = hdrop_write_ffi::GetLastError(); // 先取码（纪律）
            hdrop_write_ffi::GlobalFree(h);
            return ffi::E_OUTOFMEMORY;
        }
        std::slice::from_raw_parts_mut(mem as *mut u8, payload.len()).copy_from_slice(payload);
        hdrop_write_ffi::GlobalUnlock(h);
        (*med).tymed = ffi::TYMED_HGLOBAL;
        (*med)._pad = 0;
        (*med).u = h;
        ffi::HRESULT_S_OK
    }

    unsafe fn set_data(_this: *mut Obj, _fmt: *const Formatetc, _med: *const Stgmedium) -> i32 {
        ffi::HRESULT_S_OK // 单格式对象：OLE 不向我方 SetData
    }

    unsafe fn query_get_data(_this: *mut Obj, fmt: *const Formatetc) -> i32 {
        if fmt.is_null() {
            return ffi::E_INVALIDARG;
        }
        if (*fmt).cf_format == ffi::CF_HDROP {
            ffi::HRESULT_S_OK
        } else {
            ffi::DV_E_CLIPFORMAT
        }
    }

    unsafe fn get_format_size(this: *mut Obj, fmt: *const Formatetc, cb: *mut u32) -> i32 {
        if fmt.is_null() || cb.is_null() {
            return ffi::E_INVALIDARG;
        }
        if (*fmt).cf_format == ffi::CF_HDROP {
            *cb = (*this).payload.len() as u32;
            ffi::HRESULT_S_OK
        } else {
            ffi::DV_E_CLIPFORMAT
        }
    }

    unsafe fn dadvise(_this: *mut Obj, _src: *mut c_void, _advise: u32) -> i32 {
        ffi::E_NOTIMPL
    }
    unsafe fn unadvise(_this: *mut Obj, _advise: u32) -> i32 {
        ffi::E_NOTIMPL
    }
    unsafe fn get_advise_count(_this: *mut Obj, pcadvise: *mut u32) -> i32 {
        if pcadvise.is_null() {
            return ffi::E_INVALIDARG;
        }
        *pcadvise = 0;
        ffi::HRESULT_S_OK
    }

    /// 进程全局共享单一 vtable（**零 per-object 拷贝**）。
    /// 函数项 → 整数 cast 运行时方许（const 求值禁止指针/函数项转整——
    /// 编译期定案）→ `OnceLock` 首次初始化 `Box::new` 一份、由 static
    /// 持有至进程退出（无泄漏，~80B 一次性分配）。
    static VTBL: std::sync::OnceLock<Box<Vtbl>> = std::sync::OnceLock::new();

    fn vtbl() -> &'static Vtbl {
        VTBL.get_or_init(|| {
            // 函数项 → 整数须经指针中转（rustc 默认 lint
            // `direct cast of function item into an integer`；`as *const ()`
            // = 编译器建议形态，零新警告）。
            Box::new(Vtbl {
                query_interface: query_interface as *const () as usize,
                add_ref: add_ref as *const () as usize,
                release: release as *const () as usize,
                get_data: get_data as *const () as usize,
                set_data: set_data as *const () as usize,
                query_get_data: query_get_data as *const () as usize,
                get_format_size: get_format_size as *const () as usize,
                dadvise: dadvise as *const () as usize,
                unadvise: unadvise as *const () as usize,
                get_advise_count: get_advise_count as *const () as usize,
            })
        })
    }

    impl Obj {
        /// 建 OLE 对象（rc=1 = 调用方初引用；`payload` =
        /// [`super::build_hdrop_payload`] 产物，唯一内容源；首字段 =
        /// 共享 vtable 指针，COM 对象布局约定）。
        pub(super) fn new(payload: Vec<u8>) -> *mut Obj {
            let obj = Box::new(Obj {
                _vt: vtbl() as *const Vtbl,
                rc: AtomicUsize::new(1),
                payload,
            });
            Box::into_raw(obj)
        }

        /// 释放调用方初引用（OLE 接受 = OLE 自持其引、我方释初引安全；
        /// OLE 拒绝 = rc→0 自释，无泄漏）。
        pub(super) unsafe fn drop_initial_ref(this: *mut Obj) {
            release(this);
        }

        /// 测试专用：快照 payload 字节（不经 COM vtable——vtable 实调 =
        /// 实机探针域）。
        #[cfg(test)]
        pub(super) unsafe fn payload_snapshot(this: *const Obj) -> Vec<u8> {
            (*this).payload.clone()
        }
    }
}


///
/// 争抢三方现状（用户 09-15 伴证）：本进程写面（`write_cf_hdrop`）+ 本进程
/// 读面（tick `get_file_meta` 直读 / 粘贴时刻 `read_local_files` 直读 /
/// arboard `get_text`·`set_text`）+ **第三方进程**（`clipboard … held by
/// another party`）。gate 只解决**进程内**互斥（写序列不被自家读打断）；
/// 第三方持板无法进程内解决，由 `write_cf_hdrop` 的 Open 重试兜底。
///
/// 持锁纪律（不可重入 → 持锁临界区内**禁再锁**）：
/// - [`write_cf_hdrop`] 全程持锁（含重试退避 sleep；最坏 ~百 ms 量级，
///   臂 ≤10×100ms 重试退避〔24H2 CANTCONVERT 拒绝形态，模块 doc ⑥〕=
///   最坏升至 ~1.2s，仅该形态）；
/// - [`read_cf_hdrop`] 入口取锁、`CloseClipboard` 后随 guard 析构释放；
/// - 写面临界区内的旧板留底读（`read_old_hdrop`）与回滚（`rollback_set_hdrop`）
///   **不取锁**（已持锁，重入=自死锁）；
/// - arboard 面（`OsClipboard::get_text`/`set_text`）经既有 pub use 桥
///   挂不上本 gate（桥接需触 `clipboard.rs` 冻结读面）→ 不挂，记档。
#[cfg(windows)]
static CLIPBOARD_ACCESS_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

// 标记只由本线程自己的 guard 置/清 → 标记=true ⟺ 本线程当前持锁。
//（thread_local! 宏调用不挂 rustdoc → 此处用普通注释）
#[cfg(windows)]
thread_local! {
    static CLIP_GATE_HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// 持有者 panic 展开时 Drop 仍执行，标记与锁状态不漂移）。
#[cfg(windows)]
struct ClipGateGuard {
    _inner: std::sync::MutexGuard<'static, ()>,
}

#[cfg(windows)]
impl Drop for ClipGateGuard {
    fn drop(&mut self) {
        CLIP_GATE_HELD.with(|h| h.set(false));
    }
}

///
/// - **重入防线**（生产消费 [`gate_verdict`] 纯判定）：同线程再取 =
///   自死锁 → **panic fail-fast**（不挂死文件会话任务、不永久持 gate
///   阻塞全部读面）；生产路径结构性不可重入（临界区内旧板留底读/回滚
///   走不取锁函数），此检查=最后防线+语义钉（单测 ③ 同口径）；
/// - **锁中毒**（前临界区 panic）= 取 inner 继续用——本 gate 保护的是
///   **进程内互斥**而非共享数据完整性，原生剪贴板状态与本锁解耦，
///   中毒不改变板面事实（`unwrap_or_else` 标准最小恢复）。
#[cfg(windows)]
fn clip_gate() -> ClipGateGuard {
    use std::sync::PoisonError;
    let held = CLIP_GATE_HELD.with(|h| h.get());
    if matches!(
        gate_verdict(held.then_some("self"), "self"),
        GateVerdict::ReentryForbidden
    ) {
        panic!(
        );
    }
    let inner = CLIPBOARD_ACCESS_GATE.lock().unwrap_or_else(PoisonError::into_inner);
    CLIP_GATE_HELD.with(|h| h.set(true));
    ClipGateGuard { _inner: inner }
}

/// 本机剪贴板是否含 CF_HDROP 文件格式（轻量探测，不需要打开剪贴板）。
/// unix = 恒 false（无文件能力，fail-closed）。
///
/// （`clipboard_delay::delay_board_owned_by_us()`），板上的 CF_HDROP = 我方
/// **延迟描述**（`SetClipboardData(CF_HDROP, NULL)`，无数据）——本进程任何
/// 线程 `GetClipboardData` 都会反向触发 `WM_RENDERFORMAT` → 渲染拉取 =
/// **复制即传输回潮**（用户法律级裁定禁止）。守卫短路 = 本进程全部消费方
/// 他进程（Explorer）不受影响——其 GetClipboardData 正是粘贴授权触发点。
#[cfg(windows)]
pub fn has_cf_hdrop() -> bool {
    if crate::clipboard_delay::delay_board_owned_by_us() {
        return false;
    }
    unsafe { IsClipboardFormatAvailable(CF_HDROP) != 0 }
}
#[cfg(not(windows))]
pub fn has_cf_hdrop() -> bool {
    false
}

/// 剪贴板；`has_cf_hdrop` 同构）。用途 = 会话窗 Ctrl+V「无事件形态」接管的
/// 「本板**无文本**」判据源（硬约束：新路径仅在本板无文本且含 CF_HDROP 时
/// 接管——文本板走 egui-winit 既有 `Event::Paste` 原路径，零变化）。
///
/// 形态口径（如实记档）：格式**存在**即判有文本（含空文本格式/不可读格式
/// → 保守不接管 = 既有行为零变化）；格式缺失 = 纯文件板形态（Explorer 文件
/// 复制常态）→ 可接管。unix = 恒 false（无文件能力，接管路径结构性不可达）。
#[cfg(windows)]
pub fn has_cf_unicode_text() -> bool {
    unsafe { IsClipboardFormatAvailable(CF_UNICODETEXT) != 0 }
}
#[cfg(not(windows))]
pub fn has_cf_unicode_text() -> bool {
    false
}

/// 读取本机剪贴板 CF_HDROP 文件清单（**只读**：Open → 计数 → 逐条路径 →
/// `std::fs::metadata` 取 size/is_dir → Close，不写板不碰既有格式）。
///
/// 失败形态（全部 = `None`，不 panic 不挂起）：
/// - `OpenClipboard(0)` 失败（他进程持板 / Winlogon 锁 / session 0）→ 直接 None
///   （tick 内不重试；WARN 节流由调用方 `OsClipboard::get_file_meta` 承担）；
/// - `GetClipboardData(CF_HDROP)` 空句柄（格式在探测与读取之间被换掉）→ None；
/// - 单条 `DragQueryFileW` 失败 → 跳过该条（清单其余保留）；
/// - 单条判存 = [`probe_entry_meta`]（`metadata` 主判 + `\\?\` 长路径探针
///   长路径可解析且真实 size 回填）；双路皆败 = **鬼条丢弃**（`continue`，
///   fail-closed 不推不存在的文件——用户 09-16 伴证「写板失败后 500ms 轮询
///   仍持续上报 entries=1」幽灵通道收口点；旧「metadata 失败→保留 size=0」
///   宽容性已废）。
///
/// 写序列串行化；`OsClipboard::get_file_meta`/`read_local_files` 经既有调用
/// 自动受益，`clipboard.rs` 零逻辑改动）。Open 本身仍**单次尝试**（tick 内
/// 不重试风暴口径不变）。
#[cfg(windows)]
pub fn read_cf_hdrop() -> Option<OsFileBoard> {
    // 触发渲染拉取——本进程读面结构性短路）。
    if crate::clipboard_delay::delay_board_owned_by_us() {
        return None;
    }
    unsafe {
        // Open 单次尝试（争用/锁 = None，不重试风暴，§2.4）。
        // winapi 签名：OpenClipboard(hWnd: HWND)——HWND 为裸指针，NULL = 当前线程。
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return None;
        }
        let handle = GetClipboardData(CF_HDROP);
        if handle.is_null() {
            CloseClipboard();
            return None;
        }
        let hdrop = handle as HDROP;

        // 计数（0xFFFFFFFF = 查询总数；>255 截断，§2.4）。
        let count = DragQueryFileW(hdrop, 0xFFFFFFFF, std::ptr::null_mut(), 0) as usize;
        let count = count.min(MAX_CF_HDROP_ENTRIES);

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            // 两段式：先查长度（不含终止符），再取内容。
            let need = DragQueryFileW(hdrop, i as u32, std::ptr::null_mut(), 0) as usize;
            if need == 0 {
                continue;
            }
            let cap = (need + 1).min(PATH_BUF_CAP);
            let mut buf = vec![0u16; cap];
            let got = DragQueryFileW(hdrop, i as u32, buf.as_mut_ptr(), cap as u32) as usize;
            if got == 0 {
                continue;
            }
            // 绝对路径：仅本端内存，不出 wire（§2.2/§7.4 零内容红线）。
            let abs_path = String::from_utf16_lossy(&buf[..got]);
            // （fail-closed——陈旧句柄残留/文件已不存在不推不存在条目）。
            let (size, is_dir) = match probe_entry_meta(&abs_path) {
                Some(meta) => meta,
                None => continue,
            };
            entries.push(super::OsFileEntry {
                abs_path,
                size,
                is_dir,
            });
        }
        CloseClipboard();
        Some(OsFileBoard { entries })
    }
}

#[cfg(not(windows))]
pub fn read_cf_hdrop() -> Option<OsFileBoard> {
    None
}

/// `OpenClipboard` 单次尝试 + **短重试 ≤1 次**（瞬态争用）；失败 = `None`
/// （视为无文件 → 调用方落 ②/③ 臂，**不产生误上传**，fail-closed）。
pub fn read_local_files() -> Option<OsFileBoard> {
    if !has_cf_hdrop() {
        return None;
    }
    if let Some(board) = read_cf_hdrop() {
        return Some(board);
    }
    // 短重试 ≤1 次（设计原句口径）。
    if has_cf_hdrop() {
        read_cf_hdrop()
    } else {
        None
    }
}

//
// 全仓首个写板面（读面 `read_cf_hdrop`/`read_local_files`/`has_cf_hdrop`
// 逻辑零改）。调用链：会话窗臂 ② 拉取派发登记（`clip_board_epoch_begin`）→
// `FileSession::on_finish` 拉取**落盘成功** → `write_cf_hdrop(已落盘路径)`
// → 用户随后在 Explorer Ctrl+V / 右键粘贴即得文件（用户 09-11 实测缺口：
// 全仓无 CF_HDROP 写板 → OS 资源管理器粘贴永远拿不到远端拉取的文件）。
//
// `SetClipboardData … board cleared by EmptyClipboard`，1/2/3 文件均败，
// 文件已落盘=末环写板失败定案）：
// 1. OpenClipboard 失败 = 重试 ≤[`CLIP_OPEN_RETRY_LIMIT`] 次（不计首次），
//    退避 [`open_retry_delay_ms`] = 10,12,14,16,18,20…ms（恒 10~20 区间）；
//    最终失败日志含 GetLastError 码；
// 2. 整序列（Open→Empty→Set）一轮内失败 = 整序列重试 ≤[`CLIP_SEQ_RETRY_LIMIT`] 轮；
// 3. 已 Empty 后 Set/Alloc 失败 = **回滚**：重 Set 旧 CF_HDROP 内容
//    （进入函数先读旧板留底 [`read_old_hdrop`]）；旧板读不到（`Unknown`）
//    或回滚再 Set 失败 = **ERROR 如实暴露**「板空+文件未上」最坏情形；
//    （用户复测判读用）；首次成功=调用点既有成功行（零变化），
//    重试后成功=本函数补 INFO（含轮次/重试数）。

/// DROPFILES 头部尺寸（POINT pt(8) + BOOL fnc(4) + BOOL fWide(4) + DWORD dwReserved(4)）。
/// `pFiles` 偏移 = 20（shellapi.h DROPFILES 布局，小端 x86/x64）。
#[cfg(windows)]
const DROPFILES_HEADER_SIZE: usize = 20;

#[cfg(windows)]
const CLIP_OPEN_RETRY_LIMIT: u32 = 5;

/// 总轮数 = 1 首轮 + [`CLIP_SEQ_RETRY_LIMIT`] 重试轮 = 3 轮。
#[cfg(windows)]
const CLIP_SEQ_RETRY_LIMIT: u32 = 2;

/// `ClipboardCore.SetData` 源码同口径：`while (OleSetClipboard).Failed`
/// 重试 10 次 ×100ms——取证期取源记档，零新依赖约束 = 本文件自实现
/// 同口径重试）。全调用 OLE 调用数 ≤ 本值 × (1+CLIP_SEQ_RETRY_LIMIT)
/// = 30（**有界**）。
#[cfg(windows)]
const OLE_SET_RETRY_LIMIT: u32 = 10;

#[cfg(windows)]
const OLE_SET_RETRY_DELAY_MS: u32 = 100;

/// 宁可走 ERROR 臂也不回滚**部分**清单丢失超额条目）。
#[cfg(windows)]
const OLD_HDROP_MAX_ENTRIES: usize = 1024;

/// 序列 = 10,12,14,16,18,20,20…（步长 2ms，20ms 封顶；恒在任务书
/// 10~20ms 区间内）。纯函数（无 FFI/sleep），单测可钉。
#[cfg(windows)]
#[must_use]
pub(crate) fn open_retry_delay_ms(retry_no: u32) -> u32 {
    10 + (retry_no.saturating_sub(1).saturating_mul(2)).min(10)
}

/// **轮间退避**毫秒数（纯函数，无 FFI/sleep，单测可钉）。
///
/// 仅隔 2ms」=伪重试）。序列 = 30, 40, 50…（基线 30ms、步长 10ms、
/// 10 轮后封顶 130ms——总轮数有界 3 轮，封顶仅防未来放宽轮数时退避失控）。
#[cfg(windows)]
#[must_use]
pub(crate) fn seq_retry_delay_ms(seq_attempt: u32) -> u32 {
    30 + seq_attempt.saturating_mul(10).min(100)
}

/// 退避毫秒数（纯函数，无 FFI/sleep，单测可钉）。
///
/// 失败类与 Open/Empty/Alloc/Set 争用（[`seq_retry_delay_ms`] 30ms 口径）**
/// 不同**：24H2 读侧 quirk（模块 doc ③ 记档；179 log:93 MISMATCH）指向剪贴板
/// 引擎异步归一化窗口，短间隔重设会撞上同一坏态 → 基线 200ms、步长 200ms、
/// 1000ms 封顶（总轮数有界 3，封顶仅防未来放宽轮数时退避失控）。
/// 序列 = 200, 400, 600…ms。
#[cfg(windows)]
#[must_use]
pub(crate) fn readback_fallback_delay_ms(seq_attempt: u32) -> u32 {
    200u32.saturating_mul(seq_attempt.saturating_add(1)).min(1000)
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadbackFallback {
    /// 重开剪贴板重设：下一轮整序列（Open→Empty→**新** HGLOBAL→Set）重跑
    Retry,
    /// 兜底耗尽（末轮回读仍非 `Verified`）→ 诚实 `false`
    GiveUpExhausted,
    /// 板已被第三方替换（读回 `got>0` = 板上文件条目非本次写入）→ **零
    /// 覆盖**立即 `false`（不重设——覆盖用户刚复制的内容 = 更坏）。
    GiveUpReplaced,
}

///
/// - `board_replaced`（读回 `got>0`，板上文件条目非本次写入 = 第三方在
///   Set 与读回窗口内换了板）→ 恒 `GiveUpReplaced`（任何轮次都不重设——
///   兜底的重设臂会 `Empty` 覆盖用户新内容，零覆盖优先）；
/// - 非末轮 → `Retry`（重开剪贴板重设；此刻板持本轮 Set 内容或空板，下一
///   轮重 `Empty` 幂等；**无回滚臂** = 此刻板非「已 Empty 未落」态——已写
///   条目是用户落板意图且文件已落盘，回滚旧板反把刚写条目抹掉，更坏；
///   Open/Empty/Alloc/Set 失败臂的回滚语义走 [`seq_retry_decision`] 零变化）；
/// - 末轮 → `GiveUpExhausted`（与 Open/Empty/Alloc/Set 失败**共享**整序列
///   轮预算 [`CLIP_SEQ_RETRY_LIMIT`]：总轮数 = 1 首轮 + 重试 = 3 轮，
///   `SetClipboardData` 至多 3 次——**有界，防死循环**）。
#[cfg(windows)]
#[must_use]
pub(crate) fn readback_fallback_decision(seq_attempt: u32, board_replaced: bool) -> ReadbackFallback {
    if board_replaced {
        return ReadbackFallback::GiveUpReplaced;
    }
    if seq_attempt + 1 < CLIP_SEQ_RETRY_LIMIT + 1 {
        ReadbackFallback::Retry
    } else {
        ReadbackFallback::GiveUpExhausted
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OleSetAction {
    /// `OleSetClipboard` 返回 S_OK → OLE 已接受（板形态 = 现代 OLE 形态）
    Accepted,
    /// 本次失败且轮次未尽 → 退避 [`OLE_SET_RETRY_DELAY_MS`]ms 后同对象
    /// 再 `OleSetClipboard`（有界）。
    Retry,
    /// 读回判据不变，未读回验证不得宣称成功）。
    Degrade,
}

/// 单测可钉）。
///
/// - `hr = S_OK` → `Accepted`（任何轮次）；
/// - 失败（24H2 = [`ole_write_ffi::OLEOBJ_E_CANTCONVERT`] 确定性拒绝形态
///   / 其他 HRESULT 任意）且非末次（`attempt < limit-1`）→ `Retry`；
/// - 末次耗尽 → `Degrade`。总调用 = [`OLE_SET_RETRY_LIMIT`] = 10 次/轮
///   （全调用 ≤30 = 3 轮 × 10，**有界防死循环**）。
#[cfg(windows)]
#[must_use]
pub(crate) fn ole_set_action(hr: i32, attempt: u32) -> OleSetAction {
    if hr == ole_write_ffi::HRESULT_S_OK {
        return OleSetAction::Accepted;
    }
    if attempt + 1 < OLE_SET_RETRY_LIMIT {
        OleSetAction::Retry
    } else {
        OleSetAction::Degrade
    }
}

/// 返回后的句柄处置：**成功 = 剪贴板接管（不得再 free，double free=堆
/// 破坏）；失败 = 所有权未转移（必须 GlobalFree，防泄漏且**绝不跨轮复用**
/// ——下一轮全新 GlobalAlloc）**。
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HGlobalFate {
    /// Set 成功 → 系统接管（写方不得再触碰/释放）。
    Transferred,
    /// Set 失败 → 写方释放（本轮句柄生命周期终结）。
    Freed,
}

#[cfg(windows)]
#[must_use]
pub(crate) fn hglobal_fate_after_set(set_succeeded: bool) -> HGlobalFate {
    if set_succeeded {
        HGlobalFate::Transferred
    } else {
        HGlobalFate::Freed
    }
}

#[cfg(windows)]
pub(crate) struct ProbeResult {
    /// 板上 CF_HDROP 总条目数（`DragQueryFileW(0xFFFFFFFF)` 口径）。
    pub total: usize,
    /// 前 [`ProbeResult`] 请求上限内的路径（绝对路径，本端内存，不出 wire）。
    pub paths: Vec<String>,
}

/// - 板可读且**总条目数与逐条路径全等**（顺序敏感=写序）→ `Verified(n)`；
/// - 板可读但条目数/内容/顺序任一不符 → `Mismatch{expected, got}`
///   （含「多出来的条目」与「少条目」两态）；
/// - 板不可读（Open/Get 失败/无 CF_HDROP）→ `Unreadable`（诚实：写已被
///   OS 接受但回读不到 = 板面状态不可证实）。
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadbackVerdict {
    Verified(usize),
    Mismatch { expected: usize, got: usize },
    Unreadable,
}

#[cfg(windows)]
#[must_use]
pub(crate) fn verify_readback(expected: &[String], probe: Option<&ProbeResult>) -> ReadbackVerdict {
    let Some(p) = probe else {
        return ReadbackVerdict::Unreadable;
    };
    if p.total == expected.len() && p.paths.len() == expected.len() && p.paths == expected {
        ReadbackVerdict::Verified(expected.len())
    } else {
        ReadbackVerdict::Mismatch {
            expected: expected.len(),
            got: p.total,
        }
    }
}

/// - `\\?\` 前缀已在 → 原样（幂等）；
/// - 盘符绝对路径（`C:\…`）→ `\\?\C:\…`；
/// - UNC（`\\server\share\…`）→ `\\?\UNC\server\share\…`（Win32 长路径
///   UNC 专属形态）；
/// - 相对路径/非绝对 → `None`（无探针形态；`DragQueryFileW` 产物恒绝对，
///   此臂=防御性）。
#[cfg(windows)]
#[must_use]
pub(crate) fn long_path_probe(path: &str) -> Option<String> {
    // Win32 长路径前缀（4 字符：`\` `\` `?` `\`）。
    const LONG_PATH_PREFIX: &str = "\\\\?\\";
    if path.starts_with(LONG_PATH_PREFIX) {
        return Some(path.to_string());
    }
    let bytes = path.as_bytes();
    // 盘符绝对路径：`X:\`（3 字节前缀，第 2 字节 = ':'）。
    if bytes.len() >= 3 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/') {
        return Some(format!("\\\\?\\{}", path));
    }
    // UNC：`\\server\share…` → `\\?\UNC\server\share…`。
    if bytes.len() >= 2 && bytes[0] == b'\\' && bytes[1] == b'\\' {
        return Some(format!("\\\\?\\UNC\\{}", &path[2..]));
    }
    None
}

/// 长路径探针二次判存）：任一解析成功 → `Some((size, is_dir))`（>MAX_PATH
/// `None`（**鬼条**：陈旧句柄残留/文件已不存在 → 调用方丢弃，fail-closed
/// 不推不存在的文件）。非纯函数（触文件系统）；纯判定部分 = [`long_path_probe`]（单测钉）。
#[cfg(windows)]
#[must_use]
fn probe_entry_meta(path: &str) -> Option<(u64, bool)> {
    if let Ok(m) = std::fs::metadata(path) {
        return Some((m.len(), m.is_dir()));
    }
    if let Some(long) = long_path_probe(path) {
        if let Ok(m) = std::fs::metadata(&long) {
            return Some((m.len(), m.is_dir()));
        }
    }
    None
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailStep {
    /// OpenClipboard 重试耗尽（板未开 = 板内容未动）。
    Open,
    /// EmptyClipboard 失败（板未清 = 板内容未动）。
    Empty,
    /// GlobalAlloc 失败（**已 Empty** = 板已清空）。
    Alloc,
    /// SetClipboardData 失败（**已 Empty** = 板已清空）。
    Set,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeqAction {
    /// 重跑整序列（Open→Empty→Set 全新一轮）。
    Retry,
    /// 停止并返回 `false`。`hard_loss` = 板已 Emptied 且回滚未成功
    /// （无旧内容/旧板读不到/回滚再 Set 失败）=「板空+文件未上」最坏
    /// 情形 → 调用方必须记 **ERROR**（如实暴露）；`false` = 板内容完好
    /// 或已复原 → WARN。
    GiveUp { hard_loss: bool },
}

///
/// - 非末轮 → 一律 `Retry`（先试回滚再整序列重跑——已 Empty 的板在
///   下一轮重 Empty 无副作用）；
/// - 末轮 → `GiveUp`，`hard_loss` = 失败步已清空板（`Alloc`/`Set`）
///   **且** `board_recovered=false`（调用方传入：Open/Empty 失败恒 `true`
///   =板未动；Alloc/Set 失败 = 回滚结果，`NoFiles` 旧板=无文件内容可失
///   按 `true` 计）。
#[cfg(windows)]
#[must_use]
pub(crate) fn seq_retry_decision(
    seq_attempt: u32, // 当前轮（0 起计）
    failed_at: FailStep,
    board_recovered: bool,
) -> SeqAction {
    if seq_attempt + 1 < CLIP_SEQ_RETRY_LIMIT + 1 {
        return SeqAction::Retry;
    }
    let board_cleared = matches!(failed_at, FailStep::Alloc | FailStep::Set);
    SeqAction::GiveUp {
        hard_loss: board_cleared && !board_recovered,
    }
}

///
/// 真实 gate = `std::sync::Mutex`（**不可重入**）：持锁者若在同调用链
/// 内再取锁 = 自死锁。本模型把该纪律编码为可判语义——
/// 持锁临界区（`write_cf_hdrop`）内的旧板留底读/回滚走**不取锁**的
/// `read_old_hdrop`/`rollback_set_hdrop`，结构性杜绝重入。
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateVerdict {
    /// gate 空闲 → 可取锁。
    Proceed,
    /// 他线程持锁 → 阻塞等待（进程内串行化的正常形态：写面全程持锁，
    /// 读面 tick/粘贴读排队等待，不并发开板）。
    Wait,
    /// 请求者=持锁者自身 → **重入=自死锁，纪律禁止**（生产路径结构性
    /// 不可达；`clip_gate` 末道防线命中本臂 = panic fail-fast）。
    ReentryForbidden,
}

#[cfg(windows)]
#[must_use]
pub(crate) fn gate_verdict(holder: Option<&str>, requester: &str) -> GateVerdict {
    match holder {
        None => GateVerdict::Proceed,
        Some(h) if h == requester => GateVerdict::ReentryForbidden,
        Some(_) => GateVerdict::Wait,
    }
}

#[cfg(windows)]
enum OldHdrop {
    /// 板读取正常且**无** CF_HDROP 格式（或 0 条目）→ 板上从无旧文件内容；
    /// 已 Empty 后写失败 = 既有语义（文本/其他格式随 Empty 消失，下
    /// 次复制前不恢复）→ WARN，非 hard loss。
    NoFiles,
    /// 旧 CF_HDROP 路径集读取成功 → 已 Empty 后写失败 = 重 Set 此集回滚。
    Paths(Vec<String>),
    /// 旧板**读不到**（Open 争用/单条路径读失败/条目超限）→ 旧内容存否
    /// 未知；已 Empty 后写失败 = 最坏情形可能已发生 → ERROR 如实暴露。
    Unknown,
}

/// 保证回滚内容形态与原板一致）：20B 头（pt=(0,0) / fnc=FALSE /
/// fWide=TRUE / dwReserved=0）+ 每条路径 UTF-16（各自 NUL 终结）+
/// 列表末 NUL（末条路径 NUL 与列表 NUL 相邻 = 标准双 NUL 终结）。
#[cfg(windows)]
// clipboard_direct.rs 单测钉死 DROPFILES 布局；函数体零 diff。
pub(crate) fn build_hdrop_payload(paths: &[String]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(DROPFILES_HEADER_SIZE + 2);
    buf.extend_from_slice(&0i32.to_ne_bytes()); // pt.x = 0
    buf.extend_from_slice(&0i32.to_ne_bytes()); // pt.y = 0
    buf.extend_from_slice(&0i32.to_ne_bytes()); // fnc = FALSE
    buf.extend_from_slice(&1i32.to_ne_bytes()); // fWide = TRUE
    buf.extend_from_slice(&0u32.to_ne_bytes()); // dwReserved = 0
    for p in paths {
        for u in p.encode_utf16().chain(std::iter::once(0u16)) {
            buf.extend_from_slice(&u.to_ne_bytes());
        }
    }
    buf.extend_from_slice(&0u16.to_ne_bytes()); // 列表末 NUL（双 NUL 终结）
    buf
}

///
/// **调用方必须已持 [`CLIPBOARD_ACCESS_GATE`]**（仅 `write_cf_hdrop` 临界
/// 区内调用；本函数**不取锁**——gate 不可重入，重入=自死锁）。
///
/// Open 单次尝试（不重试：紧随其后的写序列重试环承担争用兜底；此处重试
/// 只会拉长全程持锁时长）；任一条路径读失败/截断/条目超限 = `Unknown`
/// （**不做部分留底**——回滚部分清单=丢失超额条目，更坏）。
#[cfg(windows)]
fn read_old_hdrop() -> OldHdrop {
    unsafe {
        // Open 单次尝试（失败不记码——争用兜底在写序列重试环，其日志带码）。
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return OldHdrop::Unknown;
        }
        let handle = GetClipboardData(CF_HDROP);
        if handle.is_null() {
            CloseClipboard();
            return OldHdrop::NoFiles;
        }
        let hdrop = handle as HDROP;
        let count = DragQueryFileW(hdrop, 0xFFFFFFFF, std::ptr::null_mut(), 0) as usize;
        if count == 0 {
            CloseClipboard();
            return OldHdrop::Paths(Vec::new());
        }
        if count > OLD_HDROP_MAX_ENTRIES {
            CloseClipboard();
            return OldHdrop::Unknown; // 超限 = 不全留底不可用
        }
        let mut paths = Vec::with_capacity(count);
        for i in 0..count {
            let need = DragQueryFileW(hdrop, i as u32, std::ptr::null_mut(), 0) as usize;
            if need == 0 || need > PATH_BUF_CAP - 1 {
                CloseClipboard();
                return OldHdrop::Unknown; // 单条失败/截断 = 整集不可用
            }
            let mut buf = vec![0u16; need + 1];
            let got = DragQueryFileW(hdrop, i as u32, buf.as_mut_ptr(), (need + 1) as u32) as usize;
            if got != need {
                CloseClipboard();
                return OldHdrop::Unknown;
            }
            paths.push(String::from_utf16_lossy(&buf[..got]));
        }
        CloseClipboard();
        OldHdrop::Paths(paths)
    }
}

///
/// 前置：板**已打开**且刚被 `EmptyClipboard` 清空 + 新写入失败。
/// **调用方必须已持 [`CLIPBOARD_ACCESS_GATE`]**（不取锁，防重入死锁）。
/// 所有权纪律同写路径：Set 成功 = 系统接管 HGLOBAL（不 free）；失败 =
/// 自 `GlobalFree`，板保持空（调用方按 hard loss 记 ERROR）。
/// 写在此臂同样损坏内存对象 = 用户「回滚亦败 RESTORE FAILED」同根因；
/// 失败路径先取错误码再 free）。
#[cfg(windows)]
unsafe fn rollback_set_hdrop(old_paths: &[String]) -> bool {
    use hdrop_write_ffi::{
        GetLastError, GlobalAlloc, GlobalFree, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
    };
    let payload = build_hdrop_payload(old_paths);
    let hmem = GlobalAlloc(GMEM_MOVEABLE, payload.len() as u32);
    if hmem.is_null() {
        return false;
    }
    let mem = GlobalLock(hmem);
    if mem.is_null() {
        let _lock_err = GetLastError(); // 先取码（纪律）；回滚臂码经 hard loss 行暴露。
        GlobalFree(hmem);
        return false;
    }
    std::slice::from_raw_parts_mut(mem as *mut u8, payload.len()).copy_from_slice(&payload);
    GlobalUnlock(hmem);
    // winapi 0.3.9 自带 `ctypes::c_void`（与 std 的同名类型互异）→ 显式转。
    let hdrop = SetClipboardData(CF_HDROP, hmem as *mut winapi::ctypes::c_void);
    if hdrop.is_null() {
        GlobalFree(hmem); // 失败 = 所有权未转移 → 自释放。
        false
    } else {
        true
    }
}

/// `ERROR_INVALID_HANDLE(6)`，实机 100% 复现逐位吻合）：
/// ① 载荷写入走 `GlobalAlloc→GlobalLock→写→GlobalUnlock→Set(句柄)`
/// （GMEM_MOVEABLE 初态 **UNLOCKED**——旧码裸句柄直写=写到错误地址损坏
/// 内存对象=err 6 根因）；② 序列重试轮间**真实退避 ≥30ms**（[`seq_retry_delay_ms`]，
/// 复用句柄；失败即 free）；③ Set 失败**先取错误码再 free**（顺序纪律）；
/// ④ **写后回读验证**（用户复测定案线）：Set 成功即重开板回读 CF_HDROP
/// （[`probe_hdrop_paths`] + [`verify_readback`]，≤3 次 50ms 有界重试）——
/// 写板回读 MISMATCH，179 log:93；模块 doc ⑤ 记档）：读回未 `Verified`
/// （`Mismatch`/`Unreadable`）不再立即终局 `false` → **重开剪贴板重设**
/// （下一轮整序列 `Open→Empty→新 HGLOBAL→Set` 重跑真实落板；第三方已换板
/// `got>0` = 零覆盖不重设），与 Open/Empty/Alloc/Set 失败**共享**轮预算
/// [`CLIP_SEQ_RETRY_LIMIT`]（至多 3 次 Set，**有界防死循环**），兜底后仍
/// 末轮耗尽 = ERROR 诚实暴露 + `false`；兜底退避
/// [`readback_fallback_delay_ms`]（200ms 口径，长于争用退避——24H2 异步
/// 归一化窗口）。
/// 轮首**未降级轮 OLE 臂先行**（线程幂等 [`co_init_ole`] +
/// [`try_ole_round`] = 全新手工 `IDataObject` + `OleSetClipboard`
/// ≤10×100ms 有界重试，.NET 同口径）——S_OK = 该轮跳过经典臂直接读回；
/// OLE 被拒（24H2 = CANTCONVERT 确定性形态）= 本轮起降级经典 HGLOBAL 臂
/// `Verified` = 诚实 `false`，未读回验证不得宣称成功 = 卡 fail-closed
/// 红线）。
///
/// 流程（任一最终失败 = WARN/ERROR 日志 + `false`，**不 panic、不留半开板**）：
/// 0. 取 [`CLIPBOARD_ACCESS_GATE`]（全程持锁，含退避 sleep）；
/// 1. 读旧板留底 [`read_old_hdrop`]（回滚素材，单次 Open 不重试）；
///    **OLE 臂先行**——OLE 已接受 = 跳过本条经典序列直接读回；OLE 被拒
///    = 本轮起降级）→ `OpenClipboard(0)`（失败重试 ≤5
///    次，退避 10~20ms）→ `EmptyClipboard` → `GlobalAlloc(GMEM_MOVEABLE)`
///    → `GlobalLock` → 写 DROPFILES 载荷（[`build_hdrop_payload`]）→
///    `GlobalUnlock` → `SetClipboardData(CF_HDROP, 句柄)` → `CloseClipboard`；
///    重试臂 = 轮间退避 [`seq_retry_delay_ms`] 后整序列重跑（每轮重建 HGLOBAL）；
/// 3. 已 Empty 后 Alloc/Lock/Set 失败 = 先试回滚（重 Set 旧板内容），再按
///    [`seq_retry_decision`] 定重试/终止；终止且 `hard_loss` = ERROR
///    如实暴露「板空+文件未上」；
/// 4. Set 成功 = 写后回读验证（④）；`Verified` = `true`，否则 `false`。
///
/// 所有权纪律：`SetClipboardData` **成功** = 剪贴板接管 HGLOBAL（不得 free）；
/// 失败 = 仍归本进程（`GlobalFree` 释放防泄漏）。`paths` 空 = `false`
/// （空 HDROP 无粘贴语义，且「写空板」会误擦既有格式）。
///
/// 线程纪律：调用点 = 文件会话任务（非 UI 线程）——Win32 剪贴板 API 允许
/// 任意线程 Open/Close（本文件读面已在轮询任务线程直用，同口径）。
/// unix = 恒 `false`（v1 范围 Win-only，保 unix 构建绿）。
#[cfg(windows)]
fn probe_hdrop_paths(max_entries: usize) -> Option<ProbeResult> {
    // 成功臂 Close 之后；单次 `OpenClipboard`，不重试——重试在调用点有界
    // 承担）。**不取 gate**（调用时调用方仍持锁——gate 不可重入；写序列已
    // 结束，单次读不与写序列竞态）。
    unsafe {
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return None;
        }
        let handle = GetClipboardData(CF_HDROP);
        if handle.is_null() {
            CloseClipboard();
            return None;
        }
        let hdrop = handle as HDROP;
        let total = DragQueryFileW(hdrop, 0xFFFFFFFF, std::ptr::null_mut(), 0) as usize;
        let n = total.min(max_entries).min(MAX_CF_HDROP_ENTRIES);
        let mut paths = Vec::with_capacity(n);
        for i in 0..n {
            let need = DragQueryFileW(hdrop, i as u32, std::ptr::null_mut(), 0) as usize;
            if need == 0 {
                CloseClipboard();
                return None; // 单条读失败 = 不可读（诚实，不做部分判定）
            }
            let cap = (need + 1).min(PATH_BUF_CAP);
            let mut buf = vec![0u16; cap];
            let got = DragQueryFileW(hdrop, i as u32, buf.as_mut_ptr(), cap as u32) as usize;
            if got != need {
                CloseClipboard();
                return None;
            }
            paths.push(String::from_utf16_lossy(&buf[..got]));
        }
        CloseClipboard();
        Some(ProbeResult { total, paths })
    }
}

/// 读回）。
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OleRound {
    SetOk,
    /// OLE 被拒（≤[`OLE_SET_RETRY_LIMIT`]×[`OLE_SET_RETRY_DELAY_MS`]ms 有界
    /// 重试耗尽）→ 本轮起降级经典 HGLOBAL 臂；`hr` = 末次 HRESULT（日志用）。
    Degraded { hr: i32 },
}

/// 返回 HRESULT（**仅日志用**——任何取值不改变路径：S_FALSE/
/// 调用点 = 文件会话任务线程（非 UI 线程，`write_cf_hdrop` 函数 doc 线程
/// 纪律）。
#[cfg(windows)]
fn co_init_ole() -> i32 {
    unsafe {
        ole_write_ffi::CoInitializeEx(
            std::ptr::null(),
            ole_write_ffi::COINIT_APARTMENTTHREADED,
        )
    }
}

/// 调用方已持 gate + 已 [`co_init_ole`]）。
///
/// 序列 = 全新 [`ole_hdrop::Obj`]（rc=1，`payload` = 与经典臂同源
/// [`build_hdrop_payload`] 产物）→ `OleSetClipboard` ≤[`OLE_SET_RETRY_LIMIT`]×
/// [`OLE_SET_RETRY_DELAY_MS`]ms（纯判定 [`ole_set_action`]）→ S_OK =
/// `OleRound::SetOk`（OLE 自持其引；我方初引用单独释放）；耗尽 =
/// `OleRound::Degraded{hr}`（我方初引用释放 → 对象自释，无泄漏、绝不
/// 跨轮复用）。
/// **本函数不 Open/Empty 板**——OLE 自管板（.NET 实证序列形态：无手动
/// `EmptyClipboard`）；24H2 CANTCONVERT 拒绝已证**板不修改**（模块 doc
/// ⑥ 取证记档），其后经典臂 Open/Empty/Set 不受影响。
#[cfg(windows)]
unsafe fn try_ole_round(payload: &[u8]) -> OleRound {
    let obj = ole_hdrop::Obj::new(payload.to_vec());
    let mut last_hr = 0i32;
    for attempt in 0..OLE_SET_RETRY_LIMIT {
        last_hr = ole_write_ffi::OleSetClipboard(obj as *const std::ffi::c_void);
        match ole_set_action(last_hr, attempt) {
            OleSetAction::Accepted => {
                // OLE 已接受 → OLE 自持其引；我方初引用单独释放（两引
                // 独立，不 double free）。
                ole_hdrop::Obj::drop_initial_ref(obj);
                return OleRound::SetOk;
            }
            OleSetAction::Retry => {
                std::thread::sleep(std::time::Duration::from_millis(
                    OLE_SET_RETRY_DELAY_MS as u64,
                ));
            }
            OleSetAction::Degrade => break,
        }
    }
    // OLE 未接受（重试耗尽）→ OLE 不持引，释放我方初引用 = rc→0 自释
    // （无泄漏；下一轮若仍试 OLE = 全新对象，绝不跨轮复用）。
    ole_hdrop::Obj::drop_initial_ref(obj);
    OleRound::Degraded { hr: last_hr }
}

#[cfg(windows)]
pub fn write_cf_hdrop(paths: &[std::path::PathBuf]) -> bool {
    if paths.is_empty() {
        return false;
    }
    unsafe {
        use hdrop_write_ffi::{
            GetLastError, GlobalAlloc, GlobalFree, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
        };
        // 旧板留底（回滚素材；单次 Open 不重试——争用由下方写序列重试环兜底）。
        let old_hdrop = read_old_hdrop();
        // PathBuf→str = `to_string_lossy`（Win 路径本体即 UTF-16/WTF-8，
        // 落盘路径来自引擎 commit = 可解码，无损常态）。
        let new_paths: Vec<String> = paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let payload = build_hdrop_payload(&new_paths);

        // （线程幂等；返回码仅日志用——任何取值不改变路径，最终判据 =
        let ole_co_hr = co_init_ole();
        let mut ole_degraded: Option<i32> = None;
        tracing::info!(
        );

        let mut last_err: u32 = 0;
        let mut open_retries: u32; // 每轮轮首赋值（成功臂日志引用；经典臂内计数）
        for seq_attempt in 0..=CLIP_SEQ_RETRY_LIMIT {
            open_retries = 0;
            // OLE 自管板（无手动 Open/Empty——.NET 实证序列形态）；24H2
            // CANTCONVERT 拒绝已证板不修改，下方经典臂不受影响。
            let mut ole_set_ok = false;
            if ole_degraded.is_none() {
                match try_ole_round(&payload) {
                    OleRound::SetOk => {
                        ole_set_ok = true;
                        tracing::info!(
                            seq_attempt + 1
                        );
                    }
                    OleRound::Degraded { hr } => {
                        ole_degraded = Some(hr);
                        // 24H2 门控形态 = OLEOBJ_E_CANTCONVERT（0x800401F0，
                        // 确定性，模块 doc ⑥ 取证记档）→ 本轮起降级经典臂
                        // （fail-closed：读回判据不变，未验证不宣称成功）。
                        let gate_note = if hr == ole_write_ffi::OLEOBJ_E_CANTCONVERT {
                            " [24H2 raw-FFI OLE gate form — module doc ⑥]"
                        } else {
                            ""
                        };
                        tracing::warn!(
                            seq_attempt + 1,
                            OLE_SET_RETRY_LIMIT,
                            OLE_SET_RETRY_DELAY_MS,
                        );
                    }
                }
            }
            if !ole_set_ok {
            // ── Open（首次 + ≤CLIP_OPEN_RETRY_LIMIT 重试，退避 10~20ms）──
            let mut opened = false;
            while !opened {
                if OpenClipboard(std::ptr::null_mut()) != 0 {
                    opened = true;
                    break;
                }
                last_err = GetLastError();
                if open_retries >= CLIP_OPEN_RETRY_LIMIT {
                    break;
                }
                open_retries += 1;
                std::thread::sleep(std::time::Duration::from_millis(
                    open_retry_delay_ms(open_retries) as u64,
                ));
            }
            if !opened {
                match seq_retry_decision(seq_attempt, FailStep::Open, true) {
                    SeqAction::Retry => {
                        let backoff = seq_retry_delay_ms(seq_attempt);
                        tracing::warn!(
                        );
                        std::thread::sleep(std::time::Duration::from_millis(backoff as u64));
                        continue;
                    }
                    SeqAction::GiveUp { hard_loss: _ } => {
                        // 板未开 = 板内容未动（hard_loss 恒 false，纯函数口径）。
                        tracing::warn!(
                            paths.len(),
                            CLIP_SEQ_RETRY_LIMIT + 1
                        );
                        return false;
                    }
                }
            }

            // ── Empty ──
            if EmptyClipboard() == 0 {
                last_err = GetLastError();
                CloseClipboard();
                match seq_retry_decision(seq_attempt, FailStep::Empty, true) {
                    SeqAction::Retry => {
                        let backoff = seq_retry_delay_ms(seq_attempt);
                        tracing::warn!(
                        );
                        std::thread::sleep(std::time::Duration::from_millis(backoff as u64));
                        continue;
                    }
                    SeqAction::GiveUp { hard_loss: _ } => {
                        tracing::warn!(
                            paths.len(),
                            CLIP_SEQ_RETRY_LIMIT + 1
                        );
                        return false;
                    }
                }
            }

            let hmem = GlobalAlloc(GMEM_MOVEABLE, payload.len() as u32);
            if hmem.is_null() {
                last_err = GetLastError();
                // **已 Empty** = 板已清空 → 回滚臂（同 Set 失败口径）。
                let (recovered, restore_note) = restore_after_clear(&old_hdrop);
                match seq_retry_decision(seq_attempt, FailStep::Alloc, recovered) {
                    SeqAction::Retry => {
                        let backoff = seq_retry_delay_ms(seq_attempt);
                        CloseClipboard();
                        tracing::warn!(
                            payload.len()
                        );
                        std::thread::sleep(std::time::Duration::from_millis(backoff as u64));
                        continue;
                    }
                    SeqAction::GiveUp { hard_loss } => {
                        CloseClipboard();
                        log_final_write_failure(
                            "GlobalAlloc",
                            last_err,
                            paths.len(),
                            hard_loss,
                            &restore_note,
                        );
                        return false;
                    }
                }
            }
            // 句柄**不是**数据指针（实机探针：handle ≠ GlobalLock 返回指针）。
            // 旧码以裸句柄 `from_raw_parts_mut` 写载荷 = 写到错误地址、损坏
            // 内存对象 → `SetClipboardData` 以 `ERROR_INVALID_HANDLE(6)` 拒绝
            // 正确生命周期：GlobalLock → 写 → GlobalUnlock → Set（Set 传**句柄**
            // 而非锁指针；零越界：载荷即 [`build_hdrop_payload`] 物化结果，
            // len 逐位吻合）。
            let mem = GlobalLock(hmem);
            if mem.is_null() {
                last_err = GetLastError();
                GlobalFree(hmem); // 本轮句柄生命周期终结（下一轮重建，不复用）。
                // **已 Empty** = 板已清空 → 回滚臂（同 Alloc/Set 失败口径）。
                let (recovered, restore_note) = restore_after_clear(&old_hdrop);
                match seq_retry_decision(seq_attempt, FailStep::Alloc, recovered) {
                    SeqAction::Retry => {
                        let backoff = seq_retry_delay_ms(seq_attempt);
                        CloseClipboard();
                        tracing::warn!(
                        );
                        std::thread::sleep(std::time::Duration::from_millis(backoff as u64));
                        continue;
                    }
                    SeqAction::GiveUp { hard_loss } => {
                        CloseClipboard();
                        log_final_write_failure(
                            "GlobalLock",
                            last_err,
                            paths.len(),
                            hard_loss,
                            &restore_note,
                        );
                        return false;
                    }
                }
            }
            std::slice::from_raw_parts_mut(mem as *mut u8, payload.len()).copy_from_slice(&payload);
            GlobalUnlock(hmem);

            // ── Set ──
            // winapi 0.3.9 自带 `ctypes::c_void`（与 std 的同名类型互异）→ 显式转。
            let hdrop = SetClipboardData(CF_HDROP, hmem as *mut winapi::ctypes::c_void);
            let set_ok = !hdrop.is_null();
            // 剪贴板接管（**不得再 free**——double free = 堆破坏）；失败 =
            // 写方释放（本轮句柄生命周期终结，下一轮全新重建、不复用）。
            // 立即取码」先例同口径）。
            if !set_ok {
                last_err = GetLastError();
            }
            match hglobal_fate_after_set(set_ok) {
                HGlobalFate::Transferred => {} // 所有权已转移——此后不得再触碰此句柄。
                HGlobalFate::Freed => {
                    let _ = GlobalFree(hmem);
                }
            }
            if !set_ok {
                let (recovered, restore_note) = restore_after_clear(&old_hdrop);
                match seq_retry_decision(seq_attempt, FailStep::Set, recovered) {
                    SeqAction::Retry => {
                        let backoff = seq_retry_delay_ms(seq_attempt);
                        CloseClipboard();
                        tracing::warn!(
                        );
                        std::thread::sleep(std::time::Duration::from_millis(backoff as u64));
                        continue;
                    }
                    SeqAction::GiveUp { hard_loss } => {
                        CloseClipboard();
                        log_final_write_failure(
                            "SetClipboardData",
                            last_err,
                            paths.len(),
                            hard_loss,
                            &restore_note,
                        );
                        return false;
                    }
                }
            }

            CloseClipboard();
            // 回读：≤3 次有界重试 @50ms（落板与重开之间第三方可能瞬态抢板；
            // gate 只串行化进程内——第三方抢板由此兜底；有界，不成风暴）。
            let mut probe: Option<ProbeResult> = None;
            for probe_attempt in 0..3u32 {
                if probe_attempt > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                if let Some(p) = probe_hdrop_paths(new_paths.len()) {
                    probe = Some(p);
                    break;
                }
            }
            match verify_readback(&new_paths, probe.as_ref()) {
                ReadbackVerdict::Verified(n) => {
                    if seq_attempt > 0 || open_retries > 0 {
                        tracing::info!(
                            paths.len(),
                            seq_attempt + 1
                        );
                    }
                    return true;
                }
                verdict @ (ReadbackVerdict::Mismatch { .. } | ReadbackVerdict::Unreadable) => {
                    // [`readback_fallback_decision`] doc；179 log:93 MISMATCH
                    // 检出后旧码仅记档零兜底 = 本修复点）。
                    let board_replaced = matches!(
                        verdict,
                        ReadbackVerdict::Mismatch { got, .. } if got > 0
                    );
                    match readback_fallback_decision(seq_attempt, board_replaced) {
                        ReadbackFallback::Retry => {
                            let backoff = readback_fallback_delay_ms(seq_attempt);
                            // 兜底动作行（可观测；MISMATCH/UNREADABLE 两形态
                            // 措辞各自保留——用户复测判读用）。
                            match verdict {
                                ReadbackVerdict::Mismatch { expected, got } => tracing::warn!(
                                    seq_attempt + 1,
                                    CLIP_SEQ_RETRY_LIMIT,
                                ),
                                ReadbackVerdict::Unreadable => tracing::warn!(
                                    seq_attempt + 1,
                                    CLIP_SEQ_RETRY_LIMIT,
                                ),
                                ReadbackVerdict::Verified(_) => unreachable!("non-Verified arm"),
                            }
                            std::thread::sleep(std::time::Duration::from_millis(
                                backoff as u64,
                            ));
                            // 下一轮 = 重 Open → 重 Empty → 新 HGLOBAL → 重 Set（真实落板）。
                            continue;
                        }
                        ReadbackFallback::GiveUpReplaced => {
                            // 第三方已换板（got>0 非本次内容）→ 零覆盖。
                            let (expected, got) = match verdict {
                                ReadbackVerdict::Mismatch { expected, got } => (expected, got),
                                _ => unreachable!("replaced arm requires Mismatch"),
                            };
                            tracing::error!(
                            );
                            return false;
                        }
                        ReadbackFallback::GiveUpExhausted => {
                            // 板态 = 本轮 Set 内容（尽力留在板上——读回盲≠内容
                            // 丢失，消费者粘贴行为为准，模块 doc ③⑤ 记档）；
                            // 无回滚 = 刚写条目即用户落板意图（文件已落盘）。
                            match verdict {
                                ReadbackVerdict::Mismatch { expected, got } => tracing::error!(
                                    CLIP_SEQ_RETRY_LIMIT + 1,
                                ),
                                ReadbackVerdict::Unreadable => tracing::error!(
                                    CLIP_SEQ_RETRY_LIMIT + 1,
                                ),
                                ReadbackVerdict::Verified(_) => unreachable!("non-Verified arm"),
                            }
                            return false;
                        }
                    }
                }
            }
        }
        // 循环有界：每轮或 `continue`（非末轮）或 `return`（末轮 GiveUp），
        // 末轮不可能走到此处。
        unreachable!("write_cf_hdrop retry loop is bounded (last round always returns)")
    }
}

/// 板此刻**仍打开**（调用方随后自行 Close）。
#[cfg(windows)]
unsafe fn restore_after_clear(old_hdrop: &OldHdrop) -> (bool, String) {
    match old_hdrop {
        OldHdrop::NoFiles => (
            true,
            "no prior CF_HDROP on board (text/other formats gone until next copy)".to_string(),
        ),
        OldHdrop::Paths(p) => {
            if rollback_set_hdrop(p) {
                (true, "prior CF_HDROP content restored".to_string())
            } else {
                (
                    false,
                    "RESTORE FAILED — prior CF_HDROP content LOST".to_string(),
                )
            }
        }
        OldHdrop::Unknown => (
            false,
            "prior board unreadable — prior content state unknown".to_string(),
        ),
    }
}

/// `hard_loss` = 板空+文件未上（且旧内容不可复原）→ **ERROR** 如实暴露；
/// 否则 WARN。
#[cfg(windows)]
fn log_final_write_failure(
    step: &str,
    err: u32,
    file_count: usize,
    hard_loss: bool,
    restore_note: &str,
) {
    let rounds = CLIP_SEQ_RETRY_LIMIT + 1;
    if hard_loss {
        tracing::error!(
            file_count
        );
    } else {
        tracing::warn!(
        );
    }
}

#[cfg(not(windows))]
pub fn write_cf_hdrop(paths: &[std::path::PathBuf]) -> bool {
    let _ = paths;
    false
}

//
// 用户 09-23 第 5/8 项：远控桌面窗复制粘贴文件应感知用户当前焦点目录。
// 本探测 = **纯读**（GetForegroundWindow/EnumWindows/IShellWindows 只读
// COM 接口；**零焦点窃取**、**零剪贴板板触碰**〔不 Open/不 Empty/不读
// 板格式〕、**零 wire**）；候选窗 = 前台窗为 Explorer（CabinetWClass/
// ExploreWClass）取其目录，否则 Z 序最前可见 Explorer 窗取其目录。
// **有界**：COM/窗口枚举在独立 std 线程内执行，调用方
// [`R135_1_FOCUS_PROBE_BOUND_MS`] 上限 `recv_timeout`——超时/无 Explorer
// 窗/`Location` 不可解析/非目录 = `None`（调用方 fail-closed 回退既有
// `download_dir` 口径）。**遗留边界（诚实记档）**：Explorer 进程自身
// 楔死（COM 调用永不返回）时超时线程不可回收 = 至多泄漏一个空转线程
// （有界探测语义优先于可回收性；生产触发概率 ≈ 0，记档）。

/// 在此上限内必有返回；超时 = `None`（fail-closed）。
pub const R135_1_FOCUS_PROBE_BOUND_MS: u64 = 1000;

#[cfg(windows)]
mod focused_explorer_ffi {
    use std::ffi::c_void;

    /// COM GUID（16B 布局钉单测；与 `ole_hdrop::Guid` 同布局，模块内独立
    /// 定义避免跨私有模块引用）。
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Guid(
        pub u32,
        pub u16,
        pub u16,
        pub [u8; 8],
    );

    /// `CLSID_ShellWindows`（{9BA05972-F6A8-11CF-A442-00A089C1A748}）。
    pub const CLSID_SHELL_WINDOWS: Guid = Guid(
        0x9BA05972,
        0xF6A8,
        0x11CF,
        [0xA4, 0x42, 0x00, 0xA0, 0x89, 0xC1, 0xA7, 0x48],
    );
    /// `IID_IShellWindows`（{85CB6900-4D95-11CF-9504-08002B104B60}）。
    pub const IID_ISHELL_WINDOWS: Guid = Guid(
        0x85CB6900,
        0x4D95,
        0x11CF,
        [0x95, 0x04, 0x08, 0x00, 0x2B, 0x10, 0x4B, 0x60],
    );
    /// `IID_IUnknown`（{00000000-0000-0000-C000-000000000046}）。
    pub const IID_IUNKNOWN: Guid = Guid(0x0000_0000, 0x0000, 0x0000, [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]);

    /// VARIANT（x64 = 16B 布局钉单测）。
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Variant {
        pub vt: u16,
        pub _w: [u16; 3],
        pub u: u64,
    }

    /// DISPPARAMS（x64 = 24B 布局钉单测）。
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Dispparams {
        pub c_args: u32,
        pub _pad: u32,
        pub rg_varargs: *mut c_void,
        pub rg_dispids: *mut c_void,
    }

    pub const S_OK: i32 = 0;
    pub const VT_BSTR: u16 = 8;
    pub const DISPATCH_PROPERTYGET: u16 = 4;
    pub const CLSCTX_ALL: u32 = 0x7;

    /// IShellWindows vtable（objidl 序；仅用 `release`/`find_window_si`，
    /// 余位占位）。
    #[repr(C)]
    pub struct ShellVtbl {
        pub _qinterface: unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32,
        pub _addref: unsafe extern "system" fn(*mut c_void) -> u32,
        pub release: unsafe extern "system" fn(*mut c_void) -> u32,
        pub _item: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut *mut c_void) -> i32,
        pub _count: unsafe extern "system" fn(*mut c_void, *mut i32) -> i32,
        pub _new_enum: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32,
        pub find_window_si:
            unsafe extern "system" fn(*mut c_void, *mut c_void, u32, *mut *mut c_void) -> i32,
        pub _item_from_handle:
            unsafe extern "system" fn(*mut c_void, *mut c_void, u32, *mut *mut c_void) -> i32,
        pub _on_created: unsafe extern "system" fn(*mut c_void, *mut c_void, u32) -> i32,
    }

    /// IDispatch vtable（oleauto 序；仅用 `release`/`get_ids_of_names`/
    /// `invoke`，余位占位）。
    #[repr(C)]
    pub struct DispatchVtbl {
        pub _qinterface: unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32,
        pub _addref: unsafe extern "system" fn(*mut c_void) -> u32,
        pub release: unsafe extern "system" fn(*mut c_void) -> u32,
        pub _get_type_info_count: unsafe extern "system" fn(*mut c_void, *mut u32) -> i32,
        pub _get_type_info: unsafe extern "system" fn(*mut c_void, u32, u32, *mut *mut c_void) -> i32,
        pub get_ids_of_names:
            unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut u16, u32, i32, *mut i32) -> i32,
        pub invoke: unsafe extern "system" fn(
            *mut c_void,
            i32,
            *const Guid,
            i32,
            u16,
            *mut Dispparams,
            *mut Variant,
            *mut c_void,
            *mut i32,
        ) -> i32,
    }

    #[link(name = "user32")]
    extern "system" {
        pub fn GetForegroundWindow() -> *mut c_void;
        pub fn GetClassNameW(hwnd: *mut c_void, buf: *mut u16, max_len: i32) -> i32;
        pub fn EnumWindows(
            cb: extern "system" fn(*mut c_void, *mut c_void) -> i32,
            lparam: *mut c_void,
        ) -> i32;
        pub fn IsWindowVisible(hwnd: *mut c_void) -> i32;
        pub fn GetWindowThreadProcessId(hwnd: *mut c_void, lpdw_pid: *mut u32) -> u32;
    }

    #[link(name = "ole32")]
    extern "system" {
        pub fn CoCreateInstance(
            rclsid: *const Guid,
            pv_outer: *mut c_void,
            dw_cls_ctx: u32,
            riid: *const Guid,
            ppv: *mut *mut c_void,
        ) -> i32;
    }

    #[link(name = "oleaut32")]
    extern "system" {
        pub fn SysFreeString(bstr: *mut u16);
    }
}

#[cfg(windows)]
use focused_explorer_ffi as fx;

#[cfg(windows)]
fn bstr_to_string(b: *const u16) -> String {
    if b.is_null() {
        return String::new();
    }
    let byte_len = unsafe { *b.sub(2) } as usize; // 4 字节长度前缀
    let n = byte_len / 2;
    if n == 0 {
        return String::new();
    }
    unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(b, n)) }
}

#[cfg(windows)]
unsafe fn is_explorer_window(hwnd: *mut std::ffi::c_void) -> bool {
    if fx::IsWindowVisible(hwnd) == 0 {
        return false;
    }
    let mut buf = [0u16; 64];
    let n = fx::GetClassNameW(hwnd, buf.as_mut_ptr(), buf.len() as i32);
    if n <= 0 {
        return false;
    }
    let cls = String::from_utf16_lossy(&buf[..n as usize]);
    cls == "CabinetWClass" || cls == "ExploreWClass"
}

/// **安全前提**：`hwnd` = 系统枚举句柄（回调期内有效）；`lparam` = 调用方
/// 自有 `&mut`（与 `EnumWindows` 调用同生命周期）。
#[cfg(windows)]
extern "system" fn enum_explorer_cb(hwnd: *mut std::ffi::c_void, lparam: *mut std::ffi::c_void) -> i32 {
    unsafe {
        if is_explorer_window(hwnd) {
            *(lparam as *mut *mut std::ffi::c_void) = hwnd;
            0
        } else {
            1
        }
    }
}

/// 可见 Explorer 窗；无 = None。返回 (hwnd, pid)。
#[cfg(windows)]
unsafe fn pick_explorer_window() -> Option<(*mut std::ffi::c_void, u32)> {
    let fg = fx::GetForegroundWindow();
    if !fg.is_null() && is_explorer_window(fg) {
        let mut pid: u32 = 0;
        let _ = fx::GetWindowThreadProcessId(fg, &mut pid);
        return Some((fg, pid));
    }
    let mut found: *mut std::ffi::c_void = std::ptr::null_mut();
    fx::EnumWindows(
        enum_explorer_cb,
        &mut found as *mut _ as *mut std::ffi::c_void,
    );
    if found.is_null() {
        None
    } else {
        let mut pid: u32 = 0;
        let _ = fx::GetWindowThreadProcessId(found, &mut pid);
        Some((found, pid))
    }
}

/// （IDispatch `DISPATCH_PROPERTYGET`）→ BSTR 路径串。
/// **纯读**：不切焦点、不切页、不触碰剪贴板。
///
/// `CLSID_ShellWindows` 在 24H2 未注册（`CoCreateInstance` =
/// REGDB_E_CLASSNOTREG，CLR 侧 `Activator.CreateInstance` 同败，HKCR CLSID
/// 缺失）→ 本函数在 24H2 恒早退 `None`（fail-closed 回退 download_dir）。
/// 同期排死的路：① 框窗全树（609 节点递归枚举）无任何 `Edit`/`ComboBox`
/// —— 地址栏整体在 `Microsoft.UI.Content.DesktopChildSiteBridge`（WinUI 3
/// 子站点，Win32 API 不可见）→ `WM_GETTEXT` 不可行；② UIA（`CLSID_CUIAutomation`
/// 可用）`FindAll` 可读面包屑显示名（`FileExplorerExtensions.Breadcrumb-
/// BarItemControl`），但 30000..=30080 属性全扫 + Value/Text 模式均无真实
/// 全路径（显示名为本地化壳名，如「用户」≠ 真实 `Users`）；③ `shell32`
/// 导出在位，桌面 `IShellFolder::ParseDisplayName`（vtable 槽 3，windows-rs
/// 元数据序）不识本地化显示名（`C:\用户\yu` → FILE_NOT_FOUND）且返回 PIDL
/// 无法经 `SHGetPathFromIDListW` 转换（E_UNEXPECTED）→ 24H2 焦点文件夹
/// 解析被 OS 级 shell 重构整体阻断。Win10（IShellWindows 在注册）= 本路径
/// 生效（vtable 二次间接 2026-09-23 修复后正确）。
#[cfg(windows)]
unsafe fn shell_windows_location(hwnd: *mut std::ffi::c_void, pid: u32) -> Option<String> {
    let mut sw: *mut std::ffi::c_void = std::ptr::null_mut();
    let hr = fx::CoCreateInstance(
        &fx::CLSID_SHELL_WINDOWS,
        std::ptr::null_mut(),
        fx::CLSCTX_ALL,
        &fx::IID_ISHELL_WINDOWS,
        &mut sw,
    );
    if hr != fx::S_OK || sw.is_null() {
        return None;
    }
    // COM 对象首字段 = vtable 指针：对象 ≠ vtable，须二次间接
    // （obj → *obj 读 vtable 指针 → &*vtable 指针）。单间接会把
    // 对象内存（vtable 指针 + refcount…）误读为 vtable 本体 →
    // 「调用」refcount 数值 = 必崩（24H2 真机 UIA 探针同模式实证）。
    let sw_vt_ptr: *const fx::ShellVtbl = *(sw as *const *const fx::ShellVtbl);
    let sw_vt: &fx::ShellVtbl = &*sw_vt_ptr;
    let mut disp: *mut std::ffi::c_void = std::ptr::null_mut();
    let hr = (sw_vt.find_window_si)(sw, hwnd, pid, &mut disp);
    if hr != fx::S_OK || disp.is_null() {
        (sw_vt.release)(sw);
        return None;
    }
    let disp_vt_ptr: *const fx::DispatchVtbl = *(disp as *const *const fx::DispatchVtbl);
    let disp_vt: &fx::DispatchVtbl = &*disp_vt_ptr;
    let wide: Vec<u16> = "Location".encode_utf16().chain(std::iter::once(0u16)).collect();
    let mut name_ptr: *mut u16 = wide.as_ptr() as *mut u16;
    let mut dispid: i32 = 0;
    let hr = (disp_vt.get_ids_of_names)(
        disp,
        &fx::IID_IUNKNOWN,
        &mut name_ptr,
        1,
        0,
        &mut dispid,
    );
    let location = if hr == fx::S_OK {
        let mut dispparams = fx::Dispparams {
            c_args: 0,
            _pad: 0,
            rg_varargs: std::ptr::null_mut(),
            rg_dispids: std::ptr::null_mut(),
        };
        let mut variant = fx::Variant { vt: 0, _w: [0; 3], u: 0 };
        let hr = (disp_vt.invoke)(
            disp,
            dispid,
            &fx::IID_IUNKNOWN,
            0,
            fx::DISPATCH_PROPERTYGET,
            &mut dispparams,
            &mut variant,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        if hr == fx::S_OK && variant.vt == fx::VT_BSTR {
            let bstr = variant.u as *const u16;
            let s = bstr_to_string(bstr);
            fx::SysFreeString(bstr as *mut u16);
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        } else {
            None
        }
    } else {
        None
    };
    (disp_vt.release)(disp);
    (sw_vt.release)(sw);
    location
}

/// 前置，返回值仅日志用途不判路径——`co_init_ole` doc 同口径）。
#[cfg(windows)]
unsafe fn focused_explorer_probe_inner() -> Option<std::path::PathBuf> {
    co_init_ole();
    let (hwnd, pid) = pick_explorer_window()?;
    let location = shell_windows_location(hwnd, pid)?;
    let path = std::path::PathBuf::from(location);
    // 绝对路径 + 现存目录（调用方另有可写性探测——双保险，不互替）。
    if path.is_absolute() && path.is_dir() {
        Some(path)
    } else {
        None
    }
}

/// fail-closed**）：
/// - Windows：候选窗见 [`pick_explorer_window`] doc；COM 序列见
///   [`shell_windows_location`] doc；返回绝对目录路径。
/// - 非 Windows：结构性无 Explorer → 恒 `None`（调用方回退既有口径）。
/// 返回 `None` 的情形 = 无可见 Explorer 窗 / `Location` 不可得（非文件
/// 系统位置如「此电脑」/ 回收站等虚拟位置亦返回非目录被过滤）/ 非绝对
/// 路径 / 非目录 / 探测超时（[`R135_1_FOCUS_PROBE_BOUND_MS`]ms）。
pub fn probe_focused_explorer_dir() -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        let (tx, rx) = std::sync::mpsc::channel();
        if std::thread::Builder::new()
            .name("kirin-r135-focus-probe".into())
            .spawn(move || {
                let _ = tx.send(unsafe { focused_explorer_probe_inner() });
            })
            .is_err()
        {
            return None; // 线程创建失败 = fail-closed
        }
        match rx.recv_timeout(std::time::Duration::from_millis(
            R135_1_FOCUS_PROBE_BOUND_MS,
        )) {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(
                    R135_1_FOCUS_PROBE_BOUND_MS
                );
                None
            }
        }
    }
    #[cfg(not(windows))]
    {
        None
    }
}


#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// ① 重试策略纯函数：退避序列恒 10~20ms + 重试上限口径 +
    /// 「首次失败→逐轮重试→末轮最终失败判定」决策序列。
    #[test]
    fn r116_retry_strategy_backoff_and_final_failure() {
        // 退避序列：重试 #1..=5 = 10,12,14,16,18ms；#6 起 20ms 封顶。
        assert_eq!(open_retry_delay_ms(1), 10);
        assert_eq!(open_retry_delay_ms(2), 12);
        assert_eq!(open_retry_delay_ms(3), 14);
        assert_eq!(open_retry_delay_ms(4), 16);
        assert_eq!(open_retry_delay_ms(5), 18);
        assert_eq!(open_retry_delay_ms(6), 20);
        assert_eq!(open_retry_delay_ms(999), 20);
        for n in 1..=64u32 {
            let d = open_retry_delay_ms(n);
            assert!((10..=20).contains(&d), "backoff {d}ms out of 10..=20 (retry #{n})");
        }
        // 上限口径：Open 重试 ≥5 次（不计首次）+ 整序列重试 ≥2 轮。
        assert!(CLIP_OPEN_RETRY_LIMIT >= 5);
        assert!(CLIP_SEQ_RETRY_LIMIT >= 2);
        // 「首次失败→重试」：轮 0..=CLIP_SEQ_RETRY_LIMIT-1 一律 Retry。
        for attempt in 0..CLIP_SEQ_RETRY_LIMIT {
            assert_eq!(
                seq_retry_decision(attempt, FailStep::Open, true),
                SeqAction::Retry,
                "round {attempt} must retry"
            );
        }
        // 最终失败判定：末轮（0 起计 = CLIP_SEQ_RETRY_LIMIT）= GiveUp。
        let last = CLIP_SEQ_RETRY_LIMIT;
        assert_eq!(
            seq_retry_decision(last, FailStep::Open, true),
            SeqAction::GiveUp { hard_loss: false }
        );
        // 全失败流决策序列 = 前 N 轮 Retry + 末轮 GiveUp（重试次数恰 = N）。
        let mut retries = 0u32;
        for attempt in 0..=CLIP_SEQ_RETRY_LIMIT {
            if matches!(
                seq_retry_decision(attempt, FailStep::Open, true),
                SeqAction::Retry
            ) {
                retries += 1;
            }
        }
        assert_eq!(retries, CLIP_SEQ_RETRY_LIMIT);
    }

    /// ② 回滚判定：Set/Alloc 失败（板已清空）——有旧内容且回滚成功→WARN 臂；
    /// 无旧内容/回滚失败→ERROR 臂（hard_loss）；Open/Empty 失败=板未动→
    /// 永非 hard loss；非末轮=先试回滚后整序列重试。
    #[test]
    fn r116_rollback_decision_arms() {
        let last = CLIP_SEQ_RETRY_LIMIT;
        // Set 失败 + 回滚成功（板复原为旧内容）→ 终止但非硬损（WARN 臂）。
        assert_eq!(
            seq_retry_decision(last, FailStep::Set, true),
            SeqAction::GiveUp { hard_loss: false }
        );
        // Set 失败 + 无旧内容/旧板读不到/回滚失败 → hard_loss（ERROR 臂，
        // 板空+文件未上=最坏情形如实暴露）。
        assert_eq!(
            seq_retry_decision(last, FailStep::Set, false),
            SeqAction::GiveUp { hard_loss: true }
        );
        // Alloc 失败同属「已 Empty」步 → 同臂判定。
        assert_eq!(
            seq_retry_decision(last, FailStep::Alloc, true),
            SeqAction::GiveUp { hard_loss: false }
        );
        assert_eq!(
            seq_retry_decision(last, FailStep::Alloc, false),
            SeqAction::GiveUp { hard_loss: true }
        );
        // Open/Empty 失败 = 板未清空 → board_recovered 传入值不影响 hard_loss。
        assert_eq!(
            seq_retry_decision(last, FailStep::Open, false),
            SeqAction::GiveUp { hard_loss: false }
        );
        assert_eq!(
            seq_retry_decision(last, FailStep::Empty, false),
            SeqAction::GiveUp { hard_loss: false }
        );
        // 非末轮：无论回滚成败，先重试整序列（下一轮重 Empty 无副作用）。
        assert_eq!(seq_retry_decision(0, FailStep::Set, false), SeqAction::Retry);
        assert_eq!(seq_retry_decision(0, FailStep::Set, true), SeqAction::Retry);
        assert_eq!(seq_retry_decision(0, FailStep::Alloc, false), SeqAction::Retry);
    }

    /// ③ gate 串行语义：gate 空闲→可锁；他线程持锁→阻塞等待（串行化）；
    /// 持锁者自身再锁=重入=自死锁→纪律禁止（真实 gate 为不可重入 Mutex，
    /// 写面临界区内旧板留底读/回滚走不取锁路径，结构性杜绝重入）。
    #[test]
    fn r116_gate_serial_semantics() {
        // gate 空闲 → 任意请求者可取锁。
        assert_eq!(gate_verdict(None, "write"), GateVerdict::Proceed);
        assert_eq!(gate_verdict(None, "read"), GateVerdict::Proceed);
        // 他线程持锁 → 等待（写面全程持锁期间，读面 tick/粘贴读排队）。
        assert_eq!(gate_verdict(Some("write"), "read"), GateVerdict::Wait);
        assert_eq!(gate_verdict(Some("read"), "write"), GateVerdict::Wait);
        // 同锁不可重入：持锁者再锁 = 自死锁，纯判定必须判禁。
        assert_eq!(gate_verdict(Some("write"), "write"), GateVerdict::ReentryForbidden);
        assert_eq!(gate_verdict(Some("read"), "read"), GateVerdict::ReentryForbidden);
    }

    /// ④ 载荷布局（写/回滚共用序列化）：20B 头字段 + 每条路径 UTF-16+NUL +
    /// 列表末 NUL（双 NUL 终结）+ 总长恰合（防回滚形态漂移）。
    #[test]
    fn r116_hdrop_payload_layout() {
        let paths = vec![
            "C:\\tmp\\a.txt".to_string(),
            "C:\\中文目录\\数据 文件.bin".to_string(),
        ];
        let p = build_hdrop_payload(&paths);
        let n1 = paths[0].chars().count();
        let n2 = paths[1].chars().count();
        // 总长 = 头 20 + 每路径 (字符数+1 NUL)×2B + 列表末 NUL 2B。
        assert_eq!(p.len(), DROPFILES_HEADER_SIZE + (n1 + 1) * 2 + (n2 + 1) * 2 + 2);
        // 头：pt=(0,0) / fnc=FALSE / fWide=TRUE / dwReserved=0。
        assert_eq!(&p[0..4], &0i32.to_ne_bytes());
        assert_eq!(&p[4..8], &0i32.to_ne_bytes());
        assert_eq!(&p[8..12], &0i32.to_ne_bytes());
        assert_eq!(&p[12..16], &1i32.to_ne_bytes());
        assert_eq!(&p[16..20], &0u32.to_ne_bytes());
        // 路径 1：UTF-16LE + NUL 终结。
        let expect1: Vec<u8> = paths[0]
            .encode_utf16()
            .flat_map(|u| u.to_ne_bytes())
            .chain(std::iter::once(0u8).chain(std::iter::once(0u8)))
            .collect();
        assert_eq!(&p[DROPFILES_HEADER_SIZE..DROPFILES_HEADER_SIZE + expect1.len()], &expect1[..]);
        // 路径 2 紧随其后（无间隔）。
        let off2 = DROPFILES_HEADER_SIZE + expect1.len();
        let expect2: Vec<u8> = paths[1]
            .encode_utf16()
            .flat_map(|u| u.to_ne_bytes())
            .collect();
        assert_eq!(&p[off2..off2 + expect2.len()], &expect2[..]);
        // 末 4 字节 = 路径 2 NUL + 列表末 NUL（双 NUL 终结）。
        assert_eq!(&p[p.len() - 4..], &[0u8, 0u8, 0u8, 0u8]);
    }

    /// `C:\a.txt` → 恰 40 字节；头 20B 逐字节（fWide 在偏移 12 = LE `01 00 00 00`，
    /// 余头字节全 0）；pFiles 自偏移 20 起 UTF-16LE 逐字节 + 双 NUL 终结。
    #[test]
    fn r128_hdrop_payload_bytes() {
        let paths = vec!["C:\\a.txt".to_string()];
        let p = build_hdrop_payload(&paths);
        // 总长 = 头 20 + (8 字符 + 1 NUL)×2B + 列表末 NUL 2B = 40。
        assert_eq!(p.len(), 40);
        // 头：pt.x/pt.y/fnc 全 0（偏移 0..12）。
        assert!(p[0..12].iter().all(|&b| b == 0), "header 0..12 must be zero: {p:02x?}");
        // fWide = TRUE（偏移 12..16，小端 int 1）。
        assert_eq!(&p[12..16], &[1u8, 0, 0, 0], "fWide LE: {p:02x?}");
        // dwReserved = 0（偏移 16..20）。
        assert!(p[16..20].iter().all(|&b| b == 0));
        // 路径本体（UTF-16LE 显式码位钉）：C=0x43 ':'=0x3A '\'=0x5C a=0x61
        // '.'=0x2E t=0x74 x=0x78 t=0x74。
        let w: Vec<u16> = "C:\\a.txt".encode_utf16().collect();
        assert_eq!(w, vec![0x0043, 0x003A, 0x005C, 0x0061, 0x002E, 0x0074, 0x0078, 0x0074]);
        let mut body = Vec::with_capacity(20);
        for u in w {
            body.extend_from_slice(&u.to_le_bytes());
        }
        body.extend_from_slice(&[0u8, 0u8, 0u8, 0u8]); // 路径 NUL + 列表末 NUL（双 NUL）
        assert_eq!(&p[20..], &body[..], "pFiles body (LE): {p:02x?}");
    }

    /// 伪重试修复）+ 非降/前段严格增/封顶 + HGLOBAL 所有权命运（成功=系统
    /// 接管不得 free；失败=自释放且绝不跨轮复用）。
    #[test]
    fn r128_seq_backoff_and_hglobal_fate() {
        // 前 11 轮严格递增：30,40,…,130ms（恒 ≥30——任务书口径）。
        assert_eq!(seq_retry_delay_ms(0), 30);
        assert_eq!(seq_retry_delay_ms(1), 40);
        assert_eq!(seq_retry_delay_ms(2), 50);
        for a in 1..=10u32 {
            assert!(
                seq_retry_delay_ms(a) > seq_retry_delay_ms(a - 1),
                "must be strictly increasing at round {a}"
            );
        }
        // 全程 ≥30ms 且封顶 ≤130ms（防未来放宽轮数时退避失控）。
        for a in 0..64u32 {
            let d = seq_retry_delay_ms(a);
            assert!((30..=130).contains(&d), "backoff {d}ms out of 30..=130 (round {a})");
            if a > 0 {
                assert!(d >= seq_retry_delay_ms(a - 1), "must be non-decreasing (round {a})");
            }
        }
        // HGLOBAL 命运：Set 成功 = 剪贴板接管（再 free = double free 堆破坏）；
        // 失败 = 写方释放（本轮句柄生命周期终结，下一轮全新 GlobalAlloc）。
        assert_eq!(hglobal_fate_after_set(true), HGlobalFate::Transferred);
        assert_eq!(hglobal_fate_after_set(false), HGlobalFate::Freed);
    }

    /// 内容/顺序/多条目/少条目/空板任一偏差 = Mismatch（got 精确）；
    /// 无探针结果 = Unreadable（诚实：写被 OS 接受但板面不可证实）。
    #[test]
    fn r128_readback_verdict_matrix() {
        let expected = vec!["C:\\a.txt".to_string(), "C:\\b.bin".to_string()];
        // 探针不可用 = Unreadable。
        assert_eq!(verify_readback(&expected, None), ReadbackVerdict::Unreadable);
        // 全等 = Verified(n)。
        let ok = ProbeResult {
            total: 2,
            paths: expected.clone(),
        };
        assert_eq!(
            verify_readback(&expected, Some(&ok)),
            ReadbackVerdict::Verified(2)
        );
        // 顺序翻转 = Mismatch（顺序敏感=写序）。
        let swapped = ProbeResult {
            total: 2,
            paths: vec![expected[1].clone(), expected[0].clone()],
        };
        assert!(matches!(
            verify_readback(&expected, Some(&swapped)),
            ReadbackVerdict::Mismatch { .. }
        ));
        // 少条目 = Mismatch（got=1）。
        let short = ProbeResult {
            total: 1,
            paths: vec![expected[0].clone()],
        };
        assert_eq!(
            verify_readback(&expected, Some(&short)),
            ReadbackVerdict::Mismatch {
                expected: 2,
                got: 1
            }
        );
        // 多条目 = Mismatch（got=3；前 2 条吻合但总数不符）。
        let extra = ProbeResult {
            total: 3,
            paths: vec![
                expected[0].clone(),
                expected[1].clone(),
                "C:\\c.txt".to_string(),
            ],
        };
        assert_eq!(
            verify_readback(&expected, Some(&extra)),
            ReadbackVerdict::Mismatch {
                expected: 2,
                got: 3
            }
        );
        // 内容漂移 = Mismatch（条数吻合、路径不符）。
        let drift = ProbeResult {
            total: 2,
            paths: vec![expected[0].clone(), "C:\\other.bin".to_string()],
        };
        assert!(matches!(
            verify_readback(&expected, Some(&drift)),
            ReadbackVerdict::Mismatch { .. }
        ));
        // 空板（Set 成功但板空）= Mismatch（got=0）。
        let empty = ProbeResult {
            total: 0,
            paths: Vec::new(),
        };
        assert_eq!(
            verify_readback(&expected, Some(&empty)),
            ReadbackVerdict::Mismatch {
                expected: 2,
                got: 0
            }
        );
    }

    /// 一）/ UNC 专属形态 / 前缀已在幂等 / 相对·非绝对 = None。
    #[test]
    fn r128_long_path_probe_matrix() {
        assert_eq!(
            long_path_probe("C:\\x\\y.txt"),
            Some("\\\\?\\C:\\x\\y.txt".to_string())
        );
        // 正斜杠变体亦认（第 3 字节 `/`）。
        assert_eq!(
            long_path_probe("d:/slash/mix.bin"),
            Some("\\\\?\\d:/slash/mix.bin".to_string())
        );
        // UNC → `\\?\UNC\` 专属形态。
        assert_eq!(
            long_path_probe("\\\\server\\share\\f.bin"),
            Some("\\\\?\\UNC\\server\\share\\f.bin".to_string())
        );
        // 前缀已在 → 原样（幂等）。
        assert_eq!(
            long_path_probe("\\\\?\\C:\\x"),
            Some("\\\\?\\C:\\x".to_string())
        );
        assert_eq!(
            long_path_probe("\\\\?\\UNC\\s\\x"),
            Some("\\\\?\\UNC\\s\\x".to_string())
        );
        // 相对/非绝对 = 无探针形态（DragQueryFileW 产物恒绝对，此臂防御性）。
        assert_eq!(long_path_probe("relative\\a.txt"), None);
        assert_eq!(long_path_probe(""), None);
        assert_eq!(long_path_probe("C:"), None); // 无尾斜杠 = 当前目录相对形态
    }

    ///
    /// **`#[ignore]` 理由记档**（任务书口径：环境不稳允许 ignore）：本机
    /// Win11 24H2（build 22631）实测 `DragQueryFileW` 对**任何**应用自建
    /// 经典布局 HDROP 解析 0 条（同进程/跨进程、头部 6 变体全测，见模块
    /// doc ③）——写侧已实机修复（`SetClipboardData` 成功、err 6 消失、
    /// 存储字节逐位吻合），但本测试的读回断言在 24H2 上必然误败
    /// （探针恒 0 条）。用户复测（Explorer 粘贴）= 定案线；确认用户机
    /// 读面形态后可去 ignore。手动跑：
    /// `cargo test -p kirin-desk-ui r128_real_board_roundtrip -- --ignored`
    ///（**板面破坏性**：Empty 既有格式 + 落临时探针文件；跑毕尽力复原空板）。
    #[test]
    #[ignore = "24H2 (build 22631) DragQueryFileW 对应用自建 HDROP 解析 0 条（实机 6 变体复现）→ 读回断言必误败；写侧修复已另证（exp 记录），用户复测定案"]
    fn r128_real_board_roundtrip() {
        use hdrop_write_ffi::{
            GetLastError, GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
        };
        let probe_file = std::env::temp_dir().join("kirin_r128_roundtrip_probe.bin");
        std::fs::write(&probe_file, b"r128").expect("probe file write failed");
        let paths = vec![probe_file.to_string_lossy().into_owned()];
        let payload = build_hdrop_payload(&paths);
        unsafe {
            assert_ne!(
                OpenClipboard(std::ptr::null_mut()),
                0,
                "OpenClipboard failed: err={}",
                GetLastError()
            );
            assert_ne!(EmptyClipboard(), 0, "EmptyClipboard failed");
            let hmem = GlobalAlloc(GMEM_MOVEABLE, payload.len() as u32);
            assert!(!hmem.is_null(), "GlobalAlloc failed");
            let mem = GlobalLock(hmem);
            assert!(!mem.is_null(), "GlobalLock failed");
            std::slice::from_raw_parts_mut(mem as *mut u8, payload.len())
                .copy_from_slice(&payload);
            GlobalUnlock(hmem);
            let hdrop = SetClipboardData(CF_HDROP, hmem as *mut winapi::ctypes::c_void);
            // **定案断言**：Set 必须成功——旧码（裸句柄写）在本机 100% 以
            // ERROR_INVALID_HANDLE(6) 败；修复后此断言 = err 6 消失的直接证据。
            assert!(
                !hdrop.is_null(),
                "SetClipboardData failed: err={} (err 6 = 根因未修复)",
                GetLastError()
            );
            CloseClipboard();
        }
        // 读回（24H2 读面特性下探针恒 0 条 → 下方断言误败 = ignore 理由）。
        // 判定先行收集、**清理先于 panic**——读回失败路径也必复原空板
        // （板破坏性测试的卫生纪律：不留测试 HDROP 残迹、不留探针文件）。
        let verdict: Result<(), String> = {
            let probe = probe_hdrop_paths(paths.len());
            match verify_readback(&paths, probe.as_ref()) {
                ReadbackVerdict::Verified(n) if n == 1 => Ok(()),
                ReadbackVerdict::Verified(n) => {
                    Err(format!("readback file count mismatch: {n}"))
                }
                ReadbackVerdict::Mismatch { expected, got } => Err(format!(
                    "readback mismatch: expected {expected}, board reports {got} (24H2 quirk?)"
                )),
                ReadbackVerdict::Unreadable => Err("readback unreadable".to_string()),
            }
        };
        unsafe {
            // 清理：板复原为空（测试不留文件条目；既有其他格式本已被 Empty 清）。
            if OpenClipboard(std::ptr::null_mut()) != 0 {
                let _ = EmptyClipboard();
                CloseClipboard();
            }
        }
        let _ = std::fs::remove_file(&probe_file);
        if let Err(e) = verdict {
            panic!("{e}");
        }
    }

    /// GiveUpReplaced（零覆盖，任何轮次不重设）。全失败流决策序列 = 前 N
    /// 轮 Retry + 末轮 GiveUp（兜底次数恰 = N，**有界防死循环**）；兜底退避
    /// = 200ms 口径（长于同轮 30ms 争用退避——24H2 异步归一化窗口）+ 单调
    /// 不减 + 封顶 1000ms。
    #[test]
    fn r132_3_readback_fallback_decision_and_backoff() {
        // 非末轮：一律 Retry（重设序号 1..=CLIP_SEQ_RETRY_LIMIT）。
        for attempt in 0..CLIP_SEQ_RETRY_LIMIT {
            assert_eq!(
                readback_fallback_decision(attempt, false),
                ReadbackFallback::Retry,
                "round {attempt} must retry"
            );
        }
        assert_eq!(
            readback_fallback_decision(CLIP_SEQ_RETRY_LIMIT, false),
            ReadbackFallback::GiveUpExhausted
        );
        // 全失败流决策序列 = 前 N 轮 Retry + 末轮 GiveUp（兜底次数恰 = N）。
        let mut retries = 0u32;
        for attempt in 0..=CLIP_SEQ_RETRY_LIMIT {
            if readback_fallback_decision(attempt, false) == ReadbackFallback::Retry {
                retries += 1;
            }
        }
        assert_eq!(retries, CLIP_SEQ_RETRY_LIMIT, "bounded: no infinite loop");
        // 第三方换板（board_replaced）= 任何轮次恒 GiveUpReplaced（零覆盖）。
        for attempt in 0..=CLIP_SEQ_RETRY_LIMIT {
            assert_eq!(
                readback_fallback_decision(attempt, true),
                ReadbackFallback::GiveUpReplaced,
                "replaced board must never be re-set (round {attempt})"
            );
        }
        // 兜底退避：重设 #1 = 200ms、#2 = 400ms（钉死）；恒 200..=1000 单调
        // 不减（封顶防未来放宽轮数时退避失控）；恒**长于**同轮争用退避
        // （24H2 读侧 quirk ≠ 争用，短间隔重设撞同一坏态 = 伪重试）。
        assert_eq!(readback_fallback_delay_ms(0), 200);
        assert_eq!(readback_fallback_delay_ms(1), 400);
        for a in 0..64u32 {
            let d = readback_fallback_delay_ms(a);
            assert!((200..=1000).contains(&d), "backoff {d}ms out of 200..=1000 (round {a})");
            if a > 0 {
                assert!(d >= readback_fallback_delay_ms(a - 1), "non-decreasing (round {a})");
            }
            assert!(
                d > seq_retry_delay_ms(a.min(CLIP_SEQ_RETRY_LIMIT)),
                "readback fallback backoff must exceed same-round contention backoff (round {a})"
            );
        }
    }

    /// `r128_real_board_roundtrip` 口径）。
    ///
    /// 用途：本机（Win11 22631 = 24H2 同系）经**生产** [`write_cf_hdrop`]
    /// 复现 179 log:93 MISMATCH 场景，取三方读回证据（生产返回值 /
    ///
    /// 跑前清 `target/debug/deps/*.exe`。手动跑：
    /// `cargo test -p kirin-desk-ui r132_3_real_board_fallback_probe -- --ignored --nocapture`
    /// （Empty 既有格式 + 落临时探针文件；跑毕尽力复原快照——CF_HDROP 路径
    /// 集 + CF_UNICODETEXT，单次 Open 双 Set 复原）。
    ///
    /// env `R132_3_SKIP_RESTORE=1` = 跑毕**留板**（探针 HDROP 留在板上，供
    /// 外部 OLE 侧检查：`powershell -NoProfile -Command "Get-Clipboard -Format
    /// FileDrop"` = Explorer 粘贴同路径），随后不带 env 重跑一次复原板。
    #[test]
    #[ignore = "板破坏性探针（Empty 板 + 落临时探针文件）；手动跑"]
    fn r132_3_real_board_fallback_probe() {
        use hdrop_write_ffi::{
            GlobalAlloc, GlobalFree, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
        };
        // 0. tracing 行可见（生产兜底动作行证据；探针单跑 = 无其他测试争用）。
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .try_init();
        // 1. 快照（只读）：既有 CF_HDROP 路径集 + 文本（复原素材）。
        let old_files: Vec<String> = read_cf_hdrop()
            .map(|b| b.entries.iter().map(|e| e.abs_path.clone()).collect())
            .unwrap_or_default();
        let old_text: Option<String> = arboard::Clipboard::new()
            .ok()
            .and_then(|mut c| c.get_text().ok())
            .filter(|t| !t.is_empty());
        eprintln!(
            "[R132-3 PROBE] board snapshot: files={:?} text_len={:?}",
            old_files,
            old_text.as_ref().map(String::len)
        );
        // 2. 临时探针文件。
        let probe_file = std::env::temp_dir().join("kirin_r132_3_probe.bin");
        std::fs::write(&probe_file, b"r132-3-probe").expect("probe file write failed");
        let probe_path = probe_file.to_string_lossy().into_owned();
        //    1+CLIP_SEQ_RETRY_LIMIT 轮有界）——生产日志行（INFO/WARN/ERROR）
        //    直接落 stderr（--nocapture）。
        let ok = write_cf_hdrop(std::slice::from_ref(&probe_file));
        // 4. 独立回读证据（生产返回值 + 探针交叉复核）。
        let probe = probe_hdrop_paths(1);
        let verdict = verify_readback(&[probe_path.clone()], probe.as_ref());
        eprintln!("[R132-3 PROBE] write_cf_hdrop -> {ok}");
        eprintln!(
            "[R132-3 PROBE] independent readback: total={:?} paths={:?}",
            probe.as_ref().map(|p| p.total),
            probe.as_ref().map(|p| &p.paths)
        );
        eprintln!("[R132-3 PROBE] verdict = {verdict:?}");
        // 5. HOLD（外部 OLE 检查）或复原。
        if std::env::var_os("R132_3_SKIP_RESTORE").is_some() {
            eprintln!(
                "[R132-3 PROBE] HOLD: board left as-is (probe file {probe_path} on board) — run `powershell -NoProfile -Command \"Get-Clipboard -Format FileDrop\"` now, then rerun without R132_3_SKIP_RESTORE to restore"
            );
            return; // 留板 + 留探针文件（FileDrop 检查需要路径在位）。
        }
        // 复原（单次 Open：重 Set 旧 CF_HDROP + 重 Set 旧文本——双格式共存；
        // 先 Empty 抹本探针残迹）。
        unsafe {
            if OpenClipboard(std::ptr::null_mut()) != 0 {
                let _ = EmptyClipboard();
                if !old_files.is_empty() {
                    let restored = rollback_set_hdrop(&old_files);
                    eprintln!(
                        "[R132-3 PROBE] restore CF_HDROP({} paths) -> {restored}",
                        old_files.len()
                    );
                }
                if let Some(t) = &old_text {
                    let w: Vec<u16> = t
                        .encode_utf16()
                        .chain(std::iter::once(0u16))
                        .collect();
                    let hmem = GlobalAlloc(GMEM_MOVEABLE, (w.len() * 2) as u32);
                    if hmem.is_null() {
                        eprintln!("[R132-3 PROBE] restore text: GlobalAlloc failed");
                    } else {
                        let mem = GlobalLock(hmem);
                        if mem.is_null() {
                            let _ = GlobalFree(hmem);
                            eprintln!("[R132-3 PROBE] restore text: GlobalLock failed");
                        } else {
                            std::slice::from_raw_parts_mut(mem as *mut u16, w.len())
                                .copy_from_slice(&w);
                            GlobalUnlock(hmem);
                            let htext = SetClipboardData(
                                CF_UNICODETEXT,
                                hmem as *mut winapi::ctypes::c_void,
                            );
                            if htext.is_null() {
                                let _ = GlobalFree(hmem); // 失败 = 所有权未转移。
                            }
                            eprintln!(
                                "[R132-3 PROBE] restore CF_UNICODETEXT -> {}",
                                !htext.is_null()
                            );
                        }
                    }
                }
                CloseClipboard();
            } else {
                eprintln!("[R132-3 PROBE] restore: OpenClipboard failed (board left as probe left it)");
            }
        }
        let _ = std::fs::remove_file(&probe_file);
        eprintln!("[R132-3 PROBE] done (board restored, probe file removed)");
    }

    /// （24H2 = CANTCONVERT 确定性形态 / 其他 HRESULT 任意）非末次 = Retry；
    /// 末次耗尽（attempt = limit-1）= Degrade（降级经典臂，fail-closed）；
    /// 预算口径 = 10×100ms（.NET `ClipboardCore.SetData` 同口径记档）+
    /// OLE 臂与经典臂共享轮预算（全调用 OLE ≤30 次 / 经典 Set ≤3，有界
    #[test]
    fn r132_3b_ole_set_action_and_retry_budget() {
        // S_OK = Accepted（首调成功 / 后续轮次成功同臂）。
        assert_eq!(
            ole_set_action(ole_write_ffi::HRESULT_S_OK, 0),
            OleSetAction::Accepted
        );
        assert_eq!(
            ole_set_action(ole_write_ffi::HRESULT_S_OK, OLE_SET_RETRY_LIMIT - 1),
            OleSetAction::Accepted
        );
        // 24H2 门控形态（CANTCONVERT）+ 任意失败 hr：非末次 → Retry。
        for attempt in 0..(OLE_SET_RETRY_LIMIT - 1) {
            assert_eq!(
                ole_set_action(ole_write_ffi::OLEOBJ_E_CANTCONVERT, attempt),
                OleSetAction::Retry,
                "round {attempt} must retry"
            );
            assert_eq!(
                ole_set_action(-1, attempt),
                OleSetAction::Retry,
                "round {attempt} must retry (arbitrary failure hr)"
            );
        }
        // 末次耗尽 → Degrade（经典臂接管；未读回验证不得宣称成功）。
        assert_eq!(
            ole_set_action(ole_write_ffi::OLEOBJ_E_CANTCONVERT, OLE_SET_RETRY_LIMIT - 1),
            OleSetAction::Degrade
        );
        assert_eq!(
            ole_set_action(-1, OLE_SET_RETRY_LIMIT - 1),
            OleSetAction::Degrade
        );
        // 预算口径钉死：10 次 × 100ms（.NET 同口径记档）。
        assert_eq!(OLE_SET_RETRY_LIMIT, 10);
        assert_eq!(OLE_SET_RETRY_DELAY_MS, 100);
        // 与经典臂轮预算交叉：OLE 单轮 ≤10 次 × 总轮数 3 = 全调用 OLE ≤30
        // 次；经典 `SetClipboardData` ≤3 次——全有界（共享
        assert!(CLIP_SEQ_RETRY_LIMIT >= 2);
        assert!(OLE_SET_RETRY_LIMIT * (CLIP_SEQ_RETRY_LIMIT + 1) <= 30);
    }

    /// 字节（读回判定依赖载荷全等：OLE `GetData` 产物与经典 `Set` 产物
    #[test]
    fn r132_3b_ole_payload_identity() {
        let paths = vec!["C:\\a.txt".to_string()];
        let payload = build_hdrop_payload(&paths);
        let obj = ole_hdrop::Obj::new(payload.clone());
        let got = unsafe { ole_hdrop::Obj::payload_snapshot(obj) };
        assert_eq!(
            got, payload,
            "OLE object payload must be repo-identical to the classic arm"
        );
        unsafe { ole_hdrop::Obj::drop_initial_ref(obj) }; // 初引用释放（rc→0 自释）
    }

    /// ——布局漂移 = OLE 层误读内存（OLE 接受的结构前提；取证期 5 方法
    /// vtable / 16B FORMATETC 错误形态教训记档，模块 doc ⑥）。
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn r132_3b_com_layout_nail() {
        assert_eq!(std::mem::size_of::<ole_hdrop::Formatetc>(), 24);
        assert_eq!(std::mem::size_of::<ole_hdrop::Stgmedium>(), 16);
    }

    //
    // 记录_2026-09-19.md）：
    //   a = 专用 STA 线程 + CoInitializeEx(ATA) + 该线程消息泵 + OleSetClipboard
    //       （收尾含/不含 OleFlushClipboard 两式）——检验 3B 是否缺 OLE STA 前提
    //       （3B 取证/生产路径的调用线程**不泵消息**，本变体 = 差量）；
    //   b = 经典 `SetClipboardData(hwnd, CF_HDROP, NULL)` 延迟渲染（
    //       WM_RENDERFORMAT/WM_RENDERALLFORMATS 按需供 HGLOBAL）——检验 24H2
    //       读侧 quirk（「Set 成功而读回恒 0」）是否只杀立即渲染；
    //       立即 OleSetClipboard → 拒 → 降级经典立即 Set）——对照锚，确认 3B
    //       证据链可独立复现。
    // 统一纪律：同一测试文件列表（单探针文件 `kirin_r132_3b_v_probe.bin`）/
    // DragQueryFileW 可读计数 ×3（100ms 间隔）/ Explorer 同路径对照 =
    // Explorer 粘贴同路径）/ env `R132_3B_V_HOLD=1` = 留板 + 等 sentinel
    // （供外部对照），对照毕无 HOLD 重跑复原板。板破坏性（Empty + 落临时
    // 探针文件）→ `#[ignore]` 手动跑（同 `r132_3_real_board_fallback_probe`
    // 口径）。手动跑（§0-②：跑前清 `target/debug/deps/*.exe`、新隔离目录 +
    // `KIRIN_NOHW_HW_DECODE=1`）：
    //   cargo test -p kirin-desk-ui r132_3b_v_variant_c_baseline_probe -- --ignored --nocapture
    //   R132_3B_V_HOLD=1 cargo test -p kirin-desk-ui r132_3b_v_variant_a_sta_thread_probe -- --ignored --nocapture
    //   R132_3B_V_A_FLUSH=1 R132_3B_V_HOLD=1 cargo test -p kirin-desk-ui r132_3b_v_variant_a_sta_thread_probe -- --ignored --nocapture
    //   R132_3B_V_HOLD=1 cargo test -p kirin-desk-ui r132_3b_v_variant_b_deferred_render_probe -- --ignored --nocapture

    /// processthreadsapi/ole32 → 本文件 [`hdrop_write_ffi`]/[`ole_write_ffi`]
    /// 既有 raw extern 同先例，零新依赖；**测试专用，生产代码零改动**）。
    mod v3bv_ffi {
        #[link(name = "kernel32")]
        extern "system" {
            pub fn GetCurrentThreadId() -> u32;
        }
        #[link(name = "ole32")]
        extern "system" {
            pub fn OleFlushClipboard() -> i32;
        }
    }

    struct V3bvSnapshot {
        files: Vec<String>,
        text: Option<String>,
    }

    fn v3bv_snapshot() -> V3bvSnapshot {
        let files = read_cf_hdrop()
            .map(|b| b.entries.iter().map(|e| e.abs_path.clone()).collect())
            .unwrap_or_default();
        let text = arboard::Clipboard::new()
            .ok()
            .and_then(|mut c| c.get_text().ok())
            .filter(|t| !t.is_empty());
        V3bvSnapshot { files, text }
    }

    unsafe fn v3bv_restore(snap: &V3bvSnapshot) {
        use hdrop_write_ffi::{
            GlobalAlloc, GlobalFree, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
        };
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            eprintln!("[V3B-V] restore: OpenClipboard failed (board left as-is)");
            return;
        }
        let _ = EmptyClipboard();
        if !snap.files.is_empty() {
            let ok = rollback_set_hdrop(&snap.files);
            eprintln!("[V3B-V] restore CF_HDROP({} paths) -> {ok}", snap.files.len());
        }
        if let Some(t) = &snap.text {
            let w: Vec<u16> = t
                .encode_utf16()
                .chain(std::iter::once(0u16))
                .collect();
            let hmem = GlobalAlloc(GMEM_MOVEABLE, (w.len() * 2) as u32);
            if hmem.is_null() {
                eprintln!("[V3B-V] restore text: GlobalAlloc failed");
            } else {
                let mem = GlobalLock(hmem);
                if mem.is_null() {
                    let _ = GlobalFree(hmem);
                    eprintln!("[V3B-V] restore text: GlobalLock failed");
                } else {
                    std::slice::from_raw_parts_mut(mem as *mut u16, w.len())
                        .copy_from_slice(&w);
                    GlobalUnlock(hmem);
                    let htext = SetClipboardData(
                        CF_UNICODETEXT,
                        hmem as *mut winapi::ctypes::c_void,
                    );
                    if htext.is_null() {
                        let _ = GlobalFree(hmem); // 失败 = 所有权未转移。
                    }
                    eprintln!("[V3B-V] restore CF_UNICODETEXT -> {}", !htext.is_null());
                }
            }
        }
        CloseClipboard();
    }

    fn v3bv_probe_file() -> std::path::PathBuf {
        let p = std::env::temp_dir().join("kirin_r132_3b_v_probe.bin");
        std::fs::write(&p, b"r132-3b-v-probe").expect("probe file write failed");
        p
    }

    fn v3bv_clear_sentinel() {
        let _ = std::fs::remove_file(std::env::temp_dir().join("kirin_r132_3b_v_sentinel"));
    }

    /// 180s 超时守卫——外部对照缺席也不卡死）。
    fn v3bv_hold(label: &str) {
        let sentinel = std::env::temp_dir().join("kirin_r132_3b_v_sentinel");
        eprintln!(
            "[V3B-V {label}] HOLD: board left as-is — run `powershell -NoProfile -Command \"Get-Clipboard -Format FileDrop\"` ×3 now, then create sentinel {sentinel:?} (or 180s timeout)"
        );
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_secs(180) {
            if sentinel.exists() {
                eprintln!("[V3B-V {label}] sentinel received — teardown");
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        eprintln!("[V3B-V {label}] sentinel timeout (180s) — teardown");
    }

    /// 写/读回同线程）。
    fn v3bv_readback_x3() -> Vec<Option<ProbeResult>> {
        (0..3)
            .map(|i| {
                if i > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                probe_hdrop_paths(8)
            })
            .collect()
    }

    /// 所有线程的 WM_RENDERFORMAT 响应——独立线程 + 超时守卫，超时 =
    /// Unreadable（诚实，不做部分判定）；进程退出/所有窗销毁后残留阻塞线程
    /// 自释）。
    fn v3bv_bounded_readback(timeout_secs: u64) -> Option<ProbeResult> {
        use std::sync::mpsc;
        let (tx, rx) = mpsc::channel::<Option<ProbeResult>>();
        std::thread::spawn(move || {
            let r = probe_hdrop_paths(8);
            let _ = tx.send(r);
        });
        match rx.recv_timeout(std::time::Duration::from_secs(timeout_secs)) {
            Ok(r) => r,
            Err(_) => {
                eprintln!(
                    "[V3B-V b] bounded readback timeout ({timeout_secs}s; render-request block?) — Unreadable"
                );
                None
            }
        }
    }

    /// 通道等待间隙处理——STA 活性 = OLE 跨线程/跨进程数据请求经**消息**到达
    /// 本线程的唯一通道）。
    unsafe fn v3bv_pump_messages() {
        use winapi::um::winuser::{DispatchMessageW, PeekMessageW, TranslateMessage, MSG};
        let mut msg = std::mem::zeroed::<MSG>();
        while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, winapi::um::winuser::PM_REMOVE)
            != 0
        {
            if msg.message == winapi::um::winuser::WM_QUIT {
                return;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    // 同线程 wndproc 取用——不跨线程共享；static + RefCell 非 Sync 不可，
    // 本文件 `CLIP_GATE_HELD` thread_local 先例同构；thread_local! 宏调用
    // 不挂 rustdoc → 此处用普通注释）。
    thread_local! {
        static V3BV_B_PAYLOAD: std::cell::RefCell<Option<Vec<u8>>> = std::cell::RefCell::new(None);
    }

    /// WM_RENDERALLFORMATS 按需供**新** HGLOBAL：`GlobalAlloc(GMEM_MOVEABLE)`→
    /// （系统渲染期间板已开，MSDN 口径）；供败 = `DestroyWindow` 弃板 → 系统
    /// 清板（诚实：不供部分内容）。a = 默认直通（`DefWindowProc`）。
    // winapi 0.3.9 的 `winapi::um::winuser::{HWND, UINT, WPARAM, LPARAM,
    // LRESULT}` 为 crate 内私有重导出（E0603）→ 直书公开底层形态
    // （HWND = *mut HWND__ 经 `winapi::shared::windef::HWND` 公开别名 /
    // UINT=u32 / WPARAM=usize / LPARAM=isize / LRESULT=isize，minwindef.h
    // 口径；同本文件 `GMEM_MOVEABLE` 直书先例）。
    unsafe extern "system" fn v3bv_wndproc(
        hwnd: winapi::shared::windef::HWND,
        msg: u32,
        wparam: usize,
        lparam: isize,
    ) -> isize {
        use winapi::um::winuser::{
            DefWindowProcW, DestroyWindow, WM_RENDERALLFORMATS, WM_RENDERFORMAT,
        };
        if msg == WM_RENDERFORMAT || msg == WM_RENDERALLFORMATS {
            if wparam as u32 == CF_HDROP {
                use hdrop_write_ffi::{
                    GetLastError, GlobalAlloc, GlobalFree, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
                };
                let payload = V3BV_B_PAYLOAD.with(|p| p.borrow().clone().unwrap_or_default());
                let hmem = GlobalAlloc(GMEM_MOVEABLE, payload.len() as u32);
                if hmem.is_null() {
                    eprintln!("[V3B-V b] render: GlobalAlloc failed — DestroyWindow (system empties board)");
                    DestroyWindow(hwnd);
                    return 0;
                }
                let mem = GlobalLock(hmem);
                if mem.is_null() {
                    let _ = GlobalFree(hmem);
                    eprintln!("[V3B-V b] render: GlobalLock failed — DestroyWindow");
                    DestroyWindow(hwnd);
                    return 0;
                }
                std::slice::from_raw_parts_mut(mem as *mut u8, payload.len()).copy_from_slice(&payload);
                GlobalUnlock(hmem);
                let h = SetClipboardData(CF_HDROP, hmem as *mut winapi::ctypes::c_void);
                if h.is_null() {
                    let e = GetLastError();
                    let _ = GlobalFree(hmem); // 失败 = 所有权未转移。
                    eprintln!("[V3B-V b] render: SetClipboardData failed (err={e}) — DestroyWindow");
                    DestroyWindow(hwnd);
                    return 0;
                }
                eprintln!(
                    "[V3B-V b] WM_RENDER*(0x{wparam:08X}) rendered CF_HDROP ({} bytes) — deferred render satisfied",
                    payload.len()
                );
                return 0;
            }
            eprintln!("[V3B-V b] WM_RENDER*(0x{wparam:08X}) non-CF_HDROP — no arm provided, return 0");
            0
        } else {
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
    }

    /// Z-order、不可见，纯泵形态〕；b = 真隐藏顶层窗〔剪贴板 owner，接
    /// WM_RENDER*——message-only 窗的剪贴板 owner 资格 MSDN 未明言 → 取形态
    /// 稳妥的真窗〕）。类注册幂等（同进程同测试二进制不预期重注册）。
    unsafe fn v3bv_create_window(tag: &str, message_only: bool) -> winapi::shared::windef::HWND {
        use winapi::um::winuser::{
            CreateWindowExW, HWND_MESSAGE, RegisterClassExW, WNDCLASSEXW, WS_OVERLAPPEDWINDOW,
        };
        let class_name: Vec<u16> = format!("V3BV{tag}WndClass\0").encode_utf16().collect();
        let win_name: Vec<u16> = format!("V3B-V {tag}\0").encode_utf16().collect();
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfnWndProc: Some(v3bv_wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: std::ptr::null_mut(),
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
            hIconSm: std::ptr::null_mut(),
        };
        if RegisterClassExW(&wc) == 0 {
            eprintln!(
                "[V3B-V {tag}] RegisterClassExW failed (err={})",
                hdrop_write_ffi::GetLastError()
            );
        }
        let parent = if message_only { HWND_MESSAGE } else { std::ptr::null_mut() };
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            win_name.as_ptr(),
            WS_OVERLAPPEDWINDOW,
            0,
            0,
            0,
            0,
            parent,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        eprintln!("[V3B-V {tag}] window created: hwnd={:p} (message_only={message_only})", hwnd);
        hwnd
    }

    /// OleSetClipboard（收尾含/不含 OleFlushClipboard 两式）。
    ///
    /// 检验：3B 定案「raw-FFI OleSetClipboard 确定性拒绝」在「完整 STA +
    /// 活泵」形态下是否仍成立（3B 取证/生产路径的调用线程**不泵消息**——
    /// 本变体即该差量）。`OleSetClipboard` 与读回 ×3 均在 STA 线程执行
    /// （生产形态 = 写/读回同线程；同线程 in-proc COM 调用无 marshaling）；
    /// HOLD 期泵保持活 = 服务外部跨进程读请求。
    /// env：`R132_3B_V_HOLD=1` 留板（外部 FileDrop 对照）/ `R132_3B_V_A_FLUSH=1`
    /// 收尾含 OleFlushClipboard 式（默认不含）。
    #[test]
    #[ignore = "板破坏性探针（OLE 板写入 + 落临时探针文件）；手动跑"]
    fn r132_3b_v_variant_a_sta_thread_probe() {
        use std::sync::mpsc;
        let with_flush = std::env::var_os("R132_3B_V_A_FLUSH").is_some();
        let hold = std::env::var_os("R132_3B_V_HOLD").is_some();
        let label = if with_flush { "a2+flush" } else { "a1-pump" };
        v3bv_clear_sentinel();
        let snap = v3bv_snapshot();
        eprintln!(
            "[V3B-V {label}] board snapshot: files={:?} text_len={:?}",
            snap.files,
            snap.text.as_ref().map(String::len)
        );
        let probe_file = v3bv_probe_file();
        let probe_path = probe_file.to_string_lossy().into_owned();
        let payload = build_hdrop_payload(&[probe_path.clone()]);

        enum V3bvACmd {
            Go,
            Quit,
        }
        type V3bvARes = (bool, i32, Vec<Option<ProbeResult>>, Option<i32>);

        let (cmd_tx, cmd_rx) = mpsc::channel::<V3bvACmd>();
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let (res_tx, res_rx) = mpsc::channel::<V3bvARes>();
        let payload_t = payload.clone();
        let pump = std::thread::Builder::new()
            .name("v3bv-a-sta".to_string())
            .spawn(move || {
                let co_hr = unsafe {
                    ole_write_ffi::CoInitializeEx(
                        std::ptr::null(),
                        ole_write_ffi::COINIT_APARTMENTTHREADED,
                    )
                };
                eprintln!(
                    "[V3B-V a] STA thread: CoInitializeEx(ATA)=0x{co_hr:08X} (0x00000000=S_OK 新 STA; 0x00000001=S_FALSE 本线程已 STA)"
                );
                let hwnd = unsafe { v3bv_create_window("A", true) };
                let _ = ready_tx.send(());
                let mut go_processed = false;
                loop {
                    match cmd_rx.recv_timeout(std::time::Duration::from_millis(50)) {
                        Ok(V3bvACmd::Go) if !go_processed => {
                            go_processed = true;
                            let obj = ole_hdrop::Obj::new(payload_t.clone());
                            let mut last_hr = 0i32;
                            let mut accepted = false;
                            for attempt in 0..OLE_SET_RETRY_LIMIT {
                                last_hr =
                                    unsafe { ole_write_ffi::OleSetClipboard(obj as *const std::ffi::c_void) };
                                eprintln!(
                                    "[V3B-V a] OleSetClipboard {}/{} hr=0x{last_hr:08X}",
                                    attempt + 1,
                                    OLE_SET_RETRY_LIMIT
                                );
                                match ole_set_action(last_hr, attempt) {
                                    OleSetAction::Accepted => {
                                        accepted = true;
                                        break;
                                    }
                                    OleSetAction::Retry => {
                                        unsafe { v3bv_pump_messages() };
                                        std::thread::sleep(std::time::Duration::from_millis(
                                            OLE_SET_RETRY_DELAY_MS as u64,
                                        ));
                                    }
                                    OleSetAction::Degrade => break,
                                }
                            }
                            eprintln!(
                                "[V3B-V a] OleSetClipboard done: accepted={} last_hr=0x{last_hr:08X}{}",
                                accepted,
                                if last_hr == ole_write_ffi::OLEOBJ_E_CANTCONVERT {
                                    " [24H2 raw-FFI OLE gate form — module doc ⑥]"
                                } else {
                                    ""
                                }
                            );
                            unsafe { ole_hdrop::Obj::drop_initial_ref(obj) };
                            // 读回 ×3（与 set 同线程 = 生产形态；间隔泵消息）。
                            let mut reads: Vec<Option<ProbeResult>> = Vec::new();
                            for i in 0..3u32 {
                                if i > 0 {
                                    unsafe { v3bv_pump_messages() };
                                    std::thread::sleep(std::time::Duration::from_millis(100));
                                }
                                reads.push(probe_hdrop_paths(8));
                            }
                            // 收尾式：R132_3B_V_A_FLUSH=1 = OleFlushClipboard（STA
                            // 线程调用；3B 取证 = 24H2 E_INVALIDARG 形态——本变体
                            // 在完整 STA 形态下复核）。
                            let exit_flush_hr = if with_flush {
                                let hr = unsafe { v3bv_ffi::OleFlushClipboard() };
                                eprintln!("[V3B-V a] exit OleFlushClipboard=0x{hr:08X}");
                                Some(hr)
                            } else {
                                None
                            };
                            eprintln!(
                                "[V3B-V a] readback ×3 totals={:?}",
                                reads.iter().map(|r| r.as_ref().map(|p| p.total)).collect::<Vec<_>>()
                            );
                            let _ = res_tx.send((accepted, last_hr, reads, exit_flush_hr));
                        }
                        Ok(V3bvACmd::Go) => {} // 重复 — 忽略
                        Ok(V3bvACmd::Quit) => {
                            unsafe {
                                v3bv_pump_messages();
                                winapi::um::winuser::DestroyWindow(hwnd);
                            }
                            break;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => unsafe { v3bv_pump_messages() },
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            })
            .expect("STA thread spawn failed");
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("STA thread not ready (window create timeout)");
        let _ = cmd_tx.send(V3bvACmd::Go);
        let (accepted, last_hr, reads, exit_flush_hr) = res_rx
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("OleSetClipboard+readback timeout (60s)");
        let verdict = verify_readback(&[probe_path.clone()], reads.iter().flatten().next());
        eprintln!(
            "[V3B-V {label}] RESULT: accepted={accepted} last_hr=0x{last_hr:08X} exit_flush={exit_flush_hr:?} readback ×3 totals={:?}",
            reads.iter().map(|r| r.as_ref().map(|p| p.total)).collect::<Vec<_>>()
        );
        if hold {
            v3bv_hold(label);
        }
        let _ = cmd_tx.send(V3bvACmd::Quit);
        let _ = pump.join();
        unsafe { v3bv_restore(&snap) };
        let _ = std::fs::remove_file(&probe_file);
        eprintln!("[V3B-V {label}] done (board restored, probe file removed)");
    }

    /// WM_RENDERFORMAT/WM_RENDERALLFORMATS 按需供 HGLOBAL。
    ///
    /// 检验：24H2 读侧 quirk（「Set 成功而读回恒 0」）是否只杀**立即渲染**——
    /// OS 介导的按需供给形态（消费者读 → 系统发 WM_RENDERFORMAT 至 owner 窗
    /// → 所有线程供**新** HGLOBAL）能否造出可读板。线程纪律：泵线程 = 窗
    /// 所有线程（WM_RENDER* 必须由创建线程派发）；读回 ×3 走主线程（跨线程
    /// 渲染请求触发 = 与 Explorer/PowerShell 外部读同路径——同线程请求 = 渲染
    /// 自死锁，故再经 [`v3bv_bounded_readback`] 有界独立线程）。
    /// env：`R132_3B_V_HOLD=1` 留板（外部 FileDrop **跨进程**对照——真·跨
    /// 进程渲染请求路径）。
    #[test]
    #[ignore = "板破坏性探针（延迟渲染板 + 落临时探针文件）；手动跑"]
    fn r132_3b_v_variant_b_deferred_render_probe() {
        use std::sync::mpsc;
        let hold = std::env::var_os("R132_3B_V_HOLD").is_some();
        v3bv_clear_sentinel();
        let snap = v3bv_snapshot();
        eprintln!(
            "[V3B-V b] board snapshot: files={:?} text_len={:?}",
            snap.files,
            snap.text.as_ref().map(String::len)
        );
        let probe_file = v3bv_probe_file();
        let probe_path = probe_file.to_string_lossy().into_owned();
        let payload = build_hdrop_payload(&[probe_path.clone()]);

        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let (status_tx, status_rx) = mpsc::channel::<(bool, u32, bool, u32)>();
        let payload_t = payload.clone();
        let pump = std::thread::Builder::new()
            .name("v3bv-b-pump".to_string())
            .spawn(move || {
                V3BV_B_PAYLOAD.with(|p| p.borrow_mut().replace(payload_t));
                let hwnd = unsafe { v3bv_create_window("B", false) };
                let (set_ok, set_err) = unsafe {
                    if OpenClipboard(hwnd) != 0 {
                        let _ = EmptyClipboard();
                        // 延迟渲染注册：lpData=NULL → 消费者读时系统经
                        // WM_RENDERFORMAT 向本窗索要（owner 窗 = hwnd）。
                        let _h = SetClipboardData(CF_HDROP, std::ptr::null_mut());
                        let err = hdrop_write_ffi::GetLastError();
                        let ok = err == 0;
                        eprintln!(
                            "[V3B-V b] SetClipboardData(CF_HDROP, NULL) -> GetLastError={} (accept criterion = err 0; NULL-form return value not a criterion)",
                            err
                        );
                        CloseClipboard();
                        (ok, err)
                    } else {
                        let err = hdrop_write_ffi::GetLastError();
                        eprintln!("[V3B-V b] OpenClipboard failed (err={err})");
                        (false, err)
                    }
                };
                let fmt_avail = unsafe { IsClipboardFormatAvailable(CF_HDROP) } != 0;
                eprintln!("[V3B-V b] IsClipboardFormatAvailable(CF_HDROP) after set = {fmt_avail}");
                let tid = unsafe { v3bv_ffi::GetCurrentThreadId() };
                let _ = status_tx.send((set_ok, set_err, fmt_avail, tid));
                let _ = ready_tx.send(());
                // 泵循环（WM_RENDERFORMAT 必须由本线程派发）。
                loop {
                    use winapi::um::winuser::{
                        DispatchMessageW, GetMessageW, TranslateMessage, MSG,
                    };
                    let mut msg = unsafe { std::mem::zeroed::<MSG>() };
                    let r = unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) };
                    // GetMessageW 返回 i32（winapi 0.3.9 本 crate 编译形态）：
                    // 0 = WM_QUIT（主线程 PostThreadMessageW 投递）；-1 = 错误。
                    if r == 0 || r == -1 {
                        break;
                    }
                    unsafe {
                        let _ = TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }
                unsafe {
                    // 所有窗销毁 = 系统发 WM_DESTROYCLIPBOARD 并清板（若本窗
                    // 仍持板）——板面卫生：本探针内容不得残留过进程退出。
                    winapi::um::winuser::DestroyWindow(hwnd);
                }
                eprintln!("[V3B-V b] pump thread: window destroyed — join complete");
            })
            .expect("pump thread spawn failed");
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("pump thread not ready");
        let (set_ok, set_err, fmt_avail, tid) = status_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("set status timeout");
        // 读回 ×3（主线程 = 跨线程渲染请求触发；有界守卫）。
        let mut reads: Vec<Option<ProbeResult>> = Vec::new();
        for _ in 0..3u32 {
            reads.push(v3bv_bounded_readback(10));
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let verdict = verify_readback(&[probe_path.clone()], reads.iter().flatten().next());
        eprintln!(
            "[V3B-V b] RESULT: set_null_ok={set_ok} set_err={set_err} fmt_avail={fmt_avail} readback ×3 totals={:?}",
            reads.iter().map(|r| r.as_ref().map(|p| p.total)).collect::<Vec<_>>()
        );
        if hold {
            v3bv_hold("b");
        }
        // 终止泵线程（PostThreadMessageW WM_QUIT = 跨线程安全形态）。
        unsafe {
            winapi::um::winuser::PostThreadMessageW(tid, winapi::um::winuser::WM_QUIT, 0, 0);
        }
        let _ = pump.join();
        unsafe { v3bv_restore(&snap) };
        let _ = std::fs::remove_file(&probe_file);
        eprintln!("[V3B-V b] done (board restored, probe file removed)");
    }

    /// `write_cf_hdrop` 原样调用 = raw-FFI 立即 OleSetClipboard → 拒 →
    /// 降级经典立即 Set）——**对照锚**，确认 3B 九点证据链与生产链行为
    /// （CANTCONVERT ×10 → 降级 WARN → 经典 Set ×3 → 读回恒 0 → 诚实
    /// `false`）可独立复现。
    /// env：`R132_3B_V_HOLD=1` 留板（外部 FileDrop 对照 = 板上经典形态对
    /// Explorer 同路径的消费侧可见性亲证）。
    #[test]
    #[ignore = "板破坏性探针（生产 write_cf_hdrop 全链 + 落临时探针文件）；手动跑"]
    fn r132_3b_v_variant_c_baseline_probe() {
        let hold = std::env::var_os("R132_3B_V_HOLD").is_some();
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
        v3bv_clear_sentinel();
        let snap = v3bv_snapshot();
        eprintln!(
            "[V3B-V c] board snapshot: files={:?} text_len={:?}",
            snap.files,
            snap.text.as_ref().map(String::len)
        );
        let probe_file = v3bv_probe_file();
        let probe_path = probe_file.to_string_lossy().into_owned();
        // 生产写路径原样（raw-FFI 立即 OleSetClipboard + 立即经典 Set；
        let ok = write_cf_hdrop(std::slice::from_ref(&probe_file));
        eprintln!("[V3B-V c] write_cf_hdrop -> {ok}");
        // 独立读回 ×3（DragQueryFileW 计数；同线程生产形态）。
        let reads = v3bv_readback_x3();
        let verdict = verify_readback(&[probe_path.clone()], reads.iter().flatten().next());
        eprintln!(
            "[V3B-V c] RESULT: write={ok} readback ×3 totals={:?}",
            reads.iter().map(|r| r.as_ref().map(|p| p.total)).collect::<Vec<_>>()
        );
        if hold {
            v3bv_hold("c");
        }
        unsafe { v3bv_restore(&snap) };
        let _ = std::fs::remove_file(&probe_file);
        eprintln!("[V3B-V c] done (board restored, probe file removed)");
    }


    /// `Guid` 16B / `Variant` 16B / `Dispparams` 24B / vtable 各槽 8B
    /// （IShellWindows 9 方法 = 72B / IDispatch 7 方法 = 56B）。
    #[test]
    fn r135_1_com_layout_pinned() {
        assert_eq!(std::mem::size_of::<fx::Guid>(), 16);
        assert_eq!(std::mem::size_of::<fx::Variant>(), 16);
        assert_eq!(std::mem::size_of::<fx::Dispparams>(), 24);
        assert_eq!(std::mem::size_of::<fx::ShellVtbl>(), 9 * 8);
        assert_eq!(std::mem::size_of::<fx::DispatchVtbl>(), 7 * 8);
        // 常量口径。
        assert_eq!(fx::VT_BSTR, 8);
        assert_eq!(fx::DISPATCH_PROPERTYGET, 4);
        assert_eq!(fx::S_OK, 0);
        assert_eq!(fx::CLSCTX_ALL, 0x7);
        assert_eq!(R135_1_FOCUS_PROBE_BOUND_MS, 1000);
    }

    /// 长 + UTF-16 载荷；空指针/零长 = 空串）。
    #[test]
    fn r135_1_bstr_to_string_pinned() {
        let wide: Vec<u16> = "C:\\Users\\a".encode_utf16().collect();
        let mut buf = vec![0u8; 4 + wide.len() * 2];
        let byte_len = wide.len() * 2;
        buf[0..4].copy_from_slice(&(byte_len as u32).to_le_bytes());
        buf[4..].copy_from_slice(&wide.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>());
        let s = bstr_to_string(buf[4..].as_ptr() as *const u16);
        assert_eq!(s, "C:\\Users\\a");
        assert_eq!(bstr_to_string(std::ptr::null()), "");
        // 零长 BSTR（仅 4B 前缀 = 0）。
        let zero = [0u8; 4];
        let zp = unsafe { zero.as_ptr().add(4) } as *const u16;
        assert_eq!(bstr_to_string(zp), "");
    }

    /// Explorer），返回 `Some` 必为绝对现存目录；`None` = 无聚焦/超时
    /// （fail-closed）。**纯读**：不改焦点、不触板。
    ///
    /// 跑法：先开一个 Explorer 窗口并聚焦任意文件夹 →
    /// `cargo test -p kirin-desk-ui r135_1_real_focused_explorer_probe -- --ignored --nocapture`
    /// （期望 `Some` 且 = 该文件夹）；关闭全部 Explorer 窗口再跑（期望
    /// `None`）。
    #[test]
    #[ignore = "真机 COM 探针（IShellWindows 依赖运行中 Explorer）；手动跑"]
    fn r135_1_real_focused_explorer_probe() {
        let t0 = std::time::Instant::now();
        let got = probe_focused_explorer_dir();
        let elapsed_ms = t0.elapsed().as_millis();
        eprintln!(
            got, elapsed_ms, R135_1_FOCUS_PROBE_BOUND_MS
        );
        // 有界性：必在预算内返回（超时路径亦 ≤ 预算 + 调度抖动余量）。
        assert!(
            elapsed_ms <= (R135_1_FOCUS_PROBE_BOUND_MS + 500) as u128,
            "probe took {elapsed_ms}ms beyond bound"
        );
        // 返回 Some = 绝对现存目录（内层校验的复验）。
        if let Some(p) = &got {
            assert!(p.is_absolute(), "probe returned non-absolute path: {p:?}");
            assert!(p.is_dir(), "probe returned non-directory: {p:?}");
        }
    }
}
