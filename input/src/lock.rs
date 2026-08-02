//! M8-T020 SKEY-SEC-003: 锁屏调用的**单一实现**。
//!
//! 真正平台实现位于 M8-T019 的
//! [`kirin_desk_core::connection::privacy::platform_lock_screen`]
//! （Windows `LockWorkStation` / Linux `loginctl lock-session` / macOS `CGSession -suspend`），
//! 本模块只做错误映射——特殊键注入路径（`SpecialCombo::LockScreen`）与 M8-T019
//! 隐私模式锁屏**共用同一封装，禁止另起实现**。
//!
//! 失败语义：锁屏失败 → [`InjectError::InjectFailed`]，上层记日志不重试（SRV-SKEY-015）。

use crate::injector::InjectError;

/// 锁屏本机（被控端）。
pub fn lock_screen() -> Result<(), InjectError> {
    kirin_desk_core::connection::privacy::platform_lock_screen()
        .map_err(|e| InjectError::InjectFailed(format!("lock screen: {e}")))
}
