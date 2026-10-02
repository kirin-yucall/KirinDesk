//! Windows DPAPI 身份存储后端（S-05 / F-4，S-05b-1）。
//!
//! 用 `CryptProtectData` / `CryptUnprotectData`（crypt32.dll）保护 Ed25519
//! 私钥原始字节（32 字节），保护结果落盘 `identity.dpapi.<label>.blob`。
//! 受保护 blob **不可逆**：只有同一 Windows 用户账户（默认 user scope）能
//! 解开——满足"Windows 上密钥不再以可逆文件形式存在"（审计 F-4 验收）。
//!
//! # 实现方式（架构红线：dlopen，不静态链接系统库）
//!
//! 与 `macos_keychain.rs`（M12-MAC）同模式：`libloading` 动态加载
//! `crypt32.dll`（`CryptProtectData` / `CryptUnprotectData`）与
//! `kernel32.dll`（`LocalFree`，释放输出缓冲）——**不新增 windows crate 依赖**
//! （任务文档 §4 S-05b-1："优先用 FFI 或最小依赖"）。
//!
//! # 安全语义
//!
//! - 使用 `CRYPTPROTECT_UI_FORBIDDEN`：无 UI 提示（守护进程环境可用）；
//! - user scope（不带 `CRYPTPROTECT_LOCAL_MACHINE`）：其他用户/账户无法解开；
//! - blob 被篡改或换用户解开失败 → [`KeyStoreError::Corrupt`] → 调用方
//!   fail-closed（不得静默换身份）。

#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::path::PathBuf;
use std::ptr;
use std::sync::OnceLock;

use libloading::{Library, Symbol};

use crate::crypto::keystore::{sanitize_label, write_private_file, KeyStore, KeyStoreError};

/// `CRYPTPROTECT_UI_FORBIDDEN`：禁止任何 UI 提示。
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

/// `DATA_BLOB { DWORD cbData; BYTE* pbData; }`（与 `<dpapi.h>` 对齐）。
#[repr(C)]
struct DataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

type CryptProtectDataFn = unsafe extern "system" fn(
    p_data_in: *const DataBlob,
    sz_data_descr: *const u16,
    p_optional_entropy: *const DataBlob,
    pv_reserved: *const c_void,
    p_prompt_struct: *const c_void,
    dw_flags: u32,
    p_data_out: *mut DataBlob,
) -> i32;

type CryptUnprotectDataFn = unsafe extern "system" fn(
    p_data_in: *const DataBlob,
    ppsz_data_descr: *mut *mut u16,
    p_optional_entropy: *const DataBlob,
    pv_reserved: *const c_void,
    p_prompt_struct: *const c_void,
    dw_flags: u32,
    p_data_out: *mut DataBlob,
) -> i32;

type LocalFreeFn = unsafe extern "system" fn(h_mem: *mut c_void) -> *mut c_void;

/// 已解析的 crypt32/kernel32 函数表。
struct DpapiDlls {
    _crypt32: Library,
    _kernel32: Library,
    crypt_protect_data: CryptProtectDataFn,
    crypt_unprotect_data: CryptUnprotectDataFn,
    local_free: LocalFreeFn,
}

static DPAPI: OnceLock<Result<DpapiDlls, KeyStoreError>> = OnceLock::new();

impl DpapiDlls {
    fn get() -> Result<&'static DpapiDlls, KeyStoreError> {
        DPAPI.get_or_init(Self::load).as_ref().map_err(|e| {
            // OnceLock 内已缓存错误，这里仅包装路径统一为 Backend。
            KeyStoreError::Backend(e.to_string())
        })
    }

    fn load() -> Result<Self, KeyStoreError> {
        // SAFETY: 系统固定路径 DLL；加载后仅解析符号。
        let crypt32 = unsafe { Library::new("crypt32.dll") }
            .map_err(|e| KeyStoreError::Backend(format!("dlopen crypt32.dll: {e}")))?;
        let kernel32 = unsafe { Library::new("kernel32.dll") }
            .map_err(|e| KeyStoreError::Backend(format!("dlopen kernel32.dll: {e}")))?;

        macro_rules! sym {
            ($lib:expr, $name:literal, $ty:ty) => {
                // SAFETY: 符号名与类型来自 Windows SDK 头文件。
                unsafe { $lib.get::<$ty>($name.as_bytes()) }
                    .map(|s: Symbol<'_, $ty>| *s)
                    .map_err(|e| KeyStoreError::Backend(format!("symbol '{}': {e}", $name)))?
                    as $ty
            };
        }

        Ok(Self {
            crypt_protect_data: sym!(&crypt32, "CryptProtectData", CryptProtectDataFn),
            crypt_unprotect_data: sym!(&crypt32, "CryptUnprotectData", CryptUnprotectDataFn),
            local_free: sym!(&kernel32, "LocalFree", LocalFreeFn),
            _crypt32: crypt32,
            _kernel32: kernel32,
        })
    }
}

/// Windows DPAPI 后端（user scope + UI_FORBIDDEN）。
pub struct DpapiKeyStore {
    dir: PathBuf,
}

impl DpapiKeyStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// crypt32 是否可加载（Windows 上恒为 true；失败时调用方走文件兜底）。
    pub fn available() -> bool {
        DpapiDlls::get().is_ok()
    }

    fn blob_path(&self, label: &str) -> PathBuf {
        self.dir
            .join(format!("identity.dpapi.{}.blob", sanitize_label(label)))
    }
}

impl KeyStore for DpapiKeyStore {
    fn set(&self, label: &str, secret: &[u8]) -> Result<(), KeyStoreError> {
        let dlls = DpapiDlls::get()?;
        let in_blob = DataBlob {
            cb_data: secret.len() as u32,
            pb_data: secret.as_ptr() as *mut u8,
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };

        // SAFETY: 输入 blob 指向调用期间存活的 secret 字节；输出 blob 由系统
        // 分配，返回后必须 LocalFree。
        let ok = unsafe {
            (dlls.crypt_protect_data)(
                &in_blob,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };
        if ok == 0 {
            return Err(KeyStoreError::Backend(format!(
                "CryptProtectData failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let protected = if out_blob.cb_data > 0 && !out_blob.pb_data.is_null() {
            // SAFETY: 系统返回的受保护数据缓冲，长度为 cb_data。
            unsafe {
                std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize).to_vec()
            }
        } else {
            Vec::new()
        };
        // SAFETY: CryptProtectData 文档要求 LocalFree 释放 pDataOut。
        unsafe { (dlls.local_free)(out_blob.pb_data as *mut c_void) };

        write_private_file(&self.blob_path(label), &protected)?;
        Ok(())
    }

    fn get(&self, label: &str) -> Result<Option<Vec<u8>>, KeyStoreError> {
        let dlls = DpapiDlls::get()?;
        let path = self.blob_path(label);
        let blob = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let in_blob = DataBlob {
            cb_data: blob.len() as u32,
            pb_data: blob.as_ptr() as *mut u8,
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };

        // SAFETY: 同上；ppszDataDescr 传 null（不需要描述字符串）。
        let ok = unsafe {
            (dlls.crypt_unprotect_data)(
                &in_blob,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                &mut out_blob,
            )
        };
        if ok == 0 {
            // 篡改 / 换用户账户 → 解不开 → fail-closed（调用方不得静默再生）。
            return Err(KeyStoreError::Corrupt(format!(
                "CryptUnprotectData failed (blob tampered or wrong user scope): {}",
                std::io::Error::last_os_error()
            )));
        }

        let secret = if out_blob.cb_data > 0 && !out_blob.pb_data.is_null() {
            // SAFETY: 系统返回的明文数据缓冲。
            unsafe {
                std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize).to_vec()
            }
        } else {
            Vec::new()
        };
        // SAFETY: CryptUnprotectData 文档要求 LocalFree 释放 pDataOut。
        unsafe { (dlls.local_free)(out_blob.pb_data as *mut c_void) };

        Ok(Some(secret))
    }

    fn delete(&self, label: &str) -> Result<(), KeyStoreError> {
        match std::fs::remove_file(self.blob_path(label)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kirin_desk_dpapi_{}_{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn dpapi_roundtrip() {
        let dir = temp_dir("roundtrip");
        let store = DpapiKeyStore::new(dir.clone());
        assert!(store.get("dev-1").unwrap().is_none());

        let secret: Vec<u8> = (0..32u8).collect();
        store.set("dev-1", &secret).unwrap();
        assert_eq!(store.get("dev-1").unwrap().unwrap(), secret);

        // blob 文件已落盘，但内容受 DPAPI 保护（非明文）
        let blob = std::fs::read(dir.join("identity.dpapi.dev-1.blob")).unwrap();
        assert!(!blob.is_empty());

        // 覆盖（幂等）
        store.set("dev-1", b"other").unwrap();
        assert_eq!(store.get("dev-1").unwrap().unwrap(), b"other");

        store.delete("dev-1").unwrap();
        assert!(store.get("dev-1").unwrap().is_none());
        store.delete("dev-1").unwrap(); // 幂等

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dpapi_tampered_blob_fails_closed() {
        let dir = temp_dir("tamper");
        let store = DpapiKeyStore::new(dir.clone());
        store.set("dev-1", b"secret").unwrap();

        let path = dir.join("identity.dpapi.dev-1.blob");
        let mut blob = std::fs::read(&path).unwrap();
        let mid = blob.len() / 2;
        blob[mid] ^= 0xff;
        std::fs::write(&path, blob).unwrap();

        match store.get("dev-1") {
            Err(KeyStoreError::Corrupt(_)) => {}
            other => panic!("expected Corrupt, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dpapi_available_on_windows() {
        // crypt32.dll 是 Windows 系统 DLL；本测试在 Windows 上必须可用。
        assert!(DpapiKeyStore::available());
    }
}
