//! R-13 (M15-T005): 配置敏感字段加密存储。
//!
//! 审计背景（`功能审计报告_2026-08-02.md` §4 P2-9 / M15-T005 / UI-SET-010）：
//! GoDaddy API Key/Secret、relay token 等敏感字段明文存配置。本模块提供
//! 密文格式、主密钥来源分层与脱敏工具；`config.rs` 字段接线与旧配置迁移
//! （R13-S1 后半 / R13-S3）随波次 2 合并后落地。
//!
//! # 密文格式
//!
//! 敏感字段改存 `{v: base64(nonce ‖ ciphertext)}`：
//! - 算法：ChaCha20Poly1305（与 core `crypto/aead.rs` 同系 AEAD）；
//! - `nonce`：12 字节随机（每次加密新随机）；
//! - `ciphertext`：明文 + 16 字节认证标签；
//! - AAD = 字段上下文（如 `"godaddy.api_key"`），防止密文跨字段替换；
//! - 明文空串也加密（空串字段不泄露"是否已填"）。
//!
//! # 密钥来源分层（R13-S2）
//!
//! 1. 环境变量 `KIRIN_CONFIG_KEY`（口令）→ PBKDF2-HMAC-SHA256 派生 32B 密钥
//!    （任何平台可用，优先级最高，便于无密钥环平台/脚本场景）；
//! 2. Windows：DPAPI 保护随机主密钥（`CryptProtectData`，blob 存
//!    `config_dir/kirin_config_key.dpapi`，当前用户级保护）；
//! 3. macOS：Keychain 通用密码条目（dlopen Security.framework——架构红线
//!    不静态链接系统框架，镜像 `core/src/crypto/macos_keychain.rs` 的
//!    MAC-T006 模式；service+account 固定 `kirindesk-config-key`）；
//! 4. 全部不可用 → **fail-open**：明文存储 + 启动醒目警告（不阻断开发
//!    使用；见 [`KeySource::Plaintext`]）。
//!
//! 实现取舍：**utils 内轻量自含**（保持零 core 依赖约定，不抽共享
//! crypto-util）——新增依赖仅 chacha20poly1305 / pbkdf2 / base64 / rand
//! 与平台密钥环支撑。

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::path::Path;

/// 环境变量名：配置加密口令（任何平台可设；优先级高于平台密钥环）。
pub const ENV_CONFIG_KEY: &str = "KIRIN_CONFIG_KEY";

/// PBKDF2 迭代次数（HMAC-SHA256；配置加载一次约数十~数百 ms，可接受）。
pub const PBKDF2_ITERATIONS: u32 = 600_000;

/// PBKDF2 盐（应用级常量；口令从环境变量来，本方案定位为"开发/无环平台
/// 降级"，非高保证场景——如需更强可后续改为随 blob 存储随机盐）。
const PBKDF2_SALT: &[u8] = b"kirin-desk-config-key-v1";

/// 主密钥长度（ChaCha20Poly1305 密钥 32 字节）。
pub const KEY_LEN: usize = 32;

/// ChaCha20Poly1305 随机 nonce 长度。
const NONCE_LEN: usize = 12;

/// 密文格式前缀 `{v:`（后接 base64，`}` 收尾）。
const VERSION_PREFIX: &str = "{v:";

/// Windows DPAPI blob 文件名（存于配置目录）。
const DPAPI_BLOB_FILE: &str = "kirin_config_key.dpapi";

/// 加解密错误。
#[derive(Debug, thiserror::Error)]
pub enum SecureError {
    #[error("encrypt failed: {0}")]
    Encrypt(String),
    #[error("decrypt failed: ciphertext tampered or wrong key")]
    Decrypt,
    #[error("invalid cipher format: not a {VERSION_PREFIX}...}} value")]
    InvalidFormat,
    #[error("key unavailable: {0}")]
    KeyUnavailable(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Windows DPAPI 操作失败。
    #[cfg(target_os = "windows")]
    #[error("DPAPI failed (win32 error {0})")]
    Win32(u32),
    /// macOS Keychain 操作失败。
    #[cfg(target_os = "macos")]
    #[error("Keychain failed: {0}")]
    Keychain(#[from] KeychainError),
}

/// 脱敏：密钥/令牌输出掩码（R13-S4）。空串原样返回；≤4 字符整体掩码；
/// 5~7 字符保留首 1 / 尾 1；≥8 字符保留首 2 / 尾 2，中间 `****`。
pub fn mask_secret(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    if n == 0 {
        return String::new();
    }
    if n <= 4 {
        return "****".to_string();
    }
    let keep = if n >= 8 { 2 } else { 1 };
    let mut out = String::with_capacity(n + 4);
    out.extend(chars[..keep].iter());
    out.push_str("****");
    out.extend(chars[n - keep..].iter());
    out
}

/// 判断字符串是否为密文格式（`{v:...}`）。旧明文配置的值 → `false`，
/// 供迁移（R13-S3）与新字段校验使用。
pub fn looks_encrypted(s: &str) -> bool {
    s.starts_with(VERSION_PREFIX) && s.ends_with('}')
}

/// 加密明文为 `{v: base64(nonce ‖ ciphertext)}`（AAD = `context` 字段上下文）。
pub fn encrypt_to_string(
    key: &[u8; KEY_LEN],
    plaintext: &str,
    context: &str,
) -> Result<String, SecureError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let mut buf = plaintext.as_bytes().to_vec();
    cipher
        .encrypt_in_place(Nonce::from_slice(&nonce), context.as_bytes(), &mut buf)
        .map_err(|e| SecureError::Encrypt(e.to_string()))?;

    let mut blob = Vec::with_capacity(NONCE_LEN + buf.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&buf);
    Ok(format!("{VERSION_PREFIX}{}}}", B64.encode(blob)))
}

/// 解密 `{v:...}` 密文；非密文格式 → [`SecureError::InvalidFormat`]，
/// 密钥错误/篡改 → [`SecureError::Decrypt`]（AEAD 认证失败）。
pub fn decrypt_from_string(
    key: &[u8; KEY_LEN],
    value: &str,
    context: &str,
) -> Result<String, SecureError> {
    let body = value
        .strip_prefix(VERSION_PREFIX)
        .and_then(|s| s.strip_suffix('}'))
        .ok_or(SecureError::InvalidFormat)?;
    let bytes = B64
        .decode(body)
        .map_err(|_| SecureError::InvalidFormat)?;
    if bytes.len() < NONCE_LEN + 16 {
        return Err(SecureError::InvalidFormat);
    }
    let (nonce, ct) = bytes.split_at(NONCE_LEN);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut buf = ct.to_vec();
    cipher
        .decrypt_in_place(Nonce::from_slice(nonce), context.as_bytes(), &mut buf)
        .map_err(|_| SecureError::Decrypt)?;
    String::from_utf8(buf).map_err(|_| SecureError::Decrypt)
}

/// 口令 → 主密钥（PBKDF2-HMAC-SHA256，确定性——同口令同密钥）。
pub fn derive_key_from_passphrase(passphrase: &str) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        passphrase.as_bytes(),
        PBKDF2_SALT,
        PBKDF2_ITERATIONS,
        &mut key,
    );
    key
}

/// 主密钥来源（R13-S2 分层解析结果）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// `KIRIN_CONFIG_KEY` 口令经 PBKDF2 派生。
    EnvPassphrase,
    /// Windows DPAPI 保护随机主密钥（blob 文件）。
    WindowsDpapi,
    /// macOS Keychain 条目。
    MacosKeychain,
    /// 无可用密钥源 → fail-open：明文存储 + 醒目警告。
    Plaintext,
}

/// 配置加密主密钥提供者。进程内解析一次；无密钥时字段保持明文。
pub struct KeyProvider {
    key: Option<[u8; KEY_LEN]>,
    source: KeySource,
}

impl KeyProvider {
    /// 按分层顺序解析主密钥。`dir` 为配置目录（DPAPI blob 存放处；
    /// 与 `config.rs::Config::config_dir()` 保持一致）。
    pub fn load(dir: &Path) -> Self {
        // 1. 环境变量口令 → PBKDF2（任何平台，优先级最高）。
        if let Ok(pass) = std::env::var(ENV_CONFIG_KEY) {
            if !pass.is_empty() {
                return Self {
                    key: Some(derive_key_from_passphrase(&pass)),
                    source: KeySource::EnvPassphrase,
                };
            }
        }
        // 2. Windows DPAPI。
        #[cfg(target_os = "windows")]
        if let Ok(key) = dpapi::load_or_create_key(dir) {
            return Self {
                key: Some(key),
                source: KeySource::WindowsDpapi,
            };
        }
        // 3. macOS Keychain。
        #[cfg(target_os = "macos")]
        if let Ok(key) = keychain::load_or_create_key() {
            return Self {
                key: Some(key),
                source: KeySource::MacosKeychain,
            };
        }
        // 4. fail-open：明文 + 醒目警告（不阻断开发使用）。
        tracing::warn!(
            "KirinDesk 配置加密：无可用密钥源（Windows DPAPI / macOS Keychain 不可用，\
             且未设置环境变量 {}）——敏感字段将保持明文存储；\
             设置该环境变量（口令经 PBKDF2 派生）可启用加密。",
            ENV_CONFIG_KEY
        );
        Self {
            key: None,
            source: KeySource::Plaintext,
        }
    }

    /// 主密钥（None = fail-open 明文模式）。
    pub fn key(&self) -> Option<&[u8; KEY_LEN]> {
        self.key.as_ref()
    }

    /// 命中的密钥来源。
    pub fn source(&self) -> KeySource {
        self.source
    }
}

// ════════════════════════════════════════════════════════════════
// Windows DPAPI（CryptProtectData/CryptUnprotectData）
// ════════════════════════════════════════════════════════════════

#[cfg(target_os = "windows")]
mod dpapi {
    use super::*;
    use windows::core::PCWSTR;
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    // windows 0.62：LocalFree 位于 Win32::Foundation（Win32::System::Memory
    // 无此符号，编译期即校验；与 utils/Cargo.toml 的 Win32_Foundation feature 对应）。
    // HLOCAL 为 newtype（非裸指针），`pbData as _` 无法隐式转换——显式包装。
    use windows::Win32::Foundation::{LocalFree, HLOCAL};

    /// 读取或首次创建 DPAPI 保护的主密钥。
    ///
    /// blob 文件已存在 → 解密读取；不存在或解密失败 → 生成 32B 随机密钥，
    /// DPAPI 保护后写入（当前用户级保护，重装系统/换用户后 blob 失效 →
    /// 旧密文无法解密，属预期；此时重新生成并提示）。
    pub(super) fn load_or_create_key(dir: &Path) -> Result<[u8; KEY_LEN], SecureError> {
        let blob_path = dir.join(DPAPI_BLOB_FILE);
        if let Ok(bytes) = std::fs::read(&blob_path) {
            if let Ok(key) = unprotect(&bytes) {
                if key.len() == KEY_LEN {
                    return Ok(key[..].try_into().expect("length checked"));
                }
            }
            tracing::warn!("DPAPI key blob invalid — regenerating");
        }

        let mut key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut key);
        let protected = protect(&key)?;
        std::fs::create_dir_all(dir)?;
        std::fs::write(&blob_path, protected)?;
        Ok(key)
    }

    /// `CryptProtectData`（CRYPTPROTECT_UI_FORBIDDEN：无 UI，静默失败）。
    fn protect(key: &[u8; KEY_LEN]) -> Result<Vec<u8>, SecureError> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: KEY_LEN as u32,
            pbData: key.as_ptr() as *mut u8,
        };
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: 输入/输出 blob 均为有效结构；输出经 LocalFree 释放。
        unsafe {
            CryptProtectData(
                &input,
                PCWSTR::null(),
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
        .map_err(win32_err)?;
        // SAFETY: 成功时 out.pbData 为 LocalAlloc 缓冲区，必须 LocalFree。
        let blob = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
        // SAFETY: 释放 DPAPI 分配的内存。
        // HLOCAL(pub *mut c_void)：pbData 为 *mut u8，须先转 *mut c_void 再包 Some。
        unsafe { LocalFree(Some(HLOCAL(out.pbData.cast()))) };
        Ok(blob)
    }

    /// `CryptUnprotectData`（当前用户/机器上下文可解）。
    /// 波次 2 接线（密钥重置/迁移校验）使用；当前仅测试引用。
    #[allow(dead_code)]
    pub(super) fn unprotect(blob: &[u8]) -> Result<Vec<u8>, SecureError> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: blob.len() as u32,
            pbData: blob.as_ptr() as *mut u8,
        };
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: 同 protect。
        unsafe {
            CryptUnprotectData(&input, None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        }
        .map_err(win32_err)?;
        // SAFETY: 同 protect。
        let bytes =
            unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
        // SAFETY: 释放 DPAPI 分配的内存。
        // HLOCAL(pub *mut c_void)：pbData 为 *mut u8，须先转 *mut c_void 再包 Some。
        unsafe { LocalFree(Some(HLOCAL(out.pbData.cast()))) };
        Ok(bytes)
    }

    fn win32_err(e: windows::core::Error) -> SecureError {
        SecureError::Win32(e.code().0 as u32)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn protect_unprotect_roundtrip() {
            let key = [0xAB; KEY_LEN];
            let blob = protect(&key).unwrap();
            assert_ne!(blob, key, "DPAPI blob must not equal plaintext key");
            let back = unprotect(&blob).unwrap();
            assert_eq!(back, key);
        }
    }
}

// ════════════════════════════════════════════════════════════════
// macOS Keychain（dlopen Security.framework，镜像 core 的 MAC-T006 模式）
// ════════════════════════════════════════════════════════════════

#[cfg(target_os = "macos")]
mod keychain {
    use super::*;
    use std::ffi::{c_char, c_void};
    use std::ptr;
    use std::sync::OnceLock;

    use libloading::{Library, Symbol};

    /// Keychain 条目 service+account（固定）。
    const KEYCHAIN_LABEL: &str = "kirindesk-config-key";

    // 常量（与 <Security/SecItem.h> / <CoreFoundation/CFDictionary.h> 对齐）。
    const SECURITY_FW: &str = "/System/Library/Frameworks/Security.framework/Security";
    const CORE_FOUNDATION_FW: &str =
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

    /// SecItem 键/值（CFString 常量，与头文件字符串字面量一致）。
    pub mod sec {
        pub const CLASS: &str = "class";
        pub const CLASS_GENERIC_PASSWORD: &str = "genp";
        pub const ATTR_SERVICE: &str = "svce";
        pub const ATTR_ACCOUNT: &str = "acct";
        pub const VALUE_DATA: &str = "v_Data";
        pub const RETURN_DATA: &str = "r_Data";
    }

    /// OSStatus 常量。
    pub mod osstatus {
        pub const SUCCESS: i32 = 0;
        pub const ITEM_NOT_FOUND: i32 = -25300;
    }

    /// Keychain 存储层错误（不耦合其它错误类型）。
    #[derive(Debug, thiserror::Error)]
    pub enum KeychainError {
        #[error("Keychain framework load failed: {0}")]
        Load(String),
        #[error("Keychain operation failed: OSStatus={0}")]
        Status(i32),
        #[error("Keychain item malformed: {0}")]
        Malformed(String),
    }

    type CFDictionaryCreateMutableFn = unsafe extern "C" fn(
        allocator: *const c_void,
        capacity: isize,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> *mut c_void;
    type CFDictionaryAddValueFn = unsafe extern "C" fn(
        dict: *mut c_void,
        key: *const c_void,
        value: *const c_void,
    );
    type CFStringCreateWithCStringFn = unsafe extern "C" fn(
        allocator: *const c_void,
        c_str: *const c_char,
        encoding: u32,
    ) -> *mut c_void;
    type CFDataCreateFn = unsafe extern "C" fn(
        allocator: *const c_void,
        bytes: *const u8,
        length: isize,
    ) -> *mut c_void;
    type CFDataGetLengthFn = unsafe extern "C" fn(data: *const c_void) -> isize;
    type CFDataGetBytePtrFn = unsafe extern "C" fn(data: *const c_void) -> *const u8;
    type CFGetTypeIDFn = unsafe extern "C" fn(cf: *const c_void) -> usize;
    type CFDataGetTypeIDFn = unsafe extern "C" fn() -> usize;
    type CFReleaseFn = unsafe extern "C" fn(cf: *const c_void);
    type SecItemAddFn = unsafe extern "C" fn(attributes: *const c_void, result: *mut *mut c_void) -> i32;
    type SecItemCopyMatchingFn =
        unsafe extern "C" fn(query: *const c_void, result: *mut *mut c_void) -> i32;
    type SecItemDeleteFn = unsafe extern "C" fn(query: *const c_void) -> i32;

    /// 已解析的 Security/CoreFoundation 函数表。
    struct KeychainDlls {
        _security: Library,
        _cf: Library,
        cf_dictionary_create_mutable: CFDictionaryCreateMutableFn,
        cf_dictionary_add_value: CFDictionaryAddValueFn,
        cf_string_create_with_cstring: CFStringCreateWithCStringFn,
        cf_data_create: CFDataCreateFn,
        cf_data_get_length: CFDataGetLengthFn,
        cf_data_get_byte_ptr: CFDataGetBytePtrFn,
        cf_get_type_id: CFGetTypeIDFn,
        cf_data_get_type_id: CFDataGetTypeIDFn,
        cf_release: CFReleaseFn,
        sec_item_add: SecItemAddFn,
        sec_item_copy_matching: SecItemCopyMatchingFn,
        sec_item_delete: SecItemDeleteFn,
        /// kCFBooleanTrue 单例（全局变量，dlsym 后解引用取值）。
        k_cf_boolean_true: *const c_void,
    }

    static KEYCHAIN: OnceLock<Result<KeychainDlls, KeychainError>> = OnceLock::new();

    impl KeychainDlls {
        fn get() -> Result<&'static KeychainDlls, KeychainError> {
            KEYCHAIN
                .get_or_init(Self::load)
                .as_ref()
                .map_err(|e| KeychainError::Load(e.to_string()))
        }

        fn load() -> Result<Self, KeychainError> {
            // SAFETY: 系统固定路径，加载后仅 dlsym 取符号。
            let security = unsafe { Library::new(SECURITY_FW) }
                .map_err(|e| KeychainError::Load(format!("dlopen Security: {e}")))?;
            let cf = unsafe { Library::new(CORE_FOUNDATION_FW) }
                .map_err(|e| KeychainError::Load(format!("dlopen CoreFoundation: {e}")))?;

            macro_rules! sym {
                ($lib:expr, $name:literal, $ty:ty) => {
                    // SAFETY: 符号名与类型均来自 Security/CoreFoundation 头文件。
                    unsafe { $lib.get::<$ty>($name.as_bytes()) }
                        .map(|s: Symbol<'_, $ty>| *s)
                        .map_err(|e| KeychainError::Load(format!("symbol '$name': {e}")))?
                        as $ty
                };
            }

            // kCFBooleanTrue 是全局变量（`extern const CFBooleanRef`）：dlsym 地址处
            // 存的是 CFBooleanRef（指针大小的值），解引用一次得到单例指针。
            // SAFETY: 系统导出全局变量，类型为指针。
            let k_true = unsafe { cf.get::<*const c_void>(b"kCFBooleanTrue") }
                .map(|s: Symbol<'_, *const c_void>| *s)
                .map_err(|e| KeychainError::Load(format!("symbol 'kCFBooleanTrue': {e}")))?;

            Ok(Self {
                cf_dictionary_create_mutable: sym!(
                    &cf,
                    "CFDictionaryCreateMutable",
                    CFDictionaryCreateMutableFn
                ),
                cf_dictionary_add_value: sym!(&cf, "CFDictionaryAddValue", CFDictionaryAddValueFn),
                cf_string_create_with_cstring: sym!(
                    &cf,
                    "CFStringCreateWithCString",
                    CFStringCreateWithCStringFn
                ),
                cf_data_create: sym!(&cf, "CFDataCreate", CFDataCreateFn),
                cf_data_get_length: sym!(&cf, "CFDataGetLength", CFDataGetLengthFn),
                cf_data_get_byte_ptr: sym!(&cf, "CFDataGetBytePtr", CFDataGetBytePtrFn),
                cf_get_type_id: sym!(&cf, "CFGetTypeID", CFGetTypeIDFn),
                cf_data_get_type_id: sym!(&cf, "CFDataGetTypeID", CFDataGetTypeIDFn),
                cf_release: sym!(&cf, "CFRelease", CFReleaseFn),
                sec_item_add: sym!(&security, "SecItemAdd", SecItemAddFn),
                sec_item_copy_matching: sym!(
                    &security,
                    "SecItemCopyMatching",
                    SecItemCopyMatchingFn
                ),
                sec_item_delete: sym!(&security, "SecItemDelete", SecItemDeleteFn),
                k_cf_boolean_true: k_true,
                _security: security,
                _cf: cf,
            })
        }
    }

    /// CFStringRef 封装（Drop 时 CFRelease）。
    struct CfString(*mut c_void);

    impl CfString {
        fn new(dlls: &KeychainDlls, s: &str) -> Result<Self, KeychainError> {
            let cstr = std::ffi::CString::new(s)
                .map_err(|_| KeychainError::Malformed("label contains NUL byte".into()))?;
            // kCFStringEncodingUTF8 = 0x08000100。
            // SAFETY: UTF-8 C 字符串。
            let p = unsafe {
                (dlls.cf_string_create_with_cstring)(ptr::null(), cstr.as_ptr(), 0x0800_0100)
            };
            if p.is_null() {
                return Err(KeychainError::Malformed(
                    "CFStringCreateWithCString returned NULL".into(),
                ));
            }
            Ok(Self(p))
        }
    }

    impl Drop for CfString {
        fn drop(&mut self) {
            if let Ok(dlls) = KeychainDlls::get() {
                // SAFETY: 有效 CFStringRef。
                unsafe { (dlls.cf_release)(self.0) };
            }
        }
    }

    /// CFMutableDictionaryRef 封装（Drop 时 CFRelease；NULL callbacks = 系统默认）。
    struct CfDict(*mut c_void);

    impl CfDict {
        fn new(dlls: &KeychainDlls) -> Result<Self, KeychainError> {
            // SAFETY: NULL callbacks = 系统默认（文档化），capacity=0 按需增长。
            let p = unsafe {
                (dlls.cf_dictionary_create_mutable)(ptr::null(), 0, ptr::null(), ptr::null())
            };
            if p.is_null() {
                return Err(KeychainError::Malformed(
                    "CFDictionaryCreateMutable returned NULL".into(),
                ));
            }
            Ok(Self(p))
        }

        fn add(&self, dlls: &KeychainDlls, key: &CfString, value: *const c_void) {
            // SAFETY: dict 有效；CF 字典 add 时 retain key/value，调用后仍可释放
            // 传入对象（kCFType callbacks 语义）。
            unsafe { (dlls.cf_dictionary_add_value)(self.0, key.0, value) };
        }
    }

    impl Drop for CfDict {
        fn drop(&mut self) {
            if let Ok(dlls) = KeychainDlls::get() {
                // SAFETY: 有效 CFMutableDictionaryRef。
                unsafe { (dlls.cf_release)(self.0) };
            }
        }
    }

    /// 读取配置加密主密钥（Keychain 通用密码条目，service+account =
    /// `kirindesk-config-key`）。条目不存在 → `KeychainError::Status(-25300)`。
    pub(super) fn load_key() -> Result<[u8; KEY_LEN], SecureError> {
        let dlls = KeychainDlls::get().map_err(SecureError::Keychain)?;

        let dict = CfDict::new(dlls).map_err(SecureError::Keychain)?;
        let class = CfString::new(dlls, sec::CLASS).map_err(SecureError::Keychain)?;
        let genp = CfString::new(dlls, sec::CLASS_GENERIC_PASSWORD).map_err(SecureError::Keychain)?;
        let svce = CfString::new(dlls, sec::ATTR_SERVICE).map_err(SecureError::Keychain)?;
        let acct = CfString::new(dlls, sec::ATTR_ACCOUNT).map_err(SecureError::Keychain)?;
        let ret = CfString::new(dlls, sec::RETURN_DATA).map_err(SecureError::Keychain)?;
        let label = CfString::new(dlls, KEYCHAIN_LABEL).map_err(SecureError::Keychain)?;

        dict.add(dlls, &class, genp.0);
        dict.add(dlls, &svce, label.0);
        dict.add(dlls, &acct, label.0);
        dict.add(dlls, &ret, dlls.k_cf_boolean_true);

        let mut result: *mut c_void = ptr::null_mut();
        // SAFETY: query 为构造的字典。
        let status = unsafe { (dlls.sec_item_copy_matching)(dict.0, &mut result) };
        if status != osstatus::SUCCESS {
            return Err(SecureError::Keychain(KeychainError::Status(status)));
        }
        if result.is_null() {
            return Err(SecureError::Keychain(KeychainError::Malformed(
                "SecItemCopyMatching returned NULL result".into(),
            )));
        }

        // 校验返回类型为 CFData。
        // SAFETY: 均为系统 API。
        let type_id = unsafe { (dlls.cf_get_type_id)(result) };
        let data_type_id = unsafe { (dlls.cf_data_get_type_id)() };
        if type_id != data_type_id {
            // SAFETY: 非 CFData 也需释放。
            unsafe { (dlls.cf_release)(result) };
            return Err(SecureError::Keychain(KeychainError::Malformed(format!(
                "returned CFTypeID {type_id} != CFData {data_type_id}"
            ))));
        }
        // SAFETY: len/ptr 来自有效 CFData。
        let len = unsafe { (dlls.cf_data_get_length)(result) };
        let bytes = unsafe { (dlls.cf_data_get_byte_ptr)(result) };
        let data = if len == KEY_LEN as isize && !bytes.is_null() {
            // SAFETY: len 为 CFData 长度，指针有效。
            let slice = unsafe { std::slice::from_raw_parts(bytes, len as usize) };
            let mut key = [0u8; KEY_LEN];
            key.copy_from_slice(slice);
            key
        } else {
            // SAFETY: result 为本调用创建的 CF 对象。
            unsafe { (dlls.cf_release)(result) };
            return Err(SecureError::Keychain(KeychainError::Malformed(format!(
                "key item length {} != {KEY_LEN}",
                len
            ))));
        };
        // SAFETY: result 为本调用创建的 CF 对象。
        unsafe { (dlls.cf_release)(result) };
        Ok(data)
    }

    /// 存储主密钥到 Keychain（已存在同 label 条目时先删再写，幂等覆盖）。
    pub(super) fn store_key(key: &[u8; KEY_LEN]) -> Result<(), SecureError> {
        let dlls = KeychainDlls::get().map_err(SecureError::Keychain)?;
        let _ = delete_key(); // 幂等覆盖：旧条目先删。

        let dict = CfDict::new(dlls).map_err(SecureError::Keychain)?;
        let class = CfString::new(dlls, sec::CLASS).map_err(SecureError::Keychain)?;
        let genp = CfString::new(dlls, sec::CLASS_GENERIC_PASSWORD).map_err(SecureError::Keychain)?;
        let svce = CfString::new(dlls, sec::ATTR_SERVICE).map_err(SecureError::Keychain)?;
        let acct = CfString::new(dlls, sec::ATTR_ACCOUNT).map_err(SecureError::Keychain)?;
        let vdata = CfString::new(dlls, sec::VALUE_DATA).map_err(SecureError::Keychain)?;
        let label = CfString::new(dlls, KEYCHAIN_LABEL).map_err(SecureError::Keychain)?;

        // SAFETY: key 在调用期间存活（CFDataCreate 会拷贝数据）。
        let data = unsafe {
            (dlls.cf_data_create)(ptr::null(), key.as_ptr(), KEY_LEN as isize)
        };
        if data.is_null() {
            return Err(SecureError::Keychain(KeychainError::Malformed(
                "CFDataCreate returned NULL".into(),
            )));
        }

        dict.add(dlls, &class, genp.0);
        dict.add(dlls, &svce, label.0);
        dict.add(dlls, &acct, label.0);
        dict.add(dlls, &vdata, data);

        // SAFETY: attributes 为构造的字典。
        let status = unsafe { (dlls.sec_item_add)(dict.0, ptr::null_mut()) };
        // SAFETY: data 已被字典 retain；本处释放初始引用。
        unsafe { (dlls.cf_release)(data) };
        if status != osstatus::SUCCESS {
            return Err(SecureError::Keychain(KeychainError::Status(status)));
        }
        Ok(())
    }

    /// 删除 Keychain 条目（不存在也返回 Ok——幂等）。
    pub(super) fn delete_key() -> Result<(), SecureError> {
        let dlls = KeychainDlls::get().map_err(SecureError::Keychain)?;

        let dict = CfDict::new(dlls).map_err(SecureError::Keychain)?;
        let class = CfString::new(dlls, sec::CLASS).map_err(SecureError::Keychain)?;
        let genp = CfString::new(dlls, sec::CLASS_GENERIC_PASSWORD).map_err(SecureError::Keychain)?;
        let svce = CfString::new(dlls, sec::ATTR_SERVICE).map_err(SecureError::Keychain)?;
        let acct = CfString::new(dlls, sec::ATTR_ACCOUNT).map_err(SecureError::Keychain)?;
        let label = CfString::new(dlls, KEYCHAIN_LABEL).map_err(SecureError::Keychain)?;

        dict.add(dlls, &class, genp.0);
        dict.add(dlls, &svce, label.0);
        dict.add(dlls, &acct, label.0);

        // SAFETY: query 为构造的字典。
        let status = unsafe { (dlls.sec_item_delete)(dict.0) };
        if status != osstatus::SUCCESS && status != osstatus::ITEM_NOT_FOUND {
            return Err(SecureError::Keychain(KeychainError::Status(status)));
        }
        Ok(())
    }

    /// 读取或首次创建主密钥（不存在 → 生成随机密钥并存入 Keychain）。
    pub(super) fn load_or_create_key() -> Result<[u8; KEY_LEN], SecureError> {
        match load_key() {
            Ok(key) => Ok(key),
            Err(SecureError::Keychain(KeychainError::Status(osstatus::ITEM_NOT_FOUND))) => {
                let mut key = [0u8; KEY_LEN];
                OsRng.fill_bytes(&mut key);
                store_key(&key)?;
                Ok(key)
            }
            Err(e) => Err(e),
        }
    }
}

// ════════════════════════════════════════════════════════════════
// 单元测试
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};

    /// env 与 KeyProvider 涉及进程全局态，串行执行（并行测试隔离）。
    static SYS_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_lock() -> &'static Mutex<()> {
        SYS_LOCK.get_or_init(|| Mutex::new(()))
    }

    fn test_key() -> [u8; KEY_LEN] {
        [7u8; KEY_LEN]
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kirin_secure_test_{}_{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn roundtrip_zh_text() {
        let ct = encrypt_to_string(&test_key(), "s3cr3t-中文口令", "godaddy.api_key").unwrap();
        let pt = decrypt_from_string(&test_key(), &ct, "godaddy.api_key").unwrap();
        assert_eq!(pt, "s3cr3t-中文口令");
    }

    #[test]
    fn format_matches_spec() {
        let ct = encrypt_to_string(&test_key(), "abc", "").unwrap();
        assert!(ct.starts_with("{v:"), "format: {{v: base64(nonce‖ct)}}");
        assert!(ct.ends_with('}'));
        let body = &ct[3..ct.len() - 1];
        let bytes = B64.decode(body).unwrap();
        assert_eq!(bytes.len(), NONCE_LEN + "abc".len() + 16, "nonce ‖ ct(含 tag)");
    }

    #[test]
    fn nonce_is_random_per_encryption() {
        let a = encrypt_to_string(&test_key(), "same", "").unwrap();
        let b = encrypt_to_string(&test_key(), "same", "").unwrap();
        assert_ne!(a, b, "随机 nonce → 密文不同");
    }

    #[test]
    fn empty_plaintext_encrypts() {
        let ct = encrypt_to_string(&test_key(), "", "tunnel.token").unwrap();
        assert!(looks_encrypted(&ct));
        assert_eq!(decrypt_from_string(&test_key(), &ct, "tunnel.token").unwrap(), "");
    }

    #[test]
    fn tampered_ciphertext_detected() {
        let ct = encrypt_to_string(&test_key(), "secret", "ctx").unwrap();
        let mut body = B64.decode(&ct[3..ct.len() - 1]).unwrap();
        let last = body.len() - 1;
        body[last] ^= 0xFF;
        let tampered = format!("{VERSION_PREFIX}{}}}", B64.encode(&body));
        assert!(matches!(
            decrypt_from_string(&test_key(), &tampered, "ctx"),
            Err(SecureError::Decrypt)
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let ct = encrypt_to_string(&test_key(), "secret", "ctx").unwrap();
        let other = [9u8; KEY_LEN];
        assert!(matches!(
            decrypt_from_string(&other, &ct, "ctx"),
            Err(SecureError::Decrypt)
        ));
    }

    #[test]
    fn wrong_context_aad_fails() {
        let ct = encrypt_to_string(&test_key(), "secret", "godaddy.api_key").unwrap();
        assert!(matches!(
            decrypt_from_string(&test_key(), &ct, "tunnel.token"),
            Err(SecureError::Decrypt)
        ));
    }

    #[test]
    fn plaintext_input_rejected() {
        assert!(matches!(
            decrypt_from_string(&test_key(), "plain-secret", "ctx"),
            Err(SecureError::InvalidFormat)
        ));
        assert!(matches!(
            decrypt_from_string(&test_key(), "{v:!!not-base64!!}", "ctx"),
            Err(SecureError::InvalidFormat)
        ));
    }

    #[test]
    fn looks_encrypted_detection() {
        let ct = encrypt_to_string(&test_key(), "x", "").unwrap();
        assert!(looks_encrypted(&ct));
        assert!(!looks_encrypted(""));
        assert!(!looks_encrypted("plain"));
        assert!(!looks_encrypted("{v:abc")); // 缺收尾
        assert!(!looks_encrypted("abc}"));
    }

    #[test]
    fn mask_secret_cases() {
        assert_eq!(mask_secret(""), "");
        assert_eq!(mask_secret("a"), "****");
        assert_eq!(mask_secret("abcd"), "****");
        assert_eq!(mask_secret("abcdefgh"), "ab****gh");
        assert_eq!(mask_secret("abcdef"), "a****f");
        assert_eq!(mask_secret("中文口令值"), "中****值");
    }

    #[test]
    fn pbkdf2_deterministic_and_stable() {
        let k1 = derive_key_from_passphrase("pass-口令");
        let k2 = derive_key_from_passphrase("pass-口令");
        assert_eq!(k1, k2);
        assert_ne!(derive_key_from_passphrase("other"), k1);
        assert_ne!([0u8; KEY_LEN], k1);
    }

    #[test]
    fn provider_prefers_env_passphrase() {
        let _g = env_lock().lock().unwrap();
        std::env::set_var(ENV_CONFIG_KEY, "env-pass-123");
        let dir = temp_dir("env");
        let p = KeyProvider::load(&dir);
        std::env::remove_var(ENV_CONFIG_KEY);
        assert_eq!(p.source(), KeySource::EnvPassphrase);
        assert_eq!(p.key().unwrap(), &derive_key_from_passphrase("env-pass-123"));
    }

    #[test]
    fn provider_plaintext_when_no_key_source() {
        // 配置目录不可用（指向一个已存在文件）→ DPAPI/Keychain 均失败 → fail-open。
        let _g = env_lock().lock().unwrap();
        std::env::remove_var(ENV_CONFIG_KEY);
        let file = temp_dir("plain").join("not_a_dir");
        std::fs::write(&file, b"x").unwrap();
        let p = KeyProvider::load(&file);
        assert_eq!(p.source(), KeySource::Plaintext);
        assert!(p.key().is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn provider_uses_dpapi_and_persists_blob() {
        let _g = env_lock().lock().unwrap();
        std::env::remove_var(ENV_CONFIG_KEY);
        let dir = temp_dir("dpapi");
        let p1 = KeyProvider::load(&dir);
        assert_eq!(p1.source(), KeySource::WindowsDpapi);
        let k1 = *p1.key().unwrap();
        // 第二次加载：blob 已存在 → 同一主密钥（跨重启可读）。
        let p2 = KeyProvider::load(&dir);
        assert_eq!(p2.source(), KeySource::WindowsDpapi);
        assert_eq!(p2.key().unwrap(), &k1);
        // blob 文件不含明文密钥。
        let blob = std::fs::read(dir.join(DPAPI_BLOB_FILE)).unwrap();
        assert_ne!(blob, k1.to_vec());
        // 全程加解密可用。
        let ct = encrypt_to_string(&k1, "token", "tunnel.token").unwrap();
        assert_eq!(decrypt_from_string(&k1, &ct, "tunnel.token").unwrap(), "token");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn dpapi_blob_protected_by_user_context() {
        let _g = env_lock().lock().unwrap();
        let dir = temp_dir("blob");
        let k1 = dpapi::load_or_create_key(&dir).unwrap();
        let k2 = dpapi::load_or_create_key(&dir).unwrap();
        assert_eq!(k1, k2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
