//! macOS Keychain 身份存储（M12-MAC MAC-T006；S-05/F-4 接入为**默认后端**）。
//!
//! 设计依据：`共享层/M12-MAC_macOS支持.md` MAC-T006。用 macOS Keychain
//! 存储 Ed25519 私钥原始字节（32 字节），优于文件式自定义加密存储
//! （ChaCha20Poly1305 + device_id 派生密钥，JSON `{nonce,ciphertext}`；
//! - 系统级加密（Keychain 本身加密磁盘上数据）；
//! - Touch ID / Apple Watch 解锁能力（后续可加）；
//! - 防盗用：即使 root 也无法直接读取 keychain item 内容。
//!
//! # 接线（S-05，审计 F-4）
//!
//! 本模块实现 [`crate::crypto::keystore::KeyStore`] trait，成为 macOS 上的
//! **默认身份存储后端**（`keystore::default_backend` 优先级 Keychain →
//! 文件主密钥兜底）：`store_private_key(label, key)` 存 32 字节私钥，
//! `load_private_key` / `delete_private_key` 读取/删除。Keychain 不可用
//! （框架加载失败）时降级到文件兜底后端（警告不阻断）。
//!
//! # FFI 方式（架构红线：dlopen，不静态链接系统框架）
//!
//! `libloading` 动态加载：
//! - `/System/Library/Frameworks/Security.framework/Security`（SecItem*）
//! - `/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation`（CF*）
//!
//! 通用密码条目（`kSecClassGenericPassword`）：`label` 用作 service+account，
//! 载荷为私钥原始字节（`kSecValueData`）。查询字典用 NULL callbacks（CF
//! 文档：NULL → 系统默认 `kCFTypeDictionary*CallBacks`，避免解析全局结构）；
//! `kSecReturnData` 的 true 经 dlsym 取系统单例 `kCFBooleanTrue`。
//!
//! 本模块只做**存储介质**，不实现任何加密算法（加密统一走 `core/crypto/`，
//! 见任务执行路线流程.md §六 架构红线 2）。

#![cfg(target_os = "macos")]

use std::ffi::{c_char, c_void};
use std::ptr;
use std::sync::OnceLock;

use libloading::{Library, Symbol};

use crate::crypto::keystore::{KeyStore, KeyStoreError};

// ════════════════════════════════════════════════════════════════
// 常量（与 <Security/SecItem.h> / <CoreFoundation/CFDictionary.h> 对齐）
// ════════════════════════════════════════════════════════════════

const SECURITY_FW: &str = "/System/Library/Frameworks/Security.framework/Security";
const CORE_FOUNDATION_FW: &str =
    "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

/// 常量，dlsym 后解引用取得——**不能用 `CFStringCreateWithCString` 按同值
/// 字符串重建**：SecItem 按单例身份识别字典键，同值新串不识别，
/// 返回 errSecParam（OSStatus=-50，Mojave 实测）。原先的 "class"/"genp"
/// 等字面量即此缺陷（与 utils/src/secure.rs 同源缺陷）。
pub mod sec {
    /// kSecClass（导出全局变量名）。
    pub const CLASS: &str = "kSecClass";
    /// kSecClassGenericPassword。
    pub const CLASS_GENERIC_PASSWORD: &str = "kSecClassGenericPassword";
    /// kSecAttrService。
    pub const ATTR_SERVICE: &str = "kSecAttrService";
    /// kSecAttrAccount。
    pub const ATTR_ACCOUNT: &str = "kSecAttrAccount";
    /// kSecValueData。
    pub const VALUE_DATA: &str = "kSecValueData";
    /// kSecReturnData。
    pub const RETURN_DATA: &str = "kSecReturnData";
}

/// OSStatus 常量。
pub mod osstatus {
    /// errSecSuccess。
    pub const SUCCESS: i32 = 0;
    /// errSecItemNotFound（读取/删除不存在的条目）。
    pub const ITEM_NOT_FOUND: i32 = -25300;
}

/// 此模块的错误类型（存储层专用；不耦合 `crypto/` 的其它错误）。
#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    /// dlopen / 符号解析失败。
    #[error("Keychain framework load failed: {0}")]
    Load(String),
    /// Keychain 操作被系统拒绝（未授权/损坏条目等）。
    #[error("Keychain operation failed: OSStatus={0}")]
    Status(i32),
    /// 读取的载荷格式异常（非字节 CFData 等）。
    #[error("Keychain item malformed: {0}")]
    Malformed(String),
}

// ════════════════════════════════════════════════════════════════
// CF / SecItem FFI 函数指针表
// ════════════════════════════════════════════════════════════════

/// CFTypeRef / CFStringRef / CFDataRef / CFMutableDictionaryRef 均为不透明指针。
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
    /// kCFBooleanTrue 单例地址（存 usize 而非裸指针：裸指针非 Send/Sync，
    /// 会破坏 `static KEYCHAIN: OnceLock`；地址本身是进程级单例，值安全）。
    k_cf_boolean_true: usize,
    /// kSec* 字典键单例地址（同上；SecItem 按身份识别键，见 `sec` 模块注释）。
    k_sec_class: usize,
    k_sec_class_generic_password: usize,
    k_sec_attr_service: usize,
    k_sec_attr_account: usize,
    k_sec_value_data: usize,
    k_sec_return_data: usize,
}

static KEYCHAIN: OnceLock<Result<KeychainDlls, KeychainError>> = OnceLock::new();

impl KeychainDlls {
    fn get() -> Result<&'static KeychainDlls, KeychainError> {
        KEYCHAIN
            .get_or_init(Self::load)
            .as_ref()
            .map_err(|e| match e {
                KeychainError::Load(_) => KeychainError::Load(e.to_string()),
                other => KeychainError::Load(other.to_string()),
            })
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

        // kCFBooleanTrue 是全局变量（`extern const CFBooleanRef`）：dlsym
        // 0.8 / macOS 10.14）：`Symbol<*const c_void>` 的 `*s` 得到的是
        // dlsym 符号地址本身，还需再解一层指针才是变量存储的常量值——
        // 单层解引用时 kCFBooleanTrue/kSec* 全部拿到符号地址（非法 CF
        // 对象），SecItem 返回 errSecParam(-50)。
        // SAFETY: 系统导出全局变量，类型为指针。
        let k_true_addr = unsafe { cf.get::<*const c_void>(b"kCFBooleanTrue") }
            .map(|s: Symbol<'_, *const c_void>| *s)
            .map_err(|e| KeychainError::Load(format!("symbol 'kCFBooleanTrue': {e}")))?;
        let k_true = unsafe { *(k_true_addr as *const *const c_void) };

        // kSec* 键常量（Security.framework 导出全局变量；同样需双层解引用，
        // 见上；存 usize 与 k_cf_boolean_true 同理保证 Send/Sync）。
        // SAFETY: 同 kCFBooleanTrue 模式，类型为 CFStringRef（指针）。
        macro_rules! global_sym {
            ($name:expr) => {{
                let n: &str = $name;
                let addr = unsafe { security.get::<*const c_void>(n.as_bytes()) }
                    .map(|s: Symbol<'_, *const c_void>| *s)
                    .map_err(|e| KeychainError::Load(format!("symbol '{n}': {e}")))?;
                (unsafe { *(addr as *const *const c_void) }) as usize
            }};
        }
        let k_sec_class = global_sym!(sec::CLASS);
        let k_sec_genp = global_sym!(sec::CLASS_GENERIC_PASSWORD);
        let k_sec_service = global_sym!(sec::ATTR_SERVICE);
        let k_sec_account = global_sym!(sec::ATTR_ACCOUNT);
        let k_sec_value = global_sym!(sec::VALUE_DATA);
        let k_sec_return = global_sym!(sec::RETURN_DATA);

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
            k_cf_boolean_true: k_true as usize,
            k_sec_class,
            k_sec_class_generic_password: k_sec_genp,
            k_sec_attr_service: k_sec_service,
            k_sec_attr_account: k_sec_account,
            k_sec_value_data: k_sec_value,
            k_sec_return_data: k_sec_return,
            _security: security,
            _cf: cf,
        })
    }
}

// ════════════════════════════════════════════════════════════════
// CF 对象安全封装（RAII 释放）
// ════════════════════════════════════════════════════════════════

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

/// CFMutableDictionaryRef 封装（Drop 时 CFRelease）。
///
/// callbacks 传 NULL：CF 文档明确 NULL → 使用系统默认
/// `kCFTypeDictionaryKeyCallBacks` / `kCFTypeDictionaryValueCallBacks`
/// （避免 dlsym 解析全局回调结构，行为与 CF 内部等价）。
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

    /// 加入键值对。键为 kSec* 单例常量指针（非新建 CFString，见 `sec`
    /// 模块注释）；值为任意 CF 对象（字典 retain）。
    fn add(&self, dlls: &KeychainDlls, key: *const c_void, value: *const c_void) {
        // SAFETY: dict 有效；CF 字典 add 时 retain key/value，调用后仍可释放
        // 传入对象（kCFType callbacks 语义）。
        unsafe { (dlls.cf_dictionary_add_value)(self.0, key, value) };
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

// ════════════════════════════════════════════════════════════════
// Keychain 存储（MAC-T006）
// ════════════════════════════════════════════════════════════════

/// Keychain 身份存储（M12-MAC MAC-T006 可选后端）。
pub struct MacosKeychain;

impl MacosKeychain {
    /// Security/CoreFoundation 框架是否可加载（S-05：后端选择探测用）。
    pub fn available() -> bool {
        KeychainDlls::get().is_ok()
    }

    /// 存储私钥原始字节到 Keychain（`kSecClassGenericPassword`，
    /// service+account 均由 `label` 派生）。
    ///
    /// 已存在同 label 条目时先删除再写入（幂等覆盖语义）。
    pub fn store_private_key(label: &str, key_data: &[u8]) -> Result<(), KeychainError> {
        let dlls = KeychainDlls::get()?;
        let _ = Self::delete_private_key(label); // 幂等覆盖：旧条目先删。

        let dict = CfDict::new(dlls)?;
        let service = CfString::new(dlls, label)?;
        let account = CfString::new(dlls, label)?;

        // SAFETY: key_data 在调用期间存活（CFDataCreate 会拷贝数据）。
        let data = unsafe {
            (dlls.cf_data_create)(ptr::null(), key_data.as_ptr(), key_data.len() as isize)
        };
        if data.is_null() {
            return Err(KeychainError::Malformed("CFDataCreate returned NULL".into()));
        }

        dict.add(dlls, dlls.k_sec_class as *const c_void, dlls.k_sec_class_generic_password as *const c_void);
        dict.add(dlls, dlls.k_sec_attr_service as *const c_void, service.0);
        dict.add(dlls, dlls.k_sec_attr_account as *const c_void, account.0);
        dict.add(dlls, dlls.k_sec_value_data as *const c_void, data);

        // SAFETY: attributes 为构造的字典。
        let status = unsafe { (dlls.sec_item_add)(dict.0, ptr::null_mut()) };
        // SAFETY: data 已被字典 retain；本处释放初始引用。
        unsafe { (dlls.cf_release)(data) };
        if status != osstatus::SUCCESS {
            return Err(KeychainError::Status(status));
        }
        Ok(())
    }

    /// 从 Keychain 读取私钥原始字节。
    ///
    /// 条目不存在 → [`KeychainError::Status`]（errSecItemNotFound = -25300）。
    pub fn load_private_key(label: &str) -> Result<Vec<u8>, KeychainError> {
        let dlls = KeychainDlls::get()?;

        let dict = CfDict::new(dlls)?;
        let service = CfString::new(dlls, label)?;
        let account = CfString::new(dlls, label)?;

        dict.add(dlls, dlls.k_sec_class as *const c_void, dlls.k_sec_class_generic_password as *const c_void);
        dict.add(dlls, dlls.k_sec_attr_service as *const c_void, service.0);
        dict.add(dlls, dlls.k_sec_attr_account as *const c_void, account.0);
        // kSecReturnData = kCFBooleanTrue（系统单例）。
        dict.add(dlls, dlls.k_sec_return_data as *const c_void, dlls.k_cf_boolean_true as *const c_void);

        let mut result: *mut c_void = ptr::null_mut();
        // SAFETY: query 为构造的字典。
        let status = unsafe { (dlls.sec_item_copy_matching)(dict.0, &mut result) };
        if status != osstatus::SUCCESS {
            return Err(KeychainError::Status(status));
        }
        if result.is_null() {
            return Err(KeychainError::Malformed(
                "SecItemCopyMatching returned NULL result".into(),
            ));
        }

        // 校验返回类型为 CFData。
        let type_id = unsafe { (dlls.cf_get_type_id)(result) };
        let data_type_id = unsafe { (dlls.cf_data_get_type_id)() };
        if type_id != data_type_id {
            // SAFETY: 非 CFData 也需释放。
            unsafe { (dlls.cf_release)(result) };
            return Err(KeychainError::Malformed(format!(
                "returned CFTypeID {type_id} != CFData {data_type_id}"
            )));
        }
        let len = unsafe { (dlls.cf_data_get_length)(result) };
        let bytes = unsafe { (dlls.cf_data_get_byte_ptr)(result) };
        let out = if len > 0 && !bytes.is_null() {
            // SAFETY: len 为 CFData 长度，指针有效。
            unsafe { std::slice::from_raw_parts(bytes, len as usize).to_vec() }
        } else {
            Vec::new()
        };
        // SAFETY: result 为本调用创建的 CF 对象。
        unsafe { (dlls.cf_release)(result) };
        Ok(out)
    }

    /// 删除 Keychain 中的私钥条目（不存在也返回 Ok——幂等）。
    pub fn delete_private_key(label: &str) -> Result<(), KeychainError> {
        let dlls = KeychainDlls::get()?;

        let dict = CfDict::new(dlls)?;
        let service = CfString::new(dlls, label)?;
        let account = CfString::new(dlls, label)?;

        dict.add(dlls, dlls.k_sec_class as *const c_void, dlls.k_sec_class_generic_password as *const c_void);
        dict.add(dlls, dlls.k_sec_attr_service as *const c_void, service.0);
        dict.add(dlls, dlls.k_sec_attr_account as *const c_void, account.0);

        // SAFETY: query 为构造的字典。
        let status = unsafe { (dlls.sec_item_delete)(dict.0) };
        if status != osstatus::SUCCESS && status != osstatus::ITEM_NOT_FOUND {
            return Err(KeychainError::Status(status));
        }
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════
// S-05 (F-4)：KeyStore trait 接入（macOS 默认后端）
// ════════════════════════════════════════════════════════════════

fn map_keychain_err(e: KeychainError) -> KeyStoreError {
    match e {
        KeychainError::Load(msg) => KeyStoreError::Backend(msg),
        KeychainError::Status(code) => KeyStoreError::Backend(format!("Keychain OSStatus={code}")),
        KeychainError::Malformed(msg) => KeyStoreError::Corrupt(msg),
    }
}

impl KeyStore for MacosKeychain {
    fn set(&self, label: &str, secret: &[u8]) -> Result<(), KeyStoreError> {
        Self::store_private_key(label, secret).map_err(map_keychain_err)
    }

    fn get(&self, label: &str) -> Result<Option<Vec<u8>>, KeyStoreError> {
        match Self::load_private_key(label) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(KeychainError::Status(osstatus::ITEM_NOT_FOUND)) => Ok(None),
            Err(e) => Err(map_keychain_err(e)),
        }
    }

    fn delete(&self, label: &str) -> Result<(), KeyStoreError> {
        Self::delete_private_key(label).map_err(map_keychain_err)
    }
}
