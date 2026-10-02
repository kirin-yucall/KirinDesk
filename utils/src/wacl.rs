//! （手写 advapi32/kernel32 FFI，不引 windows-rs；仅 `cfg(windows)` 编译）。
//!
//! [`crate::fsutil::write_private`] 在 Windows 臂 rename 成功后调用
//! [`tighten_private_dacl`]：`SetNamedSecurityInfoW` +
//! `PROTECTED_DACL_SECURITY_INFORMATION` 移除 ACL 继承（阻止从父目录继承
//! `Users`/`Everyone` 等宽权 ACE），显式仅保留**当前用户 + SYSTEM 完全控制**。
//! **best-effort 定性**：任一步失败返回 `Err`，调用方仅 `tracing::warn!`
//! 一致：可用性优先）。
//!
//! 权限预期（客户端私密文件清单与备份红线见 `release/README.md`
//! 「安全要点」节）：`.kirin_desk` 用户目录内私密文件（identity.masterkey、
//! identity blob、known_hosts、设备存储、临时挑战码状态等）落盘后 DACL
//! 受保护，仅当前用户与 SYSTEM 可访问。跨平台口径：Unix 臂维持 0600/0700
//! 零变化（umodel 默认权限语义），本模块不参与。

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use std::path::Path;

type BOOL = i32;
type DWORD = u32;
type WORD = u16;
type HANDLE = *mut core::ffi::c_void;
type PSID = *mut core::ffi::c_void;
type PACL = *mut ACL;
type PSECURITY_DESCRIPTOR = *mut core::ffi::c_void;
type HLOCAL = *mut core::ffi::c_void;
type PCWSTR = *const u16;

const ERROR_SUCCESS: DWORD = 0;
const SE_FILE_OBJECT: i32 = 1;
const OWNER_SECURITY_INFORMATION: DWORD = 0x0000_0001;
const DACL_SECURITY_INFORMATION: DWORD = 0x0000_0004;
const PROTECTED_DACL_SECURITY_INFORMATION: DWORD = 0x8000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const SET_ACCESS: i32 = 2;
const NO_INHERITANCE: u32 = 0;
const TRUSTEE_IS_SID: i32 = 0;
const TRUSTEE_IS_USER: i32 = 1;
const TRUSTEE_IS_WELL_KNOWN_GROUP: i32 = 5;
const TOKEN_QUERY: DWORD = 0x0008;
const TOKEN_USER_CLASS: i32 = 1;
const SECURITY_DESCRIPTOR_REVISION: DWORD = 1;
// SECURITY_DESCRIPTOR_MIN_LENGTH = sizeof(SECURITY_DESCRIPTOR)：
// x64=40 / x86=20（Revision+Sbz1+Control+4 指针字段）——按目标指针宽度取值，
// 短分配会在 InitializeSecurityDescriptor 时越界写（堆破坏）。
const SECURITY_DESCRIPTOR_MIN_LENGTH: usize = 5 * core::mem::size_of::<usize>();
const LPTR: u32 = 0x0040; // LMEM_FIXED | LMEM_ZEROINIT
const SE_DACL_PROTECTED: WORD = 0x1000;

#[repr(C)]
struct ACL {
    AclRevision: u8,
    Sbz1: u8,
    AclSize: u16,
    AceCount: u16,
    Sbz2: u16,
}

#[repr(C)]
struct TRUSTEE_W {
    pMultipleTrustee: *mut core::ffi::c_void,
    MultipleTrusteeOperation: i32,
    TrusteeForm: i32,
    TrusteeType: i32,
    ptstrName: *mut core::ffi::c_void,
}

#[repr(C)]
struct EXPLICIT_ACCESS_W {
    grfAccessPermissions: u32,
    grfAccessMode: i32,
    grfInheritance: u32,
    Trustee: TRUSTEE_W,
}

#[repr(C)]
struct SID_AND_ATTRIBUTES {
    Sid: PSID,
    Attributes: u32,
}

#[repr(C)]
struct TOKEN_USER {
    User: SID_AND_ATTRIBUTES,
}

#[link(name = "advapi32")]
extern "system" {
    fn SetEntriesInAclW(
        cCountOfExplicitEntries: DWORD,
        pListOfExplicitEntries: *mut EXPLICIT_ACCESS_W,
        OldAcl: PACL,
        NewAcl: *mut PACL,
    ) -> DWORD;
    fn SetNamedSecurityInfoW(
        pObjectName: PCWSTR,
        ObjectType: i32,
        SecurityInfo: DWORD,
        psidOwner: PSID,
        psidGroup: PSID,
        pDacl: PACL,
        pSacl: PACL,
    ) -> DWORD;
    fn GetNamedSecurityInfoW(
        pObjectName: PCWSTR,
        ObjectType: i32,
        SecurityInfo: DWORD,
        ppsidOwner: *mut PSID,
        ppsidGroup: *mut PSID,
        ppDacl: *mut PACL,
        ppSacl: *mut PACL,
        ppSecurityDescriptor: *mut PSECURITY_DESCRIPTOR,
    ) -> DWORD;
    fn GetSecurityDescriptorControl(
        pSecurityDescriptor: PSECURITY_DESCRIPTOR,
        pControl: *mut WORD,
        pdwRevision: *mut DWORD,
    ) -> BOOL;
    fn GetAce(pAcl: PACL, dwAceIndex: DWORD, pAce: *mut *mut core::ffi::c_void) -> BOOL;
    fn GetLengthSid(pSid: PSID) -> DWORD;
    fn ConvertStringSidToSidW(StringSid: PCWSTR, Sid: *mut PSID) -> BOOL;
    fn OpenProcessToken(
        ProcessHandle: HANDLE,
        DesiredAccess: DWORD,
        TokenHandle: *mut HANDLE,
    ) -> BOOL;
    fn GetTokenInformation(
        TokenHandle: HANDLE,
        TokenInformationClass: i32,
        TokenInformation: *mut core::ffi::c_void,
        TokenInformationLength: DWORD,
        ReturnLength: *mut DWORD,
    ) -> BOOL;
    fn InitializeSecurityDescriptor(
        pSecurityDescriptor: PSECURITY_DESCRIPTOR,
        dwRevision: DWORD,
    ) -> BOOL;
    fn SetSecurityDescriptorOwner(
        pSecurityDescriptor: PSECURITY_DESCRIPTOR,
        pOwner: PSID,
        bOwnerDefaulted: BOOL,
    ) -> BOOL;
    fn SetSecurityDescriptorDacl(
        pSecurityDescriptor: PSECURITY_DESCRIPTOR,
        bDaclPresent: BOOL,
        pDacl: PACL,
        bDaclDefaulted: BOOL,
    ) -> BOOL;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> HANDLE;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
    fn LocalAlloc(uFlags: u32, uBytes: usize) -> HLOCAL;
    fn LocalFree(hMem: HLOCAL) -> HLOCAL;
}

fn to_wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt as _;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn last_err(what: &str, code: DWORD) -> String {
    format!("{what} failed (Win32 code {code})")
}

/// 当前用户 SID 字节（`TokenUser`；供收紧与测试共用）。
pub fn current_user_sid_bytes() -> Result<Vec<u8>, String> {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(last_err("OpenProcessToken", 0));
        }
        let mut len: DWORD = 0;
        let _ = GetTokenInformation(token, TOKEN_USER_CLASS, std::ptr::null_mut(), 0, &mut len);
        if len == 0 {
            CloseHandle(token);
            return Err("GetTokenInformation sizing returned 0".into());
        }
        let buf = LocalAlloc(LPTR, len as usize);
        if buf.is_null() {
            CloseHandle(token);
            return Err("LocalAlloc(token buffer) failed".into());
        }
        let mut ret: DWORD = 0;
        let ok = GetTokenInformation(token, TOKEN_USER_CLASS, buf, len, &mut ret);
        CloseHandle(token);
        if ok == 0 {
            LocalFree(buf);
            return Err(last_err("GetTokenInformation", 0));
        }
        let tu = buf as *const TOKEN_USER;
        let sid = (*tu).User.Sid;
        let n = GetLengthSid(sid) as usize;
        let out = std::slice::from_raw_parts(sid as *const u8, n).to_vec();
        LocalFree(buf);
        Ok(out)
    }
}

/// DACL 查询报告（测试断言面 + WARN 探测复用）。
pub struct AclReport {
    /// DACL 受保护（继承被阻止，`SE_DACL_PROTECTED`）。
    pub dacl_protected: bool,
    /// 逐 ACE：SID 字节 / 访问掩码 / ACE 类型（0=ACCESS_ALLOWED）。
    pub aces: Vec<(Vec<u8>, u32, u8)>,
}

/// 查询文件 DACL（`GetNamedSecurityInfoW`；仅读，不改任何权限位）。
pub fn query_dacl(path: &Path) -> Result<AclReport, String> {
    let wide = to_wide(&path.to_string_lossy());
    unsafe {
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let mut pacl: PACL = std::ptr::null_mut();
        let code = GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut pacl,
            std::ptr::null_mut(),
            &mut psd,
        );
        if code != ERROR_SUCCESS {
            return Err(last_err("GetNamedSecurityInfoW", code));
        }
        let mut control: WORD = 0;
        let mut rev: DWORD = 0;
        let protected = GetSecurityDescriptorControl(psd, &mut control, &mut rev) != 0
            && (control & SE_DACL_PROTECTED) != 0;
        let mut aces = Vec::new();
        if !pacl.is_null() {
            let count = (*pacl).AceCount as u32;
            for i in 0..count {
                let mut pace: *mut core::ffi::c_void = std::ptr::null_mut();
                if GetAce(pacl, i, &mut pace) == 0 {
                    LocalFree(psd);
                    return Err(last_err("GetAce", 0));
                }
                // ACE 布局：AceType(1) AceFlags(1) AceSize(2) AccessMask(4) Sid…
                let base = pace as *const u8;
                let ace_type = *base;
                let mask = core::ptr::read_unaligned(base.add(4) as *const u32);
                let psid_ace = base.add(8) as PSID;
                let n = GetLengthSid(psid_ace) as usize;
                let sid = std::slice::from_raw_parts(psid_ace as *const u8, n).to_vec();
                aces.push((sid, mask, ace_type));
            }
        }
        LocalFree(psd);
        Ok(AclReport {
            dacl_protected: protected,
            aces,
        })
    }
}

/// 私密文件 DACL 收紧（best-effort）：移除继承（`PROTECTED_DACL`）+
/// 显式仅「当前用户 + SYSTEM」`GENERIC_ALL`。失败返回 Err 文本，
/// 调用方（fsutil::write_private）仅 WARN 不致命。
pub fn tighten_private_dacl(path: &Path) -> Result<(), String> {
    let wide = to_wide(&path.to_string_lossy());
    unsafe {
        // 1. 当前用户 SID（TokenUser）。
        let user_sid = alloc_current_user_sid()?;
        // 2. SYSTEM SID（S-1-5-18）。
        let mut sys_sid: PSID = std::ptr::null_mut();
        let s_wide = to_wide("S-1-5-18");
        if ConvertStringSidToSidW(s_wide.as_ptr(), &mut sys_sid) == 0 {
            LocalFree(user_sid);
            return Err(last_err("ConvertStringSidToSidW", 0));
        }
        // 3. 显式 ACE ×2 → 全新 ACL（无继承基底）。
        let mut ea = [
            EXPLICIT_ACCESS_W {
                grfAccessPermissions: GENERIC_ALL,
                grfAccessMode: SET_ACCESS,
                grfInheritance: NO_INHERITANCE,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: std::ptr::null_mut(),
                    MultipleTrusteeOperation: 0,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_USER,
                    ptstrName: user_sid,
                },
            },
            EXPLICIT_ACCESS_W {
                grfAccessPermissions: GENERIC_ALL,
                grfAccessMode: SET_ACCESS,
                grfInheritance: NO_INHERITANCE,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: std::ptr::null_mut(),
                    MultipleTrusteeOperation: 0,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                    ptstrName: sys_sid,
                },
            },
        ];
        let mut acl: PACL = std::ptr::null_mut();
        let code = SetEntriesInAclW(2, ea.as_mut_ptr(), std::ptr::null_mut(), &mut acl);
        if code != ERROR_SUCCESS {
            LocalFree(sys_sid);
            LocalFree(user_sid);
            return Err(last_err("SetEntriesInAclW", code));
        }
        // 4. 自建 SD（owner = 当前用户；DACL = 上步 ACL）。
        let sd = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
        if sd.is_null() {
            LocalFree(acl as HLOCAL);
            LocalFree(sys_sid);
            LocalFree(user_sid);
            return Err("LocalAlloc(SD) failed".into());
        }
        if InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION) == 0
            || SetSecurityDescriptorOwner(sd, user_sid, 0) == 0
            || SetSecurityDescriptorDacl(sd, 1, acl, 0) == 0
        {
            LocalFree(sd);
            LocalFree(acl as HLOCAL);
            LocalFree(sys_sid);
            LocalFree(user_sid);
            return Err("SD init failed".into());
        }
        // 5. 一次性写入 owner + 受保护 DACL（继承被移除）。
        let code = SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            user_sid,
            std::ptr::null_mut(),
            acl,
            std::ptr::null_mut(),
        );
        LocalFree(sd);
        LocalFree(acl as HLOCAL);
        LocalFree(sys_sid);
        LocalFree(user_sid);
        if code != ERROR_SUCCESS {
            return Err(last_err("SetNamedSecurityInfoW", code));
        }
        Ok(())
    }
}

unsafe fn alloc_current_user_sid() -> Result<PSID, String> {
    let bytes = current_user_sid_bytes()?;
    let buf = LocalAlloc(LPTR, bytes.len());
    if buf.is_null() {
        return Err("LocalAlloc(SID) failed".into());
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, bytes.len());
    Ok(buf)
}

#[cfg(windows)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::write_private;

    /// 把字符串 SID（如 S-1-1-0）转为字节，用于 ACE 匹配（本地无关化）。
    fn sid_bytes_of(s: &str) -> Vec<u8> {
        unsafe {
            let mut psid: PSID = std::ptr::null_mut();
            let wide = to_wide(s);
            assert_ne!(ConvertStringSidToSidW(wide.as_ptr(), &mut psid), 0);
            let n = GetLengthSid(psid) as usize;
            let v = std::slice::from_raw_parts(psid as *const u8, n).to_vec();
            LocalFree(psid);
            v
        }
    }

    /// 当前用户 + SYSTEM 完全控制，**无** Everyone/Users/Authenticated
    /// Users 读取 ACE（SID 比对，本地化无关）；当前用户仍可正常读写。
    #[test]
    fn test_r185_write_private_windows_acl_restricted() {
        let root = std::env::temp_dir().join(format!(
            "kirin_r185_acl_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("identity.masterkey");
        write_private(&path, b"r185-secret").unwrap();

        // 当前用户读写不受影响（收紧 ≠ 自锁）。
        assert_eq!(std::fs::read(&path).unwrap(), b"r185-secret");
        write_private(&path, b"r185-secret-2").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"r185-secret-2");

        let rep = query_dacl(&path).expect("query_dacl");
        assert!(rep.dacl_protected, "DACL 必须受保护（继承已移除）");

        let everyone = sid_bytes_of("S-1-1-0");
        let auth_users = sid_bytes_of("S-1-5-11");
        let users = sid_bytes_of("S-1-5-32-545");
        let me = current_user_sid_bytes().unwrap();
        let system = sid_bytes_of("S-1-5-18");

        let has = |sid: &[u8], mask: u32| {
            rep.aces
                .iter()
                .any(|(s, m, t)| *t == 0 /* ACCESS_ALLOWED */ && s.as_slice() == sid && m & mask != 0)
        };
        // SetEntriesInAclW 对文件对象把 GENERIC_ALL 具体化为 FILE_ALL_ACCESS。
        const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
        assert!(has(&me, FILE_ALL_ACCESS), "当前用户必须完全控制");
        assert!(has(&system, FILE_ALL_ACCESS), "SYSTEM 必须完全控制");
        for (name, sid) in [("Everyone", &everyone), ("Authenticated Users", &auth_users), ("Users", &users)] {
            assert!(
                !rep.aces.iter().any(|(s, _, _)| s == sid),
                "不得残留 {name} ACE"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
