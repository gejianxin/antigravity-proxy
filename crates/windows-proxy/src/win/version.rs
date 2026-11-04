//! Forward the public `version.dll` exports to the copy in System32.
//!
//! These names are the Win32 version-info API. The DLL search-order hijack only
//! works when every export the host imports is present and still reaches the
//! system implementation.

use std::sync::OnceLock;

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

use super::wide;

static SYSTEM: OnceLock<usize> = OnceLock::new();

fn system_module() -> HMODULE {
    *SYSTEM.get_or_init(|| unsafe {
        let mut dir = [0u16; 520];
        let n = GetSystemDirectoryW(dir.as_mut_ptr(), dir.len() as u32);
        if n == 0 || n as usize + 16 >= dir.len() {
            return 0;
        }
        let mut path = String::from_utf16_lossy(&dir[..n as usize]);
        path.push_str("\\version.dll");
        let wide_path = wide(&path);
        LoadLibraryW(wide_path.as_ptr()) as usize
    }) as HMODULE
}

unsafe fn proc(name: &[u8]) -> usize {
    let module = system_module();
    if module.is_null() {
        return 0;
    }
    GetProcAddress(module, name.as_ptr())
        .map(|fp| fp as usize)
        .unwrap_or(0)
}

macro_rules! forward {
    ($name:ident ( $($arg:ident : $ty:ty),* ) -> $ret:ty) => {
        #[no_mangle]
        pub unsafe extern "system" fn $name($($arg: $ty),*) -> $ret {
            type Fn = unsafe extern "system" fn($($ty),*) -> $ret;
            let fp = proc(concat!(stringify!($name), "\0").as_bytes());
            if fp == 0 {
                return std::mem::zeroed();
            }
            let f: Fn = std::mem::transmute(fp);
            f($($arg),*)
        }
    };
}

forward!(GetFileVersionInfoA(name: *const u8, handle: u32, len: u32, data: *mut core::ffi::c_void) -> i32);
forward!(GetFileVersionInfoW(name: *const u16, handle: u32, len: u32, data: *mut core::ffi::c_void) -> i32);
forward!(GetFileVersionInfoByHandle(flags: u32, file: *mut core::ffi::c_void, data: *mut core::ffi::c_void, len: u32) -> i32);
forward!(GetFileVersionInfoExA(flags: u32, name: *const u8, handle: u32, len: u32, data: *mut core::ffi::c_void) -> i32);
forward!(GetFileVersionInfoExW(flags: u32, name: *const u16, handle: u32, len: u32, data: *mut core::ffi::c_void) -> i32);
forward!(GetFileVersionInfoSizeA(name: *const u8, handle: *mut u32) -> u32);
forward!(GetFileVersionInfoSizeW(name: *const u16, handle: *mut u32) -> u32);
forward!(GetFileVersionInfoSizeExA(flags: u32, name: *const u8, handle: *mut u32) -> u32);
forward!(GetFileVersionInfoSizeExW(flags: u32, name: *const u16, handle: *mut u32) -> u32);
forward!(VerFindFileA(
    flags: u32,
    file: *const u8,
    windir: *const u8,
    appdir: *const u8,
    curdir: *mut u8,
    curlen: *mut u32,
    destdir: *mut u8,
    destlen: *mut u32
) -> u32);
forward!(VerFindFileW(
    flags: u32,
    file: *const u16,
    windir: *const u16,
    appdir: *const u16,
    curdir: *mut u16,
    curlen: *mut u32,
    destdir: *mut u16,
    destlen: *mut u32
) -> u32);
forward!(VerInstallFileA(
    flags: u32,
    src: *const u8,
    dest: *const u8,
    srcdir: *const u8,
    destdir: *const u8,
    curdir: *const u8,
    tmp: *mut u8,
    tmplen: *mut u32
) -> u32);
forward!(VerInstallFileW(
    flags: u32,
    src: *const u16,
    dest: *const u16,
    srcdir: *const u16,
    destdir: *const u16,
    curdir: *const u16,
    tmp: *mut u16,
    tmplen: *mut u32
) -> u32);
forward!(VerLanguageNameA(lang: u32, buf: *mut u8, buflen: u32) -> u32);
forward!(VerLanguageNameW(lang: u32, buf: *mut u16, buflen: u32) -> u32);
forward!(VerQueryValueA(block: *const core::ffi::c_void, sub: *const u8, buf: *mut *mut core::ffi::c_void, len: *mut u32) -> i32);
forward!(VerQueryValueW(block: *const core::ffi::c_void, sub: *const u16, buf: *mut *mut core::ffi::c_void, len: *mut u32) -> i32);
