//! Import-address-table patches.
//!
//! The DLL is loaded before the host entry point (search-order hijack) or while
//! the new process is still suspended (remote `LoadLibraryW`). Patching every
//! loaded module's IAT, and interposing `GetProcAddress` / `LoadLibrary*`,
//! catches both static imports and later dynamic lookups without copying MinHook.

use std::ffi::c_void;

use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use windows_sys::Win32::System::ProcessStatus::K32EnumProcessModules;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use super::log;

pub fn patch_loaded(our: *mut u8, want: &dyn Fn(&str, &str) -> Option<usize>) -> usize {
    let mut modules = [std::ptr::null_mut(); 512];
    let mut needed = 0u32;
    let bytes = (modules.len() * std::mem::size_of::<*mut u8>()) as u32;
    let ok = unsafe {
        K32EnumProcessModules(
            GetCurrentProcess(),
            modules.as_mut_ptr(),
            bytes,
            &mut needed,
        )
    };
    if ok == 0 {
        log::warn(&format!("EnumProcessModules 失败 ({})", unsafe {
            GetLastError()
        }));
        return 0;
    }
    let count = (needed as usize / std::mem::size_of::<*mut u8>()).min(modules.len());
    let mut patched = 0usize;
    for module in modules.iter().take(count) {
        patched += unsafe { patch_module(*module as *mut u8, our, want) };
    }
    patched
}

unsafe fn patch_module(
    base: *mut u8,
    our: *mut u8,
    want: &dyn Fn(&str, &str) -> Option<usize>,
) -> usize {
    if base.is_null() || base == our {
        return 0;
    }
    if (base as usize) < 0x10000 {
        return 0;
    }
    if std::ptr::read_unaligned(base as *const u16) != 0x5A4D {
        return 0;
    }
    let lfanew = std::ptr::read_unaligned(base.add(0x3C) as *const i32);
    if lfanew <= 0 || lfanew > 0x2000 {
        return 0;
    }
    let nt = base.add(lfanew as usize);
    if std::ptr::read_unaligned(nt as *const u32) != 0x0000_4550 {
        return 0;
    }
    let magic = std::ptr::read_unaligned(nt.add(24) as *const u16);
    if magic != 0x20B {
        return 0;
    }
    let import_rva = std::ptr::read_unaligned(nt.add(24 + 120) as *const u32);
    if import_rva == 0 {
        return 0;
    }
    let mut patched = 0usize;
    let mut desc = base.add(import_rva as usize);
    for _ in 0..512 {
        let oft = std::ptr::read_unaligned(desc as *const u32);
        let name_rva = std::ptr::read_unaligned(desc.add(12) as *const u32);
        let first_thunk = std::ptr::read_unaligned(desc.add(16) as *const u32);
        if name_rva == 0 || first_thunk == 0 {
            break;
        }
        let dll = read_cstr(base, name_rva).unwrap_or_default();
        let name_thunk = if oft == 0 { first_thunk } else { oft };
        let mut index = 0usize;
        loop {
            let entry_ptr = base.add(name_thunk as usize + index * 8);
            let entry = std::ptr::read_unaligned(entry_ptr as *const u64);
            if entry == 0 {
                break;
            }
            if entry & (1u64 << 63) == 0 {
                if let Some(func) = read_cstr(base, (entry as u32).wrapping_add(2)) {
                    if let Some(detour) = want(&dll, &func) {
                        let slot = base.add(first_thunk as usize + index * 8) as *mut u64;
                        let current = std::ptr::read_unaligned(slot);
                        if current != 0 && current != detour as u64 {
                            if write_slot(slot, detour as u64) {
                                patched += 1;
                            }
                        }
                    }
                }
            }
            index += 1;
            if index > 4096 {
                break;
            }
        }
        desc = desc.add(20);
    }
    patched
}

unsafe fn write_slot(slot: *mut u64, value: u64) -> bool {
    let mut old = 0u32;
    if VirtualProtect(slot as *mut c_void, 8, PAGE_READWRITE, &mut old) == 0
        && VirtualProtect(slot as *mut c_void, 8, PAGE_EXECUTE_READWRITE, &mut old) == 0
    {
        return false;
    }
    std::ptr::write_unaligned(slot, value);
    let mut ignored = 0u32;
    VirtualProtect(slot as *mut c_void, 8, old, &mut ignored);
    true
}

unsafe fn read_cstr(base: *const u8, rva: u32) -> Option<String> {
    if rva == 0 {
        return None;
    }
    let ptr = base.add(rva as usize);
    let mut len = 0usize;
    while len < 260 && *ptr.add(len) != 0 {
        len += 1;
    }
    let bytes = std::slice::from_raw_parts(ptr, len);
    Some(String::from_utf8_lossy(bytes).into_owned())
}
