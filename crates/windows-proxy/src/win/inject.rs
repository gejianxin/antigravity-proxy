use std::ffi::CString;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FALSE, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, WaitForSingleObject,
};

use super::wide;

pub fn inject_dll(process: HANDLE, dll_path: &str) -> Result<(), String> {
    if process.is_null() || dll_path.is_empty() {
        return Err("missing process or dll path".into());
    }
    let wide_path = wide(dll_path);
    let bytes = wide_path.len() * 2;
    unsafe {
        let remote = VirtualAllocEx(
            process,
            std::ptr::null(),
            bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote.is_null() {
            return Err(format!("VirtualAllocEx failed ({})", GetLastError()));
        }
        let mut written = 0usize;
        let ok = WriteProcessMemory(
            process,
            remote,
            wide_path.as_ptr() as *const _,
            bytes,
            &mut written,
        );
        if ok == FALSE || written != bytes {
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            return Err(format!("WriteProcessMemory failed ({})", GetLastError()));
        }
        let kernel = wide("kernel32.dll");
        let module = GetModuleHandleW(kernel.as_ptr());
        let name = CString::new("LoadLibraryW").map_err(|e| e.to_string())?;
        let load = GetProcAddress(module, name.as_ptr() as *const u8);
        let Some(load) = load else {
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            return Err("LoadLibraryW not found".into());
        };
        let start = Some(std::mem::transmute::<
            unsafe extern "system" fn() -> isize,
            unsafe extern "system" fn(*mut core::ffi::c_void) -> u32,
        >(load));
        let thread = CreateRemoteThread(
            process,
            std::ptr::null(),
            0,
            start,
            remote,
            0,
            std::ptr::null_mut(),
        );
        if thread.is_null() {
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            return Err(format!("CreateRemoteThread failed ({})", GetLastError()));
        }
        let wait = WaitForSingleObject(thread, 15_000);
        let mut code = 0u32;
        GetExitCodeThread(thread, &mut code);
        CloseHandle(thread);
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        if wait != WAIT_OBJECT_0 || code == 0 {
            return Err(format!(
                "remote LoadLibraryW failed (wait={wait}, module={code})"
            ));
        }
        Ok(())
    }
}
