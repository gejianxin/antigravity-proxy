//! Keep or drop `DYLD_INSERT_LIBRARIES` for child processes.
//!
//! Unrestricted children inherit the variable. macOS itself strips `DYLD_*`
//! when the child is SIP-protected or signed with library validation; this
//! code cannot override that.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use super::hooks;

const LIB_NAME: &str = "libantigravity_proxy.dylib";

pub unsafe fn spawn(
    pid: *mut i32,
    path: *const c_char,
    file_actions: *const libc::c_void,
    attrp: *const libc::c_void,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> i32 {
    if hooks::config().child_injection {
        return call(pid, path, file_actions, attrp, argv, envp);
    }
    let owned = filtered_env(envp);
    let mut ptrs: Vec<*mut c_char> = owned.iter().map(|s| s.as_ptr() as *mut c_char).collect();
    ptrs.push(std::ptr::null_mut());
    call(pid, path, file_actions, attrp, argv, ptrs.as_ptr())
}

pub unsafe fn execve(
    path: *const c_char,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> i32 {
    type Fn = unsafe extern "C" fn(*const c_char, *const *mut c_char, *const *mut c_char) -> i32;
    let fp = hooks::sym("execve");
    if fp == 0 {
        set_errno(libc::ENOENT);
        return -1;
    }
    let f: Fn = std::mem::transmute(fp);
    if hooks::config().child_injection {
        return f(path, argv, envp);
    }
    let owned = filtered_env(envp);
    let mut ptrs: Vec<*mut c_char> = owned.iter().map(|s| s.as_ptr() as *mut c_char).collect();
    ptrs.push(std::ptr::null_mut());
    f(path, argv, ptrs.as_ptr())
}

unsafe fn call(
    pid: *mut i32,
    path: *const c_char,
    file_actions: *const libc::c_void,
    attrp: *const libc::c_void,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> i32 {
    type Fn = unsafe extern "C" fn(
        *mut i32,
        *const c_char,
        *const libc::c_void,
        *const libc::c_void,
        *const *mut c_char,
        *const *mut c_char,
    ) -> i32;
    let fp = hooks::sym("posix_spawn");
    if fp == 0 {
        return libc::EAGAIN;
    }
    let f: Fn = std::mem::transmute(fp);
    f(pid, path, file_actions, attrp, argv, envp)
}

unsafe fn filtered_env(envp: *const *mut c_char) -> Vec<CString> {
    let mut out = Vec::new();
    if envp.is_null() {
        for (key, value) in std::env::vars() {
            push_pair(&mut out, &key, &value);
        }
        return out;
    }
    let mut idx = 0usize;
    loop {
        let item = *envp.add(idx);
        if item.is_null() {
            break;
        }
        if let Ok(text) = CStr::from_ptr(item).to_str() {
            if let Some((key, value)) = text.split_once('=') {
                push_pair(&mut out, key, value);
            }
        }
        idx += 1;
    }
    out
}

fn push_pair(out: &mut Vec<CString>, key: &str, value: &str) {
    if key == "DYLD_INSERT_LIBRARIES" {
        let filtered = value
            .split(':')
            .map(str::trim)
            .filter(|part| !part.is_empty() && file_name(part) != LIB_NAME)
            .collect::<Vec<_>>()
            .join(":");
        if filtered.is_empty() {
            return;
        }
        if let Ok(entry) = CString::new(format!("DYLD_INSERT_LIBRARIES={filtered}")) {
            out.push(entry);
        }
        return;
    }
    if let Ok(entry) = CString::new(format!("{key}={value}")) {
        out.push(entry);
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn set_errno(code: i32) {
    unsafe {
        *libc::__error() = code;
    }
}
