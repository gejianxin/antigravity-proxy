use std::ffi::{CStr, CString};
use std::os::raw::c_char;

pub const SO_NAME: &str = "libantigravity_proxy.so";

pub fn filter_preload_list(value: &str, so_name: &str) -> String {
    value
        .split(':')
        .map(str::trim)
        .filter(|part| !part.is_empty() && file_name(part) != so_name)
        .collect::<Vec<_>>()
        .join(":")
}

fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

struct EnvBlock {
    _owned: Vec<CString>,
    ptrs: Vec<*const c_char>,
}

impl EnvBlock {
    unsafe fn from_envp(envp: *const *const c_char) -> Self {
        let mut owned = Vec::new();
        if !envp.is_null() {
            let mut idx = 0;
            loop {
                let item = *envp.add(idx);
                if item.is_null() {
                    break;
                }
                if let Ok(text) = CStr::from_ptr(item).to_str() {
                    if let Some(value) = text.strip_prefix("LD_PRELOAD=") {
                        let filtered = filter_preload_list(value, SO_NAME);
                        if !filtered.is_empty() {
                            if let Ok(entry) = CString::new(format!("LD_PRELOAD={filtered}")) {
                                owned.push(entry);
                            }
                        }
                    } else if let Ok(entry) = CString::new(text) {
                        owned.push(entry);
                    }
                }
                idx += 1;
            }
        }
        let ptrs: Vec<*const c_char> = owned.iter().map(|s| s.as_ptr()).collect();
        let mut block = Self {
            _owned: owned,
            ptrs,
        };
        block.ptrs.push(std::ptr::null());
        block
    }

    fn as_ptr(&self) -> *const *const c_char {
        self.ptrs.as_ptr()
    }
}

unsafe fn environ_ptr() -> *const *const c_char {
    libc::environ as *const *const c_char
}

pub unsafe fn hook_execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> libc::c_int {
    if crate::guard::in_hook() || crate::get_config().child_injection {
        return crate::ffi::real_execve(path, argv, envp);
    }
    let _guard = crate::guard::Guard::enter();
    let block = EnvBlock::from_envp(envp);
    crate::ffi::real_execve(path, argv, block.as_ptr())
}

pub unsafe fn hook_execv(path: *const c_char, argv: *const *const c_char) -> libc::c_int {
    hook_execve(path, argv, environ_ptr())
}

pub unsafe fn hook_execvp(file: *const c_char, argv: *const *const c_char) -> libc::c_int {
    if crate::guard::in_hook() || crate::get_config().child_injection {
        return crate::ffi::real_execvpe(file, argv, environ_ptr());
    }
    let _guard = crate::guard::Guard::enter();
    let block = EnvBlock::from_envp(environ_ptr());
    crate::ffi::real_execvpe(file, argv, block.as_ptr())
}

pub unsafe fn hook_execvpe(
    file: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> libc::c_int {
    if crate::guard::in_hook() || crate::get_config().child_injection {
        return crate::ffi::real_execvpe(file, argv, envp);
    }
    let _guard = crate::guard::Guard::enter();
    let block = EnvBlock::from_envp(envp);
    crate::ffi::real_execvpe(file, argv, block.as_ptr())
}

pub unsafe fn hook_fexecve(
    fd: libc::c_int,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> libc::c_int {
    if crate::guard::in_hook() || crate::get_config().child_injection {
        return crate::ffi::real_fexecve(fd, argv, envp);
    }
    let _guard = crate::guard::Guard::enter();
    let block = EnvBlock::from_envp(envp);
    crate::ffi::real_fexecve(fd, argv, block.as_ptr())
}

pub unsafe fn hook_posix_spawn(
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const libc::c_void,
    attrp: *const libc::c_void,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
    search_path: bool,
) -> libc::c_int {
    let call = if search_path {
        crate::ffi::real_posix_spawnp
    } else {
        crate::ffi::real_posix_spawn
    };
    if crate::guard::in_hook() || crate::get_config().child_injection {
        return call(pid, path, file_actions, attrp, argv, envp);
    }
    let _guard = crate::guard::Guard::enter();
    let block = EnvBlock::from_envp(envp as *const *const c_char);
    let mut ptrs: Vec<*mut c_char> = block.ptrs.iter().map(|p| *p as *mut c_char).collect();
    call(pid, path, file_actions, attrp, argv, ptrs.as_mut_ptr())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_only_this_library() {
        let filtered = filter_preload_list(
            "/tmp/libantigravity_proxy.so:/usr/lib/libother.so:libantigravity_proxy.so",
            SO_NAME,
        );
        assert_eq!(filtered, "/usr/lib/libother.so");
    }
}
