//! Windows x64 proxy DLL.
//!
//! The crate is named `version` so the linked image is `version.dll`, which
//! Antigravity loads through the normal DLL search order. Winsock is hooked by
//! patching import tables (and `GetProcAddress`) rather than by vendoring MinHook.
//! On non-Windows hosts the crate builds as an empty stub so `cargo test --workspace`
//! still works.

#[cfg(windows)]
mod win;

#[cfg(windows)]
#[ctor::ctor]
fn agy_ctor() {
    win::startup();
}

#[cfg(windows)]
#[no_mangle]
pub extern "system" fn agy_proxy_init() {
    win::startup();
}

#[cfg(not(windows))]
#[no_mangle]
pub extern "C" fn agy_windows_proxy_unavailable() -> i32 {
    1
}
