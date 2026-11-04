//! macOS proxy loaded with `DYLD_INSERT_LIBRARIES`.
//!
//! dyld does not override libsystem symbols just because a dylib exports the
//! same name. Each hook is installed with a `__DATA,__interpose` tuple.
//! On non-macOS hosts this crate is an empty stub so Linux `cargo test --workspace`
//! can still build it.

#[cfg(target_os = "macos")]
mod mac;

#[cfg(target_os = "macos")]
#[ctor::ctor]
fn agy_macos_ctor() {
    mac::startup();
}

#[cfg(not(target_os = "macos"))]
#[no_mangle]
pub extern "C" fn agy_macos_proxy_unavailable() -> i32 {
    1
}
