//! macOS proxy loaded with `DYLD_INSERT_LIBRARIES`.
//!
//! dyld does not override libsystem symbols just because a dylib exports the
//! same name. Each hook is installed with a `__DATA,__interpose` tuple.
//! Calls from this dylib keep the real libSystem symbol: dyld does not
//! rewrite the interposer's own binds, and `dlsym` can hand back the hook.
//! On non-macOS hosts this crate is an empty stub so Linux `cargo test --workspace`
//! can still build it.

#[cfg(target_os = "macos")]
mod mac;

// No load-time constructor. dyld can run those before the Rust runtime is
// ready, which segfaults. Hooks call `try_startup()` on first use instead.

#[cfg(not(target_os = "macos"))]
#[no_mangle]
pub extern "C" fn agy_macos_proxy_unavailable() -> i32 {
    1
}
