//! Platform-neutral proxy core shared by the Linux `LD_PRELOAD` library and
//! the Windows injectable DLL.
//!
//! Socket I/O, hook installation, and process injection stay in the platform
//! crates. This crate owns configuration, the FakeIP ring, routing decisions,
//! and the SOCKS5 / HTTP CONNECT byte codecs.

pub mod backoff;
pub mod config;
pub mod fakeip;
pub mod process;
pub mod proto;
pub mod routing;

pub use backoff::{global_udp_backoff, UdpAssociateBackoff};
pub use config::AppConfig;
pub use routing::{Action, DecideOpts, Endpoint, Family, Proto};
