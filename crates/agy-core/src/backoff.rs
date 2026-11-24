use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const DEFAULT_UDP_BACKOFF_SECS: u64 = 60;

/// Suppresses repeated SOCKS5 UDP ASSOCIATE handshakes when the upstream proxy
/// does not support UDP (e.g. QUIC/HTTP3 packets triggering TCP connects).
pub struct UdpAssociateBackoff {
    window: Duration,
    failed_at: Mutex<Option<Instant>>,
}

impl UdpAssociateBackoff {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            failed_at: Mutex::new(None),
        }
    }

    pub fn is_backed_off(&self) -> bool {
        self.is_backed_off_at(Instant::now())
    }

    pub fn is_backed_off_at(&self, now: Instant) -> bool {
        let guard = self.failed_at.lock().unwrap_or_else(|e| e.into_inner());
        match *guard {
            Some(ts) => now.saturating_duration_since(ts) < self.window,
            None => false,
        }
    }

    /// Record a UDP ASSOCIATE failure. Returns `true` when entering a fresh
    /// backoff window (caller should log once), `false` if already suppressed.
    pub fn record_failure(&self) -> bool {
        self.record_failure_at(Instant::now())
    }

    pub fn record_failure_at(&self, now: Instant) -> bool {
        let mut guard = self.failed_at.lock().unwrap_or_else(|e| e.into_inner());
        let already_active = match *guard {
            Some(ts) => now.saturating_duration_since(ts) < self.window,
            None => false,
        };
        if !already_active {
            *guard = Some(now);
            true
        } else {
            false
        }
    }

    /// Clear backoff state once UDP ASSOCIATE succeeds.
    pub fn record_success(&self) {
        let mut guard = self.failed_at.lock().unwrap_or_else(|e| e.into_inner());
        *guard = None;
    }
}

pub fn global_udp_backoff() -> &'static UdpAssociateBackoff {
    static INSTANCE: OnceLock<UdpAssociateBackoff> = OnceLock::new();
    INSTANCE.get_or_init(|| UdpAssociateBackoff::new(Duration::from_secs(DEFAULT_UDP_BACKOFF_SECS)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suppresses_within_window_and_resets_on_expiry_or_success() {
        let b = UdpAssociateBackoff::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(!b.is_backed_off_at(t0));

        assert!(b.record_failure_at(t0));
        assert!(b.is_backed_off_at(t0 + Duration::from_secs(10)));
        assert!(!b.record_failure_at(t0 + Duration::from_secs(10)));

        // After window expires, backoff lifts and next failure logs once again.
        let t1 = t0 + Duration::from_secs(61);
        assert!(!b.is_backed_off_at(t1));
        assert!(b.record_failure_at(t1));
        assert!(b.is_backed_off_at(t1 + Duration::from_secs(5)));

        // Success clears immediately.
        b.record_success();
        assert!(!b.is_backed_off_at(t1 + Duration::from_secs(5)));
    }
}
