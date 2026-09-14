use super::valid_nonce;
use crate::PlatformError;
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// Fixed-capacity replay detector for accepted client nonces.
#[derive(Debug)]
pub struct ReplayNonceCache {
    ttl: Duration,
    capacity: usize,
    seen: BTreeMap<String, Instant>,
    order: VecDeque<String>,
}

impl ReplayNonceCache {
    /// Create a replay cache with a positive expiry window and capacity.
    ///
    /// # Errors
    ///
    /// Returns an error when either configured bound is zero.
    pub fn new(ttl: Duration, capacity: usize) -> Result<Self, PlatformError> {
        if ttl.is_zero() || capacity == 0 {
            return Err(PlatformError::ProtocolRejected(
                "replay cache requires positive bounds".into(),
            ));
        }
        Ok(Self {
            ttl,
            capacity,
            seen: BTreeMap::new(),
            order: VecDeque::new(),
        })
    }
    /// Record a validated nonce exactly once within the configured replay window.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or replayed nonces.
    pub fn accept(&mut self, nonce: &str, now: Instant) -> Result<(), PlatformError> {
        if !valid_nonce(nonce) {
            return Err(PlatformError::ProtocolRejected(
                "nonce is not bounded hexadecimal".into(),
            ));
        }
        self.evict_expired(now);
        if self.seen.contains_key(nonce) {
            return Err(PlatformError::ReplayDetected);
        }
        self.evict_capacity();
        let nonce = nonce.to_owned();
        self.seen.insert(nonce.clone(), now);
        self.order.push_back(nonce);
        Ok(())
    }
    fn evict_capacity(&mut self) {
        while self.order.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
    }
    fn evict_expired(&mut self, now: Instant) {
        while let Some(nonce) = self.order.front() {
            let Some(accepted_at) = self.seen.get(nonce) else {
                self.order.pop_front();
                continue;
            };
            if now.saturating_duration_since(*accepted_at) < self.ttl {
                break;
            }
            let nonce = self.order.pop_front().expect("front exists");
            self.seen.remove(&nonce);
        }
    }
}
