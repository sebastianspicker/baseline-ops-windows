//! Process-local Windows console cancellation observation.
//!
//! The guard intercepts only Ctrl-C and Ctrl-Break. It records the signal in an
//! atomic flag so broker code can send an authenticated cancellation message at
//! a normal execution point. Dropping the guard disables its callback before
//! unregistering it. If Windows rejects unregistration, the dormant callback
//! remains installed and the exclusive registration lease stays poisoned.

#![cfg_attr(windows, allow(unsafe_code))]

use crate::PlatformError;

#[cfg(any(windows, test))]
const CTRL_C_EVENT: u32 = 0;
#[cfg(any(windows, test))]
const CTRL_BREAK_EVENT: u32 = 1;

/// Exclusive process-local console cancellation observer.
pub struct ConsoleCancellation {
    _private: (),
}

impl ConsoleCancellation {
    /// Install the process console handler for the lifetime of this guard.
    ///
    /// # Errors
    ///
    /// Returns an error outside Windows, when another guard is active, or when
    /// Windows rejects handler registration.
    pub fn install() -> Result<Self, PlatformError> {
        platform::install()
    }

    /// Return whether Ctrl-C or Ctrl-Break has been observed by this guard.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        platform::is_cancelled()
    }
}

#[cfg(any(windows, test))]
const fn is_cancel_signal(control_type: u32) -> bool {
    matches!(control_type, CTRL_C_EVENT | CTRL_BREAK_EVENT)
}

#[cfg(any(windows, test))]
struct HandlerState {
    active: std::sync::atomic::AtomicBool,
    enabled: std::sync::atomic::AtomicBool,
    generation: std::sync::atomic::AtomicU64,
    cancelled_generation: std::sync::atomic::AtomicU64,
}

#[cfg(any(windows, test))]
impl HandlerState {
    const fn new() -> Self {
        Self {
            active: std::sync::atomic::AtomicBool::new(false),
            enabled: std::sync::atomic::AtomicBool::new(false),
            generation: std::sync::atomic::AtomicU64::new(0),
            cancelled_generation: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn acquire(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn enable(&self) {
        use std::sync::atomic::Ordering;
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.enabled.store(true, Ordering::Release);
    }

    fn observe(&self, control_type: u32) -> bool {
        use std::sync::atomic::Ordering;
        if !self.enabled.load(Ordering::Acquire) || !is_cancel_signal(control_type) {
            return false;
        }
        let generation = self.generation.load(Ordering::Acquire);
        self.mark_cancelled(generation)
    }

    fn is_cancelled(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.enabled.load(Ordering::Acquire)
            && self.cancelled_generation.load(Ordering::Acquire)
                == self.generation.load(Ordering::Acquire)
    }

    fn mark_cancelled(&self, generation: u64) -> bool {
        use std::sync::atomic::Ordering;
        self.cancelled_generation
            .fetch_max(generation, Ordering::AcqRel);
        self.enabled.load(Ordering::Acquire)
            && self.generation.load(Ordering::Acquire) == generation
    }

    fn disable(&self) {
        self.enabled
            .store(false, std::sync::atomic::Ordering::Release);
    }

    fn release_after_unregister(&self, succeeded: bool) {
        if succeeded {
            self.active
                .store(false, std::sync::atomic::Ordering::Release);
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::{ConsoleCancellation, HandlerState};
    use crate::PlatformError;
    use std::io;

    static STATE: HandlerState = HandlerState::new();

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<extern "system" fn(u32) -> i32>, add: i32) -> i32;
    }

    pub(super) fn install() -> Result<ConsoleCancellation, PlatformError> {
        if !STATE.acquire() {
            return Err(PlatformError::ProtocolRejected(
                "a console cancellation observer is already active".into(),
            ));
        }
        STATE.enable();
        if unsafe { SetConsoleCtrlHandler(Some(handle_console_control), 1) } == 0 {
            STATE.disable();
            STATE.release_after_unregister(true);
            return Err(io::Error::last_os_error().into());
        }
        Ok(ConsoleCancellation { _private: () })
    }

    pub(super) fn is_cancelled() -> bool {
        STATE.is_cancelled()
    }

    extern "system" fn handle_console_control(control_type: u32) -> i32 {
        i32::from(STATE.observe(control_type))
    }

    impl Drop for ConsoleCancellation {
        fn drop(&mut self) {
            // A callback already executing may finish its one interception, but
            // callbacks beginning after this store always defer to older/default handlers.
            STATE.disable();
            let unregistered =
                unsafe { SetConsoleCtrlHandler(Some(handle_console_control), 0) } != 0;
            STATE.release_after_unregister(unregistered);
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::ConsoleCancellation;
    use crate::PlatformError;

    pub(super) fn install() -> Result<ConsoleCancellation, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }

    pub(super) const fn is_cancelled() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_interrupt_and_break_are_cancellation_signals() {
        assert!(is_cancel_signal(CTRL_C_EVENT));
        assert!(is_cancel_signal(CTRL_BREAK_EVENT));
        for control_type in 2..=6 {
            assert!(!is_cancel_signal(control_type));
        }
    }

    #[test]
    fn failed_unregister_leaves_an_inert_poisoned_registration() {
        let state = HandlerState::new();
        assert!(state.acquire());
        state.enable();
        assert!(state.observe(CTRL_C_EVENT));
        assert!(state.is_cancelled());
        state.disable();
        state.release_after_unregister(false);
        assert!(!state.observe(CTRL_C_EVENT));
        assert!(!state.is_cancelled());
        assert!(!state.acquire());
    }

    #[test]
    fn successful_unregister_releases_the_registration_lease() {
        let state = HandlerState::new();
        assert!(state.acquire());
        state.enable();
        state.disable();
        state.release_after_unregister(true);
        assert!(state.acquire());
    }

    #[test]
    fn stale_callback_cannot_cancel_a_reinstalled_guard() {
        use std::sync::atomic::Ordering;
        let state = HandlerState::new();
        assert!(state.acquire());
        state.enable();
        let old_generation = state.generation.load(Ordering::Acquire);
        state.disable();
        state.release_after_unregister(true);
        assert!(state.acquire());
        state.enable();
        assert!(!state.mark_cancelled(old_generation));
        assert!(!state.is_cancelled());
        assert!(state.observe(CTRL_C_EVENT));
        assert!(state.is_cancelled());
    }

    #[cfg(not(windows))]
    #[test]
    fn installation_fails_closed_off_windows() {
        assert!(matches!(
            ConsoleCancellation::install(),
            Err(PlatformError::UnsupportedPlatform)
        ));
    }
}
