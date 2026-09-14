//! Reentrancy-safe ownership for application state referenced by an `HWND`.

use std::{
    cell::{Cell, RefCell},
    ptr::NonNull,
};
use windows::Win32::{
    Foundation::HWND,
    UI::WindowsAndMessaging::{GWLP_USERDATA, GetWindowLongPtrW, SetWindowLongPtrW},
};

/// Heap-owned state retained while window callbacks are active.
pub(super) struct CallbackState<T> {
    pub(super) app: RefCell<T>,
    pub(super) callback_depth: Cell<usize>,
    destroying: Cell<bool>,
}

impl<T> CallbackState<T> {
    pub(super) fn new(app: T) -> Self {
        Self {
            app: RefCell::new(app),
            callback_depth: Cell::new(0),
            destroying: Cell::new(false),
        }
    }

    pub(super) fn enter(&self) -> bool {
        if self.destroying.get() {
            return false;
        }
        let Some(depth) = self.callback_depth.get().checked_add(1) else {
            return false;
        };
        self.callback_depth.set(depth);
        true
    }

    pub(super) fn leave(&self) -> bool {
        let depth = self
            .callback_depth
            .get()
            .checked_sub(1)
            .expect("callback depth is balanced");
        self.callback_depth.set(depth);
        depth == 0 && self.destroying.get()
    }

    pub(super) fn begin_destroy(&self) -> bool {
        !self.destroying.replace(true)
    }

    pub(super) fn with_app<R>(&self, callback: impl FnOnce(&mut T) -> R) -> Option<R> {
        if self.destroying.get() {
            return None;
        }
        let mut app = self.app.try_borrow_mut().ok()?;
        Some(callback(&mut app))
    }
}

struct CallbackGuard<T> {
    state: NonNull<CallbackState<T>>,
}

impl<T> CallbackGuard<T> {
    unsafe fn enter(state: NonNull<CallbackState<T>>) -> Option<Self> {
        unsafe { state.as_ref() }.enter().then_some(Self { state })
    }
}

impl<T> Drop for CallbackGuard<T> {
    fn drop(&mut self) {
        if unsafe { self.state.as_ref() }.leave() {
            unsafe { drop(Box::from_raw(self.state.as_ptr())) };
        }
    }
}

unsafe fn with_callback_state<T>(window: HWND, callback: impl FnOnce(&CallbackState<T>)) {
    let Some(state) =
        NonNull::new(unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) } as *mut CallbackState<T>)
    else {
        return;
    };
    let Some(guard) = (unsafe { CallbackGuard::enter(state) }) else {
        return;
    };
    callback(unsafe { state.as_ref() });
    drop(guard);
}

pub(super) unsafe fn with_app<T>(window: HWND, callback: impl FnOnce(&mut T)) {
    unsafe {
        with_callback_state::<T>(window, |state| {
            let _ = state.with_app(callback);
        });
    }
}

pub(super) unsafe fn destroy_callback_state<T>(window: HWND) {
    unsafe {
        with_callback_state::<T>(window, |state| {
            if state.begin_destroy() {
                SetWindowLongPtrW(window, GWLP_USERDATA, 0);
            }
        });
    }
}
