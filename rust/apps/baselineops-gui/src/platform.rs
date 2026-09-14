//! DPI-aware Win32 event loop and worker hand-off for the native audit GUI.

#![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, channel},
    },
    thread,
};

use windows::{
    Win32::{
        Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM},
        Graphics::Gdi::{COLOR_WINDOW, GetSysColorBrush},
        System::LibraryLoader::GetModuleHandleW,
        UI::{
            HiDpi::{DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext},
            WindowsAndMessaging::{
                CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, CreateWindowExW, DefWindowProcW,
                DispatchMessageW, GWLP_USERDATA, GetClientRect, GetMessageW, HMENU, IDC_ARROW,
                IsDialogMessageW, KillTimer, LoadCursorW, MSG, PostQuitMessage, RegisterClassW,
                SWP_NOACTIVATE, SWP_NOZORDER, SetTimer, SetWindowLongPtrW, SetWindowPos,
                ShowWindow, TranslateMessage, WINDOW_EX_STYLE, WM_CLOSE, WM_COMMAND, WM_CREATE,
                WM_DESTROY, WM_DPICHANGED, WM_KEYDOWN, WM_SIZE, WM_TIMER, WNDCLASSW, WS_CAPTION,
                WS_CLIPCHILDREN, WS_MAXIMIZEBOX, WS_MINIMIZEBOX, WS_OVERLAPPED, WS_SYSMENU,
                WS_THICKFRAME, WS_VISIBLE,
            },
        },
    },
    core::{Error, Result, w},
};

use crate::{
    controller::{
        self, AuditReport, AuditState, AuthenticatedArtifact, CatalogItem, WorkerMessage,
        WorkerUpdate,
    },
    view::{
        self, AUDIT_BUTTON, AUDIT_PROFILE_BUTTON, CANCEL_BUTTON, CAPABILITY_LIST,
        OPEN_ARTIFACT_BUTTON, REVIEW_PROFILE_BUTTON, VALIDATE_PROFILE_BUTTON,
    },
};

mod callback;

use callback::CallbackState;

unsafe fn with_app(window: HWND, callback: impl FnOnce(&mut App)) {
    unsafe { callback::with_app::<App>(window, callback) };
}

const POLL_TIMER: usize = 1;
const POLL_INTERVAL_MS: u32 = 75;

struct App {
    controls: view::Controls,
    items: Vec<CatalogItem>,
    selected: usize,
    receiver: Option<Receiver<WorkerMessage>>,
    cancellation: Option<Arc<AtomicBool>>,
    artifact: Option<AuthenticatedArtifact>,
}

/// Runs the single-window, standard-control native audit interface.
pub fn run() -> Result<()> {
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)?;
        let module = GetModuleHandleW(None)?;
        let instance = HINSTANCE(module.0);
        let class_name = w!("BaselineOpsV3NativeAuditGui");
        let class = WNDCLASSW {
            hCursor: LoadCursorW(None, IDC_ARROW)?,
            hInstance: instance,
            hbrBackground: GetSysColorBrush(COLOR_WINDOW),
            lpszClassName: class_name,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(window_proc),
            ..Default::default()
        };
        if RegisterClassW(&raw const class) == 0 {
            return Err(Error::from_thread());
        }
        let style = WS_OVERLAPPED
            | WS_CAPTION
            | WS_SYSMENU
            | WS_THICKFRAME
            | WS_MINIMIZEBOX
            | WS_MAXIMIZEBOX
            | WS_CLIPCHILDREN
            | WS_VISIBLE;
        let window = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class_name,
            w!("BaselineOps for Windows v3 - Native audits"),
            style,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            960,
            680,
            None,
            None::<HMENU>,
            Some(instance),
            None,
        )?;
        let _ = ShowWindow(window, windows::Win32::UI::WindowsAndMessaging::SW_SHOW);
        message_loop(window)
    }
}

unsafe fn message_loop(window: HWND) -> Result<()> {
    let mut message = MSG::default();
    loop {
        let received = GetMessageW(&raw mut message, None, 0, 0).0;
        if received == -1 {
            return Err(Error::from_thread());
        }
        if received == 0 {
            return Ok(());
        }
        if !IsDialogMessageW(window, &raw const message).as_bool() {
            let _ = TranslateMessage(&raw const message);
            DispatchMessageW(&raw const message);
        }
    }
}

unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_CREATE => create_app(window),
        WM_SIZE => {
            with_app(window, |app| unsafe { layout(window, app) });
            LRESULT(0)
        }
        WM_DPICHANGED => {
            let recommended = &*(lparam.0 as *const RECT);
            let _ = SetWindowPos(
                window,
                None,
                recommended.left,
                recommended.top,
                recommended.right - recommended.left,
                recommended.bottom - recommended.top,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
            with_app(window, |app| unsafe { layout(window, app) });
            LRESULT(0)
        }
        WM_COMMAND => command(window, wparam),
        WM_KEYDOWN => keyboard(window, wparam),
        WM_TIMER if wparam.0 == POLL_TIMER => {
            poll_worker(window);
            LRESULT(0)
        }
        WM_CLOSE => {
            request_cancellation(window);
            DefWindowProcW(window, message, wparam, lparam)
        }
        WM_DESTROY => {
            KillTimer(Some(window), POLL_TIMER).ok();
            callback::destroy_callback_state::<App>(window);
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(window, message, wparam, lparam),
    }
}

unsafe fn create_app(window: HWND) -> LRESULT {
    let items = controller::catalog();
    let Ok(controls) = view::create(window, &items) else {
        return LRESULT(-1);
    };
    let app = App {
        controls,
        items,
        selected: 0,
        receiver: None,
        cancellation: None,
        artifact: None,
    };
    if app.items.is_empty() {
        return LRESULT(-1);
    }
    if view::set_selection(app.controls, &controller::selection_summary(app.items[0])).is_err()
        || view::set_report(app.controls, &AuditReport::ready()).is_err()
        || view::layout(app.controls, 960, 680).is_err()
    {
        return LRESULT(-1);
    }
    view::set_artifact_visible(app.controls, false);
    let pointer = Box::into_raw(Box::new(CallbackState::new(app)));
    SetWindowLongPtrW(window, GWLP_USERDATA, pointer as isize);
    if SetTimer(Some(window), POLL_TIMER, POLL_INTERVAL_MS, None) == 0 {
        SetWindowLongPtrW(window, GWLP_USERDATA, 0);
        drop(Box::from_raw(pointer));
        return LRESULT(-1);
    }
    LRESULT(0)
}

unsafe fn command(window: HWND, wparam: WPARAM) -> LRESULT {
    let id = i32::try_from(wparam.0 & 0xffff).expect("WM_COMMAND control ID is a 16-bit value");
    let notification =
        u16::try_from((wparam.0 >> 16) & 0xffff).expect("WM_COMMAND notification is 16-bit");
    match id {
        CAPABILITY_LIST if notification == 1 => {
            with_app(window, |app| {
                if let Some(selected) = view::selected_index(app.controls)
                    && let Some(item) = app.items.get(selected).copied()
                {
                    app.selected = selected;
                    let _ = view::set_selection(app.controls, &controller::selection_summary(item));
                }
            });
            LRESULT(0)
        }
        AUDIT_BUTTON => {
            with_app(window, |app| unsafe { start_audit(app) });
            LRESULT(0)
        }
        VALIDATE_PROFILE_BUTTON => {
            with_app(window, |app| unsafe { validate_profile(app) });
            LRESULT(0)
        }
        REVIEW_PROFILE_BUTTON => {
            with_app(window, |app| unsafe { review_profile(app) });
            LRESULT(0)
        }
        AUDIT_PROFILE_BUTTON => {
            with_app(window, |app| unsafe { start_profile_audit(app) });
            LRESULT(0)
        }
        CANCEL_BUTTON => {
            request_cancellation(window);
            LRESULT(0)
        }
        OPEN_ARTIFACT_BUTTON => {
            with_app(window, |app| unsafe { open_artifact(app) });
            LRESULT(0)
        }
        _ => DefWindowProcW(window, WM_COMMAND, wparam, LPARAM(0)),
    }
}

unsafe fn keyboard(window: HWND, wparam: WPARAM) -> LRESULT {
    // Standard controls provide arrow-key navigation; this adds predictable Escape cancellation.
    if wparam.0 == 27 {
        request_cancellation(window);
        return LRESULT(0);
    }
    DefWindowProcW(window, WM_KEYDOWN, wparam, LPARAM(0))
}

unsafe fn start_audit(app: &mut App) {
    if app.receiver.is_some() {
        return;
    }
    let Some(item) = app.items.get(app.selected).copied() else {
        return;
    };
    let cancellation = Arc::new(AtomicBool::new(false));
    let worker_cancellation = Arc::clone(&cancellation);
    let capability_id = item.id.to_owned();
    let (sender, receiver) = channel();
    let spawn = thread::Builder::new()
        .name("baselineops-native-audit".into())
        .spawn(move || {
            let _ = sender.send(WorkerMessage::Finished(controller::audit(
                &capability_id,
                &worker_cancellation,
            )));
        });
    match spawn {
        Ok(_) => {
            app.receiver = Some(receiver);
            app.cancellation = Some(cancellation);
            app.artifact = None;
            view::set_running(app.controls, true);
            view::set_artifact_visible(app.controls, false);
            let _ = view::set_report(app.controls, &AuditReport::running());
        }
        Err(error) => {
            let report = AuditReport {
                state: AuditState::Failed,
                status: "The native audit worker could not start.".into(),
                result: String::new(),
                error: Some(error.to_string()),
                artifact: None,
            };
            app.artifact = None;
            view::set_artifact_visible(app.controls, false);
            let _ = view::set_report(app.controls, &report);
        }
    }
}

unsafe fn validate_profile(app: &mut App) {
    let report = profile_path(app).map_or_else(invalid_profile_path_report, |path| {
        controller::validate_profile(&path)
    });
    app.artifact = None;
    view::set_artifact_visible(app.controls, false);
    let _ = view::set_report(app.controls, &report);
}

unsafe fn review_profile(app: &mut App) {
    start_profile_operation(app, true);
}

unsafe fn start_profile_audit(app: &mut App) {
    start_profile_operation(app, false);
}

unsafe fn start_profile_operation(app: &mut App, review: bool) {
    if app.receiver.is_some() {
        return;
    }
    let Some(profile_path) = profile_path(app) else {
        let _ = view::set_report(app.controls, &invalid_profile_path_report());
        return;
    };
    let cancellation = Arc::new(AtomicBool::new(false));
    let worker_cancellation = Arc::clone(&cancellation);
    let (sender, receiver) = channel();
    let spawn = thread::Builder::new()
        .name("baselineops-profile-audit".into())
        .spawn(move || {
            let progress_sender = sender.clone();
            let report = if review {
                controller::review_profile_native(&profile_path, &worker_cancellation)
            } else {
                controller::audit_profile(&profile_path, &worker_cancellation, |progress| {
                    let _ = progress_sender.send(WorkerMessage::Progress(progress));
                })
            };
            let _ = sender.send(WorkerMessage::Finished(report));
        });
    match spawn {
        Ok(_) => {
            app.receiver = Some(receiver);
            app.cancellation = Some(cancellation);
            app.artifact = None;
            view::set_running(app.controls, true);
            view::set_artifact_visible(app.controls, false);
            let _ = view::set_report(app.controls, &AuditReport::running());
        }
        Err(error) => {
            let report = AuditReport {
                state: AuditState::Failed,
                status: "The profile-audit worker could not start.".into(),
                result: String::new(),
                error: Some(error.to_string()),
                artifact: None,
            };
            let _ = view::set_report(app.controls, &report);
        }
    }
}

unsafe fn profile_path(app: &App) -> Option<std::path::PathBuf> {
    let text = view::profile_path(app.controls)?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| std::path::PathBuf::from(trimmed))
}

fn invalid_profile_path_report() -> AuditReport {
    AuditReport {
        state: AuditState::Unsupported,
        status: "Profile validation failed before any native operation started.".into(),
        result: String::new(),
        error: Some("enter a profile JSON path shorter than 32,768 characters".into()),
        artifact: None,
    }
}

unsafe fn request_cancellation(window: HWND) {
    with_app(window, |app| unsafe { request_cancellation_app(app) });
}

unsafe fn request_cancellation_app(app: &mut App) {
    let Some(cancellation) = &app.cancellation else {
        return;
    };
    if !cancellation.swap(true, Ordering::AcqRel) {
        let _ = view::set_report(app.controls, &AuditReport::cancelling());
    }
}

unsafe fn poll_worker(window: HWND) {
    with_app(window, |app| unsafe { poll_worker_app(app) });
}

unsafe fn poll_worker_app(app: &mut App) {
    let Some(receiver) = &app.receiver else {
        return;
    };
    let report = match controller::drain_worker_messages(receiver) {
        WorkerUpdate::Idle => return,
        WorkerUpdate::Progress(report) => {
            let _ = view::set_report(app.controls, &report);
            return;
        }
        WorkerUpdate::Finished(report) => report,
        WorkerUpdate::Disconnected => AuditReport {
            state: AuditState::Failed,
            status: "The native audit worker exited without a result.".into(),
            result: String::new(),
            error: Some("worker channel disconnected".into()),
            artifact: None,
        },
    };
    app.receiver = None;
    app.cancellation = None;
    app.artifact.clone_from(&report.artifact);
    view::set_running(app.controls, false);
    view::set_artifact_visible(app.controls, app.artifact.is_some());
    let _ = view::set_report(app.controls, &report);
}

unsafe fn open_artifact(app: &mut App) {
    let Some(artifact) = app.artifact.as_ref() else {
        return;
    };
    let report = read_artifact(artifact);
    let _ = view::set_report(app.controls, &report);
}

fn read_artifact(artifact: &AuthenticatedArtifact) -> AuditReport {
    const MAX_ARTIFACT_BYTES: u64 = 256 * 1024;

    let content =
        baselineops_windows::read_bounded_utf8_no_follow(&artifact.path, MAX_ARTIFACT_BYTES)
            .map_err(|error| format!("cannot safely read artifact: {error}"))
            .and_then(|content| {
                (baselineops_domain::Sha256Digest::of_bytes(content.as_bytes()) == artifact.digest)
                    .then_some(content)
                    .ok_or_else(|| {
                        "artifact digest no longer matches the authenticated audit result".into()
                    })
            });
    match content {
        Ok(content) => AuditReport {
            state: AuditState::Completed,
            status: "Opened a retained artifact in the read-only viewer.".into(),
            result: content,
            error: None,
            artifact: Some(artifact.clone()),
        },
        Err(error) => AuditReport {
            state: AuditState::Failed,
            status: "The retained artifact could not be opened.".into(),
            result: String::new(),
            error: Some(error),
            artifact: Some(artifact.clone()),
        },
    }
}

unsafe fn layout(window: HWND, app: &App) {
    let mut client = RECT::default();
    if GetClientRect(window, &raw mut client).is_ok() {
        let _ = view::layout(
            app.controls,
            client.right - client.left,
            client.bottom - client.top,
        );
    }
}

#[cfg(test)]
#[path = "platform_tests.rs"]
mod tests;
