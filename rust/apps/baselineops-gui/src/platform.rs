//! DPI-aware Win32 event loop and worker hand-off for the native audit GUI.

#![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, TryRecvError, channel},
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
    controller::{self, AuditReport, AuditState, CatalogItem},
    view::{self, AUDIT_BUTTON, CANCEL_BUTTON, CAPABILITY_LIST, OPEN_ARTIFACT_BUTTON},
};

const POLL_TIMER: usize = 1;
const POLL_INTERVAL_MS: u32 = 75;

struct App {
    controls: view::Controls,
    items: Vec<CatalogItem>,
    selected: usize,
    receiver: Option<Receiver<AuditReport>>,
    cancellation: Option<Arc<AtomicBool>>,
    artifact: Option<std::path::PathBuf>,
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
            if let Some(app) = app(window) {
                layout(window, app);
            }
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
            if let Some(app) = app(window) {
                layout(window, app);
            }
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
            drop_app(window);
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
    let app = Box::new(App {
        controls,
        items,
        selected: 0,
        receiver: None,
        cancellation: None,
        artifact: None,
    });
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
    let pointer = Box::into_raw(app);
    SetWindowLongPtrW(window, GWLP_USERDATA, pointer as isize);
    if SetTimer(Some(window), POLL_TIMER, POLL_INTERVAL_MS, None) == 0 {
        drop(Box::from_raw(pointer));
        SetWindowLongPtrW(window, GWLP_USERDATA, 0);
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
            if let Some(app) = app(window)
                && let Some(selected) = view::selected_index(app.controls)
                && let Some(item) = app.items.get(selected).copied()
            {
                app.selected = selected;
                let _ = view::set_selection(app.controls, &controller::selection_summary(item));
            }
            LRESULT(0)
        }
        AUDIT_BUTTON => {
            start_audit(window);
            LRESULT(0)
        }
        CANCEL_BUTTON => {
            request_cancellation(window);
            LRESULT(0)
        }
        OPEN_ARTIFACT_BUTTON => {
            open_artifact(window);
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

unsafe fn start_audit(window: HWND) {
    let Some(app) = app(window) else {
        return;
    };
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
            let _ = sender.send(controller::audit(&capability_id, &worker_cancellation));
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

unsafe fn request_cancellation(window: HWND) {
    let Some(app) = app(window) else {
        return;
    };
    let Some(cancellation) = &app.cancellation else {
        return;
    };
    if !cancellation.swap(true, Ordering::AcqRel) {
        let _ = view::set_report(app.controls, &AuditReport::cancelling());
    }
}

unsafe fn poll_worker(window: HWND) {
    let Some(app) = app(window) else {
        return;
    };
    let Some(receiver) = &app.receiver else {
        return;
    };
    let report = match receiver.try_recv() {
        Ok(report) => report,
        Err(TryRecvError::Empty) => return,
        Err(TryRecvError::Disconnected) => AuditReport {
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

unsafe fn open_artifact(window: HWND) {
    let Some(app) = app(window) else {
        return;
    };
    let Some(path) = app.artifact.as_deref() else {
        return;
    };
    let report = read_artifact(path);
    let _ = view::set_report(app.controls, &report);
}

fn read_artifact(path: &Path) -> AuditReport {
    const MAX_ARTIFACT_BYTES: u64 = 256 * 1024;

    let content = std::fs::metadata(path)
        .map_err(|error| format!("cannot read artifact metadata: {error}"))
        .and_then(|metadata| {
            (metadata.is_file() && metadata.len() <= MAX_ARTIFACT_BYTES)
                .then_some(())
                .ok_or_else(|| {
                    "artifact is not a regular file or exceeds the 256 KiB viewer limit".into()
                })
        })
        .and_then(|()| std::fs::read_to_string(path).map_err(|error| error.to_string()));
    match content {
        Ok(content) => AuditReport {
            state: AuditState::Completed,
            status: "Opened a retained artifact in the read-only viewer.".into(),
            result: content,
            error: None,
            artifact: Some(path.to_path_buf()),
        },
        Err(error) => AuditReport {
            state: AuditState::Failed,
            status: "The retained artifact could not be opened.".into(),
            result: String::new(),
            error: Some(error),
            artifact: Some(path.to_path_buf()),
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

unsafe fn app(window: HWND) -> Option<&'static mut App> {
    use windows::Win32::UI::WindowsAndMessaging::GetWindowLongPtrW;

    let pointer = GetWindowLongPtrW(window, GWLP_USERDATA) as *mut App;
    pointer.as_mut()
}

unsafe fn drop_app(window: HWND) {
    use windows::Win32::UI::WindowsAndMessaging::GetWindowLongPtrW;

    let pointer = GetWindowLongPtrW(window, GWLP_USERDATA) as *mut App;
    if !pointer.is_null() {
        SetWindowLongPtrW(window, GWLP_USERDATA, 0);
        drop(Box::from_raw(pointer));
    }
}
