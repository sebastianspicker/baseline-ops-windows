//! Standard-control Win32 view for the native audit launcher.

#![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;

use windows::{
    Win32::{
        Foundation::{HINSTANCE, HWND, LPARAM, WPARAM},
        Graphics::Gdi::{DEFAULT_GUI_FONT, GetStockObject},
        System::LibraryLoader::GetModuleHandleW,
        UI::{
            HiDpi::GetDpiForWindow,
            Input::KeyboardAndMouse::EnableWindow,
            WindowsAndMessaging::{
                BS_DEFPUSHBUTTON, ES_AUTOHSCROLL, ES_AUTOVSCROLL, ES_MULTILINE, ES_READONLY,
                GetWindowTextLengthW, GetWindowTextW, HMENU, LB_ADDSTRING, LB_GETCURSEL,
                LB_SETCURSEL, LBS_NOTIFY, MoveWindow, SendMessageW, SetWindowTextW,
                WINDOW_EX_STYLE, WINDOW_STYLE, WM_SETFONT, WS_BORDER, WS_CHILD, WS_GROUP,
                WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
            },
        },
    },
    core::{PCWSTR, Result, w},
};

use crate::controller::{AuditReport, CatalogItem};

pub const CAPABILITY_LIST: i32 = 1001;
pub const AUDIT_BUTTON: i32 = 1002;
pub const CANCEL_BUTTON: i32 = 1003;
pub const SELECTION_TEXT: i32 = 1004;
pub const STATUS_TEXT: i32 = 1005;
pub const RESULT_TEXT: i32 = 1006;
pub const OPEN_ARTIFACT_BUTTON: i32 = 1007;
pub const PROFILE_PATH: i32 = 1008;
pub const VALIDATE_PROFILE_BUTTON: i32 = 1009;
pub const AUDIT_PROFILE_BUTTON: i32 = 1010;
pub const REVIEW_PROFILE_BUTTON: i32 = 1011;

/// Handles for the standard controls that Windows exposes to UI Automation.
#[derive(Clone, Copy)]
pub struct Controls {
    pub list: HWND,
    pub audit: HWND,
    pub cancel: HWND,
    pub open_artifact: HWND,
    pub profile_path: HWND,
    pub validate_profile: HWND,
    pub audit_profile: HWND,
    pub review_profile: HWND,
    selection: HWND,
    status: HWND,
    result: HWND,
}

struct ProfileControls {
    path: HWND,
    validate: HWND,
    audit: HWND,
    review: HWND,
}

struct ActionControls {
    audit: HWND,
    cancel: HWND,
    open_artifact: HWND,
}

struct OutputControls {
    selection: HWND,
    status: HWND,
    result: HWND,
}

/// Creates all controls atomically from the parent-window perspective.
pub unsafe fn create(parent: HWND, items: &[CatalogItem]) -> Result<Controls> {
    let instance = HINSTANCE(GetModuleHandleW(None)?.0);
    let profile = create_profile_controls(parent, instance)?;
    let list = create_capability_list(parent, instance, items)?;
    let actions = create_action_controls(parent, instance)?;
    let output = create_output_controls(parent, instance)?;
    let controls = Controls {
        list,
        audit: actions.audit,
        cancel: actions.cancel,
        open_artifact: actions.open_artifact,
        profile_path: profile.path,
        validate_profile: profile.validate,
        audit_profile: profile.audit,
        review_profile: profile.review,
        selection: output.selection,
        status: output.status,
        result: output.result,
    };
    set_control_fonts(controls);
    let _ = EnableWindow(controls.cancel, false);
    Ok(controls)
}

unsafe fn create_profile_controls(parent: HWND, instance: HINSTANCE) -> Result<ProfileControls> {
    let path = control(
        parent,
        instance,
        w!("EDIT"),
        w!("Profile JSON path (standard-user readable, maximum 1 MiB)"),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | WINDOW_STYLE(ES_AUTOHSCROLL as u32),
        PROFILE_PATH,
    )?;
    let validate = control(
        parent,
        instance,
        w!("BUTTON"),
        w!("Validate profile"),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        VALIDATE_PROFILE_BUTTON,
    )?;
    let audit = control(
        parent,
        instance,
        w!("BUTTON"),
        w!("Audit profile"),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        AUDIT_PROFILE_BUTTON,
    )?;
    let review = control(
        parent,
        instance,
        w!("BUTTON"),
        w!("Review profile"),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        REVIEW_PROFILE_BUTTON,
    )?;
    Ok(ProfileControls {
        path,
        validate,
        audit,
        review,
    })
}

unsafe fn create_capability_list(
    parent: HWND,
    instance: HINSTANCE,
    items: &[CatalogItem],
) -> Result<HWND> {
    let list = control(
        parent,
        instance,
        w!("LISTBOX"),
        w!("Native capability catalog. Use arrow keys to select an audit."),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | WS_GROUP | WINDOW_STYLE(LBS_NOTIFY as u32),
        CAPABILITY_LIST,
    )?;
    for item in items {
        let label = wide(&format!("{:02}  {}", item.number, item.name));
        SendMessageW(
            list,
            LB_ADDSTRING,
            Some(WPARAM(0)),
            Some(LPARAM(label.as_ptr() as isize)),
        );
    }
    SendMessageW(list, LB_SETCURSEL, Some(WPARAM(0)), Some(LPARAM(0)));
    Ok(list)
}

unsafe fn create_action_controls(parent: HWND, instance: HINSTANCE) -> Result<ActionControls> {
    let audit = control(
        parent,
        instance,
        w!("BUTTON"),
        w!("Audit selected capability"),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_DEFPUSHBUTTON as u32),
        AUDIT_BUTTON,
    )?;
    let cancel = control(
        parent,
        instance,
        w!("BUTTON"),
        w!("Cancel audit"),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        CANCEL_BUTTON,
    )?;
    let open_artifact = control(
        parent,
        instance,
        w!("BUTTON"),
        w!("Open retained artifact"),
        WS_CHILD | WS_TABSTOP,
        OPEN_ARTIFACT_BUTTON,
    )?;
    Ok(ActionControls {
        audit,
        cancel,
        open_artifact,
    })
}

unsafe fn create_output_controls(parent: HWND, instance: HINSTANCE) -> Result<OutputControls> {
    let selection = control(
        parent,
        instance,
        w!("STATIC"),
        w!("Selected capability details."),
        WS_CHILD | WS_VISIBLE,
        SELECTION_TEXT,
    )?;
    let status = control(
        parent,
        instance,
        w!("STATIC"),
        w!("Status: Ready."),
        WS_CHILD | WS_VISIBLE,
        STATUS_TEXT,
    )?;
    let result = control(
        parent,
        instance,
        w!("EDIT"),
        w!("Results and errors appear here. This field is read-only."),
        WS_CHILD
            | WS_VISIBLE
            | WS_TABSTOP
            | WS_BORDER
            | WS_VSCROLL
            | WINDOW_STYLE((ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY) as u32),
        RESULT_TEXT,
    )?;
    Ok(OutputControls {
        selection,
        status,
        result,
    })
}

unsafe fn set_control_fonts(controls: Controls) {
    let font = GetStockObject(DEFAULT_GUI_FONT);
    for handle in [
        controls.list,
        controls.profile_path,
        controls.validate_profile,
        controls.audit_profile,
        controls.review_profile,
        controls.selection,
        controls.audit,
        controls.cancel,
        controls.open_artifact,
        controls.status,
        controls.result,
    ] {
        SendMessageW(
            handle,
            WM_SETFONT,
            Some(WPARAM(font.0 as usize)),
            Some(LPARAM(1)),
        );
    }
}

/// Returns the selected catalog index, if the list box has a valid selection.
pub unsafe fn selected_index(controls: Controls) -> Option<usize> {
    let selected = SendMessageW(
        controls.list,
        LB_GETCURSEL,
        Some(WPARAM(0)),
        Some(LPARAM(0)),
    )
    .0;
    usize::try_from(selected).ok()
}

/// Returns a bounded profile-path entry. An overlong entry is deliberately rejected.
pub unsafe fn profile_path(controls: Controls) -> Option<String> {
    const MAX_PATH_CHARS: usize = 32_767;

    let length = usize::try_from(GetWindowTextLengthW(controls.profile_path)).ok()?;
    if length > MAX_PATH_CHARS {
        return None;
    }
    let mut text = vec![0_u16; length.saturating_add(1)];
    let copied = usize::try_from(GetWindowTextW(controls.profile_path, &mut text)).ok()?;
    String::from_utf16(&text[..copied]).ok()
}

/// Displays selection text using a real STATIC control for accessibility clients.
pub unsafe fn set_selection(controls: Controls, text: &str) -> Result<()> {
    set_text(controls.selection, text)
}

/// Displays the current status plus structured result or diagnostic in separate text controls.
pub unsafe fn set_report(controls: Controls, report: &AuditReport) -> Result<()> {
    set_text(controls.status, &format!("Status: {}", report.status))?;
    let body = match (&report.result, &report.error) {
        (result, None) if !result.is_empty() => result.clone(),
        (_, Some(error)) => format!("Error: {error}"),
        _ => String::new(),
    };
    set_text(controls.result, &body)
}

/// Updates controls so an audit cannot overlap and cancellation remains visible.
pub unsafe fn set_running(controls: Controls, running: bool) {
    let _ = EnableWindow(controls.list, !running);
    let _ = EnableWindow(controls.audit, !running);
    let _ = EnableWindow(controls.profile_path, !running);
    let _ = EnableWindow(controls.validate_profile, !running);
    let _ = EnableWindow(controls.audit_profile, !running);
    let _ = EnableWindow(controls.review_profile, !running);
    let _ = EnableWindow(controls.cancel, running);
}

/// Shows an artifact-open affordance only for a verified existing artifact.
pub unsafe fn set_artifact_visible(controls: Controls, visible: bool) {
    use windows::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOW, ShowWindow};

    let _ = ShowWindow(
        controls.open_artifact,
        if visible { SW_SHOW } else { SW_HIDE },
    );
}

/// Lays out controls using current DPI while relying entirely on system colors and standard controls.
pub unsafe fn layout(controls: Controls, width: i32, height: i32) -> Result<()> {
    let metrics = LayoutMetrics::new(controls, width, height);
    layout_profile(controls, metrics)?;
    layout_content(controls, metrics)?;
    layout_actions(controls, metrics)
}

#[derive(Clone, Copy)]
struct LayoutMetrics {
    scale: i32,
    margin: i32,
    gap: i32,
    button_width: i32,
    button_height: i32,
    profile_height: i32,
    profile_width: i32,
    list_width: i32,
    right_x: i32,
    right_width: i32,
    buttons_y: i32,
    status_y: i32,
    result_y: i32,
    content_y: i32,
    selection_height: i32,
}

impl LayoutMetrics {
    unsafe fn new(controls: Controls, width: i32, height: i32) -> Self {
        let scale = i32::try_from(GetDpiForWindow(controls.list)).unwrap_or(96);
        let unit = |value: i32| value.saturating_mul(scale) / 96;
        let margin = unit(18);
        let gap = unit(12);
        let button_width = unit(190);
        let button_height = unit(34);
        let profile_height = unit(28);
        let list_width = ((width - margin * 2) * 38 / 100).max(unit(230));
        let right_x = margin + list_width + gap;
        let right_width = (width - right_x - margin).max(unit(250));
        let buttons_y = height - margin - button_height;
        let status_y = buttons_y - gap - unit(42);
        let result_y = status_y - gap - unit(220);
        let content_y = margin + profile_height + gap;
        Self {
            scale,
            margin,
            gap,
            button_width,
            button_height,
            profile_height,
            profile_width: (width - margin * 2 - (button_width + gap) * 3).max(unit(160)),
            list_width,
            right_x,
            right_width,
            buttons_y,
            status_y,
            result_y,
            content_y,
            selection_height: (result_y - gap - content_y).max(unit(70)),
        }
    }

    fn unit(self, value: i32) -> i32 {
        value.saturating_mul(self.scale) / 96
    }
}

unsafe fn layout_profile(controls: Controls, metrics: LayoutMetrics) -> Result<()> {
    MoveWindow(
        controls.profile_path,
        metrics.margin,
        metrics.margin,
        metrics.profile_width,
        metrics.profile_height,
        true,
    )?;
    for (index, control) in [
        controls.validate_profile,
        controls.audit_profile,
        controls.review_profile,
    ]
    .into_iter()
    .enumerate()
    {
        MoveWindow(
            control,
            metrics.margin
                + metrics.profile_width
                + metrics.gap
                + i32::try_from(index).unwrap_or(0) * (metrics.button_width + metrics.gap),
            metrics.margin,
            metrics.button_width,
            metrics.profile_height,
            true,
        )?;
    }
    Ok(())
}

unsafe fn layout_content(controls: Controls, metrics: LayoutMetrics) -> Result<()> {
    MoveWindow(
        controls.list,
        metrics.margin,
        metrics.content_y,
        metrics.list_width,
        (metrics.buttons_y - metrics.gap - metrics.content_y).max(metrics.unit(160)),
        true,
    )?;
    MoveWindow(
        controls.selection,
        metrics.right_x,
        metrics.content_y,
        metrics.right_width,
        metrics.selection_height,
        true,
    )?;
    MoveWindow(
        controls.result,
        metrics.right_x,
        metrics.result_y,
        metrics.right_width,
        metrics.unit(220),
        true,
    )?;
    MoveWindow(
        controls.status,
        metrics.right_x,
        metrics.status_y,
        metrics.right_width,
        metrics.unit(42),
        true,
    )
}

unsafe fn layout_actions(controls: Controls, metrics: LayoutMetrics) -> Result<()> {
    MoveWindow(
        controls.audit,
        metrics.margin,
        metrics.buttons_y,
        metrics.button_width,
        metrics.button_height,
        true,
    )?;
    MoveWindow(
        controls.cancel,
        metrics.margin + metrics.button_width + metrics.gap,
        metrics.buttons_y,
        metrics.button_width,
        metrics.button_height,
        true,
    )?;
    MoveWindow(
        controls.open_artifact,
        metrics.margin + (metrics.button_width + metrics.gap) * 2,
        metrics.buttons_y,
        metrics.button_width,
        metrics.button_height,
        true,
    )
}

unsafe fn control(
    parent: HWND,
    instance: HINSTANCE,
    class: PCWSTR,
    label: PCWSTR,
    style: WINDOW_STYLE,
    id: i32,
) -> Result<HWND> {
    windows::Win32::UI::WindowsAndMessaging::CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        class,
        label,
        style,
        0,
        0,
        0,
        0,
        Some(parent),
        Some(control_menu(id)),
        Some(instance),
        None,
    )
}

unsafe fn set_text(control: HWND, value: &str) -> Result<()> {
    let text = wide(value);
    SetWindowTextW(control, PCWSTR(text.as_ptr()))
}

fn control_menu(id: i32) -> HMENU {
    let value = usize::try_from(id).expect("control identifiers are positive constants");
    HMENU(value as *mut c_void)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
