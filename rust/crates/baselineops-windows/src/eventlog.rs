//! Shell-free bounded Event Log acquisition through `EvtQuery` APIs.

use crate::PlatformError;
use baselineops_capabilities::{
    EventLogObservation, EventLogQueryParameters, validate_event_query,
};

/// Query local Windows Event Log channels without export, command execution, or remote sessions.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows. Access denials,
/// bounds, and render failures are preserved as typed incomplete observations.
pub fn audit_event_log(
    parameters: &EventLogQueryParameters,
) -> Result<EventLogObservation, PlatformError> {
    validate_event_query(parameters).map_err(PlatformError::TrustFailure)?;
    #[cfg(windows)]
    {
        Ok(platform::audit_event_log(parameters))
    }
    #[cfg(not(windows))]
    platform::audit_event_log(parameters)
}

#[cfg(not(windows))]
mod platform {
    use super::{EventLogObservation, EventLogQueryParameters, PlatformError};
    pub(super) fn audit_event_log(
        _: &EventLogQueryParameters,
    ) -> Result<EventLogObservation, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]
    use super::{EventLogObservation, EventLogQueryParameters};
    use baselineops_capabilities::{EventLogRecord, Observation};
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS,
    };
    use windows::Win32::System::EventLog::{
        EVT_HANDLE, EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection,
        EvtRender, EvtRenderEventXml,
    };
    use windows::core::PCWSTR;

    pub(super) fn audit_event_log(parameters: &EventLogQueryParameters) -> EventLogObservation {
        unsafe {
            let query = match open_query(parameters) {
                Ok(query) => query,
                Err(observation) => return failed_query(observation),
            };
            let query = OwnedEventHandle(query);
            enumerate(query.0, parameters)
        }
    }

    unsafe fn open_query(
        parameters: &EventLogQueryParameters,
    ) -> Result<EVT_HANDLE, Observation<EventLogRecord>> {
        let channel = wide(&parameters.channel);
        let xpath = wide(&parameters.xpath);
        EvtQuery(
            None,
            PCWSTR(channel.as_ptr()),
            PCWSTR(xpath.as_ptr()),
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
        )
        .map_err(|error| {
            if code(&error) == ERROR_ACCESS_DENIED.0 {
                Observation::AccessDenied
            } else {
                Observation::Failed {
                    exit_code: error.code().0,
                }
            }
        })
    }

    fn failed_query(observation: Observation<EventLogRecord>) -> EventLogObservation {
        EventLogObservation {
            records: vec![observation],
            enumeration_complete: true,
        }
    }

    unsafe fn enumerate(
        query: EVT_HANDLE,
        parameters: &EventLogQueryParameters,
    ) -> EventLogObservation {
        let mut records = Vec::new();
        let mut complete = true;
        for _ in 0..parameters.max_records {
            match next_event(query, parameters.timeout_ms) {
                Ok(Some(event)) => records.push(render(event.0, parameters.max_xml_bytes)),
                Ok(None) => break,
                Err(observation) => {
                    records.push(observation);
                    complete = false;
                    break;
                }
            }
        }
        if records.len() == parameters.max_records as usize {
            complete = false;
        }
        EventLogObservation {
            records,
            enumeration_complete: complete,
        }
    }

    unsafe fn next_event(
        query: EVT_HANDLE,
        timeout_ms: u32,
    ) -> Result<Option<OwnedEventHandle>, Observation<EventLogRecord>> {
        let mut raw_handle = [EVT_HANDLE::default().0];
        let mut returned = 0_u32;
        match EvtNext(query, &mut raw_handle, timeout_ms, 0, &raw mut returned) {
            Ok(()) if returned == 1 => Ok(Some(OwnedEventHandle(EVT_HANDLE(raw_handle[0])))),
            Ok(()) => Ok(None),
            Err(error) if code(&error) == ERROR_NO_MORE_ITEMS.0 => Ok(None),
            Err(error) if code(&error) == ERROR_ACCESS_DENIED.0 => Err(Observation::AccessDenied),
            Err(_) => Err(Observation::TimedOut),
        }
    }

    unsafe fn render(handle: EVT_HANDLE, max_bytes: u32) -> Observation<EventLogRecord> {
        let (mut required, mut property_count) = (0_u32, 0_u32);
        if let Err(error) = EvtRender(
            None,
            handle,
            EvtRenderEventXml.0,
            0,
            None,
            &raw mut required,
            &raw mut property_count,
        ) && code(&error) != ERROR_INSUFFICIENT_BUFFER.0
        {
            return render_error(&error);
        }
        if !valid_render_length(required, max_bytes) {
            return Observation::Truncated;
        }
        let mut buffer = vec![0_u16; usize::try_from(required / 2).unwrap_or(0)];
        let capacity = required;
        let status = EvtRender(
            None,
            handle,
            EvtRenderEventXml.0,
            capacity,
            Some(buffer.as_mut_ptr().cast()),
            &raw mut required,
            &raw mut property_count,
        );
        if let Err(error) = status {
            return render_result_error(&error);
        }
        if !valid_render_length(required, capacity) {
            return Observation::Truncated;
        }
        let length = usize::try_from(required / 2).unwrap_or(0);
        let Ok(text) = String::from_utf16(&buffer[..length]) else {
            return Observation::Unparsed;
        };
        let text = text.trim_end_matches('\0').to_owned();
        parse_xml(text).map_or(Observation::Unparsed, Observation::Present)
    }

    fn valid_render_length(required: u32, limit: u32) -> bool {
        required != 0 && required <= limit && required.is_multiple_of(2)
    }
    fn render_error(error: &windows::core::Error) -> Observation<EventLogRecord> {
        if code(error) == ERROR_ACCESS_DENIED.0 {
            Observation::AccessDenied
        } else {
            Observation::Unparsed
        }
    }
    fn render_result_error(error: &windows::core::Error) -> Observation<EventLogRecord> {
        if code(error) == ERROR_INSUFFICIENT_BUFFER.0 {
            Observation::Truncated
        } else {
            render_error(error)
        }
    }

    fn parse_xml(xml: String) -> Option<EventLogRecord> {
        let (provider, event_id, level, time_created, record_id) = record_fields(&xml)?;
        Some(EventLogRecord {
            provider,
            event_id,
            level,
            time_created,
            record_id,
            xml: Observation::Present(xml),
            message: None,
        })
    }

    fn record_fields(xml: &str) -> Option<(String, u32, u8, String, u64)> {
        let (provider, time_created) = text_fields(xml)?;
        let (event_id, level, record_id) = numeric_fields(xml)?;
        Some((provider, event_id, level, time_created, record_id))
    }

    fn text_fields(xml: &str) -> Option<(String, String)> {
        Some((
            attribute(xml, "Provider", "Name")?,
            attribute(xml, "TimeCreated", "SystemTime")?,
        ))
    }

    fn numeric_fields(xml: &str) -> Option<(u32, u8, u64)> {
        Some((
            tag(xml, "EventID")?.parse().ok()?,
            tag(xml, "Level")?.parse().ok()?,
            tag(xml, "EventRecordID")?.parse().ok()?,
        ))
    }
    fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
        let start = xml.find(&format!("<{name}>"))? + name.len() + 2;
        let end = xml[start..].find(&format!("</{name}>"))? + start;
        Some(&xml[start..end])
    }
    fn attribute(xml: &str, tag_name: &str, attribute_name: &str) -> Option<String> {
        let start = xml.find(&format!("<{tag_name}"))?;
        let rest = &xml[start..xml[start..].find('>')? + start];
        let marker = format!("{attribute_name}=\"");
        let value = rest.find(&marker)? + marker.len();
        Some(rest[value..].split('"').next()?.to_owned())
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
    fn code(error: &windows::core::Error) -> u32 {
        u32::from_ne_bytes(error.code().0.to_ne_bytes()) & 0xffff
    }
    struct OwnedEventHandle(EVT_HANDLE);
    impl Drop for OwnedEventHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = EvtClose(self.0);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_event_log_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::audit_event_log(&baselineops_capabilities::EventLogQueryParameters {
                channel: "Application".into(),
                xpath: "*".into(),
                max_records: 1,
                timeout_ms: 1,
                max_xml_bytes: 1,
                max_message_bytes: 0
            }),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
