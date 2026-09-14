use crate::PlatformError;

pub(crate) const ERROR_MORE_DATA: u32 = 234;
pub(crate) const ERROR_OPERATION_ABORTED: u32 = 995;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadStage {
    Prefix,
    Body,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadOutcome {
    Complete { more_data: bool },
    CleanTimeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransferStatus {
    pub(crate) succeeded: bool,
    pub(crate) error: u32,
    pub(crate) actual: usize,
    pub(crate) timed_out: bool,
}

pub(crate) fn classify_read(
    status: TransferStatus,
    expected: usize,
    stage: ReadStage,
) -> Result<ReadOutcome, PlatformError> {
    if status.timed_out {
        return classify_timeout(status, stage);
    }
    if status.actual != expected {
        return Err(if status.succeeded {
            rejected("pipe message is shorter than its frame")
        } else {
            native_error("ReadFile", status.error)
        });
    }
    if status.succeeded {
        Ok(ReadOutcome::Complete { more_data: false })
    } else if status.error == ERROR_MORE_DATA {
        Ok(ReadOutcome::Complete { more_data: true })
    } else {
        Err(native_error("ReadFile", status.error))
    }
}

fn classify_timeout(
    status: TransferStatus,
    stage: ReadStage,
) -> Result<ReadOutcome, PlatformError> {
    if stage == ReadStage::Prefix
        && status.actual == 0
        && !status.succeeded
        && status.error == ERROR_OPERATION_ABORTED
    {
        return Ok(ReadOutcome::CleanTimeout);
    }
    Err(rejected(
        "pipe receive timed out after a frame transfer may have begun",
    ))
}

pub(crate) fn native_error(operation: &str, code: u32) -> PlatformError {
    PlatformError::Io(std::io::Error::other(format!(
        "{operation}: Win32 error {code}",
    )))
}

fn rejected(detail: &str) -> PlatformError {
    PlatformError::ProtocolRejected(detail.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(succeeded: bool, error: u32, actual: usize, timed_out: bool) -> TransferStatus {
        TransferStatus {
            succeeded,
            error,
            actual,
            timed_out,
        }
    }

    #[test]
    fn only_an_empty_cancelled_prefix_is_a_clean_timeout() {
        let empty = status(false, ERROR_OPERATION_ABORTED, 0, true);
        assert_eq!(
            classify_read(empty, 4, ReadStage::Prefix).unwrap(),
            ReadOutcome::CleanTimeout
        );
        assert!(classify_read(empty, 8, ReadStage::Body).is_err());
        assert!(
            classify_read(
                status(false, ERROR_OPERATION_ABORTED, 1, true),
                4,
                ReadStage::Prefix
            )
            .is_err()
        );
        assert!(classify_read(status(true, 0, 4, true), 4, ReadStage::Prefix).is_err());
    }

    #[test]
    fn exact_reads_preserve_message_boundary_status() {
        assert_eq!(
            classify_read(status(true, 0, 4, false), 4, ReadStage::Prefix).unwrap(),
            ReadOutcome::Complete { more_data: false }
        );
        assert_eq!(
            classify_read(
                status(false, ERROR_MORE_DATA, 4, false),
                4,
                ReadStage::Prefix
            )
            .unwrap(),
            ReadOutcome::Complete { more_data: true }
        );
    }

    #[test]
    fn partial_and_native_error_reads_fail_closed() {
        assert!(classify_read(status(true, 0, 3, false), 4, ReadStage::Prefix).is_err());
        assert!(classify_read(status(false, 5, 4, false), 4, ReadStage::Prefix).is_err());
        assert!(
            classify_read(
                status(false, ERROR_MORE_DATA, 3, false),
                4,
                ReadStage::Prefix
            )
            .is_err()
        );
    }
}
