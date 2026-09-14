use super::*;

#[derive(Clone, Copy, PartialEq)]
enum Stage {
    Prefix,
    Body,
    Flush,
    Sync,
}

struct Sink {
    fail_at: Stage,
    calls: Vec<Stage>,
}

impl Sink {
    fn step(&mut self, stage: Stage) -> io::Result<()> {
        self.calls.push(stage);
        if self.fail_at == stage {
            Err(io::Error::other("injected durable write failure"))
        } else {
            Ok(())
        }
    }
}

impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let stage = if self.calls.is_empty() {
            Stage::Prefix
        } else {
            Stage::Body
        };
        self.step(stage)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.step(Stage::Flush)
    }
}

impl DurableWrite for Sink {
    fn synchronize(&mut self) -> io::Result<()> {
        self.step(Stage::Sync)
    }
}

#[test]
fn prefix_body_flush_and_sync_failures_poison_and_prevent_any_retry_io() {
    for (index, fail_at) in [Stage::Prefix, Stage::Body, Stage::Flush, Stage::Sync]
        .into_iter()
        .enumerate()
    {
        let mut sink = Sink {
            fail_at,
            calls: Vec::new(),
        };
        let mut poisoned = false;
        assert!(matches!(
            write_durable_record(&mut sink, &mut poisoned, b"record"),
            Err(JournalError::Io(_))
        ));
        assert!(poisoned);
        assert_eq!(sink.calls.len(), index + 1);
        assert!(matches!(
            write_durable_record(&mut sink, &mut poisoned, b"retry"),
            Err(JournalError::WriteFailed)
        ));
        assert_eq!(sink.calls.len(), index + 1);
    }
}
