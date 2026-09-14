use super::DurableWrite;
use baselineops_windows::ProtectedJournalFile;
use std::{
    fs::File,
    io::{self, Write},
};

pub(super) enum Storage {
    Local(File),
    Protected(ProtectedJournalFile),
}

impl From<File> for Storage {
    fn from(file: File) -> Self {
        Self::Local(file)
    }
}

impl Write for Storage {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Local(file) => file.write(bytes),
            Self::Protected(file) => file.write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Local(file) => file.flush(),
            Self::Protected(file) => file.flush(),
        }
    }
}

impl DurableWrite for Storage {
    fn synchronize(&mut self) -> io::Result<()> {
        match self {
            Self::Local(file) => file.sync_all(),
            Self::Protected(file) => file.sync_all(),
        }
    }
}
