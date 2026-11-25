use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

pub const LOCK_FILE: &str = ".qr-extract.lock";

#[derive(Debug)]
pub struct ExtractionLock {
    _file: File,
}

pub fn extraction_lock(target_dir: &Path) -> io::Result<ExtractionLock> {
    std::fs::create_dir_all(target_dir)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(target_dir.join(LOCK_FILE))?;
    file.lock()?;
    Ok(ExtractionLock { _file: file })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::TryLockError;

    #[test]
    fn a_held_lock_blocks_a_second_holder_until_dropped() {
        let dir = std::env::temp_dir().join(format!("qr-lock-test-{}", std::process::id()));
        let held = extraction_lock(&dir).unwrap();
        let other = OpenOptions::new()
            .write(true)
            .open(dir.join(LOCK_FILE))
            .unwrap();
        assert!(matches!(other.try_lock(), Err(TryLockError::WouldBlock)));
        drop(held);
        other
            .try_lock()
            .expect("free once the first holder is dropped");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
