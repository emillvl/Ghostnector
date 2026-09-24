//! Writing files without ever leaving a half-written one behind.
//!
//! Both the intent journal and Tor's configuration are read by something else — a restarted
//! Ghostnector, or Tor itself — so a crash mid-write must leave either the old contents or the new
//! ones, never a truncated file that parses as something else.

use std::fs;
use std::io::Write;
use std::path::Path;

/// Write `contents` to `path` atomically, creating parent directories as needed.
pub fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let directory = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the file needs a parent directory",
        )
    })?;
    fs::create_dir_all(directory)?;

    let temporary = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(contents)?;
        // The rename below is only atomic with respect to contents that reached the disk.
        file.sync_all()?;
    }
    fs::rename(&temporary, path)?;

    // Durably record the rename, so the file cannot vanish with a power loss.
    if let Ok(handle) = fs::File::open(directory) {
        let _ = handle.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn directory(label: &str) -> std::path::PathBuf {
        let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "ghostnector-fsutil-{}-{label}-{unique}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn a_file_is_written_whole() {
        let dir = directory("whole");
        let path = dir.join("nested").join("file.txt");
        write_atomic(&path, b"first version").expect("write");
        assert_eq!(fs::read_to_string(&path).expect("read"), "first version");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn writing_over_a_file_replaces_it_completely() {
        let dir = directory("replace");
        let path = dir.join("file.txt");
        write_atomic(&path, b"a much longer first version").expect("write");
        write_atomic(&path, b"short").expect("write");
        assert_eq!(fs::read_to_string(&path).expect("read"), "short");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_temporary_file_is_left_behind() {
        let dir = directory("no-temp");
        let path = dir.join("file.txt");
        write_atomic(&path, b"contents").expect("write");
        let names: Vec<String> = fs::read_dir(&dir)
            .expect("read dir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["file.txt".to_string()], "{names:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_without_a_directory_is_refused_rather_than_guessed() {
        let error = write_atomic(Path::new("/"), b"contents").unwrap_err();
        assert!(
            error.kind() == std::io::ErrorKind::InvalidInput
                || error.kind() == std::io::ErrorKind::IsADirectory
                || error.kind() == std::io::ErrorKind::PermissionDenied
        );
    }
}
