//! Checking that a program is safe to run.
//!
//! An absolute path is only meaningful if the file at that path is owned by root and not writable
//! by anyone else. Both the control plane's service manager and its resolver tooling are run through
//! this check. (`ghostnector-netd` has its own copy on purpose: the privileged helper must not
//! depend on the control plane's code.)

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Why a program was not considered safe to run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("'{}' is not usable: {reason}", path.display())]
pub struct ToolError {
    /// The path involved.
    pub path: PathBuf,
    /// Why it was rejected.
    pub reason: String,
}

/// Verify that `path` is an absolute path to a root-owned, non-writable regular file.
pub fn check_tool(path: &Path) -> Result<(), ToolError> {
    let reject = |reason: String| ToolError {
        path: path.to_path_buf(),
        reason,
    };

    if !path.is_absolute() {
        return Err(reject("expected an absolute path".to_string()));
    }
    let metadata = std::fs::metadata(path).map_err(|error| reject(error.to_string()))?;
    if !metadata.is_file() {
        return Err(reject("not a regular file".to_string()));
    }
    if metadata.uid() != 0 {
        return Err(reject(format!("owned by uid {}, not root", metadata.uid())));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(reject(
            "writable by group or others, so it cannot be trusted".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn directory() -> PathBuf {
        let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("ghostnector-tools-{}-{unique}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        path
    }

    #[test]
    fn a_relative_path_is_refused() {
        assert!(check_tool(Path::new("systemctl")).is_err());
    }

    #[test]
    fn a_directory_is_not_a_program() {
        assert!(check_tool(Path::new("/usr/sbin")).is_err());
    }

    #[test]
    fn a_writable_program_is_refused() {
        let dir = directory();
        let program = dir.join("tool");
        std::fs::write(&program, b"#!/bin/sh\n").expect("write");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o777)).expect("loosen");
        let error = check_tool(&program).unwrap_err();
        assert!(error.reason.contains("writable"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_program_not_owned_by_root_is_refused() {
        let dir = directory();
        let program = dir.join("tool");
        std::fs::write(&program, b"#!/bin/sh\n").expect("write");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).expect("set");
        // The file is owned by whoever runs the tests, which is only root in a root test run.
        if !nix::unistd::Uid::effective().is_root() {
            let error = check_tool(&program).unwrap_err();
            assert!(error.reason.contains("not root"), "{error}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
