//! Running the policy tools.
//!
//! Two rules govern everything here:
//!
//! * **No shell.** Tools are invoked with an absolute path, a fixed argument list, and the ruleset
//!   on standard input. Nothing on the wire is ever interpreted as a command, an option, or a path.
//! * **Verify the tool before trusting it.** The binary must be an absolute path, a regular file,
//!   owned by root, and not writable by anyone else. This is what makes "absolute path" meaningful:
//!   without it, an attacker with write access to the binary would inherit `CAP_NET_ADMIN`.

use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ghostnector_policy::invariants::TABLE_NAME;

/// How much of a tool's error output to keep.
const MAX_ERROR_CHARS: usize = 2048;

/// Why a policy operation failed.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// A tool is missing, not a regular file, or writable by someone other than root.
    #[error("policy tool '{}' is not usable: {reason}", path.display())]
    ToolUnusable {
        /// The rejected path.
        path: PathBuf,
        /// Why it was rejected.
        reason: String,
    },
    /// The tool refused the policy.
    #[error("applying the policy failed: {0}")]
    Apply(String),
    /// The tool could not be run at all.
    #[error("running '{}' failed: {reason}", path.display())]
    Io {
        /// The tool.
        path: PathBuf,
        /// Why it could not be run.
        reason: String,
    },
    /// Listing the kernel's tables failed.
    #[error("listing the kernel's tables failed: {0}")]
    Listing(String),
    /// The tool's output could not be understood.
    #[error("could not parse the output of '{}': {reason}", path.display())]
    Unparsable {
        /// The tool.
        path: PathBuf,
        /// Why the output was unusable.
        reason: String,
    },
    /// The policy was applied but the table is not present afterwards.
    #[error("the policy was reported as applied, but no table is present")]
    NotApplied,
    /// Conntrack is not available.
    #[error("conntrack is not available: {0}")]
    ConntrackUnavailable(String),
}

/// The kernel-facing operations Ghostnector needs.
///
/// Deliberately tiny. There is no "run this", no "read this file", and no "delete this rule": a
/// backend can replace Ghostnector's table, flush conntrack, and say whether the table exists.
pub trait Backend: Send + Sync {
    /// Apply a replacement script as one atomic transaction.
    fn apply(&self, script: &str) -> Result<(), BackendError>;
    /// Drop conntrack entries so pre-existing flows cannot survive a transition.
    fn flush_conntrack(&self) -> Result<(), BackendError>;
    /// Whether Ghostnector's table exists in the kernel right now.
    fn table_present(&self) -> Result<bool, BackendError>;
}

/// The real backend: `nft` for policy, `conntrack` for flow state.
#[derive(Debug, Clone)]
pub struct NftCli {
    nft: PathBuf,
    conntrack: PathBuf,
    conntrack_usable: bool,
}

impl NftCli {
    /// Verify the tools and build the backend.
    ///
    /// The conntrack tool is optional: flushing is defence in depth (the default-deny policy is what
    /// stops pre-existing flows), so a missing one is a note rather than a failure.
    pub fn new(nft: PathBuf, conntrack: PathBuf) -> Result<Self, BackendError> {
        check_tool(&nft)?;
        let conntrack_usable = check_tool(&conntrack).is_ok();
        Ok(Self {
            nft,
            conntrack,
            conntrack_usable,
        })
    }

    /// Whether the optional conntrack tool is usable.
    pub fn conntrack_usable(&self) -> bool {
        self.conntrack_usable
    }
}

fn check_tool(path: &Path) -> Result<(), BackendError> {
    let reject = |reason: String| BackendError::ToolUnusable {
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
            "writable by group or others, so it cannot be trusted with privileges".to_string(),
        ));
    }
    Ok(())
}

impl Backend for NftCli {
    fn apply(&self, script: &str) -> Result<(), BackendError> {
        let mut child = Command::new(&self.nft)
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| BackendError::Io {
                path: self.nft.clone(),
                reason: error.to_string(),
            })?;

        {
            let mut stdin = child.stdin.take().ok_or_else(|| BackendError::Io {
                path: self.nft.clone(),
                reason: "the tool did not accept a script".to_string(),
            })?;
            stdin
                .write_all(script.as_bytes())
                .map_err(|error| BackendError::Io {
                    path: self.nft.clone(),
                    reason: error.to_string(),
                })?;
        }

        let output = child.wait_with_output().map_err(|error| BackendError::Io {
            path: self.nft.clone(),
            reason: error.to_string(),
        })?;

        if !output.status.success() {
            return Err(BackendError::Apply(describe_failure(
                &output.stderr,
                output.status.code(),
            )));
        }
        Ok(())
    }

    fn flush_conntrack(&self) -> Result<(), BackendError> {
        if !self.conntrack_usable {
            return Err(BackendError::ConntrackUnavailable(
                self.conntrack.display().to_string(),
            ));
        }
        // Best effort across families: an unsupported family is not a reason to fail the transition.
        for family in ["ipv4", "ipv6"] {
            let _ = Command::new(&self.conntrack)
                .arg("-F")
                .arg("-f")
                .arg(family)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        Ok(())
    }

    fn table_present(&self) -> Result<bool, BackendError> {
        let output = Command::new(&self.nft)
            .args(["-j", "list", "tables"])
            .output()
            .map_err(|error| BackendError::Io {
                path: self.nft.clone(),
                reason: error.to_string(),
            })?;

        if !output.status.success() {
            return Err(BackendError::Listing(describe_failure(
                &output.stderr,
                output.status.code(),
            )));
        }

        let parsed: serde_json::Value =
            serde_json::from_slice(&output.stdout).map_err(|error| BackendError::Unparsable {
                path: self.nft.clone(),
                reason: error.to_string(),
            })?;

        let tables = parsed
            .get("nftables")
            .and_then(|value| value.as_array())
            .ok_or_else(|| BackendError::Unparsable {
                path: self.nft.clone(),
                reason: "no table list in the output".to_string(),
            })?;

        Ok(tables.iter().any(|entry| {
            let table = entry.get("table");
            table.and_then(|t| t.get("name")).and_then(|n| n.as_str()) == Some(TABLE_NAME)
                && table.and_then(|t| t.get("family")).and_then(|f| f.as_str()) == Some("inet")
        }))
    }
}

/// Keep a tool's complaint short, printable, and free of control characters.
fn describe_failure(stderr: &[u8], code: Option<i32>) -> String {
    let text = String::from_utf8_lossy(stderr);
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = cleaned.trim();
    let mut message = if trimmed.is_empty() {
        format!("the tool exited with status {}", code.unwrap_or(-1))
    } else {
        trimmed.to_string()
    };
    if message.chars().count() > MAX_ERROR_CHARS {
        message = message.chars().take(MAX_ERROR_CHARS).collect::<String>() + " […]";
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_tool_path_is_refused() {
        let error = check_tool(Path::new("nft")).unwrap_err();
        assert!(matches!(error, BackendError::ToolUnusable { .. }));
    }

    #[test]
    fn a_directory_is_not_a_tool() {
        let error = check_tool(Path::new("/usr/sbin")).unwrap_err();
        assert!(matches!(error, BackendError::ToolUnusable { .. }));
    }

    #[test]
    fn a_missing_tool_is_refused() {
        let error = check_tool(Path::new("/usr/sbin/definitely-not-here")).unwrap_err();
        assert!(matches!(error, BackendError::ToolUnusable { .. }));
    }

    #[test]
    fn the_real_nft_is_accepted_when_present() {
        // The test environment installs nftables; if it is absent, this asserts nothing.
        if Path::new("/usr/sbin/nft").exists() {
            assert!(check_tool(Path::new("/usr/sbin/nft")).is_ok());
        }
    }

    #[test]
    fn failures_are_trimmed_and_printable() {
        let message = describe_failure(b"line one\nline two\x07\n\n", Some(1));
        assert_eq!(message, "line one line two");
        let empty = describe_failure(b"", Some(2));
        assert_eq!(empty, "the tool exited with status 2");
        let long = describe_failure(&vec![b'x'; MAX_ERROR_CHARS * 2], Some(1));
        assert!(long.ends_with('…') || long.ends_with(']'));
    }
}
