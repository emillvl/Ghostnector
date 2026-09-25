//! The typed client for the privileged helper.
//!
//! This is the only way `core` can affect the kernel, and it is deliberately narrow: connect, say
//! hello, send one verb, read one answer, hang up. There is no session to keep in sync, no result to
//! cache, and no way to send anything the verb vocabulary cannot express.
//!
//! Before the first call the endpoint is checked: the socket must be a socket, owned by this
//! process's uid, and inaccessible to anyone else, and the directory holding it must not be
//! writable by anyone else. If any of that is false, Ghostnector refuses to talk rather than take
//! instructions from a socket someone else could have planted.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ghostnector_spec::backend::Verb;
use ghostnector_spec::ipc::{ErrorCode, HelperResponse, PROTOCOL_VERSION};

/// How long to wait for the helper to answer before giving up.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);

/// Anything that can answer a verb. The real implementation talks to `netd`; tests substitute it.
pub trait HelperLink: Send + Sync {
    /// Send one verb and return the answer.
    fn invoke(&self, verb: Verb) -> Result<HelperResponse, HelperError>;
}

/// Why a call to the helper did not produce an answer.
#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    /// The endpoint is not something we are willing to trust.
    #[error("the helper's socket '{}' cannot be trusted: {reason}", path.display())]
    Endpoint {
        /// The path involved.
        path: PathBuf,
        /// Why it was rejected.
        reason: String,
    },
    /// The helper could not be reached at all.
    #[error("cannot reach the helper at '{}': {reason}", path.display())]
    Connect {
        /// The path involved.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },
    /// The helper answered, and the answer was a refusal.
    #[error("the helper refused: {message}")]
    Refused {
        /// The helper's machine-readable code.
        code: ErrorCode,
        /// The helper's explanation.
        message: String,
        /// Whether the explanation should be shown only on request.
        sensitive: bool,
    },
    /// The helper answered something that is not a valid answer.
    #[error("the helper answered something unintelligible: {0}")]
    Protocol(String),
    /// Reading or writing the socket failed.
    #[error("talking to the helper failed: {0}")]
    Transport(String),
}

/// A client for the privileged helper, over a unix socket.
#[derive(Debug, Clone)]
pub struct Helper {
    path: PathBuf,
}

impl Helper {
    /// Remember where the helper lives.
    ///
    /// The endpoint is checked on every call rather than once here, so `core` can start before
    /// `netd` does and so a socket swapped out from under it is noticed immediately. The cost is
    /// two `stat` calls per transition.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The socket in use.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl HelperLink for Helper {
    fn invoke(&self, verb: Verb) -> Result<HelperResponse, HelperError> {
        verify_endpoint(&self.path)?;
        let stream = UnixStream::connect(&self.path).map_err(|error| HelperError::Connect {
            path: self.path.clone(),
            reason: error.to_string(),
        })?;
        // A helper that accepts a connection and then stalls must not stall Ghostnector forever.
        stream
            .set_read_timeout(Some(RESPONSE_TIMEOUT))
            .map_err(|error| HelperError::Transport(error.to_string()))?;
        stream
            .set_write_timeout(Some(RESPONSE_TIMEOUT))
            .map_err(|error| HelperError::Transport(error.to_string()))?;

        let mut writer = stream
            .try_clone()
            .map_err(|error| HelperError::Transport(error.to_string()))?;
        let mut reader = BufReader::new(stream);

        send(
            &mut writer,
            &Verb::Hello {
                protocol: PROTOCOL_VERSION,
            },
        )?;
        match read(&mut reader)? {
            HelperResponse::Hello { protocol, .. } if protocol == PROTOCOL_VERSION => {}
            HelperResponse::Hello { protocol, .. } => {
                return Err(HelperError::Protocol(format!(
                    "this build speaks protocol {PROTOCOL_VERSION}, the helper speaks {protocol}"
                )))
            }
            other => return Err(unexpected("handshake", &other)),
        }

        send(&mut writer, &verb)?;
        match read(&mut reader)? {
            HelperResponse::Error(body) => Err(HelperError::Refused {
                code: body.code,
                message: body.message,
                sensitive: body.sensitive,
            }),
            answer => Ok(answer),
        }
    }
}

fn send(stream: &mut impl Write, verb: &Verb) -> Result<(), HelperError> {
    send_typed(stream, verb)
}

/// Send one newline-delimited JSON value. Shared with the namespace helper's client, so both
/// sockets use one framing implementation.
pub(crate) fn send_typed<T: serde::Serialize>(
    stream: &mut impl Write,
    value: &T,
) -> Result<(), HelperError> {
    let mut encoded =
        serde_json::to_vec(value).map_err(|error| HelperError::Protocol(error.to_string()))?;
    encoded.push(b'\n');
    stream
        .write_all(&encoded)
        .map_err(|error| HelperError::Transport(error.to_string()))?;
    stream
        .flush()
        .map_err(|error| HelperError::Transport(error.to_string()))
}

fn read(stream: &mut impl BufRead) -> Result<HelperResponse, HelperError> {
    read_typed(stream)
}

/// Read one newline-delimited JSON value.
pub(crate) fn read_typed<T: serde::de::DeserializeOwned>(
    stream: &mut impl BufRead,
) -> Result<T, HelperError> {
    let mut line = String::new();
    let read = stream
        .read_line(&mut line)
        .map_err(|error| HelperError::Transport(error.to_string()))?;
    if read == 0 {
        return Err(HelperError::Protocol(
            "the helper closed the connection without answering".to_string(),
        ));
    }
    serde_json::from_str(&line)
        .map_err(|error| HelperError::Protocol(format!("bad reply: {error}")))
}

fn unexpected(what: &str, answer: &HelperResponse) -> HelperError {
    HelperError::Protocol(format!(
        "expected {what}, got a {} reply",
        answer_kind(answer)
    ))
}

fn answer_kind(answer: &HelperResponse) -> &'static str {
    match answer {
        HelperResponse::Hello { .. } => "handshake",
        HelperResponse::Applied { .. } => "applied",
        HelperResponse::Report(_) => "report",
        HelperResponse::Verified { .. } => "verification",
        HelperResponse::Error(_) => "error",
    }
}

pub(crate) fn verify_endpoint(path: &Path) -> Result<(), HelperError> {
    let reject = |reason: String| HelperError::Endpoint {
        path: path.to_path_buf(),
        reason,
    };

    let metadata = std::fs::metadata(path).map_err(|error| reject(error.to_string()))?;
    if !metadata.file_type().is_socket() {
        return Err(reject("not a socket".to_string()));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(reject(format!(
            "mode {:o} allows group or other access",
            metadata.mode() & 0o777
        )));
    }
    let our_uid = nix::unistd::geteuid().as_raw();
    if metadata.uid() != our_uid {
        return Err(reject(format!(
            "owned by uid {} rather than {}",
            metadata.uid(),
            our_uid
        )));
    }

    // Whoever can write the directory can replace the socket, so that matters as much as the
    // socket's own permissions.
    let directory = path
        .parent()
        .ok_or_else(|| reject("no parent directory".to_string()))?;
    let directory_metadata =
        std::fs::metadata(directory).map_err(|error| reject(format!("directory: {error}")))?;
    if !directory_metadata.is_dir() {
        return Err(reject("the parent is not a directory".to_string()));
    }
    if directory_metadata.mode() & 0o022 != 0 {
        return Err(reject(format!(
            "the directory '{}' is writable by group or others",
            directory.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("ghostnector-helper-{}-{label}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("temp dir");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("restrict dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_plain_file_is_not_an_endpoint() {
        let dir = TempDir::new("plain");
        let path = dir.0.join("not-a-socket");
        std::fs::write(&path, b"hello").expect("write");
        let error = verify_endpoint(&path).unwrap_err();
        assert!(matches!(error, HelperError::Endpoint { .. }));
    }

    #[test]
    fn a_missing_endpoint_is_reported_rather_than_ignored() {
        let dir = TempDir::new("missing");
        let error = verify_endpoint(&dir.0.join("absent")).unwrap_err();
        assert!(matches!(error, HelperError::Endpoint { .. }));
    }

    #[test]
    fn a_world_writable_directory_is_refused() {
        let dir = TempDir::new("loose-dir");
        let socket_path = dir.0.join("helper.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).expect("bind");
        // Restrict the socket itself first, so the complaint can only be about the directory.
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict socket");
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o777))
            .expect("loosen dir");

        let error = verify_endpoint(&socket_path).unwrap_err();
        assert!(
            matches!(&error, HelperError::Endpoint { reason, .. } if reason.contains("writable")),
            "expected a directory complaint, got {error}"
        );
        drop(listener);
    }

    #[test]
    fn a_properly_restricted_socket_is_accepted() {
        let dir = TempDir::new("good");
        let socket_path = dir.0.join("helper.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).expect("bind");
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict socket");
        verify_endpoint(&socket_path).expect("a 0600 socket in a 0700 directory is acceptable");
        drop(listener);
    }
}
