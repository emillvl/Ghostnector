//! The typed client for the namespace helper.
//!
//! The same shape as the firewall helper's client: connect, say hello, send one verb, read one
//! answer, hang up. `core` never keeps a namespace session in sync and never sees a name, a path, a
//! ruleset or a command — only the closed verb vocabulary in
//! [`ghostnector_spec::appd`].
//!
//! The endpoint is checked on every call for the same reason it is for `netd`: `core` may start
//! before `appd`, and a socket swapped out from under it must be noticed immediately.

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ghostnector_spec::appd::{AppResponse, AppVerb, APP_PROTOCOL_VERSION};

use crate::helper::{read_typed, send_typed, verify_endpoint, HelperError};

/// How long to wait for the helper to answer before giving up.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Anything that can answer an [`AppVerb`]. The real implementation talks to `appd`.
pub trait AppHelperLink: Send + Sync {
    /// Send one verb and return the answer.
    fn invoke(&self, verb: AppVerb) -> Result<AppResponse, HelperError>;
}

/// A client for the namespace helper, over a unix socket.
#[derive(Debug, Clone)]
pub struct AppHelper {
    path: PathBuf,
}

impl AppHelper {
    /// Remember where the helper lives.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The socket in use.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AppHelperLink for AppHelper {
    fn invoke(&self, verb: AppVerb) -> Result<AppResponse, HelperError> {
        verify_endpoint(&self.path)?;
        let stream = UnixStream::connect(&self.path).map_err(|error| HelperError::Connect {
            path: self.path.clone(),
            reason: error.to_string(),
        })?;
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

        send_typed(
            &mut writer,
            &AppVerb::Hello {
                protocol: APP_PROTOCOL_VERSION,
            },
        )?;
        match read_typed::<AppResponse>(&mut reader)? {
            AppResponse::Hello { protocol, .. } if protocol == APP_PROTOCOL_VERSION => {}
            AppResponse::Hello { protocol, .. } => {
                return Err(HelperError::Protocol(format!(
                    "this build speaks protocol {APP_PROTOCOL_VERSION}, the namespace helper \
                     speaks {protocol}"
                )))
            }
            other => return Err(unexpected("handshake", &other)),
        }

        send_typed(&mut writer, &verb)?;
        match read_typed::<AppResponse>(&mut reader)? {
            AppResponse::Error(body) => Err(HelperError::Refused {
                code: body.code,
                message: body.message,
                sensitive: body.sensitive,
            }),
            answer => Ok(answer),
        }
    }
}

fn unexpected(what: &str, answer: &AppResponse) -> HelperError {
    HelperError::Protocol(format!(
        "expected {what}, got a {} reply",
        answer_kind(answer)
    ))
}

fn answer_kind(answer: &AppResponse) -> &'static str {
    match answer {
        AppResponse::Hello { .. } => "handshake",
        AppResponse::Applied { .. } => "applied",
        AppResponse::Created { .. } => "created",
        AppResponse::Inspected { .. } => "inspection",
        AppResponse::Verified { .. } => "verification",
        AppResponse::Launched { .. } => "session",
        AppResponse::Report(_) => "report",
        AppResponse::Error(_) => "error",
    }
}
