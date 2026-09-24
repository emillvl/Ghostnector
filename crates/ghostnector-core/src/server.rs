//! The socket that clients talk to.
//!
//! Unlike the helper's socket, this one is for humans and their programs: it is readable by a group
//! rather than a single uid, and it accepts a longer conversation (including a subscription that
//! streams state changes). The authorization model is therefore the filesystem's: the socket is
//! mode 0660 and owned by a group, and only members of that group can open it. The peer's uid is
//! recorded for the audit trail and used to scope `user` requests to the person who asked.

use std::io::{BufRead, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ghostnector_spec::ipc::{
    ErrorBody, ErrorCode, Event, Frame, Request, Response, PROTOCOL_VERSION,
};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

use crate::engine::{Engine, EngineError};
use crate::VERSION;

/// How many clients may be connected at once. A stalled local client costs a thread, nothing more.
const MAX_CONNECTIONS: usize = 64;

/// How often a streaming connection checks that its client is still there.
const STREAM_CHECK: Duration = Duration::from_millis(500);

/// Why the server could not run.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The socket could not be prepared.
    #[error("cannot use socket '{}': {reason}", path.display())]
    Bind {
        /// The socket path.
        path: PathBuf,
        /// Why it was rejected.
        reason: String,
    },
    /// The peer's identity could not be established.
    #[error("cannot determine the peer of a connection: {0}")]
    PeerCredentials(String),
    /// Accepting a connection failed.
    #[error("accepting a connection failed: {0}")]
    Accept(String),
    /// Reading or writing failed.
    #[error("io error: {0}")]
    Io(String),
}

/// What happened while handling one request.
enum Mode {
    /// Keep the conversation going.
    Continue,
    /// Answer, then hang up.
    Close,
    /// Answer, then stream events until the client leaves.
    Stream(Receiver<Event>),
}

struct Handled {
    response: Response,
    mode: Mode,
}

/// The client-facing server.
pub struct Server {
    engine: Arc<Engine>,
    connections: AtomicUsize,
}

impl Server {
    /// Serve this engine.
    pub fn new(engine: Arc<Engine>) -> Self {
        Self {
            engine,
            connections: AtomicUsize::new(0),
        }
    }

    /// Accept clients until the process is stopped.
    pub fn serve(self: Arc<Self>, listener: UnixListener) -> Result<(), ServerError> {
        loop {
            let (stream, _) = listener
                .accept()
                .map_err(|error| ServerError::Accept(error.to_string()))?;

            if self.connections.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                eprintln!("ghostnector-core: refusing a connection: too many are already open");
                drop(stream);
                continue;
            }

            self.connections.fetch_add(1, Ordering::SeqCst);
            let server = Arc::clone(&self);
            thread::spawn(move || {
                let result = server.handle_connection(stream);
                server.connections.fetch_sub(1, Ordering::SeqCst);
                if let Err(error) = result {
                    eprintln!("ghostnector-core: {error}");
                }
            });
        }
    }

    fn handle_connection(&self, stream: UnixStream) -> Result<(), ServerError> {
        let peer = peer_uid(&stream)?;
        let reading = stream
            .try_clone()
            .map_err(|error| ServerError::Io(error.to_string()))?;
        // A separate handle for the liveness check, so polling never disturbs the writer.
        let watching = stream
            .try_clone()
            .map_err(|error| ServerError::Io(error.to_string()))?;
        let alive = liveness_probe(&watching);
        let mut reader = std::io::BufReader::new(reading);
        let mut writer = stream;
        self.serve_stream_with(&mut reader, &mut writer, peer, &alive)
    }

    /// Read requests and write frames. Separated from the socket so it can be tested from buffers.
    ///
    /// `alive` is consulted while streaming, so a client that disappears without closing cleanly
    /// does not hold a thread open forever.
    fn serve_stream_with<R: BufRead, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        peer: u32,
        alive: &dyn Fn() -> bool,
    ) -> Result<(), ServerError> {
        let mut greeted = false;
        loop {
            let mut line = String::new();
            let read = reader
                .read_line(&mut line)
                .map_err(|error| ServerError::Io(error.to_string()))?;
            if read == 0 {
                return Ok(()); // the client hung up
            }
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let (response, mode) = match serde_json::from_str::<Request>(line) {
                Ok(Request::Hello { protocol, client }) => {
                    greeted = true;
                    eprintln!(
                        "ghostnector-core: '{}' connected from uid {peer}",
                        display_name(&client)
                    );
                    if protocol != PROTOCOL_VERSION {
                        (
                            error(
                                ErrorCode::ProtocolMismatch,
                                format!(
                                    "this daemon speaks protocol {PROTOCOL_VERSION}, the client \
                                     speaks {protocol}"
                                ),
                            ),
                            Mode::Close,
                        )
                    } else {
                        (
                            Response::Hello {
                                protocol: PROTOCOL_VERSION,
                                daemon_version: VERSION.to_string(),
                            },
                            Mode::Continue,
                        )
                    }
                }
                Ok(_) if !greeted => (
                    error(
                        ErrorCode::ProtocolMismatch,
                        "the first request on a connection must be a handshake",
                    ),
                    Mode::Close,
                ),
                Ok(request) => {
                    let handled = self.handle(request, peer);
                    (handled.response, handled.mode)
                }
                Err(parse_error) => (
                    error(
                        ErrorCode::Internal,
                        format!("malformed request: {parse_error}"),
                    ),
                    Mode::Continue,
                ),
            };

            write_frame(writer, &Frame::Response(response))?;

            match mode {
                Mode::Close => return Ok(()),
                Mode::Continue => {}
                Mode::Stream(events) => {
                    loop {
                        match events.recv_timeout(STREAM_CHECK) {
                            Ok(event) => {
                                if write_frame(writer, &Frame::Event(event)).is_err() {
                                    break; // the client stopped listening
                                }
                            }
                            Err(RecvTimeoutError::Timeout) => {
                                if !alive() {
                                    break;
                                }
                            }
                            Err(RecvTimeoutError::Disconnected) => break,
                        }
                    }
                    return Ok(());
                }
            }
        }
    }

    fn handle(&self, request: Request, peer: u32) -> Handled {
        let keep = |response| Handled {
            response,
            mode: Mode::Continue,
        };

        match request {
            Request::Hello { .. } => keep(error(
                ErrorCode::ProtocolMismatch,
                "this connection has already handshaken",
            )),
            Request::Snapshot => {
                self.engine.refresh();
                keep(Response::Snapshot(Box::new(self.engine.snapshot())))
            }
            Request::Connect { profile } => match self.engine.connect(profile, peer) {
                Ok(()) => keep(Response::Accepted),
                Err(error) => keep(Response::Error(error_body(&error))),
            },
            Request::Disconnect => match self.engine.disconnect() {
                Ok(()) => keep(Response::Accepted),
                Err(error) => keep(Response::Error(error_body(&error))),
            },
            Request::Panic => match self.engine.panic() {
                Ok(()) => keep(Response::Accepted),
                Err(error) => keep(Response::Error(error_body(&error))),
            },
            Request::Cancel => keep(error(
                ErrorCode::UnsafeState,
                "a transition cannot be interrupted once it has started; ask for the state again",
            )),
            Request::Subscribe => Handled {
                response: Response::Accepted,
                mode: Mode::Stream(self.engine.subscribe()),
            },
        }
    }
}

fn write_frame<W: Write>(writer: &mut W, frame: &Frame) -> Result<(), ServerError> {
    let mut encoded =
        serde_json::to_vec(frame).map_err(|error| ServerError::Io(error.to_string()))?;
    encoded.push(b'\n');
    writer
        .write_all(&encoded)
        .map_err(|error| ServerError::Io(error.to_string()))?;
    writer
        .flush()
        .map_err(|error| ServerError::Io(error.to_string()))
}

fn error(code: ErrorCode, message: impl Into<String>) -> Response {
    Response::Error(ErrorBody {
        code,
        message: message.into(),
        sensitive: false,
    })
}

fn error_body(error: &EngineError) -> ErrorBody {
    let code = match error {
        EngineError::InvalidProfile(_) | EngineError::NotSupported(_) => ErrorCode::InvalidProfile,
        EngineError::Helper(_) | EngineError::NotApplied | EngineError::Services(_) => {
            ErrorCode::BackendFailure
        }
        EngineError::Dns(_) => ErrorCode::BackendFailure,
        EngineError::Transition(_) => ErrorCode::UnsafeState,
        EngineError::Protocol(_) | EngineError::Journal(_) => ErrorCode::Internal,
    };
    ErrorBody {
        code,
        message: error.to_string(),
        sensitive: false,
    }
}

/// A client's self-chosen name, made safe for a log line.
fn display_name(client: &str) -> String {
    let cleaned: String = client
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '/'))
        .take(32)
        .collect();
    if cleaned.is_empty() {
        "unknown client".to_string()
    } else {
        cleaned
    }
}

/// The uid at the other end of a connection, as reported by the kernel.
pub fn peer_uid(stream: &UnixStream) -> Result<u32, ServerError> {
    let credentials = getsockopt(stream, PeerCredentials)
        .map_err(|error| ServerError::PeerCredentials(error.to_string()))?;
    Ok(credentials.uid())
}

/// A cheap "is the client still there?" check for a streaming connection.
///
/// A client that is killed rather than closed leaves the daemon writing into a socket nobody reads;
/// polling for hang-up and error conditions notices that without touching the data path.
pub fn liveness_probe(stream: &UnixStream) -> impl Fn() -> bool + '_ {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use std::os::fd::AsFd;

    move || {
        let descriptor = stream.as_fd();
        let mut descriptors = [PollFd::new(
            descriptor,
            PollFlags::POLLERR | PollFlags::POLLHUP,
        )];
        match poll(&mut descriptors, PollTimeout::ZERO) {
            Ok(_) => {
                let events = descriptors[0].revents().unwrap_or(PollFlags::empty());
                !events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP)
            }
            // If the question cannot be answered, assume the client is there and let the next
            // write decide.
            Err(_) => true,
        }
    }
}

/// Prepare the listening socket.
///
/// With a group, the socket is 0660 and group-owned, which is what lets a desktop user's programs
/// talk to a daemon that runs as a system user. Without one, it is 0600 and only usable by the uid
/// that runs the daemon.
pub fn bind_socket(path: &Path, group: Option<u32>) -> Result<UnixListener, ServerError> {
    let reject = |reason: String| ServerError::Bind {
        path: path.to_path_buf(),
        reason,
    };

    let parent = path
        .parent()
        .ok_or_else(|| reject("the socket needs a parent directory".to_string()))?;
    if !parent.is_dir() {
        return Err(reject(format!(
            "'{}' does not exist; on a real system systemd's RuntimeDirectory= creates it",
            parent.display()
        )));
    }

    if path.exists() {
        std::fs::remove_file(path)
            .map_err(|error| reject(format!("cannot remove the stale socket: {error}")))?;
    }

    let listener = UnixListener::bind(path).map_err(|error| reject(error.to_string()))?;

    match group {
        Some(gid) => {
            nix::unistd::chown(path, None, Some(nix::unistd::Gid::from_raw(gid))).map_err(
                |error| reject(format!("cannot give the socket to group {gid}: {error}")),
            )?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
                .map_err(|error| reject(error.to_string()))?;
        }
        None => {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|error| reject(error.to_string()))?;
        }
    }

    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineConfig;
    use crate::testing::{MockHelper, MockServices};
    use ghostnector_spec::{Networks, Profile, Scope};
    use std::sync::Arc;

    struct Fixture {
        server: Arc<Server>,
        engine: Arc<Engine>,
        helper: Arc<MockHelper>,
        directory: PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn fixture(label: &str) -> Fixture {
        let directory =
            std::env::temp_dir().join(format!("ghostnector-server-{}-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let helper = Arc::new(MockHelper::new());
        let engine = Arc::new(Engine::new(
            EngineConfig {
                journal_path: directory.join("intent.json"),
                ..EngineConfig::default()
            },
            Arc::clone(&helper) as Arc<dyn crate::helper::HelperLink>,
            Arc::new(MockServices::new()) as Arc<dyn crate::services::Services>,
            Arc::new(crate::testing::MockRelay::new()) as Arc<dyn crate::chokepoint::DnsRelay>,
            Arc::new(crate::testing::MockRunner::new()) as Arc<dyn crate::resolver::CommandRunner>,
        ));
        let server = Arc::new(Server::new(Arc::clone(&engine)));
        Fixture {
            server,
            engine,
            helper,
            directory,
        }
    }

    fn converse(server: &Server, requests: &str) -> String {
        let mut reader = std::io::BufReader::new(requests.as_bytes());
        let mut out = Vec::new();
        server
            .serve_stream_with(&mut reader, &mut out, 1000, &|| true)
            .expect("serve_stream");
        String::from_utf8(out).expect("utf8")
    }

    fn read_line(reader: &mut impl BufRead) -> String {
        let mut line = String::new();
        reader.read_line(&mut line).expect("read a line");
        line
    }

    const HELLO: &str = "{\"request\":\"hello\",\"protocol\":1,\"client\":\"test\"}\n";

    fn system_tor() -> String {
        let profile = Profile {
            scope: Scope::System,
            networks: Networks::tor(),
            ..Profile::default()
        };
        serde_json::to_string(&Request::Connect { profile }).expect("encode")
    }

    fn system_tor_profile() -> Profile {
        Profile {
            scope: Scope::System,
            networks: Networks::tor(),
            ..Profile::default()
        }
    }

    #[test]
    fn a_client_must_handshake_first() {
        let fixture = fixture("handshake");
        let body = converse(&fixture.server, "{\"request\":\"snapshot\"}\n");
        assert!(body.contains("protocol_mismatch"), "{body}");
        assert!(body.contains("handshake"), "{body}");
    }

    #[test]
    fn a_version_mismatch_closes_the_connection() {
        let fixture = fixture("version");
        let body = converse(
            &fixture.server,
            "{\"request\":\"hello\",\"protocol\":99,\"client\":\"old\"}\n{\"request\":\"snapshot\"}\n",
        );
        assert!(body.contains("protocol_mismatch"), "{body}");
        assert_eq!(body.lines().count(), 1, "{body}");
    }

    #[test]
    fn a_snapshot_reports_the_current_state() {
        let fixture = fixture("snapshot");
        let body = converse(
            &fixture.server,
            &format!("{HELLO}{{\"request\":\"snapshot\"}}\n"),
        );
        assert!(body.contains("\"state\":\"off\""), "{body}");
        assert!(
            body.contains("\"frame\":\"response\""),
            "expected a framed response: {body}"
        );
    }

    #[test]
    fn connecting_through_the_socket_reaches_the_helper() {
        let fixture = fixture("connect");
        let body = converse(
            &fixture.server,
            &format!("{HELLO}{}\n{{\"request\":\"snapshot\"}}\n", system_tor()),
        );
        assert!(body.contains("\"response\":\"accepted\""), "{body}");
        assert!(body.contains("\"state\":\"degraded\""), "{body}");
        assert_eq!(
            fixture.helper.applied_sequence(),
            vec![
                ghostnector_spec::ProfileId::FailClosed,
                ghostnector_spec::ProfileId::TorSystem
            ]
        );
    }

    #[test]
    fn a_refusal_becomes_an_error_frame_with_a_code() {
        let fixture = fixture("refused");
        fixture.helper.fail_apply_with("the kernel said no");
        let body = converse(&fixture.server, &format!("{HELLO}{}\n", system_tor()));
        assert!(body.contains("\"response\":\"error\""), "{body}");
        assert!(body.contains("\"code\":\"backend_failure\""), "{body}");
        assert!(body.contains("the kernel said no"), "{body}");
    }

    #[test]
    fn panicking_and_disconnecting_are_reachable_over_the_socket() {
        let fixture = fixture("panic");
        let body = converse(
            &fixture.server,
            &format!(
                "{HELLO}{}\n{{\"request\":\"panic\"}}\n{{\"request\":\"snapshot\"}}\n{{\"request\":\"disconnect\"}}\n{{\"request\":\"snapshot\"}}\n",
                system_tor()
            ),
        );
        assert!(body.contains("\"state\":\"blocked\""), "{body}");
        assert!(body.contains("\"state\":\"off\""), "{body}");
    }

    #[test]
    fn a_subscription_streams_state_changes_and_ends_when_the_client_leaves() {
        let fixture = fixture("subscribe");
        let (client, server_side) = UnixStream::pair().expect("socket pair");
        let server = Arc::clone(&fixture.server);

        let worker = std::thread::spawn(move || {
            let watcher = server_side.try_clone().expect("clone");
            let alive = liveness_probe(&watcher);
            let mut reader = std::io::BufReader::new(server_side.try_clone().expect("clone"));
            let mut writer = server_side;
            server.serve_stream_with(&mut reader, &mut writer, 1000, &alive)
        });

        let mut client_writer = client.try_clone().expect("clone");
        let mut client_reader = std::io::BufReader::new(client);
        client_writer
            .write_all(format!("{HELLO}{{\"request\":\"subscribe\"}}\n").as_bytes())
            .expect("write");
        client_writer.flush().expect("flush");

        // The handshake reply first, then the answer to the subscription.
        let hello = read_line(&mut client_reader);
        assert!(hello.contains("\"response\":\"hello\""), "{hello}");
        let accepted = read_line(&mut client_reader);
        assert!(accepted.contains("\"response\":\"accepted\""), "{accepted}");

        fixture
            .engine
            .connect(system_tor_profile(), 1000)
            .expect("connect");

        let mut saw_degraded = false;
        for _ in 0..6 {
            let event = read_line(&mut client_reader);
            if event.contains("\"state\":\"degraded\"") {
                saw_degraded = true;
            }
            if saw_degraded {
                break;
            }
        }
        assert!(saw_degraded, "the subscription must see the applied state");

        // The client vanishes without saying goodbye; the daemon must notice on its own.
        drop(client_writer);
        drop(client_reader);
        let outcome = worker.join().expect("the streaming thread must finish");
        assert!(outcome.is_ok(), "{outcome:?}");
    }

    #[test]
    fn cancel_is_refused_with_an_explanation() {
        let fixture = fixture("cancel");
        let body = converse(
            &fixture.server,
            &format!("{HELLO}{{\"request\":\"cancel\"}}\n"),
        );
        assert!(body.contains("\"code\":\"unsafe_state\""), "{body}");
    }

    #[test]
    fn client_supplied_names_are_made_safe() {
        assert_eq!(display_name("ghostnector-cli/0.1"), "ghostnector-cli/0.1");
        assert_eq!(display_name("evil\nname"), "evilname");
        assert_eq!(display_name(""), "unknown client");
        assert_eq!(display_name(&"x".repeat(100)).len(), 32);
    }
}
