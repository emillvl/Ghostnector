//! Asking Tor how it is doing, and nothing else.
//!
//! The control port is a powerful interface, so this client uses exactly two commands:
//! `AUTHENTICATE` with the cookie, and `GETINFO status/bootstrap-phase`. It never asks about
//! circuits, streams, or destinations, and it never sets anything. That restraint is deliberate:
//! the control port can see where traffic is going, and nothing in this process needs to.
//!
//! Aggregate health for the interface (circuit counts, bytes carried) would come through here too,
//! and would be the moment to re-examine that restraint rather than add a third command quietly.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// How long to wait between polls while Tor bootstraps.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// How far Tor has got towards being usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bootstrap {
    /// The control port answered but has no bootstrap phase to report yet.
    NotStarted,
    /// Tor is building its first circuits.
    Progress {
        /// Tor's own estimate, 0 to 100.
        percent: u8,
        /// Tor's summary, for the log. Not shown verbatim to users.
        summary: String,
    },
    /// Tor is ready to carry traffic.
    Done,
    /// Tor says something is wrong.
    Failed {
        /// What Tor said.
        summary: String,
    },
}

impl Bootstrap {
    /// A short description for a state message. Contains nothing sensitive.
    pub fn describe(&self) -> String {
        match self {
            Bootstrap::NotStarted => "Tor has not started bootstrapping yet".to_string(),
            Bootstrap::Progress { percent, .. } => {
                format!("Tor is {percent}% bootstrapped")
            }
            Bootstrap::Done => "Tor is ready".to_string(),
            Bootstrap::Failed { summary } => format!("Tor reported a problem: {summary}"),
        }
    }
}

/// Why Tor's health could not be established.
#[derive(Debug, thiserror::Error)]
pub enum TorControlError {
    /// Nothing is listening on the control port yet.
    #[error("Tor's control port at {address} is not answering: {reason}")]
    Unreachable {
        /// The address tried.
        address: SocketAddr,
        /// What went wrong.
        reason: String,
    },
    /// The cookie is not there yet, which is normal while Tor starts.
    #[error("Tor has not written its control cookie at '{}' yet", .0.display())]
    CookieMissing(PathBuf),
    /// The cookie exists but cannot be used.
    #[error("Tor's control cookie at '{}' cannot be used: {reason}", path.display())]
    Cookie {
        /// The path tried.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },
    /// Tor refused a command.
    #[error("Tor refused the control command: {0}")]
    Refused(String),
    /// Tor's answers could not be understood.
    #[error("Tor's answer could not be understood: {0}")]
    Protocol(String),
    /// Tor never became ready.
    #[error("Tor did not become ready within {after_secs}s (last report: {last})")]
    Timeout {
        /// How long was allowed.
        after_secs: u64,
        /// The last thing Tor said.
        last: String,
    },
    /// Tor said it failed.
    #[error("{0}")]
    BootstrapFailed(String),
}

/// A read-only client for Tor's control port.
#[derive(Debug, Clone)]
pub struct TorControl {
    address: SocketAddr,
    cookie_path: PathBuf,
    command_timeout: Duration,
}

impl TorControl {
    /// Build a client. Nothing is contacted until [`TorControl::bootstrap`] is called.
    pub fn new(address: SocketAddr, cookie_path: PathBuf, command_timeout: Duration) -> Self {
        Self {
            address,
            cookie_path,
            command_timeout,
        }
    }

    /// Where the control port is expected.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Ask Tor how far it has got.
    pub fn bootstrap(&self) -> Result<Bootstrap, TorControlError> {
        let cookie = self.read_cookie_hex()?;

        let stream =
            TcpStream::connect_timeout(&self.address, self.command_timeout).map_err(|error| {
                TorControlError::Unreachable {
                    address: self.address,
                    reason: error.to_string(),
                }
            })?;
        stream
            .set_read_timeout(Some(self.command_timeout))
            .map_err(|error| TorControlError::Unreachable {
                address: self.address,
                reason: error.to_string(),
            })?;
        stream
            .set_write_timeout(Some(self.command_timeout))
            .map_err(|error| TorControlError::Unreachable {
                address: self.address,
                reason: error.to_string(),
            })?;

        let mut writer = stream
            .try_clone()
            .map_err(|error| TorControlError::Protocol(error.to_string()))?;
        let mut reader = BufReader::new(stream);

        // Tor greets first, so a port that accepts connections but says nothing is not Tor.
        read_reply(&mut reader)?;
        send(&mut writer, &format!("AUTHENTICATE {cookie}"))?;
        read_reply(&mut reader)?;
        send(&mut writer, "GETINFO status/bootstrap-phase")?;
        let values = read_reply(&mut reader)?;

        Ok(parse_bootstrap(&values))
    }

    /// Poll until Tor is ready, Tor fails, or the budget runs out.
    pub fn wait_until_ready(&self, budget: Duration) -> Result<Bootstrap, TorControlError> {
        let deadline = Instant::now() + budget;
        let mut last = Bootstrap::NotStarted;
        let mut last_error: Option<String> = None;

        loop {
            match self.bootstrap() {
                Ok(Bootstrap::Done) => return Ok(Bootstrap::Done),
                Ok(Bootstrap::Failed { summary }) => {
                    return Err(TorControlError::BootstrapFailed(summary))
                }
                Ok(other) => {
                    last = other;
                    last_error = None;
                }
                // Anything else is Tor telling us something we should not ignore.
                Err(error) => {
                    let reason = error.to_string();
                    let merely_not_ready = matches!(
                        error,
                        TorControlError::Unreachable { .. }
                            | TorControlError::CookieMissing(_)
                            | TorControlError::Cookie { .. }
                    );
                    if !merely_not_ready {
                        return Err(error);
                    }
                    last_error = Some(reason);
                }
            }

            if Instant::now() >= deadline {
                return Err(TorControlError::Timeout {
                    after_secs: budget.as_secs(),
                    last: match &last_error {
                        Some(reason) => format!("{} ({reason})", last.describe()),
                        None => last.describe(),
                    },
                });
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn read_cookie_hex(&self) -> Result<String, TorControlError> {
        match std::fs::read(&self.cookie_path) {
            Ok(bytes) => {
                if bytes.len() != 32 {
                    return Err(TorControlError::Cookie {
                        path: self.cookie_path.clone(),
                        reason: format!("expected 32 bytes, found {}", bytes.len()),
                    });
                }
                Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(TorControlError::CookieMissing(self.cookie_path.clone()))
            }
            Err(error) => Err(TorControlError::Cookie {
                path: self.cookie_path.clone(),
                reason: error.to_string(),
            }),
        }
    }
}

fn send(stream: &mut impl Write, command: &str) -> Result<(), TorControlError> {
    stream
        .write_all(format!("{command}\r\n").as_bytes())
        .map_err(|error| TorControlError::Protocol(error.to_string()))?;
    stream
        .flush()
        .map_err(|error| TorControlError::Protocol(error.to_string()))
}

/// Read one reply, following continuation lines and data blocks.
fn read_reply(reader: &mut impl BufRead) -> Result<Vec<String>, TorControlError> {
    let mut values = Vec::new();
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .map_err(|error| TorControlError::Protocol(error.to_string()))?;
        if read == 0 {
            return Err(TorControlError::Protocol(
                "the control port closed the connection".to_string(),
            ));
        }
        let line = line.trim_end_matches(['\r', '\n']).to_string();
        if line.len() < 4 {
            return Err(TorControlError::Protocol(format!(
                "unexpected line: {line}"
            )));
        }

        let code = &line[..3];
        let separator = line.as_bytes()[3];
        match code {
            "250" => match separator {
                b'-' => values.push(line[4..].to_string()),
                b'+' => {
                    // A data block runs until a line containing only a dot.
                    values.push(line[4..].to_string());
                    loop {
                        let mut data = String::new();
                        let read = reader
                            .read_line(&mut data)
                            .map_err(|error| TorControlError::Protocol(error.to_string()))?;
                        if read == 0 {
                            return Err(TorControlError::Protocol(
                                "a data block was never terminated".to_string(),
                            ));
                        }
                        let data = data.trim_end_matches(['\r', '\n']);
                        if data == "." {
                            break;
                        }
                        values.push(data.to_string());
                    }
                }
                _ => {
                    values.push(line[4..].to_string());
                    return Ok(values);
                }
            },
            _ if code.starts_with('4') || code.starts_with('5') => {
                return Err(TorControlError::Refused(line))
            }
            _ => {
                return Err(TorControlError::Protocol(format!(
                    "unexpected reply: {line}"
                )))
            }
        }
    }
}

/// Turn `status/bootstrap-phase` into something the state machine can use.
fn parse_bootstrap(values: &[String]) -> Bootstrap {
    let Some(value) = values
        .iter()
        .find_map(|value| value.split_once("status/bootstrap-phase="))
        .map(|(_, rest)| rest)
    else {
        return Bootstrap::NotStarted;
    };

    let mut percent = 0u8;
    let mut tag = String::new();
    let mut summary = String::new();

    // `SUMMARY` is a quoted string and may contain spaces, so it cannot be found by splitting on
    // whitespace: the value runs until the closing quote.
    if let Some(start) = value.find("SUMMARY=\"") {
        let rest = &value[start + "SUMMARY=\"".len()..];
        if let Some(end) = rest.find('"') {
            summary = rest[..end].to_string();
        }
    }

    for token in value.split_whitespace() {
        if let Some(number) = token.strip_prefix("PROGRESS=") {
            percent = number.parse().unwrap_or(0);
        } else if let Some(value) = token.strip_prefix("TAG=") {
            tag = value.to_string();
        }
    }

    if percent == 100 && (tag == "done" || tag.is_empty()) {
        return Bootstrap::Done;
    }
    if tag.starts_with("error") || tag.starts_with("warn") {
        return Bootstrap::Failed {
            summary: if summary.is_empty() {
                format!("bootstrap stopped at {percent}%")
            } else {
                summary
            },
        };
    }
    Bootstrap::Progress { percent, summary }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "ghostnector-torcontrol-{}-{label}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }

        fn cookie(&self, bytes: &[u8]) -> PathBuf {
            let path = self.0.join("control_auth_cookie");
            std::fs::write(&path, bytes).expect("write cookie");
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A stand-in for Tor's control port, answering as many connections as asked.
    fn fake_control<F>(responder: F) -> (SocketAddr, Arc<AtomicUsize>)
    where
        F: Fn(&str) -> Option<String> + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("local address");
        let served = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&served);
        let responder = Arc::new(responder);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                counter.fetch_add(1, Ordering::SeqCst);
                let responder = Arc::clone(&responder);
                std::thread::spawn(move || serve(stream, responder));
            }
        });

        (address, served)
    }

    fn serve<F>(stream: TcpStream, responder: Arc<F>)
    where
        F: Fn(&str) -> Option<String> + Send + Sync + 'static,
    {
        let Ok(reading) = stream.try_clone() else {
            return;
        };
        let mut reader = BufReader::new(reading);
        let mut writer = stream;
        if writer.write_all(b"250 OK\r\n").is_err() {
            return;
        }
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            match responder(line.trim()) {
                Some(reply) => {
                    if writer.write_all(reply.as_bytes()).is_err() {
                        return;
                    }
                }
                None => return,
            }
        }
    }

    fn tor_saying(phase: &'static str) -> (SocketAddr, Arc<AtomicUsize>) {
        fake_control(move |command| {
            if command.starts_with("AUTHENTICATE") {
                Some("250 OK\r\n".to_string())
            } else if command.starts_with("GETINFO status/bootstrap-phase") {
                Some(format!("250-status/bootstrap-phase={phase}\r\n250 OK\r\n"))
            } else {
                None
            }
        })
    }

    fn client(address: SocketAddr, cookie: PathBuf) -> TorControl {
        TorControl::new(address, cookie, Duration::from_secs(2))
    }

    #[test]
    fn a_bootstrapped_tor_is_reported_as_ready() {
        let dir = TempDir::new("ready");
        let (address, _) = tor_saying("NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"");
        let control = client(address, dir.cookie(&[7u8; 32]));
        assert_eq!(control.bootstrap().expect("bootstrap"), Bootstrap::Done);
    }

    #[test]
    fn partial_progress_is_reported_as_progress() {
        let dir = TempDir::new("progress");
        let (address, _) =
            tor_saying("NOTICE BOOTSTRAP PROGRESS=45 TAG=loading_status SUMMARY=\"Loading\"");
        let control = client(address, dir.cookie(&[7u8; 32]));
        match control.bootstrap().expect("bootstrap") {
            Bootstrap::Progress { percent, .. } => assert_eq!(percent, 45),
            other => panic!("expected progress, got {other:?}"),
        }
    }

    #[test]
    fn a_failing_tor_is_reported_as_failed() {
        let dir = TempDir::new("failed");
        let (address, _) = tor_saying(
            "NOTICE BOOTSTRAP PROGRESS=10 TAG=error SUMMARY=\"Could not connect to a relay\"",
        );
        let control = client(address, dir.cookie(&[7u8; 32]));
        match control.bootstrap().expect("bootstrap") {
            Bootstrap::Failed { summary } => {
                assert!(summary.contains("Could not connect"), "{summary}")
            }
            other => panic!("expected failure, got {other:?}"),
        }
    }

    #[test]
    fn bad_authentication_is_refused_rather_than_retried_forever() {
        let dir = TempDir::new("bad-auth");
        let (address, _) = fake_control(|command| {
            if command.starts_with("AUTHENTICATE") {
                Some("515 Bad authentication\r\n".to_string())
            } else {
                None
            }
        });
        let control = client(address, dir.cookie(&[1u8; 32]));
        let error = control.bootstrap().unwrap_err();
        assert!(matches!(error, TorControlError::Refused(_)), "{error}");
    }

    #[test]
    fn a_missing_cookie_means_tor_is_simply_not_up_yet() {
        let dir = TempDir::new("no-cookie");
        let (address, _) = tor_saying("NOTICE BOOTSTRAP PROGRESS=100 TAG=done");
        let control = client(address, dir.0.join("not-written-yet"));
        let error = control.bootstrap().unwrap_err();
        assert!(
            matches!(error, TorControlError::CookieMissing(_)),
            "{error}"
        );
    }

    #[test]
    fn a_cookie_of_the_wrong_size_is_refused() {
        let dir = TempDir::new("short-cookie");
        let (address, _) = tor_saying("NOTICE BOOTSTRAP PROGRESS=100 TAG=done");
        let control = client(address, dir.cookie(&[1u8; 16]));
        let error = control.bootstrap().unwrap_err();
        assert!(matches!(error, TorControlError::Cookie { .. }), "{error}");
    }

    #[test]
    fn a_port_that_says_nothing_is_a_protocol_error() {
        let dir = TempDir::new("silent");
        let (address, _) = fake_control(|_| None);
        let control = client(address, dir.cookie(&[1u8; 32]));
        let error = control.bootstrap().unwrap_err();
        assert!(matches!(error, TorControlError::Protocol(_)), "{error}");
    }

    #[test]
    fn waiting_returns_as_soon_as_tor_is_ready() {
        let dir = TempDir::new("wait-ready");
        let (address, served) =
            tor_saying("NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"");
        let control = client(address, dir.cookie(&[3u8; 32]));
        let began = Instant::now();
        assert_eq!(
            control
                .wait_until_ready(Duration::from_secs(5))
                .expect("ready"),
            Bootstrap::Done
        );
        assert!(began.elapsed() < Duration::from_secs(5));
        assert_eq!(served.load(Ordering::SeqCst), 1, "one poll was enough");
    }

    #[test]
    fn waiting_gives_up_after_the_budget() {
        let dir = TempDir::new("wait-timeout");
        let (address, served) =
            tor_saying("NOTICE BOOTSTRAP PROGRESS=50 TAG=loading_status SUMMARY=\"Halfway\"");
        let control = client(address, dir.cookie(&[3u8; 32]));
        let error = control
            .wait_until_ready(Duration::from_millis(600))
            .unwrap_err();
        match error {
            TorControlError::Timeout { last, .. } => {
                assert!(last.contains("50%"), "{last}");
            }
            other => panic!("expected a timeout, got {other}"),
        }
        assert!(
            served.load(Ordering::SeqCst) > 1,
            "waiting must poll rather than give up after one try"
        );
    }

    #[test]
    fn waiting_stops_immediately_when_tor_says_it_failed() {
        let dir = TempDir::new("wait-failed");
        let (address, _) =
            tor_saying("NOTICE BOOTSTRAP PROGRESS=10 TAG=error SUMMARY=\"No usable relays\"");
        let control = client(address, dir.cookie(&[3u8; 32]));
        let error = control
            .wait_until_ready(Duration::from_secs(5))
            .unwrap_err();
        assert!(
            matches!(error, TorControlError::BootstrapFailed(_)),
            "{error}"
        );
    }

    #[test]
    fn a_reply_with_no_status_line_is_not_mistaken_for_readiness() {
        assert_eq!(
            parse_bootstrap(&["250 OK".to_string()]),
            Bootstrap::NotStarted
        );
    }

    #[test]
    fn a_summary_containing_spaces_survives_intact() {
        let phase = "status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=10 TAG=error \
                     SUMMARY=\"Could not connect to a relay\"";
        match parse_bootstrap(&[phase.to_string()]) {
            Bootstrap::Failed { summary } => {
                assert_eq!(summary, "Could not connect to a relay")
            }
            other => panic!("expected a failure with a whole summary, got {other:?}"),
        }
    }

    #[test]
    fn progress_at_one_hundred_without_a_tag_still_counts_as_done() {
        // Older Tor versions report 100 with an empty tag.
        assert_eq!(
            parse_bootstrap(&[
                "status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=".to_string()
            ]),
            Bootstrap::Done
        );
    }

    #[test]
    fn descriptions_are_safe_to_show() {
        assert!(Bootstrap::Progress {
            percent: 20,
            summary: "Loading relays".to_string()
        }
        .describe()
        .contains("20%"));
        assert!(Bootstrap::Done.describe().contains("ready"));
    }
}
