//! The helper's request loop.
//!
//! The security-relevant decisions all live here, and they are deliberately small enough to read in
//! one sitting:
//!
//! * A connection is only read from if its peer uid is exactly the configured one, checked with
//!   `SO_PEERCRED` — the kernel's answer, not the client's claim.
//! * The first request must be a handshake, and a version mismatch closes the connection instead of
//!   being negotiated.
//! * A verb is dispatched to a fixed operation. Unknown or malformed input produces an error
//!   response; it never reaches a command, a path, or a ruleset.
//!
//! The dispatch path ([`Server::handle`]) and the framing path ([`Server::serve_stream`]) are
//! separate so both can be tested without a socket, a kernel, or root.

use std::io::{BufRead, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use ghostnector_policy::{compile, render_replace_script, render_revert_script, Environment};
use ghostnector_spec::backend::{Params, Ports, ProfileId, Report, ResolvedIdentity, Verb};
use ghostnector_spec::exemption::Exemption;
use ghostnector_spec::ipc::{ErrorBody, ErrorCode, HelperResponse, PROTOCOL_VERSION};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

use crate::backend::Backend;
use crate::config::Config;
use crate::identities::Identities;
use crate::VERSION;

/// The most connections served at once. A local client that stalls must not consume the helper.
const MAX_CONNECTIONS: usize = 16;

/// How long a client may stall mid-request.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Why the helper could not run.
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
    /// Input or output failed.
    #[error("io error: {0}")]
    Io(String),
}

/// What the helper last applied, as it remembers it.
#[derive(Debug, Default)]
struct Applied {
    profile: Option<ProfileId>,
    params: Option<Params>,
    exemptions: Vec<Exemption>,
    notes: Vec<String>,
    /// The kernel's own report of the policy that was applied, canonicalised. The comparison at
    /// verification time is against *this*, not against what the helper intended to write, so a
    /// change made by anything else is visible even though the helper knows nothing about it.
    effective: Option<String>,
}

/// Reduce a kernel ruleset listing to the part that describes policy rather than traffic.
///
/// Counters carry live values, so they change with use and are not part of the policy. Everything
/// else is compared exactly: this runs against two listings from the same formatter, so there is no
/// brittleness to trade against precision.
fn canonical(ruleset: &str) -> String {
    let mut out = String::new();
    for line in ruleset.lines() {
        if line.trim_start().starts_with("destroy table") {
            continue;
        }
        let mut kept: Vec<&str> = Vec::new();
        let mut tokens = line.split_whitespace().peekable();
        while let Some(token) = tokens.next() {
            if (token == "packets" || token == "bytes")
                && kept.last().is_some_and(|last| *last == "counter")
            {
                tokens.next(); // the number that follows
                continue;
            }
            kept.push(token);
        }
        if kept.is_empty() {
            continue;
        }
        out.push_str(&kept.join(" "));
        out.push('\n');
    }
    out
}

/// The privileged helper.
pub struct Server<B: Backend + 'static, I: Identities + 'static> {
    config: Config,
    backend: Arc<B>,
    identities: I,
    applied: Mutex<Applied>,
    connections: AtomicUsize,
}

impl<B: Backend + 'static, I: Identities + 'static> Server<B, I> {
    /// Build a helper. Nothing is applied until a verb asks for it.
    pub fn new(config: Config, backend: Arc<B>, identities: I) -> Self {
        Self {
            config,
            backend,
            identities,
            applied: Mutex::new(Applied::default()),
            connections: AtomicUsize::new(0),
        }
    }

    /// The configuration in force.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// What the kernel currently has, plus what the helper last applied.
    ///
    /// `applied` is answered by the kernel, never by memory: if someone removed our table while we
    /// were not looking, this reports that truthfully.
    pub fn report(&self) -> Report {
        let applied = self.backend.table_present().unwrap_or(false);
        let guard = self.lock();
        Report {
            applied,
            profile: guard.profile,
            exemptions: guard.exemptions.clone(),
            resolved: self.resolved_identities(),
            // Reported so the control plane can configure Tor with the same numbers the policy
            // redirects into.
            ports: Ports {
                trans: self.config.trans_port,
                chokepoint: self.config.chokepoint_port,
                socks: self.config.socks_port,
            },
            notes: guard.notes.clone(),
        }
    }

    /// Handle one verb. This is the whole dispatch surface.
    pub fn handle(&self, verb: Verb) -> HelperResponse {
        match verb {
            Verb::Hello { protocol } => {
                if protocol != PROTOCOL_VERSION {
                    return HelperResponse::Error(self.problem(
                        ErrorCode::ProtocolMismatch,
                        format!(
                            "this helper speaks protocol {PROTOCOL_VERSION}, the caller speaks {protocol}"
                        ),
                    ));
                }
                HelperResponse::Hello {
                    protocol: PROTOCOL_VERSION,
                    version: VERSION.to_string(),
                }
            }
            Verb::ApplyProfile { profile, params } => match self.apply_profile(profile, &params) {
                Ok(report) => HelperResponse::Applied { report },
                Err(body) => HelperResponse::Error(body),
            },
            Verb::Revert => match self.revert() {
                Ok(report) => HelperResponse::Applied { report },
                Err(body) => HelperResponse::Error(body),
            },
            Verb::FlushConntrack => match self.flush() {
                Ok(report) => HelperResponse::Applied { report },
                Err(body) => HelperResponse::Error(body),
            },
            Verb::Verify => match self.verify_policy() {
                Ok((matches, detail)) => HelperResponse::Verified { matches, detail },
                Err(body) => HelperResponse::Error(body),
            },
            Verb::Report => HelperResponse::Report(self.report()),
        }
    }

    /// Read requests and write responses until the caller goes away.
    ///
    /// Separated from the socket so it can be driven from a buffer in tests.
    fn serve_stream<R: BufRead, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), ServerError> {
        let mut greeted = false;
        loop {
            let mut line = String::new();
            let read = reader
                .read_line(&mut line)
                .map_err(|error| ServerError::Io(error.to_string()))?;
            if read == 0 {
                return Ok(()); // the caller hung up
            }
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let mut close_after = false;
            let response = match serde_json::from_str::<Verb>(line) {
                Ok(Verb::Hello { protocol }) => {
                    greeted = true;
                    close_after = protocol != PROTOCOL_VERSION;
                    self.handle(Verb::Hello { protocol })
                }
                Ok(verb) if greeted => self.handle(verb),
                Ok(_) => HelperResponse::Error(self.problem(
                    ErrorCode::ProtocolMismatch,
                    "the first request on a connection must be a handshake",
                )),
                Err(error) => HelperResponse::Error(
                    self.problem(ErrorCode::Internal, format!("malformed request: {error}")),
                ),
            };

            let mut encoded = serde_json::to_vec(&response)
                .map_err(|error| ServerError::Io(error.to_string()))?;
            encoded.push(b'\n');
            writer
                .write_all(&encoded)
                .map_err(|error| ServerError::Io(error.to_string()))?;
            writer
                .flush()
                .map_err(|error| ServerError::Io(error.to_string()))?;

            if close_after {
                return Ok(());
            }
        }
    }

    /// Accept connections until the process is stopped.
    pub fn serve(self: Arc<Self>, listener: UnixListener) -> Result<(), ServerError> {
        loop {
            let (stream, _) = listener
                .accept()
                .map_err(|error| ServerError::Accept(error.to_string()))?;

            if self.connections.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                eprintln!(
                    "ghostnector-netd: refusing a connection: {MAX_CONNECTIONS} are already open"
                );
                drop(stream);
                continue;
            }

            self.connections.fetch_add(1, Ordering::SeqCst);
            let server = Arc::clone(&self);
            thread::spawn(move || {
                let result = server.handle_connection(stream);
                server.connections.fetch_sub(1, Ordering::SeqCst);
                if let Err(error) = result {
                    eprintln!("ghostnector-netd: {error}");
                }
            });
        }
    }

    fn handle_connection(&self, stream: UnixStream) -> Result<(), ServerError> {
        let peer = peer_uid(&stream)?;
        if !is_authorized(peer, self.config.peer_uid) {
            // Do not read a single byte from an identity we do not serve.
            return Err(ServerError::PeerCredentials(format!(
                "refused a connection from uid {peer}"
            )));
        }

        stream
            .set_read_timeout(Some(READ_TIMEOUT))
            .map_err(|error| ServerError::Io(error.to_string()))?;
        let reading = stream
            .try_clone()
            .map_err(|error| ServerError::Io(error.to_string()))?;
        let mut reader = std::io::BufReader::new(reading);
        let mut writer = stream;
        self.serve_stream(&mut reader, &mut writer)
    }

    fn apply_profile(&self, profile: ProfileId, params: &Params) -> Result<Report, ErrorBody> {
        let environment = self.environment();
        let compiled = compile(profile, params, &environment)
            .map_err(|error| self.problem(ErrorCode::InvalidProfile, error.to_string()))?;

        let script = render_replace_script(&compiled.ruleset);
        self.backend
            .apply(&script)
            .map_err(|error| self.problem(ErrorCode::BackendFailure, error.to_string()))?;

        // Trust the kernel, not the exit status.
        match self.backend.table_present() {
            Ok(true) => {}
            Ok(false) => {
                return Err(self.problem(
                    ErrorCode::BackendFailure,
                    "the policy was applied but no table is present".to_string(),
                ))
            }
            Err(error) => return Err(self.problem(ErrorCode::BackendFailure, error.to_string())),
        }

        // Record what the kernel says it has. Everything later is compared against this, so a change
        // made by anything else is visible even though this helper knows nothing about it.
        let effective = self
            .backend
            .list_table()
            .map(|live| canonical(&live))
            .map_err(|error| self.problem(ErrorCode::BackendFailure, error.to_string()))?;

        let mut notes = Vec::new();
        if let Err(error) = self.backend.flush_conntrack() {
            notes.push(format!(
                "conntrack was not flushed ({error}); pre-existing flows are blocked rather than captured"
            ));
        }

        // Keep a copy of the fail-closed policy where the boot guard can reach it. This is the one
        // place a second writer is tolerated, and it is this helper's own rendered output: if this
        // process is ever unavailable at boot, the machine can still deny everything.
        if profile == ProfileId::FailClosed {
            if let Err(reason) = write_fallback(&self.config.fallback_path, &script) {
                notes.push(format!(
                    "a copy of the fail-closed policy could not be kept for the boot guard: {reason}"
                ));
            }
        }

        {
            let mut applied = self.lock();
            applied.profile = Some(profile);
            applied.params = Some(params.clone());
            applied.exemptions = compiled.exemptions;
            applied.notes = notes;
            applied.effective = Some(effective);
        }
        Ok(self.report())
    }

    fn revert(&self) -> Result<Report, ErrorBody> {
        let script = render_revert_script();
        self.backend
            .apply(&script)
            .map_err(|error| self.problem(ErrorCode::BackendFailure, error.to_string()))?;
        {
            let mut applied = self.lock();
            *applied = Applied::default();
        }
        Ok(self.report())
    }
    fn flush(&self) -> Result<Report, ErrorBody> {
        self.backend
            .flush_conntrack()
            .map_err(|error| self.problem(ErrorCode::BackendFailure, error.to_string()))?;
        Ok(self.report())
    }

    /// Compare the kernel's policy against the one that was applied, and say where they differ.
    fn verify_policy(&self) -> Result<(bool, String), ErrorBody> {
        let expected = self.lock().effective.clone();
        let Some(expected) = expected else {
            return Ok((
                true,
                "nothing is applied, so there is nothing to compare".to_string(),
            ));
        };

        let live = self
            .backend
            .list_table()
            .map_err(|error| self.problem(ErrorCode::BackendFailure, error.to_string()))?;
        let live = canonical(&live);
        if live == expected {
            return Ok((
                true,
                "the kernel's policy is the one that was applied".to_string(),
            ));
        }

        if live.is_empty() {
            return Ok((
                false,
                "the policy is no longer in the kernel at all".to_string(),
            ));
        }

        // Name the first difference, which is policy text and contains no destinations.
        let expected_lines: Vec<&str> = expected.lines().collect();
        let live_lines: Vec<&str> = live.lines().collect();
        for (index, (want, got)) in expected_lines.iter().zip(live_lines.iter()).enumerate() {
            if want != got {
                return Ok((
                    false,
                    format!(
                        "line {} of the policy differs: applied '{want}' but the kernel has '{got}'",
                        index + 1
                    ),
                ));
            }
        }
        let difference = if live_lines.len() > expected_lines.len() {
            format!(
                "the kernel has a line that was not applied: '{}'",
                live_lines[expected_lines.len()]
            )
        } else if live_lines.len() < expected_lines.len() {
            format!(
                "the kernel is missing a line that was applied: '{}'",
                expected_lines[live_lines.len()]
            )
        } else {
            "the policy in the kernel differs from the one that was applied".to_string()
        };
        Ok((false, difference))
    }

    fn environment(&self) -> Environment {
        Environment {
            tor_uid: self.identities.uid_of(&self.config.tor_user).ok(),
            dnscrypt_uid: self.identities.uid_of(&self.config.dnscrypt_user).ok(),
            trans_port: self.config.trans_port,
            chokepoint_port: self.config.chokepoint_port,
            socks_port: self.config.socks_port,
            dhcp_client_port: self.config.dhcp_client_port,
        }
    }

    fn resolved_identities(&self) -> Vec<ResolvedIdentity> {
        [&self.config.tor_user, &self.config.dnscrypt_user]
            .into_iter()
            .map(|name| ResolvedIdentity {
                name: name.clone(),
                uid: self.identities.uid_of(name).ok(),
            })
            .collect()
    }

    fn problem(&self, code: ErrorCode, message: impl Into<String>) -> ErrorBody {
        ErrorBody {
            code,
            message: message.into(),
            sensitive: false,
        }
    }

    /// A poisoned lock means someone panicked while holding it; the state is still readable, and
    /// refusing to serve would be worse than serving a slightly stale report.
    fn lock(&self) -> MutexGuard<'_, Applied> {
        self.applied
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Keep a copy of a rendered policy where only root can read it.
fn write_fallback(path: &std::path::Path, script: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(script.as_bytes())
        .map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

/// Whether a peer with this uid may talk to the helper.
///
/// Root is accepted alongside the configured peer. That is not a widening: a process running as root
/// could write the policy directly and never needed this helper's permission. What the check is for
/// is refusing *unprivileged* processes that are not the control plane — and the boot guard, which
/// runs before the control plane exists, is a legitimate root caller.
pub const fn is_authorized(peer: u32, allowed: u32) -> bool {
    peer == allowed || peer == 0
}

/// The uid at the other end of a connection, as reported by the kernel.
pub fn peer_uid(stream: &UnixStream) -> Result<u32, ServerError> {
    let credentials = getsockopt(stream, PeerCredentials)
        .map_err(|error| ServerError::PeerCredentials(error.to_string()))?;
    Ok(credentials.uid())
}

/// Prepare the listening socket.
///
/// The socket is handed to the uid that is allowed to talk to us and made owner-only, so the
/// filesystem is the first gate and `SO_PEERCRED` is the second.
pub fn bind_socket(config: &Config) -> Result<UnixListener, ServerError> {
    let path = &config.socket;
    let reject = |reason: String| ServerError::Bind {
        path: path.clone(),
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

    nix::unistd::chown(
        path.as_path(),
        Some(nix::unistd::Uid::from_raw(config.peer_uid)),
        None,
    )
    .map_err(|error| {
        reject(format!(
            "cannot hand the socket to uid {}: {error}",
            config.peer_uid
        ))
    })?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| reject(format!("cannot restrict the socket: {error}")))?;

    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Parsed;
    use crate::testing::{FixedIdentities, MockBackend};

    const TOR_UID: u32 = 987;

    fn config() -> Config {
        match Config::parse(
            [
                "--socket",
                "/run/ghostnector/test.sock",
                "--peer-uid",
                "1000",
            ]
            .iter()
            .map(|value| value.to_string()),
        )
        .expect("test config parses")
        {
            Parsed::Run(config) => config,
            other => panic!("expected a runnable config, got {other:?}"),
        }
    }

    fn identities() -> FixedIdentities {
        FixedIdentities::new(&[("debian-tor", TOR_UID)])
    }

    fn server() -> (Arc<MockBackend>, Server<MockBackend, FixedIdentities>) {
        let backend = Arc::new(MockBackend::new());
        let server = Server::new(config(), Arc::clone(&backend), identities());
        (backend, server)
    }

    fn exchange<W: Write>(
        server: &Server<MockBackend, FixedIdentities>,
        requests: &str,
        response: &mut W,
    ) {
        let mut reader = std::io::BufReader::new(requests.as_bytes());
        server
            .serve_stream(&mut reader, response)
            .expect("serve_stream");
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8(bytes.to_vec()).expect("utf8")
    }

    fn connect_request() -> Verb {
        Verb::ApplyProfile {
            profile: ProfileId::TorSystem,
            params: Params::default(),
        }
    }

    fn handshake() -> String {
        format!("{{\"verb\":\"hello\",\"protocol\":{PROTOCOL_VERSION}}}\n")
    }

    #[test]
    fn authorization_is_an_exact_match_except_for_root() {
        assert!(is_authorized(1000, 1000));
        assert!(!is_authorized(1000, 1001));
        assert!(!is_authorized(1000, 0));
        assert!(
            is_authorized(0, 1000),
            "root could write the policy directly, so refusing it would protect nothing"
        );
    }

    #[test]
    fn the_handshake_must_come_first() {
        let (backend, server) = server();
        let mut out = Vec::new();
        exchange(&server, "{\"verb\":\"revert\"}\n", &mut out);
        let body = text(&out);
        assert!(body.contains("protocol_mismatch"), "{body}");
        assert!(body.contains("handshake"), "{body}");
        assert!(
            backend.scripts().is_empty(),
            "a pre-handshake verb must not touch the kernel"
        );
    }

    #[test]
    fn a_version_mismatch_is_refused_and_closes_the_connection() {
        let (_backend, server) = server();
        let mut out = Vec::new();
        // A correct handshake followed by another request: the connection must not survive.
        exchange(
            &server,
            "{\"verb\":\"hello\",\"protocol\":999}\n{\"verb\":\"report\"}\n",
            &mut out,
        );
        let body = text(&out);
        assert!(body.contains("protocol_mismatch"), "{body}");
        assert_eq!(
            body.lines().count(),
            1,
            "the connection must close after a version mismatch: {body}"
        );
    }

    #[test]
    fn applying_tor_system_renders_and_applies_the_policy() {
        let (backend, server) = server();
        let mut out = Vec::new();
        exchange(
            &server,
            &format!(
                "{}{}\n{{\"verb\":\"report\"}}\n",
                handshake(),
                serde_json::to_string(&connect_request()).expect("encode")
            ),
            &mut out,
        );

        let scripts = backend.scripts();
        assert_eq!(scripts.len(), 1, "exactly one atomic replacement");
        assert!(scripts[0].contains("destroy table inet ghostnector"));
        assert!(scripts[0].contains(&format!("meta skuid {TOR_UID}")));
        assert!(scripts[0].contains("redirect to :9040"));
        assert_eq!(backend.flush_calls(), 1);

        let body = text(&out);
        assert!(body.contains("\"result\":\"applied\""), "{body}");
        assert!(body.contains("system-user:tor"), "{body}");
        assert!(body.contains("\"applied\":true"), "{body}");
    }

    #[test]
    fn the_report_carries_the_ports_the_policy_uses() {
        // Core configures the services it supervises from these, so they must be the live values.
        let (_backend, server) = server();
        let report = server.report();
        assert_eq!(report.ports.trans, server.config().trans_port);
        assert_eq!(report.ports.chokepoint, server.config().chokepoint_port);
        assert_eq!(report.ports.socks, server.config().socks_port);
    }

    #[test]
    fn counters_are_not_part_of_the_policy() {
        let live = "\ttable inet ghostnector {\n\t\tcounter packets 42 bytes 900 accept\n\t}\n";
        let without = canonical(live);
        assert!(!without.contains("42"), "{without}");
        assert!(!without.contains("900"), "{without}");
        assert!(without.contains("counter accept"), "{without}");
    }

    #[test]
    fn the_effective_policy_is_compared_against_what_was_applied() {
        let (backend, server) = server();
        let mut out = Vec::new();
        exchange(
            &server,
            &format!(
                "{}{}\n",
                handshake(),
                serde_json::to_string(&connect_request()).expect("encode")
            ),
            &mut out,
        );

        match server.handle(Verb::Verify) {
            HelperResponse::Verified { matches, detail } => {
                assert!(matches, "an untouched policy must compare equal: {detail}")
            }
            other => panic!("expected a verification answer, got {other:?}"),
        }

        // Something else adds a rule, exactly as the adversarial case does by hand.
        backend.tamper("meta l4proto tcp dport 18080 counter accept");
        match server.handle(Verb::Verify) {
            HelperResponse::Verified { matches, detail } => {
                assert!(!matches, "an added line must be visible");
                assert!(detail.contains("18080"), "{detail}");
            }
            other => panic!("expected a verification answer, got {other:?}"),
        }
    }

    #[test]
    fn a_policy_that_vanishes_does_not_compare_equal() {
        let (backend, server) = server();
        let mut out = Vec::new();
        exchange(
            &server,
            &format!(
                "{}{}\n",
                handshake(),
                serde_json::to_string(&connect_request()).expect("encode")
            ),
            &mut out,
        );
        backend.force_table(false);
        match server.handle(Verb::Verify) {
            HelperResponse::Verified { matches, detail } => {
                assert!(!matches);
                assert!(detail.contains("no longer in the kernel"), "{detail}");
            }
            other => panic!("expected a verification answer, got {other:?}"),
        }
    }

    #[test]
    fn a_report_trusts_the_kernel_not_our_memory() {
        let (backend, server) = server();
        backend.force_table(true);
        let report = server.report();
        assert!(report.applied, "the kernel says the table exists");
        assert_eq!(report.profile, None, "we never applied anything");

        backend.force_table(false);
        assert!(!server.report().applied);
    }

    #[test]
    fn revert_clears_the_state_and_is_idempotent() {
        let (backend, server) = server();
        let mut out = Vec::new();
        let requests = format!(
            "{}{}\n{{\"verb\":\"revert\"}}\n{{\"verb\":\"revert\"}}\n",
            handshake(),
            serde_json::to_string(&connect_request()).expect("encode")
        );
        exchange(&server, &requests, &mut out);

        let report = server.report();
        assert!(!report.applied);
        assert_eq!(report.profile, None);
        assert!(report.exemptions.is_empty());
        assert_eq!(backend.scripts().len(), 3, "apply, revert, revert");
    }

    #[test]
    fn a_failed_apply_is_reported_and_leaves_no_state() {
        let (backend, server) = server();
        backend.fail_apply_with("syntax error in rule 7");
        let mut out = Vec::new();
        exchange(
            &server,
            &format!(
                "{}{}\n",
                handshake(),
                serde_json::to_string(&connect_request()).expect("encode")
            ),
            &mut out,
        );
        let body = text(&out);
        assert!(body.contains("backend_failure"), "{body}");
        assert!(body.contains("syntax error in rule 7"), "{body}");
        assert_eq!(server.report().profile, None);
    }

    #[test]
    fn a_missing_service_is_named_in_the_error() {
        let backend = Arc::new(MockBackend::new());
        let server = Server::new(config(), Arc::clone(&backend), FixedIdentities::empty());
        let mut out = Vec::new();
        exchange(
            &server,
            &format!(
                "{}{}\n",
                handshake(),
                serde_json::to_string(&connect_request()).expect("encode")
            ),
            &mut out,
        );
        let body = text(&out);
        assert!(body.contains("invalid_profile"), "{body}");
        assert!(body.contains("tor"), "{body}");
        assert!(
            backend.scripts().is_empty(),
            "nothing may reach the kernel when the policy cannot be built"
        );
    }

    #[test]
    fn a_missing_conntrack_tool_is_a_note_not_a_failure() {
        let backend = Arc::new(MockBackend::without_conntrack());
        let server = Server::new(config(), Arc::clone(&backend), identities());
        let mut out = Vec::new();
        exchange(
            &server,
            &format!(
                "{}{}\n",
                handshake(),
                serde_json::to_string(&connect_request()).expect("encode")
            ),
            &mut out,
        );
        let body = text(&out);
        assert!(body.contains("\"result\":\"applied\""), "{body}");
        assert!(body.contains("conntrack was not flushed"), "{body}");
    }

    #[test]
    fn unsupported_profiles_are_refused_rather_than_approximated() {
        let (backend, server) = server();
        let request = Verb::ApplyProfile {
            profile: ProfileId::TorApp,
            params: Params::default(),
        };
        let mut out = Vec::new();
        exchange(
            &server,
            &format!(
                "{}{}\n",
                handshake(),
                serde_json::to_string(&request).expect("encode")
            ),
            &mut out,
        );
        let body = text(&out);
        assert!(body.contains("invalid_profile"), "{body}");
        assert!(body.contains("not implemented"), "{body}");
        assert!(backend.scripts().is_empty());
    }

    #[test]
    fn malformed_frames_do_not_kill_the_connection() {
        let (_backend, server) = server();
        let mut out = Vec::new();
        exchange(
            &server,
            &format!("{}not json at all\n{{\"verb\":\"report\"}}\n", handshake()),
            &mut out,
        );
        let body = text(&out);
        assert!(body.contains("malformed request"), "{body}");
        assert!(
            body.contains("\"result\":\"report\""),
            "a bad frame must not end the session: {body}"
        );
    }

    #[test]
    fn a_revert_with_nothing_applied_is_not_an_error() {
        let (_backend, server) = server();
        let mut out = Vec::new();
        exchange(
            &server,
            &format!("{}{{\"verb\":\"revert\"}}\n", handshake()),
            &mut out,
        );
        let body = text(&out);
        assert!(body.contains("\"result\":\"applied\""), "{body}");
    }

    #[test]
    fn the_report_lists_both_configured_identities_even_when_one_is_missing() {
        let (_backend, server) = server();
        let report = server.report();
        assert_eq!(report.resolved.len(), 2);
        let tor = report
            .resolved
            .iter()
            .find(|entry| entry.name == "debian-tor")
            .expect("tor is listed");
        assert_eq!(tor.uid, Some(TOR_UID));
        let resolver = report
            .resolved
            .iter()
            .find(|entry| entry.name == "dnscrypt-proxy")
            .expect("the resolver is listed");
        assert_eq!(resolver.uid, None, "not installed, and that is not hidden");
    }
}
