//! The helper's request loop.
//!
//! The same three properties `netd` has, for the same reasons:
//!
//! * a connection is only read from if its peer uid is exactly the configured one or root, checked
//!   with `SO_PEERCRED` (the kernel's answer, not the client's claim);
//! * the first request must be a handshake, and a version mismatch closes the connection;
//! * a verb dispatches to a fixed operation. Unknown or malformed input produces an error response;
//!   it never reaches a name, a path, a command, or a ruleset.
//!
//! On top of that, a non-root peer may only act on the groups it owns, and every operation that
//! touches the kernel runs through the backend's serialised namespace entry.

use std::io::{BufRead, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ghostnector_policy::canonical_kernel_ruleset;
use ghostnector_spec::appd::{AppEntry, AppReport, AppResponse, AppVerb, APP_PROTOCOL_VERSION};
use ghostnector_spec::backend::Ports;
use ghostnector_spec::ipc::{ErrorBody, ErrorCode};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

use crate::backend::{BackendError, GroupRequest, Namespaces};
use crate::config::Config;
use crate::registry::{AppRecord, Registry, RegistryError};
use crate::VERSION;

/// The most connections served at once.
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
    /// The registry could not be loaded.
    #[error("{0}")]
    Registry(#[from] RegistryError),
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

/// The privileged helper.
pub struct Server<B: Namespaces + 'static> {
    config: Config,
    backend: Arc<B>,
    registry: Registry,
    connections: AtomicUsize,
}

impl<B: Namespaces + 'static> Server<B> {
    /// Build a helper around a backend, loading the registry.
    pub fn new(config: Config, backend: Arc<B>) -> Result<Self, ServerError> {
        let registry = Registry::load(config.state_dir.join("registry.json"), config.max_groups)?;
        Ok(Self {
            config,
            backend,
            registry,
            connections: AtomicUsize::new(0),
        })
    }

    /// The configuration in force.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// What the helper knows: the bridge, every group, and nothing else.
    pub fn report(&self) -> AppReport {
        let bridge_present = self.backend.bridge_present().unwrap_or(false);
        let entries = self
            .registry
            .records()
            .into_iter()
            .map(|record| AppEntry {
                id: record.id,
                owner_uid: record.owner_uid,
                address: record.address,
                created_at: record.created_at,
                present: self.backend.group_present(record.id).unwrap_or(false),
            })
            .collect();
        AppReport {
            bridge_present,
            core: self.config.core,
            entries,
            notes: Vec::new(),
        }
    }

    /// Handle one verb. This is the whole dispatch surface.
    pub fn handle(&self, verb: AppVerb, peer_uid: u32) -> AppResponse {
        match verb {
            AppVerb::Hello { protocol } => {
                if protocol != APP_PROTOCOL_VERSION {
                    return AppResponse::Error(self.problem(
                        ErrorCode::ProtocolMismatch,
                        format!(
                            "this helper speaks protocol {APP_PROTOCOL_VERSION}, the caller speaks {protocol}"
                        ),
                    ));
                }
                AppResponse::Hello {
                    protocol: APP_PROTOCOL_VERSION,
                    version: VERSION.to_string(),
                }
            }
            AppVerb::EnsureBridge { ports } => match self.ensure_bridge(ports) {
                Ok(report) => AppResponse::Applied { report },
                Err(body) => AppResponse::Error(body),
            },
            AppVerb::Create => match self.create(peer_uid) {
                Ok(entry) => AppResponse::Created { entry },
                Err(body) => AppResponse::Error(body),
            },
            AppVerb::Destroy { id } => match self.destroy(id, peer_uid) {
                Ok(report) => AppResponse::Applied { report },
                Err(body) => AppResponse::Error(body),
            },
            AppVerb::Inspect { id } => match self.inspect(id, peer_uid) {
                Ok((entry, notes)) => AppResponse::Inspected { entry, notes },
                Err(body) => AppResponse::Error(body),
            },
            AppVerb::Verify { id } => match self.verify(id, peer_uid) {
                Ok((matches, detail)) => AppResponse::Verified { matches, detail },
                Err(body) => AppResponse::Error(body),
            },
            AppVerb::ReportRegistry => AppResponse::Report(self.report()),
            AppVerb::Revert => match self.revert() {
                Ok(report) => AppResponse::Applied { report },
                Err(body) => AppResponse::Error(body),
            },
        }
    }

    /// Read requests and write responses until the caller goes away.
    fn serve_stream<R: BufRead, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        peer_uid: u32,
    ) -> Result<(), ServerError> {
        let mut greeted = false;
        loop {
            let mut line = String::new();
            let read = reader
                .read_line(&mut line)
                .map_err(|error| ServerError::Io(error.to_string()))?;
            if read == 0 {
                return Ok(());
            }
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let mut close_after = false;
            let response = match serde_json::from_str::<AppVerb>(line) {
                Ok(AppVerb::Hello { protocol }) => {
                    greeted = true;
                    close_after = protocol != APP_PROTOCOL_VERSION;
                    self.handle(AppVerb::Hello { protocol }, peer_uid)
                }
                Ok(verb) if greeted => self.handle(verb, peer_uid),
                Ok(_) => AppResponse::Error(self.problem(
                    ErrorCode::ProtocolMismatch,
                    "the first request on a connection must be a handshake",
                )),
                Err(error) => AppResponse::Error(
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
                eprintln!("ghostnector-appd: refusing a connection: {MAX_CONNECTIONS} are open");
                drop(stream);
                continue;
            }

            self.connections.fetch_add(1, Ordering::SeqCst);
            let server = Arc::clone(&self);
            thread::spawn(move || {
                let result = server.handle_connection(stream);
                server.connections.fetch_sub(1, Ordering::SeqCst);
                if let Err(error) = result {
                    eprintln!("ghostnector-appd: {error}");
                }
            });
        }
    }

    fn handle_connection(&self, stream: UnixStream) -> Result<(), ServerError> {
        let peer = peer_uid(&stream)?;
        if !is_authorized(peer, self.config.peer_uid) {
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
        self.serve_stream(&mut reader, &mut writer, peer)
    }

    // ---------------------------------------------------------------- verbs

    fn ensure_bridge(&self, ports: Ports) -> Result<AppReport, ErrorBody> {
        if ports.trans == 0 || ports.chokepoint == 0 || ports.socks == 0 {
            return Err(self.problem(ErrorCode::InvalidProfile, "a port cannot be zero"));
        }
        if ports.trans == ports.chokepoint
            || ports.trans == ports.socks
            || ports.chokepoint == ports.socks
        {
            return Err(self.problem(
                ErrorCode::InvalidProfile,
                "the ports must be distinct, or one listener would shadow another",
            ));
        }
        self.backend
            .ensure_bridge()
            .map_err(|error| self.backend_problem(error))?;
        self.registry
            .mark_bridge(ports)
            .map_err(|error| self.registry_problem(error))?;
        Ok(self.report())
    }

    fn create(&self, owner_uid: u32) -> Result<AppEntry, ErrorBody> {
        let ports = self.registry.ports().ok_or_else(|| {
            self.problem(
                ErrorCode::UnsafeState,
                "the bridge has not been ensured, so no namespace may be created",
            )
        })?;
        if !self.registry.bridge_ready() {
            return Err(self.problem(
                ErrorCode::UnsafeState,
                "the bridge has not been ensured, so no namespace may be created",
            ));
        }
        if !self
            .backend
            .bridge_present()
            .map_err(|error| self.backend_problem(error))?
        {
            return Err(self.problem(
                ErrorCode::UnsafeState,
                "the bridge is recorded but not present; re-ensure it before creating a group",
            ));
        }

        let now = now_unix();
        let record = self
            .registry
            .allocate(owner_uid, self.config.core, self.config.prefix, now)
            .map_err(|error| self.registry_problem(error))?;
        let request = self.request_for(&record, ports);
        match self.backend.create(&request) {
            Ok(()) => {}
            Err(error) => {
                // No orphan registry entry: if the kernel work failed, the record goes too.
                let _ = self.registry.remove(record.id);
                return Err(self.backend_problem(error));
            }
        }

        // Record what the kernel reported, not what we intended (the PC-08 mechanism).
        match self.backend.applied_policy(record.id) {
            Ok(live) => {
                let _ = self
                    .registry
                    .set_effective(record.id, canonical_kernel_ruleset(&live));
            }
            Err(error) => {
                let _ = self.registry.remove(record.id);
                let _ = self.backend.destroy(record.id);
                return Err(self.backend_problem(error));
            }
        }

        Ok(AppEntry {
            id: record.id,
            owner_uid: record.owner_uid,
            address: record.address,
            created_at: record.created_at,
            present: true,
        })
    }

    fn destroy(&self, id: u32, peer_uid: u32) -> Result<AppReport, ErrorBody> {
        // Idempotent: destroying an unknown or already-destroyed id still asks the backend to clean
        // up, so an orphaned namespace left behind by a crash is removed rather than reported.
        if let Some(record) = self.registry.get(id) {
            self.require_owner(&record, peer_uid)?;
        }
        self.backend
            .destroy(id)
            .map_err(|error| self.backend_problem(error))?;
        self.registry
            .remove(id)
            .map_err(|error| self.registry_problem(error))?;
        Ok(self.report())
    }

    fn inspect(
        &self,
        id: u32,
        peer_uid: u32,
    ) -> Result<(Option<AppEntry>, Vec<String>), ErrorBody> {
        let Some(record) = self.registry.get(id) else {
            let mut notes = Vec::new();
            if self
                .backend
                .group_present(id)
                .map_err(|error| self.backend_problem(error))?
            {
                notes.push(format!(
                    "objects for group {id} exist without a registry record; revert removes them"
                ));
            }
            return Ok((None, notes));
        };
        self.require_owner(&record, peer_uid)?;
        let present = self
            .backend
            .group_present(id)
            .map_err(|error| self.backend_problem(error))?;
        let mut notes = Vec::new();
        if !present {
            notes.push("the namespace or its link is missing".to_string());
        }
        Ok((
            Some(AppEntry {
                id: record.id,
                owner_uid: record.owner_uid,
                address: record.address,
                created_at: record.created_at,
                present,
            }),
            notes,
        ))
    }

    fn verify(&self, id: u32, peer_uid: u32) -> Result<(bool, String), ErrorBody> {
        let record = self
            .registry
            .get(id)
            .ok_or_else(|| self.problem(ErrorCode::UnsafeState, format!("no group {id}")))?;
        self.require_owner(&record, peer_uid)?;
        let Some(ports) = self.registry.ports() else {
            return Ok((
                false,
                "the ports the namespace rules should name were never recorded".to_string(),
            ));
        };
        let request = self.request_for(&record, ports);

        if !self
            .backend
            .group_present(id)
            .map_err(|error| self.backend_problem(error))?
        {
            return Ok((false, "the namespace or its link is missing".to_string()));
        }

        let problems = self
            .backend
            .shape_problems(&request)
            .map_err(|error| self.backend_problem(error))?;
        if let Some(first) = problems.first() {
            return Ok((false, first.clone()));
        }

        let live = canonical_kernel_ruleset(
            &self
                .backend
                .applied_policy(id)
                .map_err(|error| self.backend_problem(error))?,
        );
        let Some(expected) = record.effective.clone() else {
            return Ok((
                false,
                "the namespace policy was never recorded as applied; rebuild the group".to_string(),
            ));
        };
        if live == expected {
            return Ok((
                true,
                "the namespace rules and shape are the ones that were installed".to_string(),
            ));
        }
        if live.is_empty() {
            return Ok((
                false,
                "the namespace policy is no longer in the kernel at all".to_string(),
            ));
        }
        let expected_lines: Vec<&str> = expected.lines().collect();
        let live_lines: Vec<&str> = live.lines().collect();
        for (index, (want, got)) in expected_lines.iter().zip(live_lines.iter()).enumerate() {
            if want != got {
                return Ok((
                    false,
                    format!(
                        "line {} of the namespace policy differs: applied '{want}' but the \
                         namespace has '{got}'",
                        index + 1
                    ),
                ));
            }
        }
        Ok((
            false,
            "the namespace policy differs from the one that was applied".to_string(),
        ))
    }

    fn revert(&self) -> Result<AppReport, ErrorBody> {
        let mut first_error = None;
        for record in self.registry.records() {
            if let Err(error) = self.backend.destroy(record.id) {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            // Still forget the registry? No: the objects may remain, so keep the record until a
            // later revert can destroy them. Reporting the failure is the honest answer.
            return Err(self.backend_problem(error));
        }
        self.backend
            .destroy_bridge()
            .map_err(|error| self.backend_problem(error))?;
        self.registry
            .clear()
            .map_err(|error| self.registry_problem(error))?;
        Ok(self.report())
    }

    fn request_for(&self, record: &AppRecord, ports: Ports) -> GroupRequest {
        GroupRequest {
            id: record.id,
            address: record.address,
            bridge: self.config.bridge.clone(),
            core: self.config.core,
            prefix: self.config.prefix,
            dead_device: self.config.dead_device.clone(),
            ports,
            state_dir: self.config.state_dir.clone(),
        }
    }

    fn require_owner(&self, record: &AppRecord, peer_uid: u32) -> Result<(), ErrorBody> {
        if peer_uid == 0 || peer_uid == record.owner_uid {
            return Ok(());
        }
        Err(self.problem(
            ErrorCode::NotAuthorized,
            format!("group {} belongs to another user", record.id),
        ))
    }

    fn problem(&self, code: ErrorCode, message: impl Into<String>) -> ErrorBody {
        ErrorBody {
            code,
            message: message.into(),
            sensitive: false,
        }
    }

    fn backend_problem(&self, error: BackendError) -> ErrorBody {
        self.problem(ErrorCode::BackendFailure, error.to_string())
    }

    fn registry_problem(&self, error: RegistryError) -> ErrorBody {
        self.problem(ErrorCode::Internal, error.to_string())
    }
}

/// Whether a peer with this uid may talk to the helper.
///
/// Root is accepted alongside the configured peer: a process running as root could do everything
/// this helper does, so refusing it protects nothing. The check exists to refuse *unprivileged*
/// processes that are not the control plane.
pub const fn is_authorized(peer: u32, allowed: u32) -> bool {
    peer == allowed || peer == 0
}

/// The uid at the other end of a connection, as reported by the kernel.
pub fn peer_uid(stream: &UnixStream) -> Result<u32, ServerError> {
    let credentials = getsockopt(stream, PeerCredentials)
        .map_err(|error| ServerError::PeerCredentials(error.to_string()))?;
    Ok(credentials.uid())
}

/// Prepare the listening socket: mode 0600, owned by the one uid allowed to talk to us.
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
    // Restrict before handing over. Restricting after would leave the socket owned by the peer with
    // the umask's mode until the chmod, and a chmod after a chown needs CAP_FOWNER, which the unit
    // does not grant.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| reject(format!("cannot restrict the socket: {error}")))?;
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
    Ok(listener)
}

/// Seconds since the unix epoch; zero before 1970, which is harmless here.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::testing::MockNamespaces;
    use ghostnector_spec::appd::{AppReport, AppResponse, AppVerb};

    const PEER: u32 = 1000;
    const OTHER: u32 = 1001;

    fn config(max_groups: usize) -> Config {
        match Config::parse(
            [
                "--socket",
                "/run/ghostnector/test-appd.sock",
                "--peer-uid",
                &PEER.to_string(),
                "--state-dir",
                &format!(
                    "{}/ghostnector-appd-test-{}-{:?}",
                    std::env::temp_dir().display(),
                    std::process::id(),
                    std::thread::current().id()
                ),
                "--max-groups",
                &max_groups.to_string(),
            ]
            .iter()
            .map(|value| value.to_string()),
        )
        .expect("test config parses")
        {
            crate::config::Parsed::Run(config) => config,
            other => panic!("expected a runnable config, got {other:?}"),
        }
    }

    fn server(max_groups: usize) -> (Arc<MockNamespaces>, Server<MockNamespaces>) {
        let backend = Arc::new(MockNamespaces::new());
        let server = Server::new(config(max_groups), Arc::clone(&backend)).expect("server");
        (backend, server)
    }

    fn ports() -> Ports {
        Ports {
            trans: 9040,
            chokepoint: 53,
            socks: 9050,
        }
    }

    fn applied(response: AppResponse) -> AppReport {
        match response {
            AppResponse::Applied { report } => report,
            other => panic!("expected an applied report, got {other:?}"),
        }
    }

    #[test]
    fn authorization_is_an_exact_match_except_for_root() {
        assert!(is_authorized(PEER, PEER));
        assert!(!is_authorized(OTHER, PEER));
        assert!(
            is_authorized(0, PEER),
            "root could do all of this itself; refusing it would protect nothing"
        );
    }

    #[test]
    fn the_handshake_comes_first_and_a_version_mismatch_closes() {
        let (_backend, server) = server(8);
        let mut out = Vec::new();
        let requests = "{\"verb\":\"create\"}\n".to_string();
        let mut reader = std::io::BufReader::new(requests.as_bytes());
        server
            .serve_stream(&mut reader, &mut out, PEER)
            .expect("stream");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("protocol_mismatch"), "{text}");

        let mut out = Vec::new();
        let requests = "{\"verb\":\"hello\",\"protocol\":99}\n{\"verb\":\"report_registry\"}\n";
        let mut reader = std::io::BufReader::new(requests.as_bytes());
        server
            .serve_stream(&mut reader, &mut out, PEER)
            .expect("stream");
        let text = String::from_utf8(out).expect("utf8");
        assert_eq!(text.lines().count(), 1, "the connection must close: {text}");
    }

    #[test]
    fn a_group_cannot_be_created_before_the_bridge_is_ensured() {
        let (backend, server) = server(8);
        match server.handle(AppVerb::Create, PEER) {
            AppResponse::Error(body) => assert_eq!(body.code, ErrorCode::UnsafeState),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(
            backend.calls().is_empty(),
            "the kernel must not have been touched"
        );
    }

    #[test]
    fn the_bridge_refuses_impossible_port_sets() {
        let (_backend, server) = server(8);
        for bad in [
            Ports {
                trans: 0,
                chokepoint: 53,
                socks: 9050,
            },
            Ports {
                trans: 9040,
                chokepoint: 9040,
                socks: 9050,
            },
        ] {
            match server.handle(AppVerb::EnsureBridge { ports: bad }, PEER) {
                AppResponse::Error(body) => assert_eq!(body.code, ErrorCode::InvalidProfile),
                other => panic!("expected a refusal, got {other:?}"),
            }
        }
    }

    #[test]
    fn ids_and_addresses_are_allocated_internally_and_bounded() {
        let (_backend, server) = server(2);
        applied(server.handle(AppVerb::EnsureBridge { ports: ports() }, PEER));
        let first = match server.handle(AppVerb::Create, PEER) {
            AppResponse::Created { entry } => entry,
            other => panic!("expected a created group, got {other:?}"),
        };
        assert_eq!(first.id, 1);
        assert_eq!(first.owner_uid, PEER);
        assert_eq!(first.address, std::net::Ipv4Addr::new(10, 200, 0, 2));
        let second = match server.handle(AppVerb::Create, PEER) {
            AppResponse::Created { entry } => entry,
            other => panic!("expected a created group, got {other:?}"),
        };
        assert_eq!(second.id, 2);
        assert_eq!(second.address, std::net::Ipv4Addr::new(10, 200, 0, 3));
        match server.handle(AppVerb::Create, PEER) {
            AppResponse::Error(body) => assert_eq!(body.code, ErrorCode::Internal),
            other => panic!("expected the registry to be full, got {other:?}"),
        }
    }

    #[test]
    fn verification_compares_the_namespace_against_what_was_installed() {
        let (backend, server) = server(8);
        applied(server.handle(AppVerb::EnsureBridge { ports: ports() }, PEER));
        let entry = match server.handle(AppVerb::Create, PEER) {
            AppResponse::Created { entry } => entry,
            other => panic!("expected a created group, got {other:?}"),
        };
        match server.handle(AppVerb::Verify { id: entry.id }, PEER) {
            AppResponse::Verified { matches, .. } => assert!(matches),
            other => panic!("expected a verification, got {other:?}"),
        }

        // A change no probe traverses is still visible: the kernel listing is compared against the
        // one recorded at apply time.
        backend.set_policy(
            entry.id,
            "table inet ghostnector {\n\t# group 1 at 10.200.0.2\n\tmeta l4proto tcp counter accept\n}\n",
        );
        match server.handle(AppVerb::Verify { id: entry.id }, PEER) {
            AppResponse::Verified { matches, detail } => {
                assert!(!matches);
                assert!(
                    detail.contains("differs") || detail.contains("not the one"),
                    "{detail}"
                );
            }
            other => panic!("expected a failure, got {other:?}"),
        }

        // A shape change is caught even when the ruleset matches.
        backend.set_shape_problems(vec!["proxy_arp is '1' on 'ghav1'".to_string()]);
        match server.handle(AppVerb::Verify { id: entry.id }, PEER) {
            AppResponse::Verified { matches, detail } => {
                assert!(!matches);
                assert!(detail.contains("proxy_arp"), "{detail}");
            }
            other => panic!("expected a shape failure, got {other:?}"),
        }
    }

    #[test]
    fn a_failed_create_leaves_no_record() {
        let (backend, server) = server(8);
        applied(server.handle(AppVerb::EnsureBridge { ports: ports() }, PEER));
        backend.fail_next_create("the kernel said no");
        match server.handle(AppVerb::Create, PEER) {
            AppResponse::Error(body) => assert_eq!(body.code, ErrorCode::BackendFailure),
            other => panic!("expected a failure, got {other:?}"),
        }
        assert!(server.report().entries.is_empty(), "no orphan record");
        assert!(backend.live_groups().is_empty(), "no orphan objects");
    }

    #[test]
    fn a_non_root_peer_can_only_touch_its_own_groups() {
        let (_backend, server) = server(8);
        applied(server.handle(AppVerb::EnsureBridge { ports: ports() }, PEER));
        let entry = match server.handle(AppVerb::Create, PEER) {
            AppResponse::Created { entry } => entry,
            other => panic!("expected a created group, got {other:?}"),
        };
        match server.handle(AppVerb::Destroy { id: entry.id }, OTHER) {
            AppResponse::Error(body) => assert_eq!(body.code, ErrorCode::NotAuthorized),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(server.report().entries.len(), 1, "it must still exist");
        // Root may act on anything; the boot/recovery path needs that.
        applied(server.handle(AppVerb::Destroy { id: entry.id }, 0));
        assert!(server.report().entries.is_empty());
    }

    #[test]
    fn destroy_is_idempotent_and_revert_removes_everything() {
        let (backend, server) = server(8);
        applied(server.handle(AppVerb::EnsureBridge { ports: ports() }, PEER));
        for _ in 0..2 {
            match server.handle(AppVerb::Create, PEER) {
                AppResponse::Created { .. } => {}
                other => panic!("expected a created group, got {other:?}"),
            }
        }
        applied(server.handle(AppVerb::Destroy { id: 99 }, PEER));
        let before = backend.calls().len();
        applied(server.handle(AppVerb::Destroy { id: 1 }, PEER));
        assert!(
            backend.calls().len() > before,
            "an unknown id still asks the backend to clean up"
        );
        let report = applied(server.handle(AppVerb::Revert, PEER));
        assert!(report.entries.is_empty());
        assert!(!report.bridge_present, "revert removes the bridge too");
        assert!(backend.live_groups().is_empty());
    }

    #[test]
    fn inspect_reports_a_missing_object_honestly() {
        let (_backend, server) = server(8);
        applied(server.handle(AppVerb::EnsureBridge { ports: ports() }, PEER));
        let entry = match server.handle(AppVerb::Create, PEER) {
            AppResponse::Created { entry } => entry,
            other => panic!("expected a created group, got {other:?}"),
        };
        applied(server.handle(AppVerb::Destroy { id: entry.id }, PEER));
        match server.handle(AppVerb::Inspect { id: entry.id }, PEER) {
            AppResponse::Inspected { entry, .. } => {
                assert!(entry.is_none(), "a destroyed group is gone");
            }
            other => panic!("expected an inspection, got {other:?}"),
        }
        match server.handle(AppVerb::Inspect { id: 42 }, PEER) {
            AppResponse::Inspected { entry, notes } => {
                assert!(entry.is_none());
                assert!(notes.is_empty(), "{notes:?}");
            }
            other => panic!("expected an inspection, got {other:?}"),
        }
    }

    #[test]
    fn the_report_is_counts_and_ids_only() {
        let (_backend, server) = server(8);
        applied(server.handle(AppVerb::EnsureBridge { ports: ports() }, PEER));
        match server.handle(AppVerb::Create, PEER) {
            AppResponse::Created { .. } => {}
            other => panic!("expected a created group, got {other:?}"),
        }
        match server.handle(AppVerb::ReportRegistry, PEER) {
            AppResponse::Report(report) => {
                assert!(report.bridge_present);
                assert_eq!(report.entries.len(), 1);
                let json = serde_json::to_string(&report).expect("json");
                for forbidden in ["destination", "query", "bytes"] {
                    assert!(!json.contains(forbidden), "{json}");
                }
            }
            other => panic!("expected a report, got {other:?}"),
        }
    }
}
