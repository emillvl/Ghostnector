//! Bringing up the services a profile needs, and waiting until they are actually usable.
//!
//! This is where "deny first, then open" becomes concrete. The order is always:
//!
//! 1. the fail-closed policy is already applied (the engine does that before calling in here),
//! 2. the services start — Tor can bootstrap *because* the baseline exempts its uid,
//! 3. this module waits until the service says it is ready,
//! 4. only then does the engine open the real policy.
//!
//! Two implementations exist because the two deployment shapes are both legitimate: Ghostnector can
//! own Tor (a systemd unit it starts and stops), or the operator can run Tor themselves and have
//! Ghostnector use it. Neither is a test backdoor: readiness is required either way.

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ghostnector_spec::backend::{I2pPorts, Ports, ProfileId};

use crate::fsutil::write_atomic;
use crate::i2pdconf::{self, I2pSettings};
use crate::supervisor::{Supervisor, SupervisorError};
use crate::torcontrol::{TorControl, TorControlError};
use crate::torrc::{self, TorSettings};

/// Why a service could not be brought up.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// The service manager refused.
    #[error("the service could not be managed: {0}")]
    Supervisor(#[from] SupervisorError),
    /// Tor's configuration could not be written.
    #[error("Tor's configuration could not be written: {0}")]
    Config(String),
    /// Tor never became usable.
    #[error("Tor is not usable: {0}")]
    Tor(#[from] TorControlError),
    /// The I2P router never became usable.
    #[error("the I2P router is not usable: {0}")]
    Router(String),
}

/// The services a profile needs.
pub trait Services: Send + Sync {
    /// Bring up what this profile needs, and wait until it is usable.
    ///
    /// `app_core` is the host-local address APP namespaces reach: when it is present, Tor's
    /// transparent-proxy and SOCKS listeners move there so the namespace DNAT has somewhere to
    /// deliver to. It is `None` for every machine-wide profile.
    ///
    /// `i2p_ports` are the proxy ports the policy guards, reported by the helper so the router's
    /// configuration and the firewall cannot disagree.
    fn bring_up(
        &self,
        profile: ProfileId,
        ports: Ports,
        app_core: Option<Ipv4Addr>,
        i2p_ports: I2pPorts,
    ) -> Result<(), ServiceError>;
    /// Stop whatever this profile needed. Best effort: failing here is a note, not a rollback.
    fn stand_down(&self, profile: ProfileId) -> Result<(), ServiceError>;
    /// Anything the user should know about this profile's services.
    fn notes(&self, profile: ProfileId) -> Vec<String> {
        let _ = profile;
        Vec::new()
    }
}

/// Whether a profile needs Tor at all.
pub fn needs_tor(profile: ProfileId) -> bool {
    matches!(
        profile,
        ProfileId::TorSystem | ProfileId::TorUser | ProfileId::TorApp
    )
}

/// Whether a profile needs the I2P router.
pub fn needs_router(profile: ProfileId) -> bool {
    profile == ProfileId::I2pSystem
}

/// Wait until something accepts a connection on `address`.
///
/// This is the I2P readiness check: the router is usable when its local proxy answers. It is
/// deliberately a real connection, not a process check — a router that started and immediately died
/// must fail the bring-up, or the state would claim a network it cannot reach.
fn wait_for_proxy(address: SocketAddr, budget: Duration) -> Result<(), ServiceError> {
    let deadline = Instant::now() + budget;
    loop {
        match TcpStream::connect_timeout(&address, Duration::from_millis(500)) {
            Ok(_) => return Ok(()),
            Err(error) => {
                if Instant::now() >= deadline {
                    return Err(ServiceError::Router(format!(
                        "nothing accepted a connection on {address} within {}s: {error}",
                        budget.as_secs()
                    )));
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

/// How Ghostnector supervises a router it owns.
#[derive(Debug, Clone)]
pub struct I2pSupervision {
    /// The unit that runs the router.
    pub unit: String,
    /// Where the router's configuration is written.
    pub config_path: PathBuf,
    /// The template the configuration is rendered from.
    pub settings: I2pSettings,
    /// How long to wait for the proxy to answer.
    pub budget: Duration,
}

/// The resolver's health cannot be checked yet, and saying so is better than implying it is fine.
const RESOLVER_NOTE: &str =
    "the resolver's health cannot be checked yet, so encrypted DNS is assumed to be up";

/// Ghostnector owns Tor: it writes the configuration, starts the unit, and waits.
pub struct SystemdServices {
    supervisor: Arc<dyn Supervisor>,
    tor: TorControl,
    unit: String,
    torrc_path: PathBuf,
    template: TorSettings,
    budget: Duration,
    /// The router this process supervises, when one was configured.
    i2p: Option<I2pSupervision>,
}

impl SystemdServices {
    /// Assemble the pieces. Nothing is started until [`Services::bring_up`] is called.
    pub fn new(
        supervisor: Arc<dyn Supervisor>,
        tor: TorControl,
        unit: impl Into<String>,
        torrc_path: impl Into<PathBuf>,
        template: TorSettings,
        budget: Duration,
    ) -> Self {
        Self {
            supervisor,
            tor,
            unit: unit.into(),
            torrc_path: torrc_path.into(),
            template,
            budget,
            i2p: None,
        }
    }

    /// Add the router this process should supervise.
    ///
    /// Without it, an I2P profile fails closed at bring-up rather than starting a router whose
    /// configuration was never written.
    pub fn with_i2p(mut self, supervision: I2pSupervision) -> Self {
        self.i2p = Some(supervision);
        self
    }

    /// Where Tor's configuration is written.
    pub fn torrc_path(&self) -> &Path {
        &self.torrc_path
    }

    /// Where the router's configuration is written, when one is supervised.
    pub fn i2pd_config_path(&self) -> Option<&Path> {
        self.i2p.as_ref().map(|i2p| i2p.config_path.as_path())
    }
}

impl Services for SystemdServices {
    fn bring_up(
        &self,
        profile: ProfileId,
        ports: Ports,
        app_core: Option<Ipv4Addr>,
        i2p_ports: I2pPorts,
    ) -> Result<(), ServiceError> {
        if needs_router(profile) {
            let Some(i2p) = self.i2p.as_ref() else {
                return Err(ServiceError::Config(
                    "this control plane was not configured to supervise an I2P router".to_string(),
                ));
            };
            let settings = i2p.settings.clone().with_ports(i2p_ports);
            let rendered = i2pdconf::render(&settings);
            write_atomic(&i2p.config_path, rendered.as_bytes()).map_err(|error| {
                ServiceError::Config(format!(
                    "'{}' could not be written: {error}",
                    i2p.config_path.display()
                ))
            })?;
            self.supervisor.start(&i2p.unit)?;
            return wait_for_proxy(
                SocketAddr::from((Ipv4Addr::LOCALHOST, settings.http_proxy_port)),
                i2p.budget,
            );
        }

        if !needs_tor(profile) {
            return Ok(());
        }

        // The ports the firewall actually redirects into, so the two cannot disagree. In APP scope
        // the transparent proxy and SOCKS move to the core address the namespace DNAT targets;
        // there is deliberately no wildcard listener.
        let mut settings = self.template.clone().with_ports(ports);
        if let Some(core) = app_core {
            settings = settings.with_app_core(core);
        }
        let rendered = torrc::render(&settings);
        write_atomic(&self.torrc_path, rendered.as_bytes()).map_err(|error| {
            ServiceError::Config(format!(
                "'{}' could not be written: {error}",
                self.torrc_path.display()
            ))
        })?;

        self.supervisor.start(&self.unit)?;
        self.tor.wait_until_ready(self.budget)?;
        Ok(())
    }

    fn stand_down(&self, profile: ProfileId) -> Result<(), ServiceError> {
        if needs_router(profile) {
            let Some(i2p) = self.i2p.as_ref() else {
                return Ok(());
            };
            return self.supervisor.stop(&i2p.unit).map_err(ServiceError::from);
        }
        if !needs_tor(profile) {
            return Ok(());
        }
        self.supervisor.stop(&self.unit).map_err(ServiceError::from)
    }

    fn notes(&self, profile: ProfileId) -> Vec<String> {
        if profile == ProfileId::DnsLockdown {
            vec![RESOLVER_NOTE.to_string()]
        } else {
            Vec::new()
        }
    }
}

/// The operator owns Tor and the router; Ghostnector only waits for them to be usable.
pub struct ExternalServices {
    tor: TorControl,
    budget: Duration,
    i2p_budget: Duration,
}

impl ExternalServices {
    /// Assemble the pieces.
    pub fn new(tor: TorControl, budget: Duration) -> Self {
        Self {
            tor,
            budget,
            i2p_budget: budget,
        }
    }

    /// Set how long to wait for an externally managed router's proxy.
    pub fn with_i2p_budget(mut self, budget: Duration) -> Self {
        self.i2p_budget = budget;
        self
    }
}

impl Services for ExternalServices {
    fn bring_up(
        &self,
        profile: ProfileId,
        _ports: Ports,
        _app_core: Option<Ipv4Addr>,
        i2p_ports: I2pPorts,
    ) -> Result<(), ServiceError> {
        if needs_router(profile) {
            return wait_for_proxy(
                SocketAddr::from((Ipv4Addr::LOCALHOST, i2p_ports.http)),
                self.i2p_budget,
            );
        }
        if !needs_tor(profile) {
            return Ok(());
        }
        self.tor.wait_until_ready(self.budget)?;
        Ok(())
    }

    fn stand_down(&self, _profile: ProfileId) -> Result<(), ServiceError> {
        // We did not start it, so we do not stop it.
        Ok(())
    }

    fn notes(&self, profile: ProfileId) -> Vec<String> {
        let mut notes = Vec::new();
        if needs_tor(profile) {
            notes.push("Tor is managed outside Ghostnector".to_string());
        }
        if needs_router(profile) {
            notes.push("the I2P router is managed outside Ghostnector".to_string());
        }
        if profile == ProfileId::DnsLockdown {
            notes.push(RESOLVER_NOTE.to_string());
        }
        notes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddr, TcpListener};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            // Unique per call: tests run in parallel threads, and a shared directory would let one
            // test's cleanup delete another test's cookie.
            use std::sync::atomic::{AtomicU32, Ordering};
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "ghostnector-services-{}-{label}-{unique}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }

        fn cookie(&self) -> PathBuf {
            let path = self.0.join("cookie");
            std::fs::write(&path, [9u8; 32]).expect("write cookie");
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A control port that is always ready to say Tor is bootstrapped.
    fn ready_control(port: u16) -> (SocketAddr, PathBuf, TempDir) {
        let dir = TempDir::new("ready");
        let cookie = dir.cookie();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                std::thread::spawn(move || {
                    use std::io::{BufRead, BufReader, Write};
                    let Ok(reading) = stream.try_clone() else {
                        return;
                    };
                    let mut reader = BufReader::new(reading);
                    let mut writer = stream;
                    // Real Tor does not greet first: wait for the client's command.
                    let mut line = String::new();
                    while reader.read_line(&mut line).unwrap_or(0) > 0 {
                        let reply = if line.starts_with("AUTHENTICATE") {
                            "250 OK\r\n"
                        } else {
                            "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n250 OK\r\n"
                        };
                        if writer.write_all(reply.as_bytes()).is_err() {
                            return;
                        }
                        line.clear();
                    }
                });
            }
        });
        let _ = port;
        (address, cookie, dir)
    }

    fn ports() -> Ports {
        Ports {
            trans: 19040,
            chokepoint: 19054,
            socks: 19050,
        }
    }

    #[test]
    fn tor_is_needed_for_every_tor_profile_including_app_scope() {
        assert!(needs_tor(ProfileId::TorSystem));
        assert!(needs_tor(ProfileId::TorUser));
        assert!(
            needs_tor(ProfileId::TorApp),
            "APP scope needs Tor as much as any other Tor scope"
        );
        for profile in [
            ProfileId::FailClosed,
            ProfileId::DnsLockdown,
            ProfileId::I2pSystem,
        ] {
            assert!(!needs_tor(profile), "{profile:?}");
        }
    }

    #[test]
    fn only_the_i2p_profile_needs_the_router() {
        assert!(needs_router(ProfileId::I2pSystem));
        for profile in [
            ProfileId::FailClosed,
            ProfileId::DnsLockdown,
            ProfileId::TorSystem,
            ProfileId::TorUser,
            ProfileId::TorApp,
        ] {
            assert!(!needs_router(profile), "{profile:?}");
        }
    }

    #[test]
    fn the_router_is_supervised_and_its_proxy_is_waited_for() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
        let port = listener.local_addr().expect("address").port();
        let dir = TempDir::new("i2p-services");
        let config = dir.0.join("i2pd.conf");
        let mock = Arc::new(crate::testing::MockSupervisor::new());
        let supervisor: Arc<dyn Supervisor> = mock.clone();
        let services = SystemdServices::new(
            supervisor,
            TorControl::new(
                "127.0.0.1:1".parse().expect("address"),
                dir.0.join("cookie"),
                Duration::from_millis(100),
            ),
            "ghostnector-tor.service",
            dir.0.join("torrc"),
            TorSettings::default(),
            Duration::from_secs(2),
        )
        .with_i2p(I2pSupervision {
            unit: "ghostnector-i2pd.service".to_string(),
            config_path: config.clone(),
            settings: I2pSettings::default(),
            budget: Duration::from_secs(2),
        });

        services
            .bring_up(
                ProfileId::I2pSystem,
                ports(),
                None,
                I2pPorts {
                    http: port,
                    socks: 14447,
                },
            )
            .expect("the router comes up");
        assert_eq!(
            mock.started(),
            vec!["ghostnector-i2pd.service".to_string()],
            "the router unit was started"
        );
        let text = std::fs::read_to_string(&config).expect("i2pd.conf");
        assert!(text.contains(&format!("port = {port}")), "{text}");
        assert!(text.contains("port = 14447"), "{text}");
        assert!(!text.contains("0.0.0.0"), "{text}");

        services
            .stand_down(ProfileId::I2pSystem)
            .expect("the router stops");
        assert_eq!(mock.stopped(), vec!["ghostnector-i2pd.service".to_string()]);
    }

    #[test]
    fn a_router_that_never_answers_fails_the_bring_up() {
        let dir = TempDir::new("i2p-unready");
        let services = SystemdServices::new(
            Arc::new(crate::testing::MockSupervisor::new()),
            TorControl::new(
                "127.0.0.1:1".parse().expect("address"),
                dir.0.join("cookie"),
                Duration::from_millis(100),
            ),
            "ghostnector-tor.service",
            dir.0.join("torrc"),
            TorSettings::default(),
            Duration::from_secs(2),
        )
        .with_i2p(I2pSupervision {
            unit: "ghostnector-i2pd.service".to_string(),
            config_path: dir.0.join("i2pd.conf"),
            settings: I2pSettings::default(),
            budget: Duration::from_millis(300),
        });

        // Nothing listens on this port, so the readiness check must fail rather than claim a
        // network the router cannot reach.
        let error = services
            .bring_up(
                ProfileId::I2pSystem,
                ports(),
                None,
                I2pPorts {
                    http: 1,
                    socks: 14447,
                },
            )
            .expect_err("an unreachable proxy must fail");
        assert!(
            matches!(error, ServiceError::Router(_)),
            "expected a router failure, got {error}"
        );
        assert!(error.to_string().contains("nothing accepted"), "{error}");
    }

    #[test]
    fn an_i2p_profile_without_supervision_fails_closed() {
        let dir = TempDir::new("i2p-nosupervision");
        let services = SystemdServices::new(
            Arc::new(crate::testing::MockSupervisor::new()),
            TorControl::new(
                "127.0.0.1:1".parse().expect("address"),
                dir.0.join("cookie"),
                Duration::from_millis(100),
            ),
            "ghostnector-tor.service",
            dir.0.join("torrc"),
            TorSettings::default(),
            Duration::from_secs(2),
        );
        let error = services
            .bring_up(ProfileId::I2pSystem, ports(), None, I2pPorts::default())
            .expect_err("no router supervision is a configuration error");
        assert!(
            matches!(error, ServiceError::Config(_)),
            "expected a configuration failure, got {error}"
        );
    }

    #[test]
    fn external_services_wait_for_the_proxy_and_say_who_manages_it() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
        let port = listener.local_addr().expect("address").port();
        let (address, cookie, _dir) = ready_control(0);
        let tor = TorControl::new(address, cookie, Duration::from_secs(2));
        let services = ExternalServices::new(tor, Duration::from_secs(2))
            .with_i2p_budget(Duration::from_secs(2));

        assert!(services
            .bring_up(
                ProfileId::I2pSystem,
                ports(),
                None,
                I2pPorts {
                    http: port,
                    socks: 14447,
                },
            )
            .is_ok());
        let notes = services.notes(ProfileId::I2pSystem);
        assert!(
            notes.iter().any(|note| note.contains("managed outside")),
            "{notes:?}"
        );
        assert!(services.stand_down(ProfileId::I2pSystem).is_ok());
    }

    #[test]
    fn app_scope_writes_the_core_address_into_tors_configuration() {
        let (address, cookie, _dir) = ready_control(0);
        let tor = TorControl::new(address, cookie, Duration::from_secs(2));
        let dir = TempDir::new("app-torrc");
        let torrc = dir.0.join("torrc");
        let services = SystemdServices::new(
            Arc::new(crate::testing::MockSupervisor::new()),
            tor,
            "ghostnector-tor.service",
            &torrc,
            TorSettings::default(),
            Duration::from_secs(2),
        );
        services
            .bring_up(
                ProfileId::TorApp,
                ports(),
                Some(std::net::Ipv4Addr::new(10, 200, 0, 1)),
                I2pPorts::default(),
            )
            .expect("APP services come up");
        let text = std::fs::read_to_string(&torrc).expect("torrc");
        assert!(text.contains("TransPort 10.200.0.1:19040"), "{text}");
        assert!(text.contains("SocksPort 10.200.0.1:19050"), "{text}");
        assert!(!text.contains("0.0.0.0"), "{text}");
    }

    #[test]
    fn external_services_require_tor_to_be_ready_and_say_they_do_not_manage_it() {
        let (address, cookie, _dir) = ready_control(0);
        let tor = TorControl::new(address, cookie, Duration::from_secs(2));
        let services = ExternalServices::new(tor, Duration::from_secs(2));

        assert!(services
            .bring_up(ProfileId::TorSystem, ports(), None, I2pPorts::default())
            .is_ok());
        let notes = services.notes(ProfileId::TorSystem);
        assert!(
            notes
                .iter()
                .any(|note| note.contains("outside Ghostnector")),
            "{notes:?}"
        );

        // A profile that does not need Tor is not blocked by Tor's absence.
        assert!(services
            .bring_up(ProfileId::FailClosed, ports(), None, I2pPorts::default())
            .is_ok());
    }

    #[test]
    fn external_services_do_not_stop_something_they_did_not_start() {
        let (address, cookie, _dir) = ready_control(0);
        let tor = TorControl::new(address, cookie, Duration::from_secs(2));
        let services = ExternalServices::new(tor, Duration::from_secs(2));
        assert!(services.stand_down(ProfileId::TorSystem).is_ok());
    }

    #[test]
    fn the_resolver_gap_is_stated_rather_than_implied() {
        let (address, cookie, _dir) = ready_control(0);
        let tor = TorControl::new(address, cookie, Duration::from_secs(2));
        let services = ExternalServices::new(tor, Duration::from_secs(2));
        let notes = services.notes(ProfileId::DnsLockdown);
        assert_eq!(notes, vec![RESOLVER_NOTE.to_string()]);
    }
}
