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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ghostnector_spec::backend::{Ports, ProfileId};

use crate::fsutil::write_atomic;
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
}

/// The services a profile needs.
pub trait Services: Send + Sync {
    /// Bring up what this profile needs, and wait until it is usable.
    fn bring_up(&self, profile: ProfileId, ports: Ports) -> Result<(), ServiceError>;
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
    matches!(profile, ProfileId::TorSystem | ProfileId::TorUser)
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
        }
    }

    /// Where Tor's configuration is written.
    pub fn torrc_path(&self) -> &Path {
        &self.torrc_path
    }
}

impl Services for SystemdServices {
    fn bring_up(&self, profile: ProfileId, ports: Ports) -> Result<(), ServiceError> {
        if !needs_tor(profile) {
            return Ok(());
        }

        // The ports the firewall actually redirects into, so the two cannot disagree.
        let settings = self.template.clone().with_ports(ports);
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

/// The operator owns Tor; Ghostnector only waits for it to be usable.
pub struct ExternalServices {
    tor: TorControl,
    budget: Duration,
}

impl ExternalServices {
    /// Assemble the pieces.
    pub fn new(tor: TorControl, budget: Duration) -> Self {
        Self { tor, budget }
    }
}

impl Services for ExternalServices {
    fn bring_up(&self, profile: ProfileId, _ports: Ports) -> Result<(), ServiceError> {
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
                    if writer.write_all(b"250 OK\r\n").is_err() {
                        return;
                    }
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
    fn tor_is_only_needed_for_the_tor_profiles() {
        assert!(needs_tor(ProfileId::TorSystem));
        assert!(needs_tor(ProfileId::TorUser));
        for profile in [
            ProfileId::FailClosed,
            ProfileId::DnsLockdown,
            ProfileId::TorApp,
            ProfileId::I2pIsolated,
        ] {
            assert!(!needs_tor(profile), "{profile:?}");
        }
    }

    #[test]
    fn external_services_require_tor_to_be_ready_and_say_they_do_not_manage_it() {
        let (address, cookie, _dir) = ready_control(0);
        let tor = TorControl::new(address, cookie, Duration::from_secs(2));
        let services = ExternalServices::new(tor, Duration::from_secs(2));

        assert!(services.bring_up(ProfileId::TorSystem, ports()).is_ok());
        let notes = services.notes(ProfileId::TorSystem);
        assert!(
            notes
                .iter()
                .any(|note| note.contains("outside Ghostnector")),
            "{notes:?}"
        );

        // A profile that does not need Tor is not blocked by Tor's absence.
        assert!(services.bring_up(ProfileId::FailClosed, ports()).is_ok());
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
