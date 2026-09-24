//! Owning the system's resolver configuration, and giving it back exactly as it was.
//!
//! This is the part of Ghostnector most likely to annoy someone, so it is written defensively:
//!
//! * **Nothing here is the enforcement.** The firewall redirects every query aimed at port 53 into
//!   the chokepoint, so a machine whose resolver configuration Ghostnector could not change is still
//!   not leaking DNS. This module only makes the system's own configuration sane; a failure here is
//!   a note, never a rollback and never a reason to claim protection.
//! * **The original is recorded before anything is written**, and restoring compares what is there
//!   against what was written. If someone else changed it in the meantime, Ghostnector says so and
//!   leaves it alone rather than clobbering their edit.
//! * **The three environments are handled differently on purpose.** systemd-resolved is configured
//!   through its own tool and reverted through its own `revert`, because replaying a guessed set of
//!   servers is worse than asking it to go back to the network's own answers. A plain file is
//!   written and restored byte for byte. NetworkManager is left alone, with an explanation.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::fsutil::write_atomic;
use crate::tools::check_tool;

/// What manages the resolver on this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    /// systemd-resolved is answering, usually on 127.0.0.53.
    SystemdResolved,
    /// NetworkManager owns the file.
    NetworkManager,
    /// A plain file that nothing else rewrites.
    StaticFile,
    /// Something Ghostnector does not recognise.
    Unknown,
}

impl Environment {
    /// A short description for the interface.
    pub const fn describe(self) -> &'static str {
        match self {
            Environment::SystemdResolved => "systemd-resolved",
            Environment::NetworkManager => "NetworkManager",
            Environment::StaticFile => "a plain resolv.conf",
            Environment::Unknown => "something unrecognised",
        }
    }
}

/// Why a resolver operation failed.
#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    /// A file could not be read or written.
    #[error("'{}' could not be used: {reason}", path.display())]
    File {
        /// The path involved.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },
    /// A command failed.
    #[error("{0}")]
    Command(#[from] CommandError),
    /// The machine has no default route to attach the configuration to.
    #[error("no default route, so there is no link to configure")]
    NoDefaultRoute,
}

/// What happened when Ghostnector tried to give the resolver back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// The previous configuration is back.
    Restored,
    /// There was nothing to put back.
    NothingToDo,
    /// Someone else changed the configuration, so it was left alone.
    LeftAlone(String),
}

/// What the resolver looked like before Ghostnector touched it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    /// What manages the resolver here.
    pub environment: Environment,
    /// The file that was changed, when one was.
    pub path: Option<PathBuf>,
    /// What that file contained, or `None` if it did not exist.
    pub contents: Option<String>,
    /// What Ghostnector wrote, so a later change can be detected.
    pub written: Option<String>,
    /// The link whose DNS was overridden, when systemd-resolved owns the resolver.
    pub link: Option<String>,
}

/// Runs external commands, so the parts that shell out can be tested.
pub trait CommandRunner: Send + Sync {
    /// Run a program with arguments, returning its standard output.
    fn run(&self, program: &Path, arguments: &[&str]) -> Result<String, CommandError>;
}

/// Why a command could not be run.
#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    /// The program could not be started.
    #[error("running '{}' failed: {reason}", program.display())]
    Io {
        /// The program.
        program: PathBuf,
        /// What went wrong.
        reason: String,
    },
    /// The program refused.
    #[error("'{}' refused: {reason}", program.display())]
    Refused {
        /// The program.
        program: PathBuf,
        /// What it said.
        reason: String,
    },
    /// The program is not safe to run.
    #[error("{0}")]
    Unsafe(#[from] crate::tools::ToolError),
}

/// Runs commands for real, after checking that the program is safe to run.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCommands;

impl CommandRunner for SystemCommands {
    fn run(&self, program: &Path, arguments: &[&str]) -> Result<String, CommandError> {
        check_tool(program)?;
        let output = std::process::Command::new(program)
            .args(arguments)
            .output()
            .map_err(|error| CommandError::Io {
                program: program.to_path_buf(),
                reason: error.to_string(),
            })?;
        if !output.status.success() {
            let mut said = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if said.is_empty() {
                said = String::from_utf8_lossy(&output.stdout).trim().to_string();
            }
            return Err(CommandError::Refused {
                program: program.to_path_buf(),
                reason: said,
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

/// The file and tool locations this module works with.
#[derive(Debug, Clone)]
pub struct Layout {
    /// The filesystem root, so tests can work in a temporary directory.
    pub root: PathBuf,
    /// Where `resolvectl` lives.
    pub resolvectl: PathBuf,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/"),
            resolvectl: PathBuf::from("/usr/bin/resolvectl"),
        }
    }
}

/// The resolver configuration manager.
pub struct Resolver {
    layout: Layout,
    runner: Arc<dyn CommandRunner>,
}

impl Resolver {
    /// Build a manager.
    pub fn new(layout: Layout, runner: Arc<dyn CommandRunner>) -> Self {
        Self { layout, runner }
    }

    /// Where the system resolver configuration lives.
    pub fn resolv_conf(&self) -> PathBuf {
        self.layout.root.join("etc/resolv.conf")
    }

    /// What manages the resolver here.
    ///
    /// The answer decides everything else: a symlink into systemd's runtime directory is
    /// systemd-resolved's to manage, a symlink into NetworkManager's is theirs, and a plain file is
    /// nobody's but this program's.
    pub fn detect(&self) -> Environment {
        let path = self.resolv_conf();
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                let target = std::fs::read_link(&path).unwrap_or_default();
                let target = target.to_string_lossy();
                if target.contains("systemd") || target.contains("resolve") {
                    Environment::SystemdResolved
                } else if target.contains("NetworkManager") {
                    Environment::NetworkManager
                } else {
                    Environment::Unknown
                }
            }
            Ok(_) => match std::fs::read_to_string(&path) {
                // resolved's stub listener answers on this address, so a file naming it is
                // resolved's answer even when it is not a symlink.
                Ok(contents) if contents.contains("127.0.0.53") => Environment::SystemdResolved,
                Ok(_) => Environment::StaticFile,
                Err(_) => Environment::Unknown,
            },
            Err(_) => Environment::Unknown,
        }
    }

    /// Record the current configuration.
    pub fn capture(&self) -> Result<Baseline, ResolverError> {
        let environment = self.detect();
        let path = self.resolv_conf();
        let contents =
            match environment {
                Environment::StaticFile => Some(std::fs::read_to_string(&path).map_err(
                    |error| ResolverError::File {
                        path: path.clone(),
                        reason: error.to_string(),
                    },
                )?),
                _ => None,
            };
        Ok(Baseline {
            environment,
            path: (environment == Environment::StaticFile).then_some(path),
            contents,
            written: None,
            link: None,
        })
    }

    /// Send the machine's own lookups at the chokepoint.
    pub fn point_at(
        &self,
        baseline: &mut Baseline,
        chokepoint: IpAddr,
    ) -> Result<(), ResolverError> {
        match baseline.environment {
            Environment::StaticFile => {
                let original = baseline.contents.clone().unwrap_or_default();
                let written = render(&original, chokepoint);
                let path = self.resolv_conf();
                write_atomic(&path, written.as_bytes()).map_err(|error| ResolverError::File {
                    path: path.clone(),
                    reason: error.to_string(),
                })?;
                baseline.written = Some(written);
                Ok(())
            }
            Environment::SystemdResolved => {
                let link = self.default_link()?;
                let address = chokepoint.to_string();
                self.runner
                    .run(&self.layout.resolvectl, &["dns", &link, &address])?;
                // Route every domain at it: without this, resolved would only use it for names that
                // no other link claims.
                self.runner
                    .run(&self.layout.resolvectl, &["domain", &link, "~."])?;
                baseline.link = Some(link);
                Ok(())
            }
            Environment::NetworkManager => Err(ResolverError::File {
                path: self.resolv_conf(),
                reason: "NetworkManager manages the resolver here and would overwrite a change; \
                         every query still reaches the chokepoint, because the firewall redirects \
                         port 53 regardless of what this file says"
                    .to_string(),
            }),
            Environment::Unknown => Err(ResolverError::File {
                path: self.resolv_conf(),
                reason:
                    "cannot tell what manages the resolver here; every query still reaches the \
                         chokepoint, because the firewall redirects port 53 regardless"
                        .to_string(),
            }),
        }
    }

    /// Put the configuration back, without clobbering anyone else's edit.
    pub fn restore(&self, baseline: &Baseline) -> Result<RestoreOutcome, ResolverError> {
        match baseline.environment {
            Environment::StaticFile => {
                let path = self.resolv_conf();
                let current = match std::fs::read_to_string(&path) {
                    Ok(contents) => contents,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
                    Err(error) => {
                        return Err(ResolverError::File {
                            path: path.clone(),
                            reason: error.to_string(),
                        })
                    }
                };

                let expected = baseline.written.clone().unwrap_or_default();
                if current != expected {
                    return Ok(RestoreOutcome::LeftAlone(format!(
                        "'{}' changed while protection was on, so it was left as it is now",
                        path.display()
                    )));
                }

                match &baseline.contents {
                    Some(contents) => {
                        write_atomic(&path, contents.as_bytes()).map_err(|error| {
                            ResolverError::File {
                                path: path.clone(),
                                reason: error.to_string(),
                            }
                        })?;
                    }
                    // The file did not exist before, so the honest restore is to remove ours.
                    None => {
                        let _ = std::fs::remove_file(&path);
                    }
                }
                Ok(RestoreOutcome::Restored)
            }
            Environment::SystemdResolved => {
                let Some(link) = &baseline.link else {
                    return Ok(RestoreOutcome::NothingToDo);
                };
                // Asking resolved to revert is better than replaying servers we guessed at: it goes
                // back to whatever the network itself provides.
                self.runner
                    .run(&self.layout.resolvectl, &["revert", link])?;
                Ok(RestoreOutcome::Restored)
            }
            Environment::NetworkManager | Environment::Unknown => Ok(RestoreOutcome::NothingToDo),
        }
    }

    /// The interface carrying the default route, which is the one resolved should be told about.
    fn default_link(&self) -> Result<String, ResolverError> {
        let path = self.layout.root.join("proc/net/route");
        let table = std::fs::read_to_string(&path).map_err(|error| ResolverError::File {
            path: path.clone(),
            reason: error.to_string(),
        })?;
        for line in table.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // Iface Destination Gateway ... ; the default route has destination 00000000.
            if fields.len() >= 8 && fields[1] == "00000000" {
                return Ok(fields[0].to_string());
            }
        }
        Err(ResolverError::NoDefaultRoute)
    }
}

/// The configuration written while protection is on.
///
/// `search`, `domain`, and `options` are about how names are completed and tried, not about who
/// resolves them, so they are kept. `nameserver` lines are replaced, because that is the point.
fn render(original: &str, chokepoint: IpAddr) -> String {
    let mut out = String::from(
        "# Written by Ghostnector while protection is on; the previous contents are restored
# when protection is turned off.\n",
    );
    out.push_str(&format!("nameserver {chokepoint}\n"));
    for line in original.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("search ")
            || trimmed.starts_with("domain ")
            || trimmed.starts_with("options ")
        {
            out.push_str(trimmed);
            out.push('\n');
        }
    }
    out
}

/// Where the recorded resolver state lives between runs.
///
/// It is on disk rather than in memory because the state outlives any single run of the control
/// plane: a machine that was pointed at the chokepoint and then rebooted must still be able to find
/// out whose configuration it is holding.
pub struct BaselineStore {
    path: PathBuf,
}

impl BaselineStore {
    /// A store at this path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The recorded state, if any.
    pub fn load(&self) -> Result<Option<Baseline>, ResolverError> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => {
                serde_json::from_str(&text)
                    .map(Some)
                    .map_err(|error| ResolverError::File {
                        path: self.path.clone(),
                        reason: error.to_string(),
                    })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(ResolverError::File {
                path: self.path.clone(),
                reason: error.to_string(),
            }),
        }
    }

    /// Record the state.
    pub fn save(&self, baseline: &Baseline) -> Result<(), ResolverError> {
        let encoded = serde_json::to_vec_pretty(baseline).map_err(|error| ResolverError::File {
            path: self.path.clone(),
            reason: error.to_string(),
        })?;
        write_atomic(&self.path, &encoded).map_err(|error| ResolverError::File {
            path: self.path.clone(),
            reason: error.to_string(),
        })
    }

    /// Forget the state, once it has been put back.
    pub fn clear(&self) -> Result<(), ResolverError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ResolverError::File {
                path: self.path.clone(),
                reason: error.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MockRunner;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    struct Fixture {
        root: PathBuf,
        runner: Arc<MockRunner>,
        resolver: Resolver,
    }

    impl Fixture {
        fn new() -> Self {
            let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
            let root = std::env::temp_dir().join(format!(
                "ghostnector-resolver-{}-{unique}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("etc")).expect("etc");
            std::fs::create_dir_all(root.join("proc/net")).expect("proc");
            let runner = Arc::new(MockRunner::new());
            let resolver = Resolver::new(
                Layout {
                    root: root.clone(),
                    resolvectl: PathBuf::from("/usr/bin/resolvectl"),
                },
                Arc::clone(&runner) as Arc<dyn CommandRunner>,
            );
            Self {
                root,
                runner,
                resolver,
            }
        }

        fn write_resolv_conf(&self, contents: &str) {
            std::fs::write(self.resolver.resolv_conf(), contents).expect("write resolv.conf");
        }

        fn resolv_conf(&self) -> String {
            std::fs::read_to_string(self.resolver.resolv_conf()).expect("read resolv.conf")
        }

        fn symlink_resolv_conf(&self, target: &str) {
            let path = self.resolver.resolv_conf();
            let _ = std::fs::remove_file(&path);
            std::os::unix::fs::symlink(target, &path).expect("symlink");
        }

        fn default_route(&self, interface: &str) {
            let table = format!(
                "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
                 {interface}\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\n"
            );
            std::fs::write(self.root.join("proc/net/route"), table).expect("write route");
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    const CHOKEPOINT: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

    #[test]
    fn a_plain_file_is_recognised_as_a_plain_file() {
        let fixture = Fixture::new();
        fixture.write_resolv_conf("nameserver 192.0.2.53\n");
        assert_eq!(fixture.resolver.detect(), Environment::StaticFile);
    }

    #[test]
    fn a_symlink_into_systemds_runtime_directory_is_recognised() {
        let fixture = Fixture::new();
        fixture.symlink_resolv_conf("/run/systemd/resolve/stub-resolv.conf");
        assert_eq!(fixture.resolver.detect(), Environment::SystemdResolved);
    }

    #[test]
    fn a_symlink_into_networkmanagers_directory_is_recognised() {
        let fixture = Fixture::new();
        fixture.symlink_resolv_conf("/run/NetworkManager/resolv.conf");
        assert_eq!(fixture.resolver.detect(), Environment::NetworkManager);
    }

    #[test]
    fn a_file_naming_resolveds_stub_address_is_treated_as_resolved() {
        let fixture = Fixture::new();
        fixture.write_resolv_conf("nameserver 127.0.0.53\noptions edns0\n");
        assert_eq!(fixture.resolver.detect(), Environment::SystemdResolved);
    }

    #[test]
    fn a_missing_configuration_is_not_something_to_guess_about() {
        let fixture = Fixture::new();
        assert_eq!(fixture.resolver.detect(), Environment::Unknown);
    }

    #[test]
    fn a_plain_file_is_pointed_at_the_chokepoint_and_the_search_list_survives() {
        let fixture = Fixture::new();
        fixture.write_resolv_conf(
            "# a comment\nnameserver 192.0.2.53\nnameserver 192.0.2.54\nsearch example.test\n\
             options edns0 trust-ad\n",
        );
        let mut baseline = fixture.resolver.capture().expect("capture");
        fixture
            .resolver
            .point_at(&mut baseline, CHOKEPOINT)
            .expect("point");

        let written = fixture.resolv_conf();
        assert!(written.starts_with("# Written by Ghostnector"), "{written}");
        assert!(written.contains("nameserver 127.0.0.1\n"), "{written}");
        assert!(!written.contains("192.0.2.53"), "{written}");
        assert!(!written.contains("192.0.2.54"), "{written}");
        assert!(written.contains("search example.test\n"), "{written}");
        assert!(written.contains("options edns0 trust-ad\n"), "{written}");
    }

    #[test]
    fn restoring_a_plain_file_puts_the_original_bytes_back() {
        let fixture = Fixture::new();
        let original = "# a comment\nnameserver 192.0.2.53\nsearch example.test\n";
        fixture.write_resolv_conf(original);

        let mut baseline = fixture.resolver.capture().expect("capture");
        fixture
            .resolver
            .point_at(&mut baseline, CHOKEPOINT)
            .expect("point");
        let outcome = fixture.resolver.restore(&baseline).expect("restore");

        assert_eq!(outcome, RestoreOutcome::Restored);
        assert_eq!(
            fixture.resolv_conf(),
            original,
            "the file must come back byte for byte"
        );
    }

    #[test]
    fn restoring_refuses_to_clobber_a_change_someone_else_made() {
        let fixture = Fixture::new();
        fixture.write_resolv_conf("nameserver 192.0.2.53\n");
        let mut baseline = fixture.resolver.capture().expect("capture");
        fixture
            .resolver
            .point_at(&mut baseline, CHOKEPOINT)
            .expect("point");

        // Somebody else edits it while protection is on.
        fixture.write_resolv_conf("nameserver 203.0.113.53\n");

        let outcome = fixture.resolver.restore(&baseline).expect("restore");
        match outcome {
            RestoreOutcome::LeftAlone(reason) => {
                assert!(reason.contains("changed"), "{reason}");
            }
            other => panic!("expected the file to be left alone, got {other:?}"),
        }
        assert_eq!(
            fixture.resolv_conf(),
            "nameserver 203.0.113.53\n",
            "their edit must survive"
        );
    }

    #[test]
    fn a_file_that_did_not_exist_is_removed_again() {
        let fixture = Fixture::new();
        let baseline = fixture.resolver.capture().expect("capture");
        assert_eq!(baseline.environment, Environment::Unknown);

        // With a plain file present but empty, capture records "exists and is empty".
        fixture.write_resolv_conf("");
        let mut baseline = fixture.resolver.capture().expect("capture");
        fixture
            .resolver
            .point_at(&mut baseline, CHOKEPOINT)
            .expect("point");
        assert!(fixture.resolv_conf().contains("nameserver 127.0.0.1"));

        // Simulate the file not existing beforehand.
        baseline.contents = None;
        std::fs::remove_file(fixture.resolver.resolv_conf()).expect("remove");
        std::fs::write(
            fixture.resolver.resolv_conf(),
            baseline.written.clone().unwrap(),
        )
        .expect("rewrite ours");
        let outcome = fixture.resolver.restore(&baseline).expect("restore");
        assert_eq!(outcome, RestoreOutcome::Restored);
        assert!(
            !fixture.resolver.resolv_conf().exists(),
            "a file we created must not be left behind"
        );
    }

    #[test]
    fn networkmanager_is_left_alone_and_the_reason_says_why_it_is_still_safe() {
        let fixture = Fixture::new();
        fixture.symlink_resolv_conf("/run/NetworkManager/resolv.conf");
        let mut baseline = fixture.resolver.capture().expect("capture");
        let error = fixture
            .resolver
            .point_at(&mut baseline, CHOKEPOINT)
            .expect_err("NetworkManager is not ours to change");
        let message = error.to_string();
        assert!(message.contains("NetworkManager"), "{message}");
        assert!(
            message.contains("firewall redirects port 53"),
            "the message must say why the machine is still safe: {message}"
        );
        assert!(fixture.runner.calls().is_empty());
    }

    #[test]
    fn systemd_resolved_is_pointed_at_the_chokepoint_through_its_own_tool() {
        let fixture = Fixture::new();
        fixture.symlink_resolv_conf("/run/systemd/resolve/stub-resolv.conf");
        fixture.default_route("wlan0");

        let mut baseline = fixture.resolver.capture().expect("capture");
        fixture
            .resolver
            .point_at(&mut baseline, CHOKEPOINT)
            .expect("point");

        let calls = fixture.runner.calls();
        assert_eq!(
            calls,
            vec![
                "/usr/bin/resolvectl dns wlan0 127.0.0.1".to_string(),
                "/usr/bin/resolvectl domain wlan0 ~.".to_string(),
            ],
            "the tool is used rather than the file, and every domain is routed at us"
        );
        assert_eq!(baseline.link.as_deref(), Some("wlan0"));
    }

    #[test]
    fn systemd_resolved_is_restored_by_asking_it_to_revert() {
        let fixture = Fixture::new();
        fixture.symlink_resolv_conf("/run/systemd/resolve/stub-resolv.conf");
        fixture.default_route("eth0");

        let mut baseline = fixture.resolver.capture().expect("capture");
        fixture
            .resolver
            .point_at(&mut baseline, CHOKEPOINT)
            .expect("point");
        let outcome = fixture.resolver.restore(&baseline).expect("restore");

        assert_eq!(outcome, RestoreOutcome::Restored);
        assert!(
            fixture
                .runner
                .calls()
                .contains(&"/usr/bin/resolvectl revert eth0".to_string()),
            "reverting beats replaying servers we guessed at: {:?}",
            fixture.runner.calls()
        );
    }

    #[test]
    fn a_machine_with_no_default_route_is_reported_rather_than_guessed_at() {
        let fixture = Fixture::new();
        fixture.symlink_resolv_conf("/run/systemd/resolve/stub-resolv.conf");
        // No route table written at all.
        std::fs::remove_file(fixture.root.join("proc/net/route")).ok();
        let mut baseline = fixture.resolver.capture().expect("capture");
        let error = fixture
            .resolver
            .point_at(&mut baseline, CHOKEPOINT)
            .expect_err("nothing to attach to");
        assert!(matches!(error, ResolverError::File { .. }), "{error}");
    }

    #[test]
    fn an_unknown_environment_is_left_alone_and_says_nothing_was_done() {
        let fixture = Fixture::new();
        fixture.symlink_resolv_conf("/somewhere/else/resolv.conf");
        let baseline = fixture.resolver.capture().expect("capture");

        let mut mutable = baseline.clone();
        assert!(fixture.resolver.point_at(&mut mutable, CHOKEPOINT).is_err());
        assert_eq!(
            fixture.resolver.restore(&baseline).expect("restore"),
            RestoreOutcome::NothingToDo
        );
    }

    #[test]
    fn the_recorded_state_survives_a_round_trip_through_disk() {
        let fixture = Fixture::new();
        let store = BaselineStore::new(fixture.root.join("state/resolver.json"));
        assert_eq!(store.load().expect("empty"), None);

        fixture.write_resolv_conf("nameserver 192.0.2.53\nsearch example.test\n");
        let mut baseline = fixture.resolver.capture().expect("capture");
        fixture
            .resolver
            .point_at(&mut baseline, CHOKEPOINT)
            .expect("point");
        store.save(&baseline).expect("save");

        assert_eq!(store.load().expect("load"), Some(baseline.clone()));

        store.clear().expect("clear");
        assert_eq!(store.load().expect("cleared"), None);
        // Clearing twice is not an error: the second call has nothing to do.
        store.clear().expect("clear again");
    }

    #[test]
    fn a_corrupt_store_is_an_error_rather_than_a_default() {
        let fixture = Fixture::new();
        let store = BaselineStore::new(fixture.root.join("state/resolver.json"));
        std::fs::create_dir_all(fixture.root.join("state")).expect("state dir");
        std::fs::write(fixture.root.join("state/resolver.json"), b"{ not json").expect("write");
        assert!(store.load().is_err());
    }
}
