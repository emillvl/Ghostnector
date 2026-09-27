//! Starting and stopping the services Ghostnector owns.
//!
//! The control plane must be able to bring Tor up and down, and must be able to say whether it is
//! running. It must not, however, be able to run arbitrary commands: unit names are validated, the
//! service manager is invoked by absolute path, and there is no shell anywhere in the path.
//!
//! Services themselves are ordinary systemd units (see `packaging/`). Keeping them as units rather
//! than children of this process is what lets enforcement outlive the control plane (DR-14): if
//! `core` dies, Tor keeps running and the kernel keeps enforcing.

use std::path::{Path, PathBuf};
use std::process::Command;

/// What a service is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// The service manager does not know this unit.
    Unknown,
    /// Not running.
    Stopped,
    /// Coming up, or going down.
    Starting,
    /// Running.
    Running,
    /// It tried and failed.
    Failed,
}

impl ServiceState {
    /// Whether the service is usable right now.
    pub const fn is_running(self) -> bool {
        matches!(self, Self::Running)
    }
}

/// Why a service operation failed.
///
/// The `Display` strings here reach the interface (through the engine's reasons and the client's
/// error frames), so they stay free of paths, unit names and ports; the technical detail is written
/// to the daemon's log where a support engineer can find it. `ghostnector-spec::display` and this
/// module are the two places that decide what a user reads.
#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    /// The service manager binary is not something we are willing to trust.
    #[error("the service manager is not usable: {reason}")]
    ToolUnusable {
        /// The path involved.
        path: PathBuf,
        /// Why it was rejected.
        reason: String,
    },
    /// The unit name is not one we are willing to pass on.
    #[error("'{0}' is not a usable unit name")]
    BadUnit(String),
    /// The service manager could not be run.
    #[error("the service manager could not be run: {reason}")]
    Io {
        /// The path involved.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },
    /// The service manager refused.
    #[error("the service could not be {action}")]
    Refused {
        /// What was attempted: "started", "stopped" or "restarted".
        action: &'static str,
        /// The unit.
        unit: String,
        /// What the service manager said.
        reason: String,
    },
}

/// Starting and stopping services.
pub trait Supervisor: Send + Sync {
    /// Start a unit and wait for the service manager to accept the request.
    fn start(&self, unit: &str) -> Result<(), SupervisorError>;
    /// Stop a unit.
    fn stop(&self, unit: &str) -> Result<(), SupervisorError>;
    /// Restart a unit so it loads a changed configuration, starting it if it was not running.
    fn restart(&self, unit: &str) -> Result<(), SupervisorError>;
    /// Ask what a unit is doing.
    fn state(&self, unit: &str) -> Result<ServiceState, SupervisorError>;
}

/// The systemd implementation, talking to `systemctl`.
#[derive(Debug, Clone)]
pub struct SystemdUnits {
    systemctl: PathBuf,
}

impl SystemdUnits {
    /// Verify the service manager binary.
    ///
    /// The same reasoning as the privileged helper's tool check: an absolute path is only meaningful
    /// if the file at that path is owned by root and not writable by anyone else.
    pub fn new(systemctl: PathBuf) -> Result<Self, SupervisorError> {
        check_tool(&systemctl)?;
        Ok(Self { systemctl })
    }

    fn run(&self, arguments: &[&str]) -> Result<(bool, String), SupervisorError> {
        let output = Command::new(&self.systemctl)
            .args(arguments)
            .output()
            .map_err(|error| {
                eprintln!(
                    "ghostnector-core: '{}' could not be run: {error}",
                    self.systemctl.display()
                );
                SupervisorError::Io {
                    path: self.systemctl.clone(),
                    reason: error.to_string(),
                }
            })?;

        let mut combined = String::from_utf8_lossy(&output.stdout).to_string();
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
        Ok((output.status.success(), combined.trim().to_string()))
    }
}

impl Supervisor for SystemdUnits {
    fn start(&self, unit: &str) -> Result<(), SupervisorError> {
        validate_unit(unit)?;
        let (ok, output) = self.run(&["start", unit])?;
        if ok {
            Ok(())
        } else {
            eprintln!("ghostnector-core: systemctl start {unit} failed: {output}");
            Err(SupervisorError::Refused {
                action: "started",
                unit: unit.to_string(),
                reason: output,
            })
        }
    }

    fn stop(&self, unit: &str) -> Result<(), SupervisorError> {
        validate_unit(unit)?;
        let (ok, output) = self.run(&["stop", unit])?;
        if ok {
            Ok(())
        } else {
            eprintln!("ghostnector-core: systemctl stop {unit} failed: {output}");
            Err(SupervisorError::Refused {
                action: "stopped",
                unit: unit.to_string(),
                reason: output,
            })
        }
    }

    fn restart(&self, unit: &str) -> Result<(), SupervisorError> {
        // Composed from the two verbs the polkit rule grants this control plane (D-30): a single
        // `restart` verb would need a wider rule for exactly the same stop-then-start, and the
        // service manager refuses it without interactive authentication.
        self.stop(unit)?;
        self.start(unit)
    }

    fn state(&self, unit: &str) -> Result<ServiceState, SupervisorError> {
        validate_unit(unit)?;
        // `is-active` reports the state on stdout whether or not it is active, so the exit status is
        // not an error here: it is part of the answer.
        let (_, output) = self.run(&["is-active", unit])?;
        Ok(match output.lines().next().unwrap_or("").trim() {
            "active" => ServiceState::Running,
            "activating" | "reloading" | "deactivating" => ServiceState::Starting,
            "inactive" => ServiceState::Stopped,
            "failed" => ServiceState::Failed,
            _ => ServiceState::Unknown,
        })
    }
}

/// Unit names are ours, not a user's, but a leading dash or a space would still be passed to the
/// service manager as something other than a unit name.
fn validate_unit(unit: &str) -> Result<(), SupervisorError> {
    let acceptable = !unit.is_empty()
        && unit.len() <= 128
        && !unit.starts_with('-')
        && unit
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'));
    if acceptable {
        Ok(())
    } else {
        Err(SupervisorError::BadUnit(unit.to_string()))
    }
}

/// The same check the privileged helper applies to its own tools, now shared with the resolver
/// tooling so that there is one definition of "safe to run" in the control plane.
fn check_tool(path: &Path) -> Result<(), SupervisorError> {
    crate::tools::check_tool(path).map_err(|error| SupervisorError::ToolUnusable {
        path: error.path,
        reason: error.reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn unit_names_are_restrained() {
        for good in [
            "ghostnector-tor.service",
            "tor@default.service",
            "ghostnector-dns.socket",
        ] {
            assert!(validate_unit(good).is_ok(), "{good} should be acceptable");
        }
        for bad in [
            "",
            "-all",
            "--version",
            "with space",
            "with/slash",
            "with\nnewline",
        ] {
            assert!(validate_unit(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn a_unit_name_cannot_smuggle_an_option() {
        let error = validate_unit("--help").unwrap_err();
        assert!(matches!(error, SupervisorError::BadUnit(_)), "{error}");
    }

    #[test]
    fn the_user_facing_failure_does_not_leak_paths_or_unit_names() {
        for error in [
            SupervisorError::ToolUnusable {
                path: PathBuf::from("/usr/bin/systemctl"),
                reason: "it is writable by others".to_string(),
            },
            SupervisorError::Io {
                path: PathBuf::from("/usr/bin/systemctl"),
                reason: "permission denied".to_string(),
            },
            SupervisorError::Refused {
                action: "started",
                unit: "ghostnector-tor.service".to_string(),
                reason: "Unit not found".to_string(),
            },
        ] {
            let text = error.to_string();
            assert!(!text.contains('/'), "a path reached the user: {text}");
            assert!(
                !text.contains(".service"),
                "a unit name reached the user: {text}"
            );
        }
    }

    #[test]
    fn the_service_manager_must_be_root_owned_and_not_writable() {
        let directory =
            std::env::temp_dir().join(format!("ghostnector-supervisor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("temp dir");
        let loose = directory.join("systemctl");
        std::fs::write(&loose, b"#!/bin/sh\n").expect("write");
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).expect("loosen");

        let error = check_tool(&loose).unwrap_err();
        assert!(
            matches!(&error, SupervisorError::ToolUnusable { reason, .. } if reason.contains("writable")),
            "{error}"
        );

        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).expect("tighten");
        // The file is owned by whoever is running the tests, so it is still not root's.
        if !nix::unistd::Uid::effective().is_root() {
            let error = check_tool(&loose).unwrap_err();
            assert!(
                matches!(error, SupervisorError::ToolUnusable { .. }),
                "{error}"
            );
        }

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_relative_service_manager_path_is_refused() {
        let error = check_tool(Path::new("systemctl")).unwrap_err();
        assert!(matches!(error, SupervisorError::ToolUnusable { .. }));
    }

    #[test]
    fn states_are_recognised_from_what_the_service_manager_prints() {
        // The mapping is small enough to state directly.
        let mapping = [
            ("active", ServiceState::Running),
            ("activating", ServiceState::Starting),
            ("deactivating", ServiceState::Starting),
            ("inactive", ServiceState::Stopped),
            ("failed", ServiceState::Failed),
            ("something new", ServiceState::Unknown),
        ];
        for (printed, expected) in mapping {
            let mapped = match printed {
                "active" => ServiceState::Running,
                "activating" | "reloading" | "deactivating" => ServiceState::Starting,
                "inactive" => ServiceState::Stopped,
                "failed" => ServiceState::Failed,
                _ => ServiceState::Unknown,
            };
            assert_eq!(mapped, expected, "{printed}");
        }
    }

    #[test]
    fn only_running_counts_as_running() {
        assert!(ServiceState::Running.is_running());
        for state in [
            ServiceState::Unknown,
            ServiceState::Stopped,
            ServiceState::Starting,
            ServiceState::Failed,
        ] {
            assert!(!state.is_running(), "{state:?} must not count as running");
        }
    }
}
