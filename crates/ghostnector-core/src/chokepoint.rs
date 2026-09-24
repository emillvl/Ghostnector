//! Running the DNS chokepoint.
//!
//! The chokepoint is a separate process rather than a thread in this one, so a fault in the relay
//! cannot take the control plane with it. It is started as a child and tethered: if `core` dies, the
//! relay stops too. That is the fail-closed direction — a stopped relay means DNS stops, while the
//! policy keeps redirecting port 53 into nothing rather than letting queries out.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use crate::tools::check_tool;

/// Why the chokepoint could not be run.
#[derive(Debug, thiserror::Error)]
pub enum ChokepointError {
    /// The helper program is not safe to run.
    #[error("{0}")]
    ToolUnusable(#[from] crate::tools::ToolError),
    /// It could not be started.
    #[error("the DNS relay could not be started: {0}")]
    Start(String),
}

/// Starting and stopping the DNS relay.
pub trait DnsRelay: Send + Sync {
    /// Start it, or move it to a different upstream.
    fn start(&self, listen: SocketAddr, upstream: SocketAddr) -> Result<(), ChokepointError>;
    /// Stop it.
    fn stop(&self) -> Result<(), ChokepointError>;
    /// Whether it is still running.
    fn is_running(&self) -> bool;
}

/// The chokepoint as a child process.
#[derive(Debug)]
pub struct ChildRelay {
    program: PathBuf,
    child: Mutex<Option<Child>>,
}

impl ChildRelay {
    /// Verify the helper program before using it.
    pub fn new(program: PathBuf) -> Result<Self, ChokepointError> {
        check_tool(&program)?;
        Ok(Self {
            program,
            child: Mutex::new(None),
        })
    }

    /// The program in use.
    pub fn program(&self) -> &Path {
        &self.program
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Child>> {
        self.child
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl DnsRelay for ChildRelay {
    fn start(&self, listen: SocketAddr, upstream: SocketAddr) -> Result<(), ChokepointError> {
        let mut slot = self.lock();

        // A running relay is replaced rather than reused: the upstream differs between modes, and a
        // half-moved relay would resolve some names the old way.
        if let Some(mut previous) = slot.take() {
            let _ = previous.kill();
            let _ = previous.wait();
        }

        let child = Command::new(&self.program)
            .arg("--listen")
            .arg(listen.to_string())
            .arg("--upstream")
            .arg(upstream.to_string())
            // The tether: when this process goes away, the child's standard input closes and the
            // relay stops, instead of lingering with port 53 bound.
            .arg("--exit-when-stdin-closes")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| ChokepointError::Start(error.to_string()))?;

        *slot = Some(child);
        Ok(())
    }

    fn stop(&self) -> Result<(), ChokepointError> {
        let mut slot = self.lock();
        if let Some(mut child) = slot.take() {
            // Closing the tether is the polite signal; the kill is for a relay that has stopped
            // reading anything.
            drop(child.stdin.take());
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(())
    }

    fn is_running(&self) -> bool {
        let mut slot = self.lock();
        let Some(child) = slot.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(None) => true,
            Ok(Some(_)) => {
                // It exited on its own; forget it so a later start is not fooled.
                *slot = None;
                false
            }
            Err(_) => false,
        }
    }
}

impl Drop for ChildRelay {
    fn drop(&mut self) {
        if let Ok(slot) = self.child.get_mut() {
            if let Some(child) = slot.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn directory() -> PathBuf {
        let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("ghostnector-relay-{}-{unique}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        path
    }

    /// A stand-in for the relay: a script that ignores its arguments and waits.
    fn waiting_program(label: &str, seconds: u64) -> (PathBuf, PathBuf) {
        let dir = directory();
        let program = dir.join(label);
        std::fs::write(&program, format!("#!/bin/sh\nsleep {seconds}\n")).expect("write");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        (program, dir)
    }

    fn addresses() -> (SocketAddr, SocketAddr) {
        (
            "127.0.0.1:53".parse().expect("listen"),
            "127.0.0.1:9053".parse().expect("upstream"),
        )
    }

    #[test]
    fn the_helper_program_must_be_safe_to_run() {
        let error = ChildRelay::new(PathBuf::from("ghostnector-dns")).unwrap_err();
        assert!(matches!(error, ChokepointError::ToolUnusable(_)), "{error}");
    }

    #[test]
    fn a_started_relay_runs_and_can_be_stopped() {
        if !nix::unistd::Uid::effective().is_root() {
            // The tool check requires root ownership, which a test cannot arrange as a normal user.
            return;
        }
        let (program, dir) = waiting_program("relay", 60);
        let relay = ChildRelay::new(program).expect("acceptable program");
        let (listen, upstream) = addresses();

        relay.start(listen, upstream).expect("start");
        assert!(relay.is_running(), "it should be running");

        relay.stop().expect("stop");
        assert!(!relay.is_running(), "it should have stopped");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn starting_again_replaces_the_previous_relay() {
        if !nix::unistd::Uid::effective().is_root() {
            return;
        }
        let (program, dir) = waiting_program("relay-replace", 60);
        let relay = ChildRelay::new(program).expect("acceptable program");
        let (listen, upstream) = addresses();

        relay.start(listen, upstream).expect("first start");
        let first = {
            let slot = relay.lock();
            slot.as_ref().map(|child| child.id())
        };

        relay
            .start(listen, "127.0.0.1:9054".parse().expect("other"))
            .expect("second start");
        let second = {
            let slot = relay.lock();
            slot.as_ref().map(|child| child.id())
        };

        assert_ne!(first, second, "a new upstream needs a new process");
        assert!(relay.is_running());

        relay.stop().expect("stop");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_relay_that_exits_on_its_own_is_not_reported_as_running() {
        if !nix::unistd::Uid::effective().is_root() {
            return;
        }
        let (program, dir) = waiting_program("relay-exits", 0);
        let relay = ChildRelay::new(program).expect("acceptable program");
        let (listen, upstream) = addresses();
        relay.start(listen, upstream).expect("start");

        let deadline = Instant::now() + Duration::from_secs(5);
        while relay.is_running() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!relay.is_running(), "a relay that exited is not running");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
