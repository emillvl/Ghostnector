//! Doubles for tests.
//!
//! These live in the crate rather than in a separate test crate so that unit tests can exercise the
//! real dispatch path — including the parts that would otherwise need root, a kernel, and a live
//! socket.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::backend::{Backend, BackendError};
use crate::identities::{Identities, IdentityError};

/// A backend that records what it was asked to do.
#[derive(Debug, Default)]
pub struct MockBackend {
    applied: Mutex<Vec<String>>,
    table: Mutex<bool>,
    live: Mutex<String>,
    flush_calls: Mutex<usize>,
    fail_apply: Mutex<Option<String>>,
    conntrack_usable: bool,
}

impl MockBackend {
    /// A backend whose conntrack tool is available.
    pub fn new() -> Self {
        Self {
            conntrack_usable: true,
            ..Self::default()
        }
    }

    /// A backend whose conntrack tool is missing.
    pub fn without_conntrack() -> Self {
        Self::default()
    }

    /// Every script handed to [`Backend::apply`], in order.
    pub fn scripts(&self) -> Vec<String> {
        self.applied.lock().expect("mock lock").clone()
    }

    /// How many times conntrack was flushed.
    pub fn flush_calls(&self) -> usize {
        *self.flush_calls.lock().expect("mock lock")
    }

    /// Make the next apply fail with this message.
    pub fn fail_apply_with(&self, message: &str) {
        *self.fail_apply.lock().expect("mock lock") = Some(message.to_string());
    }

    /// Force the kernel-side table state, to simulate someone else changing it.
    pub fn force_table(&self, present: bool) {
        *self.table.lock().expect("mock lock") = present;
    }

    /// Add a line to what the kernel reports, as another tool would.
    pub fn tamper(&self, extra: &str) {
        let mut live = self.live.lock().expect("mock lock");
        live.push('\n');
        live.push_str(extra);
    }
}

impl Backend for MockBackend {
    fn apply(&self, script: &str) -> Result<(), BackendError> {
        if let Some(message) = self.fail_apply.lock().expect("mock lock").clone() {
            return Err(BackendError::Apply(message));
        }
        self.applied
            .lock()
            .expect("mock lock")
            .push(script.to_string());
        // A replacement script defines the table; a revert script only destroys it.
        let defines = script.contains("table inet ghostnector {");
        *self.table.lock().expect("mock lock") = defines;
        // What the kernel would report back: the table, without the replacement's destroy line.
        *self.live.lock().expect("mock lock") = if defines {
            script
                .lines()
                .filter(|line| !line.trim_start().starts_with("destroy table"))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            String::new()
        };
        Ok(())
    }

    fn flush_conntrack(&self) -> Result<(), BackendError> {
        *self.flush_calls.lock().expect("mock lock") += 1;
        if self.conntrack_usable {
            Ok(())
        } else {
            Err(BackendError::ConntrackUnavailable(
                "not installed".to_string(),
            ))
        }
    }

    fn table_present(&self) -> Result<bool, BackendError> {
        Ok(*self.table.lock().expect("mock lock"))
    }

    fn list_table(&self) -> Result<String, BackendError> {
        if !*self.table.lock().expect("mock lock") {
            return Ok(String::new());
        }
        Ok(self.live.lock().expect("mock lock").clone())
    }
}

/// An identity database with exactly the users a test names.
#[derive(Debug, Default, Clone)]
pub struct FixedIdentities {
    users: HashMap<String, u32>,
}

impl FixedIdentities {
    /// Build from name/uid pairs.
    pub fn new(users: &[(&str, u32)]) -> Self {
        Self {
            users: users
                .iter()
                .map(|(name, uid)| ((*name).to_string(), *uid))
                .collect(),
        }
    }

    /// A machine with no Ghostnector services installed.
    pub fn empty() -> Self {
        Self::default()
    }
}

impl Identities for FixedIdentities {
    fn uid_of(&self, name: &str) -> Result<u32, IdentityError> {
        self.users
            .get(name)
            .copied()
            .ok_or_else(|| IdentityError::NotInstalled(name.to_string()))
    }
}
