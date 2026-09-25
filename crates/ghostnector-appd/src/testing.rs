//! A stand-in backend for tests: no kernel, no root, fully scripted.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::backend::{BackendError, GroupRequest, Namespaces};

/// A backend whose answers the test controls.
#[derive(Debug, Default)]
pub struct MockNamespaces {
    bridge: Mutex<bool>,
    groups: Mutex<BTreeMap<u32, String>>,
    shape: Mutex<Vec<String>>,
    probe_results: Mutex<Vec<ghostnector_spec::appd::CheckVerdict>>,
    fail_create: Mutex<Option<String>>,
    calls: Mutex<Vec<String>>,
}

impl MockNamespaces {
    /// A backend with no bridge and no groups.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the kernel listing for a group, as a tampering test would.
    pub fn set_policy(&self, id: u32, listing: &str) {
        self.groups
            .lock()
            .expect("mock lock")
            .insert(id, listing.to_string());
    }

    /// Make the shape check report these problems.
    pub fn set_shape_problems(&self, problems: Vec<String>) {
        *self.shape.lock().expect("mock lock") = problems;
    }

    /// Make the probe report these verdicts.
    pub fn set_probe_results(&self, results: Vec<ghostnector_spec::appd::CheckVerdict>) {
        *self.probe_results.lock().expect("mock lock") = results;
    }

    /// Make the next create fail with this message.
    pub fn fail_next_create(&self, message: &str) {
        *self.fail_create.lock().expect("mock lock") = Some(message.to_string());
    }

    /// The operations the backend was asked to perform, in order.
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("mock lock").clone()
    }

    /// The ids that currently exist.
    pub fn live_groups(&self) -> Vec<u32> {
        self.groups
            .lock()
            .expect("mock lock")
            .keys()
            .copied()
            .collect()
    }
}

impl Namespaces for MockNamespaces {
    fn bridge_present(&self) -> Result<bool, BackendError> {
        Ok(*self.bridge.lock().expect("mock lock"))
    }

    fn ensure_bridge(&self) -> Result<(), BackendError> {
        *self.bridge.lock().expect("mock lock") = true;
        self.calls
            .lock()
            .expect("mock lock")
            .push("ensure_bridge".to_string());
        Ok(())
    }

    fn destroy_bridge(&self) -> Result<(), BackendError> {
        *self.bridge.lock().expect("mock lock") = false;
        self.calls
            .lock()
            .expect("mock lock")
            .push("destroy_bridge".to_string());
        Ok(())
    }

    fn group_present(&self, id: u32) -> Result<bool, BackendError> {
        Ok(self.groups.lock().expect("mock lock").contains_key(&id))
    }

    fn create(&self, request: &GroupRequest) -> Result<(), BackendError> {
        self.calls
            .lock()
            .expect("mock lock")
            .push(format!("create {}", request.id));
        if let Some(message) = self.fail_create.lock().expect("mock lock").take() {
            return Err(BackendError::Refused(message));
        }
        self.groups.lock().expect("mock lock").insert(
            request.id,
            format!(
                "table inet ghostnector {{\n\t# group {} at {}\n}}\n",
                request.id, request.address
            ),
        );
        Ok(())
    }

    fn destroy(&self, id: u32) -> Result<(), BackendError> {
        self.calls
            .lock()
            .expect("mock lock")
            .push(format!("destroy {id}"));
        self.groups.lock().expect("mock lock").remove(&id);
        Ok(())
    }

    fn applied_policy(&self, id: u32) -> Result<String, BackendError> {
        Ok(self
            .groups
            .lock()
            .expect("mock lock")
            .get(&id)
            .cloned()
            .unwrap_or_default())
    }

    fn probe(
        &self,
        _id: u32,
        _uid: u32,
        _config: &ghostnector_spec::appd::ProbeConfig,
    ) -> Result<Vec<ghostnector_spec::appd::CheckVerdict>, BackendError> {
        self.calls
            .lock()
            .expect("mock lock")
            .push("probe".to_string());
        Ok(self.probe_results.lock().expect("mock lock").clone())
    }

    fn shape_problems(&self, _request: &GroupRequest) -> Result<Vec<String>, BackendError> {
        Ok(self.shape.lock().expect("mock lock").clone())
    }
}
