//! The bounded APP-group registry.
//!
//! Every group the helper owns has one record here: the id it allocated, the owner that asked for
//! it, the address it assigned, when, and the kernel's canonical report of the policy it installed.
//! There is deliberately nothing else — no destinations, no traffic counters, no queries (invariant
//! I6 / DR-19).
//!
//! The file lives in `/run`, so it does not survive a reboot and can never describe objects that do
//! not exist. Within a boot it is the truth about *intent*; the kernel is the truth about what
//! exists, and [`crate::server::Server::inspect`] asks the kernel rather than trusting a record.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ghostnector_spec::app::MAX_APP_GROUPS;
use ghostnector_spec::backend::Ports;
use serde::{Deserialize, Serialize};

/// Format version. A file from the future is refused rather than guessed at.
pub const REGISTRY_VERSION: u32 = 1;

/// One group, exactly as persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRecord {
    /// The id the helper allocated.
    pub id: u32,
    /// The uid that asked for the group, from `SO_PEERCRED`.
    pub owner_uid: u32,
    /// The address assigned inside the namespace.
    pub address: Ipv4Addr,
    /// Creation time, seconds since the epoch.
    pub created_at: i64,
    /// The kernel's canonical report of the namespace policy when it was installed. Used for the
    /// effective-policy comparison. Policy text only; never exposed to a client.
    #[serde(default)]
    pub effective: Option<String>,
}

/// The registry file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RegistryFile {
    /// Format version.
    pub version: u32,
    /// Whether the bridge was ensured in this boot.
    pub bridge_ready: bool,
    /// The ports the namespace rules name, as reported by `netd`.
    pub ports: Option<Ports>,
    /// The groups.
    pub records: Vec<AppRecord>,
}

impl Default for RegistryFile {
    fn default() -> Self {
        Self {
            version: REGISTRY_VERSION,
            bridge_ready: false,
            ports: None,
            records: Vec::new(),
        }
    }
}

/// Why the registry could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// The file could not be read or written.
    #[error("registry io: {0}")]
    Io(String),
    /// The file is not a registry this build understands.
    #[error("registry '{path}' is not usable: {reason}")]
    Corrupt {
        /// The path.
        path: String,
        /// Why.
        reason: String,
    },
    /// The identifier space is exhausted.
    #[error("the registry is full: at most {max} groups are supported")]
    Full {
        /// The maximum.
        max: usize,
    },
    /// An address could not be derived for this id.
    #[error("cannot assign an address for group {id}: {reason}")]
    Address {
        /// The id.
        id: u32,
        /// Why.
        reason: String,
    },
}

/// The registry, held in memory and persisted atomically.
#[derive(Debug)]
pub struct Registry {
    path: PathBuf,
    max_groups: usize,
    file: Mutex<RegistryFile>,
}

impl Registry {
    /// Load the registry, or start empty when there is no file.
    ///
    /// A file that cannot be understood is an error, not an empty registry: guessing would orphan
    /// namespaces the machine is still running.
    pub fn load(path: PathBuf, max_groups: usize) -> Result<Self, RegistryError> {
        let max_groups = max_groups.clamp(1, MAX_APP_GROUPS);
        let file = match std::fs::read(&path) {
            Ok(bytes) => {
                let decoded: RegistryFile =
                    serde_json::from_slice(&bytes).map_err(|error| RegistryError::Corrupt {
                        path: path.display().to_string(),
                        reason: error.to_string(),
                    })?;
                if decoded.version != REGISTRY_VERSION {
                    return Err(RegistryError::Corrupt {
                        path: path.display().to_string(),
                        reason: format!(
                            "version {} is not version {REGISTRY_VERSION}",
                            decoded.version
                        ),
                    });
                }
                decoded
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => RegistryFile::default(),
            Err(error) => {
                return Err(RegistryError::Io(format!(
                    "reading '{}': {error}",
                    path.display()
                )))
            }
        };
        Ok(Self {
            path,
            max_groups,
            file: Mutex::new(file),
        })
    }

    /// The file in use.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the bridge was ensured.
    pub fn bridge_ready(&self) -> bool {
        self.lock().bridge_ready
    }

    /// The ports the namespace rules name, if the bridge was ensured.
    pub fn ports(&self) -> Option<Ports> {
        self.lock().ports
    }

    /// Every record, in id order.
    pub fn records(&self) -> Vec<AppRecord> {
        let mut records = self.lock().records.clone();
        records.sort_by_key(|record| record.id);
        records
    }

    /// One record.
    pub fn get(&self, id: u32) -> Option<AppRecord> {
        self.lock()
            .records
            .iter()
            .find(|record| record.id == id)
            .cloned()
    }

    /// Record that the bridge exists and which ports the namespace rules use.
    pub fn mark_bridge(&self, ports: Ports) -> Result<(), RegistryError> {
        {
            let mut file = self.lock();
            file.bridge_ready = true;
            file.ports = Some(ports);
        }
        self.save()
    }

    /// Allocate the smallest free id and derive its address.
    pub fn allocate(
        &self,
        owner_uid: u32,
        core: Ipv4Addr,
        prefix: u8,
        now: i64,
    ) -> Result<AppRecord, RegistryError> {
        let id = {
            let file = self.lock();
            (1..=self.max_groups as u32)
                .find(|id| !file.records.iter().any(|record| record.id == *id))
                .ok_or(RegistryError::Full {
                    max: self.max_groups,
                })?
        };
        let address = address_for(core, prefix, id)?;
        let record = AppRecord {
            id,
            owner_uid,
            address,
            created_at: now,
            effective: None,
        };
        {
            let mut file = self.lock();
            file.records.push(record.clone());
        }
        self.save()?;
        Ok(record)
    }

    /// Remove a record. Returns whether it existed.
    pub fn remove(&self, id: u32) -> Result<bool, RegistryError> {
        let removed = {
            let mut file = self.lock();
            let before = file.records.len();
            file.records.retain(|record| record.id != id);
            before != file.records.len()
        };
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    /// Record the kernel's canonical report for a group.
    pub fn set_effective(&self, id: u32, effective: String) -> Result<(), RegistryError> {
        {
            let mut file = self.lock();
            if let Some(record) = file.records.iter_mut().find(|record| record.id == id) {
                record.effective = Some(effective);
            }
        }
        self.save()
    }

    /// Forget every group and the bridge. Used by `Revert`.
    pub fn clear(&self) -> Result<(), RegistryError> {
        {
            let mut file = self.lock();
            *file = RegistryFile::default();
        }
        self.save()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RegistryFile> {
        self.file
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn save(&self) -> Result<(), RegistryError> {
        let encoded = serde_json::to_vec_pretty(&*self.lock())
            .map_err(|error| RegistryError::Io(error.to_string()))?;
        let parent = self.path.parent().ok_or_else(|| {
            RegistryError::Io("the registry needs a parent directory".to_string())
        })?;
        std::fs::create_dir_all(parent).map_err(|error| RegistryError::Io(error.to_string()))?;
        let temporary = self.path.with_extension("json.tmp");
        std::fs::write(&temporary, &encoded)
            .map_err(|error| RegistryError::Io(error.to_string()))?;
        {
            let file = std::fs::File::open(&temporary)
                .map_err(|error| RegistryError::Io(error.to_string()))?;
            file.sync_all()
                .map_err(|error| RegistryError::Io(error.to_string()))?;
        }
        std::fs::rename(&temporary, &self.path)
            .map_err(|error| RegistryError::Io(error.to_string()))?;
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    }
}

/// Derive the address for a group: the core address plus the id, inside the configured prefix.
///
/// The core address is the first usable address of the block and the groups start one above it, so
/// the mapping is a function of the id and nothing else — there is no assignment to drift.
pub fn address_for(core: Ipv4Addr, prefix: u8, id: u32) -> Result<Ipv4Addr, RegistryError> {
    if id == 0 || id as usize > MAX_APP_GROUPS {
        return Err(RegistryError::Address {
            id,
            reason: format!("id must be between 1 and {MAX_APP_GROUPS}"),
        });
    }
    if !(8..=30).contains(&prefix) {
        return Err(RegistryError::Address {
            id,
            reason: "prefix must be between 8 and 30".to_string(),
        });
    }
    let network = u32::from(core) & (!0u32 << (32 - prefix));
    let address = network + id + 1;
    let broadcast = network | (u32::MAX >> prefix);
    if address >= broadcast {
        return Err(RegistryError::Address {
            id,
            reason: "the address would fall outside the APP block".to_string(),
        });
    }
    if address == u32::from(core) {
        return Err(RegistryError::Address {
            id,
            reason: "the address would collide with the core address".to_string(),
        });
    }
    Ok(Ipv4Addr::from(address))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CORE: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);

    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ghostnector-appd-registry-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        path
    }

    #[test]
    fn addresses_are_a_function_of_the_id() {
        assert_eq!(
            address_for(CORE, 24, 1).unwrap(),
            Ipv4Addr::new(10, 200, 0, 2)
        );
        assert_eq!(
            address_for(CORE, 24, 32).unwrap(),
            Ipv4Addr::new(10, 200, 0, 33)
        );
        for bad in [0, 33, 9999] {
            assert!(address_for(CORE, 24, bad).is_err(), "{bad}");
        }
        assert!(address_for(CORE, 24, 1).is_ok());
    }

    #[test]
    fn ids_are_allocated_smallest_first_and_reused() {
        let dir = directory();
        let registry = Registry::load(dir.join("registry.json"), 4).unwrap();
        let first = registry.allocate(1000, CORE, 24, 10).unwrap();
        let second = registry.allocate(1000, CORE, 24, 20).unwrap();
        assert_eq!(first.id, 1);
        assert_eq!(second.id, 2);
        assert_eq!(first.address, Ipv4Addr::new(10, 200, 0, 2));

        assert!(registry.remove(1).unwrap());
        let third = registry.allocate(1001, CORE, 24, 30).unwrap();
        assert_eq!(third.id, 1, "the smallest free id is reused");
        assert_eq!(third.owner_uid, 1001);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_registry_is_bounded() {
        let dir = directory();
        let registry = Registry::load(dir.join("registry.json"), 2).unwrap();
        registry.allocate(1000, CORE, 24, 1).unwrap();
        registry.allocate(1000, CORE, 24, 2).unwrap();
        let error = registry.allocate(1000, CORE, 24, 3).unwrap_err();
        assert_eq!(error, RegistryError::Full { max: 2 });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_file_survives_a_round_trip_and_leaves_no_temporary() {
        let dir = directory();
        let path = dir.join("registry.json");
        {
            let registry = Registry::load(path.clone(), 8).unwrap();
            registry.mark_bridge(Ports::default()).unwrap();
            registry.allocate(1000, CORE, 24, 7).unwrap();
        }
        let reloaded = Registry::load(path.clone(), 8).unwrap();
        assert!(reloaded.bridge_ready());
        assert_eq!(reloaded.ports(), Some(Ports::default()));
        assert_eq!(reloaded.records().len(), 1);
        assert_eq!(reloaded.records()[0].owner_uid, 1000);
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "a temporary file was left behind");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_or_future_registry_is_an_error() {
        let dir = directory();
        let path = dir.join("registry.json");
        std::fs::write(&path, b"not json").unwrap();
        assert!(matches!(
            Registry::load(path.clone(), 8),
            Err(RegistryError::Corrupt { .. })
        ));
        std::fs::write(
            &path,
            format!("{{\"version\":{},\"records\":[]}}", REGISTRY_VERSION + 1),
        )
        .unwrap();
        assert!(matches!(
            Registry::load(path.clone(), 8),
            Err(RegistryError::Corrupt { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clearing_forgets_everything() {
        let dir = directory();
        let registry = Registry::load(dir.join("registry.json"), 8).unwrap();
        registry.mark_bridge(Ports::default()).unwrap();
        registry.allocate(1000, CORE, 24, 1).unwrap();
        registry.clear().unwrap();
        assert!(!registry.bridge_ready());
        assert!(registry.records().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
