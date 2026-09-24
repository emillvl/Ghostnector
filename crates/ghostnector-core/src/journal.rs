//! Persisted intent.
//!
//! The journal records *what the user asked for*, not what is installed. The kernel is the truth
//! about what is installed, and `netd` is the truth about what it applied; this file only has to
//! survive a restart well enough to answer one question: **did the user want protection when the
//! machine stopped?** If yes and nothing is applied, the machine must fail closed rather than
//! silently return to the clearnet (DR-16).
//!
//! Writes are atomic: a temporary file in the same directory, fsynced, renamed over the target, and
//! the directory fsynced. A crash mid-write therefore leaves either the old intent or the new one,
//! never a truncated file.

use std::fs;
use std::path::{Path, PathBuf};

use ghostnector_spec::backend::{Params, ProfileId};
use serde::{Deserialize, Serialize};

/// The journal format this build understands.
pub const INTENT_VERSION: u32 = 1;

/// What the user last asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Intent {
    /// Format version. A file from the future is refused rather than guessed at.
    pub version: u32,
    /// Whether protection was requested.
    pub protected: bool,
    /// The profile that was requested, when one was.
    pub profile: Option<ProfileId>,
    /// The parameters it was requested with.
    pub params: Option<Params>,
    /// When it was recorded.
    pub recorded_at: Option<i64>,
    /// The state generation at the time, for diagnostics.
    pub generation: u64,
}

impl Default for Intent {
    fn default() -> Self {
        Self {
            version: INTENT_VERSION,
            protected: false,
            profile: None,
            params: None,
            recorded_at: None,
            generation: 0,
        }
    }
}

impl Intent {
    /// Intent for a requested profile.
    pub fn requested(profile: ProfileId, params: Params, at: i64, generation: u64) -> Self {
        Self {
            version: INTENT_VERSION,
            protected: true,
            profile: Some(profile),
            params: Some(params),
            recorded_at: Some(at),
            generation,
        }
    }

    /// Intent for no protection at all.
    pub fn off(at: i64, generation: u64) -> Self {
        Self {
            version: INTENT_VERSION,
            protected: false,
            profile: None,
            params: None,
            recorded_at: Some(at),
            generation,
        }
    }
}

/// Why the journal could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// The file could not be read or written.
    #[error("journal '{}' could not be used: {reason}", path.display())]
    Io {
        /// The path involved.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },
    /// The file exists but is not valid.
    #[error("journal '{}' is not valid: {reason}", path.display())]
    Corrupt {
        /// The path involved.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },
    /// The file was written by a newer Ghostnector.
    #[error("journal '{}' has version {found}, which this build does not understand", path.display())]
    UnsupportedVersion {
        /// The path involved.
        path: PathBuf,
        /// The version found.
        found: u32,
    },
}

/// The intent file.
#[derive(Debug, Clone)]
pub struct Journal {
    path: PathBuf,
}

impl Journal {
    /// A journal at this path. Nothing is created until something is written.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The path in use.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read the intent, or a default "no protection requested" when there is no file.
    pub fn load(&self) -> Result<Intent, JournalError> {
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Intent::default())
            }
            Err(error) => {
                return Err(JournalError::Io {
                    path: self.path.clone(),
                    reason: error.to_string(),
                })
            }
        };

        let intent: Intent =
            serde_json::from_str(&text).map_err(|error| JournalError::Corrupt {
                path: self.path.clone(),
                reason: error.to_string(),
            })?;

        if intent.version > INTENT_VERSION {
            return Err(JournalError::UnsupportedVersion {
                path: self.path.clone(),
                found: intent.version,
            });
        }
        Ok(intent)
    }

    /// Write the intent atomically.
    pub fn save(&self, intent: &Intent) -> Result<(), JournalError> {
        let mut encoded =
            serde_json::to_vec_pretty(intent).map_err(|error| JournalError::Corrupt {
                path: self.path.clone(),
                reason: error.to_string(),
            })?;
        encoded.push(b'\n');

        crate::fsutil::write_atomic(&self.path, &encoded).map_err(|error| JournalError::Io {
            path: self.path.clone(),
            reason: error.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "ghostnector-journal-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }

        fn journal(&self) -> Journal {
            Journal::new(self.0.join("state.json"))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_missing_journal_means_no_protection_was_requested() {
        let dir = TempDir::new();
        let intent = dir.journal().load().expect("load");
        assert_eq!(intent, Intent::default());
        assert!(!intent.protected);
        assert_eq!(intent.profile, None);
    }

    #[test]
    fn intent_survives_a_round_trip() {
        let dir = TempDir::new();
        let journal = dir.journal();
        let written = Intent::requested(
            ProfileId::TorSystem,
            Params {
                allow_lan: true,
                ..Params::default()
            },
            1_700_000_000,
            7,
        );
        journal.save(&written).expect("save");
        assert_eq!(journal.load().expect("load"), written);
    }

    #[test]
    fn turning_protection_off_is_recorded_as_such() {
        let dir = TempDir::new();
        let journal = dir.journal();
        journal
            .save(&Intent::requested(
                ProfileId::TorUser,
                Params::default(),
                1,
                1,
            ))
            .expect("save");
        journal.save(&Intent::off(2, 2)).expect("save");
        let intent = journal.load().expect("load");
        assert!(!intent.protected);
        assert_eq!(intent.profile, None);
        assert_eq!(intent.recorded_at, Some(2));
    }

    #[test]
    fn no_temporary_file_is_left_behind() {
        let dir = TempDir::new();
        let journal = dir.journal();
        journal.save(&Intent::off(1, 1)).expect("save");
        let leftovers: Vec<_> = fs::read_dir(&dir.0)
            .expect("read dir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
    }

    #[test]
    fn a_corrupt_journal_is_an_error_not_a_default() {
        let dir = TempDir::new();
        let journal = dir.journal();
        fs::write(journal.path(), b"{ this is not json").expect("write");
        let error = journal.load().unwrap_err();
        assert!(matches!(error, JournalError::Corrupt { .. }));
    }

    #[test]
    fn a_journal_from_the_future_is_refused_rather_than_guessed_at() {
        let dir = TempDir::new();
        let journal = dir.journal();
        let text = format!("{{\"version\":{},\"protected\":true}}", INTENT_VERSION + 1);
        fs::write(journal.path(), text).expect("write");
        let error = journal.load().unwrap_err();
        assert!(matches!(
            error,
            JournalError::UnsupportedVersion { found, .. } if found == INTENT_VERSION + 1
        ));
    }

    #[test]
    fn a_truncated_file_is_reported_rather_than_read_as_defaults() {
        let dir = TempDir::new();
        let journal = dir.journal();
        fs::write(journal.path(), b"{\"version\":1,\"prot").expect("write");
        assert!(matches!(
            journal.load().unwrap_err(),
            JournalError::Corrupt { .. }
        ));
    }
}
