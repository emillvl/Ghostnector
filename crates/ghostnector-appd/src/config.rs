//! Command-line configuration for the namespace helper.
//!
//! Parsed strictly and by hand, like `netd`'s: every option takes exactly one value, unknown options
//! are fatal, and values are validated when they are read. The privileged process gets its
//! configuration from systemd, never from a peer, so the parser's job is to fail loudly on a typo —
//! not to be clever.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use ghostnector_spec::app;
use ghostnector_spec::app::valid_interface_name;

/// Default path of the policy tool.
pub const DEFAULT_NFT: &str = "/usr/sbin/nft";
/// Default path of the network configuration tool.
pub const DEFAULT_IP: &str = "/usr/sbin/ip";
/// Default path of the bridge control tool (port isolation).
pub const DEFAULT_BRIDGE_CTL: &str = "/usr/sbin/bridge";
/// Default path of the privilege-dropping launch helper.
pub const DEFAULT_LAUNCHER: &str = "/usr/libexec/ghostnector-appd-launch";
/// Default state directory: the registry and one directory per group.
pub const DEFAULT_STATE_DIR: &str = "/run/ghostnector/apps";

/// Validated configuration for the helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Unix socket to listen on. Its parent directory must already exist.
    pub socket: PathBuf,
    /// The only uid (besides root) permitted to talk to the helper.
    pub peer_uid: u32,
    /// Absolute path to `nft`.
    pub nft: PathBuf,
    /// Absolute path to `ip`.
    pub ip: PathBuf,
    /// Absolute path to `bridge` (used only for port isolation).
    pub bridge_ctl: PathBuf,
    /// Absolute path to the privilege-dropping launch helper.
    pub launcher: PathBuf,
    /// Where the registry and per-group files live.
    pub state_dir: PathBuf,
    /// The bridge carrying app links.
    pub bridge: String,
    /// The host-local core address.
    pub core: Ipv4Addr,
    /// Prefix length of the APP address space (used to place app addresses).
    pub prefix: u8,
    /// The dead-end device every namespace's default route points at.
    pub dead_device: String,
    /// The most groups this helper will create.
    pub max_groups: usize,
}

/// What the command line asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// Run with this configuration.
    Run(Box<Config>),
    /// Print usage and exit successfully.
    Help,
    /// Print the version and exit successfully.
    Version,
}

/// Why a command line was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// An option was given without a value.
    #[error("option '{0}' needs a value")]
    MissingValue(String),
    /// An option was not recognised.
    #[error("unknown option '{0}'")]
    Unknown(String),
    /// A required option was absent.
    #[error("option '{0}' is required")]
    Missing(&'static str),
    /// A value could not be used, with a reason.
    #[error("value for '{option}' is not usable: {reason}")]
    Invalid {
        /// The option that was rejected.
        option: String,
        /// Why it was rejected.
        reason: String,
    },
}

impl Config {
    /// Usage text.
    pub const USAGE: &'static str = "\
ghostnector-appd - create and verify dead-end APP namespaces (privileged)

USAGE:
    ghostnector-appd --socket <PATH> --peer-uid <UID> [OPTIONS]

REQUIRED:
    --socket <PATH>        unix socket to listen on (parent directory must exist)
    one of:
      --peer-user <NAME>   the user allowed to talk to this helper
      --peer-uid <UID>     the same, as a number (not root)

OPTIONS:
    --nft <PATH>           policy tool                [default: /usr/sbin/nft]
    --ip <PATH>            network tool               [default: /usr/sbin/ip]
    --bridge-ctl <PATH>    bridge control tool        [default: /usr/sbin/bridge]
    --launcher <PATH>      privilege-drop helper     [default: /usr/libexec/ghostnector-appd-launch]
    --state-dir <PATH>     registry and per-group files
                                           [default: /run/ghostnector/apps]
    --bridge <NAME>        bridge carrying app links  [default: ghbr0]
    --core <ADDR>          host-local core address    [default: 10.200.0.1]
    --prefix <LEN>         APP address-space prefix   [default: 24]
    --dead-device <NAME>   dead-end device in each namespace
                                           [default: ghdead]
    --max-groups <N>       most groups to create      [default: 32]
    -h, --help             print this text
    -V, --version          print the version";

    /// Parse arguments, excluding the program name.
    pub fn parse<I>(args: I) -> Result<Parsed, ConfigError>
    where
        I: IntoIterator<Item = String>,
    {
        let mut socket: Option<PathBuf> = None;
        let mut peer_uid: Option<u32> = None;
        let mut nft = PathBuf::from(DEFAULT_NFT);
        let mut ip = PathBuf::from(DEFAULT_IP);
        let mut bridge_ctl = PathBuf::from(DEFAULT_BRIDGE_CTL);
        let mut launcher = PathBuf::from(DEFAULT_LAUNCHER);
        let mut state_dir = PathBuf::from(DEFAULT_STATE_DIR);
        let mut bridge = app::DEFAULT_APP_BRIDGE.to_string();
        let mut core = app::DEFAULT_APP_CORE_ADDRESS;
        let mut prefix = app::DEFAULT_APP_PREFIX;
        let mut dead_device = app::DEFAULT_APP_DEAD_DEVICE.to_string();
        let mut max_groups = app::MAX_APP_GROUPS;

        let mut arguments = args.into_iter().peekable();
        while let Some(option) = arguments.next() {
            match option.as_str() {
                "-h" | "--help" => return Ok(Parsed::Help),
                "-V" | "--version" => return Ok(Parsed::Version),
                _ => {}
            }

            let mut value = || -> Result<String, ConfigError> {
                arguments
                    .next()
                    .ok_or_else(|| ConfigError::MissingValue(option.clone()))
            };

            match option.as_str() {
                "--socket" => socket = Some(absolute(&option, &value()?)?),
                "--nft" => nft = absolute(&option, &value()?)?,
                "--ip" => ip = absolute(&option, &value()?)?,
                "--bridge-ctl" => bridge_ctl = absolute(&option, &value()?)?,
                "--launcher" => launcher = absolute(&option, &value()?)?,
                "--state-dir" => state_dir = absolute(&option, &value()?)?,
                "--peer-uid" => {
                    let raw = value()?;
                    let uid: u32 = raw.parse().map_err(|_| ConfigError::Invalid {
                        option: option.clone(),
                        reason: "expected a numeric uid".to_string(),
                    })?;
                    if uid == 0 {
                        return Err(ConfigError::Invalid {
                            option: option.clone(),
                            reason: "the peer must not be root; run core as a system user"
                                .to_string(),
                        });
                    }
                    peer_uid = Some(uid);
                }
                "--peer-user" => {
                    let name = value()?;
                    if name.is_empty()
                        || name.len() > 32
                        || !name
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
                    {
                        return Err(ConfigError::Invalid {
                            option: option.clone(),
                            reason: "expected a user name of up to 32 characters".to_string(),
                        });
                    }
                    let user = nix::unistd::User::from_name(&name)
                        .map_err(|error| ConfigError::Invalid {
                            option: option.clone(),
                            reason: format!("cannot look up '{name}': {error}"),
                        })?
                        .ok_or_else(|| ConfigError::Invalid {
                            option: option.clone(),
                            reason: format!("there is no user called '{name}'"),
                        })?;
                    if user.uid.as_raw() == 0 {
                        return Err(ConfigError::Invalid {
                            option: option.clone(),
                            reason: "the peer must not be root".to_string(),
                        });
                    }
                    peer_uid = Some(user.uid.as_raw());
                }
                "--bridge" => {
                    let name = value()?;
                    if !valid_interface_name(&name) {
                        return Err(ConfigError::Invalid {
                            option: option.clone(),
                            reason: "expected an interface name of up to 15 characters".to_string(),
                        });
                    }
                    bridge = name;
                }
                "--dead-device" => {
                    let name = value()?;
                    if !valid_interface_name(&name) {
                        return Err(ConfigError::Invalid {
                            option: option.clone(),
                            reason: "expected an interface name of up to 15 characters".to_string(),
                        });
                    }
                    dead_device = name;
                }
                "--core" => {
                    let raw = value()?;
                    let address: Ipv4Addr = raw.parse().map_err(|_| ConfigError::Invalid {
                        option: option.clone(),
                        reason: "expected an IPv4 address".to_string(),
                    })?;
                    if !address.is_private() {
                        return Err(ConfigError::Invalid {
                            option: option.clone(),
                            reason: "the APP core address must be a private (non-routable) address"
                                .to_string(),
                        });
                    }
                    core = address;
                }
                "--prefix" => {
                    let raw = value()?;
                    let parsed: u8 = raw.parse().map_err(|_| ConfigError::Invalid {
                        option: option.clone(),
                        reason: "expected a prefix length between 8 and 30".to_string(),
                    })?;
                    if !(8..=30).contains(&parsed) {
                        return Err(ConfigError::Invalid {
                            option: option.clone(),
                            reason: "expected a prefix length between 8 and 30".to_string(),
                        });
                    }
                    prefix = parsed;
                }
                "--max-groups" => {
                    let raw = value()?;
                    let parsed: usize = raw.parse().map_err(|_| ConfigError::Invalid {
                        option: option.clone(),
                        reason: format!("expected a number between 1 and {}", app::MAX_APP_GROUPS),
                    })?;
                    if parsed == 0 || parsed > app::MAX_APP_GROUPS {
                        return Err(ConfigError::Invalid {
                            option: option.clone(),
                            reason: format!(
                                "expected a number between 1 and {}",
                                app::MAX_APP_GROUPS
                            ),
                        });
                    }
                    max_groups = parsed;
                }
                other => return Err(ConfigError::Unknown(other.to_string())),
            }
        }

        let socket = socket.ok_or(ConfigError::Missing("--socket"))?;
        let peer_uid = peer_uid.ok_or(ConfigError::Missing("--peer-uid or --peer-user"))?;

        Ok(Parsed::Run(Box::new(Config {
            socket,
            peer_uid,
            nft,
            ip,
            bridge_ctl,
            launcher,
            state_dir,
            bridge,
            core,
            prefix,
            dead_device,
            max_groups,
        })))
    }

    /// A one-line description for the log.
    pub fn summary(&self) -> String {
        format!(
            "socket={} peer_uid={} bridge={} core={}/{} groups<={}",
            self.socket.display(),
            self.peer_uid,
            self.bridge,
            self.core,
            self.prefix,
            self.max_groups
        )
    }
}

fn absolute(option: &str, raw: &str) -> Result<PathBuf, ConfigError> {
    if !raw.starts_with('/') {
        return Err(ConfigError::Invalid {
            option: option.to_string(),
            reason: "expected an absolute path".to_string(),
        });
    }
    Ok(PathBuf::from(raw))
}

/// The version line.
pub fn version_line() -> String {
    format!("ghostnector-appd {}", crate::VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn run(list: &[&str]) -> Config {
        match Config::parse(args(list)).expect("should parse") {
            Parsed::Run(config) => *config,
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn minimal_configuration_uses_the_shared_defaults() {
        let config = run(&[
            "--socket",
            "/run/ghostnector/appd.sock",
            "--peer-uid",
            "1000",
        ]);
        assert_eq!(config.peer_uid, 1000);
        assert_eq!(config.bridge, "ghbr0");
        assert_eq!(config.core, Ipv4Addr::new(10, 200, 0, 1));
        assert_eq!(config.prefix, 24);
        assert_eq!(config.dead_device, "ghdead");
        assert_eq!(config.max_groups, 32);
        assert_eq!(config.nft, PathBuf::from("/usr/sbin/nft"));
        assert_eq!(
            config.launcher,
            PathBuf::from("/usr/libexec/ghostnector-appd-launch")
        );
    }

    #[test]
    fn help_and_version_short_circuit() {
        assert_eq!(Config::parse(args(&["--help"])).unwrap(), Parsed::Help);
        assert_eq!(Config::parse(args(&["-V"])).unwrap(), Parsed::Version);
    }

    #[test]
    fn required_options_are_required() {
        assert_eq!(
            Config::parse(args(&["--peer-uid", "1000"])).unwrap_err(),
            ConfigError::Missing("--socket")
        );
        assert_eq!(
            Config::parse(args(&["--socket", "/run/x.sock"])).unwrap_err(),
            ConfigError::Missing("--peer-uid or --peer-user")
        );
    }

    #[test]
    fn every_path_and_name_is_validated() {
        for bad in ["", "with space", "with/slash", "waytoolongwaytoolong"] {
            let error = Config::parse(args(&[
                "--socket",
                "/run/x.sock",
                "--peer-uid",
                "1",
                "--bridge",
                bad,
            ]))
            .unwrap_err();
            assert!(matches!(error, ConfigError::Invalid { .. }), "{bad}");
        }
        let error =
            Config::parse(args(&["--socket", "relative.sock", "--peer-uid", "1"])).unwrap_err();
        assert!(matches!(error, ConfigError::Invalid { .. }));
        let error = Config::parse(args(&[
            "--socket",
            "/run/x.sock",
            "--peer-uid",
            "1",
            "--core",
            "198.51.100.1",
        ]))
        .unwrap_err();
        assert!(matches!(error, ConfigError::Invalid { .. }));
        for bad in ["7", "31", "0", "wide"] {
            let error = Config::parse(args(&[
                "--socket",
                "/run/x.sock",
                "--peer-uid",
                "1",
                "--prefix",
                bad,
            ]))
            .unwrap_err();
            assert!(matches!(error, ConfigError::Invalid { .. }), "{bad}");
        }
        for bad in ["0", "33", "many"] {
            let error = Config::parse(args(&[
                "--socket",
                "/run/x.sock",
                "--peer-uid",
                "1",
                "--max-groups",
                bad,
            ]))
            .unwrap_err();
            assert!(matches!(error, ConfigError::Invalid { .. }), "{bad}");
        }
    }

    #[test]
    fn root_is_not_an_acceptable_peer_and_unknown_options_are_fatal() {
        let error =
            Config::parse(args(&["--socket", "/run/x.sock", "--peer-uid", "0"])).unwrap_err();
        assert!(matches!(error, ConfigError::Invalid { .. }));
        let error = Config::parse(args(&[
            "--socket",
            "/run/x.sock",
            "--peer-uid",
            "1",
            "--turbo",
        ]))
        .unwrap_err();
        assert_eq!(error, ConfigError::Unknown("--turbo".to_string()));
    }

    #[test]
    fn the_summary_names_the_object_identity() {
        let summary = run(&[
            "--socket",
            "/run/ghostnector/appd.sock",
            "--peer-uid",
            "1000",
        ])
        .summary();
        assert!(summary.contains("peer_uid=1000"));
        assert!(summary.contains("bridge=ghbr0"));
        assert!(summary.contains("core=10.200.0.1/24"));
    }
}
