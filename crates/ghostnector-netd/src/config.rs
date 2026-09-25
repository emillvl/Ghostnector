//! Command-line configuration.
//!
//! Parsed strictly and by hand: every option takes exactly one value, unknown options are fatal, and
//! values are validated when they are read rather than when they are used. The privileged process
//! gets its configuration from systemd, never from a user, so this parser's job is to fail loudly on
//! a typo — not to be clever.

use std::path::PathBuf;

use crate::VERSION;

/// Default location of the `nft` binary. It is verified at startup: absolute, root-owned, and not
/// writable by anyone else.
pub const DEFAULT_NFT: &str = "/usr/sbin/nft";

/// Default location of the `conntrack` binary. Optional: a missing one is a note, not a failure
/// (the default-deny policy is what stops pre-existing flows, not the flush).
pub const DEFAULT_CONNTRACK: &str = "/usr/sbin/conntrack";

/// Where a copy of the fail-closed policy is kept, so the boot guard can apply it when this helper
/// is not available. It is this helper's own rendered output, written by root and readable only by
/// root.
pub const DEFAULT_FALLBACK: &str = "/var/lib/ghostnector/fail-closed.nft";

/// Default system user Tor runs as on Debian and Ubuntu.
pub const DEFAULT_TOR_USER: &str = "debian-tor";

/// Default system user the encrypted-DNS resolver runs as.
pub const DEFAULT_DNSCRYPT_USER: &str = "dnscrypt-proxy";

/// Default system user the I2P router runs as on Debian and Ubuntu.
pub const DEFAULT_I2P_USER: &str = "i2pd";

/// Default port Tor's transparent proxy listens on.
pub const DEFAULT_TRANS_PORT: u16 = 9040;

/// Default port the DNS chokepoint listens on.
///
/// The single source of truth lives in the shared vocabulary: the resolver configuration can only
/// name an address, so a `nameserver` line means port 53, and the relay must listen exactly there
/// (D-22). This is an alias, not a second copy.
pub const DEFAULT_CHOKEPOINT_PORT: u16 = ghostnector_spec::backend::DEFAULT_CHOKEPOINT_PORT;

/// Default port Tor's SOCKS proxy listens on.
pub const DEFAULT_SOCKS_PORT: u16 = 9050;

/// Default port I2P's HTTP proxy listens on. The single source of truth is the shared vocabulary.
pub const DEFAULT_I2P_HTTP_PORT: u16 = ghostnector_spec::backend::DEFAULT_I2P_HTTP_PORT;

/// Default port I2P's SOCKS proxy listens on. The single source of truth is the shared vocabulary.
pub const DEFAULT_I2P_SOCKS_PORT: u16 = ghostnector_spec::backend::DEFAULT_I2P_SOCKS_PORT;

/// Default source port of the DHCP client.
pub const DEFAULT_DHCP_CLIENT_PORT: u16 = 68;

/// Default bridge carrying APP links. The single source of truth lives in the shared vocabulary.
pub const DEFAULT_APP_BRIDGE: &str = ghostnector_spec::app::DEFAULT_APP_BRIDGE;

/// Default host-local APP core address.
pub const DEFAULT_APP_CORE: std::net::Ipv4Addr = ghostnector_spec::app::DEFAULT_APP_CORE_ADDRESS;

/// Validated configuration for the helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Unix socket to listen on. Its parent directory must already exist (systemd's
    /// `RuntimeDirectory=` provides it on a real system).
    pub socket: PathBuf,
    /// The only uid permitted to talk to the helper. Must not be root.
    pub peer_uid: u32,
    /// Absolute path to `nft`.
    pub nft: PathBuf,
    /// Absolute path to `conntrack`.
    pub conntrack: PathBuf,
    /// Where to keep a copy of the fail-closed policy for the boot guard.
    pub fallback_path: PathBuf,
    /// System user Tor runs as.
    pub tor_user: String,
    /// System user the resolver runs as.
    pub dnscrypt_user: String,
    /// System user the I2P router runs as.
    pub i2p_user: String,
    /// Tor's transparent proxy port.
    pub trans_port: u16,
    /// The DNS chokepoint port.
    pub chokepoint_port: u16,
    /// Tor's SOCKS port.
    pub socks_port: u16,
    /// I2P's HTTP proxy port.
    pub i2p_http_port: u16,
    /// I2P's SOCKS proxy port.
    pub i2p_socks_port: u16,
    /// DHCP client source port.
    pub dhcp_client_port: u16,
    /// The bridge carrying APP links on the host side.
    pub app_bridge: String,
    /// The host-local address an APP namespace DNATs to.
    pub app_core: std::net::Ipv4Addr,
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
    /// Usage text, printed for `--help` and on configuration errors.
    pub const USAGE: &'static str = "\
ghostnector-netd - apply Ghostnector's network policy (privileged)

USAGE:
    ghostnector-netd --socket <PATH> --peer-uid <UID> [OPTIONS]

REQUIRED:
    --socket <PATH>        unix socket to listen on (parent directory must exist)
    one of:
      --peer-user <NAME>   the user allowed to talk to this helper
      --peer-uid <UID>     the same, as a number (not root)

OPTIONS:
    --nft <PATH>           policy tool                 [default: /usr/sbin/nft]
    --conntrack <PATH>     conntrack tool              [default: /usr/sbin/conntrack]
    --fallback-path <PATH> where to keep a copy of the fail-closed policy, for the
                           boot guard to apply if this helper is unavailable
                                       [default: /var/lib/ghostnector/fail-closed.nft]
    --tor-user <NAME>      system user Tor runs as     [default: debian-tor]
    --dnscrypt-user <NAME> system user the resolver runs as
                                                      [default: dnscrypt-proxy]
    --i2p-user <NAME>      system user the I2P router runs as
                                                      [default: i2pd]
    --trans-port <PORT>    Tor transparent proxy port  [default: 9040]
    --chokepoint-port <PORT>  DNS chokepoint port      [default: 53]
                              (must be the port a nameserver line implies)
    --socks-port <PORT>    Tor SOCKS port              [default: 9050]
    --i2p-http-port <PORT> I2P HTTP proxy port         [default: 4444]
    --i2p-socks-port <PORT>  I2P SOCKS proxy port      [default: 4447]
    --dhcp-client-port <PORT> DHCP client source port  [default: 68]
    --app-bridge <NAME>    bridge carrying APP links   [default: ghbr0]
    --app-core <ADDR>      host-local APP core address [default: 10.200.0.1]
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
        let mut conntrack = PathBuf::from(DEFAULT_CONNTRACK);
        let mut fallback_path = PathBuf::from(DEFAULT_FALLBACK);
        let mut tor_user = DEFAULT_TOR_USER.to_string();
        let mut dnscrypt_user = DEFAULT_DNSCRYPT_USER.to_string();
        let mut i2p_user = DEFAULT_I2P_USER.to_string();
        let mut trans_port = DEFAULT_TRANS_PORT;
        let mut chokepoint_port = DEFAULT_CHOKEPOINT_PORT;
        let mut socks_port = DEFAULT_SOCKS_PORT;
        let mut i2p_http_port = DEFAULT_I2P_HTTP_PORT;
        let mut i2p_socks_port = DEFAULT_I2P_SOCKS_PORT;
        let mut dhcp_client_port = DEFAULT_DHCP_CLIENT_PORT;
        let mut app_bridge = DEFAULT_APP_BRIDGE.to_string();
        let mut app_core = DEFAULT_APP_CORE;

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
                "--socket" => socket = Some(path(&option, &value()?)?),
                "--nft" => nft = path(&option, &value()?)?,
                "--conntrack" => conntrack = path(&option, &value()?)?,
                "--fallback-path" => fallback_path = path(&option, &value()?)?,
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
                    // A unit file cannot resolve a uid, so it names the user and this resolves it
                    // against the live database: a renamed or renumbered account cannot silently
                    // widen or break the policy.
                    let name = user_name(&option, &value()?)?;
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
                "--tor-user" => tor_user = user_name(&option, &value()?)?,
                "--dnscrypt-user" => dnscrypt_user = user_name(&option, &value()?)?,
                "--i2p-user" => i2p_user = user_name(&option, &value()?)?,
                "--trans-port" => trans_port = port(&option, &value()?)?,
                "--chokepoint-port" => chokepoint_port = port(&option, &value()?)?,
                "--socks-port" => socks_port = port(&option, &value()?)?,
                "--i2p-http-port" => i2p_http_port = port(&option, &value()?)?,
                "--i2p-socks-port" => i2p_socks_port = port(&option, &value()?)?,
                "--dhcp-client-port" => dhcp_client_port = port(&option, &value()?)?,
                "--app-bridge" => {
                    let name = value()?;
                    if !ghostnector_spec::app::valid_interface_name(&name) {
                        return Err(ConfigError::Invalid {
                            option: option.clone(),
                            reason: "expected an interface name of up to 15 characters".to_string(),
                        });
                    }
                    app_bridge = name;
                }
                "--app-core" => {
                    let raw = value()?;
                    let address: std::net::Ipv4Addr =
                        raw.parse().map_err(|_| ConfigError::Invalid {
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
                    app_core = address;
                }
                other => return Err(ConfigError::Unknown(other.to_string())),
            }
        }

        let socket = socket.ok_or(ConfigError::Missing("--socket"))?;
        let peer_uid = peer_uid.ok_or(ConfigError::Missing("--peer-uid or --peer-user"))?;

        // Redirect targets and proxy ports must be distinct, or one listener would shadow another.
        let mut ports = [
            ("--trans-port", trans_port),
            ("--chokepoint-port", chokepoint_port),
            ("--socks-port", socks_port),
            ("--i2p-http-port", i2p_http_port),
            ("--i2p-socks-port", i2p_socks_port),
        ];
        ports.sort_by_key(|(_, port)| *port);
        for pair in ports.windows(2) {
            if pair[0].1 == pair[1].1 {
                return Err(ConfigError::Invalid {
                    option: pair[1].0.to_string(),
                    reason: format!("port {} is already used by {}", pair[1].1, pair[0].0),
                });
            }
        }

        Ok(Parsed::Run(Box::new(Config {
            socket,
            peer_uid,
            nft,
            conntrack,
            fallback_path,
            tor_user,
            dnscrypt_user,
            i2p_user,
            trans_port,
            chokepoint_port,
            socks_port,
            i2p_http_port,
            i2p_socks_port,
            dhcp_client_port,
            app_bridge,
            app_core,
        })))
    }

    /// A one-line description for the log, containing no paths a listener could not already see.
    pub fn summary(&self) -> String {
        format!(
            "socket={} peer_uid={} tor_user={} dnscrypt_user={} i2p_user={} \
             ports=trans:{}/dns:{}/socks:{} i2p:{}/{} app={}/{}",
            self.socket.display(),
            self.peer_uid,
            self.tor_user,
            self.dnscrypt_user,
            self.i2p_user,
            self.trans_port,
            self.chokepoint_port,
            self.socks_port,
            self.i2p_http_port,
            self.i2p_socks_port,
            self.app_bridge,
            self.app_core,
        )
    }
}

fn path(option: &str, raw: &str) -> Result<PathBuf, ConfigError> {
    if !raw.starts_with('/') {
        return Err(ConfigError::Invalid {
            option: option.to_string(),
            reason: "expected an absolute path".to_string(),
        });
    }
    Ok(PathBuf::from(raw))
}

fn port(option: &str, raw: &str) -> Result<u16, ConfigError> {
    let port: u16 = raw.parse().map_err(|_| ConfigError::Invalid {
        option: option.to_string(),
        reason: "expected a port between 1 and 65535".to_string(),
    })?;
    if port == 0 {
        return Err(ConfigError::Invalid {
            option: option.to_string(),
            reason: "port 0 is not usable".to_string(),
        });
    }
    Ok(port)
}

/// User names end up as a lookup key, so keep them to what a user name can be.
fn user_name(option: &str, raw: &str) -> Result<String, ConfigError> {
    let acceptable = !raw.is_empty()
        && raw.len() <= 32
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.');
    if !acceptable {
        return Err(ConfigError::Invalid {
            option: option.to_string(),
            reason: "expected a user name of up to 32 characters".to_string(),
        });
    }
    Ok(raw.to_string())
}

/// The version string, for `--version`.
pub fn version_line() -> String {
    format!("ghostnector-netd {VERSION}")
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
    fn minimal_configuration_uses_documented_defaults() {
        let config = run(&[
            "--socket",
            "/run/ghostnector/netd.sock",
            "--peer-uid",
            "1000",
        ]);
        assert_eq!(config.peer_uid, 1000);
        assert_eq!(config.nft, PathBuf::from("/usr/sbin/nft"));
        assert_eq!(config.tor_user, "debian-tor");
        assert_eq!(config.trans_port, 9040);
        assert_eq!(config.chokepoint_port, 53);
        assert_eq!(config.socks_port, 9050);
        assert_eq!(config.i2p_user, "i2pd");
        assert_eq!(config.i2p_http_port, 4444);
        assert_eq!(config.i2p_socks_port, 4447);
        assert_eq!(config.dhcp_client_port, 68);
        assert_eq!(config.app_bridge, "ghbr0");
        assert_eq!(config.app_core, std::net::Ipv4Addr::new(10, 200, 0, 1));
    }

    #[test]
    fn full_configuration_is_accepted() {
        let config = run(&[
            "--socket",
            "/run/x/netd.sock",
            "--peer-uid",
            "65534",
            "--nft",
            "/usr/bin/nft",
            "--conntrack",
            "/usr/bin/conntrack",
            "--tor-user",
            "tor",
            "--dnscrypt-user",
            "dns",
            "--i2p-user",
            "i2pd",
            "--trans-port",
            "19040",
            "--chokepoint-port",
            "19054",
            "--socks-port",
            "19050",
            "--i2p-http-port",
            "14444",
            "--i2p-socks-port",
            "14447",
            "--dhcp-client-port",
            "68",
        ]);
        assert_eq!(config.tor_user, "tor");
        assert_eq!(config.dnscrypt_user, "dns");
        assert_eq!(config.i2p_user, "i2pd");
        assert_eq!(config.trans_port, 19040);
        assert_eq!(config.i2p_http_port, 14444);
        assert_eq!(config.i2p_socks_port, 14447);
    }

    #[test]
    fn help_and_version_short_circuit() {
        assert_eq!(Config::parse(args(&["--help"])).unwrap(), Parsed::Help);
        assert_eq!(Config::parse(args(&["-h"])).unwrap(), Parsed::Help);
        assert_eq!(
            Config::parse(args(&["--version"])).unwrap(),
            Parsed::Version
        );
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
    fn a_peer_can_be_named_by_user() {
        // A user that must exist on any machine, and one that must not.
        let config = run(&["--socket", "/run/x.sock", "--peer-user", "nobody"]);
        let nobody = nix::unistd::User::from_name("nobody")
            .expect("lookup")
            .expect("nobody exists");
        assert_eq!(config.peer_uid, nobody.uid.as_raw());

        let error = Config::parse(args(&[
            "--socket",
            "/run/x.sock",
            "--peer-user",
            "no-such-user-4f2a",
        ]))
        .unwrap_err();
        assert!(matches!(error, ConfigError::Invalid { .. }), "{error}");
    }

    #[test]
    fn unknown_options_are_fatal_rather_than_ignored() {
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
    fn an_option_without_a_value_is_rejected() {
        let error = Config::parse(args(&["--socket"])).unwrap_err();
        assert_eq!(error, ConfigError::MissingValue("--socket".to_string()));
    }

    #[test]
    fn root_is_not_an_acceptable_peer() {
        let error =
            Config::parse(args(&["--socket", "/run/x.sock", "--peer-uid", "0"])).unwrap_err();
        assert!(matches!(error, ConfigError::Invalid { .. }));
    }

    #[test]
    fn paths_must_be_absolute() {
        let error =
            Config::parse(args(&["--socket", "run/x.sock", "--peer-uid", "1"])).unwrap_err();
        assert!(matches!(error, ConfigError::Invalid { .. }));
        let error = Config::parse(args(&[
            "--socket",
            "/run/x.sock",
            "--peer-uid",
            "1",
            "--nft",
            "nft",
        ]))
        .unwrap_err();
        assert!(matches!(error, ConfigError::Invalid { .. }));
    }

    #[test]
    fn ports_are_validated_and_must_be_distinct() {
        for bad in ["0", "70000", "eighty"] {
            let error = Config::parse(args(&[
                "--socket",
                "/run/x.sock",
                "--peer-uid",
                "1",
                "--trans-port",
                bad,
            ]))
            .unwrap_err();
            assert!(matches!(error, ConfigError::Invalid { .. }), "{bad}");
        }

        let error = Config::parse(args(&[
            "--socket",
            "/run/x.sock",
            "--peer-uid",
            "1",
            "--trans-port",
            "53",
        ]))
        .unwrap_err();
        assert!(
            matches!(error, ConfigError::Invalid { .. }),
            "trans-port colliding with the chokepoint port must be refused"
        );

        let error = Config::parse(args(&[
            "--socket",
            "/run/x.sock",
            "--peer-uid",
            "1",
            "--i2p-http-port",
            "9050",
        ]))
        .unwrap_err();
        assert!(
            matches!(error, ConfigError::Invalid { .. }),
            "an I2P proxy port colliding with a Tor port must be refused"
        );
    }

    #[test]
    fn user_names_are_restrained() {
        for bad in [
            "",
            "with space",
            "with/slash",
            "waytoolongwaytoolongwaytoolongwaytoolong",
        ] {
            let error = Config::parse(args(&[
                "--socket",
                "/run/x.sock",
                "--peer-uid",
                "1",
                "--tor-user",
                bad,
            ]))
            .unwrap_err();
            assert!(matches!(error, ConfigError::Invalid { .. }), "{bad}");
        }
    }

    #[test]
    fn the_summary_names_the_peer_and_the_ports() {
        let config = run(&[
            "--socket",
            "/run/ghostnector/netd.sock",
            "--peer-uid",
            "1000",
        ]);
        let summary = config.summary();
        assert!(summary.contains("peer_uid=1000"));
        assert!(summary.contains("trans:9040"));
        assert!(summary.contains("app=ghbr0/10.200.0.1"));
    }

    #[test]
    fn the_app_identity_is_validated_rather_than_trusted() {
        // A bridge name is generated by us and reaches a privileged argv; it must be restrained.
        for bad in ["", "with space", "with/slash", "waytoolongwaytoolong"] {
            let error = Config::parse(args(&[
                "--socket",
                "/run/x.sock",
                "--peer-uid",
                "1",
                "--app-bridge",
                bad,
            ]))
            .unwrap_err();
            assert!(matches!(error, ConfigError::Invalid { .. }), "{bad}");
        }
        // The core address must be a private, non-routable address: it is a host-local path, not a
        // destination.
        let error = Config::parse(args(&[
            "--socket",
            "/run/x.sock",
            "--peer-uid",
            "1",
            "--app-core",
            "198.51.100.1",
        ]))
        .unwrap_err();
        assert!(matches!(error, ConfigError::Invalid { .. }));

        // The APP address-space prefix belongs to the namespace helper, which allocates the
        // addresses. This helper only names the core address, so it does not accept the option:
        // minimizing the privileged surface means not carrying a knob that does nothing here.
        let error = Config::parse(args(&[
            "--socket",
            "/run/x.sock",
            "--peer-uid",
            "1",
            "--app-prefix",
            "24",
        ]))
        .unwrap_err();
        assert_eq!(error, ConfigError::Unknown("--app-prefix".to_string()));
    }
}
