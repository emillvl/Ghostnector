//! The control plane's entry point.
//!
//! It reconciles against the kernel before it serves anyone, because the truth about what is
//! enforced lives there and not here.

#[cfg(unix)]
mod inner {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::sync::Arc;
    use std::time::Duration;

    use ghostnector_core::{
        bind_socket, ChildRelay, CommandRunner, DnsRelay, Engine, EngineConfig, ExternalServices,
        Helper, Server, Services, SystemCommands, SystemdServices, SystemdUnits, TorControl,
        TorSettings, VERSION,
    };

    const DEFAULT_HELPER: &str = "/run/ghostnector/netd.sock";
    const DEFAULT_SOCKET: &str = "/run/ghostnector/core.sock";
    const DEFAULT_JOURNAL: &str = "/var/lib/ghostnector/intent.json";
    const DEFAULT_SYSTEMCTL: &str = "/usr/bin/systemctl";
    const DEFAULT_TOR_UNIT: &str = "ghostnector-tor.service";
    const DEFAULT_TORRC: &str = "/run/ghostnector/torrc";
    const DEFAULT_TOR_DATA: &str = "/var/lib/tor";
    const DEFAULT_TOR_COOKIE: &str = "/run/ghostnector/tor-control.cookie";
    const DEFAULT_TOR_CONTROL_PORT: u16 = 9051;
    const DEFAULT_TOR_DNS_PORT: u16 = 9053;
    const DEFAULT_TOR_BUDGET_SECONDS: u64 = 120;
    const DEFAULT_DNS_HELPER: &str = "/usr/libexec/ghostnector-dns";
    const DEFAULT_RESOLVER_STATE: &str = "/var/lib/ghostnector/resolver.json";
    const DEFAULT_RESOLVE_CONF_ROOT: &str = "/";
    const DEFAULT_RESOLVECTL: &str = "/usr/bin/resolvectl";
    const DEFAULT_RESOLVER_PORT: u16 = 5353;

    const USAGE: &str = "\
ghostnector-core - the control plane (no privileges)

USAGE:
    ghostnector-core [OPTIONS]

OPTIONS:
    --socket <PATH>     unix socket for clients
                                          [default: /run/ghostnector/core.sock]
    --helper <PATH>     the privileged helper's socket
                                              [default: /run/ghostnector/netd.sock]
    --journal <PATH>    where the user's intent is recorded
                                          [default: /var/lib/ghostnector/intent.json]
    --group <NAME>      group allowed to talk to this socket; without it, only
                        the uid running the daemon can connect

  Tor supervision:
    --services <MODE>   'systemd' to start and stop Tor ourselves, 'external' if
                        the operator runs Tor and we only wait for it
                                                          [default: systemd]
    --systemctl <PATH>  the service manager to use     [default: /usr/bin/systemctl]
    --tor-unit <NAME>   the unit that runs Tor [default: ghostnector-tor.service]
    --torrc <PATH>      where Tor's configuration is written
                                              [default: /run/ghostnector/torrc]
    --tor-data-dir <PATH>   Tor's data directory           [default: /var/lib/tor]
    --tor-cookie <PATH>     Tor's control cookie
                                   [default: /run/ghostnector/tor-control.cookie]
    --tor-control-port <PORT>   Tor's control port           [default: 9051]
    --tor-dns-port <PORT>       Tor's DNS listener, which the DNS chokepoint
                                forwards to                      [default: 9053]
    --tor-bootstrap-seconds <SECONDS>   how long to wait for Tor [default: 120]

  DNS:
    --dns-helper <PATH>     the DNS relay that every query passes through
                                        [default: /usr/libexec/ghostnector-dns]
    --resolver-state <PATH>  where the resolver's original configuration is recorded
                                    [default: /var/lib/ghostnector/resolver.json]
    --tor-dns-port <PORT>   Tor's DNS listener, which the relay forwards to
                                                              [default: 9053]
    --resolver-port <PORT>  the encrypted resolver's listener, used in DNS-only
                            mode                                  [default: 5353]
    --resolv-conf-root <PATH>  filesystem root used to find and change the
                               resolver configuration; for containers, not for
                               hiding                        [default: /]
    --resolvectl <PATH>     the tool used to configure systemd-resolved
                                                      [default: /usr/bin/resolvectl]

    -h, --help          print this text
    -V, --version       print the version";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ServicesMode {
        Systemd,
        External,
    }

    struct Config {
        socket: PathBuf,
        helper: PathBuf,
        journal: PathBuf,
        group: Option<String>,
        services: ServicesMode,
        systemctl: PathBuf,
        tor_unit: String,
        torrc: PathBuf,
        tor_data: PathBuf,
        tor_cookie: PathBuf,
        tor_control_port: u16,
        tor_dns_port: u16,
        tor_budget: Duration,
        dns_helper: PathBuf,
        resolver_state: PathBuf,
        resolver_port: u16,
        resolver_root: PathBuf,
        resolvectl: PathBuf,
    }

    pub fn main() -> ExitCode {
        match run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("ghostnector-core: {message}");
                ExitCode::from(2)
            }
        }
    }

    fn run() -> Result<(), String> {
        let mut arguments = std::env::args().skip(1).peekable();
        if let Some(first) = arguments.peek() {
            match first.as_str() {
                "-h" | "--help" => {
                    println!("{USAGE}");
                    return Ok(());
                }
                "-V" | "--version" => {
                    println!("ghostnector-core {VERSION}");
                    return Ok(());
                }
                _ => {}
            }
        }

        let config = parse(arguments)?;

        let group = match &config.group {
            Some(name) => {
                let group = nix::unistd::Group::from_name(name)
                    .map_err(|error| format!("cannot look up group '{name}': {error}"))?
                    .ok_or_else(|| format!("group '{name}' does not exist"))?;
                Some(group.gid.as_raw())
            }
            None => None,
        };

        let helper = Helper::new(config.helper.clone());
        let services = build_services(&config)?;
        let relay: Arc<dyn DnsRelay> = Arc::new(
            ChildRelay::new(config.dns_helper.clone()).map_err(|error| error.to_string())?,
        );
        let commands: Arc<dyn CommandRunner> = Arc::new(SystemCommands);
        let engine = Arc::new(Engine::new(
            EngineConfig {
                journal_path: config.journal.clone(),
                resolver_state_path: config.resolver_state.clone(),
                tor_dns_port: config.tor_dns_port,
                resolver_port: config.resolver_port,
                resolver_root: config.resolver_root.clone(),
                resolvectl: config.resolvectl.clone(),
            },
            Arc::new(helper),
            services,
            relay,
            commands,
        ));

        // Reconcile before serving: the kernel's answer, not ours, decides what is enforced.
        if let Err(error) = engine.reconcile() {
            eprintln!("ghostnector-core: could not reconcile with the helper: {error}");
            engine.refresh();
        }

        let listener = bind_socket(&config.socket, group).map_err(|error| error.to_string())?;
        let snapshot = engine.snapshot();
        eprintln!(
            "ghostnector-core {VERSION} listening on {} (state: {:?}, applied: {})",
            config.socket.display(),
            snapshot.state,
            snapshot.health.policy_applied
        );

        let server = Arc::new(Server::new(engine));
        server.serve(listener).map_err(|error| error.to_string())
    }

    fn build_services(config: &Config) -> Result<Arc<dyn Services>, String> {
        let tor = TorControl::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, config.tor_control_port)),
            config.tor_cookie.clone(),
            Duration::from_secs(10),
        );
        let settings = TorSettings {
            dns_port: config.tor_dns_port,
            control_port: config.tor_control_port,
            data_directory: config.tor_data.clone(),
            cookie_path: config.tor_cookie.clone(),
            ..TorSettings::default()
        };

        match config.services {
            ServicesMode::Systemd => {
                let supervisor = SystemdUnits::new(config.systemctl.clone())
                    .map_err(|error| error.to_string())?;
                Ok(Arc::new(SystemdServices::new(
                    Arc::new(supervisor),
                    tor,
                    config.tor_unit.clone(),
                    config.torrc.clone(),
                    settings,
                    config.tor_budget,
                )))
            }
            ServicesMode::External => Ok(Arc::new(ExternalServices::new(tor, config.tor_budget))),
        }
    }

    fn parse<I>(arguments: I) -> Result<Config, String>
    where
        I: Iterator<Item = String>,
    {
        let mut socket = PathBuf::from(DEFAULT_SOCKET);
        let mut helper = PathBuf::from(DEFAULT_HELPER);
        let mut journal = PathBuf::from(DEFAULT_JOURNAL);
        let mut group: Option<String> = None;
        let mut services = ServicesMode::Systemd;
        let mut systemctl = PathBuf::from(DEFAULT_SYSTEMCTL);
        let mut tor_unit = DEFAULT_TOR_UNIT.to_string();
        let mut torrc = PathBuf::from(DEFAULT_TORRC);
        let mut tor_data = PathBuf::from(DEFAULT_TOR_DATA);
        let mut tor_cookie = PathBuf::from(DEFAULT_TOR_COOKIE);
        let mut tor_control_port = DEFAULT_TOR_CONTROL_PORT;
        let mut tor_dns_port = DEFAULT_TOR_DNS_PORT;
        let mut tor_budget = Duration::from_secs(DEFAULT_TOR_BUDGET_SECONDS);
        let mut dns_helper = PathBuf::from(DEFAULT_DNS_HELPER);
        let mut resolver_state = PathBuf::from(DEFAULT_RESOLVER_STATE);
        let mut resolver_port = DEFAULT_RESOLVER_PORT;
        let mut resolver_root = PathBuf::from(DEFAULT_RESOLVE_CONF_ROOT);
        let mut resolvectl = PathBuf::from(DEFAULT_RESOLVECTL);

        let mut arguments = arguments.peekable();
        while let Some(option) = arguments.next() {
            let mut value = || {
                arguments
                    .next()
                    .ok_or_else(|| format!("option '{option}' needs a value"))
            };
            match option.as_str() {
                "--socket" => socket = absolute(&option, value()?)?,
                "--helper" => helper = absolute(&option, value()?)?,
                "--journal" => journal = absolute(&option, value()?)?,
                "--systemctl" => systemctl = absolute(&option, value()?)?,
                "--torrc" => torrc = absolute(&option, value()?)?,
                "--tor-data-dir" => tor_data = absolute(&option, value()?)?,
                "--tor-cookie" => tor_cookie = absolute(&option, value()?)?,
                "--group" => {
                    let name = value()?;
                    if name.is_empty() || name.len() > 32 {
                        return Err(format!(
                            "value for '{option}' is not usable: bad group name"
                        ));
                    }
                    group = Some(name);
                }
                "--services" => {
                    services = match value()?.as_str() {
                        "systemd" => ServicesMode::Systemd,
                        "external" => ServicesMode::External,
                        other => {
                            return Err(format!(
                                "value for '{option}' is not usable: expected systemd or \
                                 external, found '{other}'"
                            ))
                        }
                    }
                }
                "--tor-unit" => {
                    let unit = value()?;
                    if unit.is_empty()
                        || unit.starts_with('-')
                        || !unit.chars().all(|c| {
                            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@')
                        })
                    {
                        return Err(format!("value for '{option}' is not usable: bad unit name"));
                    }
                    tor_unit = unit;
                }
                "--tor-control-port" => tor_control_port = port(&option, &value()?)?,
                "--tor-dns-port" => tor_dns_port = port(&option, &value()?)?,
                "--resolver-port" => resolver_port = port(&option, &value()?)?,
                "--dns-helper" => dns_helper = absolute(&option, value()?)?,
                "--resolver-state" => resolver_state = absolute(&option, value()?)?,
                "--resolv-conf-root" => resolver_root = absolute(&option, value()?)?,
                "--resolvectl" => resolvectl = absolute(&option, value()?)?,
                "--tor-bootstrap-seconds" => {
                    let raw = value()?;
                    let seconds: u64 = raw.parse().map_err(|_| {
                        format!("value for '{option}' is not usable: expected a number of seconds")
                    })?;
                    if seconds == 0 || seconds > 3600 {
                        return Err(format!(
                            "value for '{option}' is not usable: expected 1 to 3600 seconds"
                        ));
                    }
                    tor_budget = Duration::from_secs(seconds);
                }
                other => return Err(format!("unknown option '{other}'\n\n{USAGE}")),
            }
        }

        Ok(Config {
            socket,
            helper,
            journal,
            group,
            services,
            systemctl,
            tor_unit,
            torrc,
            tor_data,
            tor_cookie,
            tor_control_port,
            tor_dns_port,
            tor_budget,
            dns_helper,
            resolver_state,
            resolver_port,
            resolver_root,
            resolvectl,
        })
    }

    fn absolute(option: &str, raw: String) -> Result<PathBuf, String> {
        if !raw.starts_with('/') {
            return Err(format!(
                "value for '{option}' is not usable: expected an absolute path"
            ));
        }
        Ok(PathBuf::from(raw))
    }

    fn port(option: &str, raw: &str) -> Result<u16, String> {
        let port: u16 = raw
            .parse()
            .map_err(|_| format!("value for '{option}' is not usable: expected a port"))?;
        if port == 0 {
            return Err(format!(
                "value for '{option}' is not usable: port 0 is not usable"
            ));
        }
        Ok(port)
    }
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    inner::main()
}

#[cfg(not(unix))]
fn main() {
    eprintln!("ghostnector-core is a Linux component and cannot run on this platform");
    std::process::exit(2);
}
