//! The control plane's entry point.
//!
//! It reconciles against the kernel before it serves anyone, because the truth about what is
//! enforced lives there and not here.

#[cfg(unix)]
mod inner {
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::sync::Arc;

    use ghostnector_core::{bind_socket, Engine, EngineConfig, Helper, Server, VERSION};

    const DEFAULT_HELPER: &str = "/run/ghostnector/netd.sock";
    const DEFAULT_SOCKET: &str = "/run/ghostnector/core.sock";
    const DEFAULT_JOURNAL: &str = "/var/lib/ghostnector/intent.json";

    const USAGE: &str = "\
ghostnector-core - the control plane (no privileges)

USAGE:
    ghostnector-core --socket <PATH> [OPTIONS]

REQUIRED:
    --socket <PATH>     unix socket for clients (parent directory must exist)

OPTIONS:
    --helper <PATH>     the privileged helper's socket
                                              [default: /run/ghostnector/netd.sock]
    --journal <PATH>    where the user's intent is recorded
                                          [default: /var/lib/ghostnector/intent.json]
    --group <NAME>      group allowed to talk to this socket; without it, only
                        the uid running the daemon can connect
    -h, --help          print this text
    -V, --version       print the version";

    struct Config {
        socket: PathBuf,
        helper: PathBuf,
        journal: PathBuf,
        group: Option<String>,
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
        let engine = Arc::new(Engine::new(
            EngineConfig {
                journal_path: config.journal.clone(),
            },
            Arc::new(helper),
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

    fn parse<I>(arguments: I) -> Result<Config, String>
    where
        I: Iterator<Item = String>,
    {
        let mut socket: Option<PathBuf> = None;
        let mut helper = PathBuf::from(DEFAULT_HELPER);
        let mut journal = PathBuf::from(DEFAULT_JOURNAL);
        let mut group: Option<String> = None;

        let mut arguments = arguments.peekable();
        while let Some(option) = arguments.next() {
            let mut value = || {
                arguments
                    .next()
                    .ok_or_else(|| format!("option '{option}' needs a value"))
            };
            match option.as_str() {
                "--socket" => socket = Some(absolute(&option, value()?)?),
                "--helper" => helper = absolute(&option, value()?)?,
                "--journal" => journal = absolute(&option, value()?)?,
                "--group" => {
                    let name = value()?;
                    if name.is_empty() || name.len() > 32 {
                        return Err(format!(
                            "value for '{option}' is not usable: bad group name"
                        ));
                    }
                    group = Some(name);
                }
                other => return Err(format!("unknown option '{other}'\n\n{USAGE}")),
            }
        }

        Ok(Config {
            socket: socket.ok_or_else(|| format!("option '--socket' is required\n\n{USAGE}"))?,
            helper,
            journal,
            group,
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
