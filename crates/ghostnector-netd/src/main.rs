//! The privileged helper's entry point.
//!
//! It does four things in order: parse the command line strictly, refuse to gain privileges later,
//! prepare the socket for the one uid it serves, and serve verbs until stopped. Everything else
//! lives in the library so it can be tested without root.

#[cfg(unix)]
mod inner {
    use std::process::ExitCode;
    use std::sync::Arc;

    use ghostnector_netd::config::version_line;
    use ghostnector_netd::{
        bind_socket, Config, NftCli, Parsed, Server, SystemIdentities, VERSION,
    };

    pub fn main() -> ExitCode {
        match run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("ghostnector-netd: {message}");
                ExitCode::from(2)
            }
        }
    }

    fn run() -> Result<(), String> {
        let config = match Config::parse(std::env::args().skip(1)) {
            Ok(Parsed::Run(config)) => config,
            Ok(Parsed::Help) => {
                println!("{}", Config::USAGE);
                return Ok(());
            }
            Ok(Parsed::Version) => {
                println!("{}", version_line());
                return Ok(());
            }
            Err(error) => return Err(format!("{error}\n\n{}", Config::USAGE)),
        };

        // Set once, before anything else can happen: this process must never gain privileges.
        nix::sys::prctl::set_no_new_privs()
            .map_err(|error| format!("cannot refuse future privilege gains: {error}"))?;

        let backend = NftCli::new(config.nft.clone(), config.conntrack.clone())
            .map_err(|error| error.to_string())?;
        if !backend.conntrack_usable() {
            eprintln!(
                "ghostnector-netd: note: '{}' is not usable; pre-existing connections will be \
                 blocked rather than captured",
                config.conntrack.display()
            );
        }

        let listener = bind_socket(&config).map_err(|error| error.to_string())?;
        eprintln!(
            "ghostnector-netd {VERSION} listening on {} ({})",
            config.socket.display(),
            config.summary()
        );

        let server = Arc::new(Server::new(config, Arc::new(backend), SystemIdentities));
        server.serve(listener).map_err(|error| error.to_string())
    }
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    inner::main()
}

#[cfg(not(unix))]
fn main() {
    eprintln!("ghostnector-netd is a Linux component and cannot run on this platform");
    std::process::exit(2);
}
