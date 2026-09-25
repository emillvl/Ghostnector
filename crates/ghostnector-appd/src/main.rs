// `#![cfg(unix)]` for the crate lives in lib.rs; the binary is a thin shell around it.
#![forbid(unsafe_code)]
//! `ghostnector-appd`: the APP-scope namespace helper.

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    use std::process::ExitCode;
    use std::sync::Arc;

    use ghostnector_appd::{
        bind_socket, config::Parsed, Config, Server, SystemNamespaces, VERSION,
    };

    let parsed = match Config::parse(std::env::args().skip(1)) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("ghostnector-appd: {error}\n\n{}", Config::USAGE);
            return ExitCode::from(2);
        }
    };
    let config = match parsed {
        Parsed::Help => {
            println!("{}", Config::USAGE);
            return ExitCode::SUCCESS;
        }
        Parsed::Version => {
            println!("ghostnector-appd {VERSION}");
            return ExitCode::SUCCESS;
        }
        Parsed::Run(config) => *config,
    };

    let backend = match SystemNamespaces::new(
        config.nft.clone(),
        config.ip.clone(),
        config.bridge_ctl.clone(),
        config.probe.clone(),
        config.bridge.clone(),
        config.core,
        config.prefix,
    ) {
        Ok(backend) => Arc::new(backend),
        Err(error) => {
            eprintln!("ghostnector-appd: {error}");
            return ExitCode::FAILURE;
        }
    };

    // The launch helper and the probe are executed on behalf of users; verify them before serving.
    for tool in [&config.launcher, &config.probe] {
        if let Err(error) = ghostnector_appd::backend::check_tool(tool) {
            eprintln!("ghostnector-appd: {error}");
            return ExitCode::FAILURE;
        }
    }

    let server = match Server::new(config.clone(), backend) {
        Ok(server) => Arc::new(server),
        Err(error) => {
            eprintln!("ghostnector-appd: {error}");
            return ExitCode::FAILURE;
        }
    };

    let listener = match bind_socket(&config) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("ghostnector-appd: {error}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "ghostnector-appd {VERSION} listening on {} ({})",
        config.socket.display(),
        config.summary()
    );
    match server.serve(listener) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ghostnector-appd: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("ghostnector-appd is a Linux component");
}
