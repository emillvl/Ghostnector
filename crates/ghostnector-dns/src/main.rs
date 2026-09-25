//! The DNS chokepoint's entry point.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

use ghostnector_dns::Chokepoint;

const DEFAULT_TIMEOUT_SECONDS: u64 = 10;
const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
ghostnector-dns - the DNS chokepoint

USAGE:
    ghostnector-dns --listen <ADDRESS:PORT> --upstream <ADDRESS:PORT> [OPTIONS]

REQUIRED:
    --listen <ADDR:PORT>    where queries are accepted, for example 127.0.0.1:53
    --upstream <ADDR:PORT>  where they are sent, for example 127.0.0.1:9053

OPTIONS:
    --timeout-seconds <SECONDS>  how long to wait for an answer [default: 10]
    --app-core <ADDR>            also accept queries on this private, host-local address,
                                 which is where APP namespaces deliver them
    --exit-when-stdin-closes     stop when standard input reaches end of file, so a
                                 supervisor that dies does not leave this relay behind
    -h, --help                   print this text
    -V, --version                print the version

The listen address must be loopback, or the exact private core address configured with
--app-core: this relay is for the machine it runs on, and never for a network.";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("ghostnector-dns: {message}");
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
                println!("ghostnector-dns {VERSION}");
                return Ok(());
            }
            _ => {}
        }
    }

    let mut listen: Option<SocketAddr> = None;
    let mut upstream: Option<SocketAddr> = None;
    let mut app_core: Option<Ipv4Addr> = None;
    let mut timeout = Duration::from_secs(DEFAULT_TIMEOUT_SECONDS);
    let mut exit_when_stdin_closes = false;

    while let Some(option) = arguments.next() {
        let mut value = || {
            arguments
                .next()
                .ok_or_else(|| format!("option '{option}' needs a value"))
        };
        match option.as_str() {
            "--listen" => listen = Some(address(&option, &value()?)?),
            "--upstream" => upstream = Some(address(&option, &value()?)?),
            "--app-core" => {
                let raw = value()?;
                let parsed: Ipv4Addr = raw.parse().map_err(|_| {
                    format!("value for '{option}' is not usable: expected an IPv4 address")
                })?;
                if !parsed.is_private() {
                    return Err(format!(
                        "value for '{option}' is not usable: the APP core address must be \
                         private and host-local"
                    ));
                }
                app_core = Some(parsed);
            }
            "--exit-when-stdin-closes" => exit_when_stdin_closes = true,
            "--timeout-seconds" => {
                let raw = value()?;
                let seconds: u64 = raw.parse().map_err(|_| {
                    format!("value for '{option}' is not usable: expected a number of seconds")
                })?;
                if seconds == 0 || seconds > 300 {
                    return Err(format!(
                        "value for '{option}' is not usable: expected 1 to 300 seconds"
                    ));
                }
                timeout = Duration::from_secs(seconds);
            }
            other => return Err(format!("unknown option '{other}'\n\n{USAGE}")),
        }
    }

    let listen = listen.ok_or_else(|| format!("option '--listen' is required\n\n{USAGE}"))?;
    let upstream = upstream.ok_or_else(|| format!("option '--upstream' is required\n\n{USAGE}"))?;

    // The same rule the firewall enforces, stated where it can never be forgotten: this relay is
    // for the machine it runs on, and an open resolver is a gift to a network. The one exception is
    // the configured private core address, which exists only on the host's private APP bridge.
    listen_is_acceptable(listen, app_core)?;

    let relay = Chokepoint::new(listen, upstream, timeout);
    eprintln!("ghostnector-dns {VERSION} relaying {listen} to {upstream}");

    if exit_when_stdin_closes {
        // A tether to the supervisor: when it goes away, its end of the pipe closes and this relay
        // stops rather than lingering with the port bound.
        std::thread::spawn(|| {
            use std::io::Read;
            let mut byte = [0u8; 1];
            loop {
                match std::io::stdin().read(&mut byte) {
                    Ok(0) | Err(_) => std::process::exit(0),
                    Ok(_) => continue, // the pipe carries nothing; only its closure matters
                }
            }
        });
    }

    relay.run().map_err(|error| error.to_string())
}

fn address(option: &str, raw: &str) -> Result<SocketAddr, String> {
    raw.parse()
        .map_err(|_| format!("value for '{option}' is not usable: expected address:port"))
}

/// Whether the relay may listen here.
///
/// Loopback always; the exact private core address when one is configured; nothing else, and never
/// a wildcard. The rule is a function so it can be tested without binding anything.
fn listen_is_acceptable(listen: SocketAddr, app_core: Option<Ipv4Addr>) -> Result<(), String> {
    let acceptable = match listen.ip() {
        IpAddr::V4(address) => address.is_loopback() || app_core == Some(address),
        IpAddr::V6(_) => listen.ip().is_loopback(),
    };
    if acceptable {
        Ok(())
    } else {
        Err(format!(
            "refusing to listen on {listen}: the chokepoint is for this machine only"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(text: &str) -> SocketAddr {
        text.parse().expect("address")
    }

    #[test]
    fn only_loopback_and_the_configured_core_address_are_acceptable() {
        let core = Ipv4Addr::new(10, 200, 0, 1);
        assert!(listen_is_acceptable(address("127.0.0.1:53"), None).is_ok());
        assert!(listen_is_acceptable(address("[::1]:53"), None).is_ok());
        assert!(listen_is_acceptable(address("10.200.0.1:53"), Some(core)).is_ok());
        assert!(
            listen_is_acceptable(address("10.200.0.1:53"), None).is_err(),
            "the core address is only acceptable when it was configured"
        );
        for bad in [
            "0.0.0.0:53",
            "192.168.1.1:53",
            "10.200.0.2:53",
            "[::]:53",
            "[fd00::1]:53",
        ] {
            assert!(
                listen_is_acceptable(address(bad), Some(core)).is_err(),
                "{bad} must be refused"
            );
        }
    }
}
