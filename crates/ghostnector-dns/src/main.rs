//! The DNS chokepoint's entry point.

use std::net::SocketAddr;
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
    -h, --help                   print this text
    -V, --version                print the version

The listen address must be loopback: this relay is for the machine it runs on, and never for
a network.";

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
    let mut timeout = Duration::from_secs(DEFAULT_TIMEOUT_SECONDS);

    while let Some(option) = arguments.next() {
        let mut value = || {
            arguments
                .next()
                .ok_or_else(|| format!("option '{option}' needs a value"))
        };
        match option.as_str() {
            "--listen" => listen = Some(address(&option, &value()?)?),
            "--upstream" => upstream = Some(address(&option, &value()?)?),
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
    // for the machine it runs on, and an open resolver is a gift to a network.
    if !listen.ip().is_loopback() {
        return Err(format!(
            "refusing to listen on {listen}: the chokepoint is for this machine only"
        ));
    }

    let relay = Chokepoint::new(listen, upstream, timeout);
    eprintln!("ghostnector-dns {VERSION} relaying {listen} to {upstream}");
    relay.run().map_err(|error| error.to_string())
}

fn address(option: &str, raw: &str) -> Result<SocketAddr, String> {
    raw.parse()
        .map_err(|_| format!("value for '{option}' is not usable: expected address:port"))
}
