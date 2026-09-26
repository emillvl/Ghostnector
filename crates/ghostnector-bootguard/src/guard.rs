//! The boot guard.
//!
//! Kernel state does not survive a reboot, so a machine that was protected when it stopped is open
//! while it starts: for those seconds, if an application managed to send something, it would leave
//! by the front door. This program closes that window.
//!
//! It runs early, as root, and does one of three things:
//!
//! 1. **Nothing**, if the journal says protection was not requested — the machine is meant to be
//!    open, so it stays open.
//! 2. **Nothing**, if the kernel command line carries `ghostnector.unprotected=1`. That is the
//!    documented way out for an operator whose machine will not come up, and it is deliberately
//!    something you can only do at the console.
//! 3. **Denies everything**, if protection was requested: first by asking the privileged helper, and
//!    — if the helper cannot be reached — by applying the copy of the fail-closed policy that the
//!    helper left behind.
//!
//! A journal that cannot be read is treated as "protection was requested", because the alternative
//! is a machine that is open while its owner believes otherwise. Recovery is documented, and it does
//! not need the network.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

use ghostnector_spec::backend::{Params, ProfileId, Verb};
use ghostnector_spec::ipc::{HelperResponse, PROTOCOL_VERSION};

const DEFAULT_NETD: &str = "/run/ghostnector/netd/netd.sock";
const DEFAULT_INTENT: &str = "/var/lib/ghostnector/intent.json";
const DEFAULT_FALLBACK: &str = "/var/lib/ghostnector/fail-closed.nft";
const DEFAULT_CMDLINE: &str = "/proc/cmdline";
const DEFAULT_NFT: &str = "/usr/sbin/nft";
const DEFAULT_WAIT_SECONDS: u64 = 15;

/// The journal format this build understands.
const UNDERSTOOD_JOURNAL_VERSION: u32 = 1;

/// The escape hatch, as it appears on the kernel command line.
const ESCAPE: &str = "ghostnector.unprotected=1";

/// What the guard did.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    /// Nothing was requested, so nothing was done.
    NotRequested,
    /// The operator asked for the machine to stay open.
    Exempted,
    /// The helper was asked, and denied everything.
    DeniedByHelper,
    /// The helper was unreachable, and its own copy of the policy was applied.
    DeniedByFallback,
}

const USAGE: &str = "\
ghostnector-bootguard - deny everything at boot if protection was requested

USAGE:
    ghostnector-bootguard [OPTIONS]

OPTIONS:
    --netd <PATH>        the privileged helper's socket
                                              [default: /run/ghostnector/netd/netd.sock]
    --intent <PATH>      the journal that records what the user asked for
                                          [default: /var/lib/ghostnector/intent.json]
    --fallback <PATH>    a copy of the fail-closed policy, for when the helper is
                           not available [default: /var/lib/ghostnector/fail-closed.nft]
    --nft <PATH>         the policy tool used for that copy
                                                  [default: /usr/sbin/nft]
    --cmdline <PATH>     where the kernel command line can be read
                                                     [default: /proc/cmdline]
    --wait-seconds <N>   how long to wait for the helper         [default: 15]
    -h, --help           print this text
    -V, --version        print the version";

pub fn main() -> ExitCode {
    match run() {
        Ok(action) => {
            eprintln!("ghostnector-bootguard: {}", describe(&action));
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("ghostnector-bootguard: {message}");
            ExitCode::from(2)
        }
    }
}

fn describe(action: &Action) -> String {
    match action {
        Action::NotRequested => {
            "protection was not requested before the last restart; nothing to do".to_string()
        }
        Action::Exempted => {
            "protection is disabled on the kernel command line; the machine stays open, and \
             Ghostnector's own state will say so"
                .to_string()
        }
        Action::DeniedByHelper => {
            "protection was requested; the helper has denied everything until it is verified"
                .to_string()
        }
        Action::DeniedByFallback => {
            "protection was requested and the helper was unreachable, so its own copy of the \
             fail-closed policy was applied"
                .to_string()
        }
    }
}

struct Config {
    netd: PathBuf,
    intent: PathBuf,
    fallback: PathBuf,
    nft: PathBuf,
    cmdline: PathBuf,
    wait: Duration,
}

fn run() -> Result<Action, String> {
    let mut arguments = std::env::args().skip(1).peekable();
    if let Some(first) = arguments.peek() {
        match first.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(Action::NotRequested);
            }
            "-V" | "--version" => {
                println!("ghostnector-bootguard {}", env!("CARGO_PKG_VERSION"));
                return Ok(Action::NotRequested);
            }
            _ => {}
        }
    }

    let config = parse(arguments)?;

    if command_line_says_open(&config.cmdline) {
        return Ok(Action::Exempted);
    }

    match protection_was_requested(&config.intent) {
        Ok(false) => return Ok(Action::NotRequested),
        Ok(true) => {}
        Err(reason) => {
            // Anything unreadable is treated as a request for protection: the machine must not be
            // open while its owner believes it is not.
            eprintln!(
                "ghostnector-bootguard: the journal could not be read ({reason}); assuming \
                 protection was requested"
            );
        }
    }

    match ask_helper(&config.netd, config.wait) {
        Ok(()) => return Ok(Action::DeniedByHelper),
        Err(reason) => {
            eprintln!("ghostnector-bootguard: the helper could not deny everything: {reason}");
        }
    }

    apply_fallback(&config.nft, &config.fallback)?;
    Ok(Action::DeniedByFallback)
}

/// Whether the operator asked, at the console, for the machine to stay open.
fn command_line_says_open(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|line| line.split_whitespace().any(|word| word == ESCAPE))
        .unwrap_or(false)
}

/// What the journal says, with the version checked rather than guessed at.
fn protection_was_requested(path: &Path) -> Result<bool, String> {
    #[derive(serde::Deserialize)]
    struct Journal {
        #[serde(default)]
        version: u32,
        #[serde(default)]
        protected: bool,
    }

    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.to_string()),
    };
    let journal: Journal = serde_json::from_str(&text).map_err(|error| error.to_string())?;
    if journal.version > UNDERSTOOD_JOURNAL_VERSION {
        return Err(format!(
            "it is version {}, which this build does not understand",
            journal.version
        ));
    }
    Ok(journal.protected)
}

/// Ask the privileged helper to deny everything, retrying while it starts up.
fn ask_helper(socket: &Path, wait: Duration) -> Result<(), String> {
    let deadline = Instant::now() + wait;

    loop {
        match try_helper(socket) {
            Ok(()) => return Ok(()),
            Err(reason) => {
                if Instant::now() >= deadline {
                    return Err(reason);
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn try_helper(socket: &Path) -> Result<(), String> {
    let stream = UnixStream::connect(socket).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;

    let mut writer = stream.try_clone().map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(stream);

    send(
        &mut writer,
        &Verb::Hello {
            protocol: PROTOCOL_VERSION,
        },
    )?;
    match read(&mut reader)? {
        HelperResponse::Hello { protocol, .. } if protocol == PROTOCOL_VERSION => {}
        other => return Err(format!("the helper greeted with {other:?}")),
    }

    send(
        &mut writer,
        &Verb::ApplyProfile {
            profile: ProfileId::FailClosed,
            params: Params::default(),
        },
    )?;
    match read(&mut reader)? {
        HelperResponse::Applied { report } if report.applied => Ok(()),
        HelperResponse::Error(body) => Err(format!("the helper refused: {}", body.message)),
        other => Err(format!("the helper answered {other:?}")),
    }
}

fn send(stream: &mut impl Write, verb: &Verb) -> Result<(), String> {
    let mut encoded = serde_json::to_vec(verb).map_err(|error| error.to_string())?;
    encoded.push(b'\n');
    stream
        .write_all(&encoded)
        .map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())
}

fn read(stream: &mut impl BufRead) -> Result<HelperResponse, String> {
    let mut line = String::new();
    let read = stream
        .read_line(&mut line)
        .map_err(|error| error.to_string())?;
    if read == 0 {
        return Err("the helper closed the connection".to_string());
    }
    serde_json::from_str(&line).map_err(|error| error.to_string())
}

/// Apply the helper's own copy of the fail-closed policy.
///
/// The `nft` this runs is root-owned by construction, and refusing to act because the file looked
/// wrong would leave the machine open: the worse of the two outcomes. That is why, alone in this
/// project, this path does not re-verify its tool.
fn apply_fallback(nft: &Path, ruleset: &Path) -> Result<(), String> {
    if !ruleset.is_file() {
        return Err(format!(
            "there is no copy of the fail-closed policy at '{}', so nothing could be denied",
            ruleset.display()
        ));
    }
    let output = Command::new(nft)
        .arg("-f")
        .arg(ruleset)
        .output()
        .map_err(|error| format!("'{}' could not be run: {error}", nft.display()))?;
    if !output.status.success() {
        let said = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!("'{}' refused: {said}", nft.display()));
    }
    Ok(())
}

fn parse<I>(arguments: I) -> Result<Config, String>
where
    I: Iterator<Item = String>,
{
    let mut netd = PathBuf::from(DEFAULT_NETD);
    let mut intent = PathBuf::from(DEFAULT_INTENT);
    let mut fallback = PathBuf::from(DEFAULT_FALLBACK);
    let mut nft = PathBuf::from(DEFAULT_NFT);
    let mut cmdline = PathBuf::from(DEFAULT_CMDLINE);
    let mut wait = Duration::from_secs(DEFAULT_WAIT_SECONDS);

    let mut arguments = arguments.peekable();
    while let Some(option) = arguments.next() {
        let mut value = || {
            arguments
                .next()
                .ok_or_else(|| format!("option '{option}' needs a value"))
        };
        match option.as_str() {
            "--netd" => netd = absolute(&option, value()?)?,
            "--intent" => intent = absolute(&option, value()?)?,
            "--fallback" => fallback = absolute(&option, value()?)?,
            "--nft" => nft = absolute(&option, value()?)?,
            "--cmdline" => cmdline = absolute(&option, value()?)?,
            "--wait-seconds" => {
                let raw = value()?;
                let seconds: u64 = raw.parse().map_err(|_| {
                    format!("value for '{option}' is not usable: expected a number of seconds")
                })?;
                if seconds > 300 {
                    return Err(format!(
                        "value for '{option}' is not usable: expected at most 300 seconds"
                    ));
                }
                wait = Duration::from_secs(seconds);
            }
            other => return Err(format!("unknown option '{other}'\n\n{USAGE}")),
        }
    }

    Ok(Config {
        netd,
        intent,
        fallback,
        nft,
        cmdline,
        wait,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ghostnector-bootguard-{}-{label}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        path
    }

    #[test]
    fn a_missing_journal_means_nothing_was_requested() {
        let dir = temp("missing");
        assert_eq!(
            protection_was_requested(&dir.join("absent.json")),
            Ok(false)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_journal_that_asks_for_protection_is_read_as_such() {
        let dir = temp("protected");
        let journal = dir.join("intent.json");
        std::fs::write(&journal, br#"{"version":1,"protected":true}"#).expect("write");
        assert_eq!(protection_was_requested(&journal), Ok(true));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_journal_is_an_error_rather_than_a_default() {
        let dir = temp("corrupt");
        let journal = dir.join("intent.json");
        std::fs::write(&journal, b"{ not json").expect("write");
        assert!(protection_was_requested(&journal).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_journal_from_the_future_is_not_guessed_at() {
        let dir = temp("future");
        let journal = dir.join("intent.json");
        std::fs::write(&journal, br#"{"version":99,"protected":true}"#).expect("write");
        assert!(protection_was_requested(&journal).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_command_line_escape_is_recognised_wherever_it_appears() {
        let dir = temp("cmdline");
        let cmdline = dir.join("cmdline");

        std::fs::write(&cmdline, b"quiet splash\n").expect("write");
        assert!(!command_line_says_open(&cmdline));

        std::fs::write(&cmdline, format!("quiet {ESCAPE} splash\n").as_bytes()).expect("write");
        assert!(command_line_says_open(&cmdline));

        std::fs::write(&cmdline, b"quiet ghostnector.unprotected=0\n").expect("write");
        assert!(
            !command_line_says_open(&cmdline),
            "only the exact word counts"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_command_line_is_not_an_escape() {
        let dir = temp("no-cmdline");
        assert!(!command_line_says_open(&dir.join("absent")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_fallback_refuses_to_pretend_when_there_is_no_policy_to_apply() {
        let dir = temp("no-fallback");
        let error = apply_fallback(Path::new("/usr/sbin/nft"), &dir.join("absent.nft"))
            .expect_err("nothing to apply");
        assert!(error.contains("no copy"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn options_are_validated() {
        fn args(list: &[&str]) -> std::vec::IntoIter<String> {
            list.iter()
                .map(|value| value.to_string())
                .collect::<Vec<String>>()
                .into_iter()
        }
        assert!(parse(args(&["--wait-seconds", "abc"])).is_err());
        assert!(parse(args(&["--wait-seconds", "9999"])).is_err());
        assert!(parse(args(&["--netd", "relative"])).is_err());
        assert!(parse(args(&["--nonsense"])).is_err());
        assert!(parse(args(&["--wait-seconds", "3"])).is_ok());
    }

    #[test]
    fn the_helper_is_asked_with_a_handshake_first() {
        // A socket that answers as the helper would, and records what it was asked.
        let dir = temp("helper");
        let socket = dir.join("netd.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind");
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = std::sync::Arc::clone(&asked);
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut writer = stream;
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 0 {
                    recorder.lock().expect("lock").push(line.trim().to_string());
                    let reply = if line.contains("hello") {
                        format!("{{\"result\":\"hello\",\"protocol\":{PROTOCOL_VERSION},\"version\":\"test\"}}\n")
                    } else {
                        "{\"result\":\"applied\",\"report\":{\"applied\":true,\"profile\":\"fail_closed\"}}\n".to_string()
                    };
                    let _ = writer.write_all(reply.as_bytes());
                    let _ = writer.flush();
                    line.clear();
                }
            }
        });

        try_helper(&socket).expect("the helper should accept the request");
        let asked = asked.lock().expect("lock").clone();
        assert!(asked[0].contains("hello"), "{asked:?}");
        assert!(asked[1].contains("fail_closed"), "{asked:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_helper_that_is_not_there_is_an_error_the_caller_can_fall_back_from() {
        let dir = temp("no-helper");
        assert!(try_helper(&dir.join("absent.sock")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_fallback_actually_applies_a_policy() {
        // Only meaningful where nftables exists; the file is a valid, empty table.
        let dir = temp("apply");
        let ruleset = dir.join("fail-closed.nft");
        std::fs::write(
            &ruleset,
            b"destroy table inet ghostnector-bootguard-test\ntable inet ghostnector-bootguard-test {\n}\n",
        )
        .expect("write");
        if Path::new("/usr/sbin/nft").exists() && nix::unistd::Uid::effective().is_root() {
            apply_fallback(Path::new("/usr/sbin/nft"), &ruleset).expect("apply");
            let output = Command::new("/usr/sbin/nft")
                .args(["list", "tables"])
                .output()
                .expect("list");
            let listed = String::from_utf8_lossy(&output.stdout);
            assert!(listed.contains("ghostnector-bootguard-test"), "{listed}");
            let _ = Command::new("/usr/sbin/nft")
                .args(["delete", "table", "inet", "ghostnector-bootguard-test"])
                .output();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
