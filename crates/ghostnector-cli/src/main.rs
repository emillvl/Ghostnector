//! `ghostnector` — the command-line client.
//!
//! It is deliberately dumb: it hands a request to the control plane and prints the answer. It holds
//! no state, needs no privileges, and knows nothing about nftables. Everything it shows comes from a
//! snapshot the daemon produced, so the command cannot disagree with the daemon about reality.

#[cfg(unix)]
mod inner {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;

    use ghostnector_spec::ipc::{ErrorBody, Frame, Request, Response, PROTOCOL_VERSION};
    use ghostnector_spec::{Networks, Profile, ProtectionState, Scope, Snapshot};

    const DEFAULT_SOCKET: &str = "/run/ghostnector/core.sock";
    const VERSION: &str = env!("CARGO_PKG_VERSION");

    const USAGE: &str = "\
ghostnector - network privacy, from the command line

USAGE:
    ghostnector [--socket <PATH>] <COMMAND>

COMMANDS:
    status                       show the current state and why it is that way
    connect [--scope <SCOPE>]    protect this machine (default scope: system)
            [--lan]              also allow reaching the local network
    disconnect                   return to the network as it was before
    panic                        deny everything now, leaving services running
    watch                        follow state changes until interrupted

SCOPES:
    system   every process on the machine (default)
    user     only processes belonging to you
    dns      encrypted DNS only, no Tor

OPTIONS:
    --socket <PATH>   where the control plane listens
                                         [default: /run/ghostnector/core.sock]
    -h, --help        print this text
    -V, --version     print the version";

    enum Command {
        Status,
        Connect { scope: Scope, lan: bool },
        Disconnect,
        Panic,
        Watch,
    }

    pub fn main() -> ExitCode {
        match run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("ghostnector: {message}");
                ExitCode::from(1)
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
                    println!("ghostnector {VERSION}");
                    return Ok(());
                }
                _ => {}
            }
        }

        let (socket, command) = parse(arguments)?;
        let mut session = Session::open(&socket)?;

        match command {
            Command::Status => match session.send(&Request::Snapshot)? {
                Response::Snapshot(snapshot) => {
                    print!("{}", render(&snapshot));
                    Ok(())
                }
                other => Err(unexpected(other)),
            },
            Command::Connect { scope, lan } => {
                let profile = Profile {
                    scope,
                    networks: if scope == Scope::Dns {
                        Networks::none()
                    } else {
                        Networks::tor()
                    },
                    allow_lan: lan,
                    ..Profile::default()
                };
                let response = session.send(&Request::Connect { profile })?;
                check_accepted(response)?;
                report(&mut session)
            }
            Command::Disconnect => {
                let response = session.send(&Request::Disconnect)?;
                check_accepted(response)?;
                report(&mut session)
            }
            Command::Panic => {
                let response = session.send(&Request::Panic)?;
                check_accepted(response)?;
                report(&mut session)
            }
            Command::Watch => session.watch(),
        }
    }

    fn check_accepted(response: Response) -> Result<(), String> {
        match response {
            Response::Accepted => Ok(()),
            Response::Error(body) => Err(explain(body)),
            other => Err(unexpected(other)),
        }
    }

    fn report(session: &mut Session) -> Result<(), String> {
        match session.send(&Request::Snapshot)? {
            Response::Snapshot(snapshot) => {
                print!("{}", render(&snapshot));
                Ok(())
            }
            other => Err(unexpected(other)),
        }
    }

    fn explain(body: ErrorBody) -> String {
        format!("{} ({:?})", body.message, body.code)
    }

    fn unexpected(response: Response) -> String {
        format!("the daemon answered something unexpected: {response:?}")
    }

    // ------------------------------------------------------------------ rendering

    fn render(snapshot: &Snapshot) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "state:        {}\n",
            describe_state(snapshot.state)
        ));
        if let Some(profile) = &snapshot.profile {
            out.push_str(&format!(
                "profile:      {} ({})\n",
                describe_scope(profile.scope),
                if profile.networks.tor {
                    "through Tor"
                } else if profile.networks.i2p {
                    "through I2P"
                } else {
                    "encrypted DNS only"
                }
            ));
            if profile.allow_lan {
                out.push_str("              including the local network\n");
            }
        }
        out.push_str(&format!(
            "policy:       {}\n",
            if snapshot.health.policy_applied {
                "applied"
            } else {
                "not applied"
            }
        ));
        out.push_str(&format!(
            "verification: {}\n",
            describe_verification(snapshot.health.verification)
        ));

        if !snapshot.reasons.is_empty() {
            out.push_str("why:\n");
            for reason in &snapshot.reasons {
                out.push_str(&format!("  - {}\n", reason.as_str()));
            }
        }
        if !snapshot.exemptions.is_empty() {
            out.push_str("exemptions:\n");
            for exemption in &snapshot.exemptions {
                out.push_str(&format!(
                    "  - {:<24} {}\n",
                    exemption.subject, exemption.reason
                ));
            }
        }
        out.push_str(&format!(
            "blocked egress attempts: {}\n",
            snapshot.blocked_egress_attempts
        ));
        out
    }

    fn describe_state(state: ProtectionState) -> String {
        match state {
            ProtectionState::Off => "off — traffic is not protected".to_string(),
            ProtectionState::Applying => "applying — a transition is in progress".to_string(),
            ProtectionState::Protected => "protected — and verified".to_string(),
            ProtectionState::Degraded => "protected, but unverified".to_string(),
            ProtectionState::Blocked => "blocked — no traffic can leave".to_string(),
            ProtectionState::Portal => "captive portal — protection is relaxed".to_string(),
        }
    }

    fn describe_scope(scope: Scope) -> String {
        match scope {
            Scope::Off => "off".to_string(),
            Scope::Dns => "encrypted DNS".to_string(),
            Scope::App => "chosen applications".to_string(),
            Scope::User => "your processes".to_string(),
            Scope::System => "the whole system".to_string(),
        }
    }

    fn describe_verification(verification: ghostnector_spec::Verification) -> &'static str {
        match verification {
            ghostnector_spec::Verification::Unknown => "not checked yet",
            ghostnector_spec::Verification::Fresh => "checked recently",
            ghostnector_spec::Verification::Stale => "not checked recently",
            ghostnector_spec::Verification::Unavailable => "nothing can verify it yet",
            ghostnector_spec::Verification::Failed => "CHECKED AND FAILED",
        }
    }

    // ------------------------------------------------------------------ transport

    struct Session {
        writer: UnixStream,
        reader: BufReader<UnixStream>,
    }

    impl Session {
        fn open(path: &Path) -> Result<Self, String> {
            let stream = UnixStream::connect(path).map_err(|error| {
                format!(
                    "cannot reach the control plane at '{}': {error}. Is ghostnector-core running?",
                    path.display()
                )
            })?;
            let writer = stream
                .try_clone()
                .map_err(|error| format!("cannot use the connection: {error}"))?;
            let mut session = Self {
                writer,
                reader: BufReader::new(stream),
            };
            let answer = session.send(&Request::Hello {
                protocol: PROTOCOL_VERSION,
                client: format!("ghostnector-cli/{VERSION}"),
            })?;
            match answer {
                Response::Hello { .. } => Ok(session),
                Response::Error(body) => Err(explain(body)),
                other => Err(unexpected(other)),
            }
        }

        fn send(&mut self, request: &Request) -> Result<Response, String> {
            let mut encoded = serde_json::to_vec(&Frame::Request(request.clone()))
                .map_err(|error| error.to_string())?;
            encoded.push(b'\n');
            self.writer
                .write_all(&encoded)
                .map_err(|error| format!("cannot talk to the control plane: {error}"))?;
            match read_frame(&mut self.reader)? {
                Frame::Response(response) => Ok(response),
                Frame::Event(_) => {
                    Err("the daemon sent an event when an answer was expected".into())
                }
                Frame::Request(_) => Err("the daemon sent a request".into()),
            }
        }

        fn watch(&mut self) -> Result<(), String> {
            match self.send(&Request::Subscribe)? {
                Response::Accepted => {}
                Response::Error(body) => return Err(explain(body)),
                other => return Err(unexpected(other)),
            }
            loop {
                match read_frame(&mut self.reader)? {
                    Frame::Event(ghostnector_spec::Event::StateChanged(snapshot)) => {
                        print!("{}", render(&snapshot));
                        println!("---");
                    }
                    Frame::Event(ghostnector_spec::Event::Notice { message }) => {
                        println!("note: {message}");
                    }
                    Frame::Event(other) => println!("{other:?}"),
                    Frame::Response(other) => println!("{other:?}"),
                    Frame::Request(_) => {}
                }
            }
        }
    }

    fn read_frame(reader: &mut impl BufRead) -> Result<Frame, String> {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .map_err(|error| format!("cannot read from the control plane: {error}"))?;
        if read == 0 {
            return Err("the control plane closed the connection".to_string());
        }
        serde_json::from_str(&line).map_err(|error| format!("unintelligible reply: {error}"))
    }

    // ------------------------------------------------------------------ arguments

    fn parse<I>(arguments: I) -> Result<(PathBuf, Command), String>
    where
        I: Iterator<Item = String>,
    {
        let mut socket = PathBuf::from(DEFAULT_SOCKET);
        let mut command: Option<Command> = None;
        let mut scope = Scope::System;
        let mut lan = false;

        let mut arguments = arguments.peekable();
        while let Some(argument) = arguments.next() {
            let mut value = || {
                arguments
                    .next()
                    .ok_or_else(|| format!("option '{argument}' needs a value"))
            };
            match argument.as_str() {
                "--socket" => {
                    let raw = value()?;
                    if !raw.starts_with('/') {
                        return Err("--socket needs an absolute path".to_string());
                    }
                    socket = PathBuf::from(raw);
                }
                "status" => command = Some(Command::Status),
                "connect" => {
                    command = Some(Command::Connect {
                        scope: Scope::System,
                        lan: false,
                    })
                }
                "disconnect" => command = Some(Command::Disconnect),
                "panic" => command = Some(Command::Panic),
                "watch" => command = Some(Command::Watch),
                "--scope" => {
                    scope = match value()?.as_str() {
                        "system" => Scope::System,
                        "user" => Scope::User,
                        "dns" => Scope::Dns,
                        other => {
                            return Err(format!(
                                "unknown scope '{other}'; expected system, user, or dns"
                            ))
                        }
                    };
                    command = Some(Command::Connect { scope, lan: false });
                }
                "--lan" => {
                    lan = true;
                    command = Some(Command::Connect { scope, lan });
                }
                other => return Err(format!("unknown argument '{other}'\n\n{USAGE}")),
            }
        }

        // `--scope` and `--lan` may arrive in either order, so apply what was collected last.
        if let Some(Command::Connect { .. }) = command {
            command = Some(Command::Connect { scope, lan });
        }

        match command {
            Some(command) => Ok((socket, command)),
            None => Err(format!("no command given\n\n{USAGE}")),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn args(list: &[&str]) -> std::vec::IntoIter<String> {
            list.iter()
                .map(|value| value.to_string())
                .collect::<Vec<String>>()
                .into_iter()
        }

        #[test]
        fn status_is_the_default_shape_of_a_command() {
            let (socket, command) = parse(args(&["status"])).expect("parse");
            assert_eq!(socket, PathBuf::from(DEFAULT_SOCKET));
            assert!(matches!(command, Command::Status));
        }

        #[test]
        fn connect_defaults_to_the_whole_system_over_tor() {
            let (_, command) = parse(args(&["connect"])).expect("parse");
            match command {
                Command::Connect { scope, lan } => {
                    assert_eq!(scope, Scope::System);
                    assert!(!lan);
                }
                _ => panic!("expected a connect"),
            }
        }

        #[test]
        fn scope_and_lan_can_arrive_in_either_order() {
            for list in [
                args(&["connect", "--scope", "user", "--lan"]),
                args(&["connect", "--lan", "--scope", "user"]),
            ] {
                match parse(list).expect("parse").1 {
                    Command::Connect { scope, lan } => {
                        assert_eq!(scope, Scope::User);
                        assert!(lan);
                    }
                    _ => panic!("expected a connect"),
                }
            }
        }

        #[test]
        fn an_unknown_command_is_refused() {
            assert!(parse(args(&["teleport"])).is_err());
        }

        #[test]
        fn an_unknown_scope_is_refused() {
            assert!(parse(args(&["connect", "--scope", "galaxy"])).is_err());
        }

        #[test]
        fn a_relative_socket_is_refused() {
            assert!(parse(args(&["--socket", "run/core.sock", "status"])).is_err());
        }

        #[test]
        fn rendering_never_calls_an_unverified_state_protected() {
            let snapshot = Snapshot {
                state: ProtectionState::Degraded,
                health: ghostnector_spec::Health {
                    policy_applied: true,
                    verification: ghostnector_spec::Verification::Unavailable,
                    ..Default::default()
                },
                reasons: vec![ghostnector_spec::Reason::new("nothing verified this")],
                ..Default::default()
            };
            let text = render(&snapshot);
            assert!(text.contains("protected, but unverified"), "{text}");
            assert!(text.contains("nothing can verify it yet"), "{text}");
            assert!(
                !text.contains("protected — and verified"),
                "a degraded state must not read as verified: {text}"
            );
        }

        #[test]
        fn an_off_state_says_so_plainly() {
            let text = render(&Snapshot::default());
            assert!(text.contains("traffic is not protected"), "{text}");
        }
    }
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    inner::main()
}

#[cfg(not(unix))]
fn main() {
    eprintln!("ghostnector is a Linux component and cannot run on this platform");
    std::process::exit(2);
}
