//! `ghostnector` — the command-line client.
//!
//! It is deliberately dumb: it hands a request to the control plane and prints the answer. It holds
//! no state, needs no privileges, and knows nothing about nftables. Everything it shows comes from a
//! snapshot the daemon produced, so the command cannot disagree with the daemon about reality.

#[cfg(unix)]
mod inner {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;

    use ghostnector_spec::ipc::{ErrorBody, Frame, Request, Response, PROTOCOL_VERSION};
    use ghostnector_spec::{display, AppStatus, Networks, Profile, Scope, Snapshot};

    const DEFAULT_SOCKET: &str = "/run/ghostnector/core.sock";
    const VERSION: &str = env!("CARGO_PKG_VERSION");

    const USAGE: &str = "\
ghostnector - network privacy, from the command line

USAGE:
    ghostnector [--socket <PATH>] <COMMAND>

COMMANDS:
    status                       show the current state and why it is that way
    connect [--network <NET>]    protect this machine (default network: tor)
            [--scope <SCOPE>]    (default scope: system)
            [--lan]              also allow reaching the local network
    disconnect                   return to the network as it was before
    panic                        deny everything now, leaving services running
    run [-- <COMMAND>...]        open a protected application session (APP scope);
                                 with a command, run it there instead of a shell
    apps                         list the protected applications
    stop-app <ID>                stop one protected application
    watch                        follow state changes until interrupted

NETWORKS:
    tor      through the Tor network (default)
    i2p      through the I2P network (whole system only)

SCOPES:
    system   every process on the machine (default)
    user     only processes belonging to you
    app      only applications you launch through `ghostnector run`
    dns      encrypted DNS only, no Tor

OPTIONS:
    --socket <PATH>   where the control plane listens
                                         [default: /run/ghostnector/core.sock]
    -h, --help        print this text
    -V, --version     print the version";

    enum Command {
        Status,
        Connect {
            scope: Scope,
            network: Network,
            lan: bool,
        },
        Disconnect,
        Panic,
        Run {
            command: Option<String>,
        },
        Apps,
        StopApp {
            id: u32,
        },
        Watch,
    }

    /// The overlay network a connect asks for. The daemon validates the combination; this is just
    /// the user's choice.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Network {
        Tor,
        I2p,
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
            Command::Connect {
                scope,
                network,
                lan,
            } => {
                let networks = match (scope, network) {
                    (Scope::Dns, _) => Networks::none(),
                    (_, Network::I2p) => Networks::i2p(),
                    _ => Networks::tor(),
                };
                let profile = Profile {
                    scope,
                    networks,
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
            Command::Run { command } => {
                let response = session.send(&Request::AppRun)?;
                let socket = match response {
                    Response::AppSession { socket, .. } => socket,
                    Response::Error(body) => return Err(explain(body)),
                    other => return Err(unexpected(other)),
                };
                run_session(&socket, command)
            }
            Command::Apps => match session.send(&Request::AppList)? {
                Response::AppList { apps } => {
                    print!("{}", render_apps(&apps));
                    Ok(())
                }
                other => Err(unexpected(other)),
            },
            Command::StopApp { id } => {
                let response = session.send(&Request::AppStop { id })?;
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

    /// Drive a prepared session: optionally run a command in it, then relay standard input and
    /// output until the session ends.
    ///
    /// The command is written to the *user's own shell* inside the namespace, as the user. It never
    /// crosses a privileged interface: the kernel already decided who may connect to the session.
    fn run_session(socket: &str, command: Option<String>) -> Result<(), String> {
        let stream = UnixStream::connect(socket)
            .map_err(|error| format!("cannot open the protected session at '{socket}': {error}"))?;
        let mut writer = stream
            .try_clone()
            .map_err(|error| format!("cannot use the session: {error}"))?;
        if let Some(command) = command {
            writeln!(writer, "exec {command}")
                .map_err(|error| format!("cannot start the command: {error}"))?;
            writer
                .flush()
                .map_err(|error| format!("cannot start the command: {error}"))?;
        }

        let input = std::thread::spawn(move || {
            let mut stdin = std::io::stdin();
            let mut buffer = [0u8; 4096];
            loop {
                match stdin.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        if writer.write_all(&buffer[..count]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = writer.shutdown(std::net::Shutdown::Write);
        });

        let mut reader = stream;
        let mut stdout = std::io::stdout();
        let mut buffer = [0u8; 4096];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    stdout
                        .write_all(&buffer[..count])
                        .map_err(|error| format!("cannot write output: {error}"))?;
                    let _ = stdout.flush();
                }
                Err(error) => return Err(format!("the session ended unexpectedly: {error}")),
            }
        }
        let _ = input.join();
        Ok(())
    }

    fn render_apps(apps: &[AppStatus]) -> String {
        if apps.is_empty() {
            return "no protected applications are running\n".to_string();
        }
        let mut out = String::new();
        out.push_str("protected applications:\n");
        for app in apps {
            out.push_str(&format!(
                "  - {:<3} {}  {}\n",
                app.id,
                app.address,
                if app.present {
                    "running"
                } else {
                    "not present"
                }
            ));
        }
        out
    }

    fn unexpected(response: Response) -> String {
        format!("the daemon answered something unexpected: {response:?}")
    }

    // ------------------------------------------------------------------ rendering

    fn render(snapshot: &Snapshot) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "state:        {}\n",
            display::state_line(snapshot)
        ));
        if let Some(profile) = &snapshot.profile {
            out.push_str(&format!(
                "profile:      {} ({})\n",
                display::scope_line(profile.scope),
                display::network_line(profile)
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
            display::verification_line(snapshot.health.verification)
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
        if !snapshot.apps.is_empty() {
            out.push_str(&render_apps(&snapshot.apps));
        }
        out.push_str(&format!(
            "blocked egress attempts: {}\n",
            snapshot.blocked_egress_attempts
        ));
        out
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
        let mut network = Network::Tor;
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
                        network: Network::Tor,
                        lan: false,
                    })
                }
                "disconnect" => command = Some(Command::Disconnect),
                "panic" => command = Some(Command::Panic),
                "apps" => command = Some(Command::Apps),
                "run" => {
                    // Everything after `run` (or after `--`) is the command to run in the session.
                    // It never crosses a privileged interface: the CLI writes it to the user's own
                    // shell over the session socket, as the user.
                    let mut rest: Vec<String> = arguments.collect();
                    if rest.first().map(String::as_str) == Some("--") {
                        rest.remove(0);
                    }
                    let joined = rest.join(" ");
                    command = Some(Command::Run {
                        command: if joined.trim().is_empty() {
                            None
                        } else {
                            Some(joined)
                        },
                    });
                    break;
                }
                "stop-app" => {
                    let raw = value()?;
                    let id: u32 = raw
                        .parse()
                        .map_err(|_| format!("'{raw}' is not an application id"))?;
                    command = Some(Command::StopApp { id });
                }
                "watch" => command = Some(Command::Watch),
                "--network" => {
                    network = match value()?.as_str() {
                        "tor" => Network::Tor,
                        "i2p" => Network::I2p,
                        other => {
                            return Err(format!("unknown network '{other}'; expected tor or i2p"))
                        }
                    };
                    command = Some(Command::Connect {
                        scope,
                        network,
                        lan,
                    });
                }
                "--scope" => {
                    scope = match value()?.as_str() {
                        "system" => Scope::System,
                        "user" => Scope::User,
                        "app" => Scope::App,
                        "dns" => Scope::Dns,
                        other => {
                            return Err(format!(
                                "unknown scope '{other}'; expected system, user, app, or dns"
                            ))
                        }
                    };
                    command = Some(Command::Connect {
                        scope,
                        network,
                        lan,
                    });
                }
                "--lan" => {
                    lan = true;
                    command = Some(Command::Connect {
                        scope,
                        network,
                        lan,
                    });
                }
                other => return Err(format!("unknown argument '{other}'\n\n{USAGE}")),
            }
        }

        // `--network`, `--scope` and `--lan` may arrive in any order, so apply what was collected.
        if let Some(Command::Connect { .. }) = command {
            command = Some(Command::Connect {
                scope,
                network,
                lan,
            });
        }

        match command {
            Some(command) => Ok((socket, command)),
            None => Err(format!("no command given\n\n{USAGE}")),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ghostnector_spec::ProtectionState;

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
                Command::Connect {
                    scope,
                    network,
                    lan,
                } => {
                    assert_eq!(scope, Scope::System);
                    assert_eq!(network, Network::Tor);
                    assert!(!lan);
                }
                _ => panic!("expected a connect"),
            }
        }

        #[test]
        fn i2p_is_selectable_and_an_unknown_network_is_refused() {
            match parse(args(&["connect", "--network", "i2p"]))
                .expect("parse")
                .1
            {
                Command::Connect {
                    scope,
                    network,
                    lan,
                } => {
                    assert_eq!(scope, Scope::System);
                    assert_eq!(network, Network::I2p);
                    assert!(!lan);
                }
                _ => panic!("expected a connect"),
            }
            assert!(parse(args(&["connect", "--network", "galaxy"])).is_err());
        }

        #[test]
        fn scope_and_lan_can_arrive_in_either_order() {
            for list in [
                args(&["connect", "--scope", "user", "--lan"]),
                args(&["connect", "--lan", "--scope", "user"]),
            ] {
                match parse(list).expect("parse").1 {
                    Command::Connect { scope, lan, .. } => {
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
        fn app_scope_is_accepted_and_run_takes_the_command_it_is_given() {
            match parse(args(&["connect", "--scope", "app"]))
                .expect("parse")
                .1
            {
                Command::Connect { scope, lan, .. } => {
                    assert_eq!(scope, Scope::App);
                    assert!(!lan);
                }
                _ => panic!("expected a connect"),
            }
            match parse(args(&["run"])).expect("parse").1 {
                Command::Run { command } => assert!(command.is_none()),
                _ => panic!("expected a run"),
            }
            match parse(args(&["run", "--", "firefox", "--new-window"]))
                .expect("parse")
                .1
            {
                Command::Run { command } => {
                    assert_eq!(command.as_deref(), Some("firefox --new-window"))
                }
                _ => panic!("expected a run"),
            }
            match parse(args(&["run", "firefox"])).expect("parse").1 {
                Command::Run { command } => assert_eq!(command.as_deref(), Some("firefox")),
                _ => panic!("expected a run"),
            }
            match parse(args(&["apps"])).expect("parse").1 {
                Command::Apps => {}
                _ => panic!("expected an apps listing"),
            }
            match parse(args(&["stop-app", "3"])).expect("parse").1 {
                Command::StopApp { id } => assert_eq!(id, 3),
                _ => panic!("expected a stop"),
            }
            assert!(parse(args(&["stop-app", "many"])).is_err());
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
