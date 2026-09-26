//! The connection to `ghostnector-core`: one control connection and one subscription.
//!
//! Two connections are required by the protocol: `Subscribe` turns a connection into an event
//! stream and the daemon never reads another request from it. The worker owns both, serialises
//! actions, and produces [`CoreUpdate`]s for the model. On any loss it closes both, reports
//! `Disconnected`, waits, and starts a **new epoch**; the model discards anything older.

#[cfg(unix)]
pub use unix::*;

#[cfg(unix)]
mod unix {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
    use std::time::{Duration, Instant};

    use ghostnector_spec::ipc::{Frame, Request, Response, PROTOCOL_VERSION};
    use ghostnector_spec::Profile;

    use crate::model::CoreUpdate;

    /// What the window asks the core to do. Typed on purpose: the window cannot send a raw frame.
    #[derive(Clone, Debug)]
    pub enum CoreCommand {
        /// Apply a profile.
        Connect(Box<Profile>),
        /// Return to the captured baseline.
        Disconnect,
        /// Apply the fail-closed baseline now.
        Panic,
        /// Prepare a protected session.
        AppRun,
        /// Stop one group.
        AppStop(u32),
        /// End the worker.
        Stop,
    }

    /// The handle the window holds. It cannot block the UI thread: it only posts commands.
    pub struct CoreHandle {
        /// Updates from the worker; the UI polls this.
        pub updates: Receiver<CoreUpdate>,
        commands: Sender<CoreCommand>,
    }

    impl CoreHandle {
        /// Post a command. Fails only if the worker has stopped.
        pub fn send(&self, command: CoreCommand) -> Result<(), String> {
            self.commands
                .send(command)
                .map_err(|_| "the Ghostnector client has stopped".to_string())
        }

        /// Ask the worker to stop.
        pub fn stop(&self) {
            let _ = self.commands.send(CoreCommand::Stop);
        }
    }

    /// Start the worker against a core socket. Never fails: the first update reports a failure to
    /// reach the socket, which is exactly what an unreachable service is.
    pub fn spawn(socket: PathBuf) -> CoreHandle {
        let (update_tx, updates) = mpsc::channel();
        let (commands, command_rx) = mpsc::channel();
        let _ = std::thread::Builder::new()
            .name("ghostnector-gui-core".to_string())
            .spawn(move || work(socket, update_tx, command_rx));
        CoreHandle { updates, commands }
    }

    const RECONNECT_DELAY: Duration = Duration::from_secs(2);
    const EVENT_POLL: Duration = Duration::from_millis(100);
    const COMMAND_POLL: Duration = Duration::from_millis(50);
    const CLIENT_NAME: &str = concat!("ghostnector-gui/", env!("CARGO_PKG_VERSION"));

    enum SessionEnd {
        Stopped,
        Lost(String),
    }

    fn work(socket: PathBuf, updates: Sender<CoreUpdate>, commands: Receiver<CoreCommand>) {
        let mut epoch = 0u64;
        loop {
            epoch += 1;
            let _ = updates.send(CoreUpdate::Connecting { epoch });
            match session(&socket, epoch, &updates, &commands) {
                SessionEnd::Stopped => return,
                SessionEnd::Lost(reason) => {
                    let _ = updates.send(CoreUpdate::Disconnected { epoch, reason });
                }
            }

            // Wait before reconnecting, but never hold a command hostage: a request while
            // disconnected gets an immediate, honest failure instead of disappearing.
            let deadline = Instant::now() + RECONNECT_DELAY;
            loop {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                match commands.recv_timeout(deadline - now) {
                    Ok(CoreCommand::Stop) => return,
                    Ok(_) => {
                        let _ = updates.send(CoreUpdate::Notice {
                            message:
                                "The Ghostnector service cannot be reached, so the request was \
                                      not sent."
                                    .to_string(),
                        });
                    }
                    Err(RecvTimeoutError::Timeout) => break,
                    Err(RecvTimeoutError::Disconnected) => return,
                }
            }
        }
    }

    fn session(
        socket: &PathBuf,
        epoch: u64,
        updates: &Sender<CoreUpdate>,
        commands: &Receiver<CoreCommand>,
    ) -> SessionEnd {
        // Control connection: handshake, then one request at a time, exactly like the CLI.
        let control = match UnixStream::connect(socket) {
            Ok(stream) => stream,
            Err(error) => {
                return SessionEnd::Lost(format!(
                    "cannot reach the Ghostnector service at '{}': {error}",
                    socket.display()
                ))
            }
        };
        let control_clone = match control.try_clone() {
            Ok(stream) => stream,
            Err(error) => return SessionEnd::Lost(format!("cannot use the connection: {error}")),
        };
        let mut control_writer = control;
        let mut control_reader = FrameReader::new(BufReader::new(control_clone));

        let daemon_version = match handshake(&mut control_writer, &mut control_reader) {
            Ok(version) => version,
            Err(reason) => return SessionEnd::Lost(reason),
        };
        let _ = updates.send(CoreUpdate::Connected {
            epoch,
            daemon_version,
        });

        // Subscription connection: handshake, subscribe, then events only.
        let events = match UnixStream::connect(socket) {
            Ok(stream) => stream,
            Err(error) => {
                return SessionEnd::Lost(format!(
                    "cannot reach the Ghostnector service for state updates: {error}"
                ))
            }
        };
        let events_clone = match events.try_clone() {
            Ok(stream) => stream,
            Err(error) => return SessionEnd::Lost(format!("cannot use the connection: {error}")),
        };
        let mut event_writer = events;
        let mut event_reader = FrameReader::new(BufReader::new(events_clone));

        match handshake(&mut event_writer, &mut event_reader) {
            Ok(_) => {}
            Err(reason) => return SessionEnd::Lost(reason),
        }
        // Subscribe on the event connection: the daemon turns that connection into a stream and
        // never reads another request from it.
        if let Err(reason) = send(&mut event_writer, &Request::Subscribe) {
            return SessionEnd::Lost(reason);
        }
        match event_reader.read() {
            Ok(Frame::Response(Response::Accepted)) => {}
            Ok(Frame::Response(Response::Error(body))) => return SessionEnd::Lost(body.message),
            Ok(_) => {
                return SessionEnd::Lost(
                    "the service answered the subscription unexpectedly".to_string(),
                )
            }
            Err(reason) => return SessionEnd::Lost(reason),
        }
        // Only now that the handshake is done does the event socket become a poll: a timeout during
        // the handshake would look like a lost connection.
        if let Err(error) = event_writer.set_read_timeout(Some(EVENT_POLL)) {
            return SessionEnd::Lost(format!("cannot set an event timeout: {error}"));
        }

        // The authoritative snapshot before anything else.
        match request(
            &mut control_writer,
            &mut control_reader,
            &Request::Snapshot,
            epoch,
            updates,
        ) {
            Ok(()) => {}
            Err(reason) => return SessionEnd::Lost(reason),
        }

        loop {
            // Drain every pending event before waiting for a command: a transition emits a burst.
            loop {
                match event_reader.poll() {
                    Ok(Some(Frame::Event(event))) => {
                        let _ = updates.send(CoreUpdate::Event { epoch, event });
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(reason) => {
                        return SessionEnd::Lost(format!("the state subscription ended: {reason}"))
                    }
                }
            }

            match commands.recv_timeout(COMMAND_POLL) {
                Ok(CoreCommand::Stop) => return SessionEnd::Stopped,
                Ok(CoreCommand::Connect(profile)) => {
                    if let Err(reason) = request(
                        &mut control_writer,
                        &mut control_reader,
                        &Request::Connect { profile: *profile },
                        epoch,
                        updates,
                    ) {
                        return SessionEnd::Lost(reason);
                    }
                }
                Ok(CoreCommand::Disconnect) => {
                    if let Err(reason) = request(
                        &mut control_writer,
                        &mut control_reader,
                        &Request::Disconnect,
                        epoch,
                        updates,
                    ) {
                        return SessionEnd::Lost(reason);
                    }
                }
                Ok(CoreCommand::Panic) => {
                    if let Err(reason) = request(
                        &mut control_writer,
                        &mut control_reader,
                        &Request::Panic,
                        epoch,
                        updates,
                    ) {
                        return SessionEnd::Lost(reason);
                    }
                }
                Ok(CoreCommand::AppRun) => {
                    if let Err(reason) =
                        app_run(&mut control_writer, &mut control_reader, epoch, updates)
                    {
                        return SessionEnd::Lost(reason);
                    }
                }
                Ok(CoreCommand::AppStop(id)) => {
                    if let Err(reason) = request(
                        &mut control_writer,
                        &mut control_reader,
                        &Request::AppStop { id },
                        epoch,
                        updates,
                    ) {
                        return SessionEnd::Lost(reason);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return SessionEnd::Stopped,
            }
        }
    }

    /// A protocol-level drain: responses that carry state become updates; refusals become notices.
    fn request(
        writer: &mut UnixStream,
        reader: &mut FrameReader,
        request: &Request,
        epoch: u64,
        updates: &Sender<CoreUpdate>,
    ) -> Result<(), String> {
        send(writer, request)?;
        match reader.read() {
            Ok(Frame::Response(response)) => {
                absorb_response(response, epoch, updates);
                Ok(())
            }
            Ok(Frame::Event(_)) => {
                Err("the service sent an event when an answer was due".to_string())
            }
            Ok(Frame::Request(_)) => Err("the service sent a request".to_string()),
            Err(reason) => Err(reason),
        }
    }

    fn app_run(
        writer: &mut UnixStream,
        reader: &mut FrameReader,
        epoch: u64,
        updates: &Sender<CoreUpdate>,
    ) -> Result<(), String> {
        send(writer, &Request::AppRun)?;
        match reader.read() {
            Ok(Frame::Response(Response::AppSession { id, socket })) => {
                let _ = updates.send(CoreUpdate::AppSession { id, socket });
                Ok(())
            }
            Ok(Frame::Response(other)) => {
                absorb_response(other, epoch, updates);
                Ok(())
            }
            Ok(_) => Err("the service answered the session request unexpectedly".to_string()),
            Err(reason) => Err(reason),
        }
    }

    fn absorb_response(response: Response, epoch: u64, updates: &Sender<CoreUpdate>) {
        match response {
            Response::Snapshot(snapshot) => {
                let _ = updates.send(CoreUpdate::Snapshot { epoch, snapshot });
            }
            Response::Error(body) => {
                let _ = updates.send(CoreUpdate::Notice {
                    message: body.message,
                });
            }
            Response::Hello { .. } | Response::Accepted | Response::AppSession { .. } => {}
            Response::AppList { .. } => {}
        }
    }

    fn handshake(writer: &mut UnixStream, reader: &mut FrameReader) -> Result<String, String> {
        send(
            writer,
            &Request::Hello {
                protocol: PROTOCOL_VERSION,
                client: CLIENT_NAME.to_string(),
            },
        )?;
        match reader.read() {
            Ok(Frame::Response(Response::Hello { daemon_version, .. })) => Ok(daemon_version),
            Ok(Frame::Response(Response::Error(body))) => Err(body.message),
            Ok(_) => Err("the service answered the handshake unexpectedly".to_string()),
            Err(reason) => Err(reason),
        }
    }

    fn send(writer: &mut UnixStream, request: &Request) -> Result<(), String> {
        let mut encoded = serde_json::to_vec(&Frame::Request(request.clone()))
            .map_err(|error| format!("cannot encode a request: {error}"))?;
        encoded.push(b'\n');
        writer
            .write_all(&encoded)
            .map_err(|error| format!("cannot talk to the Ghostnector service: {error}"))?;
        writer
            .flush()
            .map_err(|error| format!("cannot talk to the Ghostnector service: {error}"))
    }

    /// A line-framed reader that can be polled without losing a partially read line.
    struct FrameReader {
        reader: BufReader<UnixStream>,
        buffer: String,
    }

    impl FrameReader {
        fn new(reader: BufReader<UnixStream>) -> Self {
            Self {
                reader,
                buffer: String::new(),
            }
        }

        /// Read one frame, blocking as long as the underlying stream allows.
        fn read(&mut self) -> Result<Frame, String> {
            loop {
                if let Some(frame) = self.take_buffered()? {
                    return Ok(frame);
                }
                let mut chunk = String::new();
                match self.reader.read_line(&mut chunk) {
                    Ok(0) => return Err("the service closed the connection".to_string()),
                    Ok(_) => self.buffer.push_str(&chunk),
                    Err(error) => return Err(format!("cannot read from the service: {error}")),
                }
            }
        }

        /// Read one frame if one is complete, `None` on timeout with nothing buffered whole.
        fn poll(&mut self) -> Result<Option<Frame>, String> {
            if let Some(frame) = self.take_buffered()? {
                return Ok(Some(frame));
            }
            let mut chunk = String::new();
            match self.reader.read_line(&mut chunk) {
                Ok(0) => Err("the service closed the connection".to_string()),
                Ok(_) => {
                    self.buffer.push_str(&chunk);
                    if let Some(frame) = self.take_buffered()? {
                        return Ok(Some(frame));
                    }
                    Ok(None)
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::TimedOut =>
                {
                    // Partial data (if any, already in `chunk`) stays for the next poll.
                    self.buffer.push_str(&chunk);
                    Ok(None)
                }
                Err(error) => Err(format!("cannot read from the service: {error}")),
            }
        }

        fn take_buffered(&mut self) -> Result<Option<Frame>, String> {
            let Some(index) = self.buffer.find('\n') else {
                return Ok(None);
            };
            let line: String = self.buffer.drain(..=index).collect();
            let line = line.trim();
            if line.is_empty() {
                return Ok(None);
            }
            serde_json::from_str(line)
                .map(Some)
                .map_err(|error| format!("the service sent something unreadable: {error}"))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ghostnector_spec::ipc::{ErrorBody, ErrorCode, PROTOCOL_VERSION};
        use ghostnector_spec::{Event, Health, ProtectionState, Snapshot};
        use std::os::unix::net::UnixListener;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::{Arc, Mutex};

        static NEXT: AtomicU64 = AtomicU64::new(0);

        fn socket_path() -> PathBuf {
            std::env::temp_dir().join(format!(
                "gh-gui-test-{}-{}.sock",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ))
        }

        struct FakeCore {
            path: PathBuf,
        }

        impl FakeCore {
            /// A core that answers the handshake, snapshots and actions, and pushes subscribed
            /// events from a queue the test can fill.
            fn start(protected: bool) -> Self {
                let path = socket_path();
                let _ = std::fs::remove_file(&path);
                let listener = UnixListener::bind(&path).expect("bind");
                let pending: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(Vec::new()));
                let queue = Arc::clone(&pending);
                std::thread::spawn(move || {
                    for stream in listener.incoming() {
                        let Ok(stream) = stream else { break };
                        let queue = Arc::clone(&queue);
                        std::thread::spawn(move || serve(stream, protected, queue));
                    }
                });
                Self { path }
            }
        }

        impl Drop for FakeCore {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.path);
            }
        }

        fn serve(stream: UnixStream, protected: bool, queue: Arc<Mutex<Vec<Event>>>) {
            let clone = stream.try_clone().expect("clone");
            let mut reader = BufReader::new(clone);
            let mut writer = stream;
            let mut subscribed = false;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let Ok(Frame::Request(request)) = serde_json::from_str::<Frame>(line.trim()) else {
                    return;
                };
                match request {
                    Request::Hello { protocol, .. } => {
                        let response = if protocol == PROTOCOL_VERSION {
                            Response::Hello {
                                protocol: PROTOCOL_VERSION,
                                daemon_version: "0.1.0-test".to_string(),
                            }
                        } else {
                            Response::Error(ErrorBody {
                                code: ErrorCode::ProtocolMismatch,
                                message: "protocol mismatch".to_string(),
                                sensitive: false,
                            })
                        };
                        write(&mut writer, &Frame::Response(response));
                    }
                    Request::Snapshot => {
                        let snapshot = Snapshot {
                            state: if protected {
                                ProtectionState::Protected
                            } else {
                                ProtectionState::Off
                            },
                            generation: 1,
                            ..Snapshot::default()
                        };
                        write(
                            &mut writer,
                            &Frame::Response(Response::Snapshot(Box::new(snapshot))),
                        );
                    }
                    Request::Subscribe => {
                        write(&mut writer, &Frame::Response(Response::Accepted));
                        subscribed = true;
                    }
                    Request::Connect { .. } => {
                        write(&mut writer, &Frame::Response(Response::Accepted));
                        queue
                            .lock()
                            .expect("queue")
                            .push(Event::StateChanged(Box::new(Snapshot {
                                state: ProtectionState::Degraded,
                                generation: 2,
                                ..Snapshot::default()
                            })));
                    }
                    Request::Disconnect => {
                        write(&mut writer, &Frame::Response(Response::Accepted));
                        queue
                            .lock()
                            .expect("queue")
                            .push(Event::StateChanged(Box::new(Snapshot {
                                state: ProtectionState::Off,
                                generation: 3,
                                ..Snapshot::default()
                            })));
                    }
                    Request::Panic => {
                        write(&mut writer, &Frame::Response(Response::Accepted));
                        queue
                            .lock()
                            .expect("queue")
                            .push(Event::StateChanged(Box::new(Snapshot {
                                state: ProtectionState::Blocked,
                                generation: 4,
                                ..Snapshot::default()
                            })));
                    }
                    Request::AppRun => {
                        write(
                            &mut writer,
                            &Frame::Response(Response::AppSession {
                                id: 3,
                                socket: "/tmp/gh-session.sock".to_string(),
                            }),
                        );
                    }
                    Request::AppStop { .. } | Request::Cancel | Request::AppList => {
                        write(&mut writer, &Frame::Response(Response::Accepted));
                    }
                }
                if subscribed {
                    // Keep this connection open and let it stream whatever the test pushes.
                    loop {
                        let events: Vec<Event> = queue.lock().expect("queue").drain(..).collect();
                        for event in events {
                            write(&mut writer, &Frame::Event(event));
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }
        }

        fn write(writer: &mut UnixStream, frame: &Frame) {
            let mut encoded = serde_json::to_vec(frame).expect("encode");
            encoded.push(b'\n');
            let _ = writer.write_all(&encoded);
            let _ = writer.flush();
        }

        fn next_update(handle: &CoreHandle, millis: u64) -> Option<CoreUpdate> {
            handle
                .updates
                .recv_timeout(Duration::from_millis(millis))
                .ok()
        }

        fn wait_for<T>(mut read: impl FnMut() -> Option<T>, millis: u64) -> Option<T> {
            let deadline = Instant::now() + Duration::from_millis(millis);
            loop {
                if let Some(value) = read() {
                    return Some(value);
                }
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        #[test]
        fn connects_handshakes_and_accepts_the_authoritative_snapshot() {
            let core = FakeCore::start(false);
            let handle = spawn(core.path.clone());
            let mut model = crate::model::Model::default();
            let deadline = Instant::now() + Duration::from_secs(4);
            while Instant::now() < deadline {
                while let Some(update) = next_update(&handle, 100) {
                    model.apply(update);
                }
                if model.current().is_some() {
                    break;
                }
            }
            assert!(
                matches!(model.link(), crate::model::LinkState::Connected { .. }),
                "the handshake must complete: {:?}",
                model.link()
            );
            assert_eq!(model.daemon_version(), Some("0.1.0-test"));
            assert_eq!(
                model.current().expect("the authoritative snapshot").state,
                ProtectionState::Off
            );
            handle.stop();
        }

        #[test]
        fn a_command_reaches_the_core_and_its_event_reaches_the_model() {
            let core = FakeCore::start(false);
            let handle = spawn(core.path.clone());
            let mut model = crate::model::Model::default();
            wait_for(
                || {
                    while let Some(update) = next_update(&handle, 200) {
                        model.apply(update);
                    }
                    model.current().map(|_| ())
                },
                4000,
            )
            .expect("the first snapshot");

            handle
                .send(CoreCommand::Connect(Box::default()))
                .expect("send");
            wait_for(
                || {
                    while let Some(update) = next_update(&handle, 100) {
                        model.apply(update);
                    }
                    (model.current().map(|s| s.state) == Some(ProtectionState::Degraded))
                        .then_some(())
                },
                4000,
            )
            .expect("the applied state");
            handle.stop();
        }

        #[test]
        fn an_app_run_returns_the_session_socket() {
            let core = FakeCore::start(true);
            let handle = spawn(core.path.clone());
            let mut model = crate::model::Model::default();
            wait_for(
                || {
                    while let Some(update) = next_update(&handle, 200) {
                        model.apply(update);
                    }
                    model.current().map(|_| ())
                },
                4000,
            )
            .expect("the first snapshot");
            // The fake core answers AppStop with Accepted; force an error by sending a command the
            // fake does not implement as an error. Instead, assert the happy path returns a session.
            handle.send(CoreCommand::AppRun).expect("send");
            let session = wait_for(
                || match next_update(&handle, 200) {
                    Some(update @ CoreUpdate::AppSession { .. }) => Some(update),
                    _ => None,
                },
                4000,
            );
            match session {
                Some(CoreUpdate::AppSession { id, socket }) => {
                    assert_eq!(id, 3);
                    assert!(socket.contains("session"));
                }
                other => panic!("expected a session, got {other:?}"),
            }
            handle.stop();
        }

        #[test]
        fn a_protocol_mismatch_is_reported_with_the_daemons_own_message() {
            let path = socket_path();
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path).expect("bind");
            std::thread::spawn(move || {
                if let Ok((stream, _)) = listener.accept() {
                    let clone = stream.try_clone().expect("clone");
                    let mut reader = BufReader::new(clone);
                    let mut writer = stream;
                    let mut line = String::new();
                    let _ = reader.read_line(&mut line);
                    write(
                        &mut writer,
                        &Frame::Response(Response::Error(ErrorBody {
                            code: ErrorCode::ProtocolMismatch,
                            message: "this daemon speaks protocol 2".to_string(),
                            sensitive: false,
                        })),
                    );
                    std::thread::sleep(Duration::from_millis(300));
                }
            });
            let handle = spawn(path.clone());
            let disconnected = wait_for(
                || match next_update(&handle, 200) {
                    Some(update @ CoreUpdate::Disconnected { .. }) => Some(update),
                    _ => None,
                },
                3000,
            );
            match disconnected {
                Some(CoreUpdate::Disconnected { reason, .. }) => {
                    assert!(reason.contains("protocol 2"), "{reason}");
                }
                other => panic!("expected a disconnection, got {other:?}"),
            }
            let _ = std::fs::remove_file(&path);
            handle.stop();
        }

        #[test]
        fn an_unreachable_core_never_makes_the_window_claim_a_state() {
            let path = socket_path();
            let _ = std::fs::remove_file(&path);
            let handle = spawn(path.clone());
            let mut model = crate::model::Model::default();
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                while let Some(update) = next_update(&handle, 100) {
                    model.apply(update);
                }
                if Instant::now() >= deadline {
                    break;
                }
            }
            assert!(model.current().is_none());
            assert!(model.banner().text.contains("unknown"));
            // A request while unreachable is reported rather than dropped silently.
            handle
                .send(CoreCommand::Disconnect)
                .expect("command channel is alive");
            let notice = wait_for(
                || match next_update(&handle, 200) {
                    Some(update @ CoreUpdate::Notice { .. }) => Some(update),
                    _ => None,
                },
                4000,
            );
            assert!(notice.is_some(), "a request while down must be answered");
            handle.stop();
        }

        #[test]
        fn a_lost_connection_retries_with_a_new_epoch() {
            // A listener that accepts the first two connections, then closes everything.
            let path = socket_path();
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path).expect("bind");
            let accepted = Arc::new(AtomicU64::new(0));
            let counter = Arc::clone(&accepted);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { break };
                    let count = counter.fetch_add(1, Ordering::SeqCst);
                    if count < 2 {
                        // Answer the handshake, then drop the connection.
                        let clone = stream.try_clone().expect("clone");
                        let mut reader = BufReader::new(clone);
                        let mut writer = stream;
                        let mut line = String::new();
                        let _ = reader.read_line(&mut line);
                        write(
                            &mut writer,
                            &Frame::Response(Response::Hello {
                                protocol: PROTOCOL_VERSION,
                                daemon_version: "0.1.0-test".to_string(),
                            }),
                        );
                        std::thread::sleep(Duration::from_millis(100));
                    } else {
                        std::thread::sleep(Duration::from_millis(500));
                    }
                }
            });
            let handle = spawn(path.clone());
            let mut saw_second_epoch = false;
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut epochs: Vec<u64> = Vec::new();
            while Instant::now() < deadline {
                if let Some(CoreUpdate::Connecting { epoch }) = next_update(&handle, 100) {
                    epochs.push(epoch);
                    if epochs.len() >= 2 {
                        saw_second_epoch = true;
                        break;
                    }
                }
            }
            assert!(saw_second_epoch, "the client must retry: {epochs:?}");
            let _ = std::fs::remove_file(&path);
            handle.stop();
        }

        #[test]
        fn health_is_never_invented_by_the_client() {
            // The client forwards frames; it has no health vocabulary of its own to get wrong.
            let core = FakeCore::start(true);
            let handle = spawn(core.path.clone());
            let mut model = crate::model::Model::default();
            wait_for(
                || {
                    while let Some(update) = next_update(&handle, 200) {
                        model.apply(update);
                    }
                    model.current().map(|_| ())
                },
                4000,
            )
            .expect("the first snapshot");
            let current = model.current().expect("current");
            assert_eq!(
                current.health,
                Health::default(),
                "the fake reported no health"
            );
            handle.stop();
        }
    }
}
