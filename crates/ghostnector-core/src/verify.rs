//! Independent verification: the checks that turn "we applied a policy" into "the policy is working".
//!
//! The design rule (DR-18) is that the verifier is **inside the protected set**. It has no exemption,
//! no privilege, and no special path: it opens sockets exactly as any other program on the machine
//! does. That makes the checks meaningful, because a check that succeeds by being special proves
//! nothing. It also means *succeeding when it should not is the alarm*: if a UDP datagram gets out,
//! or the check endpoint answers with one of this machine's own addresses, something is wrong and the
//! state escalates.
//!
//! Three checks, each answering a different question:
//!
//! | Check | Question | Alarm |
//! |---|---|---|
//! | UDP egress | can anything leave outside the protected path? | a reply arrived |
//! | protected path | does the protected path actually work? | a non-200 answer, or an exit that is one of this machine's own addresses |
//! | canary | is DNS answering what it should, or being answered by someone else? | the canary resolved to something unexpected |
//!
//! Nothing here is persisted, and no address ever reaches the interface: the observed exit is used to
//! make a decision and then dropped (DR-19).

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

/// One check's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// The check ran and the result was the expected one.
    Passed(String),
    /// The check ran and the result was wrong. This is an alarm.
    Failed(String),
    /// The check could not reach a conclusion, which is not the same as a failure.
    Inconclusive(String),
}

impl ProbeResult {
    /// A short description, safe to show.
    pub fn describe(&self) -> &str {
        match self {
            ProbeResult::Passed(note)
            | ProbeResult::Failed(note)
            | ProbeResult::Inconclusive(note) => note,
        }
    }
}

/// What a verification run concluded overall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Every check that could run passed.
    Passed,
    /// At least one check observed something wrong.
    Failed {
        /// Why, in one line.
        reason: String,
    },
    /// No check could reach a conclusion: nothing to say either way.
    Inconclusive {
        /// Why, in one line.
        reason: String,
    },
}

/// The checks themselves, behind a trait so the engine can be tested without sockets.
pub trait Probes: Send + Sync {
    /// Confirm that a UDP datagram cannot leave the machine.
    fn udp_egress(&self) -> ProbeResult;
    /// Confirm that the protected path carries traffic, and that the exit is not this machine.
    fn protected_path(&self) -> ProbeResult;
    /// Confirm that a known name resolves to a known address.
    fn canary(&self) -> ProbeResult;
}

/// Endpoint for the liveness and identity check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpEndpoint {
    /// Where to connect.
    pub address: SocketAddr,
    /// The `Host` header, which is also the name the endpoint expects.
    pub host: String,
    /// The path to request.
    pub path: String,
}

/// A name that should resolve to one particular address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canary {
    /// The name to ask for.
    pub name: String,
    /// The address only the right resolver should give.
    pub expected: Ipv4Addr,
    /// Which resolver to ask, usually the chokepoint.
    pub resolver: SocketAddr,
}

/// How verification is configured. With nothing configured, every check is inconclusive and the
/// state honestly reports that nothing has verified it.
#[derive(Debug, Clone)]
pub struct VerificationConfig {
    /// How often to run the checks.
    pub interval: Duration,
    /// How long a passing result stays credible.
    pub stale_after: Duration,
    /// How long a single network operation may take.
    pub timeout: Duration,
    /// A UDP endpoint that answers if a datagram reaches it.
    pub udp_endpoint: Option<SocketAddr>,
    /// An endpoint that answers `200` to a GET if the protected path works.
    pub http_endpoint: Option<HttpEndpoint>,
    /// A name that should resolve to a known address.
    pub canary: Option<Canary>,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(300),
            stale_after: Duration::from_secs(900),
            timeout: Duration::from_secs(10),
            udp_endpoint: None,
            http_endpoint: None,
            canary: None,
        }
    }
}

/// A verification run's report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// What the run concluded.
    pub outcome: Outcome,
    /// One line per check, in order, safe to show.
    pub details: Vec<String>,
}

/// Runs the configured checks and decides what they mean together.
pub struct Verifier<P: Probes> {
    probes: P,
}

impl<P: Probes> Verifier<P> {
    /// Build a verifier around a set of probes.
    pub fn new(probes: P) -> Self {
        Self { probes }
    }

    /// Run every check once.
    ///
    /// One alarm is enough to fail the run; silence is not a pass, because a check that could not
    /// run tells us nothing.
    pub fn run_once(&self) -> Report {
        let results = [
            self.probes.udp_egress(),
            self.probes.protected_path(),
            self.probes.canary(),
        ];

        let mut details = Vec::new();
        let mut failure = None;
        let mut passed = 0;
        for result in &results {
            details.push(match result {
                ProbeResult::Passed(note) => format!("ok: {note}"),
                ProbeResult::Failed(note) => {
                    if failure.is_none() {
                        failure = Some(note.clone());
                    }
                    format!("failed: {note}")
                }
                ProbeResult::Inconclusive(note) => format!("unknown: {note}"),
            });
            if matches!(result, ProbeResult::Passed(_)) {
                passed += 1;
            }
        }

        let outcome = if let Some(reason) = failure {
            Outcome::Failed { reason }
        } else if passed == 0 {
            Outcome::Inconclusive {
                reason: "no check could reach a conclusion".to_string(),
            }
        } else {
            Outcome::Passed
        };

        Report { outcome, details }
    }
}

/// A verification run, behind a trait so the engine can be tested without sockets.
pub trait Verification: Send + Sync {
    /// Run every check once.
    fn run_once(&self) -> Report;
}

impl<P: Probes> Verification for Verifier<P> {
    fn run_once(&self) -> Report {
        Verifier::run_once(self)
    }
}

/// The real checks, over ordinary sockets.
pub struct NetworkProbes {
    config: VerificationConfig,
    /// This machine's own addresses, so an "exit" that is one of them can be recognised.
    local: Vec<IpAddr>,
}

impl NetworkProbes {
    /// Build the probes, reading this machine's addresses once.
    pub fn new(config: VerificationConfig) -> Self {
        Self {
            config,
            local: local_addresses(),
        }
    }
}

impl Probes for NetworkProbes {
    fn udp_egress(&self) -> ProbeResult {
        let Some(endpoint) = self.config.udp_endpoint else {
            return ProbeResult::Inconclusive(
                "no UDP endpoint is configured to check against".into(),
            );
        };

        let socket = match UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)) {
            Ok(socket) => socket,
            Err(error) => return ProbeResult::Inconclusive(format!("no UDP socket: {error}")),
        };
        if let Err(error) = socket.set_read_timeout(Some(self.config.timeout)) {
            return ProbeResult::Inconclusive(format!("no UDP timeout: {error}"));
        }

        // A single byte: any answer at all means the datagram left the machine.
        match socket.send_to(&[0u8], endpoint) {
            Ok(_) => {}
            // Nothing left the machine, which is what we wanted.
            Err(_) => return ProbeResult::Passed("UDP could not leave".to_string()),
        }

        let mut buffer = [0u8; 64];
        match socket.recv_from(&mut buffer) {
            Ok((_, from)) => ProbeResult::Failed(format!(
                "a UDP datagram reached {from}: something is letting UDP out"
            )),
            // A refusal is the kernel's rejection rule doing its job.
            Err(error)
                if error.kind() == std::io::ErrorKind::TimedOut
                    || error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::ConnectionRefused =>
            {
                ProbeResult::Passed("UDP was refused".to_string())
            }
            Err(error) => {
                ProbeResult::Inconclusive(format!("the UDP check was inconclusive: {error}"))
            }
        }
    }

    fn protected_path(&self) -> ProbeResult {
        let Some(endpoint) = &self.config.http_endpoint else {
            return ProbeResult::Inconclusive("no check endpoint is configured".into());
        };

        let stream = match TcpStream::connect_timeout(&endpoint.address, self.config.timeout) {
            Ok(stream) => stream,
            Err(error) => {
                return ProbeResult::Failed(format!(
                    "the protected path did not carry a connection: {error}"
                ))
            }
        };
        if stream.set_read_timeout(Some(self.config.timeout)).is_err()
            || stream.set_write_timeout(Some(self.config.timeout)).is_err()
        {
            return ProbeResult::Inconclusive("no timeouts could be set".into());
        }

        let mut writer = match stream.try_clone() {
            Ok(writer) => writer,
            Err(error) => return ProbeResult::Inconclusive(format!("no second handle: {error}")),
        };
        // HTTP/1.0 so the endpoint closes after answering: the body is then simply "the rest".
        let request = format!(
            "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: ghostnector-check\r\n\r\n",
            endpoint.path, endpoint.host
        );
        if let Err(error) = writer.write_all(request.as_bytes()) {
            return ProbeResult::Inconclusive(format!("the request could not be sent: {error}"));
        }

        let mut response = Vec::new();
        if let Err(error) = stream.take(8192).read_to_end(&mut response) {
            return ProbeResult::Inconclusive(format!("the answer could not be read: {error}"));
        }
        let text = String::from_utf8_lossy(&response).to_string();

        let status = text.lines().next().unwrap_or("").to_string();
        if !status.contains(" 200") {
            return ProbeResult::Failed(format!("the check endpoint answered '{status}'"));
        }

        match first_ipv4(&text) {
            Some(address) if self.local.contains(&IpAddr::V4(address)) => {
                ProbeResult::Failed("the check endpoint saw this machine's own address".to_string())
            }
            Some(_) => ProbeResult::Passed(
                "the protected path answered, and the exit is not this machine".to_string(),
            ),
            // A 200 without an address is still evidence that traffic flows.
            None => ProbeResult::Passed(
                "the protected path answered, though it did not report an address".to_string(),
            ),
        }
    }

    fn canary(&self) -> ProbeResult {
        let Some(canary) = &self.config.canary else {
            return ProbeResult::Inconclusive("no canary name is configured".into());
        };

        let id: u16 = 0x4748; // a constant: nothing here needs to guess transaction ids
        let query = build_query(id, &canary.name);
        let socket = match UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)) {
            Ok(socket) => socket,
            Err(error) => return ProbeResult::Inconclusive(format!("no DNS socket: {error}")),
        };
        if socket.set_read_timeout(Some(self.config.timeout)).is_err() {
            return ProbeResult::Inconclusive("no DNS timeout".into());
        }
        if socket.send_to(&query, canary.resolver).is_err() {
            return ProbeResult::Inconclusive("the canary query could not be sent".into());
        }

        let mut response = [0u8; 1024];
        let length = match socket.recv(&mut response) {
            Ok(length) => length,
            // No answer means resolution is broken, which is not the same as being lied to.
            Err(error) => {
                return ProbeResult::Inconclusive(format!("the canary did not answer: {error}"))
            }
        };

        match parse_addresses(&response[..length], id) {
            Ok((rcode, _)) if rcode != 0 => ProbeResult::Inconclusive(format!(
                "the canary was refused with response code {rcode}, so DNS is not working"
            )),
            Ok((_, addresses)) if addresses.is_empty() => {
                ProbeResult::Inconclusive("the canary resolved to no address".to_string())
            }
            Ok((_, addresses)) if addresses.contains(&canary.expected) => {
                ProbeResult::Passed("the canary resolved as expected".to_string())
            }
            Ok((_, addresses)) => ProbeResult::Failed(format!(
                "the canary resolved to {} instead of the expected address: DNS is being answered \
                 by something else",
                addresses
                    .iter()
                    .map(|address| address.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            Err(reason) => {
                ProbeResult::Inconclusive(format!("the canary answer was unusable: {reason}"))
            }
        }
    }
}

/// This machine's addresses, so an "exit" that is one of them is recognisable.
fn local_addresses() -> Vec<IpAddr> {
    let mut addresses = Vec::new();
    if let Ok(interfaces) = nix::ifaddrs::getifaddrs() {
        for interface in interfaces {
            if let Some(address) = interface.address {
                if let Some(ipv4) = address.as_sockaddr_in() {
                    addresses.push(IpAddr::V4(ipv4.ip()));
                } else if let Some(ipv6) = address.as_sockaddr_in6() {
                    addresses.push(IpAddr::V6(ipv6.ip()));
                }
            }
        }
    }
    addresses
}

/// The first dotted quad in a body, which is how a plain check endpoint reports an address.
fn first_ipv4(text: &str) -> Option<Ipv4Addr> {
    for token in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        if let Ok(address) = token.parse::<Ipv4Addr>() {
            return Some(address);
        }
    }
    None
}

/// A minimal A-record query. Enough for one name, one question, one answer.
fn build_query(id: u16, name: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&[0x01, 0x00]); // standard query, recursion desired
    message.extend_from_slice(&1u16.to_be_bytes()); // one question
    message.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // nothing else
    for label in name.trim_end_matches('.').split('.') {
        message.push(label.len().min(63) as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&1u16.to_be_bytes()); // type A
    message.extend_from_slice(&1u16.to_be_bytes()); // class IN
    message
}

/// Pull the address records out of a reply, and check that it is the reply to our question.
fn parse_addresses(message: &[u8], expected_id: u16) -> Result<(u8, Vec<Ipv4Addr>), String> {
    if message.len() < 12 {
        return Err("the answer was too short".to_string());
    }
    let id = u16::from_be_bytes([message[0], message[1]]);
    if id != expected_id {
        return Err("the answer was to a different question".to_string());
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    if flags & 0x8000 == 0 {
        return Err("the answer was not an answer".to_string());
    }
    let rcode = (flags & 0x000f) as u8;
    let questions = u16::from_be_bytes([message[4], message[5]]) as usize;
    let answers = u16::from_be_bytes([message[6], message[7]]) as usize;

    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_name(message, offset)? + 4;
    }

    let mut addresses = Vec::new();
    for _ in 0..answers {
        offset = skip_name(message, offset)?;
        if offset + 10 > message.len() {
            return Err("the answer was truncated".to_string());
        }
        let kind = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let class = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
        let length = u16::from_be_bytes([message[offset + 8], message[offset + 9]]) as usize;
        offset += 10;
        if offset + length > message.len() {
            return Err("a record ran past the end of the answer".to_string());
        }
        if kind == 1 && class == 1 && length == 4 {
            addresses.push(Ipv4Addr::new(
                message[offset],
                message[offset + 1],
                message[offset + 2],
                message[offset + 3],
            ));
        }
        offset += length;
    }
    Ok((rcode, addresses))
}

/// Step over a name, following compression pointers.
fn skip_name(message: &[u8], mut offset: usize) -> Result<usize, String> {
    loop {
        let Some(&length) = message.get(offset) else {
            return Err("a name ran past the end of the answer".to_string());
        };
        if length == 0 {
            return Ok(offset + 1);
        }
        if length & 0xc0 == 0xc0 {
            // A compression pointer is two bytes and ends the name.
            return Ok(offset + 2);
        }
        offset += 1 + length as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::Mutex;

    const CANARY_ADDRESS: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

    /// The probes, with each check under the test's control.
    struct Scripted {
        udp: Mutex<ProbeResult>,
        path: Mutex<ProbeResult>,
        canary: Mutex<ProbeResult>,
    }

    impl Scripted {
        fn new(udp: ProbeResult, path: ProbeResult, canary: ProbeResult) -> Self {
            Self {
                udp: Mutex::new(udp),
                path: Mutex::new(path),
                canary: Mutex::new(canary),
            }
        }
    }

    impl Probes for Scripted {
        fn udp_egress(&self) -> ProbeResult {
            self.udp.lock().expect("lock").clone()
        }
        fn protected_path(&self) -> ProbeResult {
            self.path.lock().expect("lock").clone()
        }
        fn canary(&self) -> ProbeResult {
            self.canary.lock().expect("lock").clone()
        }
    }

    fn passed() -> ProbeResult {
        ProbeResult::Passed("fine".to_string())
    }

    #[test]
    fn everything_passing_is_a_pass() {
        let verifier = Verifier::new(Scripted::new(passed(), passed(), passed()));
        assert_eq!(verifier.run_once().outcome, Outcome::Passed);
    }

    #[test]
    fn one_alarm_fails_the_whole_run() {
        let verifier = Verifier::new(Scripted::new(
            passed(),
            ProbeResult::Failed("a UDP datagram reached 203.0.113.1".to_string()),
            passed(),
        ));
        match verifier.run_once().outcome {
            Outcome::Failed { reason } => assert!(reason.contains("UDP datagram"), "{reason}"),
            other => panic!("one alarm must fail the run, got {other:?}"),
        }
    }

    #[test]
    fn silence_is_not_a_pass() {
        let verifier = Verifier::new(Scripted::new(
            ProbeResult::Inconclusive("nothing configured".to_string()),
            ProbeResult::Inconclusive("nothing configured".to_string()),
            ProbeResult::Inconclusive("nothing configured".to_string()),
        ));
        assert!(matches!(
            verifier.run_once().outcome,
            Outcome::Inconclusive { .. }
        ));
    }

    #[test]
    fn a_failure_outweighs_a_check_that_could_not_run() {
        let verifier = Verifier::new(Scripted::new(
            ProbeResult::Inconclusive("no endpoint".to_string()),
            ProbeResult::Failed("the endpoint answered 500".to_string()),
            ProbeResult::Inconclusive("no canary".to_string()),
        ));
        assert!(matches!(
            verifier.run_once().outcome,
            Outcome::Failed { .. }
        ));
    }

    #[test]
    fn the_details_say_which_checks_passed_and_which_did_not() {
        let verifier = Verifier::new(Scripted::new(
            passed(),
            ProbeResult::Failed("the endpoint answered 500".to_string()),
            ProbeResult::Inconclusive("no canary".to_string()),
        ));
        let report = verifier.run_once();
        assert!(report.details[0].starts_with("ok:"), "{:?}", report.details);
        assert!(
            report.details[1].starts_with("failed:"),
            "{:?}",
            report.details
        );
        assert!(
            report.details[2].starts_with("unknown:"),
            "{:?}",
            report.details
        );
    }

    // ---------------------------------------------------------------- the real probes

    #[test]
    fn a_udp_endpoint_that_answers_is_an_alarm() {
        let responder = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let address = responder.local_addr().expect("address");
        std::thread::spawn(move || {
            let mut buffer = [0u8; 64];
            if let Ok((_, from)) = responder.recv_from(&mut buffer) {
                let _ = responder.send_to(b"here", from);
            }
        });

        let probes = NetworkProbes::new(VerificationConfig {
            timeout: Duration::from_millis(500),
            udp_endpoint: Some(address),
            ..VerificationConfig::default()
        });
        match probes.udp_egress() {
            ProbeResult::Failed(reason) => assert!(reason.contains("letting UDP out"), "{reason}"),
            other => panic!("a reply must be an alarm, got {other:?}"),
        }
    }

    #[test]
    fn a_udp_endpoint_that_stays_silent_is_a_pass() {
        let silent = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let address = silent.local_addr().expect("address");

        let probes = NetworkProbes::new(VerificationConfig {
            timeout: Duration::from_millis(200),
            udp_endpoint: Some(address),
            ..VerificationConfig::default()
        });
        assert!(matches!(probes.udp_egress(), ProbeResult::Passed(_)));
    }

    #[test]
    fn a_closed_udp_port_counts_as_denied_rather_than_as_a_question_mark() {
        // Ports are not bound here, so the kernel answers with an ICMP refusal, which is exactly what
        // the policy's rejection rule produces.
        let probes = NetworkProbes::new(VerificationConfig {
            timeout: Duration::from_millis(300),
            udp_endpoint: Some("127.0.0.1:9".parse().expect("address")),
            ..VerificationConfig::default()
        });
        assert!(matches!(probes.udp_egress(), ProbeResult::Passed(_)));
    }

    #[test]
    fn without_an_endpoint_the_udp_check_is_inconclusive() {
        let probes = NetworkProbes::new(VerificationConfig::default());
        assert!(matches!(probes.udp_egress(), ProbeResult::Inconclusive(_)));
    }

    #[test]
    fn a_check_endpoint_answering_200_with_a_foreign_address_is_a_pass() {
        let (address, _stop) = fake_http("HTTP/1.0 200 OK\r\n\r\n198.51.100.7\n");
        let probes = NetworkProbes::new(VerificationConfig {
            timeout: Duration::from_secs(2),
            http_endpoint: Some(HttpEndpoint {
                address,
                host: "check.test".to_string(),
                path: "/".to_string(),
            }),
            ..VerificationConfig::default()
        });
        assert!(matches!(probes.protected_path(), ProbeResult::Passed(_)));
    }

    #[test]
    fn a_check_endpoint_answering_with_this_machines_address_is_an_alarm() {
        // 127.0.0.1 is always one of this machine's addresses.
        let (address, _stop) = fake_http("HTTP/1.0 200 OK\r\n\r\n127.0.0.1\n");
        let probes = NetworkProbes::new(VerificationConfig {
            timeout: Duration::from_secs(2),
            http_endpoint: Some(HttpEndpoint {
                address,
                host: "check.test".to_string(),
                path: "/".to_string(),
            }),
            ..VerificationConfig::default()
        });
        match probes.protected_path() {
            ProbeResult::Failed(reason) => assert!(reason.contains("own address"), "{reason}"),
            other => panic!("an exit that is this machine must alarm, got {other:?}"),
        }
    }

    #[test]
    fn a_check_endpoint_that_is_not_200_is_an_alarm() {
        let (address, _stop) = fake_http("HTTP/1.0 503 Service Unavailable\r\n\r\n");
        let probes = NetworkProbes::new(VerificationConfig {
            timeout: Duration::from_secs(2),
            http_endpoint: Some(HttpEndpoint {
                address,
                host: "check.test".to_string(),
                path: "/".to_string(),
            }),
            ..VerificationConfig::default()
        });
        assert!(matches!(probes.protected_path(), ProbeResult::Failed(_)));
    }

    #[test]
    fn a_path_that_carries_nothing_is_an_alarm() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        drop(listener); // nothing is listening now

        let probes = NetworkProbes::new(VerificationConfig {
            timeout: Duration::from_millis(300),
            http_endpoint: Some(HttpEndpoint {
                address,
                host: "check.test".to_string(),
                path: "/".to_string(),
            }),
            ..VerificationConfig::default()
        });
        assert!(matches!(probes.protected_path(), ProbeResult::Failed(_)));
    }

    #[test]
    fn a_canary_resolving_as_expected_is_a_pass() {
        let (address, _stop) = fake_dns(&[CANARY_ADDRESS], 0);
        let probes = NetworkProbes::new(VerificationConfig {
            timeout: Duration::from_secs(2),
            canary: Some(Canary {
                name: "canary.test".to_string(),
                expected: CANARY_ADDRESS,
                resolver: address,
            }),
            ..VerificationConfig::default()
        });
        assert!(matches!(probes.canary(), ProbeResult::Passed(_)));
    }

    #[test]
    fn a_canary_resolving_elsewhere_is_an_alarm() {
        let hijacked = Ipv4Addr::new(198, 51, 100, 66);
        let (address, _stop) = fake_dns(&[hijacked], 0);
        let probes = NetworkProbes::new(VerificationConfig {
            timeout: Duration::from_secs(2),
            canary: Some(Canary {
                name: "canary.test".to_string(),
                expected: CANARY_ADDRESS,
                resolver: address,
            }),
            ..VerificationConfig::default()
        });
        match probes.canary() {
            ProbeResult::Failed(reason) => {
                assert!(reason.contains("something else"), "{reason}")
            }
            other => panic!("a hijacked canary must alarm, got {other:?}"),
        }
    }

    #[test]
    fn a_canary_that_cannot_be_resolved_is_not_the_same_as_being_lied_to() {
        let (address, _stop) = fake_dns(&[], 3); // NXDOMAIN
        let probes = NetworkProbes::new(VerificationConfig {
            timeout: Duration::from_secs(2),
            canary: Some(Canary {
                name: "canary.test".to_string(),
                expected: CANARY_ADDRESS,
                resolver: address,
            }),
            ..VerificationConfig::default()
        });
        assert!(
            matches!(probes.canary(), ProbeResult::Inconclusive(_)),
            "a broken resolver is a problem, but it is not a lie: {:?}",
            probes.canary()
        );
    }

    #[test]
    fn a_canary_that_never_answers_is_inconclusive() {
        let silent = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let address = silent.local_addr().expect("address");
        let probes = NetworkProbes::new(VerificationConfig {
            timeout: Duration::from_millis(200),
            canary: Some(Canary {
                name: "canary.test".to_string(),
                expected: CANARY_ADDRESS,
                resolver: address,
            }),
            ..VerificationConfig::default()
        });
        assert!(matches!(probes.canary(), ProbeResult::Inconclusive(_)));
    }

    #[test]
    fn without_configuration_every_probe_is_inconclusive() {
        let probes = NetworkProbes::new(VerificationConfig::default());
        for result in [
            probes.udp_egress(),
            probes.protected_path(),
            probes.canary(),
        ] {
            assert!(matches!(result, ProbeResult::Inconclusive(_)), "{result:?}");
        }
    }

    // ---------------------------------------------------------------- the pieces

    #[test]
    fn a_query_can_be_read_back_by_the_parser() {
        let query = build_query(0x1234, "canary.test");
        let (address, _stop) = fake_dns(&[CANARY_ADDRESS], 0);
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        socket.send_to(&query, address).expect("send");
        let mut response = [0u8; 512];
        let length = socket.recv(&mut response).expect("receive");
        let (rcode, addresses) = parse_addresses(&response[..length], 0x1234).expect("parse");
        assert_eq!(rcode, 0);
        assert_eq!(addresses, vec![CANARY_ADDRESS]);
    }

    #[test]
    fn an_answer_to_a_different_question_is_refused() {
        let (address, _stop) = fake_dns(&[CANARY_ADDRESS], 0);
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        socket
            .send_to(&build_query(0x1111, "canary.test"), address)
            .expect("send");
        let mut response = [0u8; 512];
        let length = socket.recv(&mut response).expect("receive");
        assert!(parse_addresses(&response[..length], 0x2222).is_err());
    }

    #[test]
    fn the_first_address_in_a_body_is_found() {
        assert_eq!(
            first_ipv4("HTTP/1.0 200 OK\r\n\r\n203.0.113.9\n"),
            Some(Ipv4Addr::new(203, 0, 113, 9))
        );
        assert_eq!(first_ipv4("no address here"), None);
        assert_eq!(first_ipv4(""), None);
    }

    /// A one-shot HTTP server that answers with exactly this text.
    fn fake_http(response: &'static str) -> (SocketAddr, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0u8; 512];
                let _ = stream.read(&mut request);
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (address, handle)
    }

    /// A one-shot DNS server that answers with these addresses, in a reply to the question it is
    /// asked (which the test always builds the same way).
    fn fake_dns(addresses: &[Ipv4Addr], rcode: u8) -> (SocketAddr, std::thread::JoinHandle<()>) {
        let addresses = addresses.to_vec();
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let address = socket.local_addr().expect("address");
        let handle = std::thread::spawn(move || {
            let mut buffer = [0u8; 512];
            let Ok((length, from)) = socket.recv_from(&mut buffer) else {
                return;
            };
            let query = &buffer[..length];

            let mut reply = Vec::new();
            reply.extend_from_slice(&query[..2]); // the same id
            reply.extend_from_slice(&[0x81, 0x80 | (rcode & 0x0f)]); // a reply, with this code
            reply.extend_from_slice(&1u16.to_be_bytes()); // one question
            reply.extend_from_slice(&(addresses.len() as u16).to_be_bytes());
            reply.extend_from_slice(&[0, 0, 0, 0]);
            let question_end = question_end(query);
            reply.extend_from_slice(&query[12..question_end]);

            for address in &addresses {
                reply.extend_from_slice(&[0xc0, 0x0c]); // a pointer to the question's name
                reply.extend_from_slice(&1u16.to_be_bytes()); // type A
                reply.extend_from_slice(&1u16.to_be_bytes()); // class IN
                reply.extend_from_slice(&60u32.to_be_bytes()); // ttl
                reply.extend_from_slice(&4u16.to_be_bytes()); // length
                reply.extend_from_slice(&address.octets());
            }

            let _ = socket.send_to(&reply, from);
        });
        (address, handle)
    }

    type QuestionEnd = usize;

    fn question_end(query: &[u8]) -> QuestionEnd {
        let mut offset = 12;
        loop {
            let length = query[offset] as usize;
            if length == 0 {
                return offset + 1 + 4;
            }
            offset += 1 + length;
        }
    }
}
