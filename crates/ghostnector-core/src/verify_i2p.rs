//! Verification for I2P scope.
//!
//! The host-scope probes are deliberately not reused here. They assume Tor's transparent proxy and a
//! DNS chokepoint, neither of which exists in I2P scope: in I2P scope the *host* is not protected
//! either, so a datagram leaving it would prove nothing. Evidence for an I2P claim is:
//!
//! 1. **clearnet TCP from this process is refused** — the verifier is an ordinary, non-router
//!    identity, so this is exactly the claim "every flow that is not the router's own is denied";
//! 2. **the router's local proxy answers** — the path applications actually use;
//! 3. **the configured I2P canary is fetched through that proxy** — the only evidence that the
//!    router is integrated with the network rather than merely listening.
//!
//! Without a canary there is no such evidence, so an I2P profile can never become `Protected`
//! (M9 decision 4). A missing check is inconclusive, never a pass; a contradiction fails the run and
//! the engine applies the fail-closed baseline.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use ghostnector_spec::backend::I2pPorts;

use crate::verify::{Outcome, ProbeResult, Report};

/// The canary: an I2P destination only that network can answer for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct I2pCanary {
    /// The `.i2p` name (or destination) to fetch.
    pub host: String,
    /// The path to request.
    pub path: String,
    /// A marker the answer must contain, when the operator configured one.
    pub expect: Option<String>,
}

/// How I2P verification is configured.
#[derive(Debug, Clone)]
pub struct I2pVerificationConfig {
    /// How long a single network operation may take.
    pub timeout: Duration,
    /// A clearnet TCP endpoint that must be unreachable in I2P scope.
    pub clearnet: Option<SocketAddr>,
    /// The canary fetched through the router's HTTP proxy.
    pub canary: Option<I2pCanary>,
}

impl Default for I2pVerificationConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            clearnet: None,
            canary: None,
        }
    }
}

/// The checks themselves, behind a trait so the engine can be tested without sockets.
pub trait I2pProbes: Send + Sync {
    /// Confirm that clearnet TCP cannot leave this machine.
    fn clearnet_denied(&self) -> ProbeResult;
    /// Confirm that the router's HTTP proxy answers.
    fn proxy_answers(&self, proxy: SocketAddr) -> ProbeResult;
    /// Confirm that the canary is fetched through the proxy.
    fn canary(&self, proxy: SocketAddr) -> ProbeResult;
}

/// Runs the I2P checks and decides what they mean together.
pub struct I2pVerifier<P: I2pProbes> {
    probes: P,
}

impl<P: I2pProbes> I2pVerifier<P> {
    /// Build a verifier around a set of probes.
    pub fn new(probes: P) -> Self {
        Self { probes }
    }

    /// Run every check once.
    ///
    /// One alarm is enough to fail the run; silence is not a pass.
    pub fn run_once(&self, ports: I2pPorts) -> Report {
        let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, ports.http));
        let results = [
            self.probes.clearnet_denied(),
            self.probes.proxy_answers(proxy),
            self.probes.canary(proxy),
        ];

        let mut details = Vec::new();
        let mut failure = None;
        let mut passed = 0;
        let mut canary_passed = false;
        for (index, result) in results.iter().enumerate() {
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
                if index == 2 {
                    canary_passed = true;
                }
            }
        }

        // M9 decision 4: the canary is what proves the router is integrated, so its pass is
        // required. Other checks passing without it is not evidence of an I2P path.
        let outcome = if let Some(reason) = failure {
            Outcome::Failed { reason }
        } else if !canary_passed {
            Outcome::Inconclusive {
                reason: if passed == 0 {
                    "no I2P check could reach a conclusion".to_string()
                } else {
                    "the canary has not proven the router is integrated".to_string()
                },
            }
        } else {
            Outcome::Passed
        };

        Report { outcome, details }
    }
}

/// An I2P verification run, behind a trait so the engine can be tested without sockets.
pub trait I2pVerification: Send + Sync {
    /// Run every check once, against the proxy ports the helper reported.
    fn run_once(&self, ports: I2pPorts) -> Report;
}

impl<P: I2pProbes> I2pVerification for I2pVerifier<P> {
    fn run_once(&self, ports: I2pPorts) -> Report {
        I2pVerifier::run_once(self, ports)
    }
}

/// The verifier used when none was configured: it can never pass.
///
/// This is the code-level form of M9 decision 4. An I2P profile with no verification configuration
/// stays `Degraded`, because there is no evidence — not because a check failed.
pub struct NoI2pEvidence;

impl I2pVerification for NoI2pEvidence {
    fn run_once(&self, _ports: I2pPorts) -> Report {
        Report {
            outcome: Outcome::Inconclusive {
                reason: "no I2P verification is configured, so there is no evidence".to_string(),
            },
            details: vec![
                "unknown: no clearnet check endpoint is configured".to_string(),
                "unknown: no canary is configured, so the router's integration is unproven"
                    .to_string(),
            ],
        }
    }
}

/// The real checks, over ordinary sockets.
pub struct NetworkI2pProbes {
    config: I2pVerificationConfig,
}

impl NetworkI2pProbes {
    /// Build the probes.
    pub fn new(config: I2pVerificationConfig) -> Self {
        Self { config }
    }
}

impl I2pProbes for NetworkI2pProbes {
    fn clearnet_denied(&self) -> ProbeResult {
        let Some(endpoint) = self.config.clearnet else {
            return ProbeResult::Inconclusive(
                "no clearnet check endpoint is configured".to_string(),
            );
        };
        match TcpStream::connect_timeout(&endpoint, self.config.timeout) {
            Ok(_) => ProbeResult::Failed(
                "a clearnet TCP connection was carried, so something outside the router can \
                 still leave"
                    .to_string(),
            ),
            Err(_) => ProbeResult::Passed("clearnet TCP was refused".to_string()),
        }
    }

    fn proxy_answers(&self, proxy: SocketAddr) -> ProbeResult {
        match TcpStream::connect_timeout(&proxy, self.config.timeout) {
            Ok(_) => ProbeResult::Passed("the router's proxy answered".to_string()),
            Err(error) => ProbeResult::Failed(format!(
                "the router's proxy did not answer, so I2P is unreachable: {error}"
            )),
        }
    }

    fn canary(&self, proxy: SocketAddr) -> ProbeResult {
        let Some(canary) = self.config.canary.as_ref() else {
            return ProbeResult::Inconclusive(
                "no canary is configured, so the router's integration is unproven".to_string(),
            );
        };
        let stream = match TcpStream::connect_timeout(&proxy, self.config.timeout) {
            Ok(stream) => stream,
            Err(error) => {
                return ProbeResult::Inconclusive(format!("the proxy did not answer: {error}"))
            }
        };
        let _ = stream.set_read_timeout(Some(self.config.timeout));
        let _ = stream.set_write_timeout(Some(self.config.timeout));
        let mut writer = match stream.try_clone() {
            Ok(writer) => writer,
            Err(error) => return ProbeResult::Inconclusive(format!("no second handle: {error}")),
        };
        // The HTTP proxy wants an absolute URL (or a Host header) for the destination; it never
        // resolves anything itself on the clearnet.
        let request = format!(
            "GET http://{}{} HTTP/1.0\r\nHost: {}\r\nUser-Agent: ghostnector-check\r\n\r\n",
            canary.host, canary.path, canary.host
        );
        if writer.write_all(request.as_bytes()).is_err() {
            return ProbeResult::Inconclusive("the canary request could not be sent".to_string());
        }
        let mut response = Vec::new();
        if stream.take(65536).read_to_end(&mut response).is_err() {
            return ProbeResult::Inconclusive("the canary answer could not be read".to_string());
        }
        let text = String::from_utf8_lossy(&response).to_string();
        let status = text.lines().next().unwrap_or("").to_string();
        if !status.contains(" 200") {
            // A timeout or a "destination unreachable" from the router is a lack of evidence, not a
            // contradiction: eepsites come and go. Only a wrong answer alarms.
            return ProbeResult::Inconclusive(format!("the canary did not answer: {status}"));
        }
        if let Some(expected) = canary.expect.as_ref() {
            if !text.contains(expected.as_str()) {
                return ProbeResult::Failed(
                    "the canary answered, but without the expected marker: something else \
                     answered"
                        .to_string(),
                );
            }
        }
        ProbeResult::Passed("the canary was fetched through the router".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scripted {
        clearnet: ProbeResult,
        proxy: ProbeResult,
        canary: ProbeResult,
    }

    impl I2pProbes for Scripted {
        fn clearnet_denied(&self) -> ProbeResult {
            self.clearnet.clone()
        }
        fn proxy_answers(&self, _proxy: SocketAddr) -> ProbeResult {
            self.proxy.clone()
        }
        fn canary(&self, _proxy: SocketAddr) -> ProbeResult {
            self.canary.clone()
        }
    }

    fn ports() -> I2pPorts {
        I2pPorts::default()
    }

    fn scripted(
        clearnet: ProbeResult,
        proxy: ProbeResult,
        canary: ProbeResult,
    ) -> I2pVerifier<Scripted> {
        I2pVerifier::new(Scripted {
            clearnet,
            proxy,
            canary,
        })
    }

    #[test]
    fn everything_passing_is_the_only_route_to_a_pass() {
        let report = scripted(
            ProbeResult::Passed("refused".into()),
            ProbeResult::Passed("answered".into()),
            ProbeResult::Passed("fetched".into()),
        )
        .run_once(ports());
        assert_eq!(report.outcome, Outcome::Passed, "{report:?}");
        assert_eq!(report.details.len(), 3);
    }

    #[test]
    fn a_missing_canary_is_never_a_pass() {
        let report = scripted(
            ProbeResult::Passed("refused".into()),
            ProbeResult::Passed("answered".into()),
            ProbeResult::Inconclusive("no canary".into()),
        )
        .run_once(ports());
        // M9 decision 4: the canary is what proves the router is integrated, so passing the other
        // checks without it stays inconclusive, never Protected.
        assert!(
            matches!(report.outcome, Outcome::Inconclusive { .. }),
            "{report:?}"
        );
        match &report.outcome {
            Outcome::Inconclusive { reason } => {
                assert!(reason.contains("canary"), "{reason}");
            }
            other => panic!("expected inconclusive, got {other:?}"),
        }
    }

    #[test]
    fn a_clearnet_connection_is_an_alarm() {
        let report = scripted(
            ProbeResult::Failed("a clearnet connection was carried".into()),
            ProbeResult::Passed("answered".into()),
            ProbeResult::Passed("fetched".into()),
        )
        .run_once(ports());
        assert!(
            matches!(report.outcome, Outcome::Failed { .. }),
            "{report:?}"
        );
    }

    #[test]
    fn the_proxy_not_answering_is_an_alarm() {
        let report = scripted(
            ProbeResult::Passed("refused".into()),
            ProbeResult::Failed("the proxy did not answer".into()),
            ProbeResult::Passed("fetched".into()),
        )
        .run_once(ports());
        assert!(
            matches!(report.outcome, Outcome::Failed { .. }),
            "{report:?}"
        );
    }

    #[test]
    fn a_wrong_canary_answer_is_an_alarm() {
        let report = scripted(
            ProbeResult::Passed("refused".into()),
            ProbeResult::Passed("answered".into()),
            ProbeResult::Failed("the canary answered without the expected marker".into()),
        )
        .run_once(ports());
        assert!(
            matches!(report.outcome, Outcome::Failed { .. }),
            "{report:?}"
        );
    }

    #[test]
    fn with_no_canary_but_a_live_proxy_the_run_is_inconclusive_and_says_why() {
        // A router is running (something accepts connections on the proxy port), but no canary is
        // configured: the other checks may pass, yet there is no evidence of integration, so the
        // run must not pass (M9 decision 4).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
        let port = listener.local_addr().expect("address").port();
        let report = I2pVerifier::new(NetworkI2pProbes::new(I2pVerificationConfig {
            timeout: Duration::from_millis(100),
            ..I2pVerificationConfig::default()
        }))
        .run_once(I2pPorts {
            http: port,
            socks: 14447,
        });
        assert!(
            matches!(report.outcome, Outcome::Inconclusive { .. }),
            "{report:?}"
        );
        assert!(
            report
                .details
                .iter()
                .any(|detail| detail.contains("no canary is configured")),
            "{report:?}"
        );
    }

    #[test]
    fn a_dead_proxy_is_an_alarm() {
        // Nothing listens on this port: the profile claims I2P is reachable, so this is a
        // contradiction, not merely missing evidence.
        let report = I2pVerifier::new(NetworkI2pProbes::new(I2pVerificationConfig {
            timeout: Duration::from_millis(100),
            ..I2pVerificationConfig::default()
        }))
        .run_once(I2pPorts {
            http: 1,
            socks: 14447,
        });
        assert!(
            matches!(report.outcome, Outcome::Failed { .. }),
            "{report:?}"
        );
    }

    #[test]
    fn the_no_evidence_verifier_never_passes() {
        let report = NoI2pEvidence.run_once(ports());
        assert!(
            matches!(report.outcome, Outcome::Inconclusive { .. }),
            "{report:?}"
        );
    }
}
