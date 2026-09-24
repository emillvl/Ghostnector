//! The DNS chokepoint.
//!
//! Everything that resolves through Ghostnector resolves through this process. It is deliberately
//! the most boring program in the project:
//!
//! * It **relays messages unchanged**. It does not parse names, does not rewrite, does not cache,
//!   and does not answer from anything of its own. A relay that cannot be made to lie or to leak is
//!   a relay that cannot be misconfigured into lying or leaking.
//! * It **logs nothing about queries**. Not the name, not the client, not the size. Only that
//!   something was dropped, at most once a minute, and never a query in the message.
//! * It only accepts messages that look like queries, and only up to a sane size, so it cannot be
//!   used as a general-purpose forwarder.
//!
//! Why it exists at all, when the firewall already redirects port 53 into it: `/etc/resolv.conf`
//! cannot express a port, so the system's own resolver configuration can only be pointed at
//! `127.0.0.1:53`. The chokepoint is what makes that address resolve through Tor (or through the
//! encrypted resolver) instead of through whatever the machine would otherwise do.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// The largest message relayed. Larger than any sane EDNS0 reply, small enough that a flood cannot
/// exhaust memory.
pub const MAX_MESSAGE: usize = 4096;

/// The smallest thing that can be a DNS message.
const MIN_MESSAGE: usize = 12;

/// How many UDP queries may be in flight at once. Beyond this, queries are dropped: the alternative
/// is unbounded threads.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 256;

/// How often a repeated drop reason may be logged.
const LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Why the chokepoint could not run.
#[derive(Debug, thiserror::Error)]
pub enum ChokepointError {
    /// A socket could not be created.
    #[error("cannot listen on {address}: {reason}")]
    Bind {
        /// The address tried.
        address: SocketAddr,
        /// What went wrong.
        reason: String,
    },
    /// Relaying stopped.
    #[error("the relay stopped: {0}")]
    Relay(String),
}

/// The listening sockets, so that tests can learn the port the system chose.
pub struct Sockets {
    /// The UDP listener.
    pub udp: UdpSocket,
    /// The TCP listener.
    pub tcp: TcpListener,
}

/// The relay.
#[derive(Debug, Clone)]
pub struct Chokepoint {
    listen: SocketAddr,
    upstream: SocketAddr,
    timeout: Duration,
    max_in_flight: usize,
}

impl Chokepoint {
    /// A relay from `listen` to `upstream`.
    pub fn new(listen: SocketAddr, upstream: SocketAddr, timeout: Duration) -> Self {
        Self {
            listen,
            upstream,
            timeout,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
        }
    }

    /// Where queries are accepted.
    pub fn listen_address(&self) -> SocketAddr {
        self.listen
    }

    /// Where queries are sent.
    pub fn upstream_address(&self) -> SocketAddr {
        self.upstream
    }

    /// Bind both listeners. A privileged port needs the capability to bind it, which the service
    /// unit grants and nothing else does.
    pub fn bind(&self) -> Result<Sockets, ChokepointError> {
        let udp = UdpSocket::bind(self.listen).map_err(|error| ChokepointError::Bind {
            address: self.listen,
            reason: error.to_string(),
        })?;
        let tcp = TcpListener::bind(self.listen).map_err(|error| ChokepointError::Bind {
            address: self.listen,
            reason: error.to_string(),
        })?;
        Ok(Sockets { udp, tcp })
    }

    /// Bind and relay until the process is stopped.
    pub fn run(&self) -> Result<(), ChokepointError> {
        let sockets = self.bind()?;
        self.serve(sockets)
    }

    /// Relay on already-bound sockets.
    pub fn serve(&self, sockets: Sockets) -> Result<(), ChokepointError> {
        let tcp = {
            let relay = self.clone();
            let listener = sockets
                .tcp
                .try_clone()
                .map_err(|error| ChokepointError::Relay(error.to_string()))?;
            thread::spawn(move || relay.serve_tcp(listener))
        };

        self.serve_udp(&sockets.udp)?;
        let _ = tcp.join();
        Ok(())
    }

    fn serve_udp(&self, listener: &UdpSocket) -> Result<(), ChokepointError> {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let mut throttle = Throttle::default();
        // One byte more than the limit, so an oversized datagram is *detected* rather than silently
        // truncated into a corrupted message and relayed.
        let mut buffer = vec![0u8; MAX_MESSAGE + 1];

        loop {
            let (length, client) = listener
                .recv_from(&mut buffer)
                .map_err(|error| ChokepointError::Relay(error.to_string()))?;

            let Some(query) = acceptable(&buffer[..length], &mut throttle) else {
                continue;
            };
            if in_flight.load(Ordering::SeqCst) >= self.max_in_flight {
                throttle.log("too many queries in flight; dropping");
                continue;
            }

            let relay = self.clone();
            let listening = listener
                .try_clone()
                .map_err(|error| ChokepointError::Relay(error.to_string()))?;
            let counter = Arc::clone(&in_flight);
            let query = query.to_vec();
            counter.fetch_add(1, Ordering::SeqCst);
            thread::spawn(move || {
                if relay.forward_udp(&listening, client, &query).is_err() {
                    // A failure to relay is not worth a log line per query: the client will time
                    // out and retry, and the reason is almost always that upstream is not ready.
                }
                counter.fetch_sub(1, Ordering::SeqCst);
            });
        }
    }

    fn forward_udp(
        &self,
        listener: &UdpSocket,
        client: SocketAddr,
        query: &[u8],
    ) -> std::io::Result<()> {
        // A fresh, connected socket per query: an off-path attacker cannot inject a reply into a
        // port it cannot guess, and one slow upstream cannot hold up the others.
        let probe = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
        probe.set_read_timeout(Some(self.timeout))?;
        probe.connect(self.upstream)?;
        probe.send(query)?;

        let mut reply = vec![0u8; MAX_MESSAGE + 1];
        let length = probe.recv(&mut reply)?;
        if length > MAX_MESSAGE {
            // Passing on a truncated reply would be worse than passing on nothing: the client would
            // see a corrupted message rather than a timeout it can retry.
            return Ok(());
        }
        listener.send_to(&reply[..length], client)?;
        Ok(())
    }

    fn serve_tcp(&self, listener: TcpListener) {
        let mut throttle = Throttle::default();
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let relay = self.clone();
            thread::spawn(move || {
                if relay.forward_tcp(stream).is_err() {
                    // The client went away, or upstream refused: nothing to say about it.
                }
            });
            let _ = &mut throttle;
        }
    }

    fn forward_tcp(&self, client: TcpStream) -> std::io::Result<()> {
        let timeout = Some(self.timeout);
        client.set_read_timeout(timeout)?;
        client.set_write_timeout(timeout)?;

        let upstream = TcpStream::connect_timeout(&self.upstream, self.timeout)?;
        upstream.set_read_timeout(timeout)?;
        upstream.set_write_timeout(timeout)?;

        let mut from_client = client.try_clone()?;
        let mut to_client = client;
        let mut to_upstream = upstream.try_clone()?;
        let mut from_upstream = upstream;

        // One connection, as many queries as the client wants to send on it.
        loop {
            let Some(query) = read_framed(&mut from_client)? else {
                return Ok(());
            };
            write_framed(&mut to_upstream, &query)?;
            let Some(reply) = read_framed(&mut from_upstream)? else {
                return Ok(());
            };
            write_framed(&mut to_client, &reply)?;
        }
    }
}

/// Read one length-prefixed DNS message, or `None` at end of stream.
fn read_framed(stream: &mut impl Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 2];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u16::from_be_bytes(header) as usize;
    if !(MIN_MESSAGE..=MAX_MESSAGE).contains(&length) {
        return Ok(None);
    }
    let mut message = vec![0u8; length];
    stream.read_exact(&mut message)?;
    Ok(Some(message))
}

/// Write one length-prefixed DNS message.
fn write_framed(stream: &mut impl Write, message: &[u8]) -> std::io::Result<()> {
    stream.write_all(&(message.len() as u16).to_be_bytes())?;
    stream.write_all(message)?;
    stream.flush()
}

/// Whether a datagram is something this relay should pass on.
fn acceptable<'a>(message: &'a [u8], throttle: &mut Throttle) -> Option<&'a [u8]> {
    if message.len() < MIN_MESSAGE {
        throttle.log("a datagram was too short to be a DNS message; dropping");
        return None;
    }
    if message.len() > MAX_MESSAGE {
        throttle.log("a datagram was larger than any DNS message; dropping");
        return None;
    }
    // The QR bit says "this is a response". A response arriving at a resolver is either a mistake
    // or an attempt to make this relay a reflector, so it is not passed on.
    if message[2] & 0x80 != 0 {
        throttle.log("a datagram claimed to be a reply, not a query; dropping");
        return None;
    }
    Some(message)
}

/// Logs a reason at most once per interval, so a flood cannot fill the journal.
#[derive(Debug, Default)]
struct Throttle {
    last: Option<Instant>,
}

impl Throttle {
    fn log(&mut self, reason: &str) {
        let now = Instant::now();
        let due = match self.last {
            None => true,
            Some(previous) => now.duration_since(previous) >= LOG_INTERVAL,
        };
        if due {
            self.last = Some(now);
            eprintln!("ghostnector-dns: {reason}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// A query: id 0x1234, an empty question, QR clear.
    fn query() -> Vec<u8> {
        let mut message = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        message.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        message
    }

    /// An upstream that answers every datagram with `reply`, and counts what it receives.
    fn fake_upstream(reply: Vec<u8>) -> (SocketAddr, Arc<AtomicUsize>, mpsc::Receiver<Vec<u8>>) {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind upstream");
        let address = socket.local_addr().expect("address");
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&seen);
        let (sender, receiver) = mpsc::channel();

        thread::spawn(move || {
            let mut buffer = vec![0u8; MAX_MESSAGE];
            loop {
                let Ok((length, from)) = socket.recv_from(&mut buffer) else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = sender.send(buffer[..length].to_vec());
                let _ = socket.send_to(&reply, from);
            }
        });

        (address, seen, receiver)
    }

    fn chokepoint(upstream: SocketAddr) -> (Chokepoint, SocketAddr) {
        let relay = Chokepoint::new(
            "127.0.0.1:0".parse().expect("listen"),
            upstream,
            Duration::from_millis(300),
        );
        let sockets = relay.bind().expect("bind");
        let address = sockets.udp.local_addr().expect("address");
        thread::spawn(move || {
            let _ = relay.serve(sockets);
        });
        (
            Chokepoint::new(
                "127.0.0.1:0".parse().expect("listen"),
                upstream,
                Duration::from_millis(300),
            ),
            address,
        )
    }

    fn ask(address: SocketAddr, message: &[u8]) -> Option<Vec<u8>> {
        let client = UdpSocket::bind("127.0.0.1:0").expect("client");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        client.send_to(message, address).expect("send");
        let mut buffer = vec![0u8; MAX_MESSAGE];
        client
            .recv_from(&mut buffer)
            .ok()
            .map(|(length, _)| buffer[..length].to_vec())
    }

    #[test]
    fn a_query_is_relayed_and_the_reply_comes_back() {
        let reply = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        let (upstream, seen, _received) = fake_upstream(reply.clone());
        let (_relay, address) = chokepoint(upstream);

        let answer = ask(address, &query()).expect("a reply");
        assert_eq!(answer, reply, "the reply must be passed through unchanged");
        assert_eq!(seen.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_query_reaches_upstream_byte_for_byte() {
        let (upstream, _seen, received) = fake_upstream(vec![0u8; 12]);
        let (_relay, address) = chokepoint(upstream);
        let sent = query();

        let _ = ask(address, &sent);
        let forwarded = received
            .recv_timeout(Duration::from_secs(2))
            .expect("upstream saw the query");
        assert_eq!(forwarded, sent, "the relay must not rewrite anything");
    }

    #[test]
    fn a_reply_arriving_as_a_query_is_not_relayed() {
        let (upstream, seen, _received) = fake_upstream(vec![0u8; 12]);
        let (_relay, address) = chokepoint(upstream);

        let mut response = query();
        response[2] |= 0x80; // QR: this is a response
        assert!(ask(address, &response).is_none());
        assert_eq!(
            seen.load(Ordering::SeqCst),
            0,
            "a reflector must not be given the chance to reflect"
        );
    }

    #[test]
    fn a_stub_of_a_datagram_is_dropped() {
        let (upstream, seen, _received) = fake_upstream(vec![0u8; 12]);
        let (_relay, address) = chokepoint(upstream);
        assert!(ask(address, &[0u8; 4]).is_none());
        assert_eq!(seen.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_datagram_larger_than_any_dns_message_is_dropped() {
        let (upstream, seen, _received) = fake_upstream(vec![0u8; 12]);
        let (_relay, address) = chokepoint(upstream);
        // Sent as one datagram, so the relay must notice the size rather than truncate it into a
        // corrupted message and pass that on.
        let oversized = vec![0u8; MAX_MESSAGE + 1];
        let _ = ask(address, &oversized);
        assert_eq!(
            seen.load(Ordering::SeqCst),
            0,
            "an oversized datagram must not be relayed, whole or truncated"
        );
    }

    #[test]
    fn a_slow_upstream_does_not_hold_up_other_queries() {
        // Upstream that answers only the query with id 0x0002, immediately; everything else waits.
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let address = socket.local_addr().expect("address");
        thread::spawn(move || {
            let mut buffer = vec![0u8; MAX_MESSAGE];
            loop {
                let Ok((length, from)) = socket.recv_from(&mut buffer) else {
                    return;
                };
                if buffer.get(1) == Some(&0x02) {
                    let _ = socket.send_to(&buffer[..length], from);
                }
                // Everything else is silently ignored, so it will time out.
            }
        });

        let (relay, _ignored) = chokepoint(address);
        let sockets = relay.bind().expect("bind");
        let listen = sockets.udp.local_addr().expect("address");
        thread::spawn(move || {
            let _ = relay.serve(sockets);
        });

        let slow = {
            let address = listen;
            thread::spawn(move || {
                let mut message = query();
                message[1] = 0x01; // will never be answered
                ask(address, &message)
            })
        };

        let mut fast = query();
        fast[1] = 0x02;
        let began = Instant::now();
        let answered = ask(listen, &fast);
        assert!(answered.is_some(), "the answerable query must be answered");
        assert!(
            began.elapsed() < Duration::from_millis(1000),
            "it must not wait for the query that will never be answered"
        );

        let _ = slow.join();
    }

    #[test]
    fn tcp_queries_are_relayed_with_their_length_prefix() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("upstream");
        let upstream = listener.local_addr().expect("address");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut header = [0u8; 2];
                if stream.read_exact(&mut header).is_err() {
                    return;
                }
                let length = u16::from_be_bytes(header) as usize;
                let mut message = vec![0u8; length];
                if stream.read_exact(&mut message).is_err() {
                    return;
                }
                let _ = stream.write_all(&(message.len() as u16).to_be_bytes());
                let _ = stream.write_all(&message);
            }
        });

        let relay = Chokepoint::new(
            "127.0.0.1:0".parse().expect("listen"),
            upstream,
            Duration::from_secs(2),
        );
        let sockets = relay.bind().expect("bind");
        let listen = sockets.tcp.local_addr().expect("address");
        thread::spawn(move || {
            let _ = relay.serve(sockets);
        });

        let mut client = TcpStream::connect(listen).expect("connect");
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let sent = query();
        write_framed(&mut client, &sent).expect("write");
        let echoed = read_framed(&mut client).expect("read").expect("a reply");
        assert_eq!(echoed, sent);
    }

    #[test]
    fn a_client_that_hangs_up_mid_tcp_query_is_not_fatal() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("upstream");
        let upstream = listener.local_addr().expect("address");
        thread::spawn(move || {
            let _ = listener.accept();
        });

        let relay = Chokepoint::new(
            "127.0.0.1:0".parse().expect("listen"),
            upstream,
            Duration::from_millis(300),
        );
        let sockets = relay.bind().expect("bind");
        let listen = sockets.tcp.local_addr().expect("address");
        thread::spawn(move || {
            let _ = relay.serve(sockets);
        });

        {
            let mut client = TcpStream::connect(listen).expect("connect");
            client.write_all(&[0x00]).expect("half a length prefix");
            // Drop without completing the message.
        }

        // The relay is still answering afterwards.
        let mut client = TcpStream::connect(listen).expect("connect again");
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        assert!(read_framed(&mut client).is_err() || true);
    }
}
