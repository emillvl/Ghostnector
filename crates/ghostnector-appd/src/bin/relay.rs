//! The transparent TCP relay inside one APP namespace.
//!
//! ## Why this exists (D-50)
//!
//! An APP namespace's default route terminates on a dead-end device, so the only way out is the
//! namespace's own `nat` chain. That chain DNATs every TCP connection to this relay, which runs
//! *inside the same namespace* as the application. Because the DNAT happened in this namespace's
//! conntrack, the relay can ask the kernel for the connection's original destination
//! (`SO_ORIGINAL_DST`) and get a real answer. A DNAT straight to the core's `TransPort` could not:
//! Tor runs in the host namespace, whose conntrack never saw the pre-NAT tuple, so real Tor could
//! not learn the destination and every connection was accepted and reset.
//!
//! The relay carries the stream to the core's **SOCKS** listener with an explicit CONNECT for the
//! original destination. Tor therefore sees the application's own source address (this process runs
//! as the application's uid, and the namespace has exactly one non-loopback address) and isolates
//! circuits by the per-group SOCKS credential.
//!
//! ## What it deliberately is not
//!
//! * It does not parse, store, or log payloads: it only splices bytes.
//! * It refuses any connection that has no original destination (a direct connection to its
//!   loopback port), so it can never be used as an open proxy for a destination of the caller's
//!   choosing.
//! * It runs as the application's own unprivileged uid with **every capability set empty**; reading
//!   `SO_ORIGINAL_DST` needs no privilege in the namespace that created the NAT.
//! * Its only reachable peer is the core's SOCKS listener; the namespace policy allows nothing else.
//!
//! ## Shutdown
//!
//! The relay holds its network namespace open, so deleting the namespace cannot stop it, and the
//! helper's packaged capability set has no `CAP_KILL`. Instead, the helper keeps the write end of
//! this process's standard input: when it closes that pipe, the relay sees end-of-file and exits.
//! A `SIGTERM` is also honoured when the helper is allowed to send one.
//!
//! ```text
//! ghostnector-appd-relay --id <N> --uid <UID> --listen-port <P> --core <IP> --socks-port <P> --source <IP>
//! ```

#![cfg(unix)]
#![forbid(unsafe_code)]

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use caps::{CapSet, CapsHashSet};
use ghostnector_spec::app::MAX_APP_GROUPS;
use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::socket::{getsockopt, sockopt};
use nix::unistd::{Gid, Uid, User};

/// The most connections one group's relay carries at once. Beyond this new connections are closed
/// immediately: the relay must not become a resource the application can exhaust without bound.
const MAX_CONNECTIONS: usize = 256;

/// How long the SOCKS greeting, authentication and CONNECT may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// The SOCKS username prefix. The group id completes it, so each group authenticates with its own
/// credential and Tor's `IsolateSOCKSAuth` gives each group its own circuit isolation.
const SOCKS_USER_PREFIX: &str = "app";

/// The SOCKS password. It is not a secret: it exists so Tor has a per-credential isolation key.
const SOCKS_PASSWORD: &str = "ghostnector";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Options {
    id: u32,
    uid: u32,
    listen_port: u16,
    core: Ipv4Addr,
    socks_port: u16,
    source: Ipv4Addr,
}

fn usage() -> String {
    "ghostnector-appd-relay --id <N> --uid <UID> --listen-port <P> --core <IP> \
     --socks-port <P> --source <IP>"
        .to_string()
}

fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Options, String> {
    let mut id: Option<u32> = None;
    let mut uid: Option<u32> = None;
    let mut listen_port: Option<u16> = None;
    let mut core: Option<Ipv4Addr> = None;
    let mut socks_port: Option<u16> = None;
    let mut source: Option<Ipv4Addr> = None;
    let mut values = arguments.into_iter().peekable();
    while let Some(option) = values.next() {
        let mut value = || {
            values
                .next()
                .ok_or_else(|| format!("'{option}' needs a value"))
        };
        match option.as_str() {
            "--id" => {
                let raw = value()?;
                let parsed: u32 = raw
                    .parse()
                    .map_err(|_| format!("'{raw}' is not a group id"))?;
                if parsed == 0 || parsed as usize > MAX_APP_GROUPS {
                    return Err(format!("group id {parsed} is outside 1..={MAX_APP_GROUPS}"));
                }
                id = Some(parsed);
            }
            "--uid" => {
                let raw = value()?;
                let parsed: u32 = raw.parse().map_err(|_| format!("'{raw}' is not a uid"))?;
                if parsed == 0 {
                    return Err("refusing to run as root".to_string());
                }
                uid = Some(parsed);
            }
            "--listen-port" => {
                let raw = value()?;
                let parsed: u16 = raw.parse().map_err(|_| format!("'{raw}' is not a port"))?;
                if parsed == 0 {
                    return Err("the listen port must not be zero".to_string());
                }
                listen_port = Some(parsed);
            }
            "--core" => {
                let raw = value()?;
                core = Some(
                    raw.parse()
                        .map_err(|_| format!("'{raw}' is not an address"))?,
                );
            }
            "--socks-port" => {
                let raw = value()?;
                let parsed: u16 = raw.parse().map_err(|_| format!("'{raw}' is not a port"))?;
                if parsed == 0 {
                    return Err("the SOCKS port must not be zero".to_string());
                }
                socks_port = Some(parsed);
            }
            "--source" => {
                let raw = value()?;
                let parsed: Ipv4Addr = raw
                    .parse()
                    .map_err(|_| format!("'{raw}' is not an address"))?;
                if parsed.is_loopback() || parsed.is_unspecified() {
                    return Err(
                        "the source address must be the application's own address".to_string()
                    );
                }
                source = Some(parsed);
            }
            other => return Err(format!("unknown option '{other}'")),
        }
    }
    Ok(Options {
        id: id.ok_or("--id is required")?,
        uid: uid.ok_or("--uid is required")?,
        listen_port: listen_port.ok_or("--listen-port is required")?,
        core: core.ok_or("--core is required")?,
        socks_port: socks_port.ok_or("--socks-port is required")?,
        source: source.ok_or("--source is required")?,
    })
}

/// Become the application's identity and drop every capability.
///
/// The sequence mirrors the launch helper: identities first (they need the capabilities), then
/// every granting set, then a check that nothing survived. The relay needs no capability at all —
/// the namespace's own conntrack answers `SO_ORIGINAL_DST` for any process in it (proved in
/// `d50-origdst-caps.log`).
fn drop_to(uid: u32) -> Result<(), String> {
    let user = User::from_uid(Uid::from_raw(uid))
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("no user with uid {uid}"))?;
    nix::unistd::setgroups(&[]).map_err(|error| format!("cannot clear groups: {error}"))?;
    nix::unistd::setgid(Gid::from_raw(user.gid.as_raw()))
        .map_err(|error| format!("cannot set gid: {error}"))?;
    nix::unistd::setuid(Uid::from_raw(uid)).map_err(|error| format!("cannot set uid: {error}"))?;
    if Uid::effective().as_raw() != uid {
        return Err("the uid change did not take effect".to_string());
    }
    for set in [
        CapSet::Ambient,
        CapSet::Effective,
        CapSet::Permitted,
        CapSet::Inheritable,
    ] {
        caps::clear(None, set).map_err(|error| format!("{set:?}: {error}"))?;
    }
    let left: CapsHashSet =
        caps::read(None, CapSet::Ambient).map_err(|error| format!("reading ambient: {error}"))?;
    if !left.is_empty() {
        return Err("ambient capabilities survived the drop".to_string());
    }
    Ok(())
}

/// The original destination of a DNAT'ed connection, from this namespace's conntrack.
///
/// `None` means the connection was not rewritten (a direct connection to the relay's loopback
/// port), and it is refused: the relay must never carry a destination a caller chose.
fn original_destination(stream: &TcpStream) -> Option<SocketAddrV4> {
    let address = getsockopt(stream, sockopt::OriginalDst).ok()?;
    decode_sockaddr_in(&address)
}

fn decode_sockaddr_in(address: &nix::libc::sockaddr_in) -> Option<SocketAddrV4> {
    if address.sin_family != nix::libc::AF_INET as u16 {
        return None;
    }
    let port = u16::from_be(address.sin_port);
    let ip = Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes());
    if port == 0 || ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return None;
    }
    Some(SocketAddrV4::new(ip, port))
}

/// The SOCKS5 greeting: version 5, one method offered, username/password (0x02). Offering only
/// username/password is deliberate: Tor's `IsolateSOCKSAuth` then gives each group its own circuit
/// isolation key.
fn greeting_bytes() -> [u8; 3] {
    [0x05, 0x01, 0x02]
}

/// The SOCKS5 RFC 1929 username/password authentication for one group.
fn auth_bytes(id: u32) -> Vec<u8> {
    let user = format!("{SOCKS_USER_PREFIX}{id}");
    let mut bytes = vec![0x01];
    bytes.push(user.len() as u8);
    bytes.extend_from_slice(user.as_bytes());
    bytes.push(SOCKS_PASSWORD.len() as u8);
    bytes.extend_from_slice(SOCKS_PASSWORD.as_bytes());
    bytes
}

/// The SOCKS5 CONNECT request for an IPv4 destination.
fn connect_request(destination: SocketAddrV4) -> Vec<u8> {
    let mut bytes = vec![0x05, 0x01, 0x00, 0x01];
    bytes.extend_from_slice(&destination.ip().octets());
    bytes.extend_from_slice(&destination.port().to_be_bytes());
    bytes
}

/// Speak SOCKS5 to the core's Tor and return the established stream.
fn connect_socks(options: &Options, destination: SocketAddrV4) -> Result<TcpStream, String> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from((options.core, options.socks_port)),
        HANDSHAKE_TIMEOUT,
    )
    .map_err(|error| format!("cannot reach the core's SOCKS listener: {error}"))?;
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| error.to_string())?;

    stream
        .write_all(&greeting_bytes())
        .map_err(|error| format!("greeting: {error}"))?;
    let mut choice = [0u8; 2];
    stream
        .read_exact(&mut choice)
        .map_err(|error| format!("greeting reply: {error}"))?;
    if choice != [0x05, 0x02] {
        return Err(format!(
            "the SOCKS listener did not choose username/password: {choice:?}"
        ));
    }
    let auth = auth_bytes(options.id);
    stream
        .write_all(&auth)
        .map_err(|error| format!("authentication: {error}"))?;
    let mut auth_reply = [0u8; 2];
    stream
        .read_exact(&mut auth_reply)
        .map_err(|error| format!("authentication reply: {error}"))?;
    if auth_reply[0] != 0x01 || auth_reply[1] != 0x00 {
        return Err(format!("authentication refused: {auth_reply:?}"));
    }

    stream
        .write_all(&connect_request(destination))
        .map_err(|error| format!("connect request: {error}"))?;
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .map_err(|error| format!("connect reply: {error}"))?;
    if head[0] != 0x05 {
        return Err(format!("not a SOCKS5 reply: {head:?}"));
    }
    if head[1] != 0x00 {
        return Err(format!(
            "the SOCKS listener refused the connection: {}",
            head[1]
        ));
    }
    // Consume the bound address so the stream is positioned at the payload.
    let mut rest = [0u8; 18];
    match head[3] {
        0x01 => stream
            .read_exact(&mut rest[..6])
            .map_err(|error| format!("connect reply address: {error}"))?,
        0x04 => stream
            .read_exact(&mut rest[..18])
            .map_err(|error| format!("connect reply address: {error}"))?,
        0x03 => {
            let mut length = [0u8; 1];
            stream
                .read_exact(&mut length)
                .map_err(|error| format!("connect reply name: {error}"))?;
            let mut name = vec![0u8; length[0] as usize + 2];
            stream
                .read_exact(&mut name)
                .map_err(|error| format!("connect reply name: {error}"))?;
        }
        other => return Err(format!("unknown SOCKS address type {other}")),
    }
    stream
        .set_read_timeout(None)
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(None)
        .map_err(|error| error.to_string())?;
    Ok(stream)
}

/// Move bytes both ways until either side closes.
fn splice(client: TcpStream, upstream: TcpStream) {
    let Ok(mut client_reader) = client.try_clone() else {
        return;
    };
    let Ok(mut upstream_writer) = upstream.try_clone() else {
        return;
    };
    let forward = std::thread::spawn(move || {
        let _ = std::io::copy(&mut client_reader, &mut upstream_writer);
        let _ = upstream_writer.shutdown(Shutdown::Write);
    });
    let mut upstream_reader = upstream;
    let mut client_writer = client;
    let _ = std::io::copy(&mut upstream_reader, &mut client_writer);
    let _ = client_writer.shutdown(Shutdown::Write);
    let _ = forward.join();
}

fn handle(options: &Options, mut client: TcpStream) -> Result<(), String> {
    let Some(destination) = original_destination(&client) else {
        // Refuse, but consume whatever the caller already sent first: the close is then a FIN, and
        // a caller sees an empty answer rather than a reset. This is also what makes the dead-router
        // state honest: the verification probe classifies an empty answer as a failure, while a read
        // error is only inconclusive.
        drain(&mut client);
        return Err("refused a connection with no original destination".to_string());
    };
    let upstream = match connect_socks(options, destination) {
        Ok(upstream) => upstream,
        Err(error) => {
            drain(&mut client);
            return Err(error);
        }
    };
    splice(client, upstream);
    Ok(())
}

/// Read and discard what the peer has already sent, bounded, so closing is a FIN rather than a RST.
fn drain(stream: &mut TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
    let mut buffer = [0u8; 4096];
    for _ in 0..64 {
        match stream.read(&mut buffer) {
            Ok(0) => return,
            Ok(_) => continue,
            Err(_) => return,
        }
    }
}

fn serve(options: &Options) -> Result<(), String> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, options.listen_port)))
        .map_err(|error| {
            format!(
                "cannot listen on 127.0.0.1:{}: {error}",
                options.listen_port
            )
        })?;
    // Validate that the application's address really exists in this namespace; the relay's whole
    // identity guarantee rests on the namespace being the one it was started in.
    TcpListener::bind(SocketAddr::from((options.source, 0))).map_err(|error| {
        format!(
            "the application's address {} is not here: {error}",
            options.source
        )
    })?;
    let live = Arc::new(AtomicUsize::new(0));
    let stdin = std::io::stdin();
    loop {
        let mut fds = [
            PollFd::new(listener.as_fd(), PollFlags::POLLIN),
            PollFd::new(stdin.as_fd(), PollFlags::POLLIN),
        ];
        match poll(&mut fds, PollTimeout::NONE) {
            Ok(0) => continue,
            Ok(_) => {}
            Err(Errno::EINTR) => continue,
            Err(error) => return Err(format!("poll failed: {error}")),
        }
        // The helper closes the write end of this pipe to ask the relay to stop.
        if fds[1].revents().is_some_and(|flags| {
            flags.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
        }) {
            return Ok(());
        }
        if !fds[0]
            .revents()
            .is_some_and(|flags| flags.contains(PollFlags::POLLIN))
        {
            continue;
        }
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("accept failed: {error}")),
        };
        if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            live.fetch_sub(1, Ordering::SeqCst);
            drop(stream);
            continue;
        }
        let options = options.clone();
        let live = Arc::clone(&live);
        std::thread::spawn(move || {
            let _ = handle(&options, stream);
            live.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

fn main() -> std::process::ExitCode {
    let options = match parse(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("ghostnector-appd-relay: {error}\n{}", usage());
            return std::process::ExitCode::from(2);
        }
    };
    if let Err(error) = drop_to(options.uid) {
        eprintln!("ghostnector-appd-relay: {error}");
        return std::process::ExitCode::FAILURE;
    }
    match serve(&options) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ghostnector-appd-relay: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(list: &[&str]) -> Vec<String> {
        list.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn the_arguments_are_an_id_a_uid_a_port_a_core_and_a_source() {
        let options = parse(arguments(&[
            "--id",
            "3",
            "--uid",
            "1000",
            "--listen-port",
            "9041",
            "--core",
            "10.200.0.1",
            "--socks-port",
            "9050",
            "--source",
            "10.200.0.3",
        ]))
        .expect("valid arguments");
        assert_eq!(options.id, 3);
        assert_eq!(options.uid, 1000);
        assert_eq!(options.listen_port, 9041);
        assert_eq!(options.core, Ipv4Addr::new(10, 200, 0, 1));
        assert_eq!(options.socks_port, 9050);
        assert_eq!(options.source, Ipv4Addr::new(10, 200, 0, 3));
    }

    #[test]
    fn the_arguments_refuse_root_and_impossible_values() {
        for bad in [
            vec![
                "--id",
                "0",
                "--uid",
                "1000",
                "--listen-port",
                "9041",
                "--core",
                "10.0.0.1",
                "--socks-port",
                "9050",
                "--source",
                "10.200.0.2",
            ],
            vec![
                "--id",
                "33",
                "--uid",
                "1000",
                "--listen-port",
                "9041",
                "--core",
                "10.0.0.1",
                "--socks-port",
                "9050",
                "--source",
                "10.200.0.2",
            ],
            vec![
                "--id",
                "1",
                "--uid",
                "0",
                "--listen-port",
                "9041",
                "--core",
                "10.0.0.1",
                "--socks-port",
                "9050",
                "--source",
                "10.200.0.2",
            ],
            vec![
                "--id",
                "1",
                "--uid",
                "1000",
                "--listen-port",
                "0",
                "--core",
                "10.0.0.1",
                "--socks-port",
                "9050",
                "--source",
                "10.200.0.2",
            ],
            vec![
                "--id",
                "1",
                "--uid",
                "1000",
                "--listen-port",
                "9041",
                "--core",
                "10.0.0.1",
                "--socks-port",
                "9050",
                "--source",
                "127.0.0.1",
            ],
            vec![
                "--id",
                "1",
                "--uid",
                "1000",
                "--listen-port",
                "9041",
                "--core",
                "10.0.0.1",
                "--socks-port",
                "9050",
                "--source",
                "0.0.0.0",
            ],
            vec![
                "--id",
                "1",
                "--uid",
                "1000",
                "--listen-port",
                "9041",
                "--core",
                "10.0.0.1",
                "--socks-port",
                "9050",
            ],
            vec!["--netns", "ghapp1", "--uid", "1000"],
        ] {
            assert!(parse(arguments(&bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_loopback_or_unset_original_destination_is_refused() {
        let mut address = nix::libc::sockaddr_in {
            sin_family: nix::libc::AF_INET as u16,
            sin_port: 80u16.to_be(),
            sin_addr: nix::libc::in_addr {
                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
            sin_zero: [0; 8],
        };
        assert!(
            decode_sockaddr_in(&address).is_none(),
            "loopback must be refused"
        );

        address.sin_addr.s_addr = u32::from_ne_bytes([0, 0, 0, 0]);
        assert!(
            decode_sockaddr_in(&address).is_none(),
            "unset must be refused"
        );

        address.sin_addr.s_addr = u32::from_ne_bytes([198, 51, 100, 10]);
        assert_eq!(
            decode_sockaddr_in(&address),
            Some(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 10), 80))
        );

        address.sin_family = nix::libc::AF_INET6 as u16;
        assert!(
            decode_sockaddr_in(&address).is_none(),
            "a non-IPv4 family must be refused"
        );
    }

    #[test]
    fn the_socks_bytes_are_the_protocol() {
        assert_eq!(
            greeting_bytes(),
            [0x05, 0x01, 0x02],
            "user/password is the only method"
        );

        let auth = auth_bytes(7);
        assert_eq!(auth[0], 0x01, "RFC 1929 version");
        assert_eq!(auth[1], 4, "username length");
        assert_eq!(&auth[2..6], b"app7");
        assert_eq!(auth[6], 11, "password length");
        assert_eq!(&auth[7..], b"ghostnector");

        let request = connect_request(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 443));
        assert_eq!(
            request,
            vec![0x05, 0x01, 0x00, 0x01, 203, 0, 113, 9, 0x01, 0xbb]
        );
    }
}
