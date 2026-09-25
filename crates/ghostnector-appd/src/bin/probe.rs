//! The fixed verification probe.
//!
//! `appd` runs this binary inside one APP namespace, as an unprivileged user, with **no command
//! line at all**: the namespace id and the drop-to uid come from the helper's own configuration,
//! and the check endpoints arrive on standard input as JSON. It answers the same three questions
//! the host-scope verifier answers, and prints typed verdicts; it never decides the state itself.
//!
//! It is deliberately tiny and has no capability to do anything else: enter the namespace, drop
//! every privilege, run three network checks, print JSON.

#![cfg(unix)]
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::process::ExitCode;
use std::time::Duration;

use caps::CapSet;
use ghostnector_spec::app::APP_NETNS_PREFIX;
use ghostnector_spec::appd::{CanaryCheck, CheckStatus, CheckVerdict, ProbeConfig};
use nix::sched::{setns, CloneFlags};
use nix::unistd::{Gid, Uid, User};

const NETNS_DIR: &str = "/run/netns";

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let mut id: Option<u32> = None;
    let mut uid: Option<u32> = None;
    while let Some(option) = arguments.next() {
        let value = arguments.next().unwrap_or_default();
        match option.as_str() {
            "--id" => id = value.parse().ok(),
            "--uid" => uid = value.parse().ok(),
            _ => {}
        }
    }
    let (Some(id), Some(uid)) = (id, uid) else {
        eprintln!("ghostnector-appd-probe: --id and --uid are required");
        return ExitCode::from(2);
    };
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        eprintln!("ghostnector-appd-probe: no configuration on standard input");
        return ExitCode::from(2);
    }
    let config: ProbeConfig = match serde_json::from_str(&input) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("ghostnector-appd-probe: bad configuration: {error}");
            return ExitCode::from(2);
        }
    };

    if let Err(error) = enter_and_drop(id, uid) {
        eprintln!("ghostnector-appd-probe: {error}");
        return ExitCode::FAILURE;
    }

    let timeout = Duration::from_secs(config.timeout_seconds.clamp(1, 60));
    let config_core = config.core;
    let verdicts = vec![
        check_udp(config.udp, timeout),
        check_path(config.http.as_ref(), timeout, config_core),
        check_canary(config.canary.as_ref(), timeout),
    ];
    let encoded = serde_json::to_string(&verdicts).unwrap_or_else(|_| "[]".to_string());
    println!("{encoded}");
    ExitCode::SUCCESS
}

fn enter_and_drop(id: u32, uid: u32) -> Result<(), String> {
    let user = User::from_uid(Uid::from_raw(uid))
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("no user with uid {uid}"))?;
    let netns = format!("{NETNS_DIR}/{APP_NETNS_PREFIX}{id}");
    let file = std::fs::File::open(&netns).map_err(|error| format!("{netns}: {error}"))?;
    setns(&file, CloneFlags::CLONE_NEWNET).map_err(|error| format!("setns: {error}"))?;

    // Identities first (they need the capabilities), then every granting capability.
    nix::unistd::setgroups(&[]).map_err(|error| format!("setgroups: {error}"))?;
    nix::unistd::setgid(Gid::from_raw(user.gid.as_raw()))
        .map_err(|error| format!("setgid: {error}"))?;
    nix::unistd::setuid(Uid::from_raw(uid)).map_err(|error| format!("setuid: {error}"))?;
    for set in [
        CapSet::Ambient,
        CapSet::Effective,
        CapSet::Permitted,
        CapSet::Inheritable,
    ] {
        caps::clear(None, set).map_err(|error| format!("{set:?}: {error}"))?;
    }
    Ok(())
}

fn check_udp(endpoint: Option<SocketAddr>, timeout: Duration) -> CheckVerdict {
    let Some(endpoint) = endpoint else {
        return verdict(
            "udp",
            CheckStatus::Inconclusive,
            "no UDP endpoint is configured to check against",
        );
    };
    let socket = match UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)) {
        Ok(socket) => socket,
        Err(error) => {
            return verdict(
                "udp",
                CheckStatus::Inconclusive,
                &format!("no UDP socket: {error}"),
            )
        }
    };
    if socket.set_read_timeout(Some(timeout)).is_err() {
        return verdict("udp", CheckStatus::Inconclusive, "no UDP timeout");
    }
    if socket.send_to(&[0u8], endpoint).is_err() {
        return verdict("udp", CheckStatus::Passed, "UDP could not leave");
    }
    let mut buffer = [0u8; 64];
    match socket.recv_from(&mut buffer) {
        Ok((_, from)) => verdict(
            "udp",
            CheckStatus::Failed,
            &format!("a UDP datagram reached {from}: something is letting UDP out"),
        ),
        Err(error)
            if error.kind() == std::io::ErrorKind::TimedOut
                || error.kind() == std::io::ErrorKind::WouldBlock
                || error.kind() == std::io::ErrorKind::ConnectionRefused =>
        {
            verdict("udp", CheckStatus::Passed, "UDP was refused")
        }
        Err(error) => verdict(
            "udp",
            CheckStatus::Inconclusive,
            &format!("the UDP check was inconclusive: {error}"),
        ),
    }
}

fn check_path(
    endpoint: Option<&ghostnector_spec::appd::HttpCheck>,
    timeout: Duration,
    config_core: Option<Ipv4Addr>,
) -> CheckVerdict {
    let Some(endpoint) = endpoint else {
        return verdict(
            "protected-path",
            CheckStatus::Inconclusive,
            "no check endpoint is configured",
        );
    };
    let stream = match TcpStream::connect_timeout(&endpoint.address, timeout) {
        Ok(stream) => stream,
        Err(error) => {
            return verdict(
                "protected-path",
                CheckStatus::Failed,
                &format!("the protected path did not carry a connection: {error}"),
            )
        }
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut writer = match stream.try_clone() {
        Ok(writer) => writer,
        Err(error) => {
            return verdict(
                "protected-path",
                CheckStatus::Inconclusive,
                &format!("no second handle: {error}"),
            )
        }
    };
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: ghostnector-check\r\n\r\n",
        endpoint.path, endpoint.host
    );
    if writer.write_all(request.as_bytes()).is_err() {
        return verdict(
            "protected-path",
            CheckStatus::Inconclusive,
            "the request could not be sent",
        );
    }
    let mut response = Vec::new();
    if stream.take(8192).read_to_end(&mut response).is_err() {
        return verdict(
            "protected-path",
            CheckStatus::Inconclusive,
            "the answer could not be read",
        );
    }
    let text = String::from_utf8_lossy(&response).to_string();
    let status = text.lines().next().unwrap_or("").to_string();
    if !status.contains(" 200") {
        return verdict(
            "protected-path",
            CheckStatus::Failed,
            &format!("the check endpoint answered '{status}'"),
        );
    }
    let address = first_ipv4(&text);
    if let Some(reported) = address {
        // "This machine" inside a namespace is its own addresses plus the core address; an exit
        // that is one of those is the machine answering itself.
        let mut local = local_addresses();
        if let Some(core) = config_core {
            local.push(core);
        }
        if local.contains(&reported) {
            return verdict(
                "protected-path",
                CheckStatus::Failed,
                "the check endpoint saw this namespace's own address",
            );
        }
    }
    let mut result = verdict(
        "protected-path",
        CheckStatus::Passed,
        "the protected path answered",
    );
    result.address = address;
    result
}

/// The addresses of this process's interfaces, as seen from inside the namespace.
fn local_addresses() -> Vec<Ipv4Addr> {
    let mut addresses = Vec::new();
    if let Ok(interfaces) = nix::ifaddrs::getifaddrs() {
        for interface in interfaces {
            if let Some(address) = interface.address {
                if let Some(ipv4) = address.as_sockaddr_in() {
                    addresses.push(ipv4.ip());
                }
            }
        }
    }
    addresses
}

fn check_canary(canary: Option<&CanaryCheck>, timeout: Duration) -> CheckVerdict {
    let Some(canary) = canary else {
        return verdict(
            "canary",
            CheckStatus::Inconclusive,
            "no canary name is configured",
        );
    };
    let id: u16 = 0x4748;
    let query = build_query(id, &canary.name);
    let socket = match UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)) {
        Ok(socket) => socket,
        Err(error) => {
            return verdict(
                "canary",
                CheckStatus::Inconclusive,
                &format!("no DNS socket: {error}"),
            )
        }
    };
    if socket.set_read_timeout(Some(timeout)).is_err() {
        return verdict("canary", CheckStatus::Inconclusive, "no DNS timeout");
    }
    if socket.send_to(&query, canary.resolver).is_err() {
        return verdict(
            "canary",
            CheckStatus::Inconclusive,
            "the canary query could not be sent",
        );
    }
    let mut response = [0u8; 1024];
    let length = match socket.recv(&mut response) {
        Ok(length) => length,
        Err(error) => {
            return verdict(
                "canary",
                CheckStatus::Inconclusive,
                &format!("the canary did not answer: {error}"),
            )
        }
    };
    match parse_addresses(&response[..length], id) {
        Ok((rcode, _)) if rcode != 0 => verdict(
            "canary",
            CheckStatus::Inconclusive,
            &format!("the canary was refused with response code {rcode}"),
        ),
        Ok((_, addresses)) if addresses.is_empty() => verdict(
            "canary",
            CheckStatus::Inconclusive,
            "the canary resolved to no address",
        ),
        Ok((_, addresses)) if addresses.contains(&canary.expected) => verdict(
            "canary",
            CheckStatus::Passed,
            "the canary resolved as expected",
        ),
        Ok((_, addresses)) => verdict(
            "canary",
            CheckStatus::Failed,
            &format!(
                "the canary resolved to {} instead of the expected address",
                addresses
                    .iter()
                    .map(Ipv4Addr::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
        Err(reason) => verdict(
            "canary",
            CheckStatus::Inconclusive,
            &format!("the canary answer was unusable: {reason}"),
        ),
    }
}

fn verdict(check: &str, status: CheckStatus, detail: &str) -> CheckVerdict {
    CheckVerdict {
        check: check.to_string(),
        status,
        detail: detail.to_string(),
        address: None,
    }
}

fn first_ipv4(text: &str) -> Option<Ipv4Addr> {
    for token in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        if let Ok(address) = token.parse::<Ipv4Addr>() {
            return Some(address);
        }
    }
    None
}

fn build_query(id: u16, name: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&[0x01, 0x00]);
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        message.push(label.len().min(63) as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message
}

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

fn skip_name(message: &[u8], mut offset: usize) -> Result<usize, String> {
    loop {
        let Some(&length) = message.get(offset) else {
            return Err("a name ran past the end of the answer".to_string());
        };
        if length == 0 {
            return Ok(offset + 1);
        }
        if length & 0xc0 == 0xc0 {
            return Ok(offset + 2);
        }
        offset += 1 + length as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_can_be_read_back_by_the_parser() {
        let query = build_query(0x1234, "canary.test");
        // A minimal answer to that question, with one address.
        let mut reply = query[..2].to_vec();
        reply.extend_from_slice(&[0x81, 0x80]);
        reply.extend_from_slice(&1u16.to_be_bytes());
        reply.extend_from_slice(&1u16.to_be_bytes());
        reply.extend_from_slice(&[0, 0, 0, 0]);
        reply.extend_from_slice(&query[12..]);
        reply.extend_from_slice(&[0xc0, 0x0c]);
        reply.extend_from_slice(&1u16.to_be_bytes());
        reply.extend_from_slice(&1u16.to_be_bytes());
        reply.extend_from_slice(&60u32.to_be_bytes());
        reply.extend_from_slice(&4u16.to_be_bytes());
        reply.extend_from_slice(&[203, 0, 113, 9]);
        let (rcode, addresses) = parse_addresses(&reply, 0x1234).expect("parse");
        assert_eq!(rcode, 0);
        assert_eq!(addresses, vec![Ipv4Addr::new(203, 0, 113, 9)]);
    }

    #[test]
    fn the_first_address_in_a_body_is_found() {
        assert_eq!(
            first_ipv4("HTTP/1.0 200 OK\r\n\r\n203.0.113.9\n"),
            Some(Ipv4Addr::new(203, 0, 113, 9))
        );
        assert_eq!(first_ipv4("no address here"), None);
    }

    #[test]
    fn without_configuration_every_check_is_inconclusive() {
        let timeout = Duration::from_millis(100);
        for verdict in [
            check_udp(None, timeout),
            check_path(None, timeout, None),
            check_canary(None, timeout),
        ] {
            assert_eq!(verdict.status, CheckStatus::Inconclusive, "{verdict:?}");
        }
    }
}
