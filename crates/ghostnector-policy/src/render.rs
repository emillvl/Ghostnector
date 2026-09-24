//! Rendering a ruleset to nftables syntax.
//!
//! The output of this module is the exact text that gets handed to the kernel, so it is rendered
//! deterministically and pinned by golden files (`golden/*.nft`). A policy change therefore shows
//! up as a reviewable diff rather than as a silent behavioural change.
//!
//! Rendering is a *canonical projection*, not a transliteration: a rule that matches a port renders
//! as `udp dport 53` rather than `meta l4proto udp udp dport 53`. The golden files show the policy
//! as nftables will see it.
//!
//! Requires `nft` ≥ 1.0.2 for `destroy table` (used to replace the table atomically). Ubuntu 24.04
//! ships 1.0.9.
//!
//! Nothing here interpolates user input: interface names, set names, comments, and ports all come
//! from the compiler's own constants and typed values, which is what keeps invariant I9 meaningful
//! at the last step before the kernel.

use std::fmt::Write;

use crate::ir::{
    Chain, ChainKind, CtState, Expr, Family, Hook, Proto, RejectKind, Rule, Ruleset, Set, SetKind,
    Verdict,
};

/// The single table Ghostnector owns.
pub const TABLE: &str = "ghostnector";

/// Render the ruleset's table block, ready to be included in an `nft -f` batch.
pub fn render_table(ruleset: &Ruleset) -> String {
    let mut out = String::new();
    for table in &ruleset.tables {
        let family = match table.family {
            Family::Inet => "inet",
        };
        let _ = writeln!(out, "table {family} {} {{", table.name);
        for set in &table.sets {
            render_set(&mut out, set);
        }
        for chain in &table.chains {
            render_chain(&mut out, chain, &table.sets);
        }
        out.push_str("}\n");
    }
    out
}

/// Render a full replace: drop whatever Ghostnector owned, then define it again.
///
/// This whole script is one `nft -f` invocation, which nftables applies as a single transaction, so
/// there is no window in which the machine is half-protected (invariant I7).
pub fn render_replace_script(ruleset: &Ruleset) -> String {
    let mut out = format!("destroy table inet {TABLE}\n");
    out.push_str(&render_table(ruleset));
    out
}

/// Render the revert: remove exactly what Ghostnector owns, and nothing else.
pub fn render_revert_script() -> String {
    format!("destroy table inet {TABLE}\n")
}

fn render_set(out: &mut String, set: &Set) {
    let kind = match set.kind {
        SetKind::Ipv4Addr => "ipv4_addr",
        SetKind::Ipv6Addr => "ipv6_addr",
    };
    let _ = writeln!(out, "    set {} {{", set.name);
    let _ = writeln!(out, "        type {kind}");
    // Address prefixes require an interval set.
    let _ = writeln!(out, "        flags interval");
    let elements = set
        .elements
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(out, "        elements = {{ {elements} }}");
    out.push_str("    }\n");
}

fn render_chain(out: &mut String, chain: &Chain, sets: &[Set]) {
    let kind = match chain.kind {
        ChainKind::Filter => "filter",
        ChainKind::Nat => "nat",
    };
    let hook = match chain.hook {
        Hook::Prerouting => "prerouting",
        Hook::Input => "input",
        Hook::Output => "output",
        Hook::Forward => "forward",
        Hook::Postrouting => "postrouting",
    };
    let policy = match chain.policy {
        Verdict::Accept => "accept",
        Verdict::Drop => "drop",
        // nftables does not permit a reject policy on a base chain.
        Verdict::Reject { .. } => "drop",
        Verdict::Return => "accept",
        Verdict::Redirect { .. } => "accept",
    };
    let _ = writeln!(out, "    chain {} {{", chain.name);
    let _ = writeln!(
        out,
        "        type {kind} hook {hook} priority {}; policy {policy};",
        chain.priority
    );
    for rule in &chain.rules {
        render_rule(out, rule, sets);
    }
    out.push_str("    }\n");
}

/// Render one rule. `sets` is needed to pick `ip daddr` versus `ip6 daddr` for set matches.
fn render_rule(out: &mut String, rule: &Rule, sets: &[Set]) {
    let mut parts: Vec<String> = Vec::new();

    // A port match implies its protocol, so the protocol expression is folded into it — unless
    // there is more than one port match, in which case nftables needs each one qualified
    // (`udp sport 68 udp dport 67`): it cannot infer the second from the first.
    let port_proto = rule.exprs.iter().find_map(|expr| match expr {
        Expr::L4Proto { proto } => Some(*proto),
        _ => None,
    });
    let port_matches = rule
        .exprs
        .iter()
        .filter(|expr| matches!(expr, Expr::Dport { .. } | Expr::Sport { .. }))
        .count();
    let mut protocol_written = false;
    let mut port_match = |parts: &mut Vec<String>, keyword: &str, port: u16| {
        let qualified = port_matches > 1 || !protocol_written;
        protocol_written = true;
        match (qualified, port_proto) {
            (true, Some(proto)) => parts.push(format!("{} {keyword} {port}", proto_name(proto))),
            _ => parts.push(format!("{keyword} {port}")),
        }
    };

    for expr in &rule.exprs {
        match expr {
            Expr::Skuid { uid } => parts.push(format!("meta skuid {uid}")),
            Expr::SkuidNot { uid } => parts.push(format!("meta skuid != {uid}")),
            Expr::Iifname { name } => parts.push(format!("iifname \"{}\"", sanitise(name))),
            Expr::Oifname { name } => parts.push(format!("oifname \"{}\"", sanitise(name))),
            Expr::L4Proto { proto } => {
                if rule
                    .exprs
                    .iter()
                    .any(|e| matches!(e, Expr::Dport { .. } | Expr::Sport { .. }))
                {
                    continue; // folded into the port match below
                }
                parts.push(format!("meta l4proto {}", proto_name(*proto)));
            }
            Expr::Dport { port } => port_match(&mut parts, "dport", *port),
            Expr::Sport { port } => port_match(&mut parts, "sport", *port),
            Expr::DaddrInSet { set } => {
                let family = sets
                    .iter()
                    .find(|candidate| candidate.name == *set)
                    .map(|candidate| candidate.kind);
                match family {
                    Some(SetKind::Ipv6Addr) => parts.push(format!("ip6 daddr @{set}")),
                    _ => parts.push(format!("ip daddr @{set}")),
                }
            }
            Expr::CtState { state } => parts.push(format!("ct state {}", ct_state(*state))),
        }
    }

    if rule.counter {
        parts.push("counter".to_string());
    }

    parts.push(render_verdict(rule.verdict));

    if !rule.comment.is_empty() {
        parts.push(format!("comment \"{}\"", sanitise(&rule.comment)));
    }

    let _ = writeln!(out, "        {}", parts.join(" "));
}

fn render_verdict(verdict: Verdict) -> String {
    match verdict {
        Verdict::Accept => "accept".to_string(),
        Verdict::Drop => "drop".to_string(),
        Verdict::Return => "return".to_string(),
        Verdict::Redirect { port } => format!("redirect to :{port}"),
        Verdict::Reject { kind } => match kind {
            RejectKind::AdminProhibited => "reject with icmpx type admin-prohibited".to_string(),
            RejectKind::PortUnreachable => "reject with icmpx type port-unreachable".to_string(),
            RejectKind::TcpReset => "reject with tcp reset".to_string(),
        },
    }
}

fn proto_name(proto: Proto) -> &'static str {
    match proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
        Proto::Icmp => "icmp",
        Proto::Icmpv6 => "ipv6-icmp",
    }
}

fn ct_state(state: CtState) -> &'static str {
    match state {
        CtState::Established => "established",
        CtState::Related => "related",
        CtState::New => "new",
        CtState::Invalid => "invalid",
    }
}

/// Interface names and comments come from the compiler's own constants, but defence in depth is
/// cheap: strip the two characters that could break out of a quoted nft string.
fn sanitise(text: &str) -> String {
    text.replace(['"', '\\'], "'")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::{compile, Environment};
    use ghostnector_spec::backend::{Params, ProfileId};
    use std::path::PathBuf;

    fn env() -> Environment {
        Environment {
            tor_uid: Some(987),
            dnscrypt_uid: Some(988),
            trans_port: 9040,
            chokepoint_port: 9054,
            socks_port: 9050,
            dhcp_client_port: 68,
        }
    }

    fn cases() -> Vec<(&'static str, ProfileId, Params)> {
        vec![
            ("fail_closed.nft", ProfileId::FailClosed, Params::default()),
            (
                "dns_lockdown.nft",
                ProfileId::DnsLockdown,
                Params::default(),
            ),
            ("tor_system.nft", ProfileId::TorSystem, Params::default()),
            (
                "tor_system_lan.nft",
                ProfileId::TorSystem,
                Params {
                    allow_lan: true,
                    ..Params::default()
                },
            ),
            (
                "tor_user.nft",
                ProfileId::TorUser,
                Params {
                    user_uid: Some(1000),
                    ..Params::default()
                },
            ),
        ]
    }

    fn golden_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("golden")
    }

    #[test]
    fn rendering_is_deterministic() {
        let policy = compile(ProfileId::TorSystem, &Params::default(), &env()).unwrap();
        let first = render_replace_script(&policy.ruleset);
        let second = render_replace_script(&policy.ruleset);
        assert_eq!(first, second);
    }

    #[test]
    fn every_compiled_profile_renders_something_applicable() {
        for (name, profile, params) in cases() {
            let policy = compile(profile, &params, &env()).unwrap();
            let rendered = render_replace_script(&policy.ruleset);
            assert!(
                rendered.starts_with("destroy table inet ghostnector"),
                "{name} must replace the table it owns"
            );
            assert!(rendered.contains("table inet ghostnector {"), "{name}");
            for chain in policy.ruleset.chain_names() {
                assert!(rendered.contains(&format!("chain {chain} {{")), "{name}");
            }
            assert!(rendered.ends_with("}\n"), "{name} must close the table");
        }
    }

    #[test]
    fn tor_system_claims_port_53_before_the_catch_all() {
        let policy = compile(ProfileId::TorSystem, &Params::default(), &env()).unwrap();
        let rendered = render_replace_script(&policy.ruleset);
        let dns = rendered
            .find("udp dport 53 counter redirect to :9054")
            .expect("the DNS redirect must be rendered");
        let catch_all = rendered
            .find("redirect to :9040")
            .expect("the Tor redirect must be rendered");
        assert!(dns < catch_all);
    }

    #[test]
    fn redirects_never_target_a_privileged_port_and_are_loopback_ports() {
        // The rendered redirects are the ports the compiler declared; nothing else can appear.
        for (name, profile, params) in cases() {
            let policy = compile(profile, &params, &env()).unwrap();
            for line in render_replace_script(&policy.ruleset).lines() {
                if let Some(rest) = line.split("redirect to :").nth(1) {
                    let port: u16 = rest
                        .split_whitespace()
                        .next()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or_else(|| panic!("{name} has an unparseable redirect: {line}"));
                    assert!(
                        port == 9040 || port == 9054,
                        "{name} redirected to {port}, which is not a Ghostnector port"
                    );
                }
            }
        }
    }

    #[test]
    fn revert_touches_only_our_table() {
        assert_eq!(render_revert_script(), "destroy table inet ghostnector\n");
    }

    #[test]
    fn a_second_port_match_in_a_rule_is_qualified_by_its_protocol() {
        // nftables cannot infer the protocol for a second port match, so `udp sport 68 dport 67` is a
        // syntax error and the policy never reaches the kernel. That is how the inverted DHCP
        // exemption was found the second time: the first fix rendered a rule nft refused.
        for (name, profile, params) in cases() {
            let policy = compile(profile, &params, &env()).unwrap();
            for line in render_replace_script(&policy.ruleset).lines() {
                let words: Vec<&str> = line.split_whitespace().collect();
                for window in words.windows(3) {
                    let port_keyword = matches!(window[0], "sport" | "dport");
                    let followed_by_port = matches!(window[2], "sport" | "dport");
                    assert!(
                        !(port_keyword && followed_by_port),
                        "{name} renders two port matches without qualifying the second: {line}"
                    );
                }
            }
        }
    }

    #[test]
    fn rendered_policies_match_their_golden_files() {
        let update = std::env::var("GHOSTNECTOR_UPDATE_GOLDEN").is_ok();
        let dir = golden_dir();
        std::fs::create_dir_all(&dir).unwrap();

        for (name, profile, params) in cases() {
            let policy = compile(profile, &params, &env()).unwrap();
            let rendered = render_replace_script(&policy.ruleset);
            let path = dir.join(name);

            if update {
                std::fs::write(&path, &rendered).unwrap();
                continue;
            }

            let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
                panic!("missing golden file {name}; regenerate with GHOSTNECTOR_UPDATE_GOLDEN=1")
            });
            assert_eq!(
                expected, rendered,
                "golden mismatch for {name}: the policy changed. Review the diff, then \
                 regenerate deliberately with GHOSTNECTOR_UPDATE_GOLDEN=1"
            );
        }
    }
}
