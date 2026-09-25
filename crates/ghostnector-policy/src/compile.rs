//! The compiler: a named profile becomes a ruleset, or nothing at all.
//!
//! Three properties make this safe to put in front of the kernel:
//!
//! 1. **It cannot be called with an incoherent request.** The input is a [`ProfileId`] plus typed
//!    [`Params`] — the same closed vocabulary the privileged helper accepts over IPC (invariant
//!    I9) — so there is no way to ask for a policy the design does not have.
//! 2. **It checks its own output.** Every compiled ruleset is run through
//!    [`crate::invariants::check`] before it is returned. A compiler bug therefore surfaces as a
//!    rejected policy, not as a hole in the firewall.
//! 3. **The exemption list is derived, not asserted.** The effective exemptions are the subjects
//!    the rules actually cite, resolved against the catalogue. The interface can therefore never
//!    display a hole that does not exist, nor hide one that does.

use ghostnector_spec::backend::{Params, ProfileId};
use ghostnector_spec::exemption::{
    catalogue, Exemption, SUBJECT_DHCP, SUBJECT_DNSCRYPT, SUBJECT_LAN, SUBJECT_TOR,
};
use ghostnector_spec::profile::Scope;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

use crate::invariants::{
    check, CheckContext, InvariantViolation, PolicyShape, APP_CORE_SET, LOOPBACK4_SET,
    LOOPBACK6_SET, TABLE_NAME,
};
use crate::ir::{
    Chain, ChainKind, Expr, Family, Hook, Mechanism, Proto, RejectKind, Rule, RuleOrigin, Ruleset,
    Set, SetKind, Table, Verdict,
};

/// Address ranges considered "the local network" when the LAN exception is enabled.
///
/// Loopback is deliberately absent: it is handled by a rule that applies in every profile, so
/// including it here would be redundant noise in the policy.
const LAN4: [&str; 4] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
];
const LAN6: [&str; 3] = ["fc00::/7", "fe80::/10", "ff00::/8"];

/// The `nat` chain must run *before* the filter chains, or the redirect never happens and the
/// filter's default deny rejects the traffic instead.
///
/// This is not a style preference. Two chains on the same hook with the same priority are evaluated
/// in an order the kernel does not define, and an observed run showed exactly the failure that
/// follows: the filter rejected DNS and TCP before the `nat` chain could redirect them, so the
/// redirect rules' counters stayed at zero while everything the profile was supposed to carry was
/// dropped. The invariant checker enforces the relationship, not these particular numbers.
const NAT_PRIORITY: i32 = -100;
/// Filter chains run after `nat`. `accept` here is not final across tables, so a third-party
/// firewall still gets its say.
const FILTER_PRIORITY: i32 = 0;

/// Loopback destinations, by address rather than by interface.
///
/// An observed run showed why those are not the same thing: a packet that `redirect` has just
/// rewritten to a loopback port still reports its *original* output interface while the filter chain
/// runs, because the kernel recomputes the route after the filter verdict for locally generated
/// packets. A rule that accepted "the loopback interface" therefore did not accept the traffic the
/// redirect had produced: it was rejected, and everything the profile was supposed to carry was
/// dropped instead.
///
/// A packet whose destination is a loopback address cannot leave the machine, so accepting it is
/// safe, and unlike an interface match it does not depend on when the route was last computed.
const LOOPBACK4: [&str; 1] = ["127.0.0.0/8"];
const LOOPBACK6: [&str; 1] = ["::1/128"];

/// Resolved identities and ports the policy needs to name.
///
/// Identities are optional because a machine need not have every service installed: Tor mode works
/// on a host without a resolver installed, and vice versa. A profile fails only when it needs an
/// identity that is absent, and says which one.
///
/// There is deliberately no `Default` implementation, because a policy compiled from guessed uids
/// would silently protect the wrong processes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    /// The uid Tor runs as, if Tor is installed. Its egress must be direct or the design is
    /// circular.
    pub tor_uid: Option<u32>,
    /// The uid the encrypted-DNS resolver runs as, if one is installed.
    pub dnscrypt_uid: Option<u32>,
    /// Port Tor's transparent proxy listens on (loopback only).
    pub trans_port: u16,
    /// Port the DNS chokepoint listens on (loopback only).
    pub chokepoint_port: u16,
    /// Port Tor's SOCKS proxy listens on (loopback only).
    pub socks_port: u16,
    /// Port the DHCP client uses as a source, allowed so the link survives.
    pub dhcp_client_port: u16,
    /// The host-local address an APP namespace's DNAT targets, and the address the app-facing
    /// listeners bind. Never a routable destination; the helper derives it from its own
    /// configuration and validates it (M8 decision 1).
    pub app_core: Ipv4Addr,
    /// Prefix length of the APP address space. Used by the namespace helper to allocate app
    /// addresses; the host policy only ever names the core address itself.
    pub app_prefix: u8,
    /// The bridge that carries app links on the host side. The helper generates and validates it;
    /// it is never accepted from a peer.
    pub app_bridge: String,
}

impl Environment {
    /// The APP address space this environment describes, for the namespace helper's address
    /// allocation. The policy engine itself never needs the prefix: it names the core host address.
    pub fn app_network(&self) -> (std::net::Ipv4Addr, u8) {
        (self.app_core, self.app_prefix)
    }
}

/// A ruleset that has been compiled and verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledPolicy {
    /// The profile this ruleset realises.
    pub profile: ProfileId,
    /// The policy, ready to be applied atomically.
    pub ruleset: Ruleset,
    /// The complete list of holes, for display (invariant I8).
    pub exemptions: Vec<Exemption>,
}

/// Reasons a policy could not be compiled.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The compiler produced something that violates the design's own invariants.
    #[error("compiled policy violates its own invariants: {} occurrence(s)", .0.len())]
    InvariantViolations(Vec<InvariantViolation>),
    /// A profile was requested without the parameter it needs.
    #[error("profile {0:?} requires the parameter '{1}'")]
    MissingParameter(ProfileId, &'static str),
    /// A parameter is present but cannot be used.
    #[error("parameter '{0}' is not usable: {1}")]
    InvalidParameter(&'static str, &'static str),
    /// The profile is part of the design but not implemented in this milestone.
    #[error("profile {0:?} is not implemented yet")]
    Unsupported(ProfileId),
    /// A rule cited an exemption subject that is not in the catalogue. Compiler bug.
    #[error("the compiler cited exemption '{0}', which is not in the catalogue")]
    UnknownExemption(String),
    /// The profile needs a service that is not installed on this machine.
    #[error("this profile needs the {0} service, which is not installed")]
    MissingIdentity(&'static str),
}

impl From<Vec<InvariantViolation>> for PolicyError {
    fn from(violations: Vec<InvariantViolation>) -> Self {
        PolicyError::InvariantViolations(violations)
    }
}

/// Compile a named profile into a verified ruleset.
pub fn compile(
    profile: ProfileId,
    params: &Params,
    env: &Environment,
) -> Result<CompiledPolicy, PolicyError> {
    let (scope, chains, sets, shape, require_dns_redirect) = match profile {
        ProfileId::FailClosed => (
            Scope::System,
            fail_closed_chains(env)?,
            table_sets(params.allow_lan),
            PolicyShape::Machine,
            false,
        ),
        ProfileId::DnsLockdown => (
            Scope::System,
            dns_lockdown_chains(env, params.allow_lan)?,
            table_sets(params.allow_lan),
            PolicyShape::Machine,
            true,
        ),
        ProfileId::TorSystem => (
            Scope::System,
            tor_chains(env, Scope::System, None, params.allow_lan)?,
            table_sets(params.allow_lan),
            PolicyShape::Machine,
            true,
        ),
        ProfileId::TorUser => {
            let uid = params
                .user_uid
                .ok_or(PolicyError::MissingParameter(profile, "user_uid"))?;
            validate_user_uid(uid, env)?;
            (
                Scope::User,
                tor_chains(env, Scope::User, Some(uid), params.allow_lan)?,
                table_sets(params.allow_lan),
                PolicyShape::Machine,
                true,
            )
        }
        ProfileId::TorApp => {
            if params.allow_lan {
                return Err(PolicyError::InvalidParameter(
                    "allow_lan",
                    "APP scope preserves source identity and does not use SNAT or masquerade, so \
                     LAN access is unsupported under the APP architecture",
                ));
            }
            (
                Scope::App,
                app_host_chains(env),
                app_sets(env),
                PolicyShape::AppHost,
                false,
            )
        }
        ProfileId::I2pIsolated => {
            return Err(PolicyError::Unsupported(profile));
        }
    };

    let ruleset = Ruleset {
        tables: vec![Table {
            family: Family::Inet,
            name: TABLE_NAME.to_string(),
            sets,
            chains,
        }],
    };

    let exemptions = effective_exemptions(&ruleset)?;
    let allowed_ports = [env.trans_port, env.chokepoint_port];
    let app_ports = [env.trans_port, env.chokepoint_port, env.socks_port];
    let ctx = CheckContext {
        shape,
        scope,
        exemptions: &exemptions,
        allowed_redirect_ports: &allowed_ports,
        require_dns_redirect,
        require_udp_fast_fail: true,
        require_exemption_before_redirect: true,
        app_core: Some(env.app_core),
        app_bridge: (shape == PolicyShape::AppHost).then_some(env.app_bridge.as_str()),
        app_core_ports: &app_ports,
        app_dns_port: Some(env.chokepoint_port),
    };
    check(&ruleset, &ctx)?;

    Ok(CompiledPolicy {
        profile,
        ruleset,
        exemptions,
    })
}

/// Compile the ruleset that lives *inside* one APP namespace.
///
/// This is the other half of `APP` scope. It has no exemptions and no output interface: its whole
/// job is to rewrite every application connection to the host-local core address and to deny
/// everything that is not either loopback or a reply to a flow the core already accepted. A
/// separate entry point, rather than a `ProfileId`, keeps the helper's closed verb set closed: the
/// namespace helper renders this from its own configuration, never from a client request.
pub fn compile_app_namespace(env: &Environment) -> Result<CompiledPolicy, PolicyError> {
    let ruleset = Ruleset {
        tables: vec![Table {
            family: Family::Inet,
            name: TABLE_NAME.to_string(),
            sets: app_sets(env),
            chains: app_namespace_chains(env),
        }],
    };

    let exemptions = effective_exemptions(&ruleset)?;
    let allowed_ports = [env.trans_port, env.chokepoint_port];
    let app_ports = [env.trans_port, env.chokepoint_port, env.socks_port];
    let ctx = CheckContext {
        shape: PolicyShape::AppNamespace,
        scope: Scope::App,
        exemptions: &exemptions,
        allowed_redirect_ports: &allowed_ports,
        require_dns_redirect: true,
        require_udp_fast_fail: true,
        require_exemption_before_redirect: false,
        app_core: Some(env.app_core),
        app_bridge: None,
        app_core_ports: &app_ports,
        app_dns_port: Some(env.chokepoint_port),
    };
    check(&ruleset, &ctx)?;

    Ok(CompiledPolicy {
        profile: ProfileId::TorApp,
        ruleset,
        exemptions,
    })
}

fn require_tor(env: &Environment) -> Result<u32, PolicyError> {
    env.tor_uid.ok_or(PolicyError::MissingIdentity("tor"))
}

fn require_dnscrypt(env: &Environment) -> Result<u32, PolicyError> {
    env.dnscrypt_uid
        .ok_or(PolicyError::MissingIdentity("dnscrypt-proxy"))
}

/// A user scope must name a real, non-system identity.
fn validate_user_uid(uid: u32, env: &Environment) -> Result<(), PolicyError> {
    if uid == 0 {
        return Err(PolicyError::InvalidParameter(
            "user_uid",
            "root is not a user scope; use the system scope instead",
        ));
    }
    if Some(uid) == env.tor_uid || Some(uid) == env.dnscrypt_uid {
        return Err(PolicyError::InvalidParameter(
            "user_uid",
            "the uid belongs to a Ghostnector service, not to a user",
        ));
    }
    Ok(())
}

fn lan_sets(allow_lan: bool) -> Vec<Set> {
    if !allow_lan {
        return Vec::new();
    }
    vec![
        Set {
            name: "lan4".to_string(),
            kind: SetKind::Ipv4Addr,
            elements: LAN4.iter().map(|cidr| cidr.to_string()).collect(),
        },
        Set {
            name: "lan6".to_string(),
            kind: SetKind::Ipv6Addr,
            elements: LAN6.iter().map(|cidr| cidr.to_string()).collect(),
        },
    ]
}

/// The subjects the rules cite, resolved against the catalogue, in order of first appearance.
fn effective_exemptions(ruleset: &Ruleset) -> Result<Vec<Exemption>, PolicyError> {
    let mut subjects: Vec<&str> = Vec::new();
    for table in &ruleset.tables {
        for chain in &table.chains {
            for rule in &chain.rules {
                if let RuleOrigin::Exemption { subject } = &rule.origin {
                    if !subjects.contains(&subject.as_str()) {
                        subjects.push(subject);
                    }
                }
            }
        }
    }

    let all = catalogue();
    let mut effective = Vec::with_capacity(subjects.len());
    for subject in subjects {
        match all.iter().find(|exemption| exemption.subject == subject) {
            Some(exemption) => effective.push(exemption.clone()),
            None => return Err(PolicyError::UnknownExemption(subject.to_string())),
        }
    }
    Ok(effective)
}

fn rule(exprs: Vec<Expr>, verdict: Verdict, origin: RuleOrigin, comment: &str) -> Rule {
    Rule {
        exprs,
        verdict,
        counter: true,
        origin,
        comment: comment.to_string(),
    }
}

fn exemption(subject: &str) -> RuleOrigin {
    RuleOrigin::Exemption {
        subject: subject.to_string(),
    }
}

fn mechanism(mechanism: Mechanism) -> RuleOrigin {
    RuleOrigin::Mechanism { mechanism }
}

fn loopback_rule(verdict: Verdict) -> Rule {
    rule(
        vec![Expr::Oifname {
            name: "lo".to_string(),
        }],
        verdict,
        RuleOrigin::Loopback,
        "loopback cannot reach the clearnet",
    )
}

/// The rules that recognise traffic destined for a loopback address.
fn loopback_address_rules(verdict: Verdict) -> Vec<Rule> {
    ["loopback4", "loopback6"]
        .into_iter()
        .map(|set| {
            rule(
                vec![Expr::DaddrInSet {
                    set: set.to_string(),
                }],
                verdict,
                RuleOrigin::Loopback,
                "traffic to a loopback address cannot leave the machine",
            )
        })
        .collect()
}

/// The sets every table declares: the loopback addresses, and the local network when it is opted in.
fn table_sets(allow_lan: bool) -> Vec<Set> {
    let mut sets = vec![
        Set {
            name: LOOPBACK4_SET.to_string(),
            kind: SetKind::Ipv4Addr,
            elements: LOOPBACK4.iter().map(|cidr| cidr.to_string()).collect(),
        },
        Set {
            name: LOOPBACK6_SET.to_string(),
            kind: SetKind::Ipv6Addr,
            elements: LOOPBACK6.iter().map(|cidr| cidr.to_string()).collect(),
        },
    ];
    sets.extend(lan_sets(allow_lan));
    sets
}

/// The sets an APP ruleset declares: loopback, and the host-local core address.
///
/// The core set is a single host prefix, not the whole APP subnet: the only address an APP packet
/// may legitimately reach is the core itself.
fn app_sets(env: &Environment) -> Vec<Set> {
    vec![
        Set {
            name: LOOPBACK4_SET.to_string(),
            kind: SetKind::Ipv4Addr,
            elements: LOOPBACK4.iter().map(|cidr| cidr.to_string()).collect(),
        },
        Set {
            name: LOOPBACK6_SET.to_string(),
            kind: SetKind::Ipv6Addr,
            elements: LOOPBACK6.iter().map(|cidr| cidr.to_string()).collect(),
        },
        Set {
            name: APP_CORE_SET.to_string(),
            kind: SetKind::Ipv4Addr,
            elements: vec![ghostnector_spec::app::app_core_element(env.app_core)],
        },
    ]
}

/// The host side of `APP` scope: everything is input or forward. There is deliberately no output
/// chain, so activating APP scope can never change what the machine's own processes may do.
fn app_host_chains(env: &Environment) -> Vec<Chain> {
    let bridge = || Expr::Iifname {
        name: env.app_bridge.clone(),
    };
    let core = || Expr::DaddrInSet {
        set: APP_CORE_SET.to_string(),
    };

    let mut rules = vec![rule(
        vec![Expr::Iifname {
            name: "lo".to_string(),
        }],
        Verdict::Accept,
        RuleOrigin::Loopback,
        "loopback delivery",
    )];

    // The app link reaches exactly the core listeners the namespace DNAT targets.
    for port in [env.trans_port, env.chokepoint_port, env.socks_port] {
        rules.push(rule(
            vec![
                bridge(),
                core(),
                Expr::L4Proto { proto: Proto::Tcp },
                Expr::Dport { port },
            ],
            Verdict::Accept,
            mechanism(Mechanism::AppLink),
            "the app link reaches this core listener",
        ));
    }
    rules.push(rule(
        vec![
            bridge(),
            core(),
            Expr::L4Proto { proto: Proto::Udp },
            Expr::Dport {
                port: env.chokepoint_port,
            },
        ],
        Verdict::Accept,
        mechanism(Mechanism::AppLink),
        "the app link reaches the DNS chokepoint",
    ));

    // Anything else from the app link is closed here, before it can reach a host service.
    rules.push(rule(
        vec![bridge()],
        Verdict::Drop,
        mechanism(Mechanism::AppLink),
        "nothing else from the app link",
    ));

    // Second line of defence: the core listeners are never for any other interface.
    for port in [env.trans_port, env.chokepoint_port, env.socks_port] {
        rules.push(rule(
            vec![Expr::L4Proto { proto: Proto::Tcp }, Expr::Dport { port }],
            Verdict::Drop,
            mechanism(Mechanism::ListenerGuard),
            "the transparent proxies are not for the network",
        ));
    }
    rules.push(rule(
        vec![
            Expr::L4Proto { proto: Proto::Udp },
            Expr::Dport {
                port: env.chokepoint_port,
            },
        ],
        Verdict::Drop,
        mechanism(Mechanism::ListenerGuard),
        "the DNS chokepoint is not for the network",
    ));

    vec![
        Chain {
            name: "in_filter".to_string(),
            kind: ChainKind::Filter,
            hook: Hook::Input,
            priority: FILTER_PRIORITY,
            policy: Verdict::Accept,
            rules,
        },
        forward_chain(),
    ]
}

/// The ruleset inside one APP namespace. This is the only place a DNAT verdict appears.
fn app_namespace_chains(env: &Environment) -> Vec<Chain> {
    let core = || Expr::DaddrInSet {
        set: APP_CORE_SET.to_string(),
    };
    let dnat_to = |port: u16| Verdict::Dnat {
        addr: env.app_core,
        port,
    };

    let mut nat_rules = loopback_address_rules(Verdict::Return);
    // Direct SOCKS is deliberately left untouched: an app that speaks SOCKS keeps its own
    // credential-based isolation, and the source address already separates groups.
    nat_rules.push(rule(
        vec![
            core(),
            Expr::L4Proto { proto: Proto::Tcp },
            Expr::Dport {
                port: env.socks_port,
            },
        ],
        Verdict::Return,
        mechanism(Mechanism::AppCore),
        "direct SOCKS keeps its own circuit",
    ));
    // DNS before the catch-all, or port 53 would be carried by Tor instead of the chokepoint.
    for proto in [Proto::Udp, Proto::Tcp] {
        nat_rules.push(rule(
            vec![Expr::L4Proto { proto }, Expr::Dport { port: 53 }],
            dnat_to(env.chokepoint_port),
            mechanism(Mechanism::DnsRedirect),
            "DNS goes to the chokepoint",
        ));
    }
    nat_rules.push(rule(
        vec![Expr::L4Proto { proto: Proto::Tcp }],
        dnat_to(env.trans_port),
        mechanism(Mechanism::TorRedirect),
        "transparent Tor for TCP",
    ));

    let mut egress_rules = loopback_address_rules(Verdict::Accept);
    for port in [env.trans_port, env.chokepoint_port, env.socks_port] {
        egress_rules.push(rule(
            vec![
                core(),
                Expr::L4Proto { proto: Proto::Tcp },
                Expr::Dport { port },
            ],
            Verdict::Accept,
            mechanism(Mechanism::AppCore),
            "the core listener the DNAT produced",
        ));
    }
    egress_rules.push(rule(
        vec![
            core(),
            Expr::L4Proto { proto: Proto::Udp },
            Expr::Dport {
                port: env.chokepoint_port,
            },
        ],
        Verdict::Accept,
        mechanism(Mechanism::AppCore),
        "the DNS chokepoint",
    ));
    egress_rules.extend(fast_fail_rules());
    egress_rules.push(default_deny_rule());

    // Inbound: replies to the app's own flows, and nothing else. Without this, a one-line change on
    // the host side could open the app to the host or the bridge.
    let return_mechanism = mechanism(Mechanism::AppReturn);
    let mut input_rules = vec![rule(
        vec![Expr::Iifname {
            name: "lo".to_string(),
        }],
        Verdict::Accept,
        RuleOrigin::Loopback,
        "loopback delivery",
    )];
    for state in [crate::ir::CtState::Established, crate::ir::CtState::Related] {
        input_rules.push(rule(
            vec![Expr::CtState { state }],
            Verdict::Accept,
            return_mechanism.clone(),
            "replies to flows the core accepted",
        ));
    }
    input_rules.push(default_deny_rule());

    vec![
        Chain {
            name: "out_nat".to_string(),
            kind: ChainKind::Nat,
            hook: Hook::Output,
            priority: NAT_PRIORITY,
            policy: Verdict::Accept,
            rules: nat_rules,
        },
        Chain {
            name: "out_filter".to_string(),
            kind: ChainKind::Filter,
            hook: Hook::Output,
            priority: FILTER_PRIORITY,
            policy: Verdict::Drop,
            rules: egress_rules,
        },
        Chain {
            name: "in_filter".to_string(),
            kind: ChainKind::Filter,
            hook: Hook::Input,
            priority: FILTER_PRIORITY,
            policy: Verdict::Drop,
            rules: input_rules,
        },
    ]
}

/// Port a DHCP server listens on, which is where a client's request goes.
const DHCP_SERVER_PORT: u16 = 67;

fn dhcp_rule(env: &Environment) -> Rule {
    // A client's request goes *from* its own port *to* the server's. Matching the destination
    // instead would permit the direction a client never sends (server to client) and drop the one
    // it does, so the exemption would exist on paper while the lease expired.
    rule(
        vec![
            Expr::L4Proto { proto: Proto::Udp },
            Expr::Sport {
                port: env.dhcp_client_port,
            },
            Expr::Dport {
                port: DHCP_SERVER_PORT,
            },
        ],
        Verdict::Accept,
        exemption(SUBJECT_DHCP),
        "keep the link alive",
    )
}

fn fast_fail_rules() -> Vec<Rule> {
    vec![
        rule(
            vec![Expr::L4Proto { proto: Proto::Udp }],
            Verdict::Reject {
                kind: RejectKind::PortUnreachable,
            },
            mechanism(Mechanism::FastFailUdp),
            "QUIC and real-time clients must fail in milliseconds, not hang",
        ),
        rule(
            vec![Expr::L4Proto { proto: Proto::Icmp }],
            Verdict::Reject {
                kind: RejectKind::AdminProhibited,
            },
            mechanism(Mechanism::FastFailUdp),
            "ICMP is not carried by Tor",
        ),
        rule(
            vec![Expr::L4Proto {
                proto: Proto::Icmpv6,
            }],
            Verdict::Reject {
                kind: RejectKind::AdminProhibited,
            },
            mechanism(Mechanism::FastFailUdp),
            "IPv6 is denied in every profile",
        ),
    ]
}

fn default_deny_rule() -> Rule {
    rule(
        vec![],
        Verdict::Drop,
        mechanism(Mechanism::DefaultDeny),
        "deny by default",
    )
}

fn forward_chain() -> Chain {
    Chain {
        name: "fwd_filter".to_string(),
        kind: ChainKind::Filter,
        hook: Hook::Forward,
        priority: FILTER_PRIORITY,
        policy: Verdict::Drop,
        rules: vec![rule(
            vec![],
            Verdict::Drop,
            mechanism(Mechanism::ForwardDeny),
            "containers and virtual machines must not leak around the output chain",
        )],
    }
}

/// Keep the transparent-proxy listeners off the network.
///
/// The proxies bind to loopback, so this is a second line of defence: if a future change binds a
/// listener to a wildcard address, the machine does not become an open proxy for its network.
fn listener_guard_chain(env: &Environment) -> Chain {
    let guard = |port: u16| {
        rule(
            vec![Expr::L4Proto { proto: Proto::Tcp }, Expr::Dport { port }],
            Verdict::Drop,
            mechanism(Mechanism::ListenerGuard),
            "the transparent proxies are not for the network",
        )
    };
    Chain {
        name: "in_filter".to_string(),
        kind: ChainKind::Filter,
        hook: Hook::Input,
        priority: FILTER_PRIORITY,
        policy: Verdict::Accept,
        rules: vec![
            rule(
                vec![Expr::Iifname {
                    name: "lo".to_string(),
                }],
                Verdict::Accept,
                RuleOrigin::Loopback,
                "loopback delivery of redirected traffic",
            ),
            guard(env.trans_port),
            guard(env.chokepoint_port),
            guard(env.socks_port),
        ],
    }
}

fn nat_chain(rules: Vec<Rule>) -> Chain {
    let mut all = loopback_address_rules(Verdict::Return);
    all.extend(rules);
    Chain {
        name: "out_nat".to_string(),
        kind: ChainKind::Nat,
        hook: Hook::Output,
        priority: NAT_PRIORITY,
        policy: Verdict::Accept,
        rules: all,
    }
}

fn filter_chain(rules: Vec<Rule>) -> Chain {
    let mut all = loopback_address_rules(Verdict::Accept);
    all.extend(rules);
    Chain {
        name: "out_filter".to_string(),
        kind: ChainKind::Filter,
        hook: Hook::Output,
        priority: FILTER_PRIORITY,
        policy: Verdict::Drop,
        rules: all,
    }
}

/// Deny everything except loopback, Tor's own egress, and DHCP.
///
/// This is the state the machine sits in *before* services start, so there is no window during a
/// transition where traffic can escape (DR-4).
fn fail_closed_chains(env: &Environment) -> Result<Vec<Chain>, PolicyError> {
    let tor_uid = require_tor(env)?;
    let mut rules = vec![
        loopback_rule(Verdict::Accept),
        rule(
            vec![Expr::Skuid { uid: tor_uid }],
            Verdict::Accept,
            exemption(SUBJECT_TOR),
            "Tor must reach the network to bootstrap",
        ),
        dhcp_rule(env),
    ];
    rules.extend(fast_fail_rules());
    rules.push(default_deny_rule());

    Ok(vec![
        nat_chain(Vec::new()),
        filter_chain(rules),
        forward_chain(),
    ])
}

/// Encrypted DNS with a locked-down port 53. No overlay network.
fn dns_lockdown_chains(env: &Environment, allow_lan: bool) -> Result<Vec<Chain>, PolicyError> {
    let dnscrypt_uid = require_dnscrypt(env)?;
    let mut nat_rules = vec![
        loopback_rule(Verdict::Return),
        rule(
            vec![Expr::Skuid { uid: dnscrypt_uid }],
            Verdict::Return,
            exemption(SUBJECT_DNSCRYPT),
            "the resolver speaks to resolvers directly",
        ),
    ];
    let mut rules = vec![
        loopback_rule(Verdict::Accept),
        rule(
            vec![Expr::Skuid { uid: dnscrypt_uid }],
            Verdict::Accept,
            exemption(SUBJECT_DNSCRYPT),
            "the resolver's egress is not port-restricted; identity is the boundary",
        ),
    ];

    if allow_lan {
        for set in ["lan4", "lan6"] {
            nat_rules.push(lan_return_rule(set));
            rules.push(lan_accept_rule(set));
        }
    }

    // Plaintext DNS is impossible: everything aimed at port 53 goes to the chokepoint. Encrypted
    // DNS from applications (DoH on 443, DoT on 853) is not blocked, because it does not leak
    // plaintext; the interface states that it bypasses the resolver policy.
    nat_rules.push(dns_redirect_rule(Proto::Udp, env.chokepoint_port));
    nat_rules.push(dns_redirect_rule(Proto::Tcp, env.chokepoint_port));

    rules.push(dhcp_rule(env));
    rules.extend(fast_fail_rules());
    rules.push(default_deny_rule());

    Ok(vec![
        nat_chain(nat_rules),
        filter_chain(rules),
        forward_chain(),
        listener_guard_chain(env),
    ])
}

/// Transparent Tor for a whole-machine or single-identity scope.
fn tor_chains(
    env: &Environment,
    scope: Scope,
    user_uid: Option<u32>,
    allow_lan: bool,
) -> Result<Vec<Chain>, PolicyError> {
    let tor_uid = require_tor(env)?;
    let mut nat_rules = Vec::new();
    let mut rules = Vec::new();

    if scope == Scope::User {
        let uid = user_uid.expect("the caller validates that a user scope has a uid");
        nat_rules.push(rule(
            vec![Expr::SkuidNot { uid }],
            Verdict::Return,
            RuleOrigin::OutOfScope,
            "outside the scope, leave the machine alone",
        ));
        rules.push(rule(
            vec![Expr::SkuidNot { uid }],
            Verdict::Accept,
            RuleOrigin::OutOfScope,
            "outside the scope, leave the machine alone",
        ));
    }

    nat_rules.push(loopback_rule(Verdict::Return));
    nat_rules.push(rule(
        vec![Expr::Skuid { uid: tor_uid }],
        Verdict::Return,
        exemption(SUBJECT_TOR),
        "Tor's own egress must not be captured",
    ));

    rules.push(loopback_rule(Verdict::Accept));
    rules.push(rule(
        vec![Expr::Skuid { uid: tor_uid }],
        Verdict::Accept,
        exemption(SUBJECT_TOR),
        "Tor's own egress",
    ));
    rules.push(dhcp_rule(env));

    if allow_lan {
        for set in ["lan4", "lan6"] {
            nat_rules.push(lan_return_rule(set));
            rules.push(lan_accept_rule(set));
        }
    }

    // DNS first: a port-53 connection must reach the chokepoint, not the transparent proxy.
    nat_rules.push(dns_redirect_rule(Proto::Udp, env.chokepoint_port));
    nat_rules.push(dns_redirect_rule(Proto::Tcp, env.chokepoint_port));
    nat_rules.push(rule(
        vec![Expr::L4Proto { proto: Proto::Tcp }],
        Verdict::Redirect {
            port: env.trans_port,
        },
        mechanism(Mechanism::TorRedirect),
        "transparent Tor for TCP",
    ));

    rules.extend(fast_fail_rules());
    rules.push(default_deny_rule());

    Ok(vec![
        nat_chain(nat_rules),
        filter_chain(rules),
        forward_chain(),
        listener_guard_chain(env),
    ])
}

fn lan_return_rule(set: &str) -> Rule {
    rule(
        vec![Expr::DaddrInSet {
            set: set.to_string(),
        }],
        Verdict::Return,
        exemption(SUBJECT_LAN),
        "the local network is opted in",
    )
}

fn lan_accept_rule(set: &str) -> Rule {
    rule(
        vec![Expr::DaddrInSet {
            set: set.to_string(),
        }],
        Verdict::Accept,
        exemption(SUBJECT_LAN),
        "the local network is opted in",
    )
}

fn dns_redirect_rule(proto: Proto, port: u16) -> Rule {
    rule(
        vec![Expr::L4Proto { proto }, Expr::Dport { port: 53 }],
        Verdict::Redirect { port },
        mechanism(Mechanism::DnsRedirect),
        "DNS goes to the chokepoint",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render_table;

    fn env() -> Environment {
        Environment {
            tor_uid: Some(987),
            dnscrypt_uid: Some(988),
            trans_port: 9040,
            chokepoint_port: 53,
            socks_port: 9050,
            dhcp_client_port: 68,
            app_core: ghostnector_spec::app::DEFAULT_APP_CORE_ADDRESS,
            app_prefix: ghostnector_spec::app::DEFAULT_APP_PREFIX,
            app_bridge: ghostnector_spec::app::DEFAULT_APP_BRIDGE.to_string(),
        }
    }

    fn subjects(policy: &CompiledPolicy) -> Vec<String> {
        policy
            .exemptions
            .iter()
            .map(|exemption| exemption.subject.clone())
            .collect()
    }

    fn chain<'a>(policy: &'a CompiledPolicy, name: &str) -> &'a Chain {
        policy
            .ruleset
            .chain(name)
            .unwrap_or_else(|| panic!("chain {name} missing"))
    }

    #[test]
    fn fail_closed_opens_only_tor_and_dhcp() {
        let policy = compile(ProfileId::FailClosed, &Params::default(), &env()).unwrap();
        assert_eq!(subjects(&policy), vec![SUBJECT_TOR, SUBJECT_DHCP]);

        let accepts: Vec<_> = chain(&policy, "out_filter")
            .rules
            .iter()
            .filter(|rule| matches!(rule.verdict, Verdict::Accept))
            .map(|rule| rule.comment.clone())
            .collect();
        assert_eq!(
            accepts.len(),
            5,
            "two loopback addresses, loopback, tor, dhcp: {accepts:?}"
        );
        assert!(
            !chain(&policy, "out_nat").rules.is_empty(),
            "the nat chain still has its loopback rules, even for this profile"
        );
    }

    #[test]
    fn the_dhcp_exemption_matches_the_direction_a_client_sends() {
        // A DHCP client sends *from* its own port *to* the server's. Matching only a destination
        // port would allow the direction a client never uses and reject the one it does. This is
        // the regression test for the inverted exemption that RC1 shipped.
        let policy = compile(ProfileId::TorSystem, &Params::default(), &env()).unwrap();
        let dhcp = chain(&policy, "out_filter")
            .rules
            .iter()
            .find(|rule| rule.comment == "keep the link alive")
            .expect("every profile keeps the link alive");
        assert!(
            dhcp.exprs
                .iter()
                .any(|expr| matches!(expr, Expr::Sport { port: 68 })),
            "the client's own port must be the source match: {:?}",
            dhcp.exprs
        );
        assert!(
            dhcp.exprs
                .iter()
                .any(|expr| matches!(expr, Expr::Dport { port: 67 })),
            "the request goes to the server's port: {:?}",
            dhcp.exprs
        );
        let rendered = render_table(&policy.ruleset);
        assert!(
            rendered.contains("udp sport 68 udp dport 67 counter accept"),
            "{rendered}"
        );
    }

    #[test]
    fn tor_system_redirects_dns_before_tcp() {
        let policy = compile(ProfileId::TorSystem, &Params::default(), &env()).unwrap();
        let rules = &chain(&policy, "out_nat").rules;

        let dns_index = rules
            .iter()
            .position(|rule| {
                matches!(rule.verdict, Verdict::Redirect { port } if port == env().chokepoint_port)
            })
            .expect("a DNS redirect must exist");
        let tcp_index = rules
            .iter()
            .position(|rule| {
                matches!(rule.verdict, Verdict::Redirect { port } if port == env().trans_port)
            })
            .expect("a Tor redirect must exist");

        assert!(
            dns_index < tcp_index,
            "port 53 must be claimed by the chokepoint before the catch-all Tor redirect"
        );
    }

    #[test]
    fn tor_system_has_exactly_the_documented_exemptions() {
        let policy = compile(ProfileId::TorSystem, &Params::default(), &env()).unwrap();
        assert_eq!(subjects(&policy), vec![SUBJECT_TOR, SUBJECT_DHCP]);
    }

    #[test]
    fn enabling_lan_adds_exactly_one_exemption() {
        let params = Params {
            allow_lan: true,
            ..Params::default()
        };
        let policy = compile(ProfileId::TorSystem, &params, &env()).unwrap();
        assert_eq!(
            subjects(&policy),
            vec![SUBJECT_TOR, SUBJECT_LAN, SUBJECT_DHCP]
        );
        assert_eq!(
            policy.ruleset.tables[0].sets.len(),
            4,
            "loopback addresses plus the LAN"
        );
    }

    #[test]
    fn dns_lockdown_trusts_only_the_resolver() {
        let policy = compile(ProfileId::DnsLockdown, &Params::default(), &env()).unwrap();
        assert_eq!(subjects(&policy), vec![SUBJECT_DNSCRYPT, SUBJECT_DHCP]);

        assert!(chain(&policy, "out_nat").rules.iter().all(
            |rule| !matches!(rule.verdict, Verdict::Redirect { port } if port == env().trans_port)
        ));
    }

    #[test]
    fn user_scope_carves_out_the_rest_of_the_machine_and_nowhere_else() {
        let params = Params {
            user_uid: Some(1000),
            ..Params::default()
        };
        let policy = compile(ProfileId::TorUser, &params, &env()).unwrap();

        // The carve-out must exist in both chains, and must come before anything that treats the
        // scoped identity's traffic differently, or it protects nothing.
        for chain_name in ["out_filter", "out_nat"] {
            let rules = &chain(&policy, chain_name).rules;
            let carve_out = rules
                .iter()
                .position(|rule| matches!(rule.origin, RuleOrigin::OutOfScope))
                .unwrap_or_else(|| panic!("{chain_name} has no scope carve-out"));
            if let Some(exemption) = rules
                .iter()
                .position(|rule| matches!(rule.origin, RuleOrigin::Exemption { .. }))
            {
                assert!(
                    carve_out < exemption,
                    "in {chain_name} the carve-out must precede every exemption"
                );
            }
        }
        assert_eq!(
            subjects(&policy),
            vec![SUBJECT_TOR, SUBJECT_DHCP],
            "a user scope still only exempts Tor and DHCP"
        );
    }

    #[test]
    fn user_scope_requires_a_uid() {
        let error = compile(ProfileId::TorUser, &Params::default(), &env()).unwrap_err();
        assert!(matches!(
            error,
            PolicyError::MissingParameter(ProfileId::TorUser, "user_uid")
        ));
    }

    #[test]
    fn user_scope_refuses_root_and_service_uids() {
        for uid in [0, 987, 988] {
            let params = Params {
                user_uid: Some(uid),
                ..Params::default()
            };
            let error = compile(ProfileId::TorUser, &params, &env()).unwrap_err();
            assert!(
                matches!(error, PolicyError::InvalidParameter("user_uid", _)),
                "uid {uid} must be refused, got {error}"
            );
        }
    }

    #[test]
    fn a_machine_without_a_resolver_can_still_run_tor_mode() {
        // This is the case that matters in the field: Tor is installed, DNSCrypt is not.
        let mut without_resolver = env();
        without_resolver.dnscrypt_uid = None;

        for profile in [ProfileId::FailClosed, ProfileId::TorSystem] {
            compile(profile, &Params::default(), &without_resolver).unwrap_or_else(|error| {
                panic!("{profile:?} must compile without a resolver: {error}")
            });
        }
        let error = compile(
            ProfileId::DnsLockdown,
            &Params::default(),
            &without_resolver,
        )
        .expect_err("encrypted DNS cannot work without a resolver");
        assert!(matches!(
            error,
            PolicyError::MissingIdentity("dnscrypt-proxy")
        ));
    }

    #[test]
    fn profiles_that_need_tor_say_so_when_it_is_missing() {
        let mut without_tor = env();
        without_tor.tor_uid = None;
        for profile in [ProfileId::FailClosed, ProfileId::TorSystem] {
            let error = compile(profile, &Params::default(), &without_tor).unwrap_err();
            assert!(
                matches!(error, PolicyError::MissingIdentity("tor")),
                "{error}"
            );
        }
    }

    #[test]
    fn profiles_without_an_implementation_are_rejected_rather_than_approximated() {
        let error = compile(ProfileId::I2pIsolated, &Params::default(), &env()).unwrap_err();
        assert!(matches!(error, PolicyError::Unsupported(_)));
    }

    #[test]
    fn the_app_host_table_has_no_output_policy_and_bounds_the_link() {
        let policy = compile(ProfileId::TorApp, &Params::default(), &env()).unwrap();
        assert_eq!(
            policy.ruleset.chain_names(),
            vec!["in_filter", "fwd_filter"],
            "APP scope protects its applications; it must not acquire an output policy"
        );
        assert!(
            policy.exemptions.is_empty(),
            "the APP host table grants no identity a path: {:?}",
            subjects(&policy)
        );

        let rendered = render_table(&policy.ruleset);
        assert!(
            rendered.contains("iifname \"ghbr0\""),
            "the app link must be admitted by name: {rendered}"
        );
        assert!(
            rendered.contains("ip daddr @appcore4 tcp dport 9040 counter accept"),
            "the app link reaches the transparent proxy: {rendered}"
        );
        assert!(
            rendered.contains("ip daddr @appcore4 udp dport 53 counter accept"),
            "the app link reaches the chokepoint: {rendered}"
        );
        assert!(
            !rendered.contains("redirect to"),
            "an APP host table must not redirect anything: {rendered}"
        );
    }

    #[test]
    fn app_scope_refuses_lan_access_rather_than_weakening_source_identity() {
        let params = Params {
            allow_lan: true,
            ..Params::default()
        };
        let error = compile(ProfileId::TorApp, &params, &env()).unwrap_err();
        match error {
            PolicyError::InvalidParameter("allow_lan", reason) => {
                assert!(reason.contains("unsupported"), "{reason}");
            }
            other => panic!("expected the LAN parameter to be refused, got {other}"),
        }
    }

    #[test]
    fn the_app_namespace_dnats_only_to_the_core_and_denies_everything_else() {
        let policy = compile_app_namespace(&env()).unwrap();
        assert_eq!(
            policy.ruleset.chain_names(),
            vec!["out_nat", "out_filter", "in_filter"],
            "a namespace has one output path and no forwarding"
        );
        let rendered = render_table(&policy.ruleset);
        for expected in [
            "udp dport 53 counter dnat ip to 10.200.0.1:53",
            "tcp dport 53 counter dnat ip to 10.200.0.1:53",
            "meta l4proto tcp counter dnat ip to 10.200.0.1:9040",
            "ct state established counter accept",
            "ct state related counter accept",
        ] {
            assert!(
                rendered.contains(expected),
                "missing '{expected}' in:\n{rendered}"
            );
        }
        for forbidden in ["masquerade", "snat", "redirect to"] {
            assert!(
                !rendered.contains(forbidden),
                "a namespace ruleset must not contain '{forbidden}':\n{rendered}"
            );
        }
    }

    #[test]
    fn every_compiled_profile_cites_only_catalogue_subjects() {
        let all = catalogue();
        for (profile, params) in [
            (ProfileId::FailClosed, Params::default()),
            (ProfileId::DnsLockdown, Params::default()),
            (ProfileId::TorSystem, Params::default()),
            (ProfileId::TorApp, Params::default()),
            (
                ProfileId::TorSystem,
                Params {
                    allow_lan: true,
                    ..Params::default()
                },
            ),
            (
                ProfileId::TorUser,
                Params {
                    user_uid: Some(1000),
                    ..Params::default()
                },
            ),
        ] {
            let policy = compile(profile, &params, &env()).unwrap();
            for exemption in &policy.exemptions {
                assert!(
                    all.iter().any(|e| e.subject == exemption.subject),
                    "{profile:?} cited '{}', which is not in the catalogue",
                    exemption.subject
                );
            }
        }
    }

    #[test]
    fn compiled_policies_serialise_stably() {
        // The privileged helper reports what it applied; this shape is part of that contract.
        let policy = compile(ProfileId::TorSystem, &Params::default(), &env()).unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        let decoded: CompiledPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, policy);
    }

    #[test]
    fn the_lan_exemption_object_matches_the_catalogue_entry() {
        let params = Params {
            allow_lan: true,
            ..Params::default()
        };
        let policy = compile(ProfileId::TorSystem, &params, &env()).unwrap();
        assert!(policy
            .exemptions
            .iter()
            .any(|exemption| *exemption == ghostnector_spec::exemption::lan_exemption()));
    }
}
