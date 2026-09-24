//! A purpose-built ruleset representation.
//!
//! Design constraints, in order of importance:
//!
//! 1. Every policy Ghostnector can express must be inspectable by [`crate::invariants`]. Types that
//!    could hide a hole (an opaque "custom rule" escape hatch) must not exist.
//! 2. The representation stays close enough to nftables that rendering is mechanical and a future
//!    netlink encoder needs no re-interpretation.
//! 3. Rules carry their *provenance* ([`RuleOrigin`]), so the checker can ask "why is this packet
//!    accepted?" and answer it from data rather than from a comment.

use serde::{Deserialize, Serialize};

/// Address family of a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    /// `inet`: one table covering IPv4 and IPv6.
    Inet,
}

/// A complete ruleset: everything Ghostnector owns, and nothing else.
///
/// Ghostnector never edits a table it did not create (review §12.1). This type *is* that rule: it
/// describes the whole of Ghostnector's policy, and applying it is a single atomic replacement.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Ruleset {
    /// Tables owned by Ghostnector.
    pub tables: Vec<Table>,
}

impl Ruleset {
    /// Find a chain by name across all tables.
    pub fn chain(&self, name: &str) -> Option<&Chain> {
        self.tables
            .iter()
            .flat_map(|table| table.chains.iter())
            .find(|chain| chain.name == name)
    }

    /// Find a mutable chain by name across all tables.
    pub fn chain_mut(&mut self, name: &str) -> Option<&mut Chain> {
        self.tables
            .iter_mut()
            .flat_map(|table| table.chains.iter_mut())
            .find(|chain| chain.name == name)
    }

    /// The names of all chains, in declaration order.
    pub fn chain_names(&self) -> Vec<&str> {
        self.tables
            .iter()
            .flat_map(|table| table.chains.iter())
            .map(|chain| chain.name.as_str())
            .collect()
    }
}

/// A single nftables table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Table {
    /// Address family.
    pub family: Family,
    /// Table name. Ghostnector uses one owned table.
    pub name: String,
    /// Named address sets referenced by rules.
    pub sets: Vec<Set>,
    /// Chains in declaration order.
    pub chains: Vec<Chain>,
}

/// A named set of addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Set {
    /// Set name, referenced by [`Expr::DaddrInSet`].
    pub name: String,
    /// Element type.
    pub kind: SetKind,
    /// Elements in CIDR notation.
    pub elements: Vec<String>,
}

/// Element type of a [`Set`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetKind {
    /// IPv4 prefixes.
    Ipv4Addr,
    /// IPv6 prefixes.
    Ipv6Addr,
}

/// Which part of the packet path a chain sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainKind {
    /// `filter`: verdicts decide the packet's fate.
    Filter,
    /// `nat`: verdicts rewrite addresses or ports.
    Nat,
}

/// Netfilter hook a chain is attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hook {
    /// Before the routing decision (forwarded traffic).
    Prerouting,
    /// Traffic to a local socket.
    Input,
    /// Traffic from a local socket.
    Output,
    /// Traffic routed through the machine.
    Forward,
    /// After the routing decision.
    Postrouting,
}

/// A chain: hook, priority, default verdict, and rules in evaluation order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chain {
    /// Chain name, unique within the ruleset.
    pub name: String,
    /// Filter or nat.
    pub kind: ChainKind,
    /// Hook this chain is attached to.
    pub hook: Hook,
    /// Netfilter priority. Ghostnector runs its chains *before* the conventional 0 priority so
    /// that its counters see traffic before a third-party firewall drops it, and so that its
    /// fast-fail rejections are not replaced by silent drops.
    pub priority: i32,
    /// Verdict for packets that match no rule. This is the deny-by-default mechanism.
    pub policy: Verdict,
    /// Rules, evaluated in order.
    pub rules: Vec<Rule>,
}

/// A rule: match expressions in order, then exactly one verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Match expressions, all of which must hold.
    pub exprs: Vec<Expr>,
    /// What happens when they do.
    pub verdict: Verdict,
    /// Whether to attach a counter, for the interface's block/redirect counters.
    pub counter: bool,
    /// Why this rule exists. Machine-checked (see [`crate::invariants`]).
    pub origin: RuleOrigin,
    /// Short human-readable note. Never contains destinations or user data.
    pub comment: String,
}

impl Rule {
    /// True when the rule matches every packet (no expressions).
    ///
    /// Used by the invariant checker: an unconditional verdict is the most dangerous kind of rule.
    pub fn is_unconditional(&self) -> bool {
        self.exprs.is_empty()
    }
}

/// Why a rule exists. This is what lets the invariant checker answer "why is this packet
/// accepted?" from data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "origin")]
pub enum RuleOrigin {
    /// Traffic on the loopback interface, which cannot reach the internet.
    Loopback,
    /// An enumerated exemption. The string is the exemption's subject, and the checker requires it
    /// to appear in the effective exemption list (invariant I8).
    Exemption {
        /// Exemption subject, for example `system-user:tor`.
        subject: String,
    },
    /// Part of the enforcement mechanism itself.
    Mechanism {
        /// Which mechanism.
        mechanism: Mechanism,
    },
    /// Traffic that is outside the policy's scope.
    ///
    /// This exists only in the `User` scope, where the policy covers one identity and must leave
    /// the rest of the machine alone. [`crate::invariants`] rejects it in `System` scope.
    OutOfScope,
}

/// Enforcement mechanisms that produce rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mechanism {
    /// Redirect local TCP into Tor's `TransPort`.
    TorRedirect,
    /// Redirect local DNS into the chokepoint.
    DnsRedirect,
    /// The counted default-deny rule at the end of a chain.
    DefaultDeny,
    /// Reject UDP and ICMP quickly so applications fall back instead of hanging.
    FastFailUdp,
    /// Deny forwarded traffic so containers and virtual machines cannot leak around `OUTPUT`.
    ForwardDeny,
    /// Protect the proxy listeners from non-loopback clients.
    ListenerGuard,
    /// The deny-everything baseline applied before services start.
    Bootstrap,
}

/// What a rule does when its expressions match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "verdict")]
pub enum Verdict {
    /// Accept the packet.
    Accept,
    /// Silently discard it.
    Drop,
    /// Discard it and send an error, so applications fail fast instead of timing out.
    Reject {
        /// Which error to send.
        kind: RejectKind,
    },
    /// Stop evaluating this chain; the chain's policy applies.
    Return,
    /// Rewrite the destination to a loopback address and port (transparent proxy capture).
    Redirect {
        /// Destination port.
        port: u16,
    },
}

/// Error kind for [`Verdict::Reject`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectKind {
    /// `icmp admin-prohibited`, the conventional "policy says no".
    AdminProhibited,
    /// `icmp port-unreachable`, the quickest way to make a QUIC client fall back to TCP.
    PortUnreachable,
    /// `tcp reset`, for blocked TCP destinations.
    TcpReset,
}

/// A match expression.
///
/// Note there is no expression for "destination address" other than a named set, and no expression
/// for arbitrary nftables payload matching. Egress rules must not be able to name an external
/// destination (see [`crate::invariants`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "expr")]
pub enum Expr {
    /// Match the socket's owning uid.
    ///
    /// This is the identity recorded when the socket was created, so a process that drops
    /// privileges after creating a socket keeps the creating identity. The design rule that
    /// follows is: never create sockets before dropping privileges.
    Skuid {
        /// User id.
        uid: u32,
    },
    /// Match every socket *except* one owning uid.
    ///
    /// Only the `User` scope may use this: it carves out the rest of the machine so a scoped policy
    /// leaves other users and system daemons untouched. In `System` scope an exclusion of this kind
    /// would be a hole, which is why [`crate::invariants`] rejects it there.
    SkuidNot {
        /// User id to exclude.
        uid: u32,
    },
    /// Match the input interface name.
    Iifname {
        /// Interface name.
        name: String,
    },
    /// Match the output interface name.
    Oifname {
        /// Interface name.
        name: String,
    },
    /// Match the transport protocol.
    L4Proto {
        /// Protocol.
        proto: Proto,
    },
    /// Match the destination port.
    Dport {
        /// Port number.
        port: u16,
    },
    /// Match the source port.
    ///
    /// Source ports are the *client's* identity in the protocols that use them that way — DHCP is
    /// the one that matters here: its requests go from the client's port to the server's, so an
    /// exemption that matched the destination would permit the reply and drop the request.
    Sport {
        /// Port number.
        port: u16,
    },
    /// Match the destination address against a named set.
    DaddrInSet {
        /// Set name, which must exist in the same table.
        set: String,
    },
    /// Match connection-tracking state.
    CtState {
        /// State.
        state: CtState,
    },
}

/// Transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP.
    Icmp,
    /// ICMPv6.
    Icmpv6,
}

/// Connection-tracking state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CtState {
    /// Part of an established connection.
    Established,
    /// Related to an existing connection.
    Related,
    /// A new connection.
    New,
    /// Not trackable.
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(name: &str, policy: Verdict, rules: Vec<Rule>) -> Chain {
        Chain {
            name: name.to_string(),
            kind: ChainKind::Filter,
            hook: Hook::Output,
            priority: -150,
            policy,
            rules,
        }
    }

    fn rule(exprs: Vec<Expr>, verdict: Verdict, origin: RuleOrigin) -> Rule {
        Rule {
            exprs,
            verdict,
            counter: false,
            origin,
            comment: String::new(),
        }
    }

    fn sample() -> Ruleset {
        Ruleset {
            tables: vec![Table {
                family: Family::Inet,
                name: "ghostnector".to_string(),
                sets: vec![Set {
                    name: "lan4".to_string(),
                    kind: SetKind::Ipv4Addr,
                    elements: vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()],
                }],
                chains: vec![chain(
                    "out_filter",
                    Verdict::Drop,
                    vec![
                        rule(
                            vec![Expr::Oifname {
                                name: "lo".to_string(),
                            }],
                            Verdict::Accept,
                            RuleOrigin::Loopback,
                        ),
                        rule(
                            vec![],
                            Verdict::Reject {
                                kind: RejectKind::AdminProhibited,
                            },
                            RuleOrigin::Mechanism {
                                mechanism: Mechanism::DefaultDeny,
                            },
                        ),
                    ],
                )],
            }],
        }
    }

    #[test]
    fn ruleset_lookup_works_by_name() {
        let ruleset = sample();
        assert!(ruleset.chain("out_filter").is_some());
        assert!(ruleset.chain("nope").is_none());
        assert_eq!(ruleset.chain_names(), vec!["out_filter"]);
    }

    #[test]
    fn chain_mut_can_append() {
        let mut ruleset = sample();
        {
            let chain = ruleset.chain_mut("out_filter").unwrap();
            chain
                .rules
                .push(rule(vec![], Verdict::Drop, RuleOrigin::Loopback));
        }
        assert_eq!(ruleset.chain("out_filter").unwrap().rules.len(), 3);
    }

    #[test]
    fn an_unconditional_rule_is_recognisable() {
        let ruleset = sample();
        let rules = &ruleset.chain("out_filter").unwrap().rules;
        assert!(!rules[0].is_unconditional());
        assert!(rules[1].is_unconditional());
    }

    #[test]
    fn ruleset_round_trips_as_json() {
        // Golden tests depend on a stable, human-readable serialisation.
        let ruleset = sample();
        let json = serde_json::to_string_pretty(&ruleset).unwrap();
        let decoded: Ruleset = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, ruleset);
    }

    #[test]
    fn origins_serialise_with_a_discriminator() {
        let origin = RuleOrigin::Exemption {
            subject: "system-user:tor".to_string(),
        };
        let json = serde_json::to_string(&origin).unwrap();
        assert!(json.contains("\"origin\":\"exemption\""));
        assert!(json.contains("system-user:tor"));
    }

    #[test]
    fn verdicts_serialise_with_a_discriminator() {
        assert_eq!(
            serde_json::to_string(&Verdict::Accept).unwrap(),
            r#"{"verdict":"accept"}"#
        );
        assert_eq!(
            serde_json::to_string(&Verdict::Redirect { port: 9040 }).unwrap(),
            r#"{"verdict":"redirect","port":9040}"#
        );
    }
}
