//! Proofs over a compiled ruleset.
//!
//! The architecture review makes promises like "no packet leaves a non-loopback interface from a
//! protected uid unless it is Tor traffic, DHCP, or an enumerated exemption" (invariant I1). This
//! module turns that sentence — and eight others — into checks that run over the ruleset as data.
//!
//! The point is that the checker **does not trust the compiler**. A compiler bug therefore shows up
//! as a rejected policy rather than a silent hole. Every violation is reported, not just the first,
//! so a broken policy can be diagnosed in one pass.

use std::fmt;

use crate::ir::{Chain, Expr, Proto, RuleOrigin, Ruleset, Verdict};
use ghostnector_spec::exemption::{Exemption, SUBJECT_DHCP};
use ghostnector_spec::profile::Scope;
use serde::{Deserialize, Serialize};

/// The name of the single table Ghostnector owns (review §12.1).
pub const TABLE_NAME: &str = "ghostnector";

/// The chains every profile must define.
pub const REQUIRED_CHAINS: [&str; 3] = ["out_filter", "out_nat", "fwd_filter"];

/// What the checker needs to know about the policy being enforced.
#[derive(Debug, Clone)]
pub struct CheckContext<'a> {
    /// The scope the policy is meant to cover. `OutOfScope` rules are only legal for a user-scoped
    /// policy; in any other scope they are a hole.
    pub scope: Scope,
    /// The effective exemption list, exactly as it will be shown to the user.
    pub exemptions: &'a [Exemption],
    /// Ports the policy may redirect traffic to. Anything else is a typo or a hole.
    pub allowed_redirect_ports: &'a [u16],
    /// Whether this profile must resolve DNS through a chokepoint.
    pub require_dns_redirect: bool,
    /// Whether UDP and ICMP must be rejected quickly rather than silently dropped.
    pub require_udp_fast_fail: bool,
    /// Whether an exemption must precede the redirects it is protecting from.
    pub require_exemption_before_redirect: bool,
}

/// A property of the ruleset that does not hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantViolation {
    /// Stable identifier.
    pub code: ViolationCode,
    /// Chain the violation was found in.
    pub chain: String,
    /// Rule index within the chain, when the violation is about a specific rule.
    pub rule_index: Option<usize>,
    /// Human-readable explanation, safe to log.
    pub detail: String,
}

impl InvariantViolation {
    fn at(chain: &Chain, code: ViolationCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            chain: chain.name.clone(),
            rule_index: None,
            detail: detail.into(),
        }
    }

    fn in_rule(
        chain: &Chain,
        index: usize,
        code: ViolationCode,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            code,
            chain: chain.name.clone(),
            rule_index: Some(index),
            detail: detail.into(),
        }
    }

    fn global(code: ViolationCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            chain: String::new(),
            rule_index: None,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for InvariantViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.rule_index {
            Some(index) => write!(
                f,
                "{} in chain '{}' rule {}: {}",
                self.code.as_str(),
                self.chain,
                index,
                self.detail
            ),
            None if self.chain.is_empty() => write!(f, "{}: {}", self.code.as_str(), self.detail),
            None => write!(
                f,
                "{} in chain '{}': {}",
                self.code.as_str(),
                self.chain,
                self.detail
            ),
        }
    }
}

impl std::error::Error for InvariantViolation {}

/// Stable identifiers for the properties being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationCode {
    /// The table Ghostnector owns is missing entirely.
    MissingTable,
    /// A chain every profile must define is missing.
    MissingChain,
    /// The output chain's default verdict is not a deny.
    OutputChainPolicyNotDeny,
    /// The forward chain's default verdict is not a deny.
    ForwardChainPolicyNotDeny,
    /// A nat chain's default verdict is not `accept`, which nftables does not permit.
    NatChainPolicyNotAccept,
    /// The nat chain does not run before the filter chains on the same hook.
    NatChainDoesNotPrecedeFilter,
    /// An unconditional `accept` rule exists, which accepts every packet including clearnet ones.
    UnconditionalAccept,
    /// An `accept` rule in the output chain is neither loopback nor an enumerated exemption.
    UnenumeratedAccept,
    /// An `accept` rule in the output chain cites a mechanism rather than an exemption.
    MechanismAcceptInEgress,
    /// An exemption outside the output chain cites a subject that is not in the effective list.
    UnenumeratedExemption,
    /// An out-of-scope rule appears in a policy that claims to cover everything.
    OutOfScopeAcceptOutsideUserScope,
    /// An `accept` rule in the output chain allows a destination address without a declared
    /// exemption.
    DestinationAllowInEgress,
    /// An egress rule matches on an interface other than loopback, so it would break or leak when
    /// interfaces change.
    InterfaceSpecificEgressPolicy,
    /// A redirect targets a port the policy is not allowed to use.
    UnexpectedRedirectPort,
    /// The profile requires a DNS redirect and none exists.
    MissingDnsRedirect,
    /// The profile requires UDP/ICMP to fail fast and no rejection rule exists.
    MissingUdpFastFail,
    /// A redirect appears in the nat chain before the exemption that must protect it.
    ExemptionAfterRedirect,
    /// A destination exception appears after the redirect that would capture it.
    DestinationExceptionAfterRedirect,
    /// A destination exception appears after the fast-fail rule that would capture it.
    DestinationExceptionAfterFastFail,
    /// A rule references a set that does not exist in the table.
    UndeclaredSetReference,
    /// A rule matches a destination port without a transport protocol, which is not a valid match.
    InvalidRuleShape,
    /// A DHCP exemption does not match the client's own port as a source, so it permits the
    /// direction a client never sends and drops the one it does.
    DhcpExemptionDirection,
}

impl ViolationCode {
    /// Stable string identifier, used in logs and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            ViolationCode::MissingTable => "missing_table",
            ViolationCode::MissingChain => "missing_chain",
            ViolationCode::OutputChainPolicyNotDeny => "output_chain_policy_not_deny",
            ViolationCode::ForwardChainPolicyNotDeny => "forward_chain_policy_not_deny",
            ViolationCode::NatChainPolicyNotAccept => "nat_chain_policy_not_accept",
            ViolationCode::NatChainDoesNotPrecedeFilter => "nat_chain_does_not_precede_filter",
            ViolationCode::UnconditionalAccept => "unconditional_accept",
            ViolationCode::UnenumeratedAccept => "unenumerated_accept",
            ViolationCode::MechanismAcceptInEgress => "mechanism_accept_in_egress",
            ViolationCode::UnenumeratedExemption => "unenumerated_exemption",
            ViolationCode::OutOfScopeAcceptOutsideUserScope => {
                "out_of_scope_accept_outside_user_scope"
            }
            ViolationCode::DestinationAllowInEgress => "destination_allow_in_egress",
            ViolationCode::InterfaceSpecificEgressPolicy => "interface_specific_egress_policy",
            ViolationCode::UnexpectedRedirectPort => "unexpected_redirect_port",
            ViolationCode::MissingDnsRedirect => "missing_dns_redirect",
            ViolationCode::MissingUdpFastFail => "missing_udp_fast_fail",
            ViolationCode::ExemptionAfterRedirect => "exemption_after_redirect",
            ViolationCode::DestinationExceptionAfterRedirect => {
                "destination_exception_after_redirect"
            }
            ViolationCode::DestinationExceptionAfterFastFail => {
                "destination_exception_after_fast_fail"
            }
            ViolationCode::UndeclaredSetReference => "undeclared_set_reference",
            ViolationCode::InvalidRuleShape => "invalid_rule_shape",
            ViolationCode::DhcpExemptionDirection => "dhcp_exemption_direction",
        }
    }
}

/// Check a ruleset against every property the architecture promises.
///
/// Returns every violation found, so a failing policy can be fixed in one pass.
pub fn check(ruleset: &Ruleset, ctx: &CheckContext<'_>) -> Result<(), Vec<InvariantViolation>> {
    let mut violations = Vec::new();

    let Some(table) = ruleset.tables.iter().find(|table| table.name == TABLE_NAME) else {
        violations.push(InvariantViolation::global(
            ViolationCode::MissingTable,
            "the owned table is absent, so nothing is enforcing the policy",
        ));
        return Err(violations);
    };

    let set_names: Vec<&str> = table.sets.iter().map(|set| set.name.as_str()).collect();

    for required in REQUIRED_CHAINS {
        if !table.chains.iter().any(|chain| chain.name == required) {
            violations.push(InvariantViolation::global(
                ViolationCode::MissingChain,
                format!("required chain '{required}' is absent"),
            ));
        }
    }

    if let Some(chain) = table.chains.iter().find(|chain| chain.name == "out_filter") {
        check_egress(chain, ctx, &set_names, &mut violations);
    }
    if let Some(chain) = table.chains.iter().find(|chain| chain.name == "out_nat") {
        check_nat(chain, ctx, &set_names, &mut violations);
    }
    if let Some(chain) = table.chains.iter().find(|chain| chain.name == "fwd_filter") {
        if !is_deny(chain.policy) {
            violations.push(InvariantViolation::at(
                chain,
                ViolationCode::ForwardChainPolicyNotDeny,
                "forwarded traffic must be denied by default, or containers and virtual machines \
                 leak around the output chain",
            ));
        }
    }

    for chain in table
        .chains
        .iter()
        .filter(|chain| chain.kind == crate::ir::ChainKind::Nat)
    {
        if chain.policy != Verdict::Accept {
            violations.push(InvariantViolation::at(
                chain,
                ViolationCode::NatChainPolicyNotAccept,
                "nftables only permits an accept default verdict on a nat chain, so this ruleset \
                 could not be applied at all",
            ));
        }

        // The redirect has to happen before the filter verdict, or the traffic the profile is meant
        // to carry is rejected instead. Same hook, same priority means no defined order.
        for filter in table.chains.iter().filter(|filter| {
            filter.hook == chain.hook && filter.kind == crate::ir::ChainKind::Filter
        }) {
            if chain.priority >= filter.priority {
                violations.push(InvariantViolation::at(
                    chain,
                    ViolationCode::NatChainDoesNotPrecedeFilter,
                    format!(
                        "this nat chain has priority {} and the filter chain '{}' on the same hook \
                         has {}; the redirect would race the filter verdict, and traffic meant to be \
                         carried would be dropped instead",
                        chain.priority, filter.name, filter.priority
                    ),
                ));
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

fn is_deny(verdict: Verdict) -> bool {
    matches!(verdict, Verdict::Drop | Verdict::Reject { .. })
}

fn is_destination_exception(rule: &crate::ir::Rule) -> bool {
    matches!(rule.verdict, Verdict::Accept | Verdict::Return)
        && rule
            .exprs
            .iter()
            .any(|expr| matches!(expr, Expr::DaddrInSet { .. }))
}

fn check_egress(
    chain: &Chain,
    ctx: &CheckContext<'_>,
    set_names: &[&str],
    out: &mut Vec<InvariantViolation>,
) {
    if !is_deny(chain.policy) {
        out.push(InvariantViolation::at(
            chain,
            ViolationCode::OutputChainPolicyNotDeny,
            "the output chain's default verdict must be a deny, so an unmatched packet cannot \
             reach the clearnet",
        ));
    }

    let mut has_udp_fast_fail = false;
    let mut fast_fail_index: Option<usize> = None;

    for (index, rule) in chain.rules.iter().enumerate() {
        match rule.verdict {
            Verdict::Accept => {
                if rule.is_unconditional() {
                    out.push(InvariantViolation::in_rule(
                        chain,
                        index,
                        ViolationCode::UnconditionalAccept,
                        "an unconditional accept would allow every packet",
                    ));
                }
                match &rule.origin {
                    RuleOrigin::Loopback => {}
                    RuleOrigin::OutOfScope => {
                        if ctx.scope != Scope::User {
                            out.push(InvariantViolation::in_rule(
                                chain,
                                index,
                                ViolationCode::OutOfScopeAcceptOutsideUserScope,
                                format!(
                                    "traffic outside the policy's scope is accepted, but the \
                                     scope is {:?}, which claims to cover everything",
                                    ctx.scope
                                ),
                            ));
                        }
                    }
                    RuleOrigin::Exemption { subject } => {
                        if !ctx.exemptions.iter().any(|e| &e.subject == subject) {
                            out.push(InvariantViolation::in_rule(
                                chain,
                                index,
                                ViolationCode::UnenumeratedAccept,
                                format!("exemption '{subject}' is not in the effective list"),
                            ));
                        }
                        // A DHCP client sends *from* its own port *to* the server's. An exemption
                        // that matches only a destination port permits the direction a client never
                        // uses and drops the one it does, so the link dies while the policy claims
                        // to keep it alive.
                        if subject == SUBJECT_DHCP
                            && !rule
                                .exprs
                                .iter()
                                .any(|expr| matches!(expr, Expr::Sport { .. }))
                        {
                            out.push(InvariantViolation::in_rule(
                                chain,
                                index,
                                ViolationCode::DhcpExemptionDirection,
                                "a DHCP exemption must match the client's port as a source",
                            ));
                        }
                    }
                    RuleOrigin::Mechanism { mechanism } => {
                        out.push(InvariantViolation::in_rule(
                            chain,
                            index,
                            ViolationCode::MechanismAcceptInEgress,
                            format!(
                                "the {mechanism:?} mechanism must not accept traffic; accepts must \
                                 be loopback or a declared exemption"
                            ),
                        ));
                    }
                }

                let allows_destination = rule
                    .exprs
                    .iter()
                    .any(|expr| matches!(expr, Expr::DaddrInSet { .. }));
                if allows_destination
                    && !matches!(
                        rule.origin,
                        RuleOrigin::Exemption { .. }
                            | RuleOrigin::OutOfScope
                            // A rule that accepts traffic *to a loopback address* is loopback
                            // traffic, not a destination allow: it cannot leave the machine.
                            | RuleOrigin::Loopback
                    )
                {
                    out.push(InvariantViolation::in_rule(
                        chain,
                        index,
                        ViolationCode::DestinationAllowInEgress,
                        "an egress rule allows a destination address without a declared exemption",
                    ));
                }
            }
            Verdict::Reject { .. }
                if rule
                    .exprs
                    .iter()
                    .any(|expr| matches!(expr, Expr::L4Proto { proto: Proto::Udp })) =>
            {
                has_udp_fast_fail = true;
                fast_fail_index.get_or_insert(index);
            }
            _ => {}
        }

        for expr in &rule.exprs {
            match expr {
                Expr::Oifname { name } if name != "lo" => out.push(InvariantViolation::in_rule(
                    chain,
                    index,
                    ViolationCode::InterfaceSpecificEgressPolicy,
                    format!(
                        "egress policy matches interface '{name}'; it must match identity, \
                         protocol, and port so it survives interface changes"
                    ),
                )),
                Expr::Iifname { .. } => out.push(InvariantViolation::in_rule(
                    chain,
                    index,
                    ViolationCode::InterfaceSpecificEgressPolicy,
                    "an input-interface match has no meaning in an egress chain",
                )),
                Expr::DaddrInSet { set } if !set_names.contains(&set.as_str()) => {
                    out.push(InvariantViolation::in_rule(
                        chain,
                        index,
                        ViolationCode::UndeclaredSetReference,
                        format!("set '{set}' is not declared in the table"),
                    ));
                }
                _ => {}
            }
        }

        let has_port_match = rule
            .exprs
            .iter()
            .any(|expr| matches!(expr, Expr::Dport { .. }));
        let has_proto_match = rule
            .exprs
            .iter()
            .any(|expr| matches!(expr, Expr::L4Proto { .. }));
        if has_port_match && !has_proto_match {
            out.push(InvariantViolation::in_rule(
                chain,
                index,
                ViolationCode::InvalidRuleShape,
                "a destination-port match without a transport protocol is not a valid match",
            ));
        }

        if let (Some(fast_fail), true) = (fast_fail_index, is_destination_exception(rule)) {
            if index > fast_fail {
                out.push(InvariantViolation::in_rule(
                    chain,
                    index,
                    ViolationCode::DestinationExceptionAfterFastFail,
                    "this destination exception is unreachable: the fast-fail rejection above it \
                     matches first",
                ));
            }
        }
    }

    if ctx.require_udp_fast_fail && !has_udp_fast_fail {
        out.push(InvariantViolation::at(
            chain,
            ViolationCode::MissingUdpFastFail,
            "UDP must be rejected rather than silently dropped, so QUIC and real-time clients fall \
             back instead of hanging",
        ));
    }
}

fn check_nat(
    chain: &Chain,
    ctx: &CheckContext<'_>,
    set_names: &[&str],
    out: &mut Vec<InvariantViolation>,
) {
    let mut first_redirect: Option<usize> = None;
    let mut last_exemption: Option<usize> = None;
    let mut has_dns_redirect = false;

    for (index, rule) in chain.rules.iter().enumerate() {
        if let RuleOrigin::Exemption { subject } = &rule.origin {
            if !ctx.exemptions.iter().any(|e| &e.subject == subject) {
                out.push(InvariantViolation::in_rule(
                    chain,
                    index,
                    ViolationCode::UnenumeratedExemption,
                    format!("exemption '{subject}' is not in the effective list"),
                ));
            }
            if matches!(rule.verdict, Verdict::Return) {
                last_exemption = Some(index);
            }
        }
        if let RuleOrigin::OutOfScope = &rule.origin {
            if ctx.scope != Scope::User {
                out.push(InvariantViolation::in_rule(
                    chain,
                    index,
                    ViolationCode::OutOfScopeAcceptOutsideUserScope,
                    format!(
                        "traffic outside the policy's scope is left alone, but the scope is {:?}, \
                         which claims to cover everything",
                        ctx.scope
                    ),
                ));
            }
        }

        if let Verdict::Redirect { port } = rule.verdict {
            first_redirect.get_or_insert(index);
            if !ctx.allowed_redirect_ports.contains(&port) {
                out.push(InvariantViolation::in_rule(
                    chain,
                    index,
                    ViolationCode::UnexpectedRedirectPort,
                    format!("port {port} is not in the allowed redirect set"),
                ));
            }
            if rule
                .exprs
                .iter()
                .any(|expr| matches!(expr, Expr::Dport { port: 53 }))
            {
                has_dns_redirect = true;
            }
        }

        if let (Some(redirect), true) = (first_redirect, is_destination_exception(rule)) {
            if index > redirect {
                out.push(InvariantViolation::in_rule(
                    chain,
                    index,
                    ViolationCode::DestinationExceptionAfterRedirect,
                    "this destination exception is unreachable: the redirect above it matches first",
                ));
            }
        }

        for expr in &rule.exprs {
            if let Expr::DaddrInSet { set } = expr {
                if !set_names.contains(&set.as_str()) {
                    out.push(InvariantViolation::in_rule(
                        chain,
                        index,
                        ViolationCode::UndeclaredSetReference,
                        format!("set '{set}' is not declared in the table"),
                    ));
                }
            }
        }
    }

    if ctx.require_exemption_before_redirect {
        if first_redirect.is_some() && last_exemption.is_none() {
            out.push(InvariantViolation::at(
                chain,
                ViolationCode::ExemptionAfterRedirect,
                "the chain redirects traffic but contains no exemption, so Tor's own traffic would \
                 be captured",
            ));
        } else if let (Some(redirect), Some(exemption)) = (first_redirect, last_exemption) {
            if exemption > redirect {
                out.push(InvariantViolation::at(
                    chain,
                    ViolationCode::ExemptionAfterRedirect,
                    "an exemption appears after a redirect, so it no longer protects the traffic it \
                     was meant to",
                ));
            }
        }
    }

    if ctx.require_dns_redirect && !has_dns_redirect {
        out.push(InvariantViolation::at(
            chain,
            ViolationCode::MissingDnsRedirect,
            "this profile requires DNS to be resolved through a chokepoint, but no port-53 \
             redirect exists",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ChainKind, Family, Hook, Mechanism, RejectKind, Rule, Set, SetKind, Table};
    use ghostnector_spec::exemption::{lan_exemption, tor_baseline};

    const TOR_UID: u32 = 987;
    const USER_UID: u32 = 1000;
    const TRANS_PORT: u16 = 9040;
    const DNS_PORT: u16 = 9054;

    fn rule(exprs: Vec<Expr>, verdict: Verdict, origin: RuleOrigin) -> Rule {
        Rule {
            exprs,
            verdict,
            counter: false,
            origin,
            comment: String::new(),
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

    /// A ruleset that satisfies every property. Mutations of it must fail.
    fn good_ruleset() -> Ruleset {
        Ruleset {
            tables: vec![Table {
                family: Family::Inet,
                name: TABLE_NAME.to_string(),
                sets: vec![Set {
                    name: "lan4".to_string(),
                    kind: SetKind::Ipv4Addr,
                    elements: vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()],
                }],
                chains: vec![
                    Chain {
                        name: "out_nat".to_string(),
                        kind: ChainKind::Nat,
                        hook: Hook::Output,
                        // The nat chain must precede the filter chain on the same hook.
                        priority: -100,
                        policy: Verdict::Accept,
                        rules: vec![
                            rule(
                                vec![Expr::Oifname {
                                    name: "lo".to_string(),
                                }],
                                Verdict::Return,
                                RuleOrigin::Loopback,
                            ),
                            rule(
                                vec![Expr::Skuid { uid: TOR_UID }],
                                Verdict::Return,
                                exemption("system-user:tor"),
                            ),
                            rule(
                                vec![
                                    Expr::L4Proto { proto: Proto::Udp },
                                    Expr::Dport { port: 53 },
                                ],
                                Verdict::Redirect { port: DNS_PORT },
                                mechanism(Mechanism::DnsRedirect),
                            ),
                            rule(
                                vec![Expr::L4Proto { proto: Proto::Tcp }],
                                Verdict::Redirect { port: TRANS_PORT },
                                mechanism(Mechanism::TorRedirect),
                            ),
                        ],
                    },
                    Chain {
                        name: "out_filter".to_string(),
                        kind: ChainKind::Filter,
                        hook: Hook::Output,
                        priority: 0,
                        policy: Verdict::Drop,
                        rules: vec![
                            rule(
                                vec![Expr::Oifname {
                                    name: "lo".to_string(),
                                }],
                                Verdict::Accept,
                                RuleOrigin::Loopback,
                            ),
                            rule(
                                vec![Expr::Skuid { uid: TOR_UID }],
                                Verdict::Accept,
                                exemption("system-user:tor"),
                            ),
                            rule(
                                vec![
                                    Expr::L4Proto { proto: Proto::Udp },
                                    Expr::Sport { port: 68 },
                                    Expr::Dport { port: 67 },
                                ],
                                Verdict::Accept,
                                exemption("dhcp-client"),
                            ),
                            rule(
                                vec![Expr::L4Proto { proto: Proto::Udp }],
                                Verdict::Reject {
                                    kind: RejectKind::PortUnreachable,
                                },
                                mechanism(Mechanism::FastFailUdp),
                            ),
                            rule(
                                vec![Expr::L4Proto { proto: Proto::Icmp }],
                                Verdict::Reject {
                                    kind: RejectKind::AdminProhibited,
                                },
                                mechanism(Mechanism::FastFailUdp),
                            ),
                        ],
                    },
                    Chain {
                        name: "fwd_filter".to_string(),
                        kind: ChainKind::Filter,
                        hook: Hook::Forward,
                        priority: 0,
                        policy: Verdict::Drop,
                        rules: vec![],
                    },
                ],
            }],
        }
    }

    fn context<'a>(
        exemptions: &'a [Exemption],
        ports: &'a [u16],
        scope: Scope,
    ) -> CheckContext<'a> {
        CheckContext {
            scope,
            exemptions,
            allowed_redirect_ports: ports,
            require_dns_redirect: true,
            require_udp_fast_fail: true,
            require_exemption_before_redirect: true,
        }
    }

    #[test]
    fn the_reference_ruleset_satisfies_every_property() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let result = check(
            &good_ruleset(),
            &context(&exemptions, &ports, Scope::System),
        );
        assert_eq!(result, Ok(()), "reference ruleset must be clean");
    }

    #[test]
    fn a_missing_table_is_caught() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let violations = check(
            &Ruleset::default(),
            &context(&exemptions, &ports, Scope::System),
        )
        .unwrap_err();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].code, ViolationCode::MissingTable);
    }

    #[test]
    fn an_allow_policy_on_the_output_chain_is_caught() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset.chain_mut("out_filter").unwrap().policy = Verdict::Accept;
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::OutputChainPolicyNotDeny));
    }

    #[test]
    fn an_allow_policy_on_the_forward_chain_is_caught() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset.chain_mut("fwd_filter").unwrap().policy = Verdict::Accept;
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::ForwardChainPolicyNotDeny));
    }

    #[test]
    fn an_unconditional_accept_is_caught() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset.chain_mut("out_filter").unwrap().rules.push(rule(
            vec![],
            Verdict::Accept,
            RuleOrigin::Loopback,
        ));
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::UnconditionalAccept));
    }

    #[test]
    fn an_accept_citing_an_undeclared_exemption_is_caught() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset.chain_mut("out_filter").unwrap().rules.insert(
            1,
            rule(
                vec![Expr::Dport { port: 993 }],
                Verdict::Accept,
                exemption("system-user:telepathy"),
            ),
        );
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::UnenumeratedAccept));
    }

    #[test]
    fn a_dhcp_exemption_matching_only_a_destination_is_caught() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        {
            let rules = &mut ruleset.chain_mut("out_filter").expect("out_filter").rules;
            let dhcp = rules
                .iter_mut()
                .find(|rule| {
                    matches!(
                        &rule.origin,
                        RuleOrigin::Exemption { subject } if subject == "dhcp-client"
                    )
                })
                .expect("the reference ruleset has a DHCP exemption");
            // The inverted shape, which the reference ruleset used to carry: the destination port a
            // server would send to, and no source-port match at all.
            dhcp.exprs = vec![
                Expr::L4Proto { proto: Proto::Udp },
                Expr::Dport { port: 68 },
            ];
        }
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| v.code == ViolationCode::DhcpExemptionDirection),
            "{violations:?}"
        );
    }

    #[test]
    fn an_exemption_outside_the_output_chain_must_be_enumerated_too() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset.chain_mut("out_nat").unwrap().rules.insert(
            1,
            rule(
                vec![Expr::Skuid { uid: 4000 }],
                Verdict::Return,
                exemption("system-user:santa"),
            ),
        );
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::UnenumeratedExemption));
    }

    #[test]
    fn an_accept_citing_a_mechanism_is_caught() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset.chain_mut("out_filter").unwrap().rules.insert(
            1,
            rule(
                vec![Expr::L4Proto { proto: Proto::Tcp }],
                Verdict::Accept,
                mechanism(Mechanism::TorRedirect),
            ),
        );
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::MechanismAcceptInEgress));
    }

    #[test]
    fn out_of_scope_traffic_is_illegal_unless_the_policy_is_user_scoped() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset.chain_mut("out_filter").unwrap().rules.insert(
            0,
            rule(
                vec![Expr::SkuidNot { uid: USER_UID }],
                Verdict::Accept,
                RuleOrigin::OutOfScope,
            ),
        );
        ruleset.chain_mut("out_nat").unwrap().rules.insert(
            0,
            rule(
                vec![Expr::SkuidNot { uid: USER_UID }],
                Verdict::Return,
                RuleOrigin::OutOfScope,
            ),
        );

        // Legal for a user-scoped policy...
        assert_eq!(
            check(&ruleset, &context(&exemptions, &ports, Scope::User)),
            Ok(())
        );
        // ...and a hole for any policy that claims to cover everything.
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::OutOfScopeAcceptOutsideUserScope));
        assert_eq!(
            violations
                .iter()
                .filter(|v| v.code == ViolationCode::OutOfScopeAcceptOutsideUserScope)
                .count(),
            2,
            "both chains must be reported"
        );
    }

    #[test]
    fn a_destination_allow_without_an_exemption_is_caught() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset.chain_mut("out_filter").unwrap().rules.insert(
            1,
            rule(
                vec![
                    Expr::DaddrInSet {
                        set: "lan4".to_string(),
                    },
                    Expr::L4Proto { proto: Proto::Tcp },
                ],
                Verdict::Accept,
                mechanism(Mechanism::Bootstrap),
            ),
        );
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::DestinationAllowInEgress));
    }

    #[test]
    fn interface_specific_egress_policy_is_caught() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset.chain_mut("out_filter").unwrap().rules.insert(
            1,
            rule(
                vec![Expr::Oifname {
                    name: "wlan0".to_string(),
                }],
                Verdict::Drop,
                mechanism(Mechanism::DefaultDeny),
            ),
        );
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::InterfaceSpecificEgressPolicy));
    }

    #[test]
    fn a_redirect_to_an_unexpected_port_is_caught() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset.chain_mut("out_nat").unwrap().rules.push(rule(
            vec![Expr::L4Proto { proto: Proto::Tcp }],
            Verdict::Redirect { port: 6667 },
            mechanism(Mechanism::TorRedirect),
        ));
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::UnexpectedRedirectPort));
    }

    #[test]
    fn a_missing_dns_redirect_is_caught() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset.chain_mut("out_nat").unwrap().rules.retain(|rule| {
            !rule
                .exprs
                .iter()
                .any(|expr| matches!(expr, Expr::Dport { port: 53 }))
        });
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::MissingDnsRedirect));
    }

    #[test]
    fn a_missing_fast_fail_is_caught() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset
            .chain_mut("out_filter")
            .unwrap()
            .rules
            .retain(|rule| !matches!(rule.verdict, Verdict::Reject { .. }));
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::MissingUdpFastFail));
    }

    #[test]
    fn an_exemption_placed_after_a_redirect_is_caught() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        let chain = ruleset.chain_mut("out_nat").unwrap();
        let tor_rule = chain.rules.remove(1);
        chain.rules.push(tor_rule);
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::ExemptionAfterRedirect));
    }

    #[test]
    fn a_redirect_with_no_exemption_at_all_is_caught() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset
            .chain_mut("out_nat")
            .unwrap()
            .rules
            .retain(|rule| !matches!(rule.origin, RuleOrigin::Exemption { .. }));
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::ExemptionAfterRedirect));
    }

    #[test]
    fn a_nat_chain_that_does_not_precede_the_filter_chain_is_caught() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        // Equal priorities on the same hook is the arrangement that produced the observed failure:
        // the redirect raced the filter verdict, and the traffic the profile was meant to carry was
        // dropped instead.
        ruleset.chain_mut("out_nat").unwrap().priority = 0;

        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| v.code == ViolationCode::NatChainDoesNotPrecedeFilter),
            "expected the ordering violation, got {violations:?}"
        );
    }

    #[test]
    fn an_unreachable_destination_exception_is_caught() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset.chain_mut("out_filter").unwrap().rules.push(rule(
            vec![
                Expr::DaddrInSet {
                    set: "lan4".to_string(),
                },
                Expr::L4Proto { proto: Proto::Udp },
            ],
            Verdict::Accept,
            exemption("lan"),
        ));
        let mut with_lan = exemptions.clone();
        with_lan.push(lan_exemption());
        let violations = check(&ruleset, &context(&with_lan, &ports, Scope::System)).unwrap_err();
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::DestinationExceptionAfterFastFail));
    }

    #[test]
    fn a_lan_exception_in_the_right_place_is_accepted() {
        let mut exemptions = tor_baseline();
        exemptions.push(lan_exemption());
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();

        ruleset.chain_mut("out_filter").unwrap().rules.insert(
            3,
            rule(
                vec![Expr::DaddrInSet {
                    set: "lan4".to_string(),
                }],
                Verdict::Accept,
                exemption("lan"),
            ),
        );
        ruleset.chain_mut("out_nat").unwrap().rules.insert(
            1,
            rule(
                vec![Expr::DaddrInSet {
                    set: "lan4".to_string(),
                }],
                Verdict::Return,
                exemption("lan"),
            ),
        );

        assert_eq!(
            check(&ruleset, &context(&exemptions, &ports, Scope::System)),
            Ok(())
        );
    }

    #[test]
    fn an_undeclared_set_reference_is_caught() {
        let mut exemptions = tor_baseline();
        exemptions.push(lan_exemption());
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset.chain_mut("out_nat").unwrap().rules.insert(
            1,
            rule(
                vec![Expr::DaddrInSet {
                    set: "lan6".to_string(),
                }],
                Verdict::Return,
                exemption("lan"),
            ),
        );
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::UndeclaredSetReference));
    }

    #[test]
    fn a_port_match_without_a_protocol_is_caught() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset.chain_mut("out_filter").unwrap().rules.insert(
            2,
            rule(
                vec![Expr::Dport { port: 68 }],
                Verdict::Drop,
                mechanism(Mechanism::DefaultDeny),
            ),
        );
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::InvalidRuleShape));
    }

    #[test]
    fn every_violation_is_reported_not_just_the_first() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset.chain_mut("out_filter").unwrap().policy = Verdict::Accept;
        ruleset.chain_mut("fwd_filter").unwrap().policy = Verdict::Accept;
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(
            violations.len() >= 2,
            "expected both violations, got {violations:?}"
        );
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::OutputChainPolicyNotDeny));
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::ForwardChainPolicyNotDeny));
    }

    #[test]
    fn violations_have_stable_identifiers() {
        assert_eq!(
            ViolationCode::OutputChainPolicyNotDeny.as_str(),
            "output_chain_policy_not_deny"
        );
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset.chain_mut("out_filter").unwrap().policy = Verdict::Accept;
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        let text = violations[0].to_string();
        assert!(text.contains("output_chain_policy_not_deny"), "{text}");
    }

    #[test]
    fn a_rule_claiming_loopback_but_matching_an_interface_is_still_caught() {
        let exemptions = tor_baseline();
        let ports = [TRANS_PORT, DNS_PORT];
        let mut ruleset = good_ruleset();
        ruleset.chain_mut("out_filter").unwrap().rules.insert(
            0,
            rule(
                vec![Expr::Oifname {
                    name: "eth0".to_string(),
                }],
                Verdict::Accept,
                RuleOrigin::Loopback,
            ),
        );
        let violations = check(&ruleset, &context(&exemptions, &ports, Scope::System)).unwrap_err();
        assert!(violations
            .iter()
            .any(|v| v.code == ViolationCode::InterfaceSpecificEgressPolicy));
    }
}
