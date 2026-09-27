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

use crate::ir::{Chain, Expr, Mechanism, Proto, RuleOrigin, Ruleset, Verdict};
use ghostnector_spec::exemption::{Exemption, SUBJECT_DHCP, SUBJECT_I2P};
use ghostnector_spec::profile::Scope;
use serde::{Deserialize, Serialize};

/// The name of the single table Ghostnector owns (review §12.1).
pub const TABLE_NAME: &str = "ghostnector";

/// The name of the set holding the host-local APP core address.
///
/// The compiler declares it and the checker requires it exactly; a destination accept that is not
/// this set does not mean "the core address".
pub const APP_CORE_SET: &str = "appcore4";

/// The chains every profile must define.
pub const REQUIRED_CHAINS: [&str; 3] = ["out_filter", "out_nat", "fwd_filter"];

/// Which shape of policy a ruleset is, and therefore which properties apply to it.
///
/// The machine shape is the one M1–M7 built: a default-deny output chain, NAT redirects into Tor
/// and the chokepoint, an input guard, and a default-deny forward chain. The APP shapes are the two
/// halves of `APP` scope: a host table that only guards the app link and the forward path (it must
/// **not** acquire an output policy, or APP scope would silently become SYSTEM scope), and the
/// namespace-local table whose DNAT is the only mechanism that can create a usable path. The I2P
/// machine shape is the machine shape without any redirect at all: I2P has no transparent-proxy
/// equivalent, so a NAT chain in an I2P policy would claim a path that does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyShape {
    /// Machine-wide scope (`SYSTEM`, `USER`, and the DNS-lockdown/fail-closed baselines).
    Machine,
    /// Machine-wide I2P: one router-uid exemption, no redirects, no DNS chokepoint.
    I2pMachine,
    /// The host side of `APP` scope.
    AppHost,
    /// The ruleset installed inside one application namespace.
    AppNamespace,
}

/// What the checker needs to know about the policy being enforced.
#[derive(Debug, Clone)]
pub struct CheckContext<'a> {
    /// Which shape the ruleset has. Properties are checked per shape, never across them.
    pub shape: PolicyShape,
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
    /// The host-local APP core address. Required for both APP shapes.
    pub app_core: Option<std::net::Ipv4Addr>,
    /// The bridge interface the host APP table admits. Required for [`PolicyShape::AppHost`].
    pub app_bridge: Option<&'a str>,
    /// The ports a namespace may reach on the core address (transparent proxy, chokepoint, SOCKS).
    pub app_core_ports: &'a [u16],
    /// The chokepoint port, which must be reachable over both UDP and TCP from an app link.
    pub app_dns_port: Option<u16>,
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
    /// A chain that must not exist in this policy shape is present. An OUTPUT chain in the APP host
    /// table would turn app scope into machine scope; a forward chain inside a namespace has no
    /// traffic to deny.
    ForbiddenChainPresent,
    /// An accept from the app link is not bounded to the core address and a core listener port.
    AppLinkAcceptUnbounded,
    /// The app link cannot reach a core listener it must be able to reach.
    AppLinkAcceptMissing,
    /// Nothing drops the rest of what the app link could send to the host.
    AppLinkNotClosed,
    /// A namespace DNAT targets an address or port other than the configured core address and its
    /// core ports.
    AppDnatOutsideCore,
    /// The namespace's catch-all TCP DNAT does not target the namespace relay on loopback, which is
    /// the only local listener that may create the path to Tor (D-50).
    AppRelayDnatTarget,
    /// An APP namespace's output chain does not default to deny.
    AppNamespaceEgressNotDeny,
    /// An APP namespace output rule accepts a destination that is neither loopback nor the core
    /// address.
    AppNamespaceAcceptOutsideCore,
    /// An APP namespace nat chain contains a verdict or expression it must not (for example a
    /// `redirect`, which would target the namespace's own loopback, or an interface match).
    AppNamespaceNatShape,
    /// An APP namespace's input chain does not default to deny.
    AppNamespaceInboundNotDeny,
    /// An APP namespace has no established/related acceptance, so replies to the app's own flows
    /// would be dropped.
    AppNamespaceInboundMissingReturn,
    /// An APP namespace input rule accepts more than loopback or established/related traffic.
    AppNamespaceInboundUnbounded,
    /// ICMP and ICMPv6 are not rejected quickly inside a namespace.
    MissingIcmpFastFail,
    /// An APP ruleset matches an interface that is neither loopback nor the app bridge, so it would
    /// break when names change.
    InterfaceSpecificAppPolicy,
    /// The host APP table does not guard the core listener ports against non-app interfaces.
    MissingListenerGuard,
    /// An APP namespace has no destination rewrite for ordinary TCP, so transparency is broken.
    AppNamespaceDnatMissing,
    /// An APP namespace's DNS DNAT appears after the catch-all TCP DNAT, so port 53 would be
    /// captured by the Tor redirect instead of the chokepoint (the D-15 lesson, namespace edition).
    AppNamespaceDnsAfterCatchall,
    /// A filter chain's default verdict is `Return`, `Redirect` or `Dnat`, none of which is a
    /// terminal verdict a base chain can carry.
    InvalidChainPolicy,
    /// An I2P policy cites an exemption other than the I2P router's own uid and DHCP, so the
    /// mutually exclusive exemption model has been broken.
    ForeignExemptionInI2pPolicy,
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
            ViolationCode::ForbiddenChainPresent => "forbidden_chain_present",
            ViolationCode::AppLinkAcceptUnbounded => "app_link_accept_unbounded",
            ViolationCode::AppLinkAcceptMissing => "app_link_accept_missing",
            ViolationCode::AppLinkNotClosed => "app_link_not_closed",
            ViolationCode::AppDnatOutsideCore => "app_dnat_outside_core",
            ViolationCode::AppRelayDnatTarget => "app_relay_dnat_target",
            ViolationCode::AppNamespaceEgressNotDeny => "app_namespace_egress_not_deny",
            ViolationCode::AppNamespaceAcceptOutsideCore => "app_namespace_accept_outside_core",
            ViolationCode::AppNamespaceNatShape => "app_namespace_nat_shape",
            ViolationCode::AppNamespaceInboundNotDeny => "app_namespace_inbound_not_deny",
            ViolationCode::AppNamespaceInboundMissingReturn => {
                "app_namespace_inbound_missing_return"
            }
            ViolationCode::AppNamespaceInboundUnbounded => "app_namespace_inbound_unbounded",
            ViolationCode::MissingIcmpFastFail => "missing_icmp_fast_fail",
            ViolationCode::InterfaceSpecificAppPolicy => "interface_specific_app_policy",
            ViolationCode::MissingListenerGuard => "missing_listener_guard",
            ViolationCode::AppNamespaceDnatMissing => "app_namespace_dnat_missing",
            ViolationCode::AppNamespaceDnsAfterCatchall => "app_namespace_dns_after_catchall",
            ViolationCode::InvalidChainPolicy => "invalid_chain_policy",
            ViolationCode::ForeignExemptionInI2pPolicy => "foreign_exemption_in_i2p_policy",
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

    let required: &[&str] = match ctx.shape {
        PolicyShape::Machine => &REQUIRED_CHAINS,
        // I2P has no redirect and therefore no NAT chain, but it keeps the input guard (the router's
        // proxies are loopback-only) and the forward deny.
        PolicyShape::I2pMachine => &["out_filter", "in_filter", "fwd_filter"],
        // The host side of APP scope guards the link and the forward path; it has no output policy
        // at all, so it cannot become a machine-wide policy by accident.
        PolicyShape::AppHost => &["in_filter", "fwd_filter"],
        // A namespace needs both halves of the path: the DNAT that creates it, the filter that
        // enforces it, and an input chain that makes inbound connections impossible.
        PolicyShape::AppNamespace => &["out_filter", "out_nat", "in_filter"],
    };
    for required in required {
        if !table.chains.iter().any(|chain| chain.name == *required) {
            violations.push(InvariantViolation::global(
                ViolationCode::MissingChain,
                format!("required chain '{required}' is absent"),
            ));
        }
    }

    let forbidden: &[(&str, &str)] = match ctx.shape {
        PolicyShape::Machine => &[],
        PolicyShape::I2pMachine => &[(
            "out_nat",
            "I2P has no transparent-proxy equivalent: a redirect would claim a path this profile \
             does not have, and the only way to I2P is the router's local proxy",
        )],
        PolicyShape::AppHost => &[
            (
                "out_filter",
                "APP scope protects only the applications in its namespaces; an output policy \
                 would silently turn it into machine-wide scope",
            ),
            (
                "out_nat",
                "APP scope must not redirect the machine's own traffic; only the namespace DNAT \
                 carries application traffic",
            ),
        ],
        PolicyShape::AppNamespace => &[(
            "fwd_filter",
            "a namespace has one link and forwards nothing; a forward chain would only hide a \
             mistake",
        )],
    };
    for (name, why) in forbidden {
        if table.chains.iter().any(|chain| chain.name == *name) {
            violations.push(InvariantViolation::global(
                ViolationCode::ForbiddenChainPresent,
                format!("chain '{name}' must not exist in this policy shape: {why}"),
            ));
        }
    }

    for chain in &table.chains {
        if chain.kind == crate::ir::ChainKind::Filter
            && !matches!(
                chain.policy,
                Verdict::Accept | Verdict::Drop | Verdict::Reject { .. }
            )
        {
            violations.push(InvariantViolation::at(
                chain,
                ViolationCode::InvalidChainPolicy,
                "a filter chain's default verdict must be a terminal verdict",
            ));
        }
    }

    if let Some(chain) = table.chains.iter().find(|chain| chain.name == "out_filter") {
        if matches!(ctx.shape, PolicyShape::Machine | PolicyShape::I2pMachine) {
            check_egress(chain, ctx, &set_names, &mut violations);
        }
    }
    if let Some(chain) = table.chains.iter().find(|chain| chain.name == "out_nat") {
        if ctx.shape == PolicyShape::Machine {
            check_nat(chain, ctx, &set_names, &mut violations);
        }
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

    match ctx.shape {
        PolicyShape::Machine => {}
        PolicyShape::I2pMachine => check_i2p_machine(table, &mut violations),
        PolicyShape::AppHost => check_app_host(table, ctx, &set_names, &mut violations),
        PolicyShape::AppNamespace => check_app_namespace(table, ctx, &set_names, &mut violations),
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

/// An I2P policy may exempt only the router's own uid and DHCP.
///
/// This is the code-level form of the mutually exclusive exemption model: a ruleset that carries
/// Tor's uid exemption, an application identity, or anything else is refused before it can be
/// applied, no matter which compiler produced it.
fn check_i2p_machine(table: &crate::ir::Table, out: &mut Vec<InvariantViolation>) {
    for chain in &table.chains {
        for (index, rule) in chain.rules.iter().enumerate() {
            if let RuleOrigin::Exemption { subject } = &rule.origin {
                if subject != SUBJECT_I2P && subject != SUBJECT_DHCP {
                    out.push(InvariantViolation::in_rule(
                        chain,
                        index,
                        ViolationCode::ForeignExemptionInI2pPolicy,
                        format!(
                            "an I2P policy may exempt only the I2P router and DHCP, not '{subject}'"
                        ),
                    ));
                }
            }
        }
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

/// The names of the loopback destination sets, shared with the compiler.
pub const LOOPBACK4_SET: &str = "loopback4";
/// The names of the loopback destination sets, shared with the compiler.
pub const LOOPBACK6_SET: &str = "loopback6";

fn has_proto(rule: &crate::ir::Rule, proto: Proto) -> bool {
    rule.exprs
        .iter()
        .any(|expr| matches!(expr, Expr::L4Proto { proto: p } if *p == proto))
}

fn dport(rule: &crate::ir::Rule) -> Option<u16> {
    rule.exprs.iter().find_map(|expr| match expr {
        Expr::Dport { port } => Some(*port),
        _ => None,
    })
}

fn daddr_set(rule: &crate::ir::Rule) -> Option<&str> {
    rule.exprs.iter().find_map(|expr| match expr {
        Expr::DaddrInSet { set } => Some(set.as_str()),
        _ => None,
    })
}

fn is_loopback(rule: &crate::ir::Rule) -> bool {
    if !matches!(rule.origin, RuleOrigin::Loopback) {
        return false;
    }
    matches!(daddr_set(rule), Some(LOOPBACK4_SET) | Some(LOOPBACK6_SET))
        || rule.exprs.iter().any(
            |expr| matches!(expr, Expr::Iifname { name } | Expr::Oifname { name } if name == "lo"),
        )
}

fn is_mechanism(rule: &crate::ir::Rule, mechanism: Mechanism) -> bool {
    matches!(
        rule.origin,
        RuleOrigin::Mechanism {
            mechanism: found
        } if found == mechanism
    )
}

/// Interface matches are only legal when they name loopback or the configured app bridge.
fn check_app_interfaces(
    chain: &Chain,
    index: usize,
    bridge: Option<&str>,
    out: &mut Vec<InvariantViolation>,
) {
    for expr in &chain.rules[index].exprs {
        match expr {
            Expr::Iifname { name } | Expr::Oifname { name } => {
                let allowed = name == "lo" || bridge.is_some_and(|bridge| name == bridge);
                if !allowed {
                    out.push(InvariantViolation::in_rule(
                        chain,
                        index,
                        ViolationCode::InterfaceSpecificAppPolicy,
                        format!(
                            "interface '{name}' is neither loopback nor the app bridge; APP policy \
                             matches addresses, never generated interface names"
                        ),
                    ));
                }
            }
            Expr::DaddrInSet { .. } => {}
            _ => {}
        }
    }
}

/// The core set must exist and must contain exactly the configured core prefix.
fn check_core_set(
    table: &crate::ir::Table,
    ctx: &CheckContext<'_>,
    out: &mut Vec<InvariantViolation>,
) {
    let Some(core) = ctx.app_core else {
        out.push(InvariantViolation::global(
            ViolationCode::AppDnatOutsideCore,
            "an APP ruleset was checked without a configured core address",
        ));
        return;
    };
    let expected = ghostnector_spec::app::app_core_element(core);
    let declared = table.sets.iter().find(|set| set.name == APP_CORE_SET);
    match declared {
        Some(set) if set.elements.len() == 1 && set.elements[0] == expected => {}
        Some(set) => out.push(InvariantViolation::global(
            ViolationCode::AppDnatOutsideCore,
            format!(
                "set '{APP_CORE_SET}' must contain exactly '{expected}', but contains {:?}",
                set.elements
            ),
        )),
        None => out.push(InvariantViolation::global(
            ViolationCode::UndeclaredSetReference,
            format!("set '{APP_CORE_SET}' is not declared in the table"),
        )),
    }
}

/// The host side of APP scope: admit the app link to the core listeners, drop everything else from
/// it, and guard the listeners against every other interface. No output policy exists here.
fn check_app_host(
    table: &crate::ir::Table,
    ctx: &CheckContext<'_>,
    set_names: &[&str],
    out: &mut Vec<InvariantViolation>,
) {
    check_core_set(table, ctx, out);
    let Some(chain) = table.chains.iter().find(|chain| chain.name == "in_filter") else {
        return;
    };
    let bridge = ctx.app_bridge;

    let mut covered: Vec<(Proto, u16)> = Vec::new();
    let mut app_link_drop = false;

    for (index, rule) in chain.rules.iter().enumerate() {
        check_app_interfaces(chain, index, bridge, out);
        if let Some(Expr::DaddrInSet { set }) = rule
            .exprs
            .iter()
            .find(|expr| matches!(expr, Expr::DaddrInSet { .. }))
        {
            if !set_names.contains(&set.as_str()) {
                out.push(InvariantViolation::in_rule(
                    chain,
                    index,
                    ViolationCode::UndeclaredSetReference,
                    format!("set '{set}' is not declared in the table"),
                ));
            }
        }

        let from_bridge = bridge.is_some_and(|bridge| {
            rule.exprs
                .iter()
                .any(|expr| matches!(expr, Expr::Iifname { name } if name == bridge))
        });

        match rule.verdict {
            Verdict::Accept => {
                if rule.is_unconditional() {
                    out.push(InvariantViolation::in_rule(
                        chain,
                        index,
                        ViolationCode::UnconditionalAccept,
                        "an unconditional accept would admit every packet",
                    ));
                }
                if !from_bridge {
                    // The only other accept this shape may carry is loopback delivery.
                    if !is_loopback(rule) {
                        out.push(InvariantViolation::in_rule(
                            chain,
                            index,
                            ViolationCode::AppLinkAcceptUnbounded,
                            "an accept in the APP host table must come from the app bridge, or be \
                             loopback delivery",
                        ));
                    }
                    continue;
                }
                let bound_to_core = daddr_set(rule) == Some(APP_CORE_SET);
                let proto = if has_proto(rule, Proto::Udp) {
                    Some(Proto::Udp)
                } else if has_proto(rule, Proto::Tcp) {
                    Some(Proto::Tcp)
                } else {
                    None
                };
                let port = dport(rule);
                match (proto, port) {
                    (Some(proto), Some(port))
                        if bound_to_core
                            && ctx.app_core_ports.contains(&port)
                            && is_mechanism(rule, Mechanism::AppLink) =>
                    {
                        covered.push((proto, port));
                    }
                    _ => out.push(InvariantViolation::in_rule(
                        chain,
                        index,
                        ViolationCode::AppLinkAcceptUnbounded,
                        "an app-link accept must cite the AppLink mechanism and name the core \
                         address set with a core listener port",
                    )),
                }
            }
            Verdict::Drop if from_bridge && is_mechanism(rule, Mechanism::AppLink) => {
                app_link_drop = true;
            }
            _ => {}
        }
    }

    // The link must be able to reach every core listener over TCP, and the chokepoint over UDP.
    for port in ctx.app_core_ports {
        if !covered.contains(&(Proto::Tcp, *port)) {
            out.push(InvariantViolation::at(
                chain,
                ViolationCode::AppLinkAcceptMissing,
                format!("the app link cannot reach the core listener on tcp/{port}"),
            ));
        }
    }
    if let Some(dns) = ctx.app_dns_port {
        if !covered.contains(&(Proto::Udp, dns)) {
            out.push(InvariantViolation::at(
                chain,
                ViolationCode::AppLinkAcceptMissing,
                format!("the app link cannot reach the DNS chokepoint on udp/{dns}"),
            ));
        }
    }

    if !app_link_drop {
        out.push(InvariantViolation::at(
            chain,
            ViolationCode::AppLinkNotClosed,
            "nothing drops the rest of what the app link could send to the host",
        ));
    }

    for port in ctx.app_core_ports {
        let guarded = chain.rules.iter().any(|rule| {
            matches!(rule.verdict, Verdict::Drop)
                && dport(rule) == Some(*port)
                && is_mechanism(rule, Mechanism::ListenerGuard)
        });
        if !guarded {
            out.push(InvariantViolation::at(
                chain,
                ViolationCode::MissingListenerGuard,
                format!(
                    "the core listener on port {port} is not guarded against non-app interfaces"
                ),
            ));
        }
    }
}

/// One application namespace: the DNAT is the only mechanism that creates a usable path, the
/// output filter admits only the core address, and inbound connections cannot be opened.
fn check_app_namespace(
    table: &crate::ir::Table,
    ctx: &CheckContext<'_>,
    set_names: &[&str],
    out: &mut Vec<InvariantViolation>,
) {
    check_core_set(table, ctx, out);
    let Some(core) = ctx.app_core else {
        return;
    };

    // Every set a namespace rule names must be declared here; a union of the host's sets would be
    // an undeclared reference, and nftables would refuse the whole ruleset at apply time.
    for chain in &table.chains {
        for (index, rule) in chain.rules.iter().enumerate() {
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
    }

    // --- the DNAT that creates the path -------------------------------------------------------
    if let Some(chain) = table.chains.iter().find(|chain| chain.name == "out_nat") {
        let mut dns_udp: Option<usize> = None;
        let mut dns_tcp: Option<usize> = None;
        let mut catch_all_tcp: Option<usize> = None;

        for (index, rule) in chain.rules.iter().enumerate() {
            check_app_interfaces(chain, index, None, out);
            match rule.verdict {
                Verdict::Return => {}
                Verdict::Dnat { addr, port } => {
                    let is_dns = dport(rule) == Some(53)
                        && (has_proto(rule, Proto::Udp) || has_proto(rule, Proto::Tcp));
                    let is_catch_all_tcp = has_proto(rule, Proto::Tcp) && dport(rule).is_none();
                    if is_dns {
                        if addr != core || Some(port) != ctx.app_dns_port {
                            out.push(InvariantViolation::in_rule(
                                chain,
                                index,
                                ViolationCode::AppDnatOutsideCore,
                                format!(
                                    "a DNS DNAT targets {addr}:{port}; it must target the core \
                                     address and the DNS chokepoint"
                                ),
                            ));
                        }
                    } else if is_catch_all_tcp {
                        if addr != std::net::Ipv4Addr::LOCALHOST
                            || port != ghostnector_spec::app::APP_RELAY_PORT
                        {
                            out.push(InvariantViolation::in_rule(
                                chain,
                                index,
                                ViolationCode::AppRelayDnatTarget,
                                format!(
                                    "the catch-all TCP DNAT targets {addr}:{port}; it must target \
                                     the namespace relay on 127.0.0.1:{}",
                                    ghostnector_spec::app::APP_RELAY_PORT
                                ),
                            ));
                        }
                    } else {
                        out.push(InvariantViolation::in_rule(
                            chain,
                            index,
                            ViolationCode::AppDnatOutsideCore,
                            format!(
                                "a DNAT targets {addr}:{port}; the only permitted rewrites are the \
                                 DNS chokepoint and the namespace relay"
                            ),
                        ));
                    }
                    if has_proto(rule, Proto::Udp) && dport(rule) == Some(53) {
                        dns_udp.get_or_insert(index);
                    }
                    if has_proto(rule, Proto::Tcp) && dport(rule) == Some(53) {
                        dns_tcp.get_or_insert(index);
                    }
                    if has_proto(rule, Proto::Tcp) && dport(rule).is_none() {
                        catch_all_tcp.get_or_insert(index);
                    }
                }
                Verdict::Redirect { .. } => out.push(InvariantViolation::in_rule(
                    chain,
                    index,
                    ViolationCode::AppNamespaceNatShape,
                    "a redirect is not used inside a namespace; the path is an explicit DNAT to \
                     the core chokepoint and to the namespace relay",
                )),
                _ => out.push(InvariantViolation::in_rule(
                    chain,
                    index,
                    ViolationCode::AppNamespaceNatShape,
                    "a nat chain may only return or rewrite the destination",
                )),
            }
        }

        if dns_udp.is_none() || dns_tcp.is_none() {
            out.push(InvariantViolation::at(
                chain,
                ViolationCode::MissingDnsRedirect,
                "DNS must be rewritten to the core chokepoint over both UDP and TCP",
            ));
        }
        if catch_all_tcp.is_none() {
            out.push(InvariantViolation::at(
                chain,
                ViolationCode::AppNamespaceDnatMissing,
                "ordinary TCP has no destination rewrite, so nothing but DNS could reach the core \
                 address",
            ));
        }
        if let Some(catch_all) = catch_all_tcp {
            for dns in [dns_udp, dns_tcp].into_iter().flatten() {
                if dns > catch_all {
                    out.push(InvariantViolation::at(
                        chain,
                        ViolationCode::AppNamespaceDnsAfterCatchall,
                        "the DNS rewrite appears after the catch-all TCP rewrite, so port 53 would \
                         go to Tor instead of the chokepoint",
                    ));
                }
            }
        }
    }

    // --- the filter that enforces it ----------------------------------------------------------
    if let Some(chain) = table.chains.iter().find(|chain| chain.name == "out_filter") {
        if !is_deny(chain.policy) {
            out.push(InvariantViolation::at(
                chain,
                ViolationCode::AppNamespaceEgressNotDeny,
                "the namespace output chain must default to deny, or an unmatched packet could \
                 leave",
            ));
        }
        let mut udp_fast_fail = false;
        let mut icmp_fast_fail = false;
        let mut icmpv6_fast_fail = false;
        for (index, rule) in chain.rules.iter().enumerate() {
            check_app_interfaces(chain, index, None, out);
            match rule.verdict {
                Verdict::Accept => {
                    if rule.is_unconditional() {
                        out.push(InvariantViolation::in_rule(
                            chain,
                            index,
                            ViolationCode::UnconditionalAccept,
                            "an unconditional accept would admit every destination",
                        ));
                    }
                    let loopback = is_loopback(rule);
                    let core_ok = daddr_set(rule) == Some(APP_CORE_SET)
                        && dport(rule).is_some_and(|port| ctx.app_core_ports.contains(&port))
                        && is_mechanism(rule, Mechanism::AppCore);
                    if !loopback && !core_ok {
                        out.push(InvariantViolation::in_rule(
                            chain,
                            index,
                            ViolationCode::AppNamespaceAcceptOutsideCore,
                            "a namespace output accept must be loopback delivery or the core \
                             address with a core listener port",
                        ));
                    }
                }
                Verdict::Reject { .. } => {
                    if has_proto(rule, Proto::Udp) {
                        udp_fast_fail = true;
                    }
                    if has_proto(rule, Proto::Icmp) {
                        icmp_fast_fail = true;
                    }
                    if has_proto(rule, Proto::Icmpv6) {
                        icmpv6_fast_fail = true;
                    }
                }
                Verdict::Dnat { .. } | Verdict::Redirect { .. } => {
                    out.push(InvariantViolation::in_rule(
                        chain,
                        index,
                        ViolationCode::InvalidRuleShape,
                        "a filter chain cannot rewrite the destination",
                    ));
                }
                _ => {}
            }
        }
        if ctx.require_udp_fast_fail && !udp_fast_fail {
            out.push(InvariantViolation::at(
                chain,
                ViolationCode::MissingUdpFastFail,
                "UDP must be rejected rather than silently dropped, so QUIC and real-time clients \
                 fall back instead of hanging",
            ));
        }
        if !icmp_fast_fail || !icmpv6_fast_fail {
            out.push(InvariantViolation::at(
                chain,
                ViolationCode::MissingIcmpFastFail,
                "ICMP and ICMPv6 must be rejected quickly: nothing in a namespace can carry them",
            ));
        }
    }

    // --- inbound: replies to the app's own flows, and nothing else ----------------------------
    if let Some(chain) = table.chains.iter().find(|chain| chain.name == "in_filter") {
        if !is_deny(chain.policy) {
            out.push(InvariantViolation::at(
                chain,
                ViolationCode::AppNamespaceInboundNotDeny,
                "a namespace input chain must default to deny, so no inbound connection can be \
                 opened through the app path",
            ));
        }
        let mut has_return = false;
        for (index, rule) in chain.rules.iter().enumerate() {
            check_app_interfaces(chain, index, None, out);
            if !matches!(rule.verdict, Verdict::Accept) {
                continue;
            }
            let loopback = is_loopback(rule);
            let established = rule.exprs.iter().any(|expr| {
                matches!(
                    expr,
                    Expr::CtState {
                        state: crate::ir::CtState::Established | crate::ir::CtState::Related
                    }
                )
            }) && is_mechanism(rule, Mechanism::AppReturn);
            if loopback {
                continue;
            }
            if established {
                has_return = true;
                continue;
            }
            out.push(InvariantViolation::in_rule(
                chain,
                index,
                ViolationCode::AppNamespaceInboundUnbounded,
                "a namespace input accept must be loopback or the reply to a flow the core already \
                 accepted",
            ));
        }
        if !has_return {
            out.push(InvariantViolation::at(
                chain,
                ViolationCode::AppNamespaceInboundMissingReturn,
                "there is no acceptance for replies to the app's own flows, so its connections \
                 would not work",
            ));
        }
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
            shape: PolicyShape::Machine,
            scope,
            exemptions,
            allowed_redirect_ports: ports,
            require_dns_redirect: true,
            require_udp_fast_fail: true,
            require_exemption_before_redirect: true,
            app_core: Some(ghostnector_spec::app::DEFAULT_APP_CORE_ADDRESS),
            app_bridge: None,
            app_core_ports: ports,
            app_dns_port: None,
        }
    }

    /// The ports an APP ruleset may reach, in the test environment.
    const APP_PORTS: [u16; 2] = [DNS_PORT, 9050];

    fn app_context<'a>(
        shape: PolicyShape,
        exemptions: &'a [Exemption],
        core_ports: &'a [u16],
        bridge: Option<&'a str>,
    ) -> CheckContext<'a> {
        CheckContext {
            shape,
            scope: Scope::App,
            exemptions,
            allowed_redirect_ports: &[],
            require_dns_redirect: shape == PolicyShape::AppNamespace,
            require_udp_fast_fail: true,
            require_exemption_before_redirect: false,
            app_core: Some(ghostnector_spec::app::DEFAULT_APP_CORE_ADDRESS),
            app_bridge: bridge,
            app_core_ports: core_ports,
            app_dns_port: Some(DNS_PORT),
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

    fn i2p_env() -> crate::compile::Environment {
        let mut env = app_env();
        env.i2p_uid = Some(989);
        env
    }

    fn i2p_context<'a>(exemptions: &'a [Exemption]) -> CheckContext<'a> {
        CheckContext {
            shape: PolicyShape::I2pMachine,
            scope: Scope::System,
            exemptions,
            allowed_redirect_ports: &[],
            require_dns_redirect: false,
            require_udp_fast_fail: true,
            require_exemption_before_redirect: false,
            app_core: None,
            app_bridge: None,
            app_core_ports: &[],
            app_dns_port: None,
        }
    }

    #[test]
    fn an_i2p_policy_is_clean_and_may_not_carry_a_foreign_exemption_or_a_redirect() {
        let policy = crate::compile::compile(
            ghostnector_spec::backend::ProfileId::I2pSystem,
            &ghostnector_spec::backend::Params::default(),
            &i2p_env(),
        )
        .expect("the I2P policy compiles");
        let exemptions = policy.exemptions.clone();
        assert_eq!(
            check(&policy.ruleset, &i2p_context(&exemptions)),
            Ok(()),
            "the real I2P policy must satisfy the I2P shape"
        );

        // The mutually exclusive exemption model: Tor's uid may not appear in an I2P policy.
        let mut foreign = policy.ruleset.clone();
        for table in &mut foreign.tables {
            for chain in &mut table.chains {
                for rule in &mut chain.rules {
                    if let RuleOrigin::Exemption { subject } = &mut rule.origin {
                        if subject == SUBJECT_I2P {
                            *subject = "system-user:tor".to_string();
                        }
                    }
                }
            }
        }
        let violations = check(&foreign, &i2p_context(&exemptions)).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|violation| violation.code == ViolationCode::ForeignExemptionInI2pPolicy),
            "{violations:?}"
        );

        // A NAT chain would claim a transparent path I2P does not have.
        let mut redirected = policy.ruleset.clone();
        redirected.tables[0].chains.push(Chain {
            name: "out_nat".to_string(),
            kind: ChainKind::Nat,
            hook: Hook::Output,
            priority: -100,
            policy: Verdict::Accept,
            rules: Vec::new(),
        });
        let violations = check(&redirected, &i2p_context(&exemptions)).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|violation| violation.code == ViolationCode::ForbiddenChainPresent),
            "{violations:?}"
        );
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

    // ---------------------------------------------------------------- APP shapes

    fn app_env() -> crate::compile::Environment {
        crate::compile::Environment {
            tor_uid: Some(TOR_UID),
            dnscrypt_uid: None,
            i2p_uid: None,
            i2p_http_port: 4444,
            i2p_socks_port: 4447,
            trans_port: TRANS_PORT,
            chokepoint_port: DNS_PORT,
            socks_port: 9050,
            dhcp_client_port: 68,
            app_core: ghostnector_spec::app::DEFAULT_APP_CORE_ADDRESS,
            app_prefix: ghostnector_spec::app::DEFAULT_APP_PREFIX,
            app_bridge: ghostnector_spec::app::DEFAULT_APP_BRIDGE.to_string(),
        }
    }

    fn app_host_ruleset() -> Ruleset {
        crate::compile::compile(
            ghostnector_spec::backend::ProfileId::TorApp,
            &ghostnector_spec::backend::Params::default(),
            &app_env(),
        )
        .expect("the APP host profile compiles")
        .ruleset
    }

    fn app_namespace_ruleset() -> Ruleset {
        crate::compile::compile_app_namespace(&app_env())
            .expect("the APP namespace profile compiles")
            .ruleset
    }

    #[test]
    fn the_app_host_reference_satisfies_every_property() {
        let exemptions: [Exemption; 0] = [];
        assert_eq!(
            check(
                &app_host_ruleset(),
                &app_context(PolicyShape::AppHost, &exemptions, &APP_PORTS, Some("ghbr0")),
            ),
            Ok(()),
            "the compiled APP host table must satisfy its own shape checks"
        );
    }

    #[test]
    fn the_app_namespace_reference_satisfies_every_property() {
        let exemptions: [Exemption; 0] = [];
        assert_eq!(
            check(
                &app_namespace_ruleset(),
                &app_context(PolicyShape::AppNamespace, &exemptions, &APP_PORTS, None),
            ),
            Ok(()),
            "the compiled APP namespace must satisfy its own shape checks"
        );
    }

    #[test]
    fn an_app_host_table_that_acquires_an_output_policy_is_caught() {
        let exemptions: [Exemption; 0] = [];
        let mut ruleset = app_host_ruleset();
        ruleset.tables[0].chains.push(Chain {
            name: "out_filter".to_string(),
            kind: ChainKind::Filter,
            hook: Hook::Output,
            priority: 0,
            policy: Verdict::Drop,
            rules: vec![],
        });
        let violations = check(
            &ruleset,
            &app_context(PolicyShape::AppHost, &exemptions, &APP_PORTS, Some("ghbr0")),
        )
        .unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| v.code == ViolationCode::ForbiddenChainPresent),
            "{violations:?}"
        );
    }

    #[test]
    fn an_unbounded_app_link_accept_is_caught() {
        let exemptions: [Exemption; 0] = [];
        let mut ruleset = app_host_ruleset();
        {
            let rules = &mut ruleset.chain_mut("in_filter").expect("in_filter").rules;
            let accept = rules
                .iter_mut()
                .find(|rule| {
                    matches!(rule.verdict, Verdict::Accept)
                        && matches!(
                            rule.origin,
                            RuleOrigin::Mechanism {
                                mechanism: Mechanism::AppLink
                            }
                        )
                })
                .expect("the host table admits the app link");
            // Drop the core-address bound: now it admits anything the link sends to that port.
            accept
                .exprs
                .retain(|expr| !matches!(expr, Expr::DaddrInSet { .. }));
        }
        let violations = check(
            &ruleset,
            &app_context(PolicyShape::AppHost, &exemptions, &APP_PORTS, Some("ghbr0")),
        )
        .unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| v.code == ViolationCode::AppLinkAcceptUnbounded),
            "{violations:?}"
        );
    }

    #[test]
    fn an_app_link_that_is_not_closed_is_caught() {
        let exemptions: [Exemption; 0] = [];
        let mut ruleset = app_host_ruleset();
        ruleset
            .chain_mut("in_filter")
            .unwrap()
            .rules
            .retain(|rule| {
                !matches!(rule.verdict, Verdict::Drop)
                    || !matches!(
                        rule.origin,
                        RuleOrigin::Mechanism {
                            mechanism: Mechanism::AppLink
                        }
                    )
            });
        let violations = check(
            &ruleset,
            &app_context(PolicyShape::AppHost, &exemptions, &APP_PORTS, Some("ghbr0")),
        )
        .unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| v.code == ViolationCode::AppLinkNotClosed),
            "{violations:?}"
        );
    }

    #[test]
    fn a_namespace_dnat_outside_the_core_is_caught() {
        let exemptions: [Exemption; 0] = [];
        let mut ruleset = app_namespace_ruleset();
        {
            let rules = &mut ruleset.chain_mut("out_nat").unwrap().rules;
            let dnat = rules
                .iter_mut()
                .find(|rule| matches!(rule.verdict, Verdict::Dnat { .. }))
                .expect("the namespace DNATs");
            dnat.verdict = Verdict::Dnat {
                addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
                port: TRANS_PORT,
            };
        }
        let violations = check(
            &ruleset,
            &app_context(PolicyShape::AppNamespace, &exemptions, &APP_PORTS, None),
        )
        .unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| v.code == ViolationCode::AppDnatOutsideCore),
            "{violations:?}"
        );
    }

    #[test]
    fn a_namespace_accepting_a_foreign_destination_is_caught() {
        let exemptions: [Exemption; 0] = [];
        let mut ruleset = app_namespace_ruleset();
        ruleset.chain_mut("out_filter").unwrap().rules.insert(
            0,
            rule(
                vec![Expr::DaddrInSet {
                    set: "loopback4".to_string(),
                }],
                Verdict::Accept,
                mechanism(Mechanism::Bootstrap),
            ),
        );
        let violations = check(
            &ruleset,
            &app_context(PolicyShape::AppNamespace, &exemptions, &APP_PORTS, None),
        )
        .unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| v.code == ViolationCode::AppNamespaceAcceptOutsideCore),
            "{violations:?}"
        );
    }

    #[test]
    fn a_redirect_inside_a_namespace_is_caught() {
        let exemptions: [Exemption; 0] = [];
        let mut ruleset = app_namespace_ruleset();
        ruleset.chain_mut("out_nat").unwrap().rules.push(rule(
            vec![Expr::L4Proto { proto: Proto::Tcp }],
            Verdict::Redirect { port: TRANS_PORT },
            mechanism(Mechanism::TorRedirect),
        ));
        let violations = check(
            &ruleset,
            &app_context(PolicyShape::AppNamespace, &exemptions, &APP_PORTS, None),
        )
        .unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| v.code == ViolationCode::AppNamespaceNatShape),
            "{violations:?}"
        );
    }

    #[test]
    fn a_namespace_without_an_inbound_deny_is_caught() {
        let exemptions: [Exemption; 0] = [];
        let mut ruleset = app_namespace_ruleset();
        ruleset.chain_mut("in_filter").unwrap().policy = Verdict::Accept;
        let violations = check(
            &ruleset,
            &app_context(PolicyShape::AppNamespace, &exemptions, &APP_PORTS, None),
        )
        .unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| v.code == ViolationCode::AppNamespaceInboundNotDeny),
            "{violations:?}"
        );
    }

    #[test]
    fn a_violation_code_is_stable_for_the_app_shapes_too() {
        assert_eq!(
            ViolationCode::AppDnatOutsideCore.as_str(),
            "app_dnat_outside_core"
        );
        assert_eq!(
            ViolationCode::ForbiddenChainPresent.as_str(),
            "forbidden_chain_present"
        );
    }
}
