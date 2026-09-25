#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! The policy engine: a validated profile becomes a ruleset, and the ruleset is *proved* correct
//! before anything reaches the kernel.
//!
//! Two modules do the work:
//!
//! * [`ir`] is a purpose-built ruleset representation. It is deliberately not a general nftables
//!   model: it contains exactly the constructs Ghostnector's policy needs, which keeps the
//!   invariant checker exhaustive and the future netlink encoder small. Anything the IR cannot
//!   express is a policy Ghostnector cannot ship.
//! * [`invariants`] checks a ruleset against the properties the architecture review promises. The
//!   compiler calls it on its own output, so a policy that would violate an invariant can never be
//!   applied — the check is on the path, not in the test suite.
//!
//! The rule that keeps this honest: **the invariant checker does not trust the compiler.** It
//! reasons about the ruleset as data, so a compiler bug shows up as a rejected policy rather than a
//! silent hole.

pub mod canonical;
pub mod compile;
pub mod invariants;
pub mod ir;
pub mod render;

pub use canonical::canonical_kernel_ruleset;
pub use compile::{compile, compile_app_namespace, CompiledPolicy, Environment, PolicyError};
pub use invariants::{check, CheckContext, InvariantViolation, ViolationCode};
pub use ir::{
    Chain, ChainKind, CtState, Expr, Family, Hook, Mechanism, Proto, RejectKind, Rule, RuleOrigin,
    Ruleset, Set, SetKind, Table, Verdict,
};
pub use render::{render_replace_script, render_revert_script, render_table};
