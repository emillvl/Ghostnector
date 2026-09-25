# M9 decisions — recorded before implementation

These are the decisions the user approved for milestone M9 (I2P as an independent network). They
bind the implementation and the documents; changing one is a new decision, not an edit.

Source of the plan: the M9 architecture proposal (this session), grounded in `ARCHITECTURE-REVIEW.md`
§3.4 and the existing `Profile`/`Networks` vocabulary.

| # | Decision |
|---|---|
| 1 | **Naming:** the machine-wide I2P profile is `ProfileId::I2pSystem` (wire tag `i2p_system`). The unused `I2pIsolated` name is retired; nothing persisted used it. |
| 2 | **Router:** managed `i2pd` is the default (Ghostnector writes its configuration and starts/stops the unit, exactly as it does for Tor), with an external-router option mirroring the Tor `ExternalServices` shape. The router runs as its own unprivileged user and needs no capabilities. |
| 3 | **Testing:** the deterministic integration and adversarial suites use a **fake router** (hermetic, no network dependency). Before M9 is frozen, a **separate real-`i2pd` qualification run** is recorded. Claims state exactly which run proved what; the fake-router run never stands in for real-router evidence. |
| 4 | **Canary:** I2P SYSTEM scope may enter `Protected` only when the configured I2P canary passes through the router's proxy. Absent or inconclusive evidence stays `Degraded` (the G9 rule, unchanged). |
| 5 | **Composition:** APP+I2P is deferred and **explicitly refused** in M9 (`I2pNeedsSystemScope`). Tor+I2P (mixed networks) is also **explicitly refused** (`MixedNetworks`), in the validator, so no request shape can enable both. I2P-over-Tor is refused with it. |

## Security model carried into the implementation

- **One active network, one active profile.** Tor and I2P are alternatives; applying either replaces
  the entire ruleset through the fail-closed baseline, so no transition can leave both exemptions
  alive.
- **Mutually exclusive exemptions.** The only egress exemption in I2P mode is the router's own uid
  (it needs clearnet for reseed/bootstrap); Tor's uid is not exempted while I2P is active, and vice
  versa. Invariants and tests enforce that the I2P ruleset contains no Tor or APP exemption.
- **No transparent I2P.** I2P has no TransPort equivalent, so the claim is worded honestly:
  *clearnet egress is denied; I2P is reachable only through the router's local proxies*. There is no
  DNAT and no DNS chokepoint in I2P mode; clearnet DNS is denied, and `.i2p` naming is the router's
  address book via its proxy.
- **`allow_lan` is refused** in I2P scope: a LAN exception would open a second path for every
  non-router process, contradicting the model.
- **The APP path is untouched.** `appd`, the launcher, the APP policy and the Tor goldens are not
  modified; the full M1–M8 gate must stay green, and is run unchanged.

## Additional requirements carried into the implementation

- **Transition observation must use the actual external boundary**, not interface byte counters: a
  probe or capture at the boundary (the host's real egress interface / an observer at the far end of
  the path) must show what leaves during Tor↔I2P transitions. Byte counters are not evidence.
- I2P is machine-wide only; `Scope::User`/`Scope::App` + I2P are refused rather than approximated.
- The product-level API stays thin enough for M10: network, scope, state, reasons; no daemon names,
  configuration files, ports, `.i2p` addresses, or tunnels in the normal surface. Verification
  settings (the canary) are operator configuration, never GUI vocabulary.
- A phase that encounters evidence contradicting one of these assumptions stops and reports instead
  of improvising.

## Execution order

M9.0 vocabulary, refusals and this record → M9.1 the I2P policy (canonical ruleset, invariants,
golden, kernel verification) → M9.2 the router service (managed `i2pd` + external option, readiness)
→ M9.3 core integration (connect/stand-down, verification path, state semantics, CLI, journal) →
M9.4 fake-router end-to-end and adversarial (IA) suites, including boundary-observed transitions →
M9.5 real-`i2pd` qualification run, claims and ledger, freeze. A clean, tested checkpoint is kept
after each phase.
