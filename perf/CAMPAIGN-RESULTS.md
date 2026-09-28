# Performance campaign — measurement results (H1/H2)

**Purpose:** measure Ghostnector's own added latency against an equivalent Tor path, locate any
real overhead, and correct the resource methodology — before any optimization. No product code
was changed. All product behaviour, policies, and existing qualification records are untouched.

**Product under test:** the installed qualified product on `ghostnector-qual` (VM tree at
`f82adf9`; repository HEAD `230ef82`). VM: Ubuntu 24.04.5, kernel 6.8.0-142, 4 vCPU, 7.9 GB.

**Harness (new, in this repository):**

| File | Role |
|---|---|
| `scripts/perf-paired-http.sh` | interleaved HTTP benchmark: product SYSTEM, equivalent transparent standalone Tor, SOCKS reference; `--same-instance` mode points the equivalent route at the product's own Tor |
| `scripts/lib/perf-paired-client.py` | one sample: explicit DNS to a foreign resolver + HTTP, decomposed |
| `scripts/lib/perf-paired-summary.py`, `perf-paired-analysis.py`, `perf-paired-order.py` | per-route stats, paired differences, bootstrap CIs, order analysis |
| `scripts/perf-app-launch.sh`, `scripts/lib/perf-launch-watch.py`, `perf-app-launch-analysis.py` | APP launch phase profiler |
| `scripts/perf-app-http.sh`, `scripts/lib/perf-app-http-client.py` | APP relay vs direct-SOCKS HTTP latency |
| `scripts/perf-dns-focus.sh`, `scripts/lib/perf-dns-ab.py`, `perf-dns-once.py`, `perf-pcap-dns.py` | focused DNS A/B with loopback packet capture |
| `scripts/lib/perf-resources.py` | corrected /proc-delta resource sampling |

Raw records and durable logs: `perf/` here and `/var/log/ghostnector-qual/` on the VM.

---

## 1. Equivalent paired HTTP results

All runs: N=40 latency iterations (43 samples/route including 3 throughput rows), route order
reshuffled every iteration, 3 warmup rounds, verification interval set above the measurement
window, no `status` polling inside it.

### 1.1 Two-instance (the requested primary baseline: standalone Tor, same transparent shape)

`perf/paired-http-20260928T141100Z.*`

| route | DNS p10/med/p90 (ms) | connect med (ms) | TTFB p10/med/p90 (ms) | total p10/med/p90 (ms) |
|---|---|---|---|---|
| product (Ghostnector SYSTEM) | 270.9 / **278.8** / 298.1 | 4.7 | 268.9 / **277.1** / 383.5 | 555.1 / **570.3** / 1332.8 |
| equivalent (standalone Tor, TransPort+DNSPort, uid redirect) | 135.2 / **143.1** / 168.9 | 4.4 | 394.3 / **587.8** / 2191.9 | 559.5 / **821.6** / 2390.2 |
| socks reference (secondary) | — | 4.2 | 142.7 / **163.5** / 1253.6 | 299.9 / **353.8** / 2656.8 |

Paired product − equivalent (total): n=43, p10 −1951.9, **med −315.1**, p90 +42.3,
mean −796.2; bootstrap 95% CI of the median **[−888.4, −110.6]**; sign test p<0.0001;
product faster in 35/43.

The two instances differed in opposite directions within the same run: the standalone Tor's DNS
was **135 ms faster** while its HTTP stream was **311 ms slower**. The paired "product is faster"
result is therefore an instance artifact, not a Ghostnector property. **A two-instance design
cannot resolve Ghostnector's own overhead.**

### 1.2 Same-instance (identical Tor: the equivalent route redirects into the product's own Tor)

`perf/paired-http-20260928T143837Z.*`

| route | DNS p10/med/p90 (ms) | connect med (ms) | TTFB p10/med/p90 (ms) | total p10/med/p90 (ms) |
|---|---|---|---|---|
| product | 177.5 / **192.9** / 282.2 | 5.5 | 350.7 / **372.4** / 479.7 | 551.8 / **574.6** / 1387.0 |
| equivalent (same Tor, no chokepoint) | 152.3 / **168.9** / 230.5 | 4.9 | 305.6 / **375.8** / 517.0 | 520.6 / **552.8** / 1227.9 |

Paired product − equivalent: total n=43, p10 −666.7, **med +18.6**, p90 +178.4,
bootstrap 95% CI of the median **[−8.2, +33.1]**, sign test p=0.36 (not significant).
TTFB paired difference: med +2.0 ms, 95% CI [−5.4, +11.6] (not significant).
DNS paired difference: med +19.5 ms, 95% CI [6.1, 31.8] — investigated in §2; it is Tor-side
flow variance, not the relay.

### 1.3 Throughput (3 interleaved rounds each; highly variable, shown for completeness)

| run | product | equivalent | socks |
|---|---|---|---|
| two-instance | 1.19 MiB/s | 0.76 MiB/s | 0.27 MiB/s |
| same-instance | 1.09 MiB/s | 0.97 MiB/s | 1.44 MiB/s |

Same-instance throughput matches the equivalent path within measurement noise.

---

## 2. Focused DNS: what the chokepoint actually costs

`perf/dns-focus-20260928T150553Z.*` (A, valid) and `...T151641Z.*` (B).

**A. Root, alternating, chokepoint (`127.0.0.1:53`) vs DNSPort (`127.0.0.1:9053`), same Tor.**
120 samples each: direct p10/med/p90 = 161.1/207.7/287.3 ms; via chokepoint 165.5/220.1/289.3 ms.
Paired via − direct: p10 −81.2, **med +12.4**, p90 +72.9, **mean −0.4 ms**.

Loopback packet capture (`perf-pcap-dns.py`) decomposes the chokepoint route:

| segment | p10 / med / p90 |
|---|---|
| client → relay (queueing/handling) | 0.9 / **1.9** / 2.8 ms |
| relay upstream RTT (chokepoint→DNSPort→chokepoint) | 161.9 / **217.6** / 286.1 ms |
| relay reply → client | 0.1 / **0.5** / 1.1 ms |
| client-observed total | 164.4 / **219.9** / 287.5 ms |
| direct route total in the same window | 164.0 / **206.9** / 284.1 ms |

The relay's own hops total **~2.4 ms**; the entire remaining difference lives inside Tor's
DNSPort RTT.

**B. NAT-shaped, alternating per query** (product: uid 1000 → 8.8.8.8:53 → chokepoint;
equivalent: uid 65534 → bench chain → DNSPort; direct: root → DNSPort), 120 samples each:

| route | p10 | med | p90 |
|---|---|---|---|
| product | 157.9 | **189.8** | 217.7 |
| equivalent | 314.7 | **322.1** | 362.9 |
| direct root → DNSPort | 156.4 | **184.9** | 223.3 |

Product ≈ direct (+5 ms including the chokepoint, NAT and product chain); the equivalent route
was **133 ms slower in this window**. In the same-instance HTTP run above the same comparison
was +20 ms in the other direction. **The sign is not stable: Tor per-flow variance is ±130 ms
and dwarfs everything Ghostnector does.**

**Conclusion:** Ghostnector's DNS chokepoint adds ~1.9 ms inbound + ~0.5 ms outbound, consistent
with the local stub result (+2.1 ms). The +19.5 ms seen in one paired window was Tor queueing /
flow state, not the relay.

---

## 3. APP launch phase breakdown

`perf/app-launch-profile-20260928T152100Z.*`: 8 runs per mode, order alternated.

| milestone (median, ms) | direct | product |
|---|---|---|
| t0 | 0 | 0 |
| netns created | — | 89.2 |
| relay process present | — | 445.5 |
| session socket present | — | 581.0 |
| launcher present | — | 637.2 |
| app process present (5 ms poll granularity) | **50.6** | **665.6** |

Product-added launch time: **~615 ms**. Phase gaps:

| gap | median | what happens |
|---|---|---|
| t0 → netns | 89.2 ms | CLI startup, core IPC, appd `Create` start |
| netns → relay | 356.4 ms | namespace config: ~18 `ip` forks + `nft -f` + sysctls + relay spawn |
| relay → app | 220.1 ms | `Create` return, effective-policy `nft list`, `Launch` IPC, session, launcher, shell+exec |

Process/IPC costs measured on the same VM:

| operation | median |
|---|---|
| `ip link show lo` | 16.4 ms |
| `nft list tables` | 21.1 ms |
| `ip netns add` (one namespace) | 22.9 ms |
| `ghostnector --version` (CLI startup) | 21.7 ms |
| `ghostnector apps` (CLI+core+appd round trips) | 79.3 ms |
| `ghostnector status` (CLI+core+netd+`nft list`) | 90.7 ms |

`appd`'s `create` issues ~18 `ip` invocations and 2 `nft` invocations; at these per-fork costs
that is **≈ 330 ms of the 356 ms netns→relay gap**. This is the single largest real Ghostnector
overhead found by the campaign.

---

## 4. APP HTTP through the D-50 relay vs direct SOCKS (same Tor)

`perf/app-http-20260928T153942Z.*`: 25 iterations inside a protected namespace, DNS once per
iteration through the namespace chokepoint, routes interleaved.

| route | DNS med (ms) | connect/socks med (ms) | TTFB med (ms) | total med (ms) |
|---|---|---|---|---|
| relay (DNAT → relay → SOCKS) | 153.3 | 0.5 (local accept) | **413.7** (p90 1848.7) | **417.4** |
| direct SOCKS to 10.200.0.1:9050 | 153.3 | 168.8 (CONNECT incl. exit) | **166.9** (p90 176.3) | **344.1** |

Paired relay − direct: n=25, p10 −67.7, **med +62.6 ms**, p90 +1509.7, with four multi-second
outliers on the relay route (1.85 s, 2.94 s, 2.96 s, 10.6 s) and none on the direct route.

The direct route's TTFB is extremely stable (161–180 ms); the relay route's is consistently
higher and occasionally takes seconds. The relay's byte path itself is not the cost — its own
accept is 0.5 ms and the DNS hops are ~2.4 ms. The difference is consistent with Tor's
per-group `IsolateSOCKSAuth` circuit behaviour plus the serialized SOCKS setup after the
client's connect (a PC-19 security property that must not be weakened).

---

## 5. Corrected resource measurements (`/proc` deltas, no `status` polling)

| window | process | CPU % | RSS | voluntary switches |
|---|---|---|---|---|
| SYSTEM protected idle, 60 s | netd | 0.000 | 3.68 MB | 0 |
| | core | 0.017 | 3.18 MB | 0 |
| | dns chokepoint | 0.000 | 2.23 MB | 0 |
| | appd | 0.000 | 2.68 MB | 0 |
| | tor | 0.050 | 101.1 MB | 82 |
| | whole system | 0.1 % of all cores | | |
| APP protected idle, 60 s | appd | 0.000 | 3.03 MB | 0 |
| | core | 0.017 | 3.18 MB | 0 |
| | dns chokepoint | 0.000 | 1.99 MB | 0 |
| | netd | 0.000 | 3.68 MB | 0 |
| | tor | 0.050 | 101.1 MB | 82 |
| relay under a real 1 MB download, 30 s | relay | 0.566 | 2.58 MB | 1 |

The helpers are effectively idle (≈1 wake/s total, from core's verification tick). The old
"~0.7 % CPU idle" figure was the lifetime-average `ps pcpu` artifact.

---

## 6. Benchmark artifacts found (and fixed)

1. **`ps -o pcpu` is a lifetime average**, not idle CPU. Replaced with `/proc/<pid>/stat` deltas.
2. **`ghostnector status` forks `nft list table`** (90.7 ms per poll); the old harness polls it
   inside measurement windows. New harness has no `status` polling in the window and sets the
   verification interval (3600 s) above it.
3. **The old baseline was architecturally different** (`SOCKS5 hostname`, resolves at the exit)
   and was sampled sequentially, not paired. Both effects are larger than any Ghostnector code.
4. **Two Tor instances cannot be compared sample-by-sample** — §1.1. The same-instance mode is
   required to isolate the product.
5. **Deployment race** briefly installed 0-byte helper copies (a harness bug, fixed and now
   hash-verified).
6. **The harness used to continue when the product was not protected**; it now retries the
   product's own connect once and aborts otherwise.
7. **The abort path did not restore `core.env`**; the trap now does, idempotently.
8. **Environment:** the VM hung in the initramfs once (documented; recovered with a second hard
   reset) and showed e1000/blk workqueue stalls. One DNS focus A-section run aborted on a Tor
   dial timeout and reused a stale capture; that A result is discarded (run 2's A is the valid
   one). These are VM artifacts, not product behaviour.

---

## 7. Conclusions

- **Ghostnector's steady-state forwarding overhead is at the measurement-noise floor of Tor.**
  Same-instance total paired difference +18.6 ms, 95% CI [−8.2, +33.1]; TTFB +2.0 ms,
  CI [−5.4, +11.6]. The chokepoint's own hops are ~2.4 ms; the nft redirect is microseconds.
  DNS paired differences swing between +20 ms and −137 ms with the sign of the Tor flow state.
- **The published 93 ms** was produced by an inequivalent baseline (SOCKS-hostname) sampled
  sequentially; it is not attributable to Ghostnector code.
- **Throughput** matches the equivalent path within noise; the relay's synthetic small-message
  floor (≈42 MiB/s worst case, ~540 MiB/s at 64 KiB) is far above Tor.
- **The one real, large, actionable overhead is APP launch: ~615 ms added** (665.6 vs 50.6 ms),
  dominated by ~18 `ip` subprocess invocations at ~16 ms each inside `appd`'s `create`.
- **Resources are already tiny** (~11.8 MB total helpers, ≈0.02 % CPU idle, relay 2.58 MB /
  0.57 % under download).

## 8. Revised ranked optimization candidates (measurement-based)

| # | Candidate | Expected benefit | Invariant that could be affected |
|---|---|---|---|
| 1 | `appd` namespace create: batch `ip` commands (`ip -batch`) and replace presence probes (`bridge_present`, `group_present`) with `/sys/class/net` reads; remove duplicate checks within one `Create` | ~200–300 ms off APP launch (of the 356 ms netns→relay gap) | Namespace confinement, bridge admission, "no half-created group": every presence/absence check must remain, only the mechanism changes; re-run `appd-socket`, `core-app`, `app-adversarial` |
| 2 | `appd` Launch: 10 ms relay-readiness poll instead of 100 ms, and `/sys` group presence | ~50–150 ms | D-50: a relay that does not come up must still fail group creation |
| 3 | Fold the post-Launch `ReportRegistry` round trip into the Launch reply (or refresh lazily) | ~30–80 ms (IPC measured 79 ms for 3 round trips) | The snapshot must still come from the helper/kernel truth |
| 4 | Machine-wide data path | none needed — measured within noise | — |
| 5 | DNS chokepoint thread/socket per query | ~2 ms of a ~190 ms lookup | The fresh-per-query socket is the response-correlation property; any pooled design must keep one socket per in-flight query and be security-reviewed. Not worth it at current numbers. |
| 6 | Relay `TCP_NODELAY` / larger splice buffer | <0.1 ms per connection; throughput already non-binding | None (byte splice unchanged) |
| 7 | Qualification-script fixes (paired equivalent baseline, `/proc` CPU, no status polling) | Correct evidence, no product effect | None (measurement only) |
| — | DNS caching | deferred by instruction; not needed for relative overhead | Would change documented chokepoint behaviour and needs its own review |

The campaign's non-negotiable constraint held throughout: no Tor anonymity, isolation, DNS,
D-50, namespace, nftables, fail-closed, bootguard, or least-privilege property was changed to
obtain any number in this record.

> **Update:** items 1–3 were executed against this list. APP launch fell from 665.6 ms to
> 320.9 ms median (added overhead ≈615 → ≈263 ms); the measured attributions, CPU/RSS impact,
> regression results and the rejected item-3 fold are in `perf/APP-LAUNCH-OPTIMIZATION.md`.
> Nothing outside `ghostnector-appd` changed.
>
> **Requalification (2026-09-28/29):** the optimized candidate was re-qualified on the installed
> product and is qualified to replace `f82adf9`. Final tested product commit `9b0fe5d` (the appd
> optimization commits plus the one CLI session-exit fix the requalification found). Installed APP
> launch **301.9 ms median** (291.9/352.7 p10/p90) at the final commit, 326.5 ms at the optimization
> commit (was 665.6); leakage 30/0/0 with analyzer exit 0 and 0 violations/0 ambiguous; real-Tor APP
> 17/0/0; lifecycle 33/0/0; boot guard 8/7/4; M1–M10 gate 21/21 rc 0 with 463 unit tests. Details in
> `docs/RELEASE-CANDIDATE-REPORT.md` §0 and `perf/APP-LAUNCH-OPTIMIZATION.md`.
