# APP launch optimization — measured results (items 1–3)

**Context:** `perf/CAMPAIGN-RESULTS.md` established that the machine-wide steady-state data path
is at the Tor measurement-noise floor and that the only large Ghostnector-controlled cost is APP
launch (≈615 ms added; ~18 `ip` forks at ~14–16 ms each under the installed helper's sandbox).

**Method:** each candidate build was installed on the same VM and measured with the same profiler
(`scripts/perf-app-launch.sh`, 10 runs per mode, order alternated, app process appearance and the
app's own stdout timestamp). Raw records are the `perf/app-launch-profile-*.csv` files. All
regression suites were re-run against the final candidate.

**Builds measured (release, x86_64-unknown-linux-gnu, sha256 of ghostnector-appd):**

| build | commit | sha256 | artifact |
|---|---|---|---|
| qualified baseline | `f82adf9` | `10a5fa31…b3c3` | backup: `/root/product-f82adf9/` on the VM |
| item 1 only | `012e9c0` | `6a24f05e…e6a6e1` | staged on the VM |
| items 1+2 | `6a53d20` | `ee5ded98…cca35` | staged on the VM |
| item 3 fold | `0d947df` (items 1+2+`bridge` fold) | `83a5941d…c68ef` | staged on the VM |

The VM's installed product was restored to the qualified `f82adf9` binaries after the
measurements; the candidate binaries remain in `/home/ghost/stage/` and `/root/product-f82adf9/`
holds the baseline.

## Results

Product process-appearance (`app_ms`) medians:

| build | product p10 / med / p90 | direct med | added over direct | netns→relay | relay→app |
|---|---|---|---|---|---|
| qualified `f82adf9` (N=8) | 555 / **665.6** / 751 | 50.6 | ~615 ms | 356.4 ms | 220.1 ms |
| item 1 `012e9c0` (N=10) | 370 / **423.0** / 956 | 66.2 | ~357 ms | 176.9 ms | 169.3 ms |
| items 1+2 `6a53d20` (N=10) | 332 / **362.4** / 651 | 70.7 | ~292 ms | 186.7 ms | 92.3 ms |
| final `0d947df` (N=10) | 288 / **320.9** / 603 | 57.9 | ~263 ms | 146.8 ms | 100.4 ms |

With the app's own stdout timestamp (available for the final build, both modes): product
`exec_ms` median **331.8 ms** vs direct **56.5 ms**.

### Exact attribution (same profiler, same VM)

| optimization | measured saving | evidence |
|---|---|---|
| **Item 1** — one `ip -batch` per phase, `/sys` presence probes, batched destroy | **242.6 ms** (665.6 → 423.0) | netns→relay −179.5 ms (12 fewer forks), relay→app −50.8 ms (3 fewer presence forks) |
| **Item 2** — 10 ms relay-readiness poll + fail-fast on a dead relay | **60.6 ms** (423.0 → 362.4) | relay→app −77.0 ms; the old loop paid a fixed 100 ms whenever the first check missed |
| **Item 1 refinement** — `bridge_slave isolated on` folded into the `ip` batch, `bridge` tool dropped | **41.5 ms** (362.4 → 320.9) | netns→relay −39.9 ms; two fewer forks per create |
| **total** | **344.7 ms** (665.6 → 320.9, −51.8 %) | added-over-direct 615.0 → 263.0 ms (−57.2 %) |

The item-2 assignment is the difference between the item-1-only and items-1+2 builds; netns→relay
in those two runs differs by +9.8 ms of run jitter, so the measured 60.6 ms total includes that
noise. The relay→app component it removes (77 ms) is the stable part.

### CPU / RSS impact (6 launches per binary, `/proc` deltas)

| | appd CPU/launch | core CPU/launch | appd RSS high-water | core RSS high-water |
|---|---|---|---|---|
| qualified `f82adf9` | 56.7 ms | 20.0 ms | 2 928 kB | 3 156 kB |
| final `0d947df` | **28.3 ms** | **10.0 ms** | 2 944 kB | 3 148 kB |

The helper does half the CPU work per launch (fewer child processes); memory is unchanged
(within 0.5 %).

## Item 3 — investigated and rejected

The post-Launch `refresh_apps()` round trip is the only remaining candidate in the measured list.
Raw round-trip measurement on the installed helper (`perf-appd-ipc.py`, 300 samples):

| round trip | p10 | median | p90 |
|---|---|---|---|
| connect + hello | 1.497 ms | **2.502 ms** | 4.211 ms |
| connect + hello + `report_registry` | 3.388 ms | **5.179 ms** | 7.881 ms |

Folding the report into `AppResponse::Launched` would save the full ~5.2 ms round trip (the verb
itself is ~2.7 ms). That is ~1.6 % of the 321 ms launch and below the run-to-run spread
(288–603 ms). It would require changing the wire type and bumping `APP_PROTOCOL_VERSION` to a
hard failure, for a saving the profiler cannot resolve. Rejected: not the smallest justified
change, and the fresh helper report stays authoritative. A variant that reuses the Launch
connection for the report (no wire change) saves only connect+hello (~2.5 ms) and was rejected for
the same reason.

## Regression results (final candidate)

| suite | result |
|---|---|
| `cargo test -p ghostnector-appd --lib` | 34 passed / 0 failed (incl. new batch-order tests) |
| `cargo clippy -p ghostnector-appd --all-targets -D warnings` | clean |
| `appd-socket-test.sh` | **PASS**, including the new `[8b]` dead-relay case (fails in 131 ms, no namespace, no registry entry) and the existing `bridge -d link show … isolated on` assertion |
| `core-app-test.sh` | **PASS** |
| `app-adversarial.sh` | **13 held / 0 contradicted / 0 inconclusive** |

## Security / anonymity statement

No anonymity, isolation, fail-closed, or least-privilege property changed.

- The kernel objects and their order are unchanged: namespace → link → enslave → **isolate** →
  up; the default route still terminates on the dead end; the namespace policy is still applied
  before the relay starts (D-50).
- `bridge_present`, `group_present` and the shape check answer the same question as before
  (`/sys/class/net/<name>` is the same predicate as `ip link show dev <name>`).
- The PC-08 effective-policy comparison is untouched.
- The relay's SOCKS/`IsolateSOCKSAuth` path, refusal of connections without an original
  destination, and the DNS chokepoint are untouched.
- `ip -batch` uses no shell; `-force` is used only for idempotent teardown. The `bridge` binary is
  no longer executed, so the helper's verified-tool surface shrank by one.

## Commits

| commit | change |
|---|---|
| `012e9c0` | `perf(appd)`: one `ip` transaction per namespace phase, `/sys` presence probes |
| `6a53d20` | `perf(appd)`: relay readiness waits on the relay, not on a fixed 100 ms tick |
| `0d947df` | `perf(appd)`: fold bridge isolation into the `ip` batch; drop the `bridge` tool |
| (this record) | profiler timestamp-over-stdout, helper-IPC and launch-CPU measurement scripts, records |

## Remaining floor

On this VM the fixed costs that remain are ~4 process spawns in the namespace phase plus the
relay spawn (~14 ms each), the PC-08 `nft list`, the launcher spawn, and the CLI/core control
plane. The final measured median is **320.9 ms** (versus a ~50 ms direct launch); no further
safe, measurable reduction was found that does not add concurrency or change the architecture.
