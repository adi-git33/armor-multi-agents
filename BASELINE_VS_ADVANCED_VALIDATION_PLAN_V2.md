# Implementation Plan v2: Baseline vs. Advanced Validation

**Supersedes `BASELINE_VS_ADVANCED_VALIDATION_PLAN.md` (v1).** v1 was written before the THROTTLE escalation ladder existed and was later patched in place with inline `[POST-THROTTLE]` corrections — that file is now a readable record of *what changed and why*, but is no longer the document to implement from. This is a clean rewrite against the current code, with the open questions v1 left unresolved (the ladder's role in "naive" mode) decided rather than flagged. Nothing in this plan has been implemented yet.

---

## 1. Purpose

Fill in the "UNCHECKED" columns in `Validation_Report_ARMOR_v4` §3.1 (Baseline vs. Advanced Strategy) and turn §3.2 (Coordination Mechanism Contribution) from narrative into measured deltas — by running the same scenarios twice, once with the MAS's coordination/proportionality mechanisms active (current code) and once with each mechanism individually or collectively disabled.

Scope: `backend/agents/rca.py`, `backend/agents/raa.py`, plus new files under `backend/validation/`. TMA and ACA are not touched — detection/classification stays identical in every mode, so any measured Δ is attributable only to the four mechanisms below, not to detection quality. (A broader comparison that also weakens TMA/ACA — a "traditional non-adaptive IDS" straw man — was discussed separately and is out of scope here; it would double-count effects and make Δ harder to attribute. Keep it as a distinct, later experiment if wanted.)

---

## 2. What "advanced" actually does today

Four coordination/proportionality mechanisms exist in the current code, corresponding to SDD §4.1–4.4:

| Mechanism | SDD ref | Where it lives | Current (advanced) behavior |
|---|---|---|---|
| Proportional response selection | §4.1 | `rca.py` `_select_action()` | 2-tier ladder per classification (`ESCALATION_ACTIONS`): DDOS → `THROTTLE_SEGMENT` then `QUARANTINE_SEGMENT`; PORT_SCAN → `THROTTLE_SOURCE_IP` then `BLOCK_SOURCE_IP`. Escalates one level only if a same-segment/classification report recurs within `ESCALATION_WINDOW` (8s) and isn't weaker than the last one. |
| Voting-based escalation | §4.4 | `rca.py` `_call_vote()` / `_execute_immediate()` | Only the top ladder rung (`QUARANTINE_SEGMENT`, the sole member of `VOTED_ACTIONS`) goes through a coalition vote (publish CFP, wait `VOTE_WINDOW`=0.3s, tally). Every other action — `THROTTLE_SEGMENT`, `THROTTLE_SOURCE_IP`, `BLOCK_SOURCE_IP`, `LOG_ONLY` — already resolves immediately via `_execute_immediate()`, no vote, in current code. |
| Coalition formation | §4.3 | `tia.py`, subscribed by `rca.py` `_on_threat_intel()` | TIA correlates threat reports across 2+ segments and publishes `threat-intel`; RCA's `_on_threat_intel` handler treats this as a `bypass=True` case in `_select_action()`, skipping straight to the top ladder rung regardless of confidence. |
| Auction-based resource allocation | §4.2 | `raa.py` `_allocate()` | Sealed-bid: grant if capacity free; if full, evict the weakest existing allocation only if the incoming bid (`confidence × vote_ratio`) beats it, else deny. Four resource pools now: `FIREWALL` (3), `QUARANTINE` (2), `THROTTLE` (10, deliberately generous), `LOG` (unlimited). |

"Baseline / naive" = a traditional, uncoordinated IDS/IPS control where each of these four is switched off independently or together. TMA and ACA behavior is unchanged in every mode.

---

## 3. The four flags

| Flag | Naive (off) behavior | Advanced (on, current default) behavior |
|---|---|---|
| `RCA(naive_ladder=True)` | Every DDoS/PORT_SCAN incident jumps straight to its ladder's top tier on the first report — no escalation wait, no "did the lower tier fail" check. Reproduces the pre-THROTTLE flat behavior (DDoS → `QUARANTINE_SEGMENT` immediately, PORT_SCAN → `BLOCK_SOURCE_IP` immediately). | `_select_action()` runs the real 2-tier escalation logic described above. |
| `RCA(naive_voting=True)` | Even an incident that reaches `QUARANTINE_SEGMENT` resolves via `_execute_immediate()` — no CFP, no `VOTE_WINDOW` wait, self-approved. | Only `QUARANTINE_SEGMENT` goes through `_call_vote()`; everything else already skips voting today regardless of this flag. |
| `TIA` instantiated? | Not constructed/started at all — no cross-segment correlation, no `bypass=True` shortcut is ever reachable. | Started; publishes `threat-intel`; corroborated reports bypass the ladder (equivalent to always landing at the top tier for that specific incident, same effect as `naive_ladder=False` would deny). |
| `RAA(naive_auction=True)` | `_allocate()` becomes `if len(current) < capacity: grant else: deny` — no bid comparison, no eviction. Applies uniformly across all four resource pools since `RESOURCE_CAPACITY`/`RESOURCE_MAP` are generic dicts. | Sealed-bid priority allocation with eviction, as in §2. |

These four flags are independent and map 1:1 onto SDD §4.1–4.4. **Full baseline** = all four naive. **Full advanced** = all four off (today's default, zero behavior change — every flag defaults to `False`/instantiated).

---

## 4. Code changes

### 4.1 `agents/rca.py`

Add two constructor flags:
```python
def __init__(self, agent_id: str, bus: MessageBus,
             naive_ladder: bool = False, naive_voting: bool = False) -> None:
    ...
    self.naive_ladder = naive_ladder
    self.naive_voting = naive_voting
```

**`_select_action()`** — one-line change. Current:
```python
if bypass:
    level = len(ladder) - 1
```
Becomes:
```python
if bypass or self.naive_ladder:
    level = len(ladder) - 1
```
`naive_ladder=True` behaves exactly like a permanent TIA-style bypass: every incident lands at the top tier immediately, and `_mitigation_state` still gets recorded (harmless — there's nothing to escalate to). This is the minimal-diff way to reproduce the old flat behavior without duplicating the ladder logic.

**Vote gating** — appears in both `_deliberate()` and `_on_threat_intel()`. Current:
```python
if action in VOTED_ACTIONS:
    await self._call_vote(incident)
else:
    await self._execute_immediate(incident)
```
Becomes (same change in both places):
```python
if action in VOTED_ACTIONS and not self.naive_voting:
    await self._call_vote(incident)
else:
    await self._execute_immediate(incident)
```

No other changes. `_execute_immediate()`, `_call_vote()`, `_resolve()`, `_build_enforcement_target()`, `_at_max_level()` are all reused unmodified.

### 4.2 `agents/raa.py`

```python
def __init__(self, agent_id: str, bus: MessageBus, naive_auction: bool = False) -> None:
    ...
    self.naive_auction = naive_auction
```

**`_allocate()`** — current:
```python
async def _allocate(self, request: Allocation) -> None:
    rtype    = request.resource_type
    capacity = RESOURCE_CAPACITY[rtype]
    current  = self._allocations[rtype]

    if len(current) < capacity:
        await self._grant(request)
        return

    weakest = min(current, key=lambda a: a.bid_value)
    if request.bid_value > weakest.bid_value:
        await self._evict(weakest, reason=...)
        await self._grant(request)
    else:
        await self._deny(request, reason=...)
```
Becomes:
```python
async def _allocate(self, request: Allocation) -> None:
    rtype    = request.resource_type
    capacity = RESOURCE_CAPACITY[rtype]
    current  = self._allocations[rtype]

    if len(current) < capacity:
        await self._grant(request)
        return

    if self.naive_auction:
        await self._deny(request, reason=f"at capacity ({len(current)}/{capacity}); naive FCFS, no eviction")
        return

    weakest = min(current, key=lambda a: a.bid_value)
    if request.bid_value > weakest.bid_value:
        await self._evict(weakest, reason=...)
        await self._grant(request)
    else:
        await self._deny(request, reason=...)
```
`_grant`/`_deny`/`_enforce` untouched — enforcement side effects (`blocked_ips`, `quarantined_segments`, `throttled`) stay identical so metrics that depend on them (availability, etc.) are computed the same way in both modes.

### 4.3 `agents/tia.py`

No code change. Baseline runs simply don't construct/start a `ThreatIntelligenceAgent` — matches how `validate_scenarios.py` already conditionally includes/excludes agents per scenario (e.g. Scenario 4 has no RCA/RAA/TIA at all).

All flags default to off/instantiated, so every existing `validate_*.py` suite keeps passing unmodified — purely additive.

---

## 5. New validation harness files

### 5.1 `backend/validation/validate_baseline.py`
Structural mirror of `validate_scenarios.py`: identical `_make_system(seed)`, identical attacker classes/intensities/durations/seeds per scenario. Only difference: agents constructed with all four flags naive (`RCA(naive_ladder=True, naive_voting=True)`, `RAA(naive_auction=True)`, TIA omitted). Reuses `helpers.ValidationSuite` so output is structurally comparable to the advanced suite.

Scenario coverage:
- **S1** (single-segment DDoS) — the cleanest single-incident demonstration of the ladder specifically, no coalition/auction complexity to confound the reading. Expect the biggest availability/SW gap here between naive (`naive_ladder=True` → always jumps to QUARANTINE) and advanced (THROTTLE first).
- **S2** (multi-segment) — biggest gap from disabling TIA: naive has no cross-segment correlation at all.
- **S3** (resource contention) — auction behavior diverges (FCFS vs. priority+eviction).
- **S6** (voting protocol) — `naive_voting` removes the vote wait entirely; MTTR should drop but with no safety check before quarantine.
- **S4** (zero-day) — detection-only control; should be near-identical in both modes. Include it as a sanity check that the ablation is clean — if S4 differs meaningfully, something is leaking into the "coordination-only" boundary.
- **S5** (agent failure/resilience) — optional; arguably a 5th mechanism (backup registration) not covered by these four flags. Note separately rather than folding into this table.

### 5.2 `backend/validation/validate_ablation.py`

With 4 independent flags there are 16 possible combinations — impractical and unnecessary. Use a one-at-a-time (OFAT) sweep instead, matching the SDD's own four-mechanism structure (§4.1–4.4): start from full baseline, flip on one mechanism at a time, end at full advanced.

| Row | `naive_ladder` | `naive_voting` | TIA started | `naive_auction` | Isolates |
|---|---|---|---|---|---|
| Full baseline | naive | naive | off | naive | — (reference floor) |
| + proportionality | **off** | naive | off | naive | §4.1 marginal effect |
| + voting | naive | **off** | off | naive | §4.4 marginal effect |
| + coalition | naive | naive | **on** | naive | §4.3 marginal effect |
| + auction | naive | naive | off | **off** | §4.2 marginal effect |
| Full advanced | off | off | on | off | — (reference ceiling) |

6 rows, not 16 — each single-mechanism row differs from the baseline row by exactly one flag, so its Δ is directly attributable. Iterate only over `OFAT_SCENARIOS` (§5.4) — S4/S5 excluded by construction. Implement as a parameterized `run_scenario_N(seed, *, naive_ladder, naive_voting, use_tia, naive_auction)` per §5.4, extracted from `validate_scenarios.py`'s per-scenario bodies rather than copy-pasting six variants.

### 5.3 `backend/validation/validate_comparison.py`
Driver script:
1. Run `validate_baseline.run()` and `validate_scenarios.run()` (or the OFAT variants) across N seeds each (recommend N=8, seeds `2026 + i` for i in 0..7, keeping the existing `seed=2026` convention as one data point among the eight).
2. Aggregate per-metric mean ± std per scenario per mode (DR, FPR, MTTR_Response, Availability, SW, U_ATK).
3. Compute Δ = Advanced − Baseline per metric per scenario/row.
4. Emit:
   - `validation/baseline_vs_advanced.json` — machine-readable, mirroring the `suite.set_metrics()` pattern already used in `validate_scenarios.py`/`validate_system.py`.
   - A printed table matching Validation Report §3.1's row/column layout (for the two-row baseline/advanced comparison) and a second table matching the OFAT layout above (for §3.2).

### 5.4 Shared harness helpers (resolve §7's structural risks)

These four helpers are what make §7's fixes concrete rather than just documented caveats:

**`ScenarioResult` + pure `run_scenario_N()` callables.** Decouple *measurement* from *assertion*. Each extracted function returns raw numbers only:
```python
@dataclass
class ScenarioResult:
    detected: int
    mttr_ms: float | None
    availability: float
    sw: float
    u_atk: float | None
    extra: dict = field(default_factory=dict)   # scenario-specific fields

async def run_scenario_1(seed: int, *, naive_ladder=False, naive_voting=False,
                          use_tia=True, naive_auction=False) -> ScenarioResult:
    ...
```
`validate_scenarios.py`'s `run()` calls `run_scenario_1(seed=110)` (advanced defaults) and layers `suite.check(...)` on the returned `ScenarioResult` — same PASS/FAIL behavior as today. `validate_baseline.py` and `validate_ablation.py` call the same function with different flags and only collect `ScenarioResult`s into a table, no assertions needed. Extract **one scenario at a time**, and after each extraction diff the printed numeric values against the pre-refactor run — exact equality, not just "still passes" (passing thresholds by luck would hide a bug the refactor introduced).

**Peer-voter stub** (fixes single-voter risk). A minimal function, defined in the validation harness only — not a new production agent:
```python
async def _peer_accept_voter(bus: MessageBus) -> None:
    async def _on_cfp(msg: Message) -> None:
        await bus.publish(Message(topic=Topic.VOTES, performative=Performative.INFORM,
                                   content={"incident_id": msg.content["incident_id"], "vote": "ACCEPT"}))
    bus.subscribe(Topic.COALITION, _on_cfp)
```
Subscribed identically in **every** scenario/mode — naive and advanced, with or without TIA. Because it's uniform everywhere, it doesn't confound the TIA/coalition flag: S1/S3/S4/S5 now get a genuine 2-voter quorum (`votes_accept=2`) in every run, and the TIA on/off comparison still isolates exactly what TIA adds on top (real cross-segment correlation + intel bypass), not "the only vote that exists."

**`bid_value` N/A guard.** In the metrics-aggregation step of `validate_comparison.py`, gate the priority-ordering column:
```python
priority_ok = "N/A (FCFS, no priority evaluated)" if naive_auction else _check_priority_ordering(grants)
```
so a naive-mode row can never print a bid-comparison figure that looks like priority was tested.

**`OFAT_SCENARIOS` constant.** In `validate_ablation.py`:
```python
OFAT_SCENARIOS = (1, 2, 3, 6)          # four-mechanism ablation only
```
vs. `validate_baseline.py`'s
```python
BASELINE_SCENARIOS = (1, 2, 3, 4, 5, 6)  # includes S4/S5 as sanity-check controls
```
The exclusion is enforced by which constant the driver loop iterates over, not by a comment someone could miss.

**Seed-variance guards**, in `validate_comparison.py`:
```python
SEEDS = tuple(2026 + i for i in range(8))
assert len(SEEDS) >= 8, "N<8 seeds — not enough for a defensible mean±std"
```
Store per-seed raw values alongside the aggregate in `baseline_vs_advanced.json` (e.g. `"raw": {2026: 0.9012, 2027: 0.8975, ...}`), and stamp every emitted table/JSON with `"seeds": SEEDS` so any number pasted into the report is traceable back to the run that produced it — makes stale single-run figures easy to spot on sight.

---

## 6. Metrics

Reuse the exact computations already in `validate_scenarios.py` per scenario (`s*_mttr_ms`, `availability*`, `evasion*`, `u_atk_*`, `_sw(...)`, detected counts) — don't invent new formulas for baseline; the point is the same yardstick applied to both modes. The only new derived values are the per-row Δs.

---

## 7. Resolved decisions (previously "Risks / open decisions")

- **Refactor cost → resolved:** don't refactor for §5.1. Duplicate scenario bodies into `validate_baseline.py` as originally planned — zero regression risk to the validated file. For §5.2, extract `ScenarioResult` + `run_scenario_N()` pure-measurement callables (§5.4), one scenario at a time, with exact-value diffing against the pre-refactor run as the acceptance bar (not just PASS/FAIL parity).
- **Single-voter limitation → resolved:** add the uniform peer-voter stub (§5.4), subscribed in every scenario/mode regardless of TIA. Gives S1/S3/S4/S5 a genuine 2-voter quorum without confounding the TIA/coalition flag, so "voting Δ" is a real consensus test everywhere, not just S2/S6.
- **`RAA` bid_value in naive-auction mode → resolved:** the harness itself gates this now (§5.4 N/A guard) — naive rows print `"N/A (FCFS, no priority evaluated)"` instead of a number, so the report can't accidentally cite a bid comparison that never happened.
- **Seed variance → resolved:** `validate_comparison.py` asserts `N >= 8` and stores per-seed raw values plus the seed list in `baseline_vs_advanced.json` (§5.4), so every report figure is traceable to its run and stale single-seed numbers are visibly out of place.
- **S4/S5 as controls → resolved:** enforced in code via the `OFAT_SCENARIOS = (1, 2, 3, 6)` vs. `BASELINE_SCENARIOS = (1, 2, 3, 4, 5, 6)` constants (§5.4) — `validate_ablation.py` structurally cannot include S4/S5 regardless of what anyone remembers.

---

## 8. Sequencing

1. Add `naive_ladder`/`naive_voting` to `rca.py` (§4.1) and `naive_auction` to `raa.py` (§4.2). Run the full existing `validate_*.py` suite to confirm zero regressions (all flags default off).
2. Write `validate_baseline.py` (§5.1, duplicated scenario bodies). Run once at seed=2026, sanity-check output shape and rough magnitude against the current advanced suite's numbers.
3. Write `validate_comparison.py` (§5.3), run N=8 seeds both modes, produce `baseline_vs_advanced.json` + the §3.1 table.
4. Refactor `validate_scenarios.py` into callables, write `validate_ablation.py` (§5.2), run the 6-row OFAT sweep across N=8 seeds, produce the §3.2 table.
5. Update `Validation_Report_ARMOR_v4` §3.1 and §3.2 with the real numbers (replacing "UNCHECKED"), plus a short methodology paragraph: seeds used, N repetitions, which four flags exist and what each isolates, and an explicit note that TMA/ACA were held constant throughout.

---

## 9. Estimated effort

Steps 1–3: minimum viable version, fills §3.1 with a real baseline-vs-advanced Δ table. Step 4 is additive scope for §3.2's per-mechanism depth — the refactor is the expensive part, not the ablation runs themselves. Step 5 is report editing once numbers exist from steps 3–4.
