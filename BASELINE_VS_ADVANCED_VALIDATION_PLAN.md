# Implementation Plan: Baseline vs. Advanced (Coordinated) Validation

> **UPDATE — required changes after the THROTTLE ladder implementation.** This plan was written before `agents/rca.py` had the THROTTLE→BLOCK/QUARANTINE escalation ladder (FR-13; see `THROTTLE_PLAN_IMPLEMENTATION.md`). "Advanced" RCA is no longer just "votes before quarantine" — it now also has a 2-tier proportional ladder, and non-quarantine actions already resolve immediately with no vote *in current advanced-mode code*, not only in a hypothetical naive mode. That breaks a few of this plan's original assumptions. Specific fixes are marked inline below with **[POST-THROTTLE]**; the short version:
> 1. The `naive_voting` flag's behavior must change — see §1 and §2.1.
> 2. Reuse the already-built `_execute_immediate()` method; don't build a new `_resolve_immediate()`.
> 3. Decide explicitly whether `naive_voting` also disables the ladder itself (see §2.1) — this dimension didn't exist when this plan was first written.
> 4. Any "current numbers" referenced here or sanity-checked against must be the **post-THROTTLE** measured values (S1 SW 0.900, scenario-suite availability 100%, system-level SW 0.9624), not the pre-THROTTLE figures in `Validation_Report_ARMOR_v4`, which has not been regenerated yet.

**Purpose:** Fill in the "UNCHECKED" columns in Validation Report §3.1 (Baseline vs. Advanced Strategy) and turn §3.2 (Coordination Mechanism Contribution) from narrative into measured deltas, without touching detection logic (TMA/ACA) — only the coordination layer (TIA, RCA voting, RAA auction) is varied.

Scope: `backend/agents/rca.py`, `backend/agents/raa.py`, `backend/agents/tia.py`, plus new files under `backend/validation/`. No production behavior changes — all naive-mode logic is opt-in via a constructor flag, defaulting to current (advanced) behavior.

---

## 1. Definitions

**Advanced (current) MAS** — TIA correlates cross-segment threats and votes in coalitions; RCA runs a THROTTLE→BLOCK/QUARANTINE proportional escalation ladder and only initiates a 300 ms coalition vote for the top-tier action (QUARANTINE_SEGMENT) — every other tier (THROTTLE_SEGMENT/THROTTLE_SOURCE_IP/BLOCK_SOURCE_IP/LOG_ONLY) already resolves immediately with no vote, in current advanced-mode code, via `_execute_immediate()`. RAA runs sealed-bid priority allocation with eviction, including a THROTTLE resource pool. **[POST-THROTTLE: this whole paragraph replaces the pre-THROTTLE description — "advanced = always votes" is no longer true; only the top ladder rung votes.]**

**Baseline (naive)** — the "traditional, uncoordinated IDS/IPS" control: each segment's RCA acts alone and immediately, no cross-segment correlation exists, and resources are granted first-come-first-served with no priority preemption. TMA and ACA are byte-for-byte identical in both modes — detection/classification is not part of what's being ablated.

Three independent toggles map 1:1 to the three coordination mechanisms named in SDD §4:

| Flag | Off (naive) behavior | On (current/advanced) behavior |
|---|---|---|
| `RCA(naive_voting=True)` | **[POST-THROTTLE, changed]** Every incident — including ones that would reach the top ladder rung (QUARANTINE) — resolves via `_execute_immediate()`, i.e. the `if action in VOTED_ACTIONS` branch is forced to always take the `_execute_immediate()` path, never `_call_vote()`. The ladder itself (THROTTLE→QUARANTINE tier selection) still runs — see decision below. | `_select_action()` chooses the tier as normal; only `QUARANTINE_SEGMENT` (`VOTED_ACTIONS`) goes through `_call_vote()` → publish CFP → wait `VOTE_WINDOW` → tally. Everything else already goes through `_execute_immediate()` today, naive or not. |
| `TIA` instantiated? | Not started — no coalition/cross-segment correlation possible, and no `bypass=True` top-tier skip available either (that bypass only exists via TIA's `_on_threat_intel` path) | Started — publishes `threat-intel`, votes on CFPs, and its corroborated reports skip straight to the top ladder rung |
| `RAA(naive_auction=True)` | Grant if capacity free, else deny outright (no bid comparison, no eviction) — applies uniformly across all four resource pools (`FIREWALL`/`QUARANTINE`/`THROTTLE`/`LOG`) since the capacity dict is now keyed generically | Sealed-bid: evict weakest allocation if outbid |

**[POST-THROTTLE, new decision needed]** Should `naive_voting` also disable the escalation ladder itself (i.e. force every DDoS/PORT_SCAN incident straight to its top tier, mimicking the flat pre-THROTTLE `ACTIONS` mapping), or keep the ladder and only remove the vote? Recommend **keeping the ladder** for this 3-flag "coordination-only" ablation — the point of this comparison is to isolate coordination mechanisms (voting/coalition/auction) from proportionality, which is a separate, already-implemented improvement. A *different*, broader "fully naive/traditional IDS" baseline (the one discussed for Validation Report §3.1's top-level table, where TMA/ACA are also weakened) would need a 4th flag, e.g. `naive_ladder=True`, that skips `_select_action()`'s escalation logic and always picks the top tier immediately — that's a distinct experiment from this one and should not be conflated with it.

Running all three (now: voting, TIA, auction) off = full coordination-only baseline. Running them off one at a time = the ablation matrix for §3.2.

---

## 2. Code changes (agents)

### 2.1 `agents/rca.py`  **[POST-THROTTLE: rewritten — do not follow the old version of this section]**
- Add `naive_voting: bool = False` to `__init__`.
- In `_deliberate()` and `_on_threat_intel()`, the existing branch is:
  ```python
  if action in VOTED_ACTIONS:
      await self._call_vote(incident)
  else:
      await self._execute_immediate(incident)
  ```
  When `naive_voting` is True, force this to always take the `_execute_immediate()` branch, e.g. `if action in VOTED_ACTIONS and not self.naive_voting:`. **Do not** write a new `_resolve_immediate()` method — `_execute_immediate()` already does exactly what this plan originally asked for (self-approved, `votes_accept=1`/`votes_reject=0`, no `asyncio.sleep`, ~0 ms `duration_ms`) and was built during the THROTTLE work for a different reason (non-quarantine tiers). Reusing it means naive-mode QUARANTINE incidents get the same `EXECUTED` resolution shape as any other tier, just without ever publishing a CFP or waiting `VOTE_WINDOW`.
- `_select_action()` (the ladder) still runs unchanged in naive mode — this ablation only removes the *voting gate*, not the *proportionality logic*. See the "new decision needed" note in §1 if a ladder-free baseline is also wanted.
- No change to `_on_vote` (unused in naive mode since no CFP is ever published).

### 2.2 `agents/raa.py`
- Add `naive_auction: bool = False` to `__init__`.
- In `_allocate()`: when `naive_auction` is True, replace the "find weakest / evict if outbid" branch with a straight `if len(current) < capacity: grant else deny` — no `bid_value` comparison, no eviction. Keep `_grant`/`_deny`/`_enforce` untouched so enforcement side-effects (blocked_ips, quarantined_segments) stay identical for metrics that depend on them.

### 2.3 `agents/tia.py`
- No code change needed. Baseline runs simply never construct/start a TIA instance — this is the cleanest way to structurally remove cross-segment correlation and coalition triggering, and it matches how `validate_scenarios.py` already conditionally includes/excludes agents per scenario (e.g., Scenario 4 has no RCA/RAA/TIA at all).

### 2.4 `agents/base.py`
- No change.

All three flags default to `False`/instantiated, so existing `validate_*.py` suites keep passing unmodified — this is purely additive.

---

## 3. New validation harness files

### 3.1 `backend/validation/validate_baseline.py`
Structural mirror of `validate_scenarios.py`: same `_make_system(seed)`, same attacker classes/intensities/durations/seeds per scenario. Only difference: agents constructed with `RCA(..., naive_voting=True)`, `RAA(..., naive_auction=True)`, and TIA omitted entirely. Produces the same `ValidationSuite` shape (reuses `helpers.ValidationSuite`) so its output is structurally comparable to the advanced suite.

Only scenarios where coordination changes anything are worth including: **S2** (coalition — should show the biggest gap since baseline has no cross-segment correlation at all), **S3** (auction — resource contention behavior diverges), **S6** (voting — MTTR should drop but with reduced safety).

**[POST-THROTTLE, correction]** S1 was originally described as "a control — should barely move." That's no longer accurate for the `naive_voting` ablation specifically: since advanced-mode S1 now resolves most single-segment DDoS incidents via `THROTTLE_SEGMENT` (with escalation to `QUARANTINE_SEGMENT` only if the attack persists), while naive mode (voting forced off, ladder still active per §1/§2.1) still reaches the same tiers but skips the vote wait on the top rung — the two modes should track fairly closely on *which* action fires, but should still diverge on quarantine-vote *timing* whenever escalation occurs. If a `naive_ladder` flag is later added (§1, broader baseline), S1 becomes the *clearest* single-incident demonstration of the ladder's benefit (fewer unnecessary quarantines → higher availability), since it has no coalition/auction complexity to confound the reading — keep it in the comparison table, not as a "barely moves" control but as the simplest case to sanity-check the ladder's effect in isolation.

S4 (zero-day) is a detection-only control and should be near-identical in both modes; including it is a good sanity check that the ablation is clean. S5 (agent failure/resilience) is optional — arguably a 4th coordination mechanism (backup registration), worth a separate note rather than folding into this table.

### 3.2 `backend/validation/validate_ablation.py`
Runs the 2×2×2 factorial (voting on/off × auction on/off × coalition on/off) — or, more practically, the 5-row reduced matrix already sketched in the chat: baseline (all off), +voting only, +auction only, +coalition only, full MAS (all on). Reuses the same scenario bodies as a parameterized function `run_scenario(seed, *, naive_voting, naive_auction, use_tia)` rather than duplicating scenario code across three files — refactor `validate_scenarios.py`'s per-scenario blocks into callables first (see §5, risk note).

### 3.3 `backend/validation/validate_comparison.py`
Driver script that:
1. Runs `validate_baseline.run()` and `validate_scenarios.run()` (or the refactored equivalents) across N seeds each (recommend N=8, matching the existing `seed=2026` reproducibility convention but varied per repetition, e.g. `2026 + i`).
2. Aggregates per-metric mean ± std per scenario per mode (DR, FPR, MTTR_Response, Availability, SW, U_ATK).
3. Computes Δ = Advanced − Baseline per metric per scenario.
4. Emits two artifacts:
   - `validation/baseline_vs_advanced.json` — machine-readable, mirrors the `suite.set_metrics()` pattern already used in `validate_scenarios.py` and `validate_system.py`.
   - A printed table matching the exact row/column layout of Validation Report §3.1, so it can be pasted straight in.

---

## 4. Metrics to capture identically in both modes

Reuse the exact computations already present in `validate_scenarios.py` per scenario (detected counts, `s*_mttr_ms`, `availability*`, `evasion*`, `u_atk_*`, `_sw(...)`) — don't invent new formulas for baseline; the whole point is the same yardstick. The only new derived value is `Δ = advanced.metric - baseline.metric` per row of §3.1's table.

---

## 5. Risks / design decisions to flag before implementation

- **Refactor risk:** `validate_scenarios.py`'s scenario bodies are currently inline in `run()`, not standalone functions. Reusing them for both baseline and ablation runs means either (a) extracting each scenario into a `run_scenario_N(seed, **agent_flags)` function first (clean, ~30 min, touches an existing/working validated file — regression-test after), or (b) duplicating the scenario body into `validate_baseline.py` (faster, zero regression risk, but drifts over time if scenario logic changes). Recommend (b) first for the initial comparison, (a) later if the ablation matrix (§3.2) is pursued, since duplicating 5 variants of the same scenario is unmaintainable.
- **Voting is currently single-voter in most scenarios:** RCA casts its own ACCEPT and, with no coalition peer present, always passes (`votes_accept=1 > votes_reject=0`) even in advanced mode today. So "naive_voting=False" in a scenario with no TIA/peer voter isn't really testing consensus — only the 300 ms delay. Flag this explicitly in the report as a limitation, or add a second voting participant (TIA already votes on CFPs in `_on_cfp` — S2/S6 with TIA present already exercise this correctly; S1/S3 without TIA do not).
- **RAA bid_value in naive mode is unused** — confirm the report doesn't accidentally cite `bid_value` figures from naive runs as if priority ordering was evaluated.
- **Seed variance:** report mean±std across the N seeds, not single-run points, for both baseline and advanced — a single lucky/unlucky seed could overstate Δ. **[POST-THROTTLE: the specific swing this bullet originally cited (S1 SW 0.765 vs. system-level 0.858) is stale — those were pre-THROTTLE numbers.** Post-THROTTLE, S1 SW is 0.900 and system-level SW is 0.9624 in the single runs measured so far; re-measure actual variance across seeds before quoting any specific numbers in the report, don't reuse the old pair.]
- **[POST-THROTTLE, new]** Decide the §1 `naive_ladder` question (keep vs. disable the escalation ladder in naive mode) *before* writing `validate_baseline.py` — it changes what `_select_action()` does in naive mode and therefore changes every downstream metric. Don't discover this mid-implementation.

---

## 6. Sequencing

1. Add the three opt-in flags to `rca.py` / `raa.py` per the corrected §2.1 (`naive_voting` forces the `_execute_immediate()` branch unconditionally; ladder stays active) — non-breaking; run full existing `validate_*.py` suite to confirm zero regressions.
2. Write `validate_baseline.py` (duplicate scenario bodies, per §5 decision (b)).
3. Run baseline once at seed=2026 (matching current report's convention) and sanity-check output shape against the advanced suite's **current, post-THROTTLE** numbers (S1 SW ≈0.900, S2 SW ≈0.880, system-level SW ≈0.9624 — not the pre-THROTTLE figures still printed in `Validation_Report_ARMOR_v4`, which hasn't been regenerated).
4. Write `validate_comparison.py`, run N=8 seeds both modes, produce `baseline_vs_advanced.json` + printed §3.1 table.
5. (Optional, if time permits) Build `validate_ablation.py` for the 5-row §3.2 matrix.
6. Update `Validation_Report_ARMOR_v4` §3.1 and §3.2 with real numbers, replacing "UNCHECKED", and add a short methodology paragraph (seeds used, N repetitions, what was/wasn't varied) so the comparison is reproducible.

---

## 7. Estimated effort

Steps 1–4 (core baseline vs. advanced comparison, single scenario set, N-seed repetition): the minimum viable version that actually fills §3.1. Step 5 (full ablation matrix) is additive scope for §3.2 depth. Step 6 is report editing once numbers exist.
