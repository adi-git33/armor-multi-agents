# Implementation Plan: Baseline vs. Advanced (Coordinated) Validation

**Purpose:** Fill in the "UNCHECKED" columns in Validation Report §3.1 (Baseline vs. Advanced Strategy) and turn §3.2 (Coordination Mechanism Contribution) from narrative into measured deltas, without touching detection logic (TMA/ACA) — only the coordination layer (TIA, RCA voting, RAA auction) is varied.

Scope: `backend/agents/rca.py`, `backend/agents/raa.py`, `backend/agents/tia.py`, plus new files under `backend/validation/`. No production behavior changes — all naive-mode logic is opt-in via a constructor flag, defaulting to current (advanced) behavior.

---

## 1. Definitions

**Advanced (current) MAS** — TIA correlates cross-segment threats and votes in coalitions; RCA runs a 300 ms coalition vote before quarantine; RAA runs sealed-bid priority allocation with eviction.

**Baseline (naive)** — the "traditional, uncoordinated IDS/IPS" control: each segment's RCA acts alone and immediately, no cross-segment correlation exists, and resources are granted first-come-first-served with no priority preemption. TMA and ACA are byte-for-byte identical in both modes — detection/classification is not part of what's being ablated.

Three independent toggles map 1:1 to the three coordination mechanisms named in SDD §4:

| Flag | Off (naive) behavior | On (current/advanced) behavior |
|---|---|---|
| `RCA(naive_voting=True)` | Resolve immediately on deliberation, no CFP, no 300 ms wait | Publish CFP, wait `VOTE_WINDOW`, tally votes |
| `TIA` instantiated? | Not started — no coalition/cross-segment correlation possible | Started — publishes `threat-intel`, votes on CFPs |
| `RAA(naive_auction=True)` | Grant if capacity free, else deny outright (no bid comparison, no eviction) | Sealed-bid: evict weakest allocation if outbid |

Running all three off = full baseline. Running them off one at a time = the ablation matrix for §3.2.

---

## 2. Code changes (agents)

### 2.1 `agents/rca.py`
- Add `naive_voting: bool = False` to `__init__`.
- In `_deliberate()` and `_on_threat_intel()`: when `naive_voting` is True, skip `_call_vote()` and call a new `_resolve_immediate(incident)` instead — same `_resolve()` body, but `votes_accept=1, votes_reject=0` set synchronously with no `asyncio.sleep(VOTE_WINDOW)`. This preserves proportional action selection (`ACTIONS` mapping) so THROTTLE/BLOCK/QUARANTINE logic isn't itself part of the ablation.
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

Only scenarios where coordination changes anything are worth including: **S1** (control — should barely move), **S2** (coalition — should show the biggest gap since baseline has no cross-segment correlation at all), **S3** (auction — resource contention behavior diverges), **S6** (voting — MTTR should drop but with reduced safety). S4 (zero-day) is a detection-only control and should be near-identical in both modes; including it is a good sanity check that the ablation is clean. S5 (agent failure/resilience) is optional — arguably a 4th coordination mechanism (backup registration), worth a separate note rather than folding into this table.

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
- **Seed variance:** given already-documented run-to-run swings (S1 SW 0.765 vs. system-level 0.858), report mean±std across the N seeds, not single-run points, for both baseline and advanced — a single lucky/unlucky seed could overstate Δ.

---

## 6. Sequencing

1. Add the three opt-in flags to `rca.py` / `raa.py` (non-breaking; run full existing `validate_*.py` suite to confirm zero regressions).
2. Write `validate_baseline.py` (duplicate scenario bodies, per §5 decision (b)).
3. Run baseline once at seed=2026 (matching current report's convention) and sanity-check output shape against the advanced suite's existing numbers.
4. Write `validate_comparison.py`, run N=8 seeds both modes, produce `baseline_vs_advanced.json` + printed §3.1 table.
5. (Optional, if time permits) Build `validate_ablation.py` for the 5-row §3.2 matrix.
6. Update `Validation_Report_ARMOR_v4` §3.1 and §3.2 with real numbers, replacing "UNCHECKED", and add a short methodology paragraph (seeds used, N repetitions, what was/wasn't varied) so the comparison is reproducible.

---

## 7. Estimated effort

Steps 1–4 (core baseline vs. advanced comparison, single scenario set, N-seed repetition): the minimum viable version that actually fills §3.1. Step 5 (full ablation matrix) is additive scope for §3.2 depth. Step 6 is report editing once numbers exist.
