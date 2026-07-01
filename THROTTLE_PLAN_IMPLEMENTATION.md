# Implementation Plan: THROTTLE Escalation Ladder (Fixes FR-13)

> **STATUS: IMPLEMENTED AND VERIFIED (this session).** `agents/rca.py`, `agents/raa.py`, and `validation/validate_rca.py` were updated per this plan. Full regression run across all 7 validation suites: **FR-13 now fully passes** (was FAIL). Two deviations from the original plan were required, both found empirically rather than assumed — see "Deviations from plan, found during implementation" near the end of this document before reading the rest as if it were still a forward-looking design.

**Purpose:** Give the RCA a real least-disruptive-first policy — THROTTLE → BLOCK/QUARANTINE — instead of the current fixed classification→action map that sends every DDoS straight to QUARANTINE_SEGMENT. This is what the SDD §2.4.1 belief model already promises (`available_actions: type: THROTTLE|BLOCK|REDEPLOY|QUARANTINE`) and the RCA plan pseudocode already assumes ("select a proportional action based on the policy") but the code never implements.

Scope: `backend/agents/rca.py`, `backend/agents/raa.py`, `backend/validation/validate_rca.py`. No changes to TMA/ACA/TIA, no changes to the simulator's traffic generation — enforcement in this codebase is bookkeeping-only today (confirmed: `blocked_ips`/`quarantined_segments` sets are never read back by `TrafficGenerator`/`DDoSAttacker`), so "disruption" is measured purely from *which action type* fired, not from a simulated traffic-reduction effect. THROTTLE fits that same pattern — no simulator changes needed.

---

## 1. What "proportional" means here

A two-tier escalation ladder per classification, keyed by an escalation level that starts at 0 and only climbs if the lower tier visibly failed to stop the attack:

| Classification | Level 0 (first response) | Level 1 (escalation) | Rationale |
|---|---|---|---|
| DDOS | `THROTTLE_SEGMENT` | `QUARANTINE_SEGMENT` | Skip BLOCK for DDoS — FR-24 randomizes botnet source IPs, so blocking one IP is provably ineffective against this attack type. Throttle-then-quarantine is the only two-tier ladder that make sense for a distributed source. |
| PORT_SCAN | `THROTTLE_SOURCE_IP` | `BLOCK_SOURCE_IP` | Single, stable source IP (SDD 3.2.1) — throttle it first, only fully block if scanning continues. |
| NOISE | `LOG_ONLY` | *(no escalation)* | Unchanged. |

Only the top rung of each ladder (`QUARANTINE_SEGMENT`) is "high-risk" per SRS §6.4 — so only that action goes through the coalition vote. This also fixes a second, currently-undocumented bug: today `_deliberate()`/`_on_threat_intel()` call `_call_vote()` unconditionally for *every* classification, meaning even `LOG_ONLY`/`BLOCK_SOURCE_IP` currently pay the 300 ms vote tax. The SDD's own RCA pseudocode (`4.3.1 Respond To Threat`) says "if action == QUARANTINE → initiate_voting(); else → execute_action() immediately" — the code has never matched this. Fixing THROTTLE requires fixing this at the same time, since otherwise every escalation still costs 300 ms regardless of tier.

**Severity bypass (resolves the S6 conflict found below, §6):** a single report with `confidence >= CRITICAL_CONFIDENCE` (recommend `0.90`) skips straight to the top tier without waiting for a second corroborating alert. This mirrors the existing `HIGH_CONFIDENCE=0.85` bypass philosophy already in `_deliberate()` (a sufficiently unambiguous single report doesn't need corroboration) and is required for Scenario 6 to keep exercising the voting protocol — see §6.

---

## 2. `agents/rca.py` changes

**New constants**
- `ESCALATION_ACTIONS = {"DDOS": ["THROTTLE_SEGMENT", "QUARANTINE_SEGMENT"], "PORT_SCAN": ["THROTTLE_SOURCE_IP", "BLOCK_SOURCE_IP"], "NOISE": ["LOG_ONLY"]}` — replaces the flat `ACTIONS` dict as the source of truth (keep `ACTIONS` as a deprecated alias mapping to level-0 for anything importing it directly, e.g. `validate_rca.py` line 33).
- `ESCALATION_WINDOW = 8.0` (seconds) — **decided, not a placeholder**: it must be longer than TMA's own `ALERT_COOLDOWN` (5.0 s, `tma.py`), because that's the earliest a second `VOLUME_SPIKE` alert for the same segment can even be published — setting `ESCALATION_WINDOW` below 5.0 s would mean the window always closes before a legitimate second alert could arrive, and the ladder would never climb. 8.0 s gives ~3 s of ACA/RCA pipeline slack on top of TMA's cooldown, while staying well under `RESOLUTION_COOLDOWN` (30 s).
- `CRITICAL_CONFIDENCE = 0.90` — single-report bypass straight to the top tier (see severity-bypass note in §1).
- `VOTED_ACTIONS = {"QUARANTINE_SEGMENT"}` — the only tier requiring `_call_vote`.

**New belief state**
- `_mitigation_state: dict[str, dict]` per segment: `{"level": int, "classification": str, "action": str, "acted_at": float}` — replaces the binary `_cooldown` dict's role of "is this segment already handled" with a richer "at what tier, and when."

**Control-flow change in `_deliberate()` / `_on_threat_intel()`**
1. If `confidence >= CRITICAL_CONFIDENCE`: set `level = len(ladder) - 1` (top tier) immediately, skip steps 2-3 — this is the severity bypass.
2. Otherwise, look up `_mitigation_state.get(seg)`.
3. If none, or `now - acted_at > ESCALATION_WINDOW`, or classification changed to something less severe: start at level 0.
4. If an entry exists, `classification` matches (or is equal/worse), and `now - acted_at <= ESCALATION_WINDOW`: only escalate if the new report's `confidence`/`severity` is **not lower** than the value recorded at the last action (i.e., the attack hasn't visibly weakened) — bump `level = min(level + 1, len(ladder) - 1)`. If the new value is clearly lower, hold at the current level instead of escalating (see §6, escalation-trigger decision).
5. Look up `action = ESCALATION_ACTIONS[classification][level]`.
6. Replace the current blanket "cooldown → return" guard: instead of silently dropping reports during `RESOLUTION_COOLDOWN`, only suppress if the segment is *already at max level* (nothing higher to escalate to) — otherwise let it through to re-evaluate for escalation. This is the key behavioral change from today's code, where `RESOLUTION_COOLDOWN` unconditionally blocks re-evaluation for 30 s.
7. Build the `Incident` as today, but branch at vote time: `if action in VOTED_ACTIONS: await self._call_vote(incident)` else `await self._execute_immediate(incident)`.

**New method `_execute_immediate(incident)`**
Mirrors `_resolve()`'s EXECUTED branch exactly (build `enforcement_target`, publish to `Topic.RESOLUTION`, append to `self.resolutions`) but sets `votes_accept=1, votes_reject=0` synchronously with zero wait — no CFP is published, no coalition round-trip, `duration_ms ≈ 0`. This is what a THROTTLE/BLOCK "immediate mitigation" means per SDD pseudocode.

**Decay:** on successful resolution (whatever tier), record `acted_at`; if no further reports arrive for that segment within `RESOLUTION_COOLDOWN`, the next incident naturally starts fresh at level 0 (handled by the `now - acted_at > ESCALATION_WINDOW` reset condition above — `RESOLUTION_COOLDOWN` remains as the outer "fully forget this segment" boundary).

**Enforcement target:** extend the `if incident.action == "..."` chain in `_resolve()`/`_execute_immediate()` to add `THROTTLE_SEGMENT → {"segment": incident.segment}` and `THROTTLE_SOURCE_IP → {"src_ip": evidence.get("src_ip", "")}`.

---

## 3. `agents/raa.py` changes

- `RESOURCE_MAP`: add `"THROTTLE_SEGMENT": "THROTTLE"`, `"THROTTLE_SOURCE_IP": "THROTTLE"`.
- `RESOURCE_CAPACITY`: add `"THROTTLE": 10` (deliberately generous relative to `FIREWALL: 3` / `QUARANTINE: 2` — throttling is cheap/low-disruption, so it shouldn't contend the way scarce quarantine/firewall slots do; this also means THROTTLE requests essentially always grant, which is realistic and keeps the auction focused on the genuinely scarce resources).
- `_enforce()`: add a branch — `elif action in ("THROTTLE_SEGMENT", "THROTTLE_SOURCE_IP"): self.throttled.add(target.get("segment") or target.get("src_ip"))`.
- New belief set `self.throttled: set[str] = set()` in `__init__`, plus introspection helper `is_throttled(key: str) -> bool` alongside the existing `is_blocked`/`is_quarantined`.

---

## 4. Validation script updates

**`validate_rca.py` (FR-13 check, line ~136-144):**
- Count `throttle_count` alongside `block_count`/`quarantine_count`/`log_count` (match `"THROTTLE" in str(a)`).
- Change the proportionality check to `(throttle_count + block_count + log_count) >= quarantine_count`.
- Add a timing check: THROTTLE/BLOCK resolutions should have `duration_ms` near 0 (no vote wait) while QUARANTINE resolutions should show the ~`VOTE_WINDOW` delay — this directly verifies the "only quarantine votes" fix from §1.
- **Split the existing test into two, rather than reusing one attack for both:** the current test uses `intensity_multiplier=12.0`, which is severe enough to trip `CRITICAL_CONFIDENCE` immediately (single-report bypass to top tier) — so it's a good FR-11 (voting) regression test but *cannot* prove the ladder climbs, since it never spends time at THROTTLE. Keep it as-is for FR-10/FR-11. Add a second, separate test with a moderate `intensity_multiplier` (recommend 5.0-6.0 — high enough to be classified DDOS/Confirmed Threat, low enough to stay under `CRITICAL_CONFIDENCE`) run for `>= ESCALATION_WINDOW + ALERT_COOLDOWN` (so `>= 13s`, recommend `RUN_SEC=15`), and assert the *first* resolution for the segment is `THROTTLE_SEGMENT` and a *later* resolution on the same segment is `QUARANTINE_SEGMENT` — this is the actual ladder-climb proof.

**`validate_scenarios.py` / `validate_system.py`:** no code change required, but re-run after the RCA/RAA change — `disruption = quarantine_count * 1.0` (used for availability) should drop for scenarios that previously resolved every DDoS as QUARANTINE. Flag this explicitly: this fix is very likely to also move the two other headline FAILs in the current Validation Report (system-level availability, FR-31, and S1's availability/SW) — since both are computed purely from quarattine-event counts, not simulated traffic effect. Re-run the full suite and check whether those FAILs flip to PASS as a side effect, rather than assuming they're independent problems.

---

## 5. Interaction with the baseline-vs-advanced plan

This THROTTLE ladder is what makes "RCA proportionality" a real, honest differentiator between baseline and advanced mode (per the earlier plan's naive-mode design):
- **Advanced RCA:** full `ESCALATION_ACTIONS` ladder as above.
- **Naive/baseline RCA:** either the flat "always QUARANTINE" (today's behavior, for the coordination-only ablation) or the flat "always BLOCK_SOURCE_IP regardless of context" (for the broader full-system baseline) — both remain valid naive-mode strawmen once the advanced side has something real to contrast against. Without this fix, "proportional escalation" wasn't a real difference to measure; after it, it is.

---

## 6. Resolved decisions (previously open risks)

**1. Escalation trigger definition — proxy accepted, but strengthened.** Pure "another alert arrived" is too weak a signal (it only measures alert *frequency*, not whether the attack is actually still succeeding). Decision: escalate only if a new report arrives within `ESCALATION_WINDOW` **and** its `confidence`/`severity` is not lower than the value recorded at the last action. If it's clearly lower, hold at the current tier — treat that as (weak) evidence the mitigation is working. This is still a proxy, not a real measured effect (the simulator has no traffic-reduction feedback loop), so 