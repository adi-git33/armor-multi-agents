"""
StateCollector: observes the message bus and builds the display state the
live dashboard needs. Never modifies any agent — read-only observer.
"""

from __future__ import annotations
import time
from collections import deque

from core.messages import Message, Topic
from core.models import Packet
from bus.message_bus import MessageBus

from dashboard.metrics_store import load_aca_metrics, save_aca_metrics
from dashboard.ui_metadata import SEG_MAP, VIZ_TOPIC_RECIPIENTS
from dashboard.scoring import classify_threat_report, compute_metrics
from dashboard.snapshot import build_snapshot


class StateCollector:
    """
    Subscribes to every bus topic and maintains all state the
    frontend needs.  Never modifies any agent — read-only observer.
    """

    def __init__(self):
        self._start = time.monotonic()
        # Play/pause bookkeeping: while paused the session clock freezes, so
        # elapsed() (and everything derived from it — availability, log
        # timestamps) excludes paused stretches.
        self._paused_at: float | None = None
        self._paused_total = 0.0
        self.lamport = 0
        self.logs: deque = deque(maxlen=50)
        self.viz_events: deque = deque(maxlen=400)
        self._viz_seq = 0

        # Set by SimEngine.start() once the traffic generator exists, so
        # quarantine decisions here can actually cut off segment traffic.
        self.gen: "TrafficGenerator | None" = None

        # Metric counters — a real confusion matrix against active_attacks
        # (ground truth), not just ACA's self-reported classification.
        # Loaded from disk (metrics_store.ACA_METRICS_PATH) so accuracy
        # accumulates across backend restarts instead of resetting to zero
        # every launch; see scripts/seed_aca_metrics.py.
        _m = load_aca_metrics()
        self.tp = _m["tp"]   # real attack, correctly flagged as a threat
        self.fp = _m["fp"]   # no real attack, but flagged as a threat anyway
        self.fn = _m["fn"]   # real attack, missed (classified as NOISE)
        self.tn = _m["tn"]   # no real attack, correctly classified as NOISE

        # Ground truth: segment_id -> "DDOS" | "PORT_SCAN" for whichever
        # segment SimEngine.set_scenario() is actually attacking right now.
        # Set/cleared by record_attack_start()/record_attack_end(); untouched
        # by quarantine (the attacker keeps running even while its traffic
        # is blocked).
        self.active_attacks: dict[str, str] = {}
        # When each segment's current attack began / last attack ended —
        # drives the scoring.ATTACK_GRACE_SECS / CALM_LINGER_SECS windows.
        self.attack_started: dict[str, float] = {}
        self.attack_ended:   dict[str, float] = {}

        self.mttr_ms: list[float] = []
        self._disruption_start: float | None = None
        self.disruption_secs = 0.0

        # Enforcement (mirrors RAA's decisions)
        self.blocked_ips: set[str] = set()
        self.quarantined_segs: set[str] = set()

        # Per-agent display state
        self.ag_state: dict[str, str] = {}   # idle / mon / alert / active
        self.ag_task:  dict[str, str] = {}   # human-readable current task
        self.ag_trace: dict[str, deque] = {} # recent decision log entries

        # Active coalition incidents (incident_id → metadata)
        self.active_incidents: dict[str, dict] = {}

        # Live coalition voting — open ballots (incident_id → ballot) and a
        # short buffer of just-resolved ones so the UI can show the final
        # tally for a beat before it disappears.
        self.ballots: dict[str, dict] = {}
        self.resolved_ballots: deque = deque(maxlen=5)

        # Per-segment bandwidth history (70 samples ≈ same as mockup)
        self.bw_hist: dict[str, deque] = {}

        # Sampled real packets (legit + attacker) — capped, not exhaustive.
        # At real traffic rates (100s-1000s pps) we cannot stream every
        # packet over a 200ms-tick WebSocket; this is a rate-limited,
        # representative sample, clearly labeled as such in the UI.
        self.packet_log: deque = deque(maxlen=150)
        self._pkt_seq = 0
        self._pkt_tick: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Init
    # ------------------------------------------------------------------

    def init(self, seg_ids: list[str], agent_ids: list[str]):
        for sid in seg_ids:
            self.bw_hist[sid] = deque(maxlen=70)
        for aid in agent_ids:
            self.ag_state[aid] = "mon"
            self.ag_task[aid]  = "watching traffic"
            self.ag_trace[aid] = deque(maxlen=15)

    def subscribe(self, bus: MessageBus):
        bus.subscribe(Topic.ALERTS,          self._on_alert)
        bus.subscribe(Topic.THREAT_REPORTS,  self._on_threat_report)
        bus.subscribe(Topic.THREAT_INTEL,    self._on_threat_intel)
        bus.subscribe(Topic.COALITION,       self._on_coalition)
        bus.subscribe(Topic.VOTES,           self._on_vote)
        bus.subscribe(Topic.RESOLUTION,      self._on_resolution)
        bus.subscribe(Topic.RESOURCE_GRANTS, self._on_grant)

    # ------------------------------------------------------------------
    # Ground-truth bookkeeping — called by SimEngine (see dedicated
    # methods instead of it reaching into active_attacks/attack_started/
    # attack_ended/bw_hist directly).
    # ------------------------------------------------------------------

    def record_attack_start(self, segment: str, attack_type: str) -> None:
        self.active_attacks[segment] = attack_type
        self.attack_started[segment] = time.monotonic()

    def record_attack_end(self, segment: str) -> None:
        if segment in self.active_attacks:
            self.attack_ended[segment] = time.monotonic()
        self.active_attacks.pop(segment, None)

    def record_bandwidth_sample(self, segment: str, pps: float) -> None:
        self.bw_hist.setdefault(segment, deque(maxlen=70)).append(pps)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _now(self) -> str:
        t = self.elapsed()
        m, s = divmod(int(t), 60)
        return f"{m:02d}:{s:02d}.{int(t * 1000) % 1000:03d}"

    def elapsed(self) -> float:
        ref = self._paused_at if self._paused_at is not None else time.monotonic()
        return ref - self._start - self._paused_total

    def pause_clock(self) -> None:
        if self._paused_at is not None:
            return
        self._paused_at = time.monotonic()
        # Freeze the availability disruption stopwatch too — paused time
        # must not count as quarantine downtime.
        if self._disruption_start is not None:
            self.disruption_secs += self._paused_at - self._disruption_start
            self._disruption_start = None

    def resume_clock(self) -> None:
        if self._paused_at is None:
            return
        self._paused_total += time.monotonic() - self._paused_at
        self._paused_at = None
        if self.quarantined_segs:
            self._disruption_start = time.monotonic()

    def _log(self, agent: str, color: str, text: str, perf: str = ""):
        self.lamport += 1
        self.logs.appendleft({"id": self.lamport, "time": self._now(),
                               "agent": agent, "color": color, "text": text,
                               "perf": perf})

    def _trace(self, aid: str, text: str):
        self.ag_trace.setdefault(aid, deque(maxlen=15)).appendleft(
            {"time": self._now(), "text": text}
        )

    def _emit_viz_event(self, msg: Message):
        c = msg.content
        if msg.receiver and msg.receiver != "BROADCAST":
            targets = [r.strip() for r in msg.receiver.split(",") if r.strip()]
        else:
            targets = VIZ_TOPIC_RECIPIENTS.get(msg.topic, [])
        targets = [t for t in targets if t != msg.sender]

        self._viz_seq += 1
        self.viz_events.append({
            "id": self._viz_seq,
            "performative": msg.performative.value,
            "msg_id": msg.msg_id,
            "conversation_id": msg.conversation_id,
            "topic": msg.topic,
            "sender": msg.sender,
            "receiver": msg.receiver,
            "targets": targets,
            "segment": c.get("segment") or c.get("primary_segment"),
            "anomaly_type": c.get("anomaly_type"),
            "classification": c.get("classification"),
            "pattern_type": c.get("pattern_type"),
            "action": c.get("action") or c.get("proposed_action"),
            "severity": c.get("severity", 0.0),
            "at": round(self.elapsed(), 3),
        })

    # ------------------------------------------------------------------
    # Packet sampling — real legit + attacker packets, rate-limited
    # ------------------------------------------------------------------

    def _add_packet(self, kind: str, pkt: "Packet"):
        self._pkt_seq += 1
        self.packet_log.append({
            "id":       self._pkt_seq,
            # Absolute monotonic clock, not elapsed() — packet_log is a
            # session-wide running record, so timestamps here must stay
            # on one continuous clock for the frontend's "last N seconds"
            # recency filtering to work.
            "t":        round(time.monotonic(), 3),
            "kind":     kind,               # "legit" | "attack"
            "src_ip":   pkt.src_ip,
            "dst_ip":   pkt.dst_ip,
            "src_port": pkt.src_port,
            "dst_port": pkt.dst_port,
            "protocol": pkt.protocol,
            "size":     pkt.pkt_size,
            "segment":  pkt.segment,
            "label":    pkt.label,
        })

    def sample_packets(self, seg_id: str, gen: "TrafficGenerator"):
        """
        Called on every TrafficGenerator sample tick (10 Hz per segment).
        Internally rate-limited so the packet log stays a small, honest
        sample rather than an attempt at full fidelity.
        """
        # Real attack packets (currently only PortScanner deposits discrete
        # Packet objects) — peek non-destructively so we never compete with
        # the TMA's own drain_attack_packets() consumption.
        for pkt in gen.peek_attack_packets(seg_id):
            self._add_packet("attack", pkt)

        # DDoSAttacker injects a pure pps overlay, not discrete packets —
        # synthesize one clearly-labeled representative flood packet every
        # few ticks while the overlay is active, so a DDoS is still visible
        # as "packets", without claiming per-packet fidelity to the flood.
        attack_pps = gen.get_attack_pps(seg_id)
        if attack_pps > 0:
            key = f"ddos:{seg_id}"
            tick = self._pkt_tick.get(key, 0) + 1
            self._pkt_tick[key] = tick
            if tick % 3 == 0:
                hosts = gen.topology.hosts_in(seg_id)
                if hosts:
                    host = hosts[tick % len(hosts)]
                    self._add_packet("attack", Packet(
                        src_ip   = f"{(tick * 37) % 223 + 1}.{(tick * 11) % 256}."
                                   f"{(tick * 7) % 256}.{(tick * 3) % 254 + 1}",
                        dst_ip   = host.ip,
                        src_port = 40000 + (tick % 20000),
                        dst_port = 443,
                        protocol = "TCP",
                        pkt_size = 64,
                        segment  = seg_id,
                        label    = "DDoS flood (representative sample)",
                    ))

        # Legit background traffic — rate-limited to ~2 pkts/sec/segment,
        # drawn from the same weighted traffic patterns scripts/show_packets.py
        # uses.
        key = f"legit:{seg_id}"
        tick = self._pkt_tick.get(key, 0) + 1
        self._pkt_tick[key] = tick
        if tick % 5 == 0:
            seg = gen.topology.get(seg_id)
            for pkt in gen.generate_packets(seg, 2):
                self._add_packet("legit", pkt)

    # ------------------------------------------------------------------
    # Bus handlers (each is an async callback)
    # ------------------------------------------------------------------

    async def _on_alert(self, msg: Message):
        self._emit_viz_event(msg)
        c     = msg.content
        seg   = c.get("segment", "")
        atype = c.get("anomaly_type", "")
        dev   = c.get("deviation", 0.0)
        name  = SEG_MAP.get(seg, {}).get("name", seg)
        # One TMA per segment now — attribute state/log entries to the TMA
        # that actually sent this (e.g. "TMA:server"), not a fixed "TMA:1".
        sender      = msg.sender
        sender_code = f"TMA-{SEG_MAP.get(seg, {}).get('code', seg)}"

        self.ag_state[sender] = "alert"
        self.ag_task[sender]  = f"anomaly on {name}"
        self._trace(sender, f"{atype} on {name} ({dev:+.1f}σ)")
        self._log(sender_code, "#d9a23f",
                  f"Alert — {atype.lower().replace('_', ' ')} on {name} ({dev:+.1f}σ)",
                  perf=msg.performative.value)

    async def _on_threat_report(self, msg: Message):
        self._emit_viz_event(msg)
        c    = msg.content
        clf  = c.get("classification", "")   # "NOISE" | "DDOS" | "PORT_SCAN"
        sev  = c.get("severity", 0.0)
        seg  = c.get("segment", "")
        conf = c.get("confidence", 0.0)
        atk  = c.get("attack_type", clf)
        name = SEG_MAP.get(seg, {}).get("name", seg)

        # Ground truth for this segment right now (set by
        # record_attack_start()) — lets tp/fp/fn/tn reflect whether ACA's
        # call was actually correct, not just what string it happened to
        # publish. See dashboard/scoring.py for the judging rules.
        bucket = classify_threat_report(
            classification = clf,
            source_alert   = c.get("source_alert", ""),
            segment        = seg,
            now            = time.monotonic(),
            active_attacks = self.active_attacks,
            attack_started = self.attack_started,
            attack_ended   = self.attack_ended,
        )
        if bucket == "tp":
            self.tp += 1
        elif bucket == "fp":
            self.fp += 1
        elif bucket == "fn":
            self.fn += 1
        elif bucket == "tn":
            self.tn += 1

        if clf != "NOISE":
            self.ag_state["ACA:1"] = "active"
            self.ag_task["ACA:1"]  = f"classifying · severity {sev:.2f}"
            self._trace("ACA:1", f"Confirmed {atk} — sev {sev:.2f}, conf {conf:.0%}")
            self._log("ACA-1", "#cf6b5e",
                      f"Confirmed threat: {atk} on {name}, severity {sev:.2f}",
                      perf=msg.performative.value)

        save_aca_metrics(self.tp, self.fp, self.fn, self.tn)

    async def _on_threat_intel(self, msg: Message):
        self._emit_viz_event(msg)
        c       = msg.content
        pattern = c.get("pattern_type", "")
        seg     = c.get("primary_segment", "")
        name    = SEG_MAP.get(seg, {}).get("name", seg)

        self.ag_state["TIA:1"] = "active"
        self.ag_task["TIA:1"]  = f"correlating — {pattern}"
        self._trace("TIA:1", f"Pattern {pattern} on {name}")

        if "MULTI_SEGMENT" in pattern:
            self._log("TIA-1", "#3fa3a8",
                      "Multi-segment scan detected — forming response coalition",
                      perf=msg.performative.value)
        elif "COORDINATED" in pattern:
            self._log("TIA-1", "#3fa3a8",
                      "Coordinated DDoS across segments — coalition activated",
                      perf=msg.performative.value)
        else:
            self._log("TIA-1", "#3fa3a8", f"{name} ranked highest-priority threat",
                      perf=msg.performative.value)

    async def _on_coalition(self, msg: Message):
        self._emit_viz_event(msg)
        c      = msg.content
        inc_id = c.get("incident_id", "")
        seg    = c.get("segment", "")
        action = c.get("proposed_action", "")
        name   = SEG_MAP.get(seg, {}).get("name", seg)

        self.active_incidents[inc_id] = {
            "seg": seg, "action": action, "t": time.monotonic()
        }
        self.ballots[inc_id] = {
            "incident_id": inc_id,
            "segment": seg,
            "segment_name": name,
            "action": action,
            "proposer": msg.sender,
            "opened_at": round(self.elapsed(), 3),
            "votes": [],
            "outcome": None,
        }
        self.ag_state["RCA:1"] = "active"
        self.ag_task["RCA:1"]  = f"coalition vote for {name}"
        self._trace("RCA:1", f"CFP: {action} for {name}")
        self._log("RCA-1", "#4577b5",
                  f"Coalition vote — {action.lower().replace('_', ' ')} for {name}",
                  perf=msg.performative.value)

    async def _on_vote(self, msg: Message):
        self._emit_viz_event(msg)
        c      = msg.content
        inc_id = c.get("incident_id", "")
        ballot = self.ballots.get(inc_id)
        decision = msg.performative.value  # ACCEPT / REJECT

        if ballot is not None:
            ballot["votes"].append({
                "voter":    msg.sender,
                "decision": decision,
                "reason":   c.get("reason", ""),
                "t":        round(self.elapsed(), 3),
            })

        color = "#4a9e7f" if decision == "ACCEPT" else "#cf6b5e"
        self._trace(msg.sender, f"voted {decision} on {inc_id}")
        self._log(msg.sender.replace(":", "-"), color,
                  f"Vote {decision} from {msg.sender} — {c.get('reason', '') or inc_id}",
                  perf=decision)

    async def _on_resolution(self, msg: Message):
        self._emit_viz_event(msg)
        c       = msg.content
        inc_id  = c.get("incident_id", "")
        outcome = c.get("outcome", "")
        action  = c.get("action", "")
        seg     = c.get("segment", "")
        dur_ms  = c.get("duration_ms", 0)
        name    = SEG_MAP.get(seg, {}).get("name", seg)
        tgt     = c.get("enforcement_target", {})

        self.active_incidents.pop(inc_id, None)

        ballot = self.ballots.pop(inc_id, None)
        if ballot is not None:
            ballot["outcome"]       = outcome
            ballot["votes_accept"]  = c.get("votes_accept", 0)
            ballot["votes_reject"]  = c.get("votes_reject", 0)
            ballot["resolved_at"]   = round(self.elapsed(), 3)
            self.resolved_ballots.append(ballot)

        if outcome == "EXECUTED":
            self.mttr_ms.append(dur_ms)
            if len(self.mttr_ms) > 100:
                self.mttr_ms = self.mttr_ms[-100:]

            if "src_ip" in tgt:
                ip = tgt["src_ip"]
                self.blocked_ips.add(ip)
                self.ag_task["RCA:1"] = f"blocked {ip}"
                self._log("RCA-1", "#4577b5", f"Mitigation — {ip} blocked ({dur_ms} ms)",
                          perf=msg.performative.value)
            elif "segment" in tgt and action == "QUARANTINE_SEGMENT":
                qseg = tgt["segment"]
                self.quarantined_segs.add(qseg)
                if self.gen:
                    self.gen.quarantine(qseg)
                if self._disruption_start is None:
                    self._disruption_start = time.monotonic()
                qname = SEG_MAP.get(qseg, {}).get("name", qseg)
                self.ag_task["RCA:1"] = f"quarantined {qname}"
                self._log("RCA-1", "#4577b5",
                          f"Mitigation — {qname} quarantined ({dur_ms} ms)",
                          perf=msg.performative.value)
            elif "segment" in tgt:
                # THROTTLE_SEGMENT (rung 0, non-voted) — a lighter-touch
                # response than QUARANTINE_SEGMENT; does not black out
                # traffic or set the QUARANTINED badge.
                self.ag_task["RCA:1"] = f"throttled {name}"
                self._log("RCA-1", "#4577b5",
                          f"Mitigation — {name} throttled ({dur_ms} ms)",
                          perf=msg.performative.value)

            self._trace("RCA:1", f"{action} EXECUTED for {name} ({dur_ms} ms)")
        elif outcome == "RELEASED":
            rseg = tgt.get("segment", "")
            if rseg in self.quarantined_segs:
                self.quarantined_segs.discard(rseg)
                if self.gen:
                    self.gen.unquarantine(rseg)
                if self._disruption_start is not None:
                    self.disruption_secs += time.monotonic() - self._disruption_start
                    self._disruption_start = time.monotonic() if self.quarantined_segs else None
                rname = SEG_MAP.get(rseg, {}).get("name", rseg)
                self.ag_task["RCA:1"] = f"released {rname}"
                self._log("RCA-1", "#4577b5",
                          f"Mitigation — {rname} quarantine released ({dur_ms} ms hold)",
                          perf=msg.performative.value)
                self._trace("RCA:1", f"quarantine released for {rname}")
        else:
            self._log("RCA-1", "#d9a23f",
                      f"Vote rejected — {action} not executed for {name}",
                      perf=msg.performative.value)
            self._trace("RCA:1", f"{action} REJECTED for {name}")

    async def _on_grant(self, msg: Message):
        self._emit_viz_event(msg)
        c       = msg.content
        outcome = c.get("outcome", "")
        res     = c.get("resource_type", "")
        seg     = c.get("segment", "")
        name    = SEG_MAP.get(seg, {}).get("name", seg)
        bid     = c.get("bid_value")

        if outcome == "GRANTED":
            self.ag_state["RAA:1"] = "active"
            self.ag_task["RAA:1"]  = f"auction: {res.lower()} allocated"
            self._trace("RAA:1", f"{res} granted for {name}")
            bid_txt = f" (bid {bid:.2f})" if bid is not None else ""
            self._log("RAA-1", "#7b6fc4",
                      f"Auction won — {res.lower()} slot allocated for {name}{bid_txt}",
                      perf=msg.performative.value)
        elif outcome == "DENIED":
            weakest = c.get("weakest_existing_bid")
            self._trace("RAA:1", f"{res} denied for {name} (capacity full)")
            bid_txt = (f" (bid {bid:.2f} ≤ weakest {weakest:.2f})"
                       if bid is not None and weakest is not None else "")
            self._log("RAA-1", "#7b6fc4",
                      f"Auction — {res.lower()} at capacity for {name}{bid_txt}",
                      perf=msg.performative.value)
        elif outcome == "EVICTED":
            self._trace("RAA:1", f"{res} evicted for {name} — outbid")
            bid_txt = f" (bid {bid:.2f})" if bid is not None else ""
            self._log("RAA-1", "#7b6fc4",
                      f"Auction — {name} {res.lower()} allocation evicted, outbid{bid_txt}",
                      perf=msg.performative.value)

    # ------------------------------------------------------------------
    # Reset (called when one segment's scenario changes)
    # ------------------------------------------------------------------

    def reset_segment(self, segment_id: str):
        """
        Called by SimEngine.set_scenario() when segment_id's attacker
        changes. Clears only state that belongs to THIS segment — other
        segments can be mid-attack or quarantined at the same time and
        must not be disturbed. (self.active_attacks isn't touched here:
        SimEngine calls record_attack_start()/record_attack_end() itself
        right after this call, to whatever the new scenario for this
        segment actually is.)

        Left alone deliberately, same reasoning as before but now simply
        because it's session-wide, not segment-scoped: self.logs,
        self.tp/fp/fn/tn, self.mttr_ms, self.blocked_ips (not attributable
        to one segment), and agent display state (agents are global
        singletons that may legitimately be busy with a different segment).
        """
        if self.gen and segment_id in self.quarantined_segs:
            self.gen.unquarantine(segment_id)
        self.quarantined_segs.discard(segment_id)

        self.active_incidents = {
            k: v for k, v in self.active_incidents.items() if v.get("seg") != segment_id
        }
        self.ballots = {
            k: v for k, v in self.ballots.items() if v.get("segment") != segment_id
        }
        self._pkt_tick.pop(f"legit:{segment_id}", None)
        self._pkt_tick.pop(f"ddos:{segment_id}", None)

        # Availability tracks "is ANY segment currently disrupted" — if this
        # was the last quarantined segment, stop the disruption clock too.
        if self._disruption_start is not None and not self.quarantined_segs:
            self.disruption_secs += time.monotonic() - self._disruption_start
            self._disruption_start = None

    # ------------------------------------------------------------------
    # Metrics reset (frontend "reset metrics" control)
    # ------------------------------------------------------------------

    def reset_metrics(self) -> None:
        """Zero the persisted confusion matrix — lets a demo start from a
        clean slate instead of inheriting every historical session's tally."""
        self.tp = self.fp = self.fn = self.tn = 0
        save_aca_metrics(0, 0, 0, 0)

    # ------------------------------------------------------------------
    # Metrics calculation
    # ------------------------------------------------------------------

    def metrics(self) -> dict:
        el = max(1.0, self.elapsed())

        # Availability: 1.0 minus fraction of disrupted time. Roll the
        # live disruption stopwatch forward before handing it to the pure
        # formula in scoring.compute_metrics().
        if self._disruption_start is not None:
            self.disruption_secs += time.monotonic() - self._disruption_start
            self._disruption_start = time.monotonic()

        return compute_metrics(
            tp=self.tp, fp=self.fp, fn=self.fn, tn=self.tn,
            mttr_ms=self.mttr_ms,
            disruption_secs=self.disruption_secs,
            elapsed_secs=el,
            blocked_ip_count=len(self.blocked_ips),
            quarantined_seg_count=len(self.quarantined_segs),
        )

    # ------------------------------------------------------------------
    # Full snapshot for WebSocket push
    # ------------------------------------------------------------------

    def snapshot(self, gen: "TrafficGenerator", segment_scenarios: dict[str, str], running: bool) -> dict:
        """Assemble the JSON object sent to every connected browser."""
        return build_snapshot(self, gen, segment_scenarios, running)
