# Collaborative Cyber-Defense & Automated Incident Response
## Multi-Agent System — Prototype Documentation

---

## What this is

A Python prototype of a **Multi-Agent System (MAS)** that autonomously detects, classifies, and responds to network attacks. Five specialized agents run concurrently, communicate through a shared message bus, and coordinate responses through coalition voting and resource arbitration.

No real network packets — the agents and their decision logic are real; the network traffic they operate on is synthetic. A FastAPI server (`server.py`) streams live state over WebSocket to the React dashboard in `frontend/`, and `validation/` checks the SRS/SDD requirements.

---

## Quick start

```bash
# 1. Train the ML classifier (run once)
python -m agents.aca_trainer

# 2. Run the full integration test (all agents, ~38 s)
pytest tests/test_integration.py

# 3. Run individual part tests
pytest tests/test_part1.py   # Network simulation
pytest tests/test_part2.py   # Attackers
pytest tests/test_part3.py   # Message bus
pytest tests/test_part4.py   # TMA
pytest tests/test_part5.py   # ACA
pytest tests/test_part6.py   # RCA
pytest tests/test_part7.py   # TIA
pytest tests/test_part8.py   # RAA
pytest tests/test_part9_tma_5min_metrics.py  # TMA 5-min metrics

# or just run everything:
pytest
```

**Requirements:** Python 3.10+, `numpy>=2.0`, `scikit-learn>=1.4`

---

## Architecture overview

```
NETWORK SIMULATION LAYER
  NetworkTopology  -  4 segments (public-facing, server, internal, sec-mon)
  TrafficGenerator -  Gaussian pps per segment, 10 Hz sampling
  DDoSAttacker     -  ramps pps to Nx baseline
  PortScanner      -  injects port-probe packets from a fixed src_ip

        |
        | TrafficSample (every 100 ms)
        v

MESSAGE BUS  (pub/sub, FIPA-ACL, Lamport clocks, deduplication)

        |
        |---> alerts         (TMA publishes)
        |---> threat-reports (ACA publishes)
        |---> threat-intel   (TIA publishes)
        |---> coalition      (RCA publishes CFPs; TIA votes)
        |---> votes          (TIA publishes ACCEPT/REJECT)
        |---> resolution     (RCA publishes decisions)
        |---> resource-bids  (reserved for explicit bids)
        |---> resource-grants(RAA publishes grants/denials)

AGENT LAYER

  TMA  -->  ACA  -->  TIA  -->  RCA  -->  RAA
  (sense)  (classify) (correlate)(decide)  (enforce)
```

### Message flow for a DDoS attack

```
TrafficGenerator           TMA              ACA              RCA              RAA
     |                      |                |                |                |
     |-- TrafficSample ----->|                |                |                |
     |                      |-- VOLUME_SPIKE->|                |                |
     |                      |   (alert)       |-- DDOS ------->|                |
     |                      |                |   (threat-rpt) |-- CFP -------->|TIA|
     |                      |                |                |<-- ACCEPT ------|TIA|
     |                      |                |                |-- resolution -->|   |
     |                      |                |                |                |-- GRANTED
     |                      |                |                |                |   (enforced)
```

### Message flow for a multi-segment port scan (TIA correlation path)

```
PortScanner (server)  -->  TMA  -->  ACA  -->  TIA  ---> (threat-intel) ---> RCA ---> RAA
PortScanner (internal) --> TMA  -->  ACA  -->  TIA  (same IP on 2 segs = MULTI_SEGMENT_SCAN)
```

---

## Part 1 — Network simulation

**Files:** `core/models.py`, `simulation/clock.py`, `simulation/network.py`, `simulation/hosts.py`, `simulation/traffic.py`

**What it does:** Models a four-segment corporate network and generates synthetic traffic for each segment.

| Segment | Baseline | Purpose |
|---|---|---|
| public-facing | 500 pps ± 75 | Web servers exposed to internet |
| server | 200 pps ± 30 | Internal databases and app servers |
| internal | 300 pps ± 55 | Employee workstations |
| sec-mon | 50 pps ± 8 | IDS and monitoring infrastructure |

Traffic per segment is drawn from `N(mean, std²)` at 10 Hz. The `TrafficGenerator` maintains a 600-sample rolling window per segment and anti-poisoning baseline: it uses the **oldest 50% of the window** for mean/std so an ongoing attack cannot poison its own detection baseline.

**Warmup guard:** until a segment's window holds `MIN_BASELINE_SAMPLES` (30 = 3 s), `get_stats()` reports the configured design baseline with deviation 0. With fewer samples the std collapses toward the 1-pps div-by-zero guard, and the first readings after startup would otherwise register as "+100σ attacks" — firing spurious alerts and poisoning ACA's 30 s max-deviation feature.

**Test:** `pytest tests/test_part1.py`

---

## Part 2 — Attackers

**Files:** `simulation/attackers.py`

**What it does:** Two simulated adversaries that inject extra traffic into segments.

### DDoSAttacker
- Ramps from 0 to `intensity_multiplier × baseline` over `ramp_seconds`
- Sustains peak for the remainder of the duration
- Generates random source IPs each tick to mimic a botnet
- Clears the overlay when finished so traffic recovers

### PortScanner
- Probes a shuffled list of 24 common ports at a configurable interval
- Uses a **fixed source IP** (`src_ip`, default `45.33.32.156`) so TIA can track it across segments
- Injects low-volume bursts (does not spike pps above the volume threshold)
- Deposits individual `Packet` objects into the generator's attack-packet buffer so TMA can inspect port diversity

**Test:** `pytest tests/test_part2.py`

---

## Part 3 — Message bus

**Files:** `core/messages.py`, `bus/message_bus.py`

**What it does:** The shared communication backbone for all agents.

### FIPA-ACL message format
Every message has: `performative`, `sender`, `receiver`, `topic`, `content`, `conversation_id`, `lamport_ts`, `seq`.

Performatives used: `INFORM`, `ACCEPT`, `REJECT`, `CALL_FOR_PROPOSAL`, `FAILURE`.

### Message bus guarantees
- **FIFO per topic** — one asyncio queue + one delivery task per topic; order is preserved
- **Lamport clock ordering** — every message is stamped; clock is updated on receive
- **Idempotent deduplication** — `(sender, seq)` pairs are tracked; retried messages are silently dropped
- **Non-blocking delivery** — handlers are detached with `asyncio.create_task` for long operations so one slow handler does not block other topics

### Topics

| Topic | Publisher | Subscriber(s) |
|---|---|---|
| `alerts` | TMA | ACA |
| `threat-reports` | ACA | RCA, TIA |
| `threat-intel` | TIA | RCA |
| `coalition` | RCA | TIA |
| `votes` | TIA | RCA |
| `resolution` | RCA | RAA |
| `resource-bids` | (future) | RAA |
| `resource-grants` | RAA | (consumers) |

**Test:** `pytest tests/test_part3.py`

---

## Part 4 — Traffic Monitor Agent (TMA)

**File:** `agents/tma.py`

**What it does:** The sensor layer. Monitors every traffic sample from the generator and fires alerts on two types of anomalies.

### Detection mode 1 — VOLUME_SPIKE
- On each sample, computes deviation: `(current_pps - baseline_mean) / baseline_std`
- If deviation > `ANOMALY_THRESHOLD` (2.0σ) → publish `VOLUME_SPIKE` alert to `alerts` topic
- Cooldown: 5 s per segment before re-alerting
- **Escalation re-alert:** one cooldown bypass per window when the deviation crosses `ESCALATION_THRESHOLD` (4.0σ) after the last alert went out below it — a ramping attack whose first alert was dismissed as probable noise is re-reported the moment it sharpens, instead of waiting out the full 5 s

Alert fields: `segment`, `anomaly_type`, `deviation`, `severity`, `current_pps`, `baseline_mean`, `baseline_std`, `port_count=0`, `port_growth_rate=0.0`

### Detection mode 2 — PORT_SCAN
- Maintains `{ segment: { src_ip: { dst_port: last_seen_time } } }`
- If a single source IP hits `PORT_SCAN_THRESHOLD` (3) distinct destination ports within a 10 s sliding window → publish `PORT_SCAN` alert
- Cooldown: 10 s per `(segment, src_ip)` pair

Alert fields: `segment`, `anomaly_type`, `src_ip`, `ports_scanned`, `port_count`, `port_growth_rate` (unique ports / elapsed seconds), `elapsed_scan_secs`

**Design note:** TMA is the sole packet sensor. ACA never reads traffic directly — it only classifies what TMA reports. This maintains clean separation of concerns.

**Test:** `pytest tests/test_part4.py` — 8/8 PASS

---

## Part 5 — Anomaly Classifier Agent (ACA)

**Files:** `agents/aca.py`, `agents/aca_trainer.py`

**What it does:** Classifies TMA alerts as `DDOS`, `PORT_SCAN`, or `NOISE` using a trained decision tree.

### Training (`aca_trainer.py`)
8 scenarios × 6 random seeds = 428 labelled samples:

| Scenario | Description |
|---|---|
| ddos_subtle | 2.2× baseline — ramp alerts overlap with noise |
| ddos_moderate | 2.5× baseline |
| ddos_strong | 4× baseline |
| ddos_extreme | 10× baseline |
| scan_normal | probe_interval = 0.3 s |
| scan_stealthy | probe_interval = 0.7 s |
| noise_pure | pure Gaussian variation |
| noise_legit | legitimate multi-port traffic (false-positive training) |

Key design choices:
- `DDOS_DEV_FLOOR = 3σ` — alerts during DDoS only get the DDOS label if deviation ≥ 3σ, creating genuine overlap in the 3–5σ zone that forces the model to learn temporal features
- `class_weight="balanced"` — prevents the model from defaulting to NOISE prediction
- Final accuracy: **98%** (DDOS recall=1.00, PORT_SCAN perfect)
- Top features: `port_growth_rate` (0.521), `severity` (0.460)

### Classification (`aca.py`)

**Layer 1 — fast noise filter:**
If `deviation < 3σ` AND `anomaly_type == VOLUME_SPIKE` AND `recent_alert_count ≤ 1` → classify as NOISE immediately. No model call needed. (The 3σ line matches the trainer's `DDOS_DEV_FLOOR`, so first alerts inside the trained 3–5σ overlap zone reach the model instead of being auto-dismissed.)

**Layer 2 — trained model:**
9-feature vector → `DecisionTreeClassifier.predict_proba()` → classification + confidence.

Features: `anomaly_type_enc`, `deviation`, `severity`, `port_count`, `port_growth_rate`, `elapsed_scan_secs`, `recent_alert_count`, `max_deviation_30s`, `cross_segment_count`

Output (published to `threat-reports`): `segment`, `classification`, `confidence`, `severity`, `recommended_action`, `source_alert`, `evidence` (includes `src_ip` for PORT_SCAN alerts so RCA can target enforcement correctly).

**Test:** `pytest tests/test_part5.py` — 12/12 PASS

---

## Part 6 — Response Coordinator Agent (RCA)

**File:** `agents/rca.py`

**What it does:** The decision layer. Receives classified threats, deliberates on whether evidence is sufficient to act, organizes a coalition vote, and publishes a resolution.

### Action map

| Classification | Action |
|---|---|
| DDOS | QUARANTINE_SEGMENT |
| PORT_SCAN | BLOCK_SOURCE_IP |
| NOISE | LOG_ONLY (filtered before deliberation) |

### Decision flow

```
_on_threat_report / _on_threat_intel
    |
    Gate 1 (filter)
      - classification == NOISE?   drop
      - confidence < 0.70?         drop
      - segment in cooldown (30s)? drop
    |
    Gate 2 (deliberate)
      - confidence >= 0.85?                  act alone
      - corroborating reports >= 2 in 60s?   act (corroboration path)
      - otherwise?                            buffer, wait
    |
    _call_vote
      - self-vote ACCEPT
      - publish CALL_FOR_PROPOSAL to coalition
      - asyncio.create_task(_wait_and_resolve)  <- detached from delivery loop
    |
    _resolve  (after VOTE_WINDOW = 2 s)
      - accepts > rejects?   publish INFORM to resolution (EXECUTED)
      - else?                publish FAILURE (REJECTED)
      - builds enforcement_target: { src_ip } or { segment }
```

**TIA intel path:** When TIA publishes to `threat-intel`, RCA skips Gate 2 entirely — TIA has already cross-corroborated the pattern. The incident is opened directly with TIA's confidence level.

**Enforcement target:** The resolution carries `enforcement_target` so RAA knows exactly which resource to apply the action to (which IP to block, which segment to quarantine).

**Test:** `pytest tests/test_part6.py` — 13/13 PASS

---

## Part 7 — Threat Intelligence Agent (TIA)

**File:** `agents/tia.py`

**What it does:** The correlation layer. Watches threat-reports across all segments to find attack patterns that no single-segment agent can see, enriches the threat picture, and participates in coalition votes.

### Patterns detected

**MULTI_SEGMENT_SCAN**
- Same `src_ip` appears in PORT_SCAN alerts on ≥ 2 segments within 60 s
- Confidence: 0.93
- Action: BLOCK_SOURCE_IP
- Use case: scanner probing multiple network zones — more dangerous than a single-segment scan

**COORDINATED_DDOS**
- DDOS classification on ≥ 2 different segments within 30 s
- Confidence: 0.95
- Action: QUARANTINE_SEGMENT
- Use case: botnet simultaneously flooding multiple entry points

Both patterns have a 30 s cooldown to prevent repeated publications for the same ongoing event.

### Coalition voting
TIA subscribes to `coalition`. When RCA publishes a CFP, TIA:
1. Looks up its history for the incident's segment
2. Votes ACCEPT (always — no contradicting-evidence logic yet)
3. Includes `intel_count` in the vote so RCA can see the quality of corroboration

**Test:** `pytest tests/test_part7.py` — 8/8 PASS

---

## Part 8 — Resource Allocator Agent (RAA)

**File:** `agents/raa.py`

**What it does:** The enforcement layer. Receives resolutions from RCA and allocates limited defensive resources using a sealed-bid auction. Also applies simulated enforcement (tracking blocked IPs and quarantined segments).

### Resources modelled

| Resource | Capacity | Consumed by |
|---|---|---|
| FIREWALL | 3 slots | BLOCK_SOURCE_IP |
| QUARANTINE | 2 slots | QUARANTINE_SEGMENT |
| LOG | unlimited | LOG_ONLY |

### Sealed-bid auction

Each resolution carries an implicit bid:

```
bid_value = confidence × (votes_accept / total_votes)
```

High confidence + unanimous vote = high bid = priority access.

**When capacity is free:** grant immediately.

**When capacity is full:**
- Find the weakest existing allocation (lowest bid in that resource pool)
- Incoming bid > weakest → **evict** weakest, grant incoming (higher-priority incident wins)
- Incoming bid ≤ weakest → **deny** incoming (existing allocations hold)

### Outputs (published to `resource-grants`)

| Performative | Meaning |
|---|---|
| INFORM | Resource granted |
| REJECT | Incoming request denied (outbid by existing pool) |
| FAILURE | Existing allocation evicted (outbid by new request) |

### Enforcement state
RAA maintains `blocked_ips: set[str]` and `quarantined_segments: set[str]`. These represent what the enforcement layer *would* apply to a real firewall or VLAN controller. Wiring to an actual enforcement API requires only changing the `_enforce()` method — all agent logic above it stays the same.

**Test:** `pytest tests/test_part8.py` — 8/8 PASS

---

## Integration test

**File:** `test_integration.py`

Runs all five agents together against three scenarios (~38 s):

| Phase | Scenario | Key outcome |
|---|---|---|
| 1 | DDoS on `public-facing` (6×, 8 s) | TMA→ACA→RCA→RAA: `public-facing` quarantined |
| 3 | Port scan — same IP on `server` + `internal` (10 s) | TIA MULTI_SEGMENT_SCAN→RCA→RAA: `45.33.32.156` blocked |
| 4 | DDoS on `sec-mon` (5×, 7 s) | TIA COORDINATED_DDOS intel; `sec-mon` quarantined |

**Results: 15/15 PASS**

```
TMA alerts         30
ACA threat-reports 30
TIA intel           2  (MULTI_SEGMENT_SCAN + COORDINATED_DDOS)
Coalition votes     5
RCA resolutions     5
RAA grants          5  (2 QUARANTINE + 3 FIREWALL)
Blocked IPs         {'45.33.32.156'}
Quarantined segs    {'public-facing', 'sec-mon'}
```

---

## Key design decisions

**Oldest-50% baseline anti-poisoning**
The TrafficGenerator uses the oldest half of its rolling window to compute mean/std. This means an ongoing DDoS cannot shift the baseline upward and hide itself — the detection threshold stays anchored to pre-attack history.

**TMA as the sole sensor**
TMA is the only agent that reads traffic. ACA never samples the generator directly. This preserves separation of concerns: TMA decides what is anomalous at the packet level, ACA decides what it means.

**PORT_SCAN_THRESHOLD = 3 (not a hardcoded rule)**
TMA fires at 3 unique ports to be sensitive. ACA's decision tree then learns the real boundary between legitimate multi-port traffic and scanning via `port_growth_rate` (feature importance 0.521). The threshold is the sensor's sensitivity, not the classifier's boundary.

**DDOS_DEV_FLOOR = 3σ for training**
Setting the DDoS label floor at 3σ creates genuine overlap in the 3–5σ zone between DDoS ramp-up alerts and noisy normal spikes. This prevents 100% accuracy and forces the model to use temporal features (recent_alert_count, max_deviation_30s). Accuracy is 98%, not 100%, because the overlap is real.

**asyncio.create_task for vote window**
RCA's `_call_vote` detaches the 2 s vote timer using `asyncio.create_task`. If it used `await asyncio.sleep(VOTE_WINDOW)` directly inside the delivery callback, the entire `threat-reports` delivery loop would freeze for 2 s per incident, preventing any other messages from being processed.

**Enforcement target in the resolution**
RCA includes `enforcement_target: { src_ip }` or `enforcement_target: { segment }` in the resolution message. This makes the resolution self-contained: whoever enforces it (currently RAA, eventually a real firewall API) knows exactly which resource to modify without having to look anything up.

**EnforcementStub as RAA placeholder**
`simulation/enforcement.py` is a thin stub that listens to `resolution` and records what *would* have been enforced. It was used during Part 6 and 7 testing before RAA existed. RAA replaced it in Part 8 by subscribing to the same topic with the same interface, plus auction logic on top.

---

## What is real vs. simulated

| Component | Real | Simulated |
|---|---|---|
| Message bus (pub/sub, Lamport clocks, dedup) | Yes | |
| Agent decision logic (TMA thresholds, ACA ML, RCA deliberation, TIA correlation, RAA auction) | Yes | |
| FIPA-ACL protocol, coalition voting | Yes | |
| Network traffic (pps, packets, segments) | | Gaussian RNG |
| Attacker behavior (DDoS ramp, port probes) | | Python objects |
| Enforcement outcome (block IP, quarantine segment) | | Python sets |

To connect to a real network: replace `TrafficGenerator.run()` with a `scapy` or `libpcap` capture loop, and replace `ResourceAllocatorAgent._enforce()` with real firewall/SDN API calls. Every agent in between stays unchanged.

---

## File map

```
cyberDefenseProtoType/
|
|-- core/
|   |-- models.py          Packet, TrafficSample, Host, TrafficPattern
|   +-- messages.py        FIPA-ACL Message, Performative enum, Topic constants
|
|-- bus/
|   +-- message_bus.py     Pub/sub backbone, Lamport clocks, deduplication
|
|-- simulation/
|   |-- clock.py           SimClock (wall-clock wrapper)
|   |-- network.py         NetworkTopology, 4 segments
|   |-- hosts.py           HostRegistry, 21 named hosts
|   |-- traffic.py         TrafficGenerator, Gaussian baseline, 10 Hz
|   |-- attackers.py       DDoSAttacker, PortScanner
|   +-- enforcement.py     EnforcementStub (RAA placeholder for tests)
|
|-- agents/
|   |-- base.py            BaseAgent (lifecycle, subscribe/guard, publish helper)
|   |-- _history.py        Shared sliding-window/cooldown helpers
|   |-- aca_features.py    Shared ACA feature vector (aca.py + aca_trainer.py)
|   |-- tma.py             TrafficMonitorAgent  (Part 4)
|   |-- aca_trainer.py     Synthetic data + DecisionTree training  (Part 5)
|   |-- aca.py             AnomalyClassifierAgent  (Part 5)
|   |-- rca.py             ResponseCoordinatorAgent  (Part 6)
|   |-- tia.py             ThreatIntelligenceAgent  (Part 7)
|   +-- raa.py             ResourceAllocatorAgent  (Part 8)
|
|-- dashboard/             Live-dashboard state/presentation (used by server.py)
|   |-- state_collector.py StateCollector — observes the bus, builds display state
|   |-- scoring.py         Confusion-matrix judging + DR/FPR/MTTR/availability/SW formulas
|   |-- snapshot.py        JSON view-model assembly for the WebSocket broadcast
|   |-- beliefs.py         Agent-inspector belief-base presentation
|   |-- ui_metadata.py     Segment/agent display config, BDI desire/plan tables
|   +-- metrics_store.py   ACA confusion-matrix JSON persistence
|-- sim_engine.py          SimEngine — MAS lifecycle + scenario switching
|-- routes.py              Plain HTTP routes
|-- websocket.py           WebSocket broadcast loop + inbound command dispatch
|-- server.py              FastAPI app assembly (uvicorn entry point)
|
|-- scripts/               Manual debug/demo utilities (not part of the live app)
|   |-- main.py            Part 1 console demo
|   |-- demo_attack.py     Part 2 scripted attack demo
|   |-- show_packets.py    Sample-packet inspector
|   |-- show_topology.py   Network topology inspector
|   +-- seed_aca_metrics.py  Bootstraps models/aca_metrics.json
|
+-- tests/                 pytest suite (pytest.ini + conftest.py at backend/ root)
    |-- test_part1.py  through  test_part8.py    Per-agent unit tests
    +-- test_integration.py                      Full system scenario test
```
