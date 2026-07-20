"""
Anomaly Classifier Agent  (SDD §4.3)
======================================
Subscribes to TMA alerts, classifies them using a pre-trained
RandomForestClassifier, and publishes threat reports.

Two-layer design
-----------------
Layer 1 — rule filter:
    Dismiss alerts that are almost certainly Gaussian noise:
    single low-deviation spike with no recent history on that segment.
    Fast path — no model call needed.

Layer 2 — trained classifier:
    Everything that passes the filter is scored by the random forest.
    Outputs: classification (NOISE / DDOS / PORT_SCAN) + confidence.

Output published to threat-reports topic:
    segment, classification, confidence, severity,
    recommended_action, evidence dict.
"""

from __future__ import annotations
import json
import logging
import pickle
import time
from pathlib import Path

import numpy as np

from agents.base import BaseAgent
from agents._history import append_and_expire
from agents.aca_features import extract_features
from bus.message_bus import MessageBus
from core.messages import Message, Performative, Topic

logger = logging.getLogger(__name__)

MODEL_PATH    = Path(__file__).resolve().parent.parent / "models" / "aca_model.pkl"
FEEDBACK_PATH = Path(__file__).resolve().parent.parent / "models" / "aca_feedback.jsonl"

# How long a Layer-2 prediction stays eligible to be matched against a later
# resolution. RCA's own VOTE_WINDOW is 0.3s, so resolutions normally land
# within a second or two of the report — 60s gives generous slack for
# escalation/coalition paths without matching a stale, unrelated alert.
PREDICTION_CACHE_WINDOW = 60.0

# Layer-1 filter thresholds
NOISE_MAX_DEVIATION  = 3.0   # sigma — below this AND no history → noise
                             # (3.0 matches the trainer's DDOS_DEV_FLOOR, so
                             # first alerts in the 3-4σ band reach the model,
                             # which was trained on exactly that overlap zone)
NOISE_MAX_HISTORY    = 1     # alert count in 30s — at most this → noise

# Evidence window
HISTORY_WINDOW = 30.0        # seconds of alert history to keep per segment

RECOMMENDED_ACTIONS = {
    "NOISE":     "LOG_ONLY",
    "DDOS":      "QUARANTINE_SEGMENT",
    "PORT_SCAN": "BLOCK_SOURCE_IP",
}


class AnomalyClassifierAgent(BaseAgent):

    def __init__(self, agent_id: str, bus: MessageBus) -> None:
        super().__init__(agent_id, bus)

        # Load trained model
        with open(MODEL_PATH, "rb") as f:
            payload = pickle.load(f)
        self._clf    = payload["model"]
        self._labels = payload["labels"]   # ["NOISE", "DDOS", "PORT_SCAN"]

        # Per-segment alert history for context features
        self._history: dict[str, list[dict]] = {}

        # Per-segment cache of recent Layer-2 predictions (with the feature
        # vector that produced them), so a later resolution can be matched
        # back to the classification it confirms or overturns.
        self._pending_predictions: dict[str, list[dict]] = {}

        # Online-learning feedback buffer (FR-08): resolved incidents are
        # ground truth for the classifications that triggered them. A
        # RandomForest cannot update incrementally, so feedback accumulates
        # here as an audit trail (EXECUTED + REJECTED), while only EXECUTED
        # samples with a matched feature vector are persisted to
        # FEEDBACK_PATH for aca_trainer to fold into a retrain on request
        # (`python -m agents.aca_trainer --with-feedback`). REJECTED means
        # the coalition voted down the *action*, not confirmed ground
        # truth on the classification, so it is excluded from training.
        self.feedback_buffer: list[dict] = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        await super().start()
        self.subscribe(Topic.ALERTS, self._on_alert)
        self.subscribe(Topic.RESOLUTION, self._on_resolution)
        logger.info("[%s] ready — model loaded from %s", self.agent_id, MODEL_PATH)

    # ------------------------------------------------------------------
    # Online-learning hook  (FR-08)
    # ------------------------------------------------------------------

    async def _on_resolution(self, msg: Message) -> None:
        self.on_incident_resolved(msg.content)

    def on_incident_resolved(self, resolution: dict) -> None:
        """Record a resolved incident as labelled feedback. EXECUTED
        confirms the classification that opened the incident; REJECTED
        marks the *action* as voted down (a weaker, noisier signal — the
        classification itself may still have been correct), so only
        EXECUTED outcomes are persisted for retraining."""
        outcome = resolution.get("outcome", "")
        if outcome not in ("EXECUTED", "REJECTED"):
            return   # RELEASED etc. carry no classification verdict
        segment        = resolution.get("segment", "")
        classification = resolution.get("classification", "")
        self.feedback_buffer.append({
            "segment":        segment,
            "classification": classification,
            "action":         resolution.get("action", ""),
            "outcome":        outcome,
            "confidence":     resolution.get("confidence", 0.0),
            "time":           time.monotonic(),
        })
        if len(self.feedback_buffer) > 500:
            del self.feedback_buffer[: len(self.feedback_buffer) - 500]

        if outcome != "EXECUTED":
            return

        features = self._pop_matching_prediction(segment, classification)
        if features is None:
            return   # e.g. Layer-1 rule filter (no model prediction to confirm)
        self._persist_feedback_sample(features, classification)

    def _pop_matching_prediction(self, segment: str, classification: str) -> list[float] | None:
        """Find and remove the oldest cached Layer-2 prediction on `segment`
        that produced `classification` — i.e. the one most likely to have
        opened the incident this resolution refers to."""
        preds = self._pending_predictions.get(segment, [])
        for i, p in enumerate(preds):
            if p["classification"] == classification:
                return preds.pop(i)["features"]
        return None

    def _persist_feedback_sample(self, features: list[float], label: str) -> None:
        """Append one operator-confirmed (feature_vector, label) pair to
        FEEDBACK_PATH. Uses wall-clock time.time() (not monotonic) since
        this record is read back by a separate process/run."""
        record = {"features": features, "label": label, "time": time.time()}
        try:
            with open(FEEDBACK_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except OSError:
            logger.warning("[%s] failed to persist feedback sample", self.agent_id, exc_info=True)

    # ------------------------------------------------------------------
    # Alert handler
    # ------------------------------------------------------------------

    async def _on_alert(self, msg: Message) -> None:
        c   = msg.content
        seg = c["segment"]
        now = time.monotonic()

        # Update history
        self._history[seg] = append_and_expire(
            self._history.get(seg, []), {"time": now, **c}, now, HISTORY_WINDOW
        )

        # ── Layer 1: fast noise filter ────────────────────────────────
        dev         = c.get("deviation", 0.0)
        recent_hist = self._history[seg]
        recent_count = len(recent_hist)

        if (abs(dev) < NOISE_MAX_DEVIATION
                and c["anomaly_type"] == "VOLUME_SPIKE"
                and recent_count <= NOISE_MAX_HISTORY):
            await self._publish_report(
                seg, "NOISE", confidence=0.85,
                severity=c.get("severity", 0.0),
                content=c, evidence={"filter": "layer1_noise", "deviation": dev},
            )
            return

        # ── Layer 2: trained model ────────────────────────────────────
        features = extract_features(c, seg, now, self._history)
        proba    = self._clf.predict_proba([features])[0]
        label_idx  = int(np.argmax(proba))
        confidence = float(proba[label_idx])
        classification = self._labels[label_idx]

        # evidence summary — reuse the feature vector's own window stats
        # (recent_alert_count / max_deviation_30s / cross_segment_count)
        # instead of recomputing them a second time.
        evidence = {
            "alert_count_30s": int(features[6]),
            "max_deviation_30s": features[7],
            "cross_segment_count": int(features[8]),
            "port_count": c.get("port_count", 0),
            "filter": "layer2_model",
        }
        # Carry src_ip through so RCA can tell enforcement which IP to block
        if c.get("src_ip"):
            evidence["src_ip"] = c["src_ip"]

        self._pending_predictions[seg] = append_and_expire(
            self._pending_predictions.get(seg, []),
            {"time": now, "classification": classification, "features": features},
            now, PREDICTION_CACHE_WINDOW,
        )

        await self._publish_report(
            seg, classification, confidence,
            severity=c.get("severity", 0.0),
            content=c, evidence=evidence,
        )

    # ------------------------------------------------------------------
    # Publish threat report
    # ------------------------------------------------------------------

    async def _publish_report(
        self,
        segment:        str,
        classification: str,
        confidence:     float,
        severity:       float,
        content:        dict,
        evidence:       dict,
    ) -> None:
        await self.publish(
            topic        = Topic.THREAT_REPORTS,
            performative = Performative.INFORM,
            content      = {
                "segment":            segment,
                "classification":     classification,
                "confidence":         round(confidence, 3),
                "severity":           round(severity,   3),
                "recommended_action": RECOMMENDED_ACTIONS.get(
                                          classification, "INVESTIGATE"),
                "source_alert":       content.get("anomaly_type"),
                "evidence":           evidence,
            },
        )
        logger.info(
            "[%s] %-12s  seg=%-15s  conf=%.2f  sev=%.2f  action=%s",
            self.agent_id, classification, segment,
            confidence, severity,
            RECOMMENDED_ACTIONS.get(classification, "INVESTIGATE"),
        )
