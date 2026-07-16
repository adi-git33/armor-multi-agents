"""
Anomaly Classifier Agent  (SDD §4.3)
======================================
Subscribes to TMA alerts, classifies them using a pre-trained
DecisionTreeClassifier, and publishes threat reports.

Two-layer design
-----------------
Layer 1 — rule filter:
    Dismiss alerts that are almost certainly Gaussian noise:
    single low-deviation spike with no recent history on that segment.
    Fast path — no model call needed.

Layer 2 — trained classifier:
    Everything that passes the filter is scored by the decision tree.
    Outputs: classification (NOISE / DDOS / PORT_SCAN) + confidence.

Output published to threat-reports topic:
    segment, classification, confidence, severity,
    recommended_action, evidence dict.
"""

from __future__ import annotations
import logging
import pickle
import time
from pathlib import Path

import numpy as np

from agents.base import BaseAgent
from bus.message_bus import MessageBus
from core.messages import Message, Performative, Topic

logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "aca_model.pkl"

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

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        await super().start()
        self.bus.subscribe(Topic.ALERTS, self._on_alert)
        logger.info("[%s] ready — model loaded from %s", self.agent_id, MODEL_PATH)

    # ------------------------------------------------------------------
    # Alert handler
    # ------------------------------------------------------------------

    async def _on_alert(self, msg: Message) -> None:
        if not self._running:
            return

        c   = msg.content
        seg = c["segment"]
        now = time.monotonic()

        # Update history
        if seg not in self._history:
            self._history[seg] = []
        self._history[seg].append({"time": now, **c})

        # Expire old entries
        self._history[seg] = [
            a for a in self._history[seg]
            if now - a["time"] <= HISTORY_WINDOW
        ]

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
        features = self._extract_features(c, seg, now)
        proba    = self._clf.predict_proba([features])[0]
        label_idx  = int(np.argmax(proba))
        confidence = float(proba[label_idx])
        classification = self._labels[label_idx]

        # evidence summary
        window_devs = [a.get("deviation", 0.0) for a in recent_hist]
        cross = sum(
            1 for s, hist in self._history.items()
            if s != seg and any(now - a["time"] <= 5.0 for a in hist)
        )
        evidence = {
            "alert_count_30s": recent_count,
            "max_deviation_30s": max(window_devs, default=dev),
            "cross_segment_count": cross,
            "port_count": c.get("port_count", 0),
            "filter": "layer2_model",
        }
        # Carry src_ip through so RCA can tell enforcement which IP to block
        if c.get("src_ip"):
            evidence["src_ip"] = c["src_ip"]

        await self._publish_report(
            seg, classification, confidence,
            severity=c.get("severity", 0.0),
            content=c, evidence=evidence,
        )

    # ------------------------------------------------------------------
    # Feature extraction  (must match aca_trainer.py FEATURE_NAMES)
    # ------------------------------------------------------------------

    def _extract_features(
        self, c: dict, seg: str, now: float
    ) -> list[float]:
        enc  = 1.0 if c["anomaly_type"] == "PORT_SCAN" else 0.0
        dev  = float(c.get("deviation",         0.0))
        sev  = float(c.get("severity",          0.0))
        pc   = float(c.get("port_count",        0))
        pgr  = float(c.get("port_growth_rate",  0.0))
        esc  = float(c.get("elapsed_scan_secs", 0.0))

        hist   = self._history.get(seg, [])
        window = [a for a in hist if now - a["time"] <= 30.0]
        recent_count = float(len(window))
        max_dev      = float(max((a.get("deviation", 0.0) for a in window),
                                  default=dev))
        cross = float(sum(
            1 for s, h in self._history.items()
            if s != seg and any(now - a["time"] <= 5.0 for a in h)
        ))

        # Order must match FEATURE_NAMES in aca_trainer.py
        return [enc, dev, sev, pc, pgr, esc, recent_count, max_dev, cross]

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
