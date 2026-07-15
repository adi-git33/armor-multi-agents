"""
validation/api.py — HTTP + WebSocket surface for the validation suites
========================================================================
Exposes what previously only ran from the CLI (`python validation/run_validation.py`)
to the frontend's Validation page:

  GET  /api/validation/suites   -> suite metadata (id/label/title/rough duration)
  GET  /api/validation/last     -> the last completed run, persisted to disk
  WS   /api/validation/ws       -> run one suite or all of them, streaming
                                    suite-started / check-completed /
                                    suite-completed / run-completed events
                                    (run-completed carries "metrics" — the
                                    structured numbers the frontend charts
                                    render from, no PNGs involved)

Deliberately does NOT reimplement the SRS §7.3 target-mapping logic —
it reuses build_srs_target_table() from run_validation.py, the same
function _print_master_summary() uses for the CLI table, so the two
surfaces can never drift apart.

Some suites (esp. "scenarios") run for over a minute of real asyncio.sleep()
time, so a single request/response would leave the browser staring at a
frozen spinner. A WebSocket lets us push each ValidationResult the moment
`suite.check()` produces it — see the result-callback hook added to
ValidationSuite in helpers.py (set_result_callback/reset_result_callback).

Why callbacks are set on *two* modules (see _set_result_callback below):
validate_tma.py loads helpers.py under the module name "validation.helpers"
(matching a real package import); every other validate_*.py does a bare
`from helpers import ValidationSuite`, which Python caches under the
plain name "helpers" — a second, distinct module object with its own
ValidationSuite class and its own copy of the callback ContextVar. Both
must be registered so live streaming works no matter which suite is
running.
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

_HERE = Path(__file__).resolve().parent
_BACKEND = _HERE.parent
for _p in (str(_BACKEND), str(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from validation.run_validation import SUITES, run_suite, build_srs_target_table  # noqa: E402
from validation.visualize_results import aggregate_metrics, degradation_panel_data  # noqa: E402
import validation.helpers as _helpers_pkg  # noqa: E402
import helpers as _helpers_bare  # noqa: E402  (bare name — see module docstring)

router = APIRouter(prefix="/api/validation", tags=["validation"])

_LAST_RUN_PATH = _HERE / "last_run.json"

# The web UI groups suites into "agent" suites (run each agent's own
# validate_*.py) and "scenario" suites (the six SRS §8 scenarios, each
# independently runnable — see validate_scenarios.py's run_s1..run_s6).
# The legacy combined "scenarios" key still exists in SUITES for CLI/back-
# compat (`--suite scenarios`) but isn't exposed as its own button — the
# web "run all scenarios" action runs s1..s6 individually instead, which
# streams live progress per-scenario instead of one 90s black box.
AGENT_SUITE_KEYS = ["tma", "aca", "rca", "tia", "raa", "system"]
SCENARIO_KEYS = ["s1", "s2", "s3", "s4", "s5", "s6"]

# Rough expected durations (seconds) — purely informational, shown in the
# control bar so users know what they're about to click. Derived from the
# sleep/run windows in each validate_*.py.
SUITE_META = {
    "tma":       {"title": "Traffic Monitor Agent",   "est_sec": 35},
    "aca":       {"title": "Anomaly Classifier Agent", "est_sec": 30},
    "rca":       {"title": "Response Coordinator Agent", "est_sec": 25},
    "tia":       {"title": "Threat Intelligence Agent", "est_sec": 30},
    "raa":       {"title": "Resource Allocator Agent", "est_sec": 30},
    "system":    {"title": "System-Level (FR-29..FR-34 + SW)", "est_sec": 45},
    "s1":        {"title": "Single-Segment DDoS Attack", "est_sec": 8},
    "s2":        {"title": "Multi-Segment Coordinated Attack", "est_sec": 16},
    "s3":        {"title": "Resource Contention Under Heavy Load", "est_sec": 8},
    "s4":        {"title": "Zero-Day / Novel Attack Detection", "est_sec": 8},
    "s5":        {"title": "Agent Failure & Resilience", "est_sec": 7},
    "s6":        {"title": "Voting Protocol Validation", "est_sec": 16},
}


def _resolve_keys(target: str) -> list[str] | None:
    if target == "all":
        return AGENT_SUITE_KEYS + SCENARIO_KEYS
    if target == "all_scenarios":
        return list(SCENARIO_KEYS)
    if target in SUITES:
        return [target]
    return None


@router.get("/suites")
async def list_suites() -> dict:
    suites = []
    for key in AGENT_SUITE_KEYS + SCENARIO_KEYS:
        module_name, label, _func_name = SUITES[key]
        meta = SUITE_META.get(key, {})
        suites.append({
            "id": key,
            "label": key.upper(),
            "full_label": label,
            "title": meta.get("title", label),
            "est_sec": meta.get("est_sec", 30),
            "module": module_name,
            "group": "scenario" if key in SCENARIO_KEYS else "agent",
        })
    return {"suites": suites}


@router.get("/last")
async def get_last_run() -> dict:
    if not _LAST_RUN_PATH.exists():
        return {"available": False}
    try:
        data = json.loads(_LAST_RUN_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"available": False}
    data["available"] = True
    return data


def _save_last_run(payload: dict) -> None:
    try:
        _LAST_RUN_PATH.write_text(json.dumps(payload, default=str), encoding="utf-8")
    except OSError:
        pass


def _set_result_callback(cb):
    tokens = []
    for mod in (_helpers_bare, _helpers_pkg):
        tokens.append((mod, mod.set_result_callback(cb)))
    return tokens


def _reset_result_callback(tokens) -> None:
    for mod, token in tokens:
        mod.reset_result_callback(token)


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


@router.websocket("/ws")
async def validation_ws(ws: WebSocket) -> None:
    await ws.accept()
    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue
            if msg.get("type") == "run":
                await _run_and_stream(ws, msg.get("suite", "all"))
    except WebSocketDisconnect:
        pass


async def _run_and_stream(ws: WebSocket, target: str) -> None:
    keys = _resolve_keys(target)
    if keys is None:
        await ws.send_text(json.dumps({"type": "error", "message": f"unknown suite '{target}'"}))
        return

    # A single queue + one sender task guarantees events reach the browser
    # in the exact order they were produced, even though check-completed
    # events are queued from inside a synchronous callback fired mid-suite.
    queue: asyncio.Queue = asyncio.Queue()

    def emit(evt: dict) -> None:
        queue.put_nowait(evt)

    async def sender() -> None:
        while True:
            evt = await queue.get()
            if evt is None:
                return
            try:
                await ws.send_text(json.dumps(evt, default=str))
            except Exception:
                return

    sender_task = asyncio.create_task(sender())

    suites_run: list[tuple[str, Any]] = []
    # Mirrors what's streamed to the browser, keyed by suite id, so the
    # completed run can be written to disk and reloaded verbatim on the
    # next page visit — see _save_last_run() / GET /api/validation/last.
    per_suite_snapshot: dict[str, dict] = {}
    t_run_start = time.monotonic()

    for key in keys:
        module_name, label, func_name = SUITES[key]
        emit({"type": "suite-started", "key": key, "label": label})
        results_snapshot: list[dict] = []

        def on_result(r, _key=key, _sink=results_snapshot):
            payload = {
                "req_id": r.req_id,
                "label": r.label,
                "passed": r.passed,
                "observed": _jsonable(r.observed),
                "expected": _jsonable(r.expected),
                "note": r.note or "",
            }
            _sink.append(payload)
            emit({"type": "check-completed", "key": _key, **payload})

        t0 = time.monotonic()
        tokens = _set_result_callback(on_result)
        try:
            suite = await run_suite(module_name, func_name)
            suites_run.append((label, suite))
            wall = time.monotonic() - t0
            emit({
                "type": "suite-completed",
                "key": key,
                "label": label,
                "pass_count": suite.pass_count,
                "total_count": suite.total_count,
                "all_passed": suite.all_passed,
                "wall_sec": round(wall, 2),
            })
            per_suite_snapshot[key] = {
                "label": label,
                "status": "done",
                "pass_count": suite.pass_count,
                "total_count": suite.total_count,
                "all_passed": suite.all_passed,
                "wall_sec": round(wall, 2),
                "results": results_snapshot,
            }
        except Exception as exc:
            emit({"type": "suite-error", "key": key, "label": label, "message": str(exc)})
            per_suite_snapshot[key] = {
                "label": label,
                "status": "error",
                "error_message": str(exc),
                "results": results_snapshot,
            }
        finally:
            _reset_result_callback(tokens)

    total_wall = time.monotonic() - t_run_start
    all_results = [(label, r) for label, suite in suites_run for r in suite.results]
    total = len(all_results)
    passed = sum(1 for _, r in all_results if r.passed)
    target_table = build_srs_target_table(all_results)

    # Structured numbers instead of pre-rendered PNGs — the frontend renders
    # its own charts from this (see ValidationCharts/*), so it can add
    # tooltips, resize, and follow the app's own theme instead of shipping a
    # static image. degradation_panel_data() is a fixed illustrative
    # comparison, not derived from suites_run, so it's included every run.
    metrics = aggregate_metrics(suites_run)
    metrics["degradation"] = degradation_panel_data()

    run_completed = {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "all_ok": (total - passed) == 0,
        "wall_sec": round(total_wall, 2),
        "target_table": target_table,
        "metrics": metrics,
    }
    emit({"type": "run-completed", **run_completed})
    emit(None)
    await sender_task

    _save_last_run({
        "timestamp": time.time(),
        "target": target,
        "keys": keys,
        "per_suite": per_suite_snapshot,
        **run_completed,
    })
