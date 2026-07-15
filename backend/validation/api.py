"""
validation/api.py — HTTP + WebSocket surface for the validation suites
========================================================================
Exposes what previously only ran from the CLI (`python validation/run_validation.py`)
to the frontend's Validation page:

  GET  /api/validation/suites   -> suite metadata (id/label/title/rough duration)
  WS   /api/validation/ws       -> run one suite or all of them, streaming
                                    suite-started / check-completed /
                                    suite-completed / run-completed events

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
from validation.visualize_results import export_charts  # noqa: E402
import validation.helpers as _helpers_pkg  # noqa: E402
import helpers as _helpers_bare  # noqa: E402  (bare name — see module docstring)

router = APIRouter(prefix="/api/validation", tags=["validation"])

# Rough expected durations (seconds) — purely informational, shown in the
# control bar so users know what they're about to click. Derived from the
# sleep/run windows in each validate_*.py; "scenarios" runs all 6 SRS §8
# scenarios and is genuinely the long pole.
SUITE_META = {
    "tma":       {"title": "Traffic Monitor Agent",   "est_sec": 35},
    "aca":       {"title": "Anomaly Classifier Agent", "est_sec": 30},
    "rca":       {"title": "Response Coordinator Agent", "est_sec": 25},
    "tia":       {"title": "Threat Intelligence Agent", "est_sec": 30},
    "raa":       {"title": "Resource Allocator Agent", "est_sec": 30},
    "system":    {"title": "System-Level (FR-29..FR-34 + SW)", "est_sec": 45},
    "scenarios": {"title": "Scenarios (SRS §8, all 6)", "est_sec": 90},
}


@router.get("/suites")
async def list_suites() -> dict:
    suites = []
    for key, (module_name, label) in SUITES.items():
        meta = SUITE_META.get(key, {})
        suites.append({
            "id": key,
            "label": key.upper(),
            "full_label": label,
            "title": meta.get("title", label),
            "est_sec": meta.get("est_sec", 30),
            "module": module_name,
        })
    return {"suites": suites}


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
    keys = list(SUITES) if target == "all" else [target]
    if any(k not in SUITES for k in keys):
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
    t_run_start = time.monotonic()

    for key in keys:
        module_name, label = SUITES[key]
        emit({"type": "suite-started", "key": key, "label": label})

        def on_result(r, _key=key):
            emit({
                "type": "check-completed",
                "key": _key,
                "req_id": r.req_id,
                "label": r.label,
                "passed": r.passed,
                "observed": _jsonable(r.observed),
                "expected": _jsonable(r.expected),
                "note": r.note or "",
            })

        t0 = time.monotonic()
        tokens = _set_result_callback(on_result)
        try:
            suite = await run_suite(module_name)
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
        except Exception as exc:
            emit({"type": "suite-error", "key": key, "label": label, "message": str(exc)})
        finally:
            _reset_result_callback(tokens)

    total_wall = time.monotonic() - t_run_start
    all_results = [(label, r) for label, suite in suites_run for r in suite.results]
    total = len(all_results)
    passed = sum(1 for _, r in all_results if r.passed)
    target_table = build_srs_target_table(all_results)

    chart_paths: list[Path] = []
    try:
        chart_paths = export_charts(suites_run)
    except Exception:
        chart_paths = []

    emit({
        "type": "run-completed",
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "all_ok": (total - passed) == 0,
        "wall_sec": round(total_wall, 2),
        "target_table": target_table,
        "charts": [f"/charts/{p.name}" for p in chart_paths],
    })
    emit(None)
    await sender_task
