"""
WebSocket transport: broadcasts a state snapshot to every connected
browser every 200 ms, and dispatches inbound scenario/control commands
to the SimEngine. Attach an engine with attach() before starting the app.
"""

from __future__ import annotations
import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

router = APIRouter()
_clients: list[WebSocket] = []
_engine = None


def attach(engine) -> None:
    """Register the SimEngine this module's route/broadcast loop drives."""
    global _engine
    _engine = engine


async def broadcast_loop() -> None:
    """Push a state snapshot to every connected WebSocket every 200 ms."""
    while True:
        await asyncio.sleep(0.2)
        if not _clients:
            continue
        try:
            payload = json.dumps(_engine.snapshot())
        except Exception as exc:
            logger.error("snapshot error: %s", exc)
            continue
        dead = []
        for ws in list(_clients):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in _clients:
                _clients.remove(ws)


async def _dispatch_command(msg: dict) -> None:
    if msg.get("type") == "scenario":
        await _engine.set_scenario(msg["name"], msg.get("segment"))
    elif msg.get("type") == "control":
        action = msg.get("action")
        if action == "reset_metrics":
            _engine.sc.reset_metrics()
        elif action == "pause":
            await _engine.pause()
        elif action == "resume":
            await _engine.resume()


@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    _clients.append(ws)
    try:
        while True:
            # Accept any incoming messages (e.g., ping or future controls)
            data = await ws.receive_text()
            try:
                await _dispatch_command(json.loads(data))
            except Exception:
                pass
    except WebSocketDisconnect:
        pass
    finally:
        if ws in _clients:
            _clients.remove(ws)
