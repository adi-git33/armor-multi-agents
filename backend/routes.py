"""Plain HTTP routes (non-WebSocket) for the dashboard server."""

from __future__ import annotations
import pathlib

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

FRONTEND = pathlib.Path(__file__).parent / "frontend" / "index.html"


@router.get("/")
async def root():
    if FRONTEND.exists():
        return HTMLResponse(FRONTEND.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Frontend not found</h1>"
                        "<p>Create <code>frontend/index.html</code></p>")
