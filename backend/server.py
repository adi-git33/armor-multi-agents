"""
Cyber-Defense MAS  —  FastAPI visualization server
====================================================
Runs all five defense agents in-process alongside the web server.
State is streamed to connected browsers via WebSocket every 200 ms.

Start:
    pip install fastapi uvicorn
    python -m agents.aca_trainer          # once — trains the ML model
    uvicorn server:app --port 8000

Then open:  http://localhost:8000
"""

import asyncio
import logging
import pathlib
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# Ensure intra-backend imports (bus/core/simulation/agents) resolve whether
# this module is loaded as `server` or `backend.server`.
BACKEND_ROOT = pathlib.Path(__file__).resolve().parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from sim_engine import SimEngine
import routes
import websocket

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

engine = SimEngine()
websocket.attach(engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await engine.start()
    # Seed the default scenario so there is something to see immediately
    await engine.set_scenario("calm")
    asyncio.create_task(websocket.broadcast_loop())
    yield
    await engine.stop()


app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)
app.include_router(routes.router)
app.include_router(websocket.router)

# Validation suite runner -- separate page/concern from the live dashboard
# above. The router owns /api/validation/suites + /api/validation/ws;
# charts/ is mounted here (not inside the router) since StaticFiles needs
# an app-level mount point.
from validation.api import router as validation_router  # noqa: E402

app.include_router(validation_router)
_CHARTS_DIR = pathlib.Path(__file__).parent / "validation" / "charts"
_CHARTS_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/charts", StaticFiles(directory=str(_CHARTS_DIR)), name="charts")
