"""
Shared pytest configuration for the backend test suite.

pytest.ini sets `pythonpath = .` so these tests import bus/core/simulation/
agents the same way the rest of the backend does (no package prefix), and
`asyncio_mode = auto` so `async def test_*` functions run without an
explicit @pytest.mark.asyncio on each one.
"""
import tempfile
from pathlib import Path

# Several tests spin up real AnomalyClassifierAgent instances wired to a
# live bus/RCA, whose genuine EXECUTED resolutions would otherwise be
# persisted straight into the production models/aca_feedback.jsonl (see
# agents/aca.py FEEDBACK_PATH) — silently contaminating real operator
# feedback with test-run data. Redirect it to a scratch file before any
# test module gets a chance to import agents.aca.
import agents.aca as _aca_module
import agents.aca_trainer as _aca_trainer_module

_scratch_feedback_path = Path(tempfile.gettempdir()) / "armor_test_aca_feedback.jsonl"
if _scratch_feedback_path.exists():
    _scratch_feedback_path.unlink()
_aca_module.FEEDBACK_PATH         = _scratch_feedback_path
_aca_trainer_module.FEEDBACK_PATH = _scratch_feedback_path
