"""
Shared pytest configuration for the backend test suite.

pytest.ini sets `pythonpath = .` so these tests import bus/core/simulation/
agents the same way the rest of the backend does (no package prefix), and
`asyncio_mode = auto` so `async def test_*` functions run without an
explicit @pytest.mark.asyncio on each one.
"""
