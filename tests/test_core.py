import pytest

from curlrecon.core import ReconEngine
from curlrecon.models import TargetResult


@pytest.mark.asyncio
async def test_engine_initialization():
    engine = ReconEngine(method="POST", timeout=5.0)
    assert engine.method == "POST"
    assert engine.timeout == 5.0


@pytest.mark.asyncio
async def test_engine_run_invalid_url():
    engine = ReconEngine(timeout=1.0)
    results = await engine.run(["http://invalid.invalid"])
    assert len(results) == 1
    assert results[0].success is False
    assert results[0].error is not None
