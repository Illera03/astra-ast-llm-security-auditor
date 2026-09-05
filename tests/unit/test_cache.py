import os
from pathlib import Path

import pytest

from app.core.cache import AnalysisCache
from app.llm.client import LLMResponse


@pytest.fixture
def temp_cache(tmp_path: Path) -> AnalysisCache:
    """Fixture to provide a clean, temporary database for each test."""
    db_file = os.path.join(tmp_path, "test_cache.db")
    return AnalysisCache(db_path=db_file)


def test_cache_miss_returns_none(temp_cache: AnalysisCache) -> None:
    """Test that retrieving an unknown context returns None."""
    result = temp_cache.get("def unknown_func(): pass")
    assert result is None


def test_cache_hit_returns_saved_response(temp_cache: AnalysisCache) -> None:
    """Test that saving and retrieving a context works perfectly."""
    context_code = "subprocess.run(user_input)"
    fake_response = LLMResponse(
        is_exploitable=True,
        confidence=0.95,
        exploit_path="Data flows directly to OS command",
    )

    # 1. Save to cache
    temp_cache.set(context_code, fake_response)

    # 2. Retrieve from cache
    cached_result = temp_cache.get(context_code)

    assert cached_result is not None
    assert cached_result.is_exploitable is True
    assert cached_result.confidence == 0.95
    assert cached_result.exploit_path == "Data flows directly to OS command"
