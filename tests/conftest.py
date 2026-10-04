from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _clear_explain_cache() -> Iterator[None]:
    from fixr_rag.explain import _cache

    _cache.clear()
    yield
    _cache.clear()
