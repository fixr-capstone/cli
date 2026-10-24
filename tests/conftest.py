from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _plain_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    # Tests compare rendered text; these make rich write colour codes into it.
    for name in ("FORCE_COLOR", "TTY_COMPATIBLE", "TTY_INTERACTIVE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _clear_explain_cache() -> Iterator[None]:
    from fixr_rag.explain import _cache

    _cache.clear()
    yield
    _cache.clear()
