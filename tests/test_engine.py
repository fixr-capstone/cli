from pathlib import Path

import pytest

from fixr_cli import engine
from fixr_cli.engine import scan

_SAMPLE = "import subprocess\nsubprocess.call('ls', shell=True)\npassword = 'hunter2'\n"


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "sample"
    project.mkdir()
    (project / "app.py").write_text(_SAMPLE, encoding="utf-8")
    return project


class _Message:
    content = "stub explanation"


class _Choice:
    def __init__(self) -> None:
        self.message = _Message()
        self.finish_reason = "stop"


class _Response:
    def __init__(self) -> None:
        self.choices = [_Choice()]


class _Completions:
    async def create(self, **kwargs: object) -> _Response:
        return _Response()


class _Chat:
    def __init__(self) -> None:
        self.completions = _Completions()


class _StubClient:
    def __init__(self) -> None:
        self.chat = _Chat()


@pytest.mark.slow
def test_scan_without_dependency_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    result = scan(_project(tmp_path))

    by_tool = {run.tool: run for run in result.tools}
    assert by_tool["bandit"].status == "ran"
    assert by_tool["flake8"].status == "ran"
    assert by_tool["pip-audit"].status == "skipped"
    assert by_tool["deptry"].status == "skipped"
    assert by_tool["pip-audit"].reason == "no requirements.txt or pyproject.toml found"
    assert result.findings
    assert all(not Path(finding.file_path).is_absolute() for finding in result.findings)
    assert any(finding.file_path == "app.py" for finding in result.findings)
    assert result.explain_status == "no-key"
    assert result.explained == 0
    assert result.label == "sample"


@pytest.mark.slow
def test_scan_explains_with_stub_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    result = scan(_project(tmp_path), groq_client=_StubClient())

    assert result.explain_status == "ok"
    assert result.explained >= 1
    assert any(finding.metadata.get("explanation") == "stub explanation" for finding in result.findings)


@pytest.mark.slow
def test_failing_tool_does_not_stop_the_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original = engine.invoke_fixr

    def wrapper(cfg):
        if cfg.FIXR_CONFIG.invocation_order and cfg.FIXR_CONFIG.invocation_order[0] == "flake8":
            raise RuntimeError("flake8 exploded")
        return original(cfg)

    monkeypatch.setattr(engine, "invoke_fixr", wrapper)
    result = scan(_project(tmp_path), explain=False)

    by_tool = {run.tool: run for run in result.tools}
    assert by_tool["flake8"].status == "failed"
    assert by_tool["flake8"].reason == "flake8 exploded"
    assert by_tool["bandit"].status == "ran"
    assert by_tool["pip-audit"].status == "skipped"
    assert by_tool["deptry"].status == "skipped"
    assert result.explain_status == "off"


def test_pinned_requirements_fall_back_when_resolution_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _project(tmp_path)
    (project / "requirements.txt").write_text("requests==2.25.0\n", encoding="utf-8")
    original = engine.invoke_fixr
    attempts: list[bool] = []

    def wrapper(cfg):
        if cfg.FIXR_CONFIG.invocation_order[0] != "pip-audit":
            return original(cfg)
        attempts.append(cfg.PIP_AUDIT_ARGS_CONFIG.no_deps)
        if not cfg.PIP_AUDIT_ARGS_CONFIG.no_deps:
            raise SystemExit(1)
        output = Path(cfg.FIXR_CONFIG.common_directory) / "pip-audit.json"
        output.write_text('{"dependencies": [], "fixes": []}', encoding="utf-8")
        return 0

    monkeypatch.setattr(engine, "invoke_fixr", wrapper)
    result = scan(project, explain=False)

    audit = next(run for run in result.tools if run.tool == "pip-audit")
    assert attempts == [False, True]
    assert audit.status == "ran"
    assert audit.reason == engine.PINNED_ONLY
