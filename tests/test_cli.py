import json
import subprocess
import sys
from pathlib import Path

import pytest

from fixr_cli import __version__
from fixr_cli.cli import main
from fixr_cli.engine import scan


def test_importing_the_cli_stays_light() -> None:
    heavy = ("fixr_cli.engine", "xgboost", "groq", "bandit", "flake8", "fixr_rag")
    probe = f"import sys, fixr_cli.cli; print([m for m in {heavy!r} if m in sys.modules])"
    loaded = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    ).stdout.strip()
    assert loaded == "[]"


_VULNERABLE = """\
import pickle
import subprocess

x = 1
password = "hunter2"
assert x
data = b""
pickle.loads(data)
cmd = "ls"
subprocess.call(cmd, shell=True)
"""

_B105 = 'password = "hunter2"\n'


class _Choice:
    def __init__(self, content: str) -> None:
        self.message = type("Message", (), {"content": content})()
        self.finish_reason = "stop"


class _Response:
    def __init__(self, content: str) -> None:
        self.choices = [_Choice(content)]


class _Completions:
    def __init__(self, stub: "StubGroq") -> None:
        self._stub = stub

    async def create(self, **kwargs: object) -> _Response:
        self._stub.calls.append(kwargs)
        prompt = ""
        messages = kwargs.get("messages")
        if isinstance(messages, list):
            for message in messages:
                if isinstance(message, dict) and message.get("role") == "user":
                    content = message.get("content")
                    if isinstance(content, str):
                        prompt = content
        if "Rule: B105" in prompt:
            text = (
                "This is a false positive: the string is a status code, not a password. "
                "No change is required."
            )
        else:
            text = "Explanation for this rule.\n\n```python\nfixed_code()\n```"
        return _Response(text)


class _Chat:
    def __init__(self, stub: "StubGroq") -> None:
        self.completions = _Completions(stub)


class StubGroq:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.chat = _Chat(self)


@pytest.fixture(autouse=True)
def _no_groq_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)


def _project(tmp_path: Path, source: str, name: str = "sample") -> Path:
    root = tmp_path / name
    root.mkdir()
    (root / "app.py").write_text(source, encoding="utf-8")
    return root


def test_version() -> None:
    assert main(["--version"]) == 0


def test_version_text(capsys: pytest.CaptureFixture[str]) -> None:
    main(["--version"])
    assert capsys.readouterr().out.strip() == f"fixr {__version__}"


def test_no_subcommand_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "scan" in captured.err


def test_explain_zero_is_a_usage_error() -> None:
    assert main(["scan", "--explain", "0"]) == 2


def test_missing_path(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    missing = tmp_path / "no-such-project"
    assert main(["scan", str(missing), "--no-explain"]) == 2
    assert "fixr: error:" in capsys.readouterr().err


def test_json_schema_marks_b105(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    project = _project(tmp_path, _VULNERABLE)
    prompt = tmp_path / "out.md"
    stub = StubGroq()
    code = main(
        ["scan", str(project), "--format", "json", "--fix-prompt", str(prompt)],
        groq_client=stub,
    )
    assert code == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert {
        "version",
        "target",
        "seconds",
        "fail_on",
        "tools",
        "counts",
        "explanations",
        "findings",
    } <= set(data)
    assert data["version"] == __version__
    assert data["fail_on"] == "high"
    assert data["explanations"]["status"] == "ok"
    assert data["counts"]["failing"] >= 1
    b105 = next(item for item in data["findings"] if item["rule_id"] == "B105")
    assert b105["likely_false_alarm"] is True
    assert b105["id"].startswith("api")
    assert "Fix prompt for an AI coding tool written to" in captured.err
    assert "## Likely false alarms, leave these alone" in prompt.read_text(encoding="utf-8")
    assert stub.calls


def test_fail_on_none_exits_zero(tmp_path: Path) -> None:
    project = _project(tmp_path, _VULNERABLE, name="none")
    assert main(["scan", str(project), "--fail-on", "none"], groq_client=StubGroq()) == 0


def test_fail_on_medium_exits_one(tmp_path: Path) -> None:
    project = _project(tmp_path, _VULNERABLE, name="medium")
    assert main(["scan", str(project), "--fail-on", "medium"], groq_client=StubGroq()) == 1


def test_b105_alone_is_not_a_failure(tmp_path: Path) -> None:
    project = _project(tmp_path, _B105, name="password")
    assert main(["scan", str(project)], groq_client=StubGroq()) == 0


def test_fix_prompt_file(tmp_path: Path) -> None:
    project = _project(tmp_path, _VULNERABLE, name="prompt")
    destination = tmp_path / "fixes.md"
    code = main(
        ["scan", str(project), "--fix-prompt", str(destination)],
        groq_client=StubGroq(),
    )
    assert code == 1
    assert "## Likely false alarms, leave these alone" in destination.read_text(encoding="utf-8")


def test_no_key_notice(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    project = _project(tmp_path, _VULNERABLE, name="nokey")
    code = main(["scan", str(project)])
    assert code in (0, 1)
    captured = capsys.readouterr().out
    assert "GROQ_API_KEY" in captured
    assert "functions are sent." in captured


def test_json_no_key_notice_goes_to_stderr(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    project = _project(tmp_path, "x = 1\n", name="jsonkey")
    assert main(["scan", str(project), "--format", "json"]) == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["explanations"]["status"] == "no-key"
    assert "GROQ_API_KEY" in captured.err
    assert "GROQ_API_KEY" not in captured.out


def test_clean_project_has_nothing_to_fix(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    project = _project(tmp_path, "x = 1\n", name="clean")
    assert main(["scan", str(project), "--no-explain"]) == 0
    assert "Nothing to fix." in capsys.readouterr().out


def test_no_explain_does_not_call_groq(tmp_path: Path) -> None:
    project = _project(tmp_path, _VULNERABLE, name="quiet")
    stub = StubGroq()
    main(["scan", str(project), "--no-explain", "--fail-on", "none"], groq_client=stub)
    assert stub.calls == []


def test_cannot_write_fix_prompt(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    project = _project(tmp_path, "x = 1\n", name="unwritable")
    code = main(["scan", str(project), "--no-explain", "--fix-prompt", str(tmp_path)])
    assert code == 2
    assert "fixr: error: cannot write" in capsys.readouterr().err


def test_keyboard_interrupt(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("fixr_cli.engine.scan", boom)
    assert main(["scan", str(tmp_path)]) == 130


def test_progress_messages(tmp_path: Path) -> None:
    project = _project(tmp_path, _B105, name="progress")
    quiet: list[str] = []
    scan(project, explain=False, on_progress=quiet.append)
    assert "Ranking findings" in quiet
    assert not any("Groq" in message for message in quiet)

    explained: list[str] = []
    scan(project, groq_client=StubGroq(), on_progress=explained.append)
    assert "Ranking findings" in explained
    assert any(
        message.startswith("Explaining the top ") and message.endswith(" Bandit findings with Groq")
        for message in explained
    )
