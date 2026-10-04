import io
import json
from pathlib import Path

import pytest
from fixr_rag.chat import UNAVAILABLE
from ml_filtering.normalizer.schema import RankedFinding

from fixr_cli.chat import CHAT_FINDINGS, chat_payload, load_results, run_chat
from fixr_cli.cli import main
from fixr_cli.engine import ScanResult, ToolRun
from fixr_cli.findings import Finding
from fixr_cli.render import build_report, to_json


class _Delta:
    def __init__(self, content: str) -> None:
        self.content = content


class _Choice:
    def __init__(self, content: str) -> None:
        self.delta = _Delta(content)


class _Chunk:
    def __init__(self, content: str) -> None:
        self.choices = [_Choice(content)]


class _Stream:
    def __init__(self, parts: tuple[str, ...]) -> None:
        self._chunks = [_Chunk(part) for part in parts]

    def __aiter__(self) -> "_Stream":
        return self

    async def __anext__(self) -> _Chunk:
        if not self._chunks:
            raise StopAsyncIteration
        return self._chunks.pop(0)


class _Completions:
    def __init__(self, client: "_Client") -> None:
        self._client = client

    async def create(self, **kwargs: object) -> _Stream:
        self._client.calls.append(kwargs)
        if self._client.failures:
            self._client.failures -= 1
            raise RuntimeError("groq unavailable")
        return _Stream(self._client.parts)


class _Chat:
    def __init__(self, client: "_Client") -> None:
        self.completions = _Completions(client)


class _Client:
    """Streaming stand-in for Groq. ``failures`` makes the next creates raise."""

    def __init__(self, parts: tuple[str, ...] = ("Hello", " there."), *, failures: int = 0) -> None:
        self.parts = parts
        self.failures = failures
        self.calls: list[dict[str, object]] = []
        self.chat = _Chat(self)


class _Script:
    def __init__(self, lines: list[str]) -> None:
        self._lines = list(lines)
        self.prompts: list[str] = []

    def __call__(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self._lines:
            raise EOFError
        return self._lines.pop(0)


@pytest.fixture(autouse=True)
def _no_groq_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)


def _finding(
    *,
    id: str = "api0",
    severity: str = "high",
    title: str = "Hardcoded password",
    description: str = "A password is in the source.",
    file: str = "app.py",
    line: int = 2,
    snippet: str = 'password = "hunter2"',
    suggested_fix: str = "Use an environment variable.",
    style: bool = False,
    rule: str | None = "B105",
) -> Finding:
    return Finding(
        id=id,
        severity=severity,  # type: ignore[arg-type]
        title=title,
        description=description,
        file=file,
        line=line,
        snippet=snippet,
        suggested_fix=suggested_fix,
        style=style,
        rule=rule,
    )


def _messages(call: dict[str, object]) -> list[dict[str, str]]:
    messages = call["messages"]
    assert isinstance(messages, list)
    return messages


def _chat(
    findings: list[Finding],
    script: _Script,
    client: _Client | None = None,
) -> tuple[str, _Client]:
    stub = client or _Client()
    out = io.StringIO()
    code = run_chat(findings, label="proj", groq_client=stub, read=script, out=out)
    assert code == 0
    return out.getvalue(), stub


def test_question_streams_the_reply() -> None:
    findings = [
        _finding(),
        _finding(
            id="api1", severity="medium", title="Shell call", rule="B602", file="run.py", line=9
        ),
        _finding(id="style", title="line too long", style=True, rule="E501", severity="low"),
    ]
    text, stub = _chat(findings, _Script(["what is wrong?"]))
    assert "Chat about proj: 2 findings and 1 style notes." in text
    assert "  1. HIGH  B105  Hardcoded password  app.py:2" in text
    assert "  2. MEDIUM  B602  Shell call  run.py:9" in text
    assert "line too long" not in text
    assert "fixr> Hello there.\n" in text
    assert text.count("fixr> ") == 1
    assert stub.calls


def test_history_is_sent_with_the_next_question() -> None:
    _text, stub = _chat([_finding()], _Script(["what is wrong?", "and then?"]))
    messages = _messages(stub.calls[1])
    assert messages[0]["role"] == "system"
    assert messages[1] == {"role": "user", "content": "what is wrong?"}
    assert messages[2] == {"role": "assistant", "content": "Hello there."}
    assert messages[3] == {"role": "user", "content": "and then?"}


def test_focus_is_sent_with_the_question() -> None:
    findings = [
        _finding(id="api0", title="Hardcoded password"),
        _finding(
            id="api1", title="Shell call", rule="B602", severity="medium", file="run.py", line=4
        ),
    ]
    _text, stub = _chat(findings, _Script(["/focus 1", "why this one?"]))
    system = _messages(stub.calls[0])[0]["content"]
    assert "The person is asking about this finding in particular" in system
    assert "Hardcoded password (app.py:2)" in system
    assert system.index("Hardcoded password") < system.index("Shell call")


def test_focus_rejects_an_unknown_number() -> None:
    text, stub = _chat([_finding()], _Script(["/focus 99"]))
    assert "No finding 99; pick 1 to 1." in text
    assert stub.calls == []


def test_focus_off_clears_focus() -> None:
    text, _stub = _chat([_finding()], _Script(["/focus 1", "/focus off", "/focus"]))
    assert "Focused on 1. HIGH Hardcoded password app.py:2" in text
    assert text.count("Focus cleared.") == 2


def test_quit_stops_reading() -> None:
    calls = 0

    def read(prompt: str) -> str:
        nonlocal calls
        calls += 1
        assert prompt == "you> "
        if calls > 1:
            raise AssertionError("read past /quit")
        return "/quit"

    out = io.StringIO()
    assert run_chat([_finding()], label="proj", groq_client=_Client(), read=read, out=out) == 0
    assert calls == 1


def test_unknown_command() -> None:
    text, stub = _chat([_finding()], _Script(["/xyz"]))
    assert "Unknown command /xyz. Try /help." in text
    assert stub.calls == []


def test_unavailable_reply_is_not_remembered() -> None:
    stub = _Client(failures=1)
    text, _same = _chat([_finding()], _Script(["first question", "second question"]), stub)
    assert f"fixr> {UNAVAILABLE}" in text
    messages = _messages(stub.calls[1])
    contents = [message["content"] for message in messages]
    assert "first question" not in contents
    assert contents[-1] == "second question"
    assert all(message["role"] != "assistant" for message in messages)


def test_chat_payload_caps_clips_and_puts_focus_first() -> None:
    non_style = [
        _finding(
            id=f"n{index}",
            title="T" * 600,
            snippet="S" * 9000,
            description="D" * 9000,
            suggested_fix="F" * 9000,
            rule="R" * 40,
            file="P" * 600,
            line=index + 1,
        )
        for index in range(50)
    ]
    style = [
        _finding(id=f"s{index}", title=f"style {index}", style=True, rule="E501", severity="low")
        for index in range(8)
    ]
    payload = chat_payload([*non_style, *style], "n49")
    assert len(payload) == CHAT_FINDINGS + 5
    ids = [item["id"] for item in payload]
    assert ids[0] == "n49"
    assert ids[:CHAT_FINDINGS] == ["n49", *[f"n{index}" for index in range(CHAT_FINDINGS - 1)]]
    assert ids[CHAT_FINDINGS:] == [f"s{index}" for index in range(5)]
    assert "n39" not in ids
    assert "s5" not in ids
    first = payload[0]
    assert set(first) == {
        "id",
        "rule",
        "severity",
        "title",
        "file",
        "line",
        "snippet",
        "description",
        "suggestedFix",
        "style",
    }
    assert len(first["title"]) == 500
    assert len(first["file"]) == 500
    assert len(first["snippet"]) == 8000
    assert len(first["description"]) == 8000
    assert len(first["suggestedFix"]) == 8000
    assert first["rule"] == "R" * 32
    assert first["suggestedFix"] == "F" * 8000
    plain = chat_payload([_finding(rule=None, title="short")], None)[0]
    assert plain["rule"] is None
    assert plain["suggestedFix"] == "Use an environment variable."


def test_intro_omits_a_missing_line_and_summarises_the_rest() -> None:
    findings = [_finding(id=f"n{index}", line=0, rule=None, file="req.txt") for index in range(12)]
    text, _stub = _chat(findings, _Script(["/list"]))
    assert "  1. HIGH  Hardcoded password  req.txt" in text
    assert "req.txt:" not in text
    assert "  and 2 more (/list shows all)" in text
    assert "  12. HIGH  Hardcoded password  req.txt" in text


def test_load_results_round_trip(tmp_path: Path) -> None:
    ranked = [
        RankedFinding(
            tool="bandit",
            category="security",
            rule_id="B105",
            severity="high",
            file_path="app.py",
            line=3,
            message="Possible hardcoded password: 'hunter2'",
            snippet='password = "hunter2"\n',
            tp_probability=0.9,
            priority_score=2.0,
        ),
        RankedFinding(
            tool="flake8",
            category="style",
            rule_id="E501",
            severity="low",
            file_path="app.py",
            line=3,
            message="line too long (90 > 88 characters)",
            tp_probability=1.0,
            priority_score=0.1,
        ),
    ]
    result = ScanResult(
        root=tmp_path,
        label="sample",
        tools=[ToolRun(tool="bandit", status="ran", raw=1, seconds=0.1)],
        findings=ranked,
        raw_total=2,
        deduped_total=2,
        bandit_total=1,
        bandit_judged=1,
        dropped_by_classifier=0,
        explain_status="off",
        explained=0,
        seconds=0.2,
    )
    report = build_report(result)
    path = tmp_path / "results.json"
    path.write_text(json.dumps(to_json(report)), encoding="utf-8")
    label, loaded = load_results(path)
    assert label == "sample"
    shown = [(item.id, item.rule, item.style, item.file, item.line, item.title) for item in loaded]
    expected = [
        (item.id, item.rule, item.style, item.file, item.line, item.title)
        for item in report.display
    ]
    assert shown == expected


def test_load_results_rejects_bad_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        load_results(path)
    path.write_text('{"target": "x"}', encoding="utf-8")
    with pytest.raises(ValueError, match="findings"):
        load_results(path)
    path.write_text('{"findings": {}}', encoding="utf-8")
    with pytest.raises(ValueError, match="findings"):
        load_results(path)


def _report(tmp_path: Path) -> Path:
    result = ScanResult(
        root=tmp_path,
        label="saved",
        tools=[],
        findings=[
            RankedFinding(
                tool="bandit",
                category="security",
                rule_id="B105",
                severity="low",
                file_path="app.py",
                line=1,
                message="Possible hardcoded password: 'hunter2'",
                tp_probability=1.0,
                priority_score=1.0,
            )
        ],
        raw_total=1,
        deduped_total=1,
        bandit_total=1,
        bandit_judged=0,
        dropped_by_classifier=0,
        explain_status="off",
        explained=0,
        seconds=0.1,
    )
    path = tmp_path / "results.json"
    path.write_text(json.dumps(to_json(build_report(result))), encoding="utf-8")
    return path


def test_cli_chat_from_file(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    path = _report(tmp_path)
    stub = _Client()
    monkeypatch.setattr("builtins.input", _Script(["what is wrong?", "/quit"]))
    assert main(["chat", "--from", str(path)], groq_client=stub) == 0
    captured = capsys.readouterr()
    assert "Chat about saved:" in captured.out
    assert "fixr> Hello there." in captured.out
    assert stub.calls


def test_cli_chat_scans_a_project(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    project = tmp_path / "demo"
    project.mkdir()
    (project / "app.py").write_text('password = "hunter2"\n', encoding="utf-8")
    monkeypatch.setattr("builtins.input", lambda _prompt: "/quit")
    code = main(["chat", str(project), "--no-explain"], groq_client=_Client())
    assert code == 0
    output = capsys.readouterr().out
    assert "Chat about demo:" in output
    assert "app.py" in output


def test_cli_chat_needs_a_key(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    missing = tmp_path / "absent"
    code = main(["chat", str(missing)])
    assert code == 2
    error = capsys.readouterr().err
    assert "fixr: error: fixr chat needs a Groq API key. Set GROQ_API_KEY and try again." in error
    assert "path does not exist" not in error


def test_cli_chat_rejects_path_and_from(tmp_path: Path) -> None:
    code = main(
        ["chat", str(tmp_path), "--from", str(tmp_path / "r.json")],
        groq_client=_Client(),
    )
    assert code == 2


def test_cli_chat_missing_from_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    code = main(["chat", "--from", str(missing)], groq_client=_Client())
    assert code == 2
    assert f"fixr: error: cannot read {missing}:" in capsys.readouterr().err
