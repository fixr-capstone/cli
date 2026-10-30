import io
import json
from pathlib import Path

from ml_filtering.normalizer.schema import RankedFinding
from rich.console import Console

from fixr_cli import __version__
from fixr_cli.engine import ScanResult, ToolRun
from fixr_cli.findings import is_likely_false_alarm
from fixr_cli.render import (
    _upgrade_phrase,
    build_report,
    failing,
    fix_prompt_text,
    render_text,
    to_json,
)

_FALSE = (
    "This is a false positive: the string is a status code, not a password. "
    "No change is required."
)
_REAL = "Explanation for this rule.\n\n```python\nfixed_code()\n```"


def test_upgrade_phrase_picks_the_release_that_clears_every_advisory() -> None:
    assert _upgrade_phrase("41.0.1", [["42.0.0", "41.0.7"], ["41.0.3"]]) == (
        "upgrade to 41.0.7 or later"
    )
    assert _upgrade_phrase("45.0.6", [["46.0.5"], ["48.0.1", "46.0.7"], []]) == (
        "upgrade to 46.0.7 or later (1 with no fixed release yet)"
    )
    assert _upgrade_phrase("1.0", [[], []]) == "no fixed release yet"


def _finding(**overrides: object) -> RankedFinding:
    data: dict[str, object] = {
        "tool": "bandit",
        "category": "security",
        "rule_id": "B101",
        "severity": "low",
        "file_path": "app.py",
        "line": 1,
        "message": "Use of assert detected",
        "tp_probability": 1.0,
        "priority_score": 1.0,
    }
    data.update(overrides)
    return RankedFinding(**data)


def _result(findings: list[RankedFinding], **overrides: object) -> ScanResult:
    data: dict[str, object] = {
        "root": Path("/tmp/proj"),
        "label": "proj",
        "tools": [
            ToolRun(tool="bandit", status="ran", raw=1200, seconds=0.34),
            ToolRun(tool="pip-audit", status="skipped", reason="no requirements file"),
            ToolRun(tool="deptry", status="failed", reason="deptry [exploded]"),
            ToolRun(tool="flake8", status="ran", raw=3, seconds=0.2),
        ],
        "findings": findings,
        "raw_total": 59,
        "deduped_total": 40,
        "bandit_total": 6,
        "bandit_judged": 4,
        "dropped_by_classifier": 1,
        "explain_status": "ok",
        "explained": 2,
        "seconds": 1.26,
    }
    data.update(overrides)
    return ScanResult(**data)


def _text(result: ScanResult, **kwargs: object) -> str:
    report = build_report(
        result,
        fail_on=str(kwargs.pop("fail_on", "high")),
        explain_limit=5,
    )
    buffer = io.StringIO()
    # A dumb terminal ignores width unless height is set as well.
    console = Console(file=buffer, record=True, width=120, height=40)
    render_text(report, console, show_style=bool(kwargs.get("show_style", False)))
    return buffer.getvalue()


def _kitchen() -> list[RankedFinding]:
    findings = [
        _finding(
            rule_id="B105",
            severity="high",
            file_path="models/response_codes.py",
            line=19,
            message="Possible hardcoded password: '1:pw'",
            snippet='19     SUCCESSFUL_PASSWORD_CHANGE = "1:pw"\n',
            metadata={"explanation": _FALSE, "test_name": "hardcoded_password_string"},
            priority_score=3.0,
        ),
        _finding(
            rule_id="B602",
            severity="high",
            file_path="app.py",
            line=4,
            message="subprocess call with shell=True identified, security issue.",
            snippet="4 subprocess.call(cmd, shell=True)\n",
            metadata={"explanation": _REAL},
            priority_score=2.5,
        ),
        _finding(
            tool="pip-audit",
            category="dependency",
            rule_id="PYSEC-1",
            severity="medium",
            file_path="anyio",
            line=None,
            message="### Impact\n\nServices using internationalized names are vulnerable.",
            metadata={
                "package": "anyio",
                "installed_version": "4.9.0",
                "fix_versions": ["4.14.2"],
                "aliases": ["CVE-1"],
            },
            priority_score=2.0,
        ),
        _finding(
            tool="pip-audit",
            category="dependency",
            rule_id="PYSEC-2",
            severity="medium",
            file_path="anyio",
            line=None,
            message="### Summary\n\nAnother hole.",
            metadata={
                "package": "anyio",
                "installed_version": "4.9.0",
                "fix_versions": ["4.15.0"],
                "aliases": [],
            },
            priority_score=1.9,
        ),
        _finding(
            tool="pip-audit",
            category="dependency",
            rule_id="PYSEC-9",
            severity="medium",
            file_path="oldpkg",
            line=None,
            message="### Description\n\nNo release fixes this.",
            metadata={"package": "oldpkg", "installed_version": "1.0.0", "fix_versions": []},
            priority_score=1.8,
        ),
        _finding(
            rule_id="B301",
            severity="medium",
            file_path="app.py",
            line=8,
            message="Use of [pickle] is unsafe",
            priority_score=1.5,
        ),
    ]
    for index in range(9):
        findings.append(
            _finding(
                rule_id="B101",
                severity="low",
                file_path=f"mod{index}.py",
                line=index + 1,
                message="Use of assert detected",
                priority_score=1.0,
            )
        )
    findings.extend(
        [
            _finding(
                tool="deptry",
                category="dependency",
                rule_id="DEP002",
                severity="low",
                file_path="requirements.txt",
                line=None,
                message="'aiohappyeyeballs' defined as a dependency but not used in the codebase",
                metadata={"module": "aiohappyeyeballs"},
            ),
            _finding(
                tool="deptry",
                category="dependency",
                rule_id="DEP002",
                severity="low",
                file_path="requirements.txt",
                line=None,
                message="'requests' defined as a dependency but not used in the codebase",
                metadata={"module": "requests"},
            ),
            _finding(
                tool="flake8",
                category="style",
                rule_id="E501",
                severity="low",
                file_path="client/__main__.py",
                line=9,
                message="line too long (117 > 79 characters)",
            ),
            _finding(
                tool="flake8",
                category="style",
                rule_id="W293",
                severity="low",
                file_path="client/__main__.py",
                line=12,
                message="blank line contains whitespace",
            ),
            _finding(
                tool="flake8",
                category="style",
                rule_id="E501",
                severity="high",
                file_path="client/other.py",
                line=3,
                message="line too long (200 > 79 characters)",
            ),
        ]
    )
    return findings


def test_text_report_covers_each_section() -> None:
    text = _text(_result(_kitchen()))
    assert "Fixr scan of proj (1.3s)" in text
    assert "bandit      ran     1,200 findings, 0.3s" in text
    assert "skipped: no requirements file" in text
    assert "failed: deptry [exploded]" in text
    assert "59 raw findings, 40 after removing duplicates." in text
    assert "The false-alarm classifier judged 4 of 6 Bandit findings and dropped 1." in text
    assert "Groq explained 2 findings." in text
    assert "1. HIGH  subprocess call with shell=True identified, security issue." in text
    assert "app.py:4  B602" in text
    assert "Flagged code:" in text
    assert "subprocess.call(cmd, shell=True)" in text
    assert "What is wrong:" in text
    assert "Explanation for this rule." in text
    assert "Suggested fix:" in text
    assert "fixed_code()" in text
    assert "Possible hardcoded password" not in text.split("Likely false alarms", 1)[0]
    assert "Vulnerable dependencies" in text
    assert "anyio 4.9.0: 2 advisories (PYSEC-1, PYSEC-2), upgrade to 4.15.0 or later" in text
    assert text.count("  requirements.txt") == 1
    assert "oldpkg 1.0.0: 1 advisory (PYSEC-9), no fixed release yet" in text
    assert "MEDIUM  B301  Use of [pickle] is unsafe (1)" in text
    assert "LOW  B101  Use of assert detected (9)" in text
    assert "mod0.py:1" in text
    assert "and 1 more" in text
    assert "LOW  DEP002  '…' defined as a dependency but not used in the codebase (2)" in text
    assert "names: aiohappyeyeballs, requests" in text
    assert "requirements.txt" in text
    assert "Likely false alarms" in text
    assert "models/response_codes.py:19  B105  Possible hardcoded password." in text
    assert "This is a false positive:" in text
    assert "3 style notes from flake8 across 2 rules (top: E501 2, W293 1)." in text
    assert "Run with --show-style to list them." in text
    assert "2 high, 4 medium, 11 low findings (style notes not counted)." in text
    assert "1 at or above --fail-on high (1 likely false alarm not counted)" in text
    assert "Nothing to fix." not in text


def test_long_code_lines_wrap_instead_of_being_cropped() -> None:
    flagged = 'if token == "True" and argv[index - 1].startswith("--"): continue'
    fix = 'if token == "True" and argv[index - 1].startswith(("--", "-")):  # nosec B105'
    finding = _finding(
        rule_id="B105",
        severity="high",
        file_path="cli.py",
        line=7,
        message="Possible hardcoded password: 'True'",
        snippet=f"7 {flagged}\n",
        metadata={"explanation": f"Explanation.\n\n```python\n{fix}\n```"},
        priority_score=3.0,
    )
    report = build_report(_result([finding]), fail_on="high", explain_limit=5)
    buffer = io.StringIO()
    console = Console(file=buffer, width=40, height=40)
    render_text(report, console, show_style=False)
    text = "".join(buffer.getvalue().split())
    assert "".join(flagged.split()) in text
    assert "".join(fix.split()) in text


def test_show_style_lists_rules_without_the_length_count() -> None:
    text = _text(_result(_kitchen()), show_style=True)
    assert "Run with --show-style" not in text
    assert "line too long" in text
    assert "(117 > 79 characters)" not in text
    assert "client/__main__.py:9" in text


def test_untrained_bandit_rules_use_the_kept_sentence() -> None:
    result = _result([], bandit_total=3, bandit_judged=0, dropped_by_classifier=0, explained=0)
    text = _text(result)
    assert (
        "None of the 3 Bandit findings use a rule the false-alarm classifier "
        "was trained on, so all were kept."
    ) in text
    assert "Nothing to fix." in text


def test_explain_status_lines() -> None:
    assert "No Bandit findings to explain." in _text(
        _result([], explain_status="ok", explained=0, bandit_total=0)
    )
    assert "Explanations are off (--no-explain)." in _text(
        _result([], explain_status="off", explained=0)
    )
    assert "Groq explained 1 of the top findings; the rest failed." in _text(
        _result([], explain_status="partial", explained=1)
    )
    assert "Explanations failed; showing scanner output only." in _text(
        _result([], explain_status="failed", explained=0)
    )


def test_no_key_notice_uses_the_limit() -> None:
    report_text = io.StringIO()
    result = _result([], explain_status="no-key", explained=0, bandit_total=0)
    report = build_report(result, explain_limit=7)
    render_text(report, Console(file=report_text, record=True, width=120, height=40))
    text = report_text.getvalue()
    assert "Set GROQ_API_KEY to have Groq explain the top 7 Bandit findings." in text
    assert "Only those functions are sent." in text
    assert "Nothing to fix." in text


def test_rule_text_without_an_explanation_is_not_a_false_alarm() -> None:
    findings = [
        _finding(
            rule_id="B105",
            severity="high",
            message="This is a false positive.",
            metadata={},
        )
    ]
    report = build_report(_result(findings, explain_status="off", explained=0))
    assert report.false_alarm == [False]
    assert is_likely_false_alarm(report.display[0].description) is True
    assert failing(report) == [0]


def test_failing_respects_threshold_style_and_false_alarms() -> None:
    findings = _kitchen()
    report = build_report(_result(findings), fail_on="high")
    assert [report.display[index].rule for index in failing(report)] == ["B602"]
    medium = build_report(_result(findings), fail_on="medium")
    assert "B301" in [report.display[index].rule for index in failing(medium)]
    assert "PYSEC-1" in [report.api[index]["rule_id"] for index in failing(medium)]
    assert failing(build_report(_result(findings), fail_on="none")) == []
    low = build_report(_result(findings), fail_on="low")
    assert "E501" not in [report.display[index].rule for index in failing(low)]
    unknown = build_report(
        _result([_finding(severity="unknown", rule_id="B999")]),
        fail_on="medium",
    )
    assert failing(unknown) == []
    assert failing(build_report(_result([_finding(severity="unknown")]), fail_on="low")) == [0]


def test_json_schema_and_round_seconds() -> None:
    report = build_report(_result(_kitchen()), fail_on="high", explain_limit=5)
    payload = to_json(report)
    encoded = json.dumps(payload)
    parsed = json.loads(encoded)
    assert set(parsed) == {
        "version",
        "target",
        "seconds",
        "fail_on",
        "tools",
        "counts",
        "explanations",
        "findings",
    }
    assert parsed["version"] == __version__
    assert parsed["target"] == "proj"
    assert parsed["seconds"] == 1.3
    assert parsed["tools"][0]["seconds"] == 0.3
    assert parsed["tools"][1]["reason"] == "no requirements file"
    assert parsed["tools"][2]["status"] == "failed"
    assert parsed["counts"]["raw"] == 59
    assert parsed["counts"]["deduplicated"] == 40
    assert parsed["counts"]["ranked"] == len(parsed["findings"])
    assert parsed["counts"]["style"] == 3
    assert parsed["counts"]["likely_false_alarms"] == 1
    assert parsed["counts"]["failing"] == 1
    assert parsed["explanations"] == {"status": "ok", "explained": 2, "limit": 5}
    assert parsed["findings"][0]["id"] == "api0"
    assert parsed["findings"][0]["likely_false_alarm"] is True
    assert parsed["findings"][1]["likely_false_alarm"] is False
    assert "message" in parsed["findings"][2]


def test_fix_prompt_shelves_only_flagged_descriptions() -> None:
    report = build_report(_result(_kitchen()))
    prompt = fix_prompt_text(report)
    assert "## Likely false alarms, leave these alone" in prompt
    assert "models/response_codes.py:19" in prompt
    bare = build_report(
        _result(
            [_finding(rule_id="B105", severity="high", message="This is a false positive.")],
            explain_status="off",
            explained=0,
        )
    )
    assert "## Likely false alarms" not in fix_prompt_text(bare)


def test_footer_hides_the_fail_line_when_fail_on_is_none() -> None:
    text = _text(_result(_kitchen()), fail_on="none")
    assert "--fail-on" not in text


def _doubted() -> RankedFinding:
    return _finding(
        rule_id="B324",
        severity="high",
        file_path="app.py",
        line=33,
        message="Use of weak MD5 hash for security.",
        tp_probability=0.04,
        priority_score=0.12,
        metadata={"likely_false_alarm": True},
    )


def test_a_kept_high_severity_finding_the_classifier_doubts_is_a_likely_false_alarm() -> None:
    # No Groq explanation is needed: the website files these under "Likely false alarms" too.
    report = build_report(_result([_doubted(), _finding(rule_id="B602", severity="high", line=4)]))

    assert report.false_alarm == [True, False]
    assert len(failing(report)) == 1
    counts = to_json(report)["counts"]
    assert counts["likely_false_alarms"] == 1
    assert counts["failing"] == 1
    assert to_json(report)["findings"][0]["likely_false_alarm"] is True

    text = _text(_result([_doubted()]))
    assert "Likely false alarms" in text
    assert "app.py:33  B324  Use of weak MD5 hash for security. Likely false alarm:" in text
    assert "chance this is real" in text
    assert "Nothing to fix." in text
    assert "0 at or above --fail-on high (1 likely false alarm not counted)" in text

    prompt = fix_prompt_text(build_report(_result([_doubted()])))
    assert "and 1 likely false alarm." in prompt
    assert "## Likely false alarms, leave these alone" in prompt
    assert "## Fix these" not in prompt
