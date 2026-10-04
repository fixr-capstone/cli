import json
from pathlib import Path

import pytest

from fixr_cli.findings import matches_website_rule, to_finding
from fixr_cli.fix_prompt import build_fix_prompt

FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN = FIXTURES / "golden"
CASES = ["messy", "minor", "clean", "sample_project"]


def _load(case: str) -> tuple[list, list]:
    if case == "sample_project":
        raw = json.loads((FIXTURES / "sample_project_scan.json").read_text())["findings"]
    else:
        raw = json.loads((FIXTURES / "samples.json").read_text())[case]["findings"]
    findings = [to_finding(item, index) for index, item in enumerate(raw)]
    return [finding for finding in findings if not finding.style], [
        finding for finding in findings if finding.style
    ]


def _section(prompt: str, heading: str) -> str:
    lines = prompt.split("\n")
    start = next(index for index, line in enumerate(lines) if line.startswith(heading))
    end = next(
        (index for index in range(start + 1, len(lines)) if lines[index].startswith("## ")),
        len(lines),
    )
    return "\n".join(lines[start:end])


@pytest.mark.parametrize("case", CASES)
def test_build_fix_prompt_matches_golden(case: str) -> None:
    nonstyle, style = _load(case)
    expected = (GOLDEN / f"{case}.fix_prompt.md").read_bytes().decode()
    assert build_fix_prompt(nonstyle, style, is_false_alarm=matches_website_rule) == expected


def test_widened_predicate_shelves_response_code_passwords() -> None:
    nonstyle, style = _load("sample_project")
    prompt = build_fix_prompt(nonstyle, style)
    alarms = _section(prompt, "## Likely false alarms, leave these alone")
    alarm_lines = [line for line in alarms.split("\n") if "models/response_codes.py" in line]
    assert len(alarm_lines) == 2
    assert all("hardcoded password" in line for line in alarm_lines)
    assert "models/response_codes.py:19" in alarms
    assert "models/response_codes.py:50" in alarms
    if "## Fix these" in prompt:
        assert "models/response_codes.py" not in _section(prompt, "## Fix these")
