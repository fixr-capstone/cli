import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from fixr_cli.findings import (
    dedent,
    flagged_lines,
    is_likely_false_alarm,
    matches_website_rule,
    split_explanation,
    to_finding,
)

FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN = FIXTURES / "golden"
CASES = ["messy", "minor", "clean", "sample_project"]


def _raw_findings(case: str) -> list[dict[str, Any]]:
    if case == "sample_project":
        data = json.loads((FIXTURES / "sample_project_scan.json").read_text())
        return data["findings"]
    data = json.loads((FIXTURES / "samples.json").read_text())
    return data[case]["findings"]


def _as_ts(finding: Any, prototype: dict[str, Any]) -> dict[str, Any]:
    data = asdict(finding)
    data["suggestedFix"] = data.pop("suggested_fix")
    if "style" not in prototype:
        data.pop("style")
    if "rule" not in prototype:
        data.pop("rule")
    return data


@pytest.mark.parametrize("case", CASES)
def test_to_finding_matches_golden(case: str) -> None:
    expected = json.loads((GOLDEN / f"{case}.findings.json").read_text())
    got = [to_finding(item, index) for index, item in enumerate(_raw_findings(case))]
    assert [_as_ts(finding, proto) for finding, proto in zip(got, expected, strict=True)] == expected


def test_split_explanation_no_fence() -> None:
    description, fix = split_explanation("**Hello**\n\n\n\nworld  ")
    assert fix == ""
    assert description == "Hello\n\nworld"


def test_split_explanation_one_fence() -> None:
    description, fix = split_explanation("Explain.\n\n```python\n    value = 1\n```\n")
    assert fix == "value = 1"
    assert description == "Explain.\n\n(see the suggested fix)"


def test_split_explanation_inlines_earlier_fence() -> None:
    text = (
        "An attack looks like:\n\n```python\n' OR 1=1\n```\n\n"
        "Use a parameter:\n\n```python\n    query = '%s'\n```\n"
    )
    description, fix = split_explanation(text)
    assert fix == "query = '%s'"
    assert description == (
        "An attack looks like:\n\n' OR 1=1\n\nUse a parameter:\n\n(see the suggested fix)"
    )
    assert "```" not in description


def test_flagged_lines_keeps_from_flagged_line() -> None:
    snippet = (
        "14 def get_user(user_id):\n"
        "15     query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"\n"
        "16     result = db.execute(query)\n"
    )
    assert flagged_lines(snippet, 15) == (
        "    query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"\n"
        "    result = db.execute(query)"
    )


def test_flagged_lines_unnumbered_falls_back_to_trimmed_snippet() -> None:
    assert flagged_lines("  not numbered  \n", 3) == "not numbered"


def test_dedent_removes_common_indent() -> None:
    assert dedent("    alpha\n      beta\n") == "alpha\n  beta"


def test_dedent_all_blank_yields_empty_lines() -> None:
    assert dedent("\n\n  \n") == ""
    assert dedent("   \n   ") == ""


def test_website_rule_misses_enum_change_wording() -> None:
    text = "No change to the enum is required."
    assert matches_website_rule(text) is False
    assert is_likely_false_alarm(text) is True


def test_not_an_actual_password_is_a_false_alarm() -> None:
    assert is_likely_false_alarm("it is not an actual password or secret") is True


def test_false_positive_phrase_is_a_false_alarm() -> None:
    assert is_likely_false_alarm("This is a false positive.") is True


def test_real_fix_is_not_a_false_alarm() -> None:
    assert is_likely_false_alarm("Use parameterised queries to fix the injection.") is False
