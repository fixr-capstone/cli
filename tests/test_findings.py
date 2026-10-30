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


_GROQ_B105 = (
    'The string `"True"` is not a credential; it\u2019s just a literal used to filter out a '
    "boolean value from the command\u2011line argument list. The code simply discards any token "
    'that equals `"True"` when it follows an option flag.\n\n'
    "Fix \u2013 No functional change is required. Mark the line to silence Bandit:\n\n"
    "(see the suggested fix)\n\n"
    "This removes the false\u2011positive alert while keeping the original logic intact."
)


def test_website_rule_misses_groq_b105_wording() -> None:
    assert matches_website_rule(_GROQ_B105) is False
    assert is_likely_false_alarm(_GROQ_B105) is True


@pytest.mark.parametrize(
    "text",
    [
        "This is a false-positive.",
        "This is a false\u2011positive.",
        "This is a false\u2010alarm.",
        "This is a false\u00a0positive.",
        "These are false positives.",
        "No functional change is required.",
        "No code changes are needed.",
        "No further change is needed.",
        "The string is not a credential; it is a literal.",
        "It is not a password, just a label.",
        "It is not a secret and is public.",
    ],
)
def test_wider_false_alarm_wording(text: str) -> None:
    assert is_likely_false_alarm(text) is True


@pytest.mark.parametrize(
    "text",
    [
        "This is not a false positive: the key is hard-coded.",
        "This isn't a false alarm.",
        "This isn\u2019t a false alarm.",
        "This is never a false positive.",
        "MD5 is not a password hashing algorithm.",
        "Using random is not a secure choice for tokens.",
    ],
)
def test_negated_or_unrelated_wording_is_not_a_false_alarm(text: str) -> None:
    assert is_likely_false_alarm(text) is False


def test_real_fix_is_not_a_false_alarm() -> None:
    assert is_likely_false_alarm("Use parameterised queries to fix the injection.") is False


def _flagged(probability: float | None) -> dict[str, Any]:
    item: dict[str, Any] = {
        "rule_id": "B324",
        "category": "security",
        "severity": "high",
        "file_path": "app.py",
        "line": 3,
        "message": "Use of weak MD5 hash for security.",
        "snippet": "3 hashlib.md5(x)\n",
        "metadata": {"likely_false_alarm": True},
    }
    if probability is not None:
        item["tp_probability"] = probability
    return item


@pytest.mark.parametrize(
    ("probability", "chance"),
    [(0.004, "under 1"), (0.01, "1"), (0.045, "5"), (0.1, "10"), (None, "under 1")],
)
def test_to_finding_says_when_the_classifier_doubts_a_kept_finding(
    probability: float | None, chance: str
) -> None:
    # Same wording as the website's toFinding (frontend/lib/api.ts).
    finding = to_finding(_flagged(probability), 0)
    assert finding.description == (
        f"Likely false alarm: Fixr's classifier puts the chance this is real at {chance}%. "
        "Check it before ignoring it. B324: Use of weak MD5 hash for security."
    )
    assert is_likely_false_alarm(finding.description)


def test_to_finding_leaves_unflagged_findings_alone() -> None:
    item = _flagged(0.5)
    item["metadata"] = {}
    assert to_finding(item, 0).description == "B324: Use of weak MD5 hash for security."
