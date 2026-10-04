from dataclasses import asdict

from fixr_cli.findings import display_finding, to_finding

_BANDIT = {
    "tool": "bandit",
    "category": "security",
    "rule_id": "B105",
    "severity": "high",
    "file_path": "models/response_codes.py",
    "line": 19,
    "column": 33,
    "message": "Possible hardcoded password: '1:pw'",
    "snippet": '19     SUCCESSFUL_PASSWORD_CHANGE = "1:pw"\n',
    "cwe_id": 259,
    "confidence": "MEDIUM",
    "metadata": {"test_name": "hardcoded_password_string"},
    "tp_probability": 1.0,
    "priority_score": 3.0,
}


def _audit(**overrides: object) -> dict:
    api = {
        "tool": "pip-audit",
        "category": "dependency",
        "rule_id": "PYSEC-2026-4025",
        "severity": "medium",
        "file_path": "anyio",
        "line": None,
        "column": None,
        "message": (
            "### Impact\n\nServices using internationalized domain names are vulnerable."
        ),
        "snippet": None,
        "metadata": {
            "package": "anyio",
            "installed_version": "4.9.0",
            "fix_versions": ["4.14.2"],
            "aliases": ["CVE-2026-63374", "GHSA-82r6-8w77-94w6"],
        },
    }
    api.update(overrides)
    return api


def test_other_tools_match_to_finding() -> None:
    assert asdict(display_finding(_BANDIT, 4)) == asdict(to_finding(_BANDIT, 4))


def test_pip_audit_title_and_description() -> None:
    finding = display_finding(_audit(), 0)
    title = "anyio 4.9.0 has a known vulnerability"
    assert finding.title == title
    assert finding.id == "api0"
    assert finding.description == (
        f"PYSEC-2026-4025: {title}. "
        "Services using internationalized domain names are vulnerable. "
        "Fixed in 4.14.2. "
        "Also known as CVE-2026-63374, GHSA-82r6-8w77-94w6."
    )


def test_pip_audit_omits_missing_version_and_fixes() -> None:
    api = _audit()
    api["metadata"] = {"package": "anyio", "aliases": []}
    finding = display_finding(api, 2)
    assert finding.title == "anyio has a known vulnerability"
    assert "No fixed release is available yet." in finding.description
    assert "Also known as" not in finding.description
    assert "Impact" not in finding.description


def test_pip_audit_package_falls_back_to_file_path() -> None:
    api = _audit()
    api["metadata"] = {}
    api["file_path"] = "requests"
    finding = display_finding(api, 0)
    assert finding.title == "requests has a known vulnerability"


def test_vulnerability_summary_heading_is_removed() -> None:
    api = _audit(
        message="### Vulnerability Summary\n\nA bug exists in the parser.",
    )
    finding = display_finding(api, 0)
    assert "Vulnerability Summary" not in finding.description
    assert "A bug exists in the parser." in finding.description


def test_only_the_leading_heading_word_is_removed() -> None:
    api = _audit(message="### Overview\n\nDetails follow in the body of this advisory.")
    finding = display_finding(api, 0)
    assert "Details follow in the body of this advisory." in finding.description
    assert not finding.description.split(": ", 1)[1].startswith("Overview")


def test_long_advisory_clips_on_a_word_boundary() -> None:
    api = _audit(
        message="### Impact\n\n" + ("alpha beta " * 50),
        metadata={"package": "anyio"},
    )
    finding = display_finding(api, 0)
    prefix = "PYSEC-2026-4025: anyio has a known vulnerability. "
    suffix = " No fixed release is available yet."
    assert finding.description.startswith(prefix)
    assert finding.description.endswith(suffix)
    summary = finding.description[len(prefix) : -len(suffix)]
    assert summary.endswith("…")
    assert len(summary) <= 280
    assert set(summary[:-1].split()) <= {"alpha", "beta"}


def test_short_advisory_gains_sentence_punctuation() -> None:
    api = _audit(message="### Summary\n\nUnterminated note", metadata={"package": "pkg"})
    finding = display_finding(api, 0)
    assert "Unterminated note." in finding.description


def test_explanation_replaces_the_advisory() -> None:
    api = _audit()
    api["metadata"] = {
        **api["metadata"],
        "explanation": "Upgrade the package.\n\n```python\npip install anyio==4.14.2\n```",
    }
    finding = display_finding(api, 3)
    assert finding.id == "api3"
    assert finding.title == "anyio 4.9.0 has a known vulnerability"
    assert "Upgrade the package." in finding.description
    assert finding.suggested_fix == "pip install anyio==4.14.2"
    assert "Fixed in" not in finding.description
    assert "Also known as" not in finding.description
