import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low"]

# The last code block is the fix; earlier ones (attack examples) stay inline as text.
FENCE = re.compile(r"```[\w-]*\n([\s\S]*?)```", re.ASCII)
_BLANK_LINES = re.compile(r"\n{3,}")
_TITLE_QUOTE = re.compile(r":\s*'[^']*'$")
_NUMBERED_LINE = re.compile(r"^(\d+) ?(.*)$", re.ASCII)

# Fixr's explanation already judged these harmless; listing them as fixes invites pointless edits.
WEBSITE_FALSE_ALARM = re.compile(
    r"\bfalse (positive|alarm)\b|no (code )?change is (required|needed)|no action is (required|needed)|\bis harmless\b",
    re.IGNORECASE | re.ASCII,
)
FALSE_ALARM = re.compile(
    r"\bfalse (positive|alarm)\b|no (code )?change is (required|needed)|no action is (required|needed)|\bis harmless\b"
    r"|no (?:code )?changes? (?:to [^.]{1,60} )?(?:is|are) (?:required|needed)"
    r"|\bnot an? (?:actual|real) (?:password|secret|credential|key|token)\b",
    re.IGNORECASE | re.ASCII,
)


@dataclass(eq=False)
class Finding:
    id: str
    severity: Severity
    title: str
    description: str
    file: str
    line: int
    snippet: str
    suggested_fix: str
    style: bool = False
    rule: str | None = None


def clean(s: str) -> str:
    return _BLANK_LINES.sub("\n\n", s.replace("**", "")).strip()


def dedent(code: str) -> str:
    lines = code.rstrip().split("\n")
    indents = [_leading_spaces(line) for line in lines if line.strip()]
    if not indents:
        return "\n".join("" for _ in lines)
    pad = min(indents)
    return "\n".join(line[pad:] for line in lines)


def split_explanation(text: str) -> tuple[str, str]:
    matches = list(FENCE.finditer(text))
    if not matches:
        return clean(text), ""
    last = matches[-1]
    rest = text[: last.start()] + "(see the suggested fix)" + text[last.end() :]
    description = clean(FENCE.sub(lambda match: match.group(1), rest))
    return description, dedent(last.group(1))


# Bandit prefixes each snippet line with its number and pads with context lines; keep from the flagged line on.
def flagged_lines(snippet: str, line: int) -> str:
    rows: list[str] = []
    for raw in snippet.split("\n"):
        match = _NUMBERED_LINE.match(raw)
        if match and int(match.group(1)) >= line:
            rows.append(match.group(2))
    return "\n".join(rows).rstrip() or snippet.strip()


def matches_website_rule(description: str) -> bool:
    return WEBSITE_FALSE_ALARM.search(description) is not None


def is_likely_false_alarm(description: str) -> bool:
    return FALSE_ALARM.search(description) is not None


def to_finding(api: Mapping[str, Any], index: int) -> Finding:
    raw_severity = api.get("severity")
    severity: Severity = raw_severity if raw_severity in ("high", "medium") else "low"
    metadata = api.get("metadata")
    explanation = ""
    if isinstance(metadata, dict):
        raw_explanation = metadata.get("explanation")
        if raw_explanation is not None:
            explanation = raw_explanation
    description, fix = split_explanation(explanation)
    message = api["message"]
    rule_id = api["rule_id"]
    if not description:
        description = f"{rule_id}: {message}"
    description = _doubt(api, metadata) + description
    file_path = api["file_path"].replace("\\", "/")
    line = api.get("line")
    if line is None:
        line = 0
    snippet = api.get("snippet")
    if snippet is None:
        snippet = ""
    return Finding(
        id=f"api{index}",
        severity=severity,
        title=_TITLE_QUOTE.sub("", message, count=1),
        description=description,
        file=file_path.split("/repository/")[-1],
        line=line,
        snippet=flagged_lines(snippet, line),
        suggested_fix=fix,
        style=api.get("category") == "style",
        rule=rule_id,
    )


# High severity is never hidden; when the classifier doubts it, it is kept and said so.
def _doubt(api: Mapping[str, Any], metadata: object) -> str:
    if not isinstance(metadata, dict) or not metadata.get("likely_false_alarm"):
        return ""
    probability = api.get("tp_probability")
    if not isinstance(probability, (int, float)):
        probability = 0
    chance = "under 1" if probability < 0.01 else str(math.floor(probability * 100 + 0.5))
    return (
        f"Likely false alarm: Fixr's classifier puts the chance this is real at {chance}%. "
        "Check it before ignoring it. "
    )


def _leading_spaces(line: str) -> int:
    count = 0
    for char in line:
        if char != " ":
            break
        count += 1
    return count


_HASH_RUNS = re.compile(r"#+")
_ADVISORY_HEADING = re.compile(
    r"^(?:vulnerability summary|description|overview|details|summary|impact)\b[:\-–—]?\s*",
    re.IGNORECASE,
)
_ADVISORY_SPACE = re.compile(r"\s+")
_SUMMARY_LIMIT = 280
_SENTENCE_END = ".!?…"


def display_finding(api: Mapping[str, Any], index: int) -> Finding:
    if api.get("tool") != "pip-audit":
        return to_finding(api, index)
    metadata = _metadata(api)
    package = metadata.get("package") or api.get("file_path") or ""
    version = metadata.get("installed_version")
    if version:
        title = f"{package} {version} has a known vulnerability"
    else:
        title = f"{package} has a known vulnerability"
    merged = dict(api)
    merged["message"] = title
    finding = to_finding(merged, index)
    if metadata.get("explanation"):
        return finding
    finding.description = _pip_audit_description(api, metadata, title)
    return finding


def _metadata(api: Mapping[str, Any]) -> dict[str, Any]:
    metadata = api.get("metadata")
    if isinstance(metadata, dict):
        return metadata
    return {}


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _pip_audit_description(api: Mapping[str, Any], metadata: Mapping[str, Any], title: str) -> str:
    summary = _advisory_summary(str(api.get("message") or ""))
    fixes = _string_list(metadata.get("fix_versions"))
    aliases = _string_list(metadata.get("aliases"))
    if fixes:
        fixed = f"Fixed in {', '.join(fixes)}."
    else:
        fixed = "No fixed release is available yet."
    body = f"{summary} {fixed}".strip()
    description = f"{api['rule_id']}: {title}. {body}"
    if aliases:
        description += f" Also known as {', '.join(aliases)}."
    return description


def _advisory_summary(message: str) -> str:
    text = _HASH_RUNS.sub(" ", message)
    text = _ADVISORY_SPACE.sub(" ", text).strip()
    text = _ADVISORY_HEADING.sub("", text, count=1).strip()
    return _finish_summary(text)


def _finish_summary(text: str) -> str:
    if not text:
        return ""
    if len(text) <= _SUMMARY_LIMIT and text[-1] in _SENTENCE_END:
        return text
    if len(text) < _SUMMARY_LIMIT:
        return f"{text}."
    return _clip_words(text)


def _clip_words(text: str) -> str:
    budget = _SUMMARY_LIMIT - 1
    cut = text[:budget]
    if len(text) > budget and not text[budget].isspace():
        space = cut.rfind(" ")
        if space > 0:
            cut = cut[:space]
    cut = cut.rstrip()
    if not cut:
        cut = text[:budget]
    if len(cut) > budget:
        cut = cut[:budget]
    return f"{cut}…"
