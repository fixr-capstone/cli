import re
from collections.abc import Callable

from fixr_cli.findings import Finding, is_likely_false_alarm

SECRET_RULES = {"B105", "B106", "B107"}
# Detail costs the AI tool context; past this, findings are listed by rule instead.
DETAILED = 25
LOCATIONS = 12
SNIPPET_LINES = 15

# Only identifier-like quotes count: flake8's "whitespace before ':'" quotes punctuation, not a name.
NAME = re.compile(r"'([A-Za-z_][\w.-]*)'", re.ASCII)
_PY_SUFFIX = re.compile(r"\.py$")
_IS_TEST = re.compile(r"(^|/)(tests?|testing)/|(^|/)test_[^/]*\.py$|_test\.py$")
_WHITESPACE = re.compile(r"\s+")
_SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s")
# "line too long (117 > 79 characters)" describes one line, not the group.
_LINE_TOO_LONG = re.compile(r"\s*\(\d+ > \d+ characters\)", re.ASCII)


def build_fix_prompt(
    findings: list[Finding],
    notes: list[Finding],
    *,
    is_false_alarm: Callable[[str], bool] = is_likely_false_alarm,
) -> str:
    false_alarms = [finding for finding in findings if is_false_alarm(finding.description)]
    alarm_ids = {id(finding) for finding in false_alarms}
    real = [finding for finding in findings if id(finding) not in alarm_ids]
    # Findings arrive ranked, so the first worth detailing are the most serious.
    worth_detail = [finding for finding in real if finding.severity != "low" or finding.suggested_fix]
    detailed = worth_detail[:DETAILED]
    detailed_ids = {id(finding) for finding in detailed}
    rest = [finding for finding in real if id(finding) not in detailed_ids]
    has_secret = any(finding.rule and finding.rule in SECRET_RULES for finding in detailed)
    local = _local_names([finding.file for finding in (*findings, *notes)])

    issue = "issue" if len(findings) == 1 else "issues"
    ones = "one" if len(rest) == 1 else "ones"
    alarm = "alarm" if len(false_alarms) == 1 else "alarms"
    out = [
        "# Security fixes for this project",
        "",
        "You are helping someone fix security problems that Fixr, an automated scanner, found in their Python code. They may not be a developer and may not be able to review code changes, so work carefully and explain in plain words.",
        "",
        f"Fixr found {len(findings)} {issue}: {len(detailed)} to fix, {len(rest)} lower-priority {ones} grouped by type, and {len(false_alarms)} likely false {alarm}.",
        "",
        "## How to work",
        "",
        '1. Fix the issues under "Fix these" one at a time, in the order listed. The most serious come first.',
        "2. Change only what each fix needs. Do not refactor, rename or reformat unrelated code.",
        "3. Keep the program doing what it does today, apart from closing the security hole.",
        "4. If a fix needs a new setting, secret or package, tell the person exactly what to do, step by step.",
        "5. If an issue looks like a false alarm in this code, say why and leave the code alone.",
        "6. After each fix, explain in one or two plain sentences what changed and why it matters.",
        '7. Do not touch the "Likely false alarms". Handle the lower-priority groups only after the main fixes, and only if the person agrees.',
        "8. If the project has tests, run them after the changes.",
        "",
    ]
    if has_secret:
        out.append(
            "> **A secret may be written in the code.** If it is a real key or password, moving it out of the code is not enough: anyone who saw the code may already have it. Tell the person to create a new one with the service that issued it and delete the old one."
        )
        out.append("")

    if detailed:
        out.append(f"## Fix these ({len(detailed)})")
        out.append("")
        for index, finding in enumerate(detailed):
            out.append(f"### {index + 1}. {finding.title}")
            out.append("")
            out.append(f"- Severity: {finding.severity}")
            out.append(f"- Where: {_where(finding)}")
            if finding.rule:
                out.append(f"- Scanner rule: {finding.rule}")
            out.append("")
            if finding.snippet:
                out.append("Flagged code:")
                out.append("")
                out.append(_block(finding.snippet))
                out.append("")
            out.append("What is wrong:")
            out.append("")
            out.append(finding.description)
            out.append("")
            if finding.suggested_fix:
                out.append("Suggested fix (a starting point, adapt it to the surrounding code):")
                out.append("")
                out.append(_block(finding.suggested_fix))
                out.append("")

    if rest:
        out.append("## Lower-priority issues, grouped by type")
        out.append("")
        out.append(
            "Each group is one pattern. Fix a group the same way everywhere, or explain why it is safe here."
        )
        out.append("")
        for rule, items in _by_rule(rest):
            tests = sum(1 for finding in items if _is_test(finding.file))
            named = _names_of(items)
            own = [name for name in named if name in local]
            title = _generic(items[0].title) if len(named) > 1 else items[0].title
            place = "place" if len(items) == 1 else "places"
            out.append(f"### {rule}: {title} ({len(items)} {place})")
            out.append("")
            out.append(f"- Severity: {items[0].severity}")
            if len(named) > 1:
                out.append(f"- Names: {_code_list(named)}")
            if own:
                listed = _code_list(own)
                if len(own) == 1:
                    out.append(
                        f"- {listed} is a folder or module of this project, not an installed package. Ignore that one; do not add it as dependencies."
                    )
                else:
                    out.append(
                        f"- {listed} are folders or modules of this project, not installed packages. Ignore those; do not add them as dependencies."
                    )
            out.append(f"- Where: {_locations(items)}")
            if tests == len(items):
                out.append(
                    "- All of these are in test files, where this is usually expected. Leave them unless the person asks."
                )
            elif tests:
                out.append(f"- {tests} of these are in test files, where this is usually expected.")
            out.append("")

    if false_alarms:
        out.append("## Likely false alarms, leave these alone")
        out.append("")
        out.append(
            "Fixr's review found these are not real problems in this code. Do not change them."
        )
        out.append("")
        for finding in false_alarms:
            rule = "" if finding.rule is None else finding.rule
            out.append(
                f"- {_where(finding)} {rule} {finding.title}. {_first_sentence(finding.description)}"
            )
        out.append("")

    if notes:
        # Locations are left out: style is a formatter's job, and listing thousands of lines buries the security work.
        groups = _by_rule(notes)
        note = "note" if len(notes) == 1 else "notes"
        out.append("## Optional style clean-up")
        out.append("")
        out.append(
            f"The linter also left {len(notes)} style {note}. These are not security problems. Do not fix them by hand; if the person wants them gone, suggest running a formatter such as `ruff format` or `black`, as a separate change."
        )
        out.append("")
        for rule, items in groups[:8]:
            title = _generic(items[0].title) if len(_names_of(items)) > 1 else items[0].title
            title = _LINE_TOO_LONG.sub("", title, count=1)
            out.append(f"- {rule}: {title} ({len(items)})")
        if len(groups) > 8:
            out.append(f"- and {len(groups) - 8} other kinds")
        out.append("")

    out.append("## When you are done")
    out.append("")
    out.append(
        "Give the person a short summary: which issues you fixed, which you left and why, and anything they must do themselves."
    )
    out.append("")
    return "\n".join(out)


def _block(code: str) -> str:
    lines = code.split("\n")
    body = "\n".join(lines[:SNIPPET_LINES])
    if len(lines) > SNIPPET_LINES:
        body += "\n# ..."
    return f"```python\n{body}\n```"


def _where(finding: Finding) -> str:
    suffix = f":{finding.line}" if finding.line else ""
    return f"`{finding.file}{suffix}`"


def _first_sentence(text: str) -> str:
    collapsed = _WHITESPACE.sub(" ", text).strip()
    return _SENTENCE_BREAK.split(collapsed)[0]


def _is_test(file: str) -> bool:
    return _IS_TEST.search(file) is not None


def _by_rule(items: list[Finding]) -> list[tuple[str, list[Finding]]]:
    groups: dict[str, list[Finding]] = {}
    for finding in items:
        key = finding.title if finding.rule is None else finding.rule
        groups.setdefault(key, []).append(finding)
    return sorted(groups.items(), key=lambda pair: len(pair[1]), reverse=True)


# Titles like "'pydantic' imported but ..." name one package; a group needs the pattern and every name.
def _generic(title: str) -> str:
    return NAME.sub("'…'", title)


def _names_of(items: list[Finding]) -> list[str]:
    seen: dict[str, None] = {}
    for finding in items:
        for match in NAME.finditer(finding.title):
            seen.setdefault(match.group(1), None)
    return list(seen)


def _code_list(names: list[str], max_names: int = 20) -> str:
    shown = ", ".join(f"`{name}`" for name in names[:max_names])
    if len(names) > max_names:
        shown += f" and {len(names) - max_names} more"
    return shown


# Folders and modules of the scanned project: deptry reports these as missing packages when it misreads the root.
def _local_names(files: list[str]) -> set[str]:
    names: set[str] = set()
    for file in files:
        names.update(_PY_SUFFIX.sub("", file, count=1).split("/"))
    return names


def _locations(items: list[Finding]) -> str:
    shown = ", ".join(_where(finding) for finding in items[:LOCATIONS])
    extra = len(items) - LOCATIONS
    if extra > 0:
        return f"{shown} and {extra} more"
    return shown
