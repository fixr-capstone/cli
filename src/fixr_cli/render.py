"""Turn a scan into text, JSON, and a fix prompt."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from packaging.version import InvalidVersion, Version
from rich.console import Console
from rich.syntax import Syntax
from rich.text import Text

from fixr_cli import __version__
from fixr_cli.engine import ScanResult
from fixr_cli.findings import Finding, display_finding, is_likely_false_alarm
from fixr_cli.fix_prompt import (
    _LINE_TOO_LONG,
    _first_sentence,
    _generic,
    _names_of,
    build_fix_prompt,
)

_RANK = {"unknown": 1, "low": 1, "medium": 2, "high": 3}
_LABEL_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3}
_SEVERITY_STYLE = {"high": "red", "medium": "yellow", "low": "dim", "unknown": "dim"}
_LOCATIONS = 8
_NAME_LIMIT = 20
_STYLE_TOP = 5


@dataclass
class Report:
    result: ScanResult
    api: list[dict[str, Any]]
    display: list[Finding]
    false_alarm: list[bool]
    fail_on: str
    explain_limit: int


def no_key_notice(limit: int) -> str:
    return (
        f"Set GROQ_API_KEY to have Groq explain the top {limit} Bandit findings. "
        "Only those functions are sent."
    )


def build_report(
    result: ScanResult,
    *,
    fail_on: str = "high",
    explain_limit: int = 5,
) -> Report:
    api = [finding.model_dump(mode="json") for finding in result.findings]
    display = [display_finding(item, index) for index, item in enumerate(api)]
    false_alarm = [
        _has_explanation(item) and is_likely_false_alarm(shown.description)
        for item, shown in zip(api, display, strict=True)
    ]
    return Report(
        result=result,
        api=api,
        display=display,
        false_alarm=false_alarm,
        fail_on=fail_on,
        explain_limit=explain_limit,
    )


def failing(report: Report) -> list[int]:
    if report.fail_on == "none":
        return []
    threshold = _RANK[report.fail_on]
    chosen: list[int] = []
    for index, shown in enumerate(report.display):
        if shown.style or report.false_alarm[index]:
            continue
        severity = str(report.api[index].get("severity", "unknown"))
        if _RANK.get(severity, 1) >= threshold:
            chosen.append(index)
    return chosen


def to_json(report: Report) -> dict[str, Any]:
    result = report.result
    findings = [
        {**item, "id": shown.id, "likely_false_alarm": alarm}
        for item, shown, alarm in zip(report.api, report.display, report.false_alarm, strict=True)
    ]
    style = sum(1 for shown in report.display if shown.style)
    return {
        "version": __version__,
        "target": result.label,
        "seconds": _one_decimal(result.seconds),
        "fail_on": report.fail_on,
        "tools": [
            {
                "tool": str(run.tool),
                "status": run.status,
                "reason": run.reason,
                "raw": run.raw,
                "seconds": _one_decimal(run.seconds),
            }
            for run in result.tools
        ],
        "counts": {
            "raw": result.raw_total,
            "deduplicated": result.deduped_total,
            "ranked": len(result.findings),
            "style": style,
            "bandit": result.bandit_total,
            "bandit_judged": result.bandit_judged,
            "dropped_by_classifier": result.dropped_by_classifier,
            "likely_false_alarms": sum(report.false_alarm),
            "failing": len(failing(report)),
        },
        "explanations": {
            "status": result.explain_status,
            "explained": result.explained,
            "limit": report.explain_limit,
        },
        "findings": findings,
    }


def fix_prompt_text(report: Report) -> str:
    flagged = {
        report.display[index].description
        for index, alarm in enumerate(report.false_alarm)
        if alarm
    }

    def pred(description: str) -> bool:
        return description in flagged

    findings = [shown for shown in report.display if not shown.style]
    notes = [shown for shown in report.display if shown.style]
    return build_fix_prompt(findings, notes, is_false_alarm=pred)


def render_text(report: Report, console: Console, *, show_style: bool = False) -> None:
    _render_header(report, console)
    console.print()
    _render_tools(report, console)
    console.print()
    _render_pipeline(report, console)
    _render_explanations(report, console)
    console.print()
    if not _real_indexes(report):
        console.print(Text("Nothing to fix.", style="green"))
    else:
        _render_explained(report, console)
        _render_dependencies(report, console)
        _render_other(report, console)
    _render_false_alarms(report, console)
    _render_style(report, console, show_style=show_style)
    console.print()
    _render_footer(report, console)


def _one_decimal(value: float) -> float:
    return float(f"{value:.1f}")


def _has_explanation(api: Mapping[str, Any]) -> bool:
    metadata = api.get("metadata")
    if not isinstance(metadata, dict):
        return False
    return bool(metadata.get("explanation"))


def _metadata(api: Mapping[str, Any]) -> dict[str, Any]:
    metadata = api.get("metadata")
    if isinstance(metadata, dict):
        return metadata
    return {}


def _real_indexes(report: Report) -> list[int]:
    return [
        index
        for index, shown in enumerate(report.display)
        if not shown.style and not report.false_alarm[index]
    ]


def _render_header(report: Report, console: Console) -> None:
    header = Text("Fixr scan of ", style="bold")
    header.append(report.result.label)
    header.append(f" ({report.result.seconds:.1f}s)", style="dim")
    console.print(header)


def _heading(console: Console, title: str) -> None:
    console.print(Text(title, style="bold"))


def _render_tools(report: Report, console: Console) -> None:
    for run in report.result.tools:
        line = Text(f"{run.tool:<12}")
        if run.status == "ran":
            line.append(f"ran     {run.raw:,} findings, {run.seconds:.1f}s")
            if run.reason:
                line.append(f" ({run.reason})", style="yellow")
        elif run.status == "failed":
            line.append("failed: ", style="red")
            line.append(run.reason or "", style="red")
        else:
            line.append("skipped: ", style="dim")
            line.append(run.reason or "", style="dim")
        console.print(line)


def _render_pipeline(report: Report, console: Console) -> None:
    result = report.result
    console.print(
        f"{result.raw_total:,} raw findings, {result.deduped_total:,} after removing duplicates."
    )
    if result.bandit_total <= 0:
        return
    if result.bandit_judged == 0:
        console.print(
            f"None of the {result.bandit_total} Bandit findings use a rule the "
            "false-alarm classifier was trained on, so all were kept."
        )
        return
    console.print(
        f"The false-alarm classifier judged {result.bandit_judged} of "
        f"{result.bandit_total} Bandit findings and dropped {result.dropped_by_classifier}."
    )


def _render_explanations(report: Report, console: Console) -> None:
    status = report.result.explain_status
    explained = report.result.explained
    if status == "ok":
        if explained == 0:
            console.print("No Bandit findings to explain.")
        else:
            console.print(f"Groq explained {explained} findings.")
        return
    if status == "partial":
        console.print(f"Groq explained {explained} of the top findings; the rest failed.")
        return
    if status == "failed":
        console.print("Explanations failed; showing scanner output only.")
        return
    if status == "off":
        console.print("Explanations are off (--no-explain).")
        return
    console.print(Text(no_key_notice(report.explain_limit), style="yellow"))


def _render_explained(report: Report, console: Console) -> None:
    indexes = [
        index
        for index in _real_indexes(report)
        if _has_explanation(report.api[index])
    ]
    if not indexes:
        return
    _heading(console, "Explained by Groq")
    for number, index in enumerate(indexes, start=1):
        shown = report.display[index]
        severity = str(report.api[index].get("severity", shown.severity))
        header = Text(f"{number}. ")
        header.append(severity.upper(), style=_SEVERITY_STYLE.get(severity))
        header.append("  ")
        header.append(shown.title)
        console.print(header)
        console.print(Text(f"{_where(shown)}  {shown.rule or ''}"))
        if shown.snippet:
            console.print("Flagged code:")
            console.print(Syntax(shown.snippet, "python", background_color="default"))
        console.print("What is wrong:")
        console.print(Text(shown.description))
        if shown.suggested_fix:
            console.print("Suggested fix:")
            console.print(Syntax(shown.suggested_fix, "python", background_color="default"))
        console.print()


def _render_dependencies(report: Report, console: Console) -> None:
    groups: dict[str, list[int]] = {}
    for index, item in enumerate(report.api):
        if item.get("tool") != "pip-audit":
            continue
        metadata = _metadata(item)
        package = str(metadata.get("package") or item.get("file_path") or "")
        groups.setdefault(package, []).append(index)
    if not groups:
        return
    _heading(console, "Vulnerable dependencies")
    for package, members in groups.items():
        console.print(Text(_dependency_line(report, package, members)))
    console.print()


def _dependency_line(report: Report, package: str, members: list[int]) -> str:
    version = ""
    identifiers: list[str] = []
    advisory_fixes: list[list[str]] = []
    for index in members:
        item = report.api[index]
        metadata = _metadata(item)
        if not version and metadata.get("installed_version"):
            version = str(metadata["installed_version"])
        rule = str(item.get("rule_id") or "")
        if rule and rule not in identifiers:
            identifiers.append(rule)
        advisory_fixes.append([str(fix) for fix in metadata.get("fix_versions") or []])
    noun = "advisory" if len(members) == 1 else "advisories"
    version_bit = f" {version}" if version else ""
    listed = ", ".join(identifiers)
    upgrade = _upgrade_phrase(version, advisory_fixes)
    return f"{package}{version_bit}: {len(members)} {noun} ({listed}), {upgrade}"


def _upgrade_phrase(installed: str, advisory_fixes: list[list[str]]) -> str:
    """Advisories list fixes per release line; the upgrade that clears them all is the
    highest of each advisory's lowest fix above the installed version."""
    current = _version(installed)
    needed: list[Version] = []
    for fixes in advisory_fixes:
        above = [
            parsed
            for parsed in map(_version, fixes)
            if parsed is not None and (current is None or parsed > current)
        ]
        if above:
            needed.append(min(above))
    if not needed:
        return "no fixed release yet"
    target = f"upgrade to {max(needed)} or later"
    unfixed = len(advisory_fixes) - len(needed)
    if unfixed:
        return f"{target} ({unfixed} with no fixed release yet)"
    return target


def _version(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


def _render_other(report: Report, console: Console) -> None:
    indexes = [
        index
        for index in _real_indexes(report)
        if not _has_explanation(report.api[index]) and report.api[index].get("tool") != "pip-audit"
    ]
    if not indexes:
        return
    explained = any(_has_explanation(report.api[index]) for index in _real_indexes(report))
    _heading(console, "Other findings by rule" if explained else "Findings by rule")
    _render_groups(report, _grouped(report, indexes), console, style_titles=False)
    console.print()


def _render_false_alarms(report: Report, console: Console) -> None:
    lines: list[str] = []
    for index, alarm in enumerate(report.false_alarm):
        if not alarm:
            continue
        shown = report.display[index]
        sentence = _first_sentence(shown.description)
        lines.append(f"{_where(shown)}  {shown.rule or ''}  {shown.title}. {sentence}")
    if not lines:
        return
    _heading(console, "Likely false alarms (Fixr's explanation found these harmless)")
    for line in lines:
        console.print(Text(line))
    console.print()


def _render_style(report: Report, console: Console, *, show_style: bool) -> None:
    indexes = [index for index, shown in enumerate(report.display) if shown.style]
    if not indexes:
        return
    groups = _grouped(report, indexes)
    console.print(_style_summary(groups, show_style=show_style))
    if show_style:
        _render_groups(report, groups, console, style_titles=True)
    console.print()


def _style_summary(groups: list[tuple[str, list[int]]], *, show_style: bool) -> str:
    count = sum(len(members) for _, members in groups)
    rules = len(groups)
    note = "note" if count == 1 else "notes"
    rule_word = "rule" if rules == 1 else "rules"
    by_count = sorted(groups, key=lambda pair: (-len(pair[1]), pair[0]))
    top = ", ".join(f"{name} {len(members):,}" for name, members in by_count[:_STYLE_TOP])
    sentence = f"{count} style {note} from flake8 across {rules} {rule_word} (top: {top})."
    if not show_style:
        sentence += " Run with --show-style to list them."
    return sentence


def _render_groups(
    report: Report,
    groups: list[tuple[str, list[int]]],
    console: Console,
    *,
    style_titles: bool,
) -> None:
    for rule, members in groups:
        findings = [report.display[index] for index in members]
        names = _names_of(findings)
        title = _generic(findings[0].title) if len(names) > 1 else findings[0].title
        if style_titles:
            title = _LINE_TOO_LONG.sub("", title, count=1)
        severity = _highest_label(report, members)
        header = Text()
        header.append(severity.upper(), style=_SEVERITY_STYLE.get(severity))
        header.append(f"  {rule}  ")
        header.append(title)
        header.append(f" ({len(members)})")
        console.print(header)
        if len(names) > 1:
            console.print(Text(f"  {_name_line(names)}"))
        for line in _location_lines(findings):
            console.print(Text(line))


def _grouped(report: Report, indexes: list[int]) -> list[tuple[str, list[int]]]:
    groups: dict[str, list[int]] = {}
    for index in indexes:
        shown = report.display[index]
        key = shown.title if shown.rule is None else shown.rule
        groups.setdefault(key, []).append(index)
    return sorted(groups.items(), key=lambda pair: _group_sort_key(report, pair[0], pair[1]))


def _group_sort_key(report: Report, rule: str, members: list[int]) -> tuple[int, int, str]:
    highest = max(
        _RANK.get(str(report.api[index].get("severity", "unknown")), 1) for index in members
    )
    return (-highest, -len(members), rule)


def _highest_label(report: Report, members: list[int]) -> str:
    best = "unknown"
    for index in members:
        name = str(report.api[index].get("severity", "unknown"))
        if _LABEL_ORDER.get(name, 0) > _LABEL_ORDER.get(best, 0):
            best = name
    return best


def _name_line(names: list[str]) -> str:
    shown = ", ".join(names[:_NAME_LIMIT])
    extra = len(names) - _NAME_LIMIT
    if extra > 0:
        return f"names: {shown} and {extra} more"
    return f"names: {shown}"


def _location_lines(findings: list[Finding]) -> list[str]:
    places = list(dict.fromkeys(_where(finding) for finding in findings))
    lines = [f"  {place}" for place in places[:_LOCATIONS]]
    extra = len(places) - _LOCATIONS
    if extra > 0:
        lines.append(f"  and {extra} more")
    return lines


def _where(finding: Finding) -> str:
    if finding.line:
        return f"{finding.file}:{finding.line}"
    return finding.file


def _render_footer(report: Report, console: Console) -> None:
    high, medium, low = _severity_totals(report)
    console.print(
        f"{high} high, {medium} medium, {low} low findings (style notes not counted)."
    )
    if report.fail_on == "none":
        return
    line = f"{len(failing(report))} at or above --fail-on {report.fail_on}"
    alarms = sum(report.false_alarm)
    if alarms:
        word = "alarm" if alarms == 1 else "alarms"
        line += f" ({alarms} likely false {word} not counted)"
    console.print(f"{line}.")


def _severity_totals(report: Report) -> tuple[int, int, int]:
    high = medium = low = 0
    for index, shown in enumerate(report.display):
        if shown.style:
            continue
        severity = str(report.api[index].get("severity", "unknown"))
        if severity == "high":
            high += 1
        elif severity == "medium":
            medium += 1
        else:
            low += 1
    return high, medium, low
