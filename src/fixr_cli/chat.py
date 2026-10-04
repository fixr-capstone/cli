"""Interactive questions about a scan."""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO

from fixr_rag.chat import UNAVAILABLE, stream_reply

from fixr_cli.findings import Finding, display_finding

try:
    import readline  # noqa: F401
except ImportError:
    pass

CHAT_FINDINGS = 40
_STYLE_SENT = 5
_LISTED = 10
_HISTORY = 40
_TURN_LIMIT = 4000
_RULE_LIMIT = 32
_TITLE_LIMIT = 500
_FILE_LIMIT = 500
_BODY_LIMIT = 8000

_HELP = """\
/focus N     focus on finding N
/focus       clear the focus
/focus off   clear the focus
/list        list every finding
/help        show these commands
/quit        leave the chat
/exit        leave the chat"""


def chat_payload(findings: list[Finding], focus_id: str | None) -> list[dict[str, Any]]:
    focused = [finding for finding in findings if finding.id == focus_id]
    others = [finding for finding in findings if finding.id != focus_id and not finding.style]
    ranked = focused + others
    notes = [finding for finding in findings if finding.style][:_STYLE_SENT]
    return [_payload(finding) for finding in [*ranked[:CHAT_FINDINGS], *notes]]


def run_chat(
    findings: list[Finding],
    *,
    label: str,
    groq_client=None,
    read: Callable[[str], str] | None = None,
    out: TextIO | None = None,
) -> int:
    if out is None:
        out = sys.stdout
    reader = read or input
    real = [finding for finding in findings if not finding.style]
    notes = sum(1 for finding in findings if finding.style)
    _writeln(
        out,
        f"Chat about {label}: {len(real)} findings and {notes} style notes. "
        "Ask a question, or use /focus N, /list, /help, /quit.",
    )
    _print_findings(real, out, limit=_LISTED)
    history: list[dict[str, str]] = []
    focus_id: str | None = None
    while True:
        try:
            entered = reader("you> ")
        except EOFError:
            out.write("\n")
            out.flush()
            return 0
        except KeyboardInterrupt:
            out.write("\n")
            out.flush()
            return 0
        text = entered.strip()
        if not text:
            continue
        if text.startswith("/"):
            stop, focus_id = _command(text, real, focus_id, out)
            if stop:
                return 0
            continue
        _ask(text, findings, history, focus_id, groq_client, out)


def load_results(path: Path) -> tuple[str, list[Finding]]:
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON ({exc.msg})") from exc
    raw = _raw_findings(data)
    if raw is None:
        raise ValueError("findings is missing or not a list")
    try:
        findings = [display_finding(item, index) for index, item in enumerate(raw)]
    except (TypeError, KeyError, AttributeError) as exc:
        raise ValueError(f"findings are not scan results ({exc})") from exc
    return data.get("target") or path.name, findings


def _raw_findings(data: object) -> list[Any] | None:
    if not isinstance(data, dict):
        return None
    raw = data.get("findings")
    if not isinstance(raw, list):
        return None
    return raw


def _payload(finding: Finding) -> dict[str, Any]:
    rule = finding.rule[:_RULE_LIMIT] if finding.rule else finding.rule
    return {
        "id": finding.id,
        "rule": rule,
        "severity": finding.severity,
        "title": finding.title[:_TITLE_LIMIT],
        "file": finding.file[:_FILE_LIMIT],
        "line": finding.line,
        "snippet": finding.snippet[:_BODY_LIMIT],
        "description": finding.description[:_BODY_LIMIT],
        "suggestedFix": finding.suggested_fix[:_BODY_LIMIT],
        "style": finding.style,
    }


def _command(
    text: str,
    real: list[Finding],
    focus_id: str | None,
    out: TextIO,
) -> tuple[bool, str | None]:
    parts = text.split()
    name = parts[0]
    if name in {"/quit", "/exit"} and len(parts) == 1:
        return True, focus_id
    if name == "/help" and len(parts) == 1:
        _writeln(out, _HELP)
        return False, focus_id
    if name == "/list" and len(parts) == 1:
        _print_findings(real, out, limit=None)
        return False, focus_id
    if name == "/focus" and (len(parts) == 1 or (len(parts) == 2 and parts[1] == "off")):
        _writeln(out, "Focus cleared.")
        return False, None
    if name == "/focus" and len(parts) == 2:
        return False, _focus(parts[1], real, focus_id, out)
    _writeln(out, f"Unknown command {name}. Try /help.")
    return False, focus_id


def _focus(token: str, real: list[Finding], focus_id: str | None, out: TextIO) -> str | None:
    if not real:
        _writeln(out, "There are no findings to focus on.")
        return focus_id
    number = int(token) if token.isdigit() else None
    if number is None or number < 1 or number > len(real):
        _writeln(out, f"No finding {token}; pick 1 to {len(real)}.")
        return focus_id
    chosen = real[number - 1]
    _writeln(out, f"Focused on {number}. {chosen.severity.upper()} {chosen.title} {_place(chosen)}")
    return chosen.id


def _ask(
    text: str,
    findings: list[Finding],
    history: list[dict[str, str]],
    focus_id: str | None,
    groq_client,
    out: TextIO,
) -> None:
    history.append({"role": "user", "content": text[:_TURN_LIMIT]})
    try:
        reply = asyncio.run(_stream(history, findings, focus_id, groq_client, out))
    except KeyboardInterrupt:
        out.write("\n(stopped)\n")
        out.flush()
        history.pop()
        return
    if not reply or reply.endswith(UNAVAILABLE):
        history.pop()
        return
    history.append({"role": "assistant", "content": reply[:_TURN_LIMIT]})
    del history[:-_HISTORY]


def _print_findings(real: list[Finding], out: TextIO, *, limit: int | None) -> None:
    if not real:
        _writeln(out, "No findings.")
        return
    shown = real if limit is None else real[:limit]
    for number, finding in enumerate(shown, start=1):
        _writeln(out, _finding_line(number, finding))
    if limit is not None and len(real) > limit:
        _writeln(out, f"  and {len(real) - limit} more (/list shows all)")


def _finding_line(number: int, finding: Finding) -> str:
    pieces = [finding.severity.upper()]
    if finding.rule is not None:
        pieces.append(finding.rule)
    pieces.append(finding.title)
    pieces.append(_place(finding))
    return f"  {number}. " + "  ".join(pieces)


def _place(finding: Finding) -> str:
    if finding.line:
        return f"{finding.file}:{finding.line}"
    return finding.file


def _writeln(out: TextIO, text: str) -> None:
    out.write(f"{text}\n")
    out.flush()


async def _stream(
    history: list[dict[str, str]],
    findings: list[Finding],
    focus_id: str | None,
    groq_client,
    out: TextIO,
) -> str:
    pieces: list[str] = []
    started = False
    async for chunk in stream_reply(
        history,
        chat_payload(findings, focus_id),
        focus_id,
        client=groq_client,
    ):
        if not started:
            out.write("fixr> ")
            started = True
        out.write(chunk)
        out.flush()
        pieces.append(chunk)
    if started:
        out.write("\n")
        out.flush()
    return "".join(pieces)
