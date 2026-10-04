"""Run the scanners, rank what they report, and optionally explain the top findings."""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext, redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from fixr_rag.context import attach_context
from fixr_rag.explain import explain_findings, select_for_explanation
from ml_filtering.features import OTHER_CATEGORY
from ml_filtering.filtering import deduplicate, filter_noise
from ml_filtering.model import load_model
from ml_filtering.normalizer import normalize_tool_output
from ml_filtering.normalizer.schema import Finding, RankedFinding
from ml_filtering.ranking import rank_findings
from ml_filtering.scoring import attach_scores
from static_fixr.fixr import invoke_fixr
from static_fixr.strings.core import ToolName

from fixr_cli.project import (
    audit_pinned_only,
    configure,
    load_bundle_config,
    rewrite_transitive,
)
from fixr_cli.target import prepare_target

ExplainStatus = Literal["off", "no-key", "ok", "partial", "failed"]
PINNED_ONLY = "dependencies could not be resolved, so only the pinned versions were checked"


@dataclass
class ToolRun:
    tool: str
    status: Literal["ran", "skipped", "failed"]
    reason: str | None = None
    raw: int = 0
    seconds: float = 0.0


@dataclass
class ScanResult:
    root: Path
    label: str
    tools: list[ToolRun]
    findings: list[RankedFinding]
    raw_total: int
    deduped_total: int
    bandit_total: int
    bandit_judged: int
    dropped_by_classifier: int
    explain_status: ExplainStatus
    explained: int
    seconds: float


def _short_reason(exc: BaseException) -> str:
    if isinstance(exc, SystemExit):
        code = exc.code
        text = code if isinstance(code, str) and code else f"SystemExit: {code}"
    else:
        text = str(exc).strip() or type(exc).__name__
    return text.splitlines()[0].strip()


def _output_path(out: Path, tool: str) -> Path:
    return out / f"{tool}.json"


@contextmanager
def _silenced() -> Iterator[None]:
    previous = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        with (
            open(os.devnull, "w", encoding="utf-8") as devnull,
            redirect_stdout(devnull),
            redirect_stderr(devnull),
        ):
            yield
    finally:
        logging.disable(previous)


def _run_tool(cfg, tool: str, out: Path, *, verbose: bool) -> ToolRun:
    cfg.FIXR_CONFIG.invocation_order = (ToolName(tool),)
    started = time.perf_counter()
    try:
        with nullcontext() if verbose else _silenced():
            invoke_fixr(cfg)
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        _output_path(out, tool).unlink(missing_ok=True)
        return ToolRun(
            tool=tool,
            status="failed",
            reason=_short_reason(exc),
            seconds=time.perf_counter() - started,
        )

    seconds = time.perf_counter() - started
    if tool == ToolName.DEPTRY:
        try:
            rewrite_transitive(_output_path(out, tool))
        except (Exception, SystemExit) as exc:  # noqa: BLE001
            _output_path(out, tool).unlink(missing_ok=True)
            return ToolRun(
                tool=tool,
                status="failed",
                reason=_short_reason(exc),
                seconds=seconds,
            )
    return ToolRun(tool=tool, status="ran", seconds=seconds)


def _execute(cfg, tool: str, plan, out: Path, *, verbose: bool, on_progress) -> ToolRun:
    if plan.skip_reason is not None:
        return ToolRun(tool=tool, status="skipped", reason=plan.skip_reason)
    if on_progress is not None:
        on_progress(f"Running {tool}")
    run = _run_tool(cfg, tool, out, verbose=verbose)
    if run.status != "failed" or not plan.pinned_fallback:
        return run
    audit_pinned_only(cfg)
    retry = _run_tool(cfg, tool, out, verbose=verbose)
    retry.seconds += run.seconds
    if retry.status == "ran":
        retry.reason = PINNED_ONLY
    return retry


def _normalize_runs(tools: list[ToolRun], out: Path) -> list[Finding]:
    collected: list[Finding] = []
    for run in tools:
        if run.status != "ran":
            continue
        try:
            parsed = normalize_tool_output(run.tool, _output_path(out, run.tool))
        except Exception as exc:  # noqa: BLE001
            run.status = "failed"
            run.reason = _short_reason(exc)
            _output_path(out, run.tool).unlink(missing_ok=True)
            continue
        run.raw = len(parsed)
        collected.extend(parsed)
    return collected


def _rank(
    findings: list[Finding],
) -> tuple[list[RankedFinding], int, int, int, int]:
    deduped = deduplicate(findings)
    model, categories = load_model()
    known_rules = set(categories["rule_id"]) - {OTHER_CATEGORY}
    bandit = [finding for finding in deduped if finding.tool == ToolName.BANDIT]
    scored = attach_scores(deduped, model, categories)
    filtered = filter_noise(scored)
    ranked = rank_findings(filtered)
    judged = sum(1 for finding in bandit if finding.rule_id in known_rules)
    return ranked, len(deduped), len(bandit), judged, len(scored) - len(filtered)


def _count_explained(findings: list[RankedFinding]) -> int:
    return sum(1 for finding in findings if finding.metadata.get("explanation"))


def _explain(
    ranked: list[RankedFinding],
    root: Path,
    *,
    explain: bool,
    explain_limit: int,
    groq_client,
    on_progress: Callable[[str], None] | None = None,
) -> tuple[ExplainStatus, int]:
    if not explain:
        return "off", 0
    if groq_client is None and not os.environ.get("GROQ_API_KEY"):
        return "no-key", 0

    to_explain = select_for_explanation(ranked, explain_limit)
    attach_context(to_explain, root)
    if to_explain and on_progress is not None:
        on_progress(f"Explaining the top {len(to_explain)} Bandit findings with Groq")
    try:
        asyncio.run(explain_findings(to_explain, client=groq_client))
    except Exception:  # noqa: BLE001
        return "failed", _count_explained(ranked)

    explained = _count_explained(ranked)
    if not to_explain or explained == len(to_explain):
        return "ok", explained
    if explained == 0:
        return "failed", 0
    return "partial", explained


def _relative_file_path(file_path: str, root: Path) -> str:
    if not file_path:
        return file_path
    candidate = Path(file_path)
    attempts = [candidate]
    if not candidate.is_absolute():
        attempts.append(root / candidate)
    root_resolved = root.resolve()
    for attempt in attempts:
        try:
            return attempt.resolve().relative_to(root_resolved).as_posix()
        except (ValueError, OSError):
            continue
    try:
        return candidate.relative_to(root).as_posix()
    except ValueError:
        return candidate.as_posix()


def _relativize(findings: list[RankedFinding], root: Path) -> None:
    for finding in findings:
        if finding.tool == ToolName.PIP_AUDIT:
            continue
        finding.file_path = _relative_file_path(finding.file_path, root)


def scan(
    path: Path,
    *,
    explain: bool = True,
    explain_limit: int = 5,
    verbose: bool = False,
    groq_client=None,
    on_progress: Callable[[str], None] | None = None,
) -> ScanResult:
    started = time.perf_counter()
    path = Path(path)
    with prepare_target(path) as root, tempfile.TemporaryDirectory() as out_dir:
        out = Path(out_dir)
        cfg = load_bundle_config()
        plans = configure(cfg, root, out)
        tools = [
            _execute(cfg, tool, plan, out, verbose=verbose, on_progress=on_progress)
            for tool, plan in plans.items()
        ]
        collected = _normalize_runs(tools, out)
        if on_progress is not None:
            on_progress("Ranking findings")
        ranked, deduped_total, bandit_total, bandit_judged, dropped = _rank(collected)
        explain_status, explained = _explain(
            ranked,
            root,
            explain=explain,
            explain_limit=explain_limit,
            groq_client=groq_client,
            on_progress=on_progress,
        )
        _relativize(ranked, root)
        return ScanResult(
            root=root,
            label=path.resolve().name if path.is_dir() else path.name,
            tools=tools,
            findings=ranked,
            raw_total=sum(run.raw for run in tools),
            deduped_total=deduped_total,
            bandit_total=bandit_total,
            bandit_judged=bandit_judged,
            dropped_by_classifier=dropped,
            explain_status=explain_status,
            explained=explained,
            seconds=time.perf_counter() - started,
        )
