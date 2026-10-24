"""Command-line interface for fixr."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from fixr_cli import __version__

# The scanners, model and Groq client are imported inside the commands: flake8's worker
# processes re-import this module on macOS, and each would otherwise pay seconds of imports.


def main(argv: list[str] | None = None, *, groq_client=None) -> int:
    try:
        return _main(argv, groq_client=groq_client)
    except KeyboardInterrupt:
        return 130
    except SystemExit as exc:
        return _exit_code(exc)


def _exit_code(exc: SystemExit) -> int:
    code = exc.code
    if code is None or code == 0:
        return 0
    if isinstance(code, int):
        return code
    return 1


def _main(argv: list[str] | None, *, groq_client) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "command", None) is None:
        parser.print_help(sys.stderr)
        return 2
    if args.command == "chat":
        return _chat(args, groq_client=groq_client)
    return _scan(args, groq_client=groq_client)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fixr",
        description="Find, rank and explain security issues in Python code, on your machine.",
    )
    parser.add_argument("--version", action="version", version=f"fixr {__version__}")
    subparsers = parser.add_subparsers(dest="command")
    _add_scan_parser(subparsers)
    _add_chat_parser(subparsers)
    return parser


def _add_scan_parser(subparsers: argparse._SubParsersAction) -> None:
    scan_parser = subparsers.add_parser(
        "scan", help="Scan a Python project", description="Scan a Python project."
    )
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        metavar="PATH",
        help="folder, .py file or .zip to scan (default: the current folder)",
    )
    scan_parser.add_argument(
        "--format", choices=("text", "json"), default="text", help="output format (default: text)"
    )
    scan_parser.add_argument(
        "--fix-prompt", metavar="FILE", help="also write a fix prompt for an AI coding tool"
    )
    _add_explain_options(scan_parser)
    scan_parser.add_argument(
        "--show-style", action="store_true", help="list every style note instead of a summary"
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high"),
        default="high",
        help="lowest severity that makes the exit code 1 (default: high)",
    )
    _add_verbose_option(scan_parser)


def _add_chat_parser(subparsers: argparse._SubParsersAction) -> None:
    chat_parser = subparsers.add_parser(
        "chat",
        help="Ask questions about a scan",
        description="Ask questions about a scan. Needs GROQ_API_KEY.",
    )
    source = chat_parser.add_mutually_exclusive_group()
    source.add_argument(
        "path",
        nargs="?",
        default=None,
        metavar="PATH",
        help="folder, .py file or .zip to scan first (default: the current folder)",
    )
    source.add_argument(
        "--from",
        dest="from_file",
        metavar="FILE",
        help="chat about a saved `fixr scan --format json` result instead of scanning",
    )
    _add_explain_options(chat_parser)
    _add_verbose_option(chat_parser)


def _add_explain_options(parser: argparse.ArgumentParser) -> None:
    explain = parser.add_mutually_exclusive_group()
    explain.add_argument(
        "--no-explain", action="store_true", help="do not send any code to Groq for explanations"
    )
    explain.add_argument(
        "--explain",
        type=_explain_count,
        metavar="N",
        help="explain the top N Bandit findings with Groq (1-20, default: 5)",
    )


def _add_verbose_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--verbose", action="store_true", help="show the scanners' own logs")


def _explain_count(value: str) -> int:
    try:
        count = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("explain limit must be an integer from 1 to 20") from exc
    if count < 1 or count > 20:
        raise argparse.ArgumentTypeError("explain limit must be an integer from 1 to 20")
    return count


def _scan(args: argparse.Namespace, *, groq_client) -> int:
    from fixr_cli.engine import scan
    from fixr_cli.render import build_report, failing
    from fixr_cli.target import TargetError

    explain_limit = 5 if args.explain is None else args.explain
    status, on_progress = _start_progress(args, enabled=args.format == "text")
    try:
        result = scan(
            Path(args.path),
            explain=not args.no_explain,
            explain_limit=explain_limit,
            verbose=args.verbose,
            groq_client=groq_client,
            on_progress=on_progress,
        )
    except TargetError as exc:
        print(f"fixr: error: {exc}", file=sys.stderr)
        return 2
    finally:
        if status is not None:
            status.stop()

    report = build_report(result, fail_on=args.fail_on, explain_limit=explain_limit)
    _emit(report, args)
    if args.fix_prompt and _write_fix_prompt(report, args) != 0:
        return 2
    considered = [run for run in result.tools if run.status != "skipped"]
    if considered and all(run.status == "failed" for run in considered):
        print("fixr: error: every scanner failed", file=sys.stderr)
        return 2
    if failing(report):
        return 1
    return 0


def _start_progress(args: argparse.Namespace, *, enabled: bool = True):
    if not enabled or args.verbose or not sys.stderr.isatty():
        return None, None
    from rich.console import Console

    status = Console(stderr=True).status("Scanning")
    status.start()

    def on_progress(message: str) -> None:
        status.update(message)

    return status, on_progress


def _chat(args: argparse.Namespace, *, groq_client) -> int:
    # Importing fixr_rag loads GROQ_API_KEY from a .env file, so this precedes the key check.
    from fixr_cli.chat import load_results, run_chat
    from fixr_cli.engine import scan
    from fixr_cli.render import build_report
    from fixr_cli.target import TargetError

    if groq_client is None and not os.environ.get("GROQ_API_KEY"):
        print(
            "fixr: error: fixr chat needs a Groq API key. Set GROQ_API_KEY and try again.",
            file=sys.stderr,
        )
        return 2
    if args.from_file is not None:
        try:
            label, findings = load_results(Path(args.from_file))
        except OSError as exc:
            reason = exc.strerror or str(exc)
            print(f"fixr: error: cannot read {args.from_file}: {reason}", file=sys.stderr)
            return 2
        except ValueError as exc:
            print(f"fixr: error: cannot read {args.from_file}: {exc}", file=sys.stderr)
            return 2
        return run_chat(findings, label=label, groq_client=groq_client)

    path = args.path if args.path is not None else "."
    explain_limit = 5 if args.explain is None else args.explain
    status, on_progress = _start_progress(args)
    try:
        result = scan(
            Path(path),
            explain=not args.no_explain,
            explain_limit=explain_limit,
            verbose=args.verbose,
            groq_client=groq_client,
            on_progress=on_progress,
        )
    except TargetError as exc:
        print(f"fixr: error: {exc}", file=sys.stderr)
        return 2
    finally:
        if status is not None:
            status.stop()
    report = build_report(result, explain_limit=explain_limit)
    return run_chat(report.display, label=result.label, groq_client=groq_client)


def _emit(report, args: argparse.Namespace) -> None:
    from rich.console import Console

    from fixr_cli.render import no_key_notice, render_text, to_json

    if args.format == "json":
        if report.result.explain_status == "no-key":
            print(no_key_notice(report.explain_limit), file=sys.stderr)
        print(json.dumps(to_json(report), indent=2))
        return
    render_text(report, Console(), show_style=args.show_style)


def _write_fix_prompt(report, args: argparse.Namespace) -> int:
    from fixr_cli.render import fix_prompt_text

    path = args.fix_prompt
    try:
        Path(path).write_text(fix_prompt_text(report), encoding="utf-8")
    except OSError as exc:
        reason = exc.strerror or str(exc)
        print(f"fixr: error: cannot write {path}: {reason}", file=sys.stderr)
        return 2
    stream = sys.stderr if args.format == "json" else sys.stdout
    print(f"Fix prompt for an AI coding tool written to {path}", file=stream)
    return 0
