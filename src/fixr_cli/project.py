"""Locate a project's dependency files and point the scanners at them."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from static_fixr.config.bundle import BundleConfig
from static_fixr.config.tools.pip_audit import PipAuditArgsConfig
from static_fixr.strings.core import ToolName

DEPENDENCY_FILES = ("pyproject.toml", "requirements.txt")
NOT_PROJECT_DIRS = {".venv", "venv", "env", "site-packages", "node_modules", "__pycache__"}

TOOL_ORDER: tuple[ToolName, ...] = (
    ToolName.BANDIT,
    ToolName.PIP_AUDIT,
    ToolName.DEPTRY,
    ToolName.FLAKE8,
)
_NO_DEPENDENCY_FILE = "no requirements.txt or pyproject.toml found"
_DEPTRY_EXCLUDE = (r".*[\\/](\.?venv|env|site-packages|node_modules|\.git)([\\/]|$)",)

_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
_EXTRAS = r"(?:\[[A-Za-z0-9._-]+(?:\s*,\s*[A-Za-z0-9._-]+)*\])?"
_PINNED = re.compile(rf"^(?P<name>{_NAME})(?P<extras>{_EXTRAS})==(?P<version>[^\s=;,*]+)(?P<rest>.*)$")
_HASH_TOKEN = re.compile(r"^--hash=\S+$")


def bundle_config_path() -> Path:
    return Path(__file__).resolve().parent / "bundle_config.toml"


def load_bundle_config() -> BundleConfig:
    BundleConfig.update_config_filepath(str(bundle_config_path()))
    return BundleConfig()


def _is_project_path(path: Path, root: Path) -> bool:
    return not any(
        part in NOT_PROJECT_DIRS or part.startswith(".")
        for part in path.relative_to(root).parts[:-1]
    )


def find_dependency_root(root: Path) -> Path | None:
    """The shallowest folder holding a dependency file.

    Past GitHub's ``<repo>-main/`` wrapper, and above any nested sub-package
    that has its own pyproject. Virtualenvs and other dot-directories are ignored.
    """
    found = [
        path.parent
        for name in DEPENDENCY_FILES
        for path in root.rglob(name)
        if _is_project_path(path, root)
    ]
    return min(found, key=lambda candidate: len(candidate.parts), default=None)


def local_modules(project_dir: Path) -> tuple[str, ...]:
    """Top-level modules and packages of the project itself (flat and src layouts)."""
    names: set[str] = set()
    for base in (project_dir, project_dir / "src"):
        if not base.is_dir():
            continue
        for child in base.iterdir():
            if child.name in NOT_PROJECT_DIRS or child.name.startswith("."):
                continue
            if child == project_dir / "src":
                continue
            if child.suffix == ".py":
                names.add(child.stem)
            elif child.is_dir() and next(child.rglob("*.py"), None):
                names.add(child.name)
    return tuple(sorted(names))


def _logical_lines(text: str) -> list[str]:
    lines: list[str] = []
    pending = ""
    continuing = False
    for raw in text.splitlines():
        piece = raw.strip()
        if continuing:
            if piece.endswith("\\"):
                pending += " " + piece[:-1].rstrip()
                continue
            lines.append(f"{pending} {piece}".strip())
            pending = ""
            continuing = False
            continue
        if piece.endswith("\\"):
            pending = piece[:-1].rstrip()
            continuing = True
            continue
        lines.append(piece)
    if continuing:
        lines.append(pending.strip())
    return lines


def _strip_inline_comment(line: str) -> str:
    if " #" in line:
        line = line.split(" #", 1)[0]
    return line.strip()


def _tail_is_pin_only(rest: str) -> bool:
    kept = [token for token in rest.split() if not _HASH_TOKEN.match(token)]
    body = " ".join(kept).strip()
    if not body:
        return True
    return body.startswith(";") and body != ";"


def _is_exact_pin(line: str) -> bool:
    match = _PINNED.match(line)
    if match is None:
        return False
    return _tail_is_pin_only(match.group("rest"))


def requirements_fully_pinned(path: Path) -> bool:
    """True when every requirement is an exact ``==`` pin.

    Blank lines and comments are ignored. A trailing backslash joins lines.
    ``-r``, ``-c``, ``-e``, ``--index-url`` and any specifier other than ``==``
    make the file not fully pinned. An empty file is not fully pinned.
    """
    saw_requirement = False
    for line in _logical_lines(path.read_text(encoding="utf-8", errors="replace")):
        line = _strip_inline_comment(line)
        if not line or line.startswith("#"):
            continue
        if line.startswith("-") or not _is_exact_pin(line):
            return False
        saw_requirement = True
    return saw_requirement


class _PipAuditArgs(PipAuditArgsConfig):
    """The bundle emits booleans as ``--no-deps True``, and pip-audit reads the
    stray ``True`` as a project path that conflicts with ``--requirement``."""

    tool_name: ClassVar[str] = PipAuditArgsConfig.tool_name
    tool_output_file: ClassVar[str] = PipAuditArgsConfig.tool_output_file

    def construct_sys_argv_sequence(self) -> list[str]:
        argv = super().construct_sys_argv_sequence()
        return [
            token
            for index, token in enumerate(argv)
            if not (token == "True" and index and argv[index - 1].startswith("--"))
        ]


@dataclass
class ToolPlan:
    tool: str
    skip_reason: str | None = None
    # A requirements file pinning only direct dependencies hides vulnerable transitive
    # ones from a --no-deps audit, so the pinned-only audit is a fallback, not the default.
    pinned_fallback: bool = False


def audit_pinned_only(cfg: BundleConfig) -> None:
    """Check the pinned versions as written, without resolving their dependencies."""
    cfg.PIP_AUDIT_ARGS_CONFIG.no_deps = True
    cfg.PIP_AUDIT_ARGS_CONFIG.disable_pip = True


def configure(cfg: BundleConfig, root: Path, output_dir: Path) -> dict[str, ToolPlan]:
    """Point ``cfg`` at ``root`` and decide which of the four tools can run."""
    cfg.BANDIT_ARGS_CONFIG.targets = [str(root)]
    cfg.FLAKE8_ARGS_CONFIG.targets = str(root)
    cfg.FIXR_CONFIG.common_directory = output_dir
    cfg.FIXR_CONFIG.coerce_human_readable_output = False

    plans = {tool: ToolPlan(tool=tool) for tool in TOOL_ORDER}
    dep_root = find_dependency_root(root)
    if dep_root is None:
        plans[ToolName.PIP_AUDIT].skip_reason = _NO_DEPENDENCY_FILE
        plans[ToolName.DEPTRY].skip_reason = _NO_DEPENDENCY_FILE
    else:
        pip_audit = _PipAuditArgs.model_validate(cfg.PIP_AUDIT_ARGS_CONFIG.model_dump(by_alias=True))
        cfg.PIP_AUDIT_ARGS_CONFIG = pip_audit
        pip_audit.project_path = dep_root
        requirements = dep_root / "requirements.txt"
        if requirements.is_file() and requirements_fully_pinned(requirements):
            plans[ToolName.PIP_AUDIT].pinned_fallback = True

        deptry = cfg.DEPTRY_ARGS_CONFIG
        deptry.root = (dep_root,)
        deptry.config = dep_root / "pyproject.toml"
        deptry.requirements_files = [dep_root / "requirements.txt"]
        deptry.requirements_files_dev = [
            dep_root / name for name in ("dev-requirements.txt", "requirements-dev.txt")
        ]
        deptry.known_first_party = local_modules(dep_root)
        deptry.exclude = _DEPTRY_EXCLUDE

    cfg.FIXR_CONFIG.invocation_order = tuple(
        ToolName(tool) for tool, plan in plans.items() if plan.skip_reason is None
    )
    return plans


def rewrite_transitive(deptry_json: Path) -> None:
    """Rewrite deptry DEP003 (transitive) findings as DEP001 (undeclared).

    deptry reports an undeclared import as transitive when the package happens
    to be installed where deptry runs. For the user's project the import is
    simply not declared.
    """
    if not deptry_json.exists():
        return
    entries = json.loads(deptry_json.read_text(encoding="utf-8"))
    for entry in entries:
        if entry["error"]["code"] == "DEP003":
            module = entry.get("module", "?")
            entry["error"] = {
                "code": "DEP001",
                "message": (
                    f"'{module}' imported but missing from the dependency definitions"
                ),
            }
    deptry_json.write_text(json.dumps(entries), encoding="utf-8")
