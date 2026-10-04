import json
from pathlib import Path

import pytest
from static_fixr.strings.core import ToolName

from fixr_cli.project import (
    audit_pinned_only,
    configure,
    find_dependency_root,
    load_bundle_config,
    local_modules,
    requirements_fully_pinned,
    rewrite_transitive,
)

_NO_DEPS = "no requirements.txt or pyproject.toml found"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("requests==2.32.3\n", True),
        ("requests==2.32.*\n", False),
        ("requests[security]==2.32.3\n", True),
        ("requests>=2.0\n", False),
        ("-r other.txt\n", False),
        ("requests==2.32.3\n-r other.txt\n", False),
        ("--index-url https://pypi.org/simple\nrequests==1.0\n", False),
        ("# comment\n\nrequests==2.32.3  # pinned\n\n", True),
        (
            "requests==2.32.3 \\\n    --hash=sha256:0123456789abcdef\n",
            True,
        ),
        ('requests==2.32.3 ; python_version >= "3.8"\n', True),
        (
            'requests==2.32.3 ; python_version >= "3.8" \\\n    --hash=sha256:0123456789abcdef\n',
            True,
        ),
        ("", False),
        ("# nothing here\n\n", False),
    ],
)
def test_requirements_fully_pinned(tmp_path: Path, text: str, expected: bool) -> None:
    path = tmp_path / "requirements.txt"
    path.write_text(text, encoding="utf-8")
    assert requirements_fully_pinned(path) is expected


def test_dependency_root_ignores_venv_and_picks_shallowest(tmp_path: Path) -> None:
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "requirements.txt").write_text("pip==24.0\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")
    nested = tmp_path / "pkg"
    nested.mkdir()
    (nested / "requirements.txt").write_text("flask==1.0\n", encoding="utf-8")

    assert find_dependency_root(tmp_path) == tmp_path


def test_dependency_root_venv_only_is_absent(tmp_path: Path) -> None:
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "pyproject.toml").write_text("[project]\nname = 'venv'\n", encoding="utf-8")
    assert find_dependency_root(tmp_path) is None


def test_local_modules_flat_and_src(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "mod.py").write_text("y = 1\n", encoding="utf-8")
    lib = tmp_path / "src" / "lib"
    lib.mkdir(parents=True)
    (lib / "core.py").write_text("z = 1\n", encoding="utf-8")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "site.py").write_text("nope = 1\n", encoding="utf-8")

    assert local_modules(tmp_path) == ("app", "lib", "pkg")


def test_configure_requirements_only(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "requirements.txt").write_text("requests>=2.31.0\n", encoding="utf-8")
    out = tmp_path / "out"
    cfg = load_bundle_config()

    plans = configure(cfg, root, out)

    assert list(plans) == ["bandit", "pip-audit", "deptry", "flake8"]
    assert plans["pip-audit"].skip_reason is None
    assert cfg.PIP_AUDIT_ARGS_CONFIG.project_path == root
    assert cfg.PIP_AUDIT_ARGS_CONFIG.no_deps is False
    assert ToolName.PIP_AUDIT in cfg.FIXR_CONFIG.invocation_order
    assert cfg.BANDIT_ARGS_CONFIG.targets == [str(root)]
    assert cfg.FLAKE8_ARGS_CONFIG.targets == str(root)
    assert cfg.FIXR_CONFIG.common_directory == out
    assert cfg.FIXR_CONFIG.coerce_human_readable_output is False


def test_configure_fully_pinned_requirements(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "requirements.txt").write_text(
        "requests==2.32.3 \\\n    --hash=sha256:0123456789abcdef\n",
        encoding="utf-8",
    )
    cfg = load_bundle_config()

    plans = configure(cfg, root, tmp_path / "out")

    assert plans["pip-audit"].skip_reason is None
    assert plans["pip-audit"].pinned_fallback is True
    assert cfg.PIP_AUDIT_ARGS_CONFIG.project_path == root
    assert cfg.PIP_AUDIT_ARGS_CONFIG.no_deps is False

    audit_pinned_only(cfg)
    cfg.PIP_AUDIT_ARGS_CONFIG.project_path = None
    cfg.PIP_AUDIT_ARGS_CONFIG.requirements = [root / "requirements.txt"]
    argv = cfg.PIP_AUDIT_ARGS_CONFIG.construct_sys_argv_sequence()
    assert "True" not in argv
    assert {"--no-deps", "--disable-pip"} <= set(argv)


def test_configure_without_dependency_files(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    cfg = load_bundle_config()

    plans = configure(cfg, root, tmp_path / "out")

    assert plans["pip-audit"].skip_reason == _NO_DEPS
    assert plans["deptry"].skip_reason == _NO_DEPS
    assert ToolName.PIP_AUDIT not in cfg.FIXR_CONFIG.invocation_order
    assert ToolName.DEPTRY not in cfg.FIXR_CONFIG.invocation_order
    assert ToolName.BANDIT in cfg.FIXR_CONFIG.invocation_order
    assert ToolName.FLAKE8 in cfg.FIXR_CONFIG.invocation_order


def test_configure_pyproject_only(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        "[project]\nname = 'demo'\nversion = '0.1.0'\n",
        encoding="utf-8",
    )
    cfg = load_bundle_config()

    plans = configure(cfg, root, tmp_path / "out")

    assert plans["pip-audit"].skip_reason is None
    assert cfg.PIP_AUDIT_ARGS_CONFIG.project_path == root
    assert cfg.PIP_AUDIT_ARGS_CONFIG.no_deps is False
    assert cfg.PIP_AUDIT_ARGS_CONFIG.disable_pip is False
    assert plans["deptry"].skip_reason is None
    assert cfg.DEPTRY_ARGS_CONFIG.root == (root,)


def test_rewrite_transitive_dep003(tmp_path: Path) -> None:
    path = tmp_path / "deptry.json"
    path.write_text(
        json.dumps(
            [
                {"error": {"code": "DEP003", "message": "transitive"}, "module": "requests"},
                {"error": {"code": "DEP002", "message": "unused"}, "module": "flask"},
            ]
        ),
        encoding="utf-8",
    )

    rewrite_transitive(path)

    entries = json.loads(path.read_text(encoding="utf-8"))
    assert entries[0]["error"]["code"] == "DEP001"
    assert "requests" in entries[0]["error"]["message"]
    assert entries[1]["error"]["code"] == "DEP002"


def test_rewrite_transitive_missing_file(tmp_path: Path) -> None:
    rewrite_transitive(tmp_path / "absent.json")
