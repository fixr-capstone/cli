from pathlib import Path
from zipfile import ZipFile

import pytest

from fixr_cli.target import TargetError, prepare_target


def test_directory_is_used_directly(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    marker = project / "keep.py"
    marker.write_text("x = 1\n", encoding="utf-8")

    with prepare_target(project) as root:
        assert root == project.resolve()
        assert (root / "keep.py").read_text(encoding="utf-8") == "x = 1\n"

    assert marker.is_file()


def test_python_file_is_copied_and_removed(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("print('hi')\n", encoding="utf-8")

    with prepare_target(source) as root:
        assert root != source.parent
        assert (root / "app.py").read_text(encoding="utf-8") == "print('hi')\n"
        held = root

    assert not held.exists()
    assert source.is_file()


def test_zip_unwraps_single_top_level_directory(tmp_path: Path) -> None:
    archive = tmp_path / "project.zip"
    with ZipFile(archive, "w") as zf:
        zf.writestr("repo-main/app.py", "x = 1\n")
        zf.writestr("repo-main/pkg/mod.py", "y = 2\n")

    with prepare_target(archive) as root:
        assert root.name == "repo-main"
        assert (root / "app.py").read_text(encoding="utf-8") == "x = 1\n"
        assert (root / "pkg" / "mod.py").is_file()
        held = root

    assert not held.exists()


def test_zip_slip_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "evil.zip"
    with ZipFile(archive, "w") as zf:
        zf.writestr("../evil.py", "pwned")

    with pytest.raises(TargetError, match="Unsafe ZIP path"), prepare_target(archive):
        pass


def test_missing_path_and_non_zip_are_rejected(tmp_path: Path) -> None:
    notes = tmp_path / "notes.txt"
    notes.write_text("hi", encoding="utf-8")
    with pytest.raises(TargetError), prepare_target(notes):
        pass

    with pytest.raises(TargetError), prepare_target(tmp_path / "missing"):
        pass

    bogus = tmp_path / "nope.zip"
    bogus.write_bytes(b"this is not a zip")
    with pytest.raises(TargetError), prepare_target(bogus):
        pass
