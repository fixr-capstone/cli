"""Turn a user-supplied path into a directory the scanners can read."""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from zipfile import BadZipFile, LargeZipFile, ZipFile

MAX_ZIP_ENTRIES = 20_000
MAX_EXTRACTED_BYTES = 500 * 2**20


class TargetError(Exception):
    """The path cannot be prepared as a scan root."""


def _safe_extract(archive: ZipFile, destination: Path) -> None:
    destination = destination.resolve()
    members = archive.infolist()
    if len(members) > MAX_ZIP_ENTRIES:
        raise TargetError(f"ZIP has more than {MAX_ZIP_ENTRIES} entries")
    declared = sum(member.file_size for member in members)
    if declared > MAX_EXTRACTED_BYTES:
        raise TargetError(f"ZIP expands to more than {MAX_EXTRACTED_BYTES // 2**20} MB")

    for member in members:
        target = (destination / member.filename).resolve()
        if not target.is_relative_to(destination):
            raise TargetError(f"Unsafe ZIP path: {member.filename}")

    archive.extractall(destination)


def _unwrap_single_directory(extracted: Path) -> Path:
    entries = list(extracted.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return extracted


@contextmanager
def prepare_target(path: Path) -> Iterator[Path]:
    """Yield the directory to scan, deleting any temporary copy on exit.

    A directory is used in place. A ``.py`` file is copied into a fresh
    temporary directory. A ``.zip`` is extracted there; when the archive has
    exactly one top-level directory (GitHub's ``<repo>-main`` wrapper), that
    directory is yielded instead of the extract root.
    """
    path = Path(path)
    if path.is_dir():
        yield path.resolve()
        return

    suffix = path.suffix.lower()
    if path.is_file() and suffix == ".py":
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp)
            shutil.copy(path, dest / path.name)
            yield dest
        return

    if path.is_file() and suffix == ".zip":
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp)
            try:
                with ZipFile(path) as archive:
                    _safe_extract(archive, dest)
            except TargetError:
                raise
            except (BadZipFile, LargeZipFile, OSError, ValueError) as exc:
                raise TargetError(f"not a valid ZIP file: {path}") from exc
            yield _unwrap_single_directory(dest)
        return

    if not path.exists():
        raise TargetError(f"path does not exist: {path}")
    raise TargetError(f"unsupported target (expected a directory, .py file, or .zip): {path}")
