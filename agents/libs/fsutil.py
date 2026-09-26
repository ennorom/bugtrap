"""Small filesystem helpers shared by the runner."""
from __future__ import annotations

import shutil
from pathlib import Path


def maybe_copy(src: Path, dst: Path) -> None:
    if src.is_file():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(src, dst)


def remove_if_exists(path: Path) -> None:
    path.unlink(missing_ok=True)
