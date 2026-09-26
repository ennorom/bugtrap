"""Locating the source file, and the code base, for one manifest case.

The file itself comes from the case metadata (preferring the buggy revision
when asked). External-method resolution additionally needs a code base root:
that is a git checkout of the recorded project_url at the recorded revision,
cached under /tmp, or the extracted sample directory when the case ships one.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from agents.libs.jsonio import read_json

AGENTS_DIR = Path(__file__).resolve().parent.parent


def shlex_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


EXTRACTED_SAMPLE_ROOTS = {
    (AGENTS_DIR / "cwe_code_paper").resolve(),
    (AGENTS_DIR / "infer_java_code_paper").resolve(),
}


REPO_BARE_CACHE_ROOT = Path("/tmp/autoanalyzergen_repo_bare_cache")


REPO_CHECKOUT_CACHE_ROOT = Path("/tmp/autoanalyzergen_repo_checkout_cache")


GIT_TIMEOUT = 90


def sanitize_token(value: str, fallback: str = "unknown") -> str:
    token = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in (value or "").strip())
    token = token.strip("_")
    return token or fallback


def resolve_case_source_path(entry: dict, prefer_buggy: bool = False) -> Path:
    source_row = entry.get("_source_row")
    metadata_path = entry.get("metadata_path")
    if metadata_path:
        meta_candidate = Path(str(metadata_path))
        if meta_candidate.is_file():
            try:
                meta = read_json(meta_candidate)
            except Exception:
                meta = None
            if isinstance(meta, dict):
                preferred_file = ""
                if prefer_buggy:
                    preferred_file = str(meta.get("buggy_file_name") or "").strip()
                file_name = preferred_file or str(meta.get("file_name") or "").strip()
                if file_name:
                    source_candidate = meta_candidate.parent / file_name
                    if source_candidate.is_file():
                        return source_candidate
    result_dir = entry.get("result_dir")
    if result_dir:
        result_dir_path = Path(str(result_dir))
        if result_dir_path.is_dir():
            candidates = sorted(result_dir_path.glob("data_*.json"))
            if len(candidates) == 1:
                try:
                    meta = read_json(candidates[0])
                except Exception:
                    meta = None
                if isinstance(meta, dict):
                    preferred_file = ""
                    if prefer_buggy:
                        preferred_file = str(meta.get("buggy_file_name") or "").strip()
                    file_name = preferred_file or str(meta.get("file_name") or meta.get("source_file") or "").strip()
                    if file_name:
                        source_candidate = candidates[0].parent / file_name
                        if source_candidate.is_file():
                            return source_candidate
    return Path(entry["snippet_abs_path"])


def _slugify_project_url(project_url: str) -> str:
    token = re.sub(r"[^A-Za-z0-9._-]+", "_", project_url.strip())
    return token.strip("_") or "repo"


def _ensure_bare_repo(project_url: str) -> Path:
    repo_dir = REPO_BARE_CACHE_ROOT / f"{_slugify_project_url(project_url)}.git"
    if repo_dir.is_dir():
        return repo_dir
    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "-c", "init.defaultBranch=main", "-C", str(repo_dir.parent), "init", "--bare", str(repo_dir.name)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=GIT_TIMEOUT,
    )
    subprocess.run(
        ["git", "--git-dir", str(repo_dir), "remote", "add", "origin", project_url],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=GIT_TIMEOUT,
    )
    return repo_dir


def _fetch_revision_to_bare(project_url: str, revision: str) -> Path | None:
    if not project_url or not revision:
        return None
    try:
        repo_dir = _ensure_bare_repo(project_url)
        subprocess.run(
            ["git", "--git-dir", str(repo_dir), "fetch", "--depth", "1", "origin", revision],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=GIT_TIMEOUT,
        )
        return repo_dir
    except Exception:
        return None


def _ensure_repo_checkout(project_url: str, revision: str) -> Path | None:
    repo_dir = _fetch_revision_to_bare(project_url, revision)
    if repo_dir is None:
        return None
    checkout_dir = REPO_CHECKOUT_CACHE_ROOT / _slugify_project_url(project_url) / revision
    ready_marker = checkout_dir / ".ready"
    if ready_marker.is_file():
        return checkout_dir
    checkout_dir.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [
                "bash",
                "-lc",
                f"git --git-dir {shlex_quote(str(repo_dir))} archive {shlex_quote(revision)} | tar -x -C {shlex_quote(str(checkout_dir))}",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=GIT_TIMEOUT * 2,
        )
        ready_marker.write_text("ok\n", encoding="utf-8")
        return checkout_dir
    except Exception:
        return None


def _load_case_metadata(entry: dict) -> dict | None:
    metadata_path = str(entry.get("metadata_path") or "").strip()
    if not metadata_path:
        return None
    candidate = Path(metadata_path)
    if not candidate.is_file():
        return None
    try:
        payload = read_json(candidate)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def derive_external_resolution_inputs(source_path: Path, entry: dict) -> tuple[str, str]:
    meta = _load_case_metadata(entry) or {}
    project_url = str(meta.get("project_url") or "").strip()
    filepath = str(meta.get("filepath") or "").strip()
    prefer_buggy = source_path.name == str(meta.get("buggy_file_name") or "").strip()
    revision = ""
    if prefer_buggy:
        revision = str(meta.get("buggy_revision") or "").strip()
    else:
        revision = str(meta.get("fixed_revision") or meta.get("commit_id") or "").strip()
    if project_url and filepath and revision:
        checkout_root = _ensure_repo_checkout(project_url, revision)
        if checkout_root is not None and (checkout_root / filepath).is_file():
            return str(checkout_root), filepath
    try:
        resolved_source = source_path.resolve()
    except Exception:
        resolved_source = source_path
    for sample_root in EXTRACTED_SAMPLE_ROOTS:
        try:
            resolved_source.relative_to(sample_root)
            return "", ""
        except Exception:
            pass
    result_dir_raw = str(entry.get("result_dir") or "").strip()
    result_dir = Path(result_dir_raw).resolve() if result_dir_raw else source_path.parent
    code_base_root: Path | None = None
    if result_dir.is_dir() and result_dir.name.startswith("result_Paper_") and result_dir.parent.is_dir():
        code_base_root = result_dir.parent
    elif source_path.parent.parent.is_dir():
        code_base_root = source_path.parent.parent
    if code_base_root is None:
        return "", ""
    try:
        source_rel_path = str(source_path.resolve().relative_to(code_base_root.resolve())).replace("\\", "/")
    except Exception:
        return "", ""
    return str(code_base_root.resolve()), source_rel_path
