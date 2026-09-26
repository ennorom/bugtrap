"""Backward/forward slice context for a decision candidate.

Seeds a Joern slice at the candidate line; when that line carries no CFG node,
probes nearby lines and then the enclosing method's own lines, and finally
falls back to a local window of the method text. Results are cached per
(file, line, direction) for the duration of one file's run.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from agents.libs.language_support import detect_language_from_path
from agents.libs.drivers import get as get_driver

# C/C++ slicing has one tool and no fallback: a failed slice is reported and the
# caller degrades to a local window of the method.
SLICE_DRIVER = "joern"


def _slice_invoker(mode: str):
    """Adapt the driver contract to the (path, line, ...) call these helpers use."""
    driver = get_driver(SLICE_DRIVER)

    def invoke(source_path, probe_line, var_name="", scanned_file="", widen=0):
        return driver.analyze(source_path, mode, lines=probe_line, var_name=var_name,
                              scanned_file=scanned_file, widen=widen)

    return invoke
from agents.libs.evidence import prompt_text


SLICE_NEARBY_OFFSETS = (0, -1, 1, -2, 2, -3, 3)


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _candidate_method_bounds(candidate: Dict[str, Any], criterion_line: int) -> tuple[int | None, int | None]:
    start_line = _to_int(candidate.get("method_start_line"))
    end_line = _to_int(candidate.get("method_end_line"))
    if start_line and end_line and end_line >= start_line:
        return start_line, end_line

    rel_line = _to_int(candidate.get("method_line_number"))
    method_content = str(candidate.get("method_content") or "")
    method_len = len(method_content.splitlines()) if method_content else 0
    if rel_line and rel_line > 0 and method_len > 0:
        inferred_start = criterion_line - rel_line + 1
        inferred_end = inferred_start + method_len - 1
        if inferred_start > 0 and inferred_end >= inferred_start:
            if not start_line:
                start_line = inferred_start
            if not end_line:
                end_line = inferred_end
    return start_line, end_line


def _internal_analysis_probe_lines(candidate: Dict[str, Any], criterion_line: int) -> list[int]:
    analysis_result = candidate.get("internal_analysis_result")
    if not isinstance(analysis_result, dict) or analysis_result.get("status") != "ok":
        return []
    method = analysis_result.get("method")
    if not isinstance(method, dict):
        return []
    body = method.get("body")
    if not isinstance(body, list):
        return []

    lines: set[int] = set()
    for entry in body:
        if not isinstance(entry, dict):
            continue
        line = _to_int(entry.get("line"))
        if line and line > 0:
            lines.add(line)
    return sorted(lines, key=lambda line: (abs(line - criterion_line), line))


def _candidate_probe_lines(candidate: Dict[str, Any], criterion_line: int) -> list[int]:
    start_line, end_line = _candidate_method_bounds(candidate, criterion_line)
    probe_lines: list[int] = []
    seen: set[int] = set()
    preferred_lines = [criterion_line + offset for offset in SLICE_NEARBY_OFFSETS]
    preferred_lines.extend(_internal_analysis_probe_lines(candidate, criterion_line))
    for line in preferred_lines:
        if line <= 0:
            continue
        if start_line is not None and line < start_line:
            continue
        if end_line is not None and line > end_line:
            continue
        if line in seen:
            continue
        seen.add(line)
        probe_lines.append(line)
    return probe_lines or [criterion_line]


def _invoke_cached_slice(
    source_path: Path,
    probe_line: int,
    cache_suffix: str,
    slice_cache: Dict[tuple[str, int, str], Dict[str, Any]],
    invoker,
    joern_widen: int = 0,
) -> Dict[str, Any]:
    # Encode widen into the suffix so a widen>0 retry is not shadowed by a
    # previously-cached widen=0 empty result.
    widen_tag = f"w{int(joern_widen)}" if int(joern_widen) > 0 else ""
    cache_key = (str(source_path), probe_line, f"{cache_suffix}{widen_tag}")
    slice_result = slice_cache.get(cache_key)
    if slice_result is None:
        slice_result = invoker(
            source_path, probe_line, var_name="", scanned_file=source_path.name,
            widen=int(joern_widen),
        )
        slice_cache[cache_key] = slice_result
    return slice_result


def _finalize_slice_result(
    source_path: Path,
    requested_line: int,
    used_line: int,
    slice_result: Dict[str, Any],
    attempts: list[int] | None = None,
    direction: str | None = None,
) -> Dict[str, Any]:
    criterion = slice_result.get("criterion")
    if isinstance(criterion, dict):
        criterion_payload = dict(criterion)
    else:
        criterion_payload = {"line": used_line, "var": ""}
    if used_line != requested_line:
        criterion_payload["requested_line"] = requested_line
        criterion_payload["used_line"] = used_line
        criterion_payload["used_line_offset"] = used_line - requested_line

    result: Dict[str, Any] = {
        "tool": slice_result.get("tool"),
        "status": slice_result.get("status"),
        "language": detect_language_from_path(source_path),
        "criterion": criterion_payload,
    }
    if direction:
        result["direction"] = direction
    if attempts and len(attempts) > 1:
        result["attempted_lines"] = attempts

    if slice_result.get("status") != "ok":
        result["message"] = slice_result.get("message", "slice failed")
        return result

    result["slice_lines"] = slice_result.get("slice_lines") or []
    result["slice_stmts"] = slice_result.get("slice_stmts") or []
    result["slice_code"] = slice_result.get("slice_code") or ""
    result["seed_count"] = slice_result.get("seed_count", 0)
    return result


def _build_candidate_slice(source_path: Path, candidate: Dict[str, Any],
                           slice_cache: Dict[tuple[str, int, str], Dict[str, Any]],
                           joern_widen: int = 0) -> Dict[str, Any]:
    criterion_line = candidate.get("line_number")
    try:
        criterion_line = int(criterion_line)
    except (TypeError, ValueError):
        return {
            "tool": "joern",
            "status": "error",
            "language": detect_language_from_path(source_path),
            "criterion": {"line": candidate.get("line_number"), "var": ""},
            "message": "missing or invalid candidate line number",
        }

    probe_lines = _candidate_probe_lines(candidate, criterion_line)
    exact_result = _invoke_cached_slice(
        source_path, criterion_line, "", slice_cache, _slice_invoker("slice"),
        joern_widen=joern_widen,
    )
    if exact_result.get("status") == "ok" and (exact_result.get("slice_lines") or []):
        return _finalize_slice_result(source_path, criterion_line, criterion_line, exact_result)

    if exact_result.get("status") != "ok":
        return _finalize_slice_result(source_path, criterion_line, criterion_line, exact_result, probe_lines)

    for probe_line in probe_lines:
        if probe_line == criterion_line:
            continue
        probe_result = _invoke_cached_slice(
            source_path, probe_line, "", slice_cache, _slice_invoker("slice"),
            joern_widen=joern_widen,
        )
        if probe_result.get("status") == "ok" and (probe_result.get("slice_lines") or []):
            return _finalize_slice_result(
                source_path, criterion_line, probe_line, probe_result, probe_lines
            )

    result = _finalize_slice_result(source_path, criterion_line, criterion_line, exact_result, probe_lines)
    result["status"] = "error"
    result["message"] = f"empty slice near line {criterion_line}"
    return result


def _build_candidate_forward_slice(source_path: Path, candidate: Dict[str, Any],
                                   slice_cache: Dict[tuple[str, int, str], Dict[str, Any]],
                                   joern_widen: int = 0) -> Dict[str, Any]:
    """Forward slice from the candidate line — shows where the candidate's
    value/state flows downstream. Mirror of _build_candidate_slice but with
    a separate cache key suffix ('fwd') so the two slices don't collide."""
    criterion_line = candidate.get("line_number")
    try:
        criterion_line = int(criterion_line)
    except (TypeError, ValueError):
        return {
            "tool": "joern",
            "status": "error",
            "language": detect_language_from_path(source_path),
            "criterion": {"line": candidate.get("line_number"), "var": ""},
            "message": "missing or invalid candidate line number",
        }

    probe_lines = _candidate_probe_lines(candidate, criterion_line)
    exact_result = _invoke_cached_slice(
        source_path, criterion_line, "fwd", slice_cache, _slice_invoker("forward_slice"),
        joern_widen=joern_widen,
    )
    if exact_result.get("status") == "ok" and (exact_result.get("slice_lines") or []):
        return _finalize_slice_result(
            source_path, criterion_line, criterion_line, exact_result, direction="forward"
        )

    if exact_result.get("status") != "ok":
        result = _finalize_slice_result(
            source_path, criterion_line, criterion_line, exact_result, probe_lines, direction="forward"
        )
        result["message"] = result.get("message", "forward slice failed")
        return result

    for probe_line in probe_lines:
        if probe_line == criterion_line:
            continue
        probe_result = _invoke_cached_slice(
            source_path, probe_line, "fwd", slice_cache, _slice_invoker("forward_slice"),
            joern_widen=joern_widen,
        )
        if probe_result.get("status") == "ok" and (probe_result.get("slice_lines") or []):
            return _finalize_slice_result(
                source_path, criterion_line, probe_line, probe_result, probe_lines, direction="forward"
            )

    result = _finalize_slice_result(
        source_path, criterion_line, criterion_line, exact_result, probe_lines, direction="forward"
    )
    result["status"] = "error"
    result["message"] = f"empty forward slice near line {criterion_line}"
    return result


def _build_candidate_window_block(candidate: Dict[str, Any], radius: int = 6) -> str:
    method_content = prompt_text(candidate.get("method_content") or candidate.get("method_body"))
    if not method_content:
        return ""

    rel_line = _to_int(candidate.get("method_line_number"))
    if not rel_line or rel_line <= 0:
        return method_content

    lines = method_content.splitlines()
    if not lines:
        return method_content

    idx = min(max(rel_line - 1, 0), len(lines) - 1)
    start_idx = max(0, idx - radius)
    end_idx = min(len(lines), idx + radius + 1)
    criterion_line = _to_int(candidate.get("line_number")) or rel_line
    start_line, _ = _candidate_method_bounds(candidate, criterion_line)
    if start_line is None:
        return "\n".join(lines[start_idx:end_idx]).strip()
    return "\n".join(
        f"{start_line + line_idx:5d}: {lines[line_idx]}"
        for line_idx in range(start_idx, end_idx)
    ).strip()


def resolve_candidate_context(candidate: Dict[str, Any], source_path: Path | None,
                               decision_context: str,
                               slice_cache: Dict[tuple[str, int, str], Dict[str, Any]],
                               joern_widen: int = 0) -> Dict[str, Any]:
    method_content = prompt_text(candidate.get("method_content"))
    mode = (decision_context or "method").strip().lower()
    if mode != "slice" or source_path is None:
        return {
            "mode": "method",
            "label": "candidate_method_content",
            "block": method_content or "(empty)",
        }

    backward = _build_candidate_slice(source_path, candidate, slice_cache, joern_widen=joern_widen)
    forward = _build_candidate_forward_slice(source_path, candidate, slice_cache, joern_widen=joern_widen)

    back_ok = backward.get("status") == "ok" and prompt_text(backward.get("slice_code"))
    fwd_ok = forward.get("status") == "ok" and prompt_text(forward.get("slice_code"))

    if back_ok or fwd_ok:
        parts = []
        if back_ok:
            parts.append("----- BACKWARD SLICE (what feeds the candidate) -----\n"
                         + prompt_text(backward.get("slice_code")))
        if fwd_ok:
            parts.append("----- FORWARD SLICE (where the candidate's value/state flows) -----\n"
                         + prompt_text(forward.get("slice_code")))
        return {
            "mode": "slice",
            "label": "candidate_slice_content",
            "block": "\n\n".join(parts),
            "slice": backward,
            "forward_slice": forward,
        }

    window_block = _build_candidate_window_block(candidate)
    if window_block:
        return {
            "mode": "slice-fallback-window",
            "label": "candidate_local_window_fallback",
            "block": window_block,
            "slice": backward,
            "forward_slice": forward,
        }

    return {
        "mode": "slice-fallback-method",
        "label": "candidate_method_content_fallback",
        "block": method_content or "(empty)",
        "slice": backward,
        "forward_slice": forward,
    }
