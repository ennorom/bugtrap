"""Joern driver: C/C++ CFG/DFG/AST extraction and slicing.

C/C++ has no second tool, so a failure is reported rather than substituted:
`analyze` returns the error payload and the caller logs it. The .sc scripts it
runs live in joern_scripts/ next to this module.

Output schema matches SootDriver/ComexDriver:
  {
    "tool": "joern",
    "status": "ok",
    "classes": [{"name": "Global", "methods": [{...}]}]
  }
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from agents.libs.drivers.base import AnalysisDriver, error_payload, normalize_envelope, register

# Default timeout; can be overridden by caller.
JOERN_TIMEOUT_SECONDS: int = 120

_SCRIPTS_DIR = Path(__file__).resolve().parent / "joern_scripts"
# Transcripts have always been written to the internal analysis agent's logs/.
_LOG_DIR = Path(__file__).resolve().parents[2] / "internal_analysis_agent" / "logs"
_SCRIPT_MAP = {
    "cfg": "cfg.sc",
    "dfg": "dfg.sc",
    "ast": "ast.sc",
    "slice": "slice.sc",
    "forward_slice": "forward_slice.sc",
    "member_types": "member_types.sc",
}
_JOERN_CANDIDATES = [
    Path("/local/home/ennorom/projects/packages/joern-cli/joern"),
    Path("/local/home/ennorom/projects/packages/joern-cli/bin/joern"),
]
_JAVA_HOME_CANDIDATES = [
    Path("/usr/lib/jvm/jdk21"),
    Path("/usr/lib/jvm/java-21"),
    Path("/usr/lib/jvm/java-17"),
    Path("/usr/lib/jvm/java"),
]
_C_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
_LINUX_KERNEL_QUALIFIERS = (
    "__user",
    "__iomem",
    "__force",
    "__percpu",
    "__rcu",
)


def _find_joern() -> Optional[str]:
    found = shutil.which("joern")
    if found:
        return found
    for candidate in _JOERN_CANDIDATES:
        if candidate.is_file():
            return str(candidate)
    return None


def _find_java_home() -> Optional[str]:
    env_java_home = str(os.environ.get("JAVA_HOME") or "").strip()
    if env_java_home:
        candidate = Path(env_java_home).expanduser()
        if candidate.is_dir():
            return str(candidate)
    for candidate in _JAVA_HOME_CANDIDATES:
        if candidate.is_dir():
            return str(candidate)
    return None


def _safe_name(name: str) -> str:
    return re.sub(r"[^\w.-]", "_", name or "unknown")


def _needs_c_normalization(source_path: Path, text: str) -> bool:
    return source_path.suffix.lower() in _C_SOURCE_SUFFIXES and any(
        token in text for token in _LINUX_KERNEL_QUALIFIERS
    )


def _strip_kernel_qualifiers(text: str) -> str:
    normalized = text
    for token in _LINUX_KERNEL_QUALIFIERS:
        normalized = re.sub(rf"\b{re.escape(token)}\b", " " * len(token), normalized)
    return normalized


def _prepare_joern_source(source_path: Path) -> tuple[Path, str | None]:
    try:
        text = source_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return source_path, None
    if not _needs_c_normalization(source_path, text):
        return source_path, None
    normalized = _strip_kernel_qualifiers(text)
    if normalized == text:
        return source_path, None
    temp_dir = tempfile.mkdtemp(prefix="joern_src_")
    analysis_name = f"{source_path.stem}__joern_norm{source_path.suffix}"
    analysis_path = Path(temp_dir) / analysis_name
    analysis_path.write_text(normalized, encoding="utf-8")
    return analysis_path, temp_dir


def _log_raw(mode: str, scanned_file: str, stdout: str, stderr: str) -> None:
    log_dir = _LOG_DIR
    log_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = _safe_name(scanned_file)
    path = log_dir / f"internal_analysis_joern_{mode}_{ts}_{safe}.txt"
    path.write_text(
        f"scanned_file: {scanned_file}\ntool: joern/{mode}\n\nSTDOUT:\n{stdout}\n\nSTDERR:\n{stderr}\n",
        encoding="utf-8",
    )


def _extract_last_json(text: str) -> Optional[Dict[str, Any]]:
    """
    Extract the last valid top-level JSON object from text.
    Joern may print progress/status lines before the actual JSON output.
    """
    starts = [idx for idx in range(len(text)) if text.startswith('{"status"', idx)]
    starts.extend(idx for idx in range(len(text)) if text.startswith('{"tool"', idx))
    seen: set[int] = set()
    for start in reversed(starts):
        if start in seen:
            continue
        seen.add(start)
        depth = 0
        in_string = False
        escaped = False
        for end in range(start, len(text)):
            ch = text[end]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : end + 1])
                    except json.JSONDecodeError:
                        break
    return None


def invoke_joern_slice(
    source_path: Path,
    lines: "int | list[int]",
    var_name: str = "",
    scanned_file: str = "",
    timeout: int = JOERN_TIMEOUT_SECONDS,
    widen: int = 0,
) -> Dict[str, Any]:
    """Run a backward slice on *source_path* seeded from one or more lines.

    Joern walks the PDG backward from all seed lines in a single traversal
    and returns the union slice. *widen* (default 0 = disabled) is forwarded
    to the slice script as the opt-in fallback radius for cases where the
    exact seed line has no CFG node attached (see slice.sc docs).
    """
    if isinstance(lines, int):
        seed_iter = [lines]
    else:
        seed_iter = list(lines)
    seeds = sorted({int(x) for x in seed_iter if int(x) > 0})
    if not seeds:
        return {"tool": "joern", "status": "error", "message": "no seed lines"}
    extra = [("lines", ",".join(str(x) for x in seeds))]
    if var_name:
        extra.append(("var", var_name))
    if widen and int(widen) > 0:
        extra.append(("widen", str(int(widen))))
    return invoke_joern_file(
        source_path, "slice", scanned_file=scanned_file, timeout=timeout, extra_params=extra
    )


def invoke_joern_forward_slice(
    source_path: Path,
    lines: "int | list[int]",
    var_name: str = "",
    scanned_file: str = "",
    timeout: int = JOERN_TIMEOUT_SECONDS,
    widen: int = 0,
) -> Dict[str, Any]:
    """Run a forward slice on *source_path* seeded from one or more lines.

    *widen* (default 0 = disabled) is forwarded to the forward_slice script
    as the opt-in fallback radius for cases where the exact seed line has no
    CFG node attached (see forward_slice.sc docs).
    """
    if isinstance(lines, int):
        seed_iter = [lines]
    else:
        seed_iter = list(lines)
    seeds = sorted({int(x) for x in seed_iter if int(x) > 0})
    if not seeds:
        return {"tool": "joern", "status": "error", "message": "no seed lines"}
    extra = [("lines", ",".join(str(x) for x in seeds))]
    if var_name:
        extra.append(("var", var_name))
    if widen and int(widen) > 0:
        extra.append(("widen", str(int(widen))))
    return invoke_joern_file(
        source_path, "forward_slice", scanned_file=scanned_file, timeout=timeout, extra_params=extra
    )


def invoke_joern_file(
    source_path: Path,
    mode: str,
    scanned_file: str = "",
    timeout: int = JOERN_TIMEOUT_SECONDS,
    extra_params: Optional[list] = None,
) -> Dict[str, Any]:
    """
    Run Joern on *source_path* (a C/C++ file) and extract CFG, DFG, or AST
    for all user-defined methods.

    Args:
        source_path: Path to the .c/.cpp/.h/... file.
        mode:        One of "cfg", "dfg", "ast".
        scanned_file: Label used for log file naming only.
        timeout:     Max seconds to wait for Joern (0 = no limit).

    Returns:
        dict with keys: tool, status, classes (on success) or message (on error).
    """
    joern_bin = _find_joern()
    if not joern_bin:
        return {
            "tool": "joern",
            "status": "error",
            "message": (
                "joern binary not found in PATH. "
                "Install Joern (https://joern.io) and ensure it is on PATH."
            ),
        }

    script_name = _SCRIPT_MAP.get(mode.lower())
    if not script_name:
        return {"tool": "joern", "status": "error", "message": f"Unknown mode: {mode}"}

    script_path = _SCRIPTS_DIR / script_name
    if not script_path.exists():
        return {
            "tool": "joern",
            "status": "error",
            "message": f"Joern script not found: {script_path}",
        }

    analysis_path, analysis_temp_dir = _prepare_joern_source(source_path)

    cmd = [
        joern_bin,
        "--script", str(script_path),
        "--param", f"file={analysis_path}",
    ]
    for key, value in (extra_params or []):
        cmd.extend(["--param", f"{key}={value}"])
    ws_dir = tempfile.mkdtemp(prefix="joern_ws_")
    try:
        env = dict(os.environ)
        env["JOERN_WORKSPACE"] = ws_dir
        java_home = _find_java_home()
        if java_home:
            env["JAVA_HOME"] = java_home
            env["PATH"] = f"{Path(java_home) / 'bin'}:{env.get('PATH', '')}"
        t = timeout if timeout > 0 else None
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=t, env=env)
    except subprocess.TimeoutExpired:
        shutil.rmtree(ws_dir, ignore_errors=True)
        if analysis_temp_dir:
            shutil.rmtree(analysis_temp_dir, ignore_errors=True)
        return {
            "tool": "joern",
            "status": "error",
            "message": f"Joern timed out after {timeout}s analysing {source_path.name}",
        }
    except OSError as exc:
        shutil.rmtree(ws_dir, ignore_errors=True)
        if analysis_temp_dir:
            shutil.rmtree(analysis_temp_dir, ignore_errors=True)
        return {"tool": "joern", "status": "error", "message": str(exc)}
    finally:
        shutil.rmtree(ws_dir, ignore_errors=True)
        if analysis_temp_dir:
            shutil.rmtree(analysis_temp_dir, ignore_errors=True)

    _log_raw(mode, scanned_file, proc.stdout, proc.stderr)

    # Non-zero exit is only fatal when there is no usable output.
    if proc.returncode != 0 and not proc.stdout.strip():
        msg = (proc.stderr or proc.stdout or "Joern exited non-zero").strip()
        return {"tool": "joern", "status": "error", "message": msg[:400]}

    result = _extract_last_json(proc.stdout)
    if result is None:
        snippet = proc.stdout.strip()[:200]
        return {
            "tool": "joern",
            "status": "error",
            "message": f"No JSON found in Joern output. stdout: {snippet}",
        }

    result.setdefault("tool", "joern")
    return result


@register
class JoernDriver(AnalysisDriver):
    name = "joern"
    languages = frozenset({"c", "cpp", "c++"})
    modes = frozenset({"ast", "cfg", "dfg", "member_types", "slice", "forward_slice"})

    def analyze(self, source_path: Path, mode: str, *, scanned_file: str = "",
                timeout: int = JOERN_TIMEOUT_SECONDS, lines: Any = None,
                var_name: str = "", widen: int = 0, **_: Any) -> Dict[str, Any]:
        path = Path(source_path)
        if mode in ("slice", "forward_slice"):
            if lines is None:
                return error_payload(self.name, "no seed lines")
            invoke = invoke_joern_slice if mode == "slice" else invoke_joern_forward_slice
            result = invoke(path, lines, var_name=var_name, scanned_file=scanned_file,
                            timeout=timeout, widen=widen)
            return normalize_envelope(result, self.name)
        if mode in ("ast", "cfg", "dfg", "member_types"):
            return normalize_envelope(
                invoke_joern_file(path, mode, scanned_file, timeout=timeout), self.name
            )
        return error_payload(self.name, f"unsupported mode: {mode}")
