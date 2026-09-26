"""Spoon driver: Java AST, and exact method boundaries.

Two modes over the same tool — `ast` parses a whole file, `method_map` returns
method spans that are more reliable than brace matching.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from agents.libs.drivers.base import AnalysisDriver, error_payload, normalize_envelope, register
from agents.libs.drivers.java_runtime import JAVA_DRIVER_HOME, build_ast_classpath
from agents.libs.logging_utils import log_raw_tool_output

AGENTS_DIR = JAVA_DRIVER_HOME.parent


# FIXED: AST must receive full Java file – Spoon cannot parse method snippets.
def invoke_ast(full_java_code: str, scanned_file: str = ""):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".java") as tmp:
        tmp_path = Path(tmp.name)
        tmp.write(full_java_code.encode())
        tmp.flush()

    cp = build_ast_classpath()
    proc = subprocess.run(
        ["java", "-cp", cp, "SpoonDriver", "ast", str(tmp_path)],
        text=True, capture_output=True
    )

    tmp_path.unlink(missing_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_raw_tool_output(JAVA_DRIVER_HOME, "internal_analysis", "spoon", scanned_file, ts, proc.stdout, proc.stderr)

    if proc.returncode != 0:
        return {"tool": "spoon", "status": "error", "message": proc.stderr}

    try:
        parsed = json.loads(proc.stdout)
        if isinstance(parsed, dict):
            parsed.setdefault("tool", "spoon")
        return parsed
    except:
        return {"tool": "spoon", "status": "error", "message": proc.stdout}




SPOON_METHOD_DRIVER_CLASS = "SpoonMethodMapDriver"


SPOON_METHOD_DRIVER_BUILD_DIR = AGENTS_DIR / "sink_point_agent" / "build"


SPOON_METHOD_DRIVER_SOURCE = SPOON_METHOD_DRIVER_BUILD_DIR / f"{SPOON_METHOD_DRIVER_CLASS}.java"


SPOON_METHOD_DRIVER_CLASS_FILE = SPOON_METHOD_DRIVER_BUILD_DIR / f"{SPOON_METHOD_DRIVER_CLASS}.class"


SPOON_CORE_JAR = AGENTS_DIR / "internal_analysis_agent" / "libs" / "spoon-core-10.4.2-jar-with-dependencies.jar"


_SPOON_DRIVER_READY: bool | None = None


_SPOON_DRIVER_CLASSPATH: str = ""


def _ensure_spoon_method_driver_compiled() -> bool:
    global _SPOON_DRIVER_READY, _SPOON_DRIVER_CLASSPATH
    if _SPOON_DRIVER_READY is not None:
        return _SPOON_DRIVER_READY
    if not SPOON_METHOD_DRIVER_SOURCE.is_file():
        _SPOON_DRIVER_READY = False
        return False
    if not SPOON_CORE_JAR.is_file():
        _SPOON_DRIVER_READY = False
        return False
    SPOON_METHOD_DRIVER_BUILD_DIR.mkdir(parents=True, exist_ok=True)
    needs_compile = not SPOON_METHOD_DRIVER_CLASS_FILE.is_file()
    if not needs_compile:
        try:
            needs_compile = SPOON_METHOD_DRIVER_SOURCE.stat().st_mtime > SPOON_METHOD_DRIVER_CLASS_FILE.stat().st_mtime
        except OSError:
            needs_compile = True
    if needs_compile:
        try:
            subprocess.run(
                ["javac", "-cp", str(SPOON_CORE_JAR), str(SPOON_METHOD_DRIVER_SOURCE)],
                check=True,
                capture_output=True,
                text=True,
            )
        except Exception as exc:
            print(f"[WARN] Spoon method driver compile failed: {exc}", file=sys.stderr)
            _SPOON_DRIVER_READY = False
            return False
    _SPOON_DRIVER_CLASSPATH = f"{SPOON_METHOD_DRIVER_BUILD_DIR}:{SPOON_CORE_JAR}"
    _SPOON_DRIVER_READY = True
    return True


def invoke_spoon_method_map(java_path: Path) -> list[dict[str, Any]] | None:
    if not _ensure_spoon_method_driver_compiled():
        return None
    try:
        proc = subprocess.run(
            ["java", "-cp", _SPOON_DRIVER_CLASSPATH, SPOON_METHOD_DRIVER_CLASS, str(java_path)],
            check=False,
            capture_output=True,
            text=True,
        )
    except Exception as exc:
        print(f"[WARN] Spoon method driver execution failed: {exc}", file=sys.stderr)
        return None
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "").strip()
        if msg:
            print(f"[WARN] Spoon method driver returned error: {msg}", file=sys.stderr)
        return None
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("status") != "success":
        return None
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    methods = data.get("methods")
    if not isinstance(methods, list):
        return None
    return [item for item in methods if isinstance(item, dict)]

@register
class SpoonDriver(AnalysisDriver):
    name = "spoon"
    languages = frozenset({"java"})
    modes = frozenset({"ast", "method_map"})

    def analyze(self, source_path: Path, mode: str, *, source_code: str = "",
                scanned_file: str = "", **_: Any) -> Dict[str, Any]:
        if mode == "ast":
            # Spoon parses a file, so the caller hands over the text it read.
            return normalize_envelope(invoke_ast(source_code, scanned_file), self.name)
        if mode == "method_map":
            methods = invoke_spoon_method_map(Path(source_path))
            if methods is None:
                return error_payload(self.name, "spoon method map unavailable")
            return {"tool": self.name, "status": "ok", "methods": methods}
        return error_payload(self.name, f"unsupported mode: {mode}")
