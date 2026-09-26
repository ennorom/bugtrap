"""Shared JVM plumbing for the Java drivers.

Classpaths, on-demand compilation of the Java driver sources, and the
subprocess call. JAVA_DRIVER_HOME points at the directory holding those sources
(build/*.java) and their JARs; transcripts go to its logs/.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from agents.libs.logging_utils import log_raw_tool_output, safe_file_name


# Java driver sources (build/*.java) and their JAR dependencies (libs/*.jar).
JAVA_DRIVER_HOME = Path(__file__).resolve().parents[2] / "internal_analysis_agent"


LOG_DIR = JAVA_DRIVER_HOME / "logs"


# Set from the agent CLI via configure_timeouts(); 0 disables a timeout.
GRAPH_DRIVER_TIMEOUT_SECONDS = 0


COMEX_TIMEOUT_SECONDS = 180


def configure_timeouts(driver_timeout_seconds: int | None = None,
                       comex_timeout_seconds: int | None = None) -> None:
    global GRAPH_DRIVER_TIMEOUT_SECONDS, COMEX_TIMEOUT_SECONDS
    if driver_timeout_seconds is not None:
        GRAPH_DRIVER_TIMEOUT_SECONDS = max(0, int(driver_timeout_seconds))
    if comex_timeout_seconds is not None:
        COMEX_TIMEOUT_SECONDS = max(0, int(comex_timeout_seconds))


def build_ast_classpath():
    libs = JAVA_DRIVER_HOME / "libs"
    spoon = libs / "spoon-core-10.4.2-jar-with-dependencies.jar"
    gson  = libs / "gson-2.10.1.jar"
    return f"{JAVA_DRIVER_HOME / 'build'}:{spoon}:{gson}"


def run_graph_driver(driver: str, java_path: Path, class_name: str, mode: str, scanned_file: str) -> Dict[str, Any]:
    cp = build_expanded_classpath()
    cmd = ["java", "-cp", cp, driver, mode, str(java_path), class_name]
    env = dict(os.environ)
    if driver == "ComexDriver":
        env.setdefault("COMEX_PYTHON", sys.executable)
        if COMEX_TIMEOUT_SECONDS > 0:
            env.setdefault("COMEX_TIMEOUT_SECONDS", str(COMEX_TIMEOUT_SECONDS))
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if driver == "ComexDriver":
        safe_file = safe_file_name(scanned_file)
        raw_path = LOG_DIR / f"internal_analysis_comex_cli_{ts}_{safe_file}.txt"
        env["COMEX_RAW_LOG"] = str(raw_path)
    try:
        timeout = GRAPH_DRIVER_TIMEOUT_SECONDS if GRAPH_DRIVER_TIMEOUT_SECONDS > 0 else None
        proc = subprocess.run(cmd, text=True, capture_output=True, env=env, timeout=timeout)
    except OSError as exc:
        tool_name = "soot" if driver == "SootDriver" else "comex"
        return {"tool": tool_name, "status": "error", "message": str(exc)}
    except subprocess.TimeoutExpired as exc:
        tool_name = "soot" if driver == "SootDriver" else "comex"
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        log_raw_tool_output(JAVA_DRIVER_HOME, "internal_analysis", tool_name, scanned_file, ts, stdout, stderr)
        timeout_text = f" after {GRAPH_DRIVER_TIMEOUT_SECONDS}s" if GRAPH_DRIVER_TIMEOUT_SECONDS > 0 else ""
        return {
            "tool": tool_name,
            "status": "error",
            "message": f"{tool_name} driver timed out{timeout_text}.",
        }
    tool_name = "soot" if driver == "SootDriver" else "comex"
    log_raw_tool_output(JAVA_DRIVER_HOME, "internal_analysis", tool_name, scanned_file, ts, proc.stdout, proc.stderr)
    if proc.returncode != 0:
        return {"tool": tool_name, "status": "error", "message": (proc.stderr or proc.stdout).strip()}
    try:
        parsed = json.loads(proc.stdout)
        if isinstance(parsed, dict):
            parsed.setdefault("tool", "soot" if driver == "SootDriver" else "comex")
        return parsed
    except json.JSONDecodeError:
        tool_name = "soot" if driver == "SootDriver" else "comex"
        return {"tool": tool_name, "status": "error", "message": "Invalid JSON output from driver."}


def has_methods_payload(result: Dict[str, Any]) -> bool:
    if not isinstance(result, dict):
        return False
    classes = result.get("classes")
    if isinstance(classes, list):
        for cls in classes:
            methods = cls.get("methods") if isinstance(cls, dict) else None
            if isinstance(methods, list) and methods:
                return True
    data = result.get("data")
    if isinstance(data, dict):
        classes = data.get("classes")
        if isinstance(classes, list):
            for cls in classes:
                methods = cls.get("methods") if isinstance(cls, dict) else None
                if isinstance(methods, list) and methods:
                    return True
    return False


def ensure_driver_compiled() -> None:
    build_dir = JAVA_DRIVER_HOME / "build"
    libs = build_expanded_classpath()
    driver_sources = {
        "SootDriver": build_dir / "SootDriver.java",
        "SpoonDriver": build_dir / "SpoonDriver.java",
        "ComexDriver": build_dir / "ComexDriver.java",
    }
    for name, src in driver_sources.items():
        class_file = build_dir / f"{name}.class"
        if class_file.is_file():
            try:
                if class_file.stat().st_mtime >= src.stat().st_mtime:
                    continue
            except OSError:
                pass
        if not src.is_file():
            raise RuntimeError(f"Missing {name} source: {src}")
        print(f"[INFO] Compiling {name}")
        subprocess.run(
            ["javac", "-cp", libs, str(src)],
            check=True,
        )


def build_expanded_classpath():
    libs = JAVA_DRIVER_HOME / "libs"
    return f"{JAVA_DRIVER_HOME / 'build'}:{libs}/*"
