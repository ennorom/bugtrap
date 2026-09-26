"""Comex driver: CFG/DFG for Java.

Comex trips over `interface` declarations, so it retries once against a
source rewritten to use an abstract class.
"""
from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any, Dict

from agents.libs.drivers.base import AnalysisDriver, normalize_envelope, register
from agents.libs.drivers.java_runtime import has_methods_payload, run_graph_driver
from agents.libs.language_support import read_source_file


def _is_comex_class_name_bug(result: Dict[str, Any]) -> bool:
    if not isinstance(result, dict):
        return False
    if str(result.get("status") or "").strip().lower() != "error":
        return False
    message = str(result.get("message") or "")
    return "UnboundLocalError" in message and "class_name" in message


def _build_comex_interface_compat_source(java_code: str) -> str | None:
    if not java_code:
        return None
    if "interface" not in java_code:
        return None

    transformed = java_code
    # Convert the first interface declaration to an abstract class while
    # preserving line numbers (same line replacement).
    transformed = re.sub(
        r"\binterface\s+([A-Za-z_$][\w$]*)\s+extends\b",
        r"abstract class \1 implements",
        transformed,
        count=1,
    )
    transformed, changed = re.subn(
        r"\binterface\s+([A-Za-z_$][\w$]*)\b",
        r"abstract class \1",
        transformed,
        count=1,
    )
    if changed == 0:
        return None
    # `default` is valid for interfaces but not classes.
    transformed = re.sub(r"\bdefault\s+", "", transformed)
    return transformed


def _run_comex_with_compat_retry(java_path: Path, class_name: str, mode: str,
                                 scanned_file: str) -> Dict[str, Any]:
    base_result = run_graph_driver("ComexDriver", java_path, class_name, mode, scanned_file)
    if not _is_comex_class_name_bug(base_result):
        return base_result

    try:
        java_code = read_source_file(java_path)
    except Exception:
        return base_result
    compat_code = _build_comex_interface_compat_source(java_code)
    if not compat_code:
        return base_result

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".java") as tmp:
            tmp_path = Path(tmp.name)
            tmp.write(compat_code.encode("utf-8"))
            tmp.flush()
        print(
            f"[WARN] {mode}: Comex hit class_name parser bug; retrying with interface-compat source for {scanned_file}"
        )
        retry = run_graph_driver("ComexDriver", tmp_path, class_name, mode, scanned_file)
        if retry.get("status") != "error" and has_methods_payload(retry):
            retry.setdefault("tool", "comex")
            return retry
        # Keep original error context if retry still fails or is empty.
        return base_result
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)



@register
class ComexDriver(AnalysisDriver):
    name = "comex"
    languages = frozenset({"java"})
    modes = frozenset({"cfg", "dfg"})

    def analyze(self, source_path: Path, mode: str, *, class_name: str = "",
                scanned_file: str = "", **_: Any) -> Dict[str, Any]:
        result = _run_comex_with_compat_retry(Path(source_path), class_name, mode, scanned_file)
        return normalize_envelope(result, self.name)
