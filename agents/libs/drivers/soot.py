"""Soot driver: CFG/DFG for one compiled Java class."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from agents.libs.drivers.base import AnalysisDriver, normalize_envelope, register
from agents.libs.drivers.java_runtime import run_graph_driver



@register
class SootDriver(AnalysisDriver):
    name = "soot"
    languages = frozenset({"java"})
    modes = frozenset({"cfg", "dfg"})

    def analyze(self, source_path: Path, mode: str, *, class_name: str = "",
                scanned_file: str = "", **_: Any) -> Dict[str, Any]:
        result = run_graph_driver("SootDriver", Path(source_path), class_name, mode, scanned_file)
        return normalize_envelope(result, self.name)
