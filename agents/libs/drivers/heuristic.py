"""Heuristic driver: the last resort in the Java fallback chain.

Builds a line-by-line stand-in graph from a method the agent already located,
so a candidate still carries evidence when every real tool failed. The method
arrives through `method_entry`, so `source_path` is unused here.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from agents.libs.drivers.base import AnalysisDriver, error_payload, register
from agents.libs.graph_payloads import heuristic_analysis_result


@register
class HeuristicDriver(AnalysisDriver):
    name = "heuristic"
    languages = frozenset({"*"})
    modes = frozenset({"ast", "cfg", "dfg"})

    def analyze(self, source_path: Path, mode: str, *, method_entry: Any = None,
                **_: Any) -> Dict[str, Any]:
        if mode not in self.modes:
            return error_payload(self.name, f"unsupported mode: {mode}")
        # Already the contract shape: {"tool": "heuristic", "status", "method"}.
        return heuristic_analysis_result(method_entry, mode)
