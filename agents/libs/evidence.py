"""Shaping candidate evidence for the decision prompt.

Two levels of detail: the full internal-analysis JSON, or a compacted view
(method signature, a few CFG statements or DFG edges, truncated call lines) for
runs that need a smaller prompt.
"""
from __future__ import annotations

from typing import Any, Dict, List

from agents.libs.jsonio import dump_json


def get_supporting_context(candidate: Dict[str, Any]) -> Dict[str, list]:
    supporting = candidate.get("supporting_context") if isinstance(candidate, dict) else None
    if isinstance(supporting, dict):
        secondary = supporting.get("secondary_methods")
        external = supporting.get("external_methods")
    else:
        # Backward compatibility with older outputs.
        secondary = candidate.get("secondary_methods") if isinstance(candidate, dict) else None
        external = candidate.get("external_methods") if isinstance(candidate, dict) else None
    if not isinstance(secondary, list):
        secondary = []
    if not isinstance(external, list):
        external = []
    return {"secondary_methods": secondary, "external_methods": external}


def truncate_text(text: str, limit: int = 1400) -> str:
    cleaned = (text or "").strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[:limit].rstrip() + " ..."


def prompt_text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (list, dict)):
        rendered = dump_json(value)
    else:
        rendered = str(value)
    rendered = rendered.strip()
    return rendered if rendered else default


def compact_analysis_payload(analysis: Dict[str, Any], fallback_tool: str = "") -> Dict[str, Any]:
    compact: Dict[str, Any] = {}
    if not isinstance(analysis, dict):
        return compact
    tool = (analysis.get("mode") or analysis.get("tool") or fallback_tool or "").upper()
    if tool:
        compact["tool"] = tool
    status = analysis.get("status")
    if status:
        compact["status"] = status
    message = analysis.get("message")
    if message:
        compact["message"] = truncate_text(str(message), limit=240)

    method = analysis.get("method")
    if isinstance(method, dict):
        signature = method.get("signature") or method.get("method_signature")
        if signature:
            compact["method_signature"] = truncate_text(str(signature), limit=180)

        cfg = method.get("cfg")
        if isinstance(cfg, list):
            stmts = [str(node.get("stmt")) for node in cfg if isinstance(node, dict) and node.get("stmt")]
            if stmts:
                compact["cfg_stmts"] = stmts[:6]
            return compact

        dfg = method.get("dfg")
        if isinstance(dfg, list):
            edges = []
            for edge in dfg:
                if not isinstance(edge, dict):
                    continue
                var = edge.get("var")
                use = edge.get("use")
                if var and use:
                    edges.append(f"{var}->{use}")
            if edges:
                compact["dfg_edges"] = edges[:6]
            return compact

        body = method.get("body")
        if body:
            compact["body_snippet"] = truncate_text(" ".join(str(body).split()), limit=260)
    return compact


def compact_secondary_evidence(secondary_methods: list[dict]) -> list[dict]:
    compact: list[dict] = []
    for sec in secondary_methods:
        if not isinstance(sec, dict):
            continue
        sec_payload = sec.get("internal_analysis_result") or {}
        sec_tool = ""
        if isinstance(sec_payload, dict):
            sec_tool = sec_payload.get("tool") or sec_payload.get("mode") or ""
        signature = sec.get("method_signature")
        call_line = sec.get("called_at_line_content")
        entry: Dict[str, Any] = {
            "called_at_line_number": sec.get("called_at_line_number"),
            "called_at_line_content": truncate_text(str(call_line), limit=220) if call_line else None,
            "analysis_compact": compact_analysis_payload(sec_payload, sec_tool),
        }
        if signature:
            entry["method_signature"] = signature
        elif sec.get("method_name"):
            entry["method_name"] = sec.get("method_name")
        if not signature and sec.get("param_count") is not None:
            entry["param_count"] = sec.get("param_count")
        compact.append({k: v for k, v in entry.items() if v not in (None, "", [], {})})
    return compact


def compact_external_evidence(external_methods: list[dict]) -> list[dict]:
    compact: list[dict] = []
    for ext in external_methods:
        if not isinstance(ext, dict):
            continue
        signature = ext.get("method_signature")
        call_line = ext.get("called_at_line_content")
        ext_payload = ext.get("internal_analysis_result") or {}
        ext_tool = ""
        if isinstance(ext_payload, dict):
            ext_tool = ext_payload.get("tool") or ext_payload.get("mode") or ""
        entry: Dict[str, Any] = {
            "fqcn": ext.get("fqcn"),
            "called_at_line_number": ext.get("called_at_line_number"),
            "called_at_line_content": truncate_text(str(call_line), limit=220) if call_line else None,
            "analysis_compact": compact_analysis_payload(ext_payload, ext_tool),
        }
        if signature:
            entry["method_signature"] = signature
        elif ext.get("method_name"):
            entry["method_name"] = ext.get("method_name")
            if ext.get("param_count") is not None:
                entry["param_count"] = ext.get("param_count")
        compact.append({k: v for k, v in entry.items() if v not in (None, "", [], {})})
    return compact


def full_supporting_evidence(methods: list[dict], include_fqcn: bool = False) -> list[dict]:
    full: list[dict] = []
    for item in methods:
        if not isinstance(item, dict):
            continue
        entry: Dict[str, Any] = {}
        if include_fqcn and item.get("fqcn"):
            entry["fqcn"] = item.get("fqcn")
        for key in ("called_at_line_number", "called_at_line_content", "method_signature", "method_name", "param_count"):
            value = item.get(key)
            if value not in (None, "", [], {}):
                entry[key] = value
        if "internal_analysis_result" in item:
            entry["internal_analysis_result"] = item.get("internal_analysis_result")
        full.append(entry)
    return full


def compact_method_refs(items: List[Dict[str, Any]], is_external: bool) -> List[Dict[str, Any]]:
    """Call-site view of supporting methods: who is called, where, with what arity.

    No bodies and no analysis payloads — this is what the planner reasons over
    when choosing an analysis graph.
    """
    compact: List[Dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        out: Dict[str, Any] = {
            "method_name": item.get("method_name"),
            "called_at_line_number": item.get("called_at_line_number"),
            "called_at_line_content": item.get("called_at_line_content"),
        }
        if item.get("method_signature"):
            out["method_signature"] = item.get("method_signature")
        if item.get("param_count") is not None:
            out["param_count"] = item.get("param_count")
        if is_external:
            if item.get("fqcn"):
                out["fqcn"] = item.get("fqcn")
            if item.get("source_rel_path"):
                out["source_rel_path"] = item.get("source_rel_path")
        compact.append({k: v for k, v in out.items() if v is not None and v != ""})
    return compact
