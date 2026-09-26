"""The knowledge-base entry shape, and retrieval over it.

One entry per bug rule: a description payload, the program_patterns catalog and
the library-safety registry. Retrieval is tag-overlap (Jaccard) based, with a
relaxed variant for relearning, where a new example's tags may not overlap any
existing pattern yet.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List


# ---------- KB helpers ----------
def empty_description_payload() -> Dict[str, Any]:
    return {
        "cwe_summary": "",
        "potential_mitigations": "",
        "demonstrative_examples": "",
        "selected_observed_examples": [],
        "cve_corpus": [],
    }


def init_rule_entry() -> Dict[str, Any]:
    return {
        "description": empty_description_payload(),
        "program_patterns": {"version": 1, "patterns": [], "uncategorized": []},
        "library_safety_registry": {},
    }


def merge_library_safety_pairs(entry: Dict[str, Any], pairs: Any) -> int:
    """Merge LLM-emitted `library_safety_pairs` into the rule's registry.

    Cache form: `{unsafe_token: safe_sibling}`. Lookup-essential signal only.
    Returns the number of new entries added (excludes overwrites).
    """
    if not isinstance(pairs, list) or not pairs:
        return 0
    registry = entry.setdefault("library_safety_registry", {})
    if not isinstance(registry, dict):
        registry = {}
        entry["library_safety_registry"] = registry
    added = 0
    for item in pairs:
        if not isinstance(item, dict):
            continue
        unsafe = str(item.get("unsafe") or "").strip()
        safe = str(item.get("safe") or "").strip()
        if not unsafe or not safe or len(unsafe) > 80 or len(safe) > 80:
            continue
        if unsafe not in registry:
            added += 1
        registry[unsafe] = safe
    return added


def normalize_description_payload(bug_meta: Dict[str, Any]) -> Dict[str, Any]:
    """Support legacy string descriptions and richer structured payloads."""
    payload = empty_description_payload()
    raw = bug_meta.get("description")

    if isinstance(raw, str):
        payload["cwe_summary"] = raw.strip()
        return payload

    if isinstance(raw, dict):
        source = raw
    else:
        # Backward-compatible support for top-level rich fields.
        source = bug_meta

    for key, default in payload.items():
        value = source.get(key)
        if isinstance(default, list):
            payload[key] = value if isinstance(value, list) else default
        elif isinstance(value, str):
            payload[key] = value.strip()
    return payload


def ensure_description_payload(entry: Dict[str, Any], bug_meta: Dict[str, Any]) -> None:
    """Populate description from bug_rules once, preserving existing KB content."""
    desc = entry.setdefault("description", empty_description_payload())
    incoming = normalize_description_payload(bug_meta)
    for key, value in incoming.items():
        if isinstance(value, list):
            if not desc.get(key):
                desc[key] = value
        else:
            if value and not desc.get(key):
                desc[key] = value


def tag_overlap(a: List[str], b: List[str]) -> float:
    s1 = {t.lower() for t in a}
    s2 = {t.lower() for t in b}
    if not s1 or not s2:
        return 0.0
    return len(s1 & s2) / len(s1 | s2)


def top_k_candidates(patterns: List[Dict[str, Any]], tags: List[str], k: int) -> List[Dict[str, Any]]:
    scored = [(tag_overlap(tags, p.get("tags", [])), p) for p in patterns]
    scored.sort(key=lambda x: -x[0])
    return [p for s, p in scored[:k] if s > 0]


def top_k_candidates_relaxed(patterns: List[Dict[str, Any]], tags: List[str], k: int) -> List[Dict[str, Any]]:
    """Like top_k_candidates but does NOT require non-zero overlap.

    Used for relearning, where the new example's tags may be disjoint from any
    existing pattern's tags yet the LLM still needs candidates to consider
    MATCH/REFINE against.
    """
    scored = [(tag_overlap(tags, p.get("tags", [])), p) for p in patterns]
    scored.sort(key=lambda x: -x[0])
    return [p for _, p in scored[:k]]


def extract_referenced_pattern_ids(text: str, patterns: List[Dict[str, Any]]) -> List[str]:
    """Return pattern_ids from `patterns` that appear by name in `text`.

    The relearning extras (failure_description / buggy_explanation) frequently
    name the prior agent's matched pattern_id verbatim (e.g.,
    "Matched `unchecked_downcast_or_type_macro_result`"). Surfacing those as
    authoritative candidates lets the LLM REFINE the right pattern instead of
    falling back to NO_MATCH.
    """
    if not text:
        return []
    text_l = text.lower()
    out: List[str] = []
    for p in patterns:
        pid = str(p.get("pattern_id") or "").strip()
        if pid and pid.lower() in text_l and pid not in out:
            out.append(pid)
    return out


def make_ref(example: Dict[str, Any]) -> Dict[str, Any]:
    bug_lines = (
        example.get("buggy_slice_target_lines")
        or (example.get("buggy_method") or {}).get("slice_target_lines")
        or example.get("hit_lines_in_method", [])
    )
    return {"file": example.get("file_name", ""), "bug_lines": bug_lines}


def prototype_score(proto: Dict[str, str] | None) -> int:
    """Crude quality score: prefer 3-7 line buggy with non-empty fixed."""
    proto = proto or {}
    buggy, fixed = proto.get("buggy", "") or "", proto.get("fixed", "") or ""
    if not buggy or not fixed:
        return 0
    lines = buggy.count("\n") + 1
    return max(0, 10 - abs(5 - lines))


def normalize_cfg_shape(cfg: Any) -> Dict[str, Any]:
    """Coerce an LLM-emitted cfg_shape into the canonical shape, dropping junk."""
    if not isinstance(cfg, dict):
        return {}
    nodes = cfg.get("nodes")
    edges = cfg.get("edges")
    constraint = cfg.get("constraint")
    out: Dict[str, Any] = {}
    if isinstance(nodes, list) and nodes:
        out["nodes"] = [str(n).strip() for n in nodes if str(n).strip()]
    if isinstance(edges, list) and edges:
        clean_edges = []
        for e in edges:
            if isinstance(e, (list, tuple)) and len(e) >= 2:
                a, b = str(e[0]).strip(), str(e[1]).strip()
                if a and b:
                    clean_edges.append([a, b])
        if clean_edges:
            out["edges"] = clean_edges
    if isinstance(constraint, str) and constraint.strip():
        out["constraint"] = constraint.strip()[:300]
    return out


def cfg_shape_score(cfg: Dict[str, Any] | None) -> int:
    """Richness score for cfg_shape — more nodes/edges + constraint is richer.
    Used to decide whether a new cfg_shape should replace an existing one."""
    if not isinstance(cfg, dict) or not cfg:
        return 0
    n = len(cfg.get("nodes") or [])
    e = len(cfg.get("edges") or [])
    c = 1 if (cfg.get("constraint") or "").strip() else 0
    return n + e + c
