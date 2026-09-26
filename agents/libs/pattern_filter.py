"""Cheap source-level pre-filter for KB patterns.

Maps the abstract CFG tokens used in a pattern's cfg_shape.nodes onto regexes,
so patterns whose operations do not appear in the file at all can be dropped
before prompting. No Joern dependency.
"""
from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Lightweight semantic-token fingerprint for CFG pre-filtering.
# Maps abstract CFG node tokens (used in KB cfg_shape.nodes) to regexes that
# detect their presence in source. Cheap; no Joern dependency.
# ---------------------------------------------------------------------------
_SEMANTIC_TOKEN_PATTERNS: dict[str, list[str]] = {
    "BOUND_CHECK": [r"if\s*\([^)]*[<>]=?\s*[A-Z_][A-Z0-9_]*",
                    r"if\s*\([^)]*\s*<\s*\w+\s*\)",
                    r"if\s*\([^)]*\s*>\s*\w+\s*\)"],
    "INDEXED_ACCESS": [r"\w+\s*\[\s*[\w\+\-]+\s*\]"],
    "INDEXED_WRITE": [r"\w+\s*\[\s*\w+\s*[\+\-]*\s*\]\s*=",
                      r"\w+\s*\[\s*\w+\+\+\s*\]"],
    "MUTATE": [r"\b\w+\s*\+\+", r"\b\w+\s*--",
               r"\b\w+\s*[\+\-\*\/]=", r"\b\w+\s*=\s*\w+\s*[\+\-]"],
    "READ": [r"\*\s*\w+", r"\w+\s*->\s*\w+", r"\w+\.\w+"],
    "GUARD": [r"\bif\s*\("],
    "SAFE_RETURN": [r"\breturn\b", r"\bgoto\s+\w+"],
    "PARSE": [r"\bsizeof\s*\(", r"\bmemcpy\s*\(", r"\bmemcmp\s*\(",
              r"\bstrncpy\s*\(", r"\bstrlen\s*\("],
    "LOOP": [r"\bfor\s*\(", r"\bwhile\s*\("],
    "CALL": [r"\b[a-zA-Z_]\w*\s*\("],
    "ALLOC": [r"\bmalloc\s*\(", r"\bcalloc\s*\(", r"\bkzalloc\s*\(",
              r"\bkmalloc\s*\("],
    "FREE": [r"\bfree\s*\(", r"\bkfree\s*\("],
    "CAST": [r"\(\s*\w+\s*\*\s*\)"],
}


def extract_semantic_tokens(source: str) -> set[str]:
    """Return the set of abstract CFG node tokens present in *source*."""
    if not source:
        return set()
    found: set[str] = set()
    for token, patterns in _SEMANTIC_TOKEN_PATTERNS.items():
        for pat in patterns:
            try:
                if re.search(pat, source):
                    found.add(token)
                    break
            except re.error:
                continue
    return found


def pattern_eligible_by_cfg(method_tokens: set[str], cfg_shape: dict | None) -> bool:
    """A pattern is eligible if at least half of its cfg_shape.nodes' type
    prefixes appear in the method. Empty cfg_shape => always eligible."""
    if not cfg_shape or not isinstance(cfg_shape, dict):
        return True
    nodes = cfg_shape.get("nodes") or []
    if not nodes:
        return True
    required: set[str] = set()
    for node in nodes:
        if not isinstance(node, str):
            continue
        type_name = node.split("(")[0].strip()
        if type_name:
            required.add(type_name)
    if not required:
        return True
    overlap = required & method_tokens
    return len(overlap) >= max(1, len(required) // 2)
