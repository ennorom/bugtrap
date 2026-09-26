"""The knowledge-base block the decision agent judges candidates against.

Renders a rule's patterns — shape, prototypes, cfg nodes and the
violation_criterion that is the actual test — and sizes that block against
whatever the model's context window has left after the candidate evidence.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

from agents.libs.jsonio import dump_json
from agents.libs.models import estimate_tokens, model_context_window

DEFAULT_KB_PATH = Path("knowledge_base/knowledge_base_lite.json")


# --- KB context budgeting -------------------------------------------------
# The decision prompt is: system (fixed text + KB patterns) + user (candidate
# evidence) + room for the answer. Everything except the KB block is fixed by
# the inputs, so the KB block gets whatever is left of the model's window.
DECISION_MAX_NEW_TOKENS = 700


SYSTEM_PROMPT_OVERHEAD_TOKENS = 1600   # fixed instruction text, measured ~1.4k


KB_BUDGET_SAFETY_TOKENS = 2000         # margin for chat framing + estimate error


KB_MIN_PATTERNS = 15                   # never emit fewer than the previous cap


def kb_context_budget_tokens(model: str, candidates: list, override: int = 0) -> int:
    """Tokens available for the KNOWN BUG PATTERNS block.

    window - answer - fixed instructions - largest candidate prompt - margin.
    The candidate estimate uses the serialized candidate, which is what the
    user prompt is built from, so the worst candidate in the file sets the
    budget and every candidate in the run shares one system prompt.
    """
    if override and override > 0:
        return int(override)
    worst_candidate = 0
    for cand in candidates or []:
        if not isinstance(cand, dict):
            continue
        worst_candidate = max(worst_candidate, estimate_tokens(dump_json(cand), model))
    budget = (
        model_context_window(model)
        - DECISION_MAX_NEW_TOKENS
        - SYSTEM_PROMPT_OVERHEAD_TOKENS
        - worst_candidate
        - KB_BUDGET_SAFETY_TOKENS
    )
    return max(0, budget)


def strip_summary_boilerplate(text: str) -> str:
    """Drop CWE 'Common Consequences' / 'Impact' boilerplate from a summary.

    Keeps everything up to (but not including) those headings. If neither
    heading is found, returns the full text unchanged.
    """
    if not text:
        return ""
    lowered = text.lower()
    cut = len(text)
    for marker in ("common consequences", "impact\n", "\nimpact ", "details\ndos:"):
        idx = lowered.find(marker)
        if idx != -1 and idx < cut:
            cut = idx
    return text[:cut].rstrip()


def build_lite_kb_context(entry: Dict[str, Any], budget_tokens: int = 0,
                          model: str = "") -> str:
    """Render a lite-KB entry as a compact context block for the decision agent.

    Each section carries a brief usage hint so the agent knows how to apply it.
    Drops 'Common Consequences' / 'Impact' boilerplate from the CWE summary,
    drops potential_mitigations, drops per-pattern tags and cfg_edges. Keeps
    prototypes (buggy and fixed) since they anchor structural recognition.
    Skips uncategorized and CVE corpus.

    Every pattern is emitted unless *budget_tokens* runs out, in which case the
    block is truncated at that point but never below KB_MIN_PATTERNS entries.
    """
    if not isinstance(entry, dict):
        return ""
    desc = entry.get("description")
    desc = desc if isinstance(desc, dict) else {}
    pp = entry.get("program_patterns") or {}
    patterns = pp.get("patterns") or []
    parts: list[str] = []

    def _prototype_preview(value: Any) -> str:
        if isinstance(value, list):
            text = "\n".join(str(item).strip() for item in value if str(item).strip())
        elif isinstance(value, str):
            text = value
        else:
            text = str(value or "")
        return text[:240]

    summary = strip_summary_boilerplate((desc.get("cwe_summary") or "").strip())
    if summary:
        parts.append(
            "CWE SUMMARY (background only; use to confirm the candidate's general "
            "bug class but do not vote on this alone):\n" + summary[:800]
        )
    registry = entry.get("library_safety_registry")
    if isinstance(registry, dict) and registry:
        cache_line = ", ".join(f"{k}->{v}" for k, v in sorted(registry.items()))[:1400]
        parts.append(
            "LIBRARY SAFETY REGISTRY (authoritative API/macro contracts: <unsafe>-><safe_sibling>; treat as given facts, do NOT hedge):\n"
            + cache_line
        )
    if patterns:
        header = (
            "KNOWN BUG PATTERNS (use these as the per-rule definition of buggy. "
            "For each candidate, pick the pattern whose violation_criterion most "
            "closely fits, then judge the candidate against that criterion):"
        )
        lines: list[str] = [header]
        spent = estimate_tokens(header, model)
        emitted = 0
        dropped = 0
        for pat in patterns:
            if not isinstance(pat, dict):
                continue
            pid = (pat.get("pattern_id") or "").strip()
            shape = (pat.get("shape") or "").strip()
            proto = pat.get("prototype") or {}
            proto_b = _prototype_preview(proto.get("buggy"))
            proto_f = _prototype_preview(proto.get("fixed"))
            cfg = pat.get("cfg_shape") or {}
            constraint = ""
            cfg_nodes: list[str] = []
            if isinstance(cfg, dict):
                constraint = (cfg.get("constraint") or "").strip()
                raw_nodes = cfg.get("nodes") or []
                if isinstance(raw_nodes, list):
                    cfg_nodes = [str(n).strip() for n in raw_nodes if str(n).strip()][:8]
            sink_role = str(pat.get("sink_role") or "deref").strip().lower() or "deref"
            block = [f"- [{pid}] sink_role={sink_role}  {shape}"]
            if proto_b:
                block.append("  buggy prototype (shape of the bug to recognize):\n    "
                             + proto_b.replace("\n", "\n    "))
            if proto_f:
                block.append("  fixed prototype (shape of a satisfying guard; absence of "
                             "this shape in the candidate is evidence the bug remains):\n    "
                             + proto_f.replace("\n", "\n    "))
            if cfg_nodes:
                block.append("  cfg_nodes (abstract operations in the pattern; use to "
                             "identify the candidate's role): " + ", ".join(cfg_nodes))
            if constraint:
                block.append("  violation_criterion (the predicate to evaluate against "
                             "the candidate; this is the test): " + constraint[:280])
            rendered = "\n".join(block)
            cost = estimate_tokens(rendered, model)
            if budget_tokens > 0 and emitted >= KB_MIN_PATTERNS and spent + cost > budget_tokens:
                dropped += 1
                continue
            lines.append(rendered)
            spent += cost
            emitted += 1
        if dropped:
            print(
                f"[INFO] KB context: {emitted}/{emitted + dropped} patterns included "
                f"(~{spent} tokens, budget {budget_tokens}); {dropped} dropped.",
                file=sys.stderr,
            )
        else:
            print(f"[INFO] KB context: all {emitted} patterns included (~{spent} tokens).",
                  file=sys.stderr)
        parts.append("\n".join(lines))
    return "\n\n".join(parts)




def load_rule_context(kb_path: Path, bug_rule: str, model: str, candidates: list,
                      kb_context_tokens: int = 0) -> str:
    """Render the KB block for *bug_rule*.

    Falls back to knowledge_base.json when the lite file is absent, and degrades
    to an empty context rather than failing the run.
    """
    lite_kb_context = ""
    kb_path = Path(kb_path) if kb_path else DEFAULT_KB_PATH
    if not kb_path.is_file():
        kb_path = Path("knowledge_base/knowledge_base.json")
    if kb_path.is_file():
        try:
            kb = json.loads(kb_path.read_text(encoding="utf-8"))
            entry = kb.get(bug_rule, {}) or {}
            # CWE summary + program_patterns, capped only by what is left of the
            # model's context window.
            budget = kb_context_budget_tokens(model, candidates, override=kb_context_tokens)
            lite_kb_context = build_lite_kb_context(entry, budget_tokens=budget, model=model)
        except Exception as exc:
            print(f"[WARN] Failed to read knowledge base: {exc}", file=sys.stderr)
    else:
        print(f"[WARN] Knowledge base not found: {kb_path}", file=sys.stderr)
    return lite_kb_context
