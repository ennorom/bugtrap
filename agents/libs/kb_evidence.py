"""Rendering a training example for the knowledge-base prompts.

The buggy/fixed view the learner sees: manifest and diff target lines with
their source context, backward/forward slices, a slice-local CFG summary, and —
for relearning — the labelled buggy lines, the human failure description and
the prior agent's reasoning that has to be corrected.
"""
from __future__ import annotations

from typing import Any, Dict, List


# ---------- prompts ----------
def build_description_context(desc: Dict[str, Any], mode: str = "brief") -> str:
    """Compact CWE-context block from the description payload.

    mode='brief' -> cwe_summary only (~1 KB), used in match/refine.
    mode='full'  -> + mitigations + demonstrative examples + selected
                    observed examples + top-3 CVE summaries (~6 KB),
                    used in pattern proposal.
    """
    desc = desc or {}
    parts: List[str] = []
    summary = (desc.get("cwe_summary") or "").strip()
    if summary:
        parts.append("CWE SUMMARY:\n" + summary[:1200])
    if mode == "full":
        mit = (desc.get("potential_mitigations") or "").strip()
        if mit:
            parts.append("POTENTIAL MITIGATIONS:\n" + mit[:1500])
        demo = (desc.get("demonstrative_examples") or "").strip()
        if demo:
            parts.append("DEMONSTRATIVE EXAMPLES:\n" + demo[:2500])
        observed = desc.get("selected_observed_examples") or []
        observed_lines: List[str] = []
        for item in observed[:3]:
            if not isinstance(item, dict):
                continue
            cid = (item.get("cve_id") or "").strip()
            exd = (item.get("example_description") or "").strip()
            if cid and exd:
                observed_lines.append(f"- {cid}: {exd[:280]}")
        if observed_lines:
            parts.append("SELECTED OBSERVED EXAMPLES:\n" + "\n".join(observed_lines))
        cves = desc.get("cve_corpus") or []
        cve_lines: List[str] = []
        for c in cves[:3]:
            if not isinstance(c, dict):
                continue
            cid = (c.get("cve_id") or "").strip()
            sm = (c.get("issue_summary") or c.get("cwe_example_description") or "").strip()
            if cid and sm:
                cve_lines.append(f"- {cid}: {sm[:280]}")
        if cve_lines:
            parts.append("EXAMPLE CVEs (issue summaries):\n" + "\n".join(cve_lines))
    return "\n\n".join(parts)


def with_context(base_prompt: str, ctx: str) -> str:
    if not ctx:
        return base_prompt
    return base_prompt + "\n\nCONTEXT (use as background; do not copy verbatim):\n" + ctx


def summarize_slice_cfg(cfg: Dict[str, Any] | None, node_limit: int = 8, edge_limit: int = 12) -> str:
    cfg = cfg or {}
    if (cfg.get("status") or "") != "ok":
        return ""
    nodes = cfg.get("nodes") or []
    if not isinstance(nodes, list) or not nodes:
        return ""
    node_lines: List[str] = []
    kept_ids: List[Any] = []
    for node in nodes[:node_limit]:
        if not isinstance(node, dict):
            continue
        node_id = node.get("id")
        kept_ids.append(node_id)
        line = node.get("line")
        stmt = str(node.get("stmt") or "").strip()
        prefix = f"{line}: " if line is not None else ""
        if stmt:
            node_lines.append(f"- {prefix}{stmt[:180]}")
    edges = []
    for edge in (cfg.get("edges") or [])[:edge_limit]:
        if isinstance(edge, (list, tuple)) and len(edge) >= 2:
            a, b = edge[0], edge[1]
            if a in kept_ids and b in kept_ids:
                edges.append(f"{a}->{b}")
    parts = []
    if node_lines:
        parts.append("NODES:\n" + "\n".join(node_lines))
    if edges:
        parts.append("EDGES:\n" + ", ".join(edges))
    return "\n".join(parts)


def _format_anchor_context(entries: Any) -> str:
    if not isinstance(entries, list):
        return ""
    lines: List[str] = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        line = item.get("line")
        code = str(item.get("code") or "").strip()
        if line is None or not code:
            continue
        lines.append(f"- {line}: {code[:220]}")
    return "\n".join(lines)


def _format_training_targets(example: Dict[str, Any], side: str) -> str:
    method_entry = example.get(f"{side}_method") or {}
    if not isinstance(method_entry, dict):
        method_entry = {}
    side_label = "BUGGY" if side == "buggy" else "FIXED"
    role_line = (
        "This is the pre-fix side. Diff-derived lines indicate buggy statements that were removed, replaced, or newly guarded in the fix."
        if side == "buggy"
        else "This is the post-fix side. Diff-derived lines indicate added guards, corrected access logic, or repaired checks."
    )
    manifest_lines = list(method_entry.get("manifest_target_lines") or example.get(f"{side}_manifest_target_lines") or [])
    diff_lines = list(method_entry.get("diff_target_lines") or example.get(f"{side}_diff_target_lines") or [])
    combined_lines = list(method_entry.get("combined_target_lines") or [])
    slice_lines = list(method_entry.get("slice_target_lines") or example.get(f"{side}_slice_target_lines") or [])
    parts = [f"{side_label} ROLE:\n{role_line}"]
    if manifest_lines:
        parts.append(f"{side_label} MANIFEST TARGET LINES: {manifest_lines}")
    if diff_lines:
        parts.append(f"{side_label} DIFF TARGET LINES: {diff_lines}")
    if combined_lines:
        parts.append(f"{side_label} COMBINED TARGET LINES: {combined_lines}")
    if slice_lines:
        parts.append(f"{side_label} SLICE TARGET LINES: {slice_lines}")
    manifest_ctx = _format_anchor_context(method_entry.get("manifest_target_context"))
    if manifest_ctx:
        parts.append(f"{side_label} MANIFEST TARGET CONTEXT:\n{manifest_ctx}")
    diff_ctx = _format_anchor_context(method_entry.get("diff_target_context"))
    if diff_ctx:
        parts.append(f"{side_label} DIFF TARGET CONTEXT:\n{diff_ctx}")
    slice_ctx = _format_anchor_context(method_entry.get("slice_target_context"))
    if slice_ctx:
        parts.append(f"{side_label} SLICE TARGET CONTEXT:\n{slice_ctx}")
    return "\n\n".join(parts)


def build_training_view(example: Dict[str, Any], side: str) -> str:
    parts: List[str] = []
    manual_shape = str(example.get("manual_shape") or "").strip()
    if manual_shape:
        parts.append("MANUAL SHAPE (authoritative):\n" + manual_shape[:600])
    target_block = _format_training_targets(example, side)
    if target_block:
        parts.append(target_block)
    backward = ((example.get(f"{side}_slice") or {}).get("slice_code") or "").strip()
    forward = ((example.get(f"{side}_forward_slice") or {}).get("slice_code") or "").strip()
    cfg_summary = summarize_slice_cfg(example.get(f"{side}_slice_cfg"))
    if backward:
        parts.append("BACKWARD SLICE:\n" + backward[:1400])
    if forward and forward != backward:
        parts.append("FORWARD SLICE:\n" + forward[:1400])
    if cfg_summary:
        parts.append("SLICE CFG:\n" + cfg_summary[:1200])
    if not parts:
        method_blob = str((example.get(f"{side}_method") or {}).get("code") or "").strip()
        if method_blob:
            parts.append("METHOD CONTEXT:\n" + method_blob[:1800])
    return "\n\n".join(parts)


def build_relearning_extras(example: Dict[str, Any]) -> str:
    """Compact extras block for relearning. Token-budgeted: ~3000-4500 chars total.

    Layout (only sections with content are emitted):
      1. CATEGORY directive (1 line) — routes the LLM's match/refine/propose choice.
      2. LABELED BUGGY LINES (SecVulEval ground truth) — concise [line: code] list.
      3. HUMAN FAILURE DESCRIPTION — capped.
      4. PRIOR AGENT REASONING — capped (omitted for sink_missed since no prior decision).
      5. COMMIT MESSAGE — capped.
    """
    parts: List[str] = []
    category = str(example.get("category") or "").strip().lower()
    if category == "weak_pattern":
        parts.append(
            "CATEGORY: weak_pattern — the sink was flagged but the decision agent voted No on insufficient evidence. "
            "Prefer REFINE on the pattern_id named in PRIOR AGENT REASONING (strengthen its violation_criterion to close the gap). "
            "Choose NO_MATCH only if that pattern is semantically wrong for this bug; the propose step will then create a new pattern."
        )
    elif category == "sink_missed":
        parts.append(
            "CATEGORY: sink_missed — the buggy line was never proposed as a sink candidate (no prior decision). "
            "Prefer REFINE on the closest structurally-related CANDIDATE PATTERN — strengthen its shape, sink_role, and violation_criterion so sink_point can match this bug next time. "
            "Choose NO_MATCH only if NO existing pattern is semantically related; the propose step will then create a new sink-detector-friendly pattern."
        )
    labeled = example.get("labeled_buggy_lines") or []
    if isinstance(labeled, list) and labeled:
        lines_block: List[str] = []
        used = 0
        for item in labeled[:20]:
            if not (isinstance(item, list) and len(item) >= 2):
                continue
            row = f"  {item[0]}: {str(item[1] or '').strip()[:200]}"
            if used + len(row) > 1200:
                break
            lines_block.append(row)
            used += len(row)
        if lines_block:
            parts.append("LABELED BUGGY LINES (SecVulEval ground truth — these are the lines whose change implements the fix):\n" + "\n".join(lines_block))
    failure = str(example.get("failure_description") or "").strip()
    if failure:
        parts.append("HUMAN FAILURE DESCRIPTION:\n" + failure[:1600])
    if category != "sink_missed":
        buggy_expl = str(example.get("buggy_explanation") or "").strip()
        if buggy_expl:
            parts.append("PRIOR AGENT REASONING (the trap to avoid):\n" + buggy_expl[:1400])
    commit = str(example.get("commit_message") or "").strip()
    if commit:
        parts.append("COMMIT MESSAGE:\n" + commit[:800])
    return "\n\n".join(parts)
