#!/usr/bin/env python3
"""Decision agent: is this sink candidate a real instance of the bug rule?

Judges each candidate against the KB pattern whose violation_criterion fits it,
using the identity / protection / reachability test in the system prompt.
Evidence shaping, Joern slicing and model plumbing live in agents/libs.
"""
from __future__ import annotations
from pathlib import Path
import argparse, json, re, sys
from typing import Dict, Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.append(str(SCRIPT_DIR))
BASE_DIR = SCRIPT_DIR.parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))
from agents.libs.language_support import detect_language_from_path, language_display_name
from agents.libs import models
from agents.libs.slice_context import resolve_candidate_context
from agents.libs.evidence import (
    compact_analysis_payload,
    compact_external_evidence,
    compact_secondary_evidence,
    full_supporting_evidence,
    get_supporting_context,
    prompt_text,
    truncate_text,
)
from agents.libs.jsonio import dump_json, read_json
from agents.libs.kb_context import DECISION_MAX_NEW_TOKENS, DEFAULT_KB_PATH, load_rule_context
from agents.libs.logging_utils import log_prompt


# ---------------------------------------------------------------------------
# SYSTEM + USER PROMPT GENERATION
# ---------------------------------------------------------------------------

def build_system_prompt(language: str = "source",
                        analysis_prompt_mode: str = "full",
                        decision_context: str = "method",
                        lite_kb_context: str = "") -> str:
    analysis_prompt_mode = (analysis_prompt_mode or "full").strip().lower()
    use_full_analysis = analysis_prompt_mode == "full"
    analysis_evidence_label = "full internal analysis evidence" if use_full_analysis else "compact analysis evidence"

    analysis_mode_section = ""
    if use_full_analysis:
        analysis_mode_section = (
            "- The user prompt includes full internal-analysis JSON for the primary candidate and any related supporting methods. "
            "Use those JSON details directly when judging guards, bounds, reachability, data flow, and control flow.\n"
        )
    context_mode_section = ""
    if (decision_context or "method").strip().lower() == "slice":
        context_mode_section = (
            "- The user prompt includes a backward slice rooted at the candidate line when slicing succeeds. "
            "Treat that slice as the primary local code evidence for the candidate, and use the internal-analysis JSON to recover broader control/data-flow context when needed.\n"
        )

    return (
        f"You are the Decision Agent for {language_display_name(language)} analysis. Decide whether a sink-point candidate is a real instance of the given bug rule.\n\n"
        "Output ONE JSON object with exactly two keys:\n"
        "{\n"
        "  \"buggy\": \"Yes\" | \"No\",\n"
        "  \"buggy_explanation\": string\n"
        "}\n\n"
        "EVIDENCE (the user prompt supplies all of it):\n"
        f"- candidate evidence (the sink line and its justification); {analysis_evidence_label} JSON; supporting_context.secondary_methods and .external_methods.\n"
        "- Backward slice (where the candidate's value originates) and forward slice (where it propagates) are the primary local code views when present.\n"
        "- Types, names, conventions, and surrounding 'looks careful' code are NOT evidence.\n"
        "- TYPE EVIDENCE (member_types): when internal_analysis_result.member_types is present for any `parent.member` / `parent->member` access on the candidate line or its enclosing method, treat the declared member_type as authoritative. Do NOT hedge between 'pointer' and 'inline array' assumptions. If `is_pointer=true` and `resolved=true`, the member is nullable and a guard on the parent alone does NOT discharge the obligation for the member. If `is_inline_array=true` and `resolved=true`, the member is not a separate pointer and the parent guard is sufficient for the addressing. If `resolved=false`, default to nullable-pointer (FN is costlier than FP for null-deref). Sibling sinks in the same method that share pattern_id, root pointer, and guard set must reach the same vote — if their member types resolve differently, name that as the only structural difference; if they resolve identically (or both are unresolved), votes MUST agree.\n"
        "\n"
        "DECISION TEST. From KNOWLEDGE BASE CONTEXT, pick the pattern whose violation_criterion best fits the candidate's operation (approximate fit is expected; the catalog is finite). Then judge the candidate against THREE criteria. State each criterion's status (SATISFIED or UNSATISFIED) with a single line citation from the evidence.\n"
        "  (A) IDENTITY — the candidate performs the pattern's dangerous operation on a specific variable/expression/resource you can name.\n"
        "  (B) PROTECTION — do NOT accept any visible guard, check, bound, invariant, loop bound, validation, sanitization, narrowing, or contract at face value. First state what a COMPLETE protection for THIS candidate would require: (i) the EXACT expression that must be checked AND the check must execute BEFORE the candidate operation runs (the value going INTO the candidate operation; the operation's own result, a value produced by it, or any value that only exists after the operation does NOT count, and neither does a parent/container or adjacent expression in place of the named subject), (ii) the EXACT set of invalid states it must reject (NULL alone is incomplete when the producing context can also yield ERR_PTR/sentinel/wrong-type/uninitialized/out-of-range; one container's count is incomplete when the indexed container is a different identifier; a debug-only assert is incomplete on a release path), (iii) the check must dominate the candidate site on the same path and not be invalidated before use. Mark (B) SATISFIED only if visible code matches (i) AND (ii) AND (iii); partial coverage of any one element = UNSATISFIED. BINDING STEP (mandatory before voting): name the exact line number and source expression in visible code that satisfies each of (i),(ii),(iii); if you cannot point at a present line+expression for any one, that element is UNSATISFIED. The 'most important missing evidence' line MAY name a fact that would flip the vote, but it MUST NOT cite uncertainty about the criterion's own stated preconditions (e.g., whether a named non-null-safe helper is in fact non-null-safe, whether a named multi-state API admits ERR_PTR) — those are taken as given by the matched pattern's criterion. LIBRARY SAFETY REGISTRY RULE: if the candidate line uses any token K listed as an UNSAFE key in LIBRARY SAFETY REGISTRY, (B) is UNSATISFIED unless visible code on the SAME source also uses the corresponding safe sibling V (or an equivalent prior null/state guard on that source). Do not doubt the registry contract; treat it as authoritative.\n"
        "  (C) REACHABILITY — no reachable path between that protective element and the candidate can bypass, mutate, reassign, or invalidate it.\n"
        "\n"
        "VOTE:\n"
        "  • No  — (A) SATISFIED AND (B) SATISFIED AND (C) SATISFIED, each with a line citation.\n"
        "  • Yes — (A) SATISFIED AND at least one of (B)(C) UNSATISFIED, each cited. If you cannot point to a specific line establishing (B), treat it as UNSATISFIED.\n"
        "Do not vote Unknown. (The system reserves Unknown only for cases where required internal-analysis data is missing; that is decided outside this prompt.)\n"
        "\n"
        "buggy_explanation:\n"
        "- 3 to 5 sentences, no bullets, no markdown.\n"
        "- Name the matched pattern_id and quote its violation_criterion verbatim.\n"
        "- State (A), (B), (C) inline with a line citation for each, then the vote.\n"
        "- Close with the single most important piece of missing evidence (if any) that could change the vote.\n"
        "\n"
        "Output rules:\n"
        "- Valid JSON only. Double quotes. No markdown fences. No extra fields.\n\n"
        + (
            "KNOWLEDGE BASE CONTEXT (the source of the pattern, its protective requirement, and its violation_criterion; do not copy verbatim):\n"
            f"{lite_kb_context}\n\n"
            if lite_kb_context else ""
        )
    )



def build_user_prompt(candidate: Dict[str, Any], bug_rule: str, description: str,
                      language: str = "source",
                      analysis_prompt_mode: str = "full",
                      decision_context: str = "method") -> str:
    line_content = prompt_text(candidate.get("line_content"))
    analysis_prompt_mode = (analysis_prompt_mode or "full").strip().lower()
    use_full_analysis = analysis_prompt_mode == "full"

    # support both keys for robustness
    justification = prompt_text(
        candidate.get("sink_point_justification")
        or candidate.get("justification")
    )

    context_label = prompt_text(candidate.get("candidate_context_label"), default="candidate_method_content")
    context_block = prompt_text(candidate.get("candidate_context_block"))
    if not context_block:
        context_block = prompt_text(candidate.get("method_content"))
    context_mode = prompt_text(candidate.get("candidate_context_mode"), default=(decision_context or "method"))
    slice_payload = candidate.get("candidate_slice")
    selected_analysis_justification = prompt_text(candidate.get("selected_analysis_justification"))

    analysis_payload = candidate.get("internal_analysis_result") or {}
    supporting = get_supporting_context(candidate)
    if use_full_analysis:
        method_block = context_block if context_block else "(empty)"
        primary_analysis_block = dump_json(analysis_payload)
        secondary_label = "supporting_context.secondary_methods_full"
        secondary_block = dump_json(full_supporting_evidence(supporting["secondary_methods"]))
        external_label = "supporting_context.external_methods_full"
        external_block = dump_json(full_supporting_evidence(supporting["external_methods"], include_fqcn=True))
        analysis_label = "internal_analysis_full_json"
    else:
        method_block = truncate_text(context_block, limit=1800) if context_block else "(empty)"
        analysis_compact = compact_analysis_payload(
            analysis_payload if isinstance(analysis_payload, dict) else {},
            candidate.get("analysis_tool") or "",
        )
        primary_analysis_block = dump_json(analysis_compact)
        secondary_label = "supporting_context.secondary_methods"
        secondary_block = dump_json(compact_secondary_evidence(supporting["secondary_methods"]))
        external_label = "supporting_context.external_methods"
        external_block = dump_json(compact_external_evidence(supporting["external_methods"]))
        analysis_label = "analysis_compact"

    prompt_lines = [
        f"DECISION_ANALYSIS_PROMPT_MODE:\n{analysis_prompt_mode}",
        "",
        f"DECISION_CONTEXT:\n{context_mode}",
        "",
        f"BUG RULE TITLE:\n{bug_rule}",
        f"BUG RULE DESCRIPTION:\n{description}",
        f"LANGUAGE:\n{language_display_name(language)}",
        "",
        "CANDIDATE EVIDENCE:",
        f"line_content: {line_content}",
        f"sink_point_justification: {justification}",
        f"selected_analysis_justification: {selected_analysis_justification or '(empty)'}",
        "",
        f"[{context_label}]",
        method_block,
    ]
    if isinstance(slice_payload, dict):
        prompt_lines.extend([
            "",
            "candidate_slice_metadata:",
            dump_json({
                "status": slice_payload.get("status"),
                "criterion": slice_payload.get("criterion"),
                "slice_lines": slice_payload.get("slice_lines"),
                "message": slice_payload.get("message"),
            }),
        ])
    prompt_lines.extend([
        "",
        f"{analysis_label}:",
        primary_analysis_block,
        "",
        f"{secondary_label}:",
        secondary_block,
        "",
        f"{external_label}:",
        external_block,
        "",
        "Return ONLY the JSON object required by the system prompt."
    ])
    return "\n".join(prompt_lines)


# ---------------------------------------------------------------------------
# LLM CALL (ROBUST JSON EXTRACTION)
# ---------------------------------------------------------------------------

def call_llm(system_prompt: str, user_prompt: str,
             model_cfg: dict, scanned_file: str) -> Dict[str, Any]:
    text = models.chat(SCRIPT_DIR, "decision", scanned_file, system_prompt, user_prompt,
                       model_cfg, max_new_tokens=DECISION_MAX_NEW_TOKENS)

    # Extract JSON boundaries
    s, e = text.find("{"), text.rfind("}")
    if s == -1 or e == -1 or e <= s:
        raise ValueError(f"LLM did not return valid JSON:\n{text}")

    json_str = text[s:e+1].strip()

    # Parse JSON
    try:
        obj = json.loads(json_str)
    except Exception as exc:
        raise ValueError(
            f"Failed to parse JSON: {exc}\nExtracted JSON:\n{json_str}"
        )

    # Validate required structure
    if "buggy" not in obj:
        raise ValueError(f"Missing 'buggy' key in LLM JSON: {obj}")

    if "buggy_explanation" not in obj:
        raise ValueError(f"Missing 'buggy_explanation' key in LLM JSON: {obj}")

    return obj


def analysis_failure_reason(analysis_result: Any, analysis_tool: str) -> str | None:
    """Why this candidate cannot be judged, or None when evidence is usable.

    An error payload (Joern/Soot/Spoon failed, or the method was never located
    in the graph) carries no method-level evidence. Sending it to the model
    spends tokens on a verdict that has nothing to stand on, so the candidate
    is resolved as Unknown without an LLM call. Ambiguous matches
    (matching_methods, no single method) keep the previous CFG/DFG-only gate.
    """
    if not analysis_result:
        return "missing internal analysis information"
    if not isinstance(analysis_result, dict):
        return "malformed internal analysis information"
    if str(analysis_result.get("status") or "").strip().lower() == "error":
        tool = str(analysis_result.get("tool") or "").strip() or "internal"
        message = str(analysis_result.get("message") or "").strip()
        return f"{tool} analysis failed" + (f": {message[:200]}" if message else "")
    if analysis_tool in {"CFG", "DFG"} and not isinstance(analysis_result.get("method"), dict):
        return "missing method level internal analysis information"
    return None


def _extract_candidate_receiver(line: str, language: str) -> str:
    if language == "java":
        match = re.search(r"\b([A-Za-z_$][\w$]*)\s*\.", line or "")
    else:
        match = re.search(r"\b([A-Za-z_][\w]*)\s*->", line or "")
    return match.group(1) if match else ""


def heuristic_decision(candidate: Dict[str, Any], bug_rule: str, description: str,
                       language: str) -> Dict[str, str]:
    line = str(candidate.get("line_content") or "")
    method_content = str(candidate.get("method_content") or "")
    rel_line = int(candidate.get("method_line_number") or 0)
    method_lines = method_content.splitlines()
    window_start = max(0, rel_line - 4)
    context = "\n".join(method_lines[window_start:rel_line]) if rel_line > 0 else method_content[:400]
    receiver = _extract_candidate_receiver(line, language)
    text = f"{bug_rule} {description}".lower()
    is_null_rule = "null" in text and ("dereference" in text or "pointer" in text)
    guard_patterns = [r"!=\s*null", r"==\s*null", r"!=\s*NULL", r"==\s*NULL"]
    guarded = any(re.search(pat, context) for pat in guard_patterns)
    risky = ("." in line and "(" in line) if language == "java" else ("->" in line or bool(re.search(r"\*\s*[A-Za-z_][\w]*", line)))
    if receiver and re.search(rf"\b{re.escape(receiver)}\b", context):
        guarded = guarded or bool(re.search(rf"\b{re.escape(receiver)}\b.*(?:!=\s*null|!=\s*NULL)", context))
    if is_null_rule and risky and not guarded:
        return {
            "buggy": "Yes",
            "buggy_explanation": "The sink line performs a dereference-like operation on a value that is not clearly guarded in the nearby method context. The fallback analysis did not find a dominating null check immediately before the reported use. Supporting graph data is heuristic, so the exact path sensitivity remains uncertain. A visible non-null guarantee close to the sink would be enough to change this decision."
        }
    return {
        "buggy": "No",
        "buggy_explanation": "The fallback decision could not establish an unsafe dereference lifecycle from the visible local evidence alone. Either the sink is not clearly a dereference-like operation for this rule, or nearby context suggests a guard may already exist. The available analysis for this run is heuristic rather than model-backed, so hidden interprocedural facts were not considered. Stronger path or data-flow evidence could change this result."
    }


# ---------------------------------------------------------------------------
# CANDIDATE VERIFICATION USING LLM
# ---------------------------------------------------------------------------

def verify(decisions: Dict[str, Any],
           model_cfg: dict, out_path: Path | None = None,
           language: str = "source",
           analysis_prompt_mode: str = "full",
           decision_context: str = "method",
           source_path: Path | None = None,
           joern_widen: int = 0,
           kb_path: Path | None = None,
           kb_context_tokens: int = 0) -> Dict[str, Any]:
    bug_rule, payload = next(iter(decisions.items()))
    description = payload.get("description", "")
    scanned_file = payload.get("scanned_file", "")
    candidates = payload.get("candidates", [])
    out = {
        bug_rule: {
            "description": description,
            "scanned_file": scanned_file,
            "source_rel_path": payload.get("source_rel_path", ""),
            "code_base_path": payload.get("code_base_path", ""),
            "candidates": [],
        }
    }

    lite_kb_context = load_rule_context(
        kb_path, bug_rule, model_cfg.get("model", ""), candidates,
        kb_context_tokens=kb_context_tokens,
    )

    system_prompt = build_system_prompt(
        language=language,
        analysis_prompt_mode=analysis_prompt_mode,
        decision_context=decision_context,
        lite_kb_context=lite_kb_context,
    )
    log_prompt(SCRIPT_DIR, bug_rule, "system_prompt", system_prompt)
    slice_cache: Dict[tuple[str, int, str], Dict[str, Any]] = {}

    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    for idx, cand in enumerate(candidates, 1):
        analysis_tool = (cand.get("analysis_tool") or "").upper()
        analysis_result = cand.get("internal_analysis_result")

        supporting = get_supporting_context(cand)
        secondary = supporting["secondary_methods"]
        if isinstance(secondary, list):
            missing_secondary = None
            for sec in secondary:
                if not isinstance(sec, dict):
                    continue
                sec_name = sec.get("method_name") or "unknown"
                sec_payload = sec.get("internal_analysis_result")
                if not sec_payload:
                    missing_secondary = sec_name
                    break
            if missing_secondary:
                updated = {
                    **cand,
                    "buggy": "Unknown",
                    "buggy_explanation": f"missing internal analysis information for secondary method: {missing_secondary}"
                }
                out[bug_rule]["candidates"].append(updated)
                if out_path:
                    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
                continue

        failure_reason = analysis_failure_reason(analysis_result, analysis_tool)
        if failure_reason:
            updated = {
                **cand,
                "buggy": "Unknown",
                "buggy_explanation": failure_reason,
            }
            out[bug_rule]["candidates"].append(updated)
            if out_path:
                out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
            continue

        context_payload = resolve_candidate_context(cand, source_path, decision_context, slice_cache,
                                                     joern_widen=joern_widen)
        prompt_candidate = {
            **cand,
            "candidate_context_mode": context_payload["mode"],
            "candidate_context_label": context_payload["label"],
            "candidate_context_block": context_payload["block"],
        }
        if "slice" in context_payload:
            prompt_candidate["candidate_slice"] = context_payload["slice"]
        if "forward_slice" in context_payload:
            prompt_candidate["candidate_forward_slice"] = context_payload["forward_slice"]

        user_prompt = build_user_prompt(
            candidate=prompt_candidate,
            bug_rule=bug_rule,
            description=description,
            language=language,
            analysis_prompt_mode=analysis_prompt_mode,
            decision_context=decision_context,
        )
        log_prompt(SCRIPT_DIR, bug_rule, f"user_prompt_candidate_{idx}", user_prompt)

        try:
            llm_result = call_llm(system_prompt, user_prompt, model_cfg, scanned_file)
        except Exception as exc:
            print(f"[WARN] Decision LLM failed; using heuristic fallback: {exc}", file=sys.stderr)
            llm_result = heuristic_decision(cand, bug_rule, description, language)

        updated = {
            **cand,
            "buggy": llm_result["buggy"],
            "buggy_explanation": llm_result["buggy_explanation"]
        }
        if "slice" in context_payload:
            updated["candidate_slice"] = context_payload["slice"]
        if "forward_slice" in context_payload:
            updated["candidate_forward_slice"] = context_payload["forward_slice"]
        updated["decision_context"] = context_payload["mode"]
        out[bug_rule]["candidates"].append(updated)

        if out_path:
            out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    return out


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Decision Agent: LLM-based bug verification.")
    ap.add_argument("--file", required=True, help="Path to the source file.")
    ap.add_argument("--output", default="decision_agent/decision.json")
    ap.add_argument("--input", default="internal_analysis_agent/internal_analysis_decision.json")
    ap.add_argument("--model", default="qwen", help="LLM backend to use (default: qwen)")
    ap.add_argument("--analysis-prompt-mode", default="full", choices=["compact", "full"],
                    help="How much internal analysis evidence to include in the decision prompt. full passes the full internal_analysis_result JSON; compact preserves the previous summarized prompt.")
    ap.add_argument("--decision-context", default="method", choices=["method", "slice"],
                    help="Primary local code context for the decision prompt. method passes the full method body; slice passes a backward slice rooted at the candidate line with safe fallback to method context.")
    ap.add_argument("--knowledge-base", dest="knowledge_base", default=str(DEFAULT_KB_PATH),
                    help=f"Knowledge base JSON to read patterns from (default: {DEFAULT_KB_PATH}). "
                         "Pass the same path the sink agent used when comparing KB versions.")
    ap.add_argument("--kb-context-tokens", dest="kb_context_tokens", type=int, default=0,
                    help="Token budget for the KB pattern block (0 = derive it from the model's "
                         "context window minus the largest candidate prompt).")
    ap.add_argument("--joern-widen", dest="joern_widen", type=int, default=3,
                    help="Joern slice fallback radius (default 3; pass 0 to disable). "
                         "When >0 and the exact seed line yields no CFG nodes, the slice "
                         "script widens the seed search to lines within +/-N of the seed, "
                         "bounded to the seed's enclosing user method. Bitwise identical "
                         "output when exact match succeeds. Same flag/semantics as preprocessing_agent_lite.py.")


    args = ap.parse_args()

    source_path = Path(args.file)
    decisions = read_json(Path(args.input))
    language = detect_language_from_path(source_path)

    model_cfg = models.resolve_model(args.model)

    out_path = Path(args.output)
    verify(
        decisions,
        model_cfg,
        out_path,
        language=language,
        analysis_prompt_mode=args.analysis_prompt_mode,
        decision_context=args.decision_context,
        source_path=source_path,
        joern_widen=args.joern_widen,
        kb_path=Path(args.knowledge_base) if args.knowledge_base else None,
        kb_context_tokens=args.kb_context_tokens,
    )


if __name__ == "__main__":
    main()
