#!/usr/bin/env python3

from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from typing import List, Dict, Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.append(str(SCRIPT_DIR))
BASE_DIR = SCRIPT_DIR.parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))
from agents.libs import models
from agents.libs.jsonio import atomic_write, extract_json_array, extract_json_object
from agents.libs.kb_evidence import (
    build_description_context,
    build_relearning_extras,
    build_training_view,
    with_context,
)
from agents.libs.kb_schema import (
    cfg_shape_score,
    ensure_description_payload,
    extract_referenced_pattern_ids,
    init_rule_entry,
    make_ref,
    merge_library_safety_pairs,
    normalize_cfg_shape,
    prototype_score,
    top_k_candidates,
    top_k_candidates_relaxed,
)
from agents.libs.models import QwenPromptTooLong

TOP_K = 3
PROPOSE_THRESHOLD = 10


def call_llm(sys_p: str, usr_p: str, model_cfg: Dict[str, Any], pipe: Any | None,
             max_new_tokens: int = 1200) -> str:
    """One KB exchange. Qwen prompts are length-checked before generating."""
    return models.generate(sys_p, usr_p, model_cfg, max_new_tokens=max_new_tokens,
                           pipe=pipe, guard_prompt_length=True)


def tag_extraction_prompt(bug_rule: str, ctx: str = "") -> str:
    base = (
        f"You are a static-analysis expert. Bug rule: {bug_rule}.\n"
        "Given a buggy/fixed vulnerability context built from labelled manifest targets, diff-derived targets, backward slices, forward slices, "
        "and slice-local CFG hints, output 3-7 short retrieval tags "
        "(snake_case) describing the bug's structural shape. Use implementation-"
        "agnostic terms (e.g., 'indexed_write', 'pointer_advance', 'stale_bound_check', "
        "'fixed_offset_read'). The buggy/fixed pair is a diff pair: learn primarily from the contrast between buggy diff targets and fixed diff targets. "
        "Manifest targets are auxiliary location hints and may be weaker than the diff labels. Output ONLY a JSON array of strings."
    )
    return with_context(base, ctx)


def tag_extraction_user(buggy: str, fixed: str, extras: str = "") -> str:
    text = "BUGGY EVIDENCE:\n" + buggy[:2200] + "\n\nFIXED EVIDENCE:\n" + fixed[:2200]
    if extras:
        text += "\n\n" + extras
    return text


def match_or_refine_prompt(bug_rule: str, ctx: str = "") -> str:
    base = (
        f"You are a static-analysis expert. Bug rule: {bug_rule}.\n"
        "Given a new buggy/fixed code-slice pair and a list of CANDIDATE PATTERNS "
        "(each with id, shape, prototype), output ONE of:\n"
        " - {\"action\":\"MATCH\",\"pattern_id\":\"<id>\"}\n"
        " - {\"action\":\"REFINE\",\"pattern_id\":\"<id>\",\"refinement\":\"<one-line: what to sharpen>\","
        "\"new_shape\":\"<1-2 sentences: the updated structural shape that closes the prior FN/FP trap; REQUIRED for REFINE>\","
        "\"new_violation_criterion\":\"<ONE sentence, MAX 280 chars: the predicate the decision agent will evaluate verbatim against the candidate. REQUIRED for REFINE. Must be consistent with new_shape — if new_shape says 'X is the bug', the criterion must test for X, not for a downstream consequence of X. Format: 'bug if <condition> and <missing protection>'.>\","
        "\"new_sink_role\":\"<one of: deref | guard | assignment | argument_pass | cast — the syntactic role of the BUGGY LINE in this pattern. 'deref' = the bug fires at a dereference/use site. 'guard' = the bug IS the inadequate check itself (e.g., `if (!ptr)` after an API that admits ERR_PTR; flag the check line). 'assignment' = the bug is the assignment of an unverified value. 'argument_pass' = the bug is passing an unvalidated value to a callee. 'cast' = the bug is the cast invocation itself on a nullable source. Default 'deref' if unsure. REQUIRED for REFINE.>\","
        "\"new_prototype\":{\"buggy\":\"<3-5 line excerpt using ABSTRACT names only>\",\"fixed\":\"<3-5 line excerpt using ABSTRACT names only>\"} or null,"
        "\"new_cfg_shape\":{\"nodes\":[\"<semantic node>\",...],"
        "\"edges\":[[\"<from>\",\"<to>\"],...],\"constraint\":\"<one line>\"} or null}\n"
        "ABSTRACT NAMING RULE for new_prototype.buggy / new_prototype.fixed AND for new_shape examples: use ONLY generic placeholders (`parent`, `member`, `obj`, `p`, `n`, `arr`, `buf`, `MAX`, `LEN`, `T`, `helper(...)`, `accessor(...)`). Do NOT carry identifiers, type names, struct names, function names, macro names, or constants from the BUGGY EVIDENCE / FIXED EVIDENCE blocks into the prototype or the shape. The goal is a structural template that matches future programs whose names differ; concrete names from the supplied evidence are forbidden in these output fields.\n"
        "OPTIONAL TOP-LEVEL FIELD `library_safety_pairs`: when the buggy/fixed evidence (or extras) names a non-null-safe library API and its null-safe sibling, emit `[{\"unsafe\":\"<token>\", \"safe\":\"<token>\"}, ...]`. Examples: dyn_cast→dyn_cast_or_null; DCHECK_EQ→CHECK_EQ; strcpy→strlcpy; Optional.get→Optional.orElse; !ptr_after_devm_*_get_optional→IS_ERR_OR_NULL. Tokens are bare identifiers/macro names, not abstract names. Omit or set null when no such pairing is in the example.\n"
        "When the input includes HUMAN FAILURE DESCRIPTION or PRIOR AGENT'S (INCORRECT) REASONING, "
        "your REFINE.new_shape MUST encode the precise correction so a future evaluator avoids the same trap "
        "(e.g., tighten the GUARD scope to the exact dereferenced expression, exclude release-stripped asserts, "
        "require the loop bound's container to match the indexed container).\n"
        " - {\"action\":\"NO_MATCH\",\"shape_sketch\":\"<one line>\","
        "\"candidate_pattern_name\":\"<snake_case>\"}\n"
        "Prefer MATCH/REFINE over NO_MATCH when the structural shape is the same.\n"
        "The training view is explicitly labelled as a buggy/fixed diff pair. Treat diff-derived target lines as the strongest signal for what behavior changed; use manifest targets only as supporting location hints.\n"
        "Use the CONTEXT block to align your reasoning with the canonical CWE definition; "
        "do not invent code or copy text from it.\n"
        "For new_cfg_shape (optional): nodes are abstract semantic tokens "
        "(e.g., BOUND_CHECK(n,MAX), MUTATE(n), INDEXED_ACCESS(arr,n), READ(p), "
        "GUARD(cond), SAFE_RETURN); edges are control-flow ordering [from, to]; "
        "constraint is a one-line path predicate (e.g., 'no BOUND_CHECK between "
        "MUTATE and INDEXED_ACCESS'). Provide only when the existing cfg_shape is "
        "absent or genuinely narrower than what this example shows.\n"
        "Output ONLY one JSON object."
    )
    return with_context(base, ctx)


def match_or_refine_user(buggy: str, fixed: str, candidates: List[Dict[str, Any]], extras: str = "") -> str:
    cands_text = "\n".join(
        f"- id: {c['pattern_id']}\n"
        f"  shape: {c.get('shape','')}\n"
        f"  prototype_buggy: {c.get('prototype',{}).get('buggy','')[:300]}"
        for c in candidates
    )
    text = (
        "CANDIDATE PATTERNS:\n" + (cands_text or "(none)") + "\n\n"
        "NEW EXAMPLE:\nBUGGY EVIDENCE:\n" + buggy[:2200] + "\nFIXED EVIDENCE:\n" + fixed[:2200]
    )
    if extras:
        text += "\n\n" + extras
    return text


def propose_patterns_prompt(bug_rule: str, ctx: str = "") -> str:
    base = (
        f"You are a static-analysis expert. Bug rule: {bug_rule}.\n"
        "Given a cluster of uncategorized buggy/fixed vulnerability contexts, propose 1-2 NEW patterns. "
        "Each pattern object MUST include:\n"
        " - pattern_id (snake_case)\n"
        " - shape (1 sentence)\n"
        " - sink_role: one of \"deref\" | \"guard\" | \"assignment\" | \"argument_pass\" | \"cast\" — the syntactic role of the BUGGY LINE in this pattern (see meanings in REFINE schema). Default \"deref\" if unsure.\n"
        " - prototype: {buggy, fixed} as 3-5 line excerpts with abstract names (n, arr, MAX, buf)\n"
        " - tags: 3-5 snake_case retrieval tags\n"
        " - cfg_shape: {\"nodes\":[<semantic tokens>], \"edges\":[[from,to],...], \"constraint\":\"<one line>\"}\n"
        "   Nodes are abstract control/data tokens (e.g., BOUND_CHECK(n,MAX), MUTATE(n), "
        "   INDEXED_ACCESS(arr,n), READ(p), GUARD(cond), SAFE_RETURN). Edges encode "
        "   control-flow order. Constraint is a one-line path predicate that, when violated, "
        "   indicates the bug (e.g., 'no BOUND_CHECK between MUTATE and INDEXED_ACCESS').\n"
        "OPTIONAL TOP-LEVEL FIELD `library_safety_pairs`: when the buggy/fixed evidence names a non-null-safe library API and its null-safe sibling (e.g., dyn_cast→dyn_cast_or_null, DCHECK_EQ→CHECK_EQ, strcpy→strlcpy), emit `[{\"unsafe\":\"<token>\",\"safe\":\"<token>\"},...]`. Omit when no pairing exists.\n"
        "Ground each pattern in the CONTEXT block (CWE summary, mitigations, demonstrative "
        "examples, real CVE summaries). The pattern shape should be a faithful generalization "
        "consistent with the CWE definition; the missing protection should align with the "
        "mitigations listed. These examples are labelled buggy/fixed diff pairs: learn the pattern from what the buggy diff targets do and what the fixed diff targets add, guard, or repair. Do NOT copy CONTEXT text verbatim or use identifiers/literals from it.\n"
        "Output ONLY a JSON array of pattern objects."
    )
    return with_context(base, ctx)


def propose_patterns_user(examples: List[Dict[str, Any]]) -> str:
    blocks = []
    for i, ex in enumerate(examples, 1):
        b = ex.get("buggy_excerpt", "") or ""
        f = ex.get("fixed_excerpt", "") or ""
        block = f"### Example {i}\nBUGGY:\n{b}\nFIXED:\n{f}"
        extras = str(ex.get("extras") or "").strip()
        if extras:
            block += "\n" + extras
        blocks.append(block)
    return "UNCATEGORIZED CLUSTER:\n" + "\n\n".join(blocks)


# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="Lite incremental KB builder (program_patterns).")
    ap.add_argument("--examples", default="preprocessing_agent/preprocessing_output.json")
    ap.add_argument("--bugs", default="files/bug_rules_cwe.json")
    ap.add_argument("--output", default="knowledge_base/knowledge_base_lite.json")
    ap.add_argument("--model", default="qwen")
    ap.add_argument("--model-cache", dest="model_cache", default=None)
    ap.add_argument("--propose-threshold", type=int, default=PROPOSE_THRESHOLD)
    args = ap.parse_args()

    model_cfg = models.resolve_model(args.model, args.model_cache, strict=False)
    pipe = models.qwen_pipe(model_cfg) if model_cfg["backend"] == "qwen" else None

    examples_path = Path(args.examples)
    bugs_path = Path(args.bugs)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not examples_path.is_file():
        sys.exit(f"[ERROR] Missing examples: {examples_path}")
    if not bugs_path.is_file():
        sys.exit(f"[ERROR] Missing bugs: {bugs_path}")

    examples_data = json.loads(examples_path.read_text(encoding="utf-8"))
    bugs_data = json.loads(bugs_path.read_text(encoding="utf-8"))
    kb: Dict[str, Any] = {}
    if out_path.is_file():
        try:
            kb = json.loads(out_path.read_text(encoding="utf-8"))
        except Exception:
            kb = {}

    for bug_rule, bug_meta in bugs_data.items():
        bug_examples = examples_data.get(bug_rule, [])
        entry = kb.get(bug_rule) or init_rule_entry()
        ensure_description_payload(entry, bug_meta)
        if not bug_examples:
            kb[bug_rule] = entry
            atomic_write(out_path, kb)
            continue

        print(f"\n[KB] {bug_rule}: {len(bug_examples)} examples")
        pp = entry["program_patterns"]
        patterns = pp["patterns"]
        uncategorized = pp["uncategorized"]

        ctx_brief = build_description_context(entry.get("description", {}), mode="brief")
        ctx_full = build_description_context(entry.get("description", {}), mode="full")

        for idx, ex in enumerate(bug_examples, 1):
            buggy_code = build_training_view(ex, "buggy")
            fixed_code = build_training_view(ex, "fixed")
            if not buggy_code or not fixed_code:
                continue
            extras = build_relearning_extras(ex)

            # 1) tags
            try:
                text = call_llm(
                    tag_extraction_prompt(bug_rule, ctx_brief),
                    tag_extraction_user(buggy_code, fixed_code, extras),
                    model_cfg, pipe, max_new_tokens=200,
                )
                tags = [str(t) for t in (extract_json_array(text) or []) if isinstance(t, str)]
            except QwenPromptTooLong as e:
                print(f"  [{idx}] SKIP (qwen prompt too long): {e}")
                continue
            except Exception as e:
                print(f"  [{idx}] tag extraction failed: {e}")
                continue

            # 2) retrieve
            candidates = top_k_candidates(patterns, tags, TOP_K)
            if extras:
                # Relearning: force-include pattern_ids that the failure_description /
                # buggy_explanation name verbatim, and fall back to top-K-relaxed so the
                # LLM always gets a chance to REFINE rather than dropping to uncategorized.
                forced_ids = extract_referenced_pattern_ids(extras, patterns)
                if forced_ids:
                    have = {c["pattern_id"] for c in candidates}
                    forced_patterns = [p for p in patterns if p["pattern_id"] in forced_ids and p["pattern_id"] not in have]
                    candidates = forced_patterns + candidates
                if not candidates:
                    candidates = top_k_candidates_relaxed(patterns, tags, TOP_K)

            this_iter_uncat = False
            if not candidates:
                uncategorized.append({
                    "file": ex.get("file_name", ""),
                    "shape_sketch": "",
                    "tags": tags,
                    "buggy_excerpt": buggy_code[:600],
                    "fixed_excerpt": fixed_code[:600],
                    "extras": extras,
                })
                this_iter_uncat = True
                print(f"  [{idx}] NO_MATCH (no tag overlap)")
            else:
                # 3) match or refine
                try:
                    text = call_llm(
                        match_or_refine_prompt(bug_rule, ctx_brief),
                        match_or_refine_user(buggy_code, fixed_code, candidates, extras),
                        model_cfg, pipe, max_new_tokens=600,
                    )
                    decision = extract_json_object(text) or {}
                except QwenPromptTooLong as e:
                    print(f"  [{idx}] SKIP match/refine (qwen prompt too long): {e}")
                    continue
                except Exception as e:
                    print(f"  [{idx}] match call failed: {e}")
                    continue

                action = str(decision.get("action", "")).upper()
                if action == "MATCH":
                    pid = decision.get("pattern_id")
                    p = next((x for x in patterns if x["pattern_id"] == pid), None)
                    if p:
                        p["support"]["refs"].append(make_ref(ex))
                        p["support"]["example_count"] = len(p["support"]["refs"])
                        print(f"  [{idx}] MATCH -> {pid}")
                elif action == "REFINE":
                    pid = decision.get("pattern_id")
                    p = next((x for x in patterns if x["pattern_id"] == pid), None)
                    if p:
                        p["version"] = int(p.get("version", 1)) + 1
                        new_shape = str(decision.get("new_shape") or "").strip()
                        if new_shape:
                            p["shape"] = new_shape
                        # The decision agent quotes cfg_shape.constraint verbatim
                        # as the violation_criterion. Replace it unconditionally
                        # when provided so REFINE shape and operational rule stay
                        # in lockstep (this gap is what caused refined shapes to
                        # have no effect on test-time verdicts).
                        new_violation = str(decision.get("new_violation_criterion") or "").strip()
                        if new_violation:
                            cfg_block = p.get("cfg_shape")
                            if not isinstance(cfg_block, dict):
                                cfg_block = {}
                            cfg_block["constraint"] = new_violation[:280]
                            p["cfg_shape"] = cfg_block
                        new_sink_role = str(decision.get("new_sink_role") or "").strip().lower()
                        if new_sink_role in ("deref", "guard", "assignment", "argument_pass", "cast"):
                            p["sink_role"] = new_sink_role
                        added_pairs = merge_library_safety_pairs(entry, decision.get("library_safety_pairs"))
                        if added_pairs:
                            print(f"  [{idx}] +{added_pairs} library_safety pair(s)")
                        new_proto = decision.get("new_prototype")
                        if isinstance(new_proto, dict) and prototype_score(new_proto) > prototype_score(p.get("prototype")):
                            p["prototype"] = {"buggy": new_proto.get("buggy", ""), "fixed": new_proto.get("fixed", "")}
                        new_cfg = normalize_cfg_shape(decision.get("new_cfg_shape"))
                        if new_cfg and cfg_shape_score(new_cfg) > cfg_shape_score(p.get("cfg_shape")):
                            p["cfg_shape"] = new_cfg
                        p["support"]["refs"].append(make_ref(ex))
                        p["support"]["example_count"] = len(p["support"]["refs"])
                        p["history"].append({
                            "v": p["version"],
                            "from_examples": p["support"]["example_count"],
                            "change": str(decision.get("refinement", ""))[:200],
                        })
                        print(f"  [{idx}] REFINE -> {pid}")
                else:
                    uncategorized.append({
                        "file": ex.get("file_name", ""),
                        "shape_sketch": str(decision.get("shape_sketch", ""))[:200],
                        "candidate_pattern_name": str(decision.get("candidate_pattern_name", ""))[:120],
                        "tags": tags,
                        "buggy_excerpt": buggy_code[:600],
                        "fixed_excerpt": fixed_code[:600],
                    })
                    this_iter_uncat = True
                    print(f"  [{idx}] NO_MATCH")

            # 4) propose new patterns when cluster ripe.
            # In relearning (extras present), drop the threshold to 1 so a single
            # FN example with rich failure context immediately yields a new pattern.
            effective_threshold = 1 if (extras and this_iter_uncat) else args.propose_threshold
            if len(uncategorized) >= effective_threshold:
                cluster = uncategorized[:effective_threshold]
                try:
                    text = call_llm(
                        propose_patterns_prompt(bug_rule, ctx_full),
                        propose_patterns_user(cluster),
                        model_cfg, pipe, max_new_tokens=2000,
                    )
                    proposed = extract_json_array(text) or []
                except QwenPromptTooLong as e:
                    print(f"  [propose] skipped (qwen prompt too long): {e}")
                    proposed = []
                except Exception as e:
                    print(f"  [propose] failed: {e}")
                    proposed = []
                added = 0
                for pat in proposed:
                    if not isinstance(pat, dict):
                        continue
                    pid = str(pat.get("pattern_id", "")).strip()
                    if not pid or any(p["pattern_id"] == pid for p in patterns):
                        continue
                    proto = pat.get("prototype", {}) or {}
                    sink_role_val = str(pat.get("sink_role") or "").strip().lower()
                    if sink_role_val not in ("deref", "guard", "assignment", "argument_pass", "cast"):
                        sink_role_val = "deref"
                    added_pairs = merge_library_safety_pairs(entry, pat.get("library_safety_pairs"))
                    if added_pairs:
                        print(f"  [propose:{pid}] +{added_pairs} library_safety pair(s)")
                    patterns.append({
                        "pattern_id": pid,
                        "version": 1,
                        "shape": str(pat.get("shape", "")),
                        "sink_role": sink_role_val,
                        "cfg_shape": normalize_cfg_shape(pat.get("cfg_shape")),
                        "prototype": {"buggy": proto.get("buggy", ""), "fixed": proto.get("fixed", "")},
                        "tags": [str(t) for t in pat.get("tags", []) if isinstance(t, str)],
                        "support": {"example_count": 0, "refs": []},
                        "history": [{"v": 1, "from_examples": len(cluster),
                                     "change": "initial pattern from uncategorized cluster"}],
                    })
                    added += 1
                if added:
                    pp["version"] = int(pp.get("version", 1)) + 1
                    # Consume exactly the examples that went into the cluster.
                    # Using the static threshold here discarded up to
                    # propose_threshold entries during relearning, where the
                    # cluster is a single example.
                    pp["uncategorized"] = uncategorized[len(cluster):]
                    uncategorized = pp["uncategorized"]
                    print(f"  [propose] +{added} new patterns; uncategorized -> {len(uncategorized)}")

            if idx % 5 == 0:
                kb[bug_rule] = entry
                atomic_write(out_path, kb)

        kb[bug_rule] = entry
        atomic_write(out_path, kb)
        print(f"[SAVE] {bug_rule}: {len(patterns)} patterns, {len(uncategorized)} uncategorized")

    print(f"\n[DONE] KB -> {out_path}")


if __name__ == "__main__":
    main()
