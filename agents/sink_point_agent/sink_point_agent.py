#!/usr/bin/env python3

from __future__ import annotations
from pathlib import Path
import argparse, json, re, sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.append(str(SCRIPT_DIR))
BASE_DIR = SCRIPT_DIR.parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))
from agents.libs.language_support import detect_language_from_path, language_display_name, read_source_file
from agents.libs import models
from agents.libs.jsonio import load_llm_json_object
from agents.libs.logging_utils import log_llm_exchange, log_prompt, timestamp
from agents.libs.pattern_filter import extract_semantic_tokens, pattern_eligible_by_cfg
from agents.libs.source_parsing import (
    MethodInfo,
    build_class_method_map,
    build_class_method_map_regex,
    extract_field_type_map,
    iter_method_calls,
    normalize_method_name,
    normalize_signature,
    param_count_from_method,
    parse_call_names,
    parse_package_and_imports,
    parse_target_method_norms,
)
from agents.libs.supporting_context import (
    build_external_methods_for_candidate,
    build_secondary_methods_for_prompt,
    summarize_secondary_methods,
)


def read_program_file(p: Path) -> str:
    return read_source_file(p)

def _write_no_rule_payload(
    bug: str,
    scanned_file: str,
    source_rel_path: str = "",
    code_base_path: str = "",
) -> None:
    out_path = Path("sink_point_agent/sink_point_candidates.json")
    payload = {
        bug: {
            "description": "",
            "scanned_file": scanned_file,
            "source_rel_path": source_rel_path,
            "code_base_path": code_base_path,
            "status": "No Rule",
            "candidates": [],
        }
    }
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

def build_system_prompt(bug_rule: str, desc: str, patterns: list[str],
                        rule_specific_instructions: str | list[str] | None = None,
                        language: str = "java",
                        attribute_mode: str = "default") -> str:
    """Build a lean, inclusive sink-point prompt.

    Sink-point's job is recall, not final verdict. Decision-agent runs after
    and applies strict filtering. So we keep the prompt small (just enough
    framing + the pattern catalog) and tell the LLM to flag liberally.
    """
    pattern_block = "\n".join(f"- {s}" for s in patterns)
    if isinstance(rule_specific_instructions, list):
        lines = [f"- {str(item).strip()}" for item in rule_specific_instructions if str(item).strip()]
        rule_specific_text = "\n".join(lines) if lines else "(none)"
    elif isinstance(rule_specific_instructions, str):
        rule_specific_text = rule_specific_instructions.strip() or "(none)"
    else:
        rule_specific_text = "(none)"
    language_name = language_display_name(language)
    return (
        f"You are a senior {language_name} static-analysis expert.\n"
        f"BUG RULE: {bug_rule}\n"
        f"CWE CONTEXT:\n{desc}\n"
        "\n"
        "KNOWN BUG PATTERNS:\n"
        f"{pattern_block}\n"
        "\n"
        "YOUR TASK: identify every code location that resembles any of the known bug patterns. "
        "Sink-point candidates are exploration leads, not final verdicts — your goal is to surface "
        "all plausibly relevant locations so that subsequent analysis has the full set to reason over. "
        "Aim for broad coverage; partial or borderline resemblance is enough to include a location.\n"
        "\n"
        "WHAT COUNTS AS A CANDIDATE:\n"
        "- Code whose shape resembles a pattern's BUGGY excerpt — even loosely.\n"
        "- Code whose surrounding control/data flow matches a pattern's CFG hint.\n"
        "- Code that resembles the buggy side of any concrete bug/fix example shown in the CWE context.\n"
        "- Operations relevant to the bug rule (reads, indexed accesses, pointer derefs, length-driven loops, casts, copies, parser steps) that share structural elements with any pattern.\n"
        "- Do not omit a candidate based on the assumption that an existing check or guard is sufficient — surface it and let later analysis judge.\n"
        "- sink_role guides WHERE to look on the line: for sink_role=deref scan dereference/use sites; for sink_role=guard scan `if (...)`/ternary/while-cond guard expressions whose tested value came from a pointer/handle-returning API (the inadequate-check line itself is the candidate, not a downstream use); for sink_role=assignment scan the assignment of an unverified return value; for sink_role=argument_pass scan call sites that forward an unvalidated value; for sink_role=cast scan the cast/unwrap invocation itself.\n"
        "\n"
        "How to reason:\n"
        "1. For each method, list operations that relate to the bug rule.\n"
        "2. For each such operation, identify any pattern (or demonstrative example) it resembles.\n"
        "3. Emit it as a candidate with the matched pattern_id(s) cited.\n"
        "4. The FIXED excerpt of each pattern is reference material that shows the shape of safe code — it is for context only. Do NOT use it to suppress candidates.\n"
        "\n"
        "Rule-specific instructions:\n"
        f"{rule_specific_text}\n"
        "\n"
        "Output rules:\n"
        "- Use only provided line numbers 'N:'.\n"
        "- line_content must match exactly.\n"
        "- Each candidate's justification MUST cite the pattern_id(s) it matched.\n"
        "- No markdown fences, comments, or trailing commas.\n"
        "- Return only a valid JSON object with \"candidates\".\n"
        "- Only return an empty list when nothing in the method bears any resemblance to any pattern.\n"
        "\n"
        "{\n"
        "  \"candidates\": [\n"
        "    {\n"
        "      \"line_number\": <int>,\n"
        "      \"line_content\": \"<exact code line>\",\n"
        "      \"candidate\": \"<statement summary>\",\n"
        "      \"sink_point_justification\": \"<brief: matched pattern_id(s) and why>\"\n"
        "    }\n"
        "  ]\n"
        "}\n"
    )


def build_user_prompt(numbered_lines: list[tuple[int, str]], secondary_summary: str | None = None,
                      language: str = "java",
                      attribute_mode: str = "default") -> str:
    numbered = "\n".join(f"{ln}: {text}" for ln, text in numbered_lines)
    language_name = language_display_name(language)
    prompt = (
        f"Analyze the {language_name} source below and output all sink point candidates.\n"
        "Each line is prefixed with its line number 'N:'. When you report line_number, "
        "you must use one of these N values. Your entire reply must be a valid JSON "
        "object with a \"candidates\" list.\n\n"
    )
    if attribute_mode == "diff":
        prompt += (
            "When a legacy pattern entry contains ';', focus on the buggy text before ';' and use the text after ';' as reference for what safe code may contain.\n\n"
        )
    if secondary_summary:
        prompt += (
            "Secondary Method Context:\n"
            "- For each listed secondary method, this shows how values passed from the main method may be used or propagated.\n"
            "- This context is informational and should be used to understand cross-method value, variable or object lifecycles.\n"
            f"{secondary_summary}\n\n"
    )
    prompt += (
        f"----- BEGIN {language_name.upper()} CODE -----\n"
        f"{numbered}\n"
        f"----- END {language_name.upper()} CODE -----"
    )
    return prompt

def _normalize(s: str) -> str:
    return (s or "").strip()

def _resolve_candidates_with_real_lines(candidates: list[dict], method_info: MethodInfo, java_code: str) -> list[dict]:
    lines = java_code.splitlines()
    resolved: list[dict] = []

    def _norm_ws(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "").strip())

    for cand in candidates:
        raw_content = _normalize(cand.get("line_content", ""))
        raw_ln = cand.get("line_number")

        # 1) Prefer line_number if valid and in-range
        ln_from_number = None
        try:
            ln_tmp = int(raw_ln)
            if method_info.start_line <= ln_tmp <= method_info.end_line:
                ln_from_number = ln_tmp
        except (TypeError, ValueError):
            ln_from_number = None

        # 2) Fallback: whitespace-normalized containment match on content
        ln_from_content = None
        if raw_content:
            raw_n = _norm_ws(raw_content)
            for idx in range(method_info.start_line - 1, method_info.end_line):
                line_n = _norm_ws(lines[idx])
                if raw_n == line_n or raw_n in line_n or line_n in raw_n:
                    ln_from_content = idx + 1
                    break

        final_ln = ln_from_number or ln_from_content
        if final_ln is None:
            continue

        # Overwrite with authoritative source line
        cand["line_number"] = final_ln
        cand["line_content"] = lines[final_ln - 1]
        resolved.append(cand)

    return resolved

def _merge_duplicate_candidates(candidates: list[dict]) -> list[dict]:
    merged: dict[tuple[object, str], dict] = {}
    order: list[tuple[object, str]] = []
    for cand in candidates:
        line_number = cand.get("line_number")
        line_content = (cand.get("line_content") or "").strip()
        key = (line_number, line_content)
        if key not in merged:
            merged[key] = cand
            order.append(key)
            continue
        base = merged[key]
        for field in ("candidate", "sink_point_justification"):
            val = (cand.get(field) or "").strip()
            if not val:
                continue
            existing = (base.get(field) or "").strip()
            if not existing:
                base[field] = val
            elif val not in existing:
                base[field] = f"{existing} | {val}"
    return [merged[k] for k in order]


def _is_null_dereference_rule(bug_rule: str, desc: str) -> bool:
    text = f"{bug_rule} {desc}".lower()
    return "null" in text and ("dereference" in text or "pointer" in text)


def _is_oob_read_rule(bug_rule: str, desc: str) -> bool:
    text = f"{bug_rule} {desc}".lower()
    return (
        (
            ("out-of-bounds" in text or "out of bounds" in text)
            and any(term in text for term in ("read", "buffer", "array", "index", "offset", "memory"))
        )
        or ("buffer over-read" in text or "buffer overread" in text)
        or ("read past the end" in text or "before the beginning" in text)
        or ("reads data past the end" in text)
    )


def _looks_like_declaration_or_signature(line: str) -> bool:
    return bool(re.match(r"^(?:static\s+)?(?:inline\s+)?[A-Za-z_][\w\s\*\[\]]*\([^)]*\)\s*\{?$", line))


def heuristic_candidates_for_method(method: MethodInfo, bug_rule: str, desc: str,
                                    language: str) -> list[dict]:
    candidates: list[dict] = []
    for idx, (ln, line) in enumerate(method.snippet):
        stripped = line.strip()
        if not stripped or stripped in {"{", "}"}:
            continue
        if idx == 0:
            continue
        risky = False
        if _is_null_dereference_rule(bug_rule, desc):
            if language == "java":
                match = re.search(r"\b([A-Za-z_$][\w$]*)\s*\.", stripped)
                receiver = match.group(1) if match else ""
                risky = (
                    "." in stripped
                    and "(" in stripped
                    and bool(receiver)
                    and receiver[:1].islower()
                )
            else:
                risky = (
                    ("->" in stripped or bool(re.search(r"\*\s*[A-Za-z_][\w]*", stripped)))
                    and not _looks_like_declaration_or_signature(stripped)
                )
        elif _is_oob_read_rule(bug_rule, desc):
            if language == "java":
                risky = (
                    bool(re.search(r"\b[A-Za-z_$][\w$]*\s*\[[^\]]+\]", stripped))
                    or bool(re.search(r"\.(?:get|charAt)\s*\(", stripped))
                )
            else:
                risky = (
                    bool(re.search(r"(?:->|\.)[A-Za-z_][\w]*\s*\[[^\]]+\]", stripped))
                    or bool(re.search(r"\b[A-Za-z_][\w]*\s*\[[^\]]+\]", stripped))
                    or bool(re.search(r"\b(?:memcpy|memmove|memcmp|strncmp|strncpy|strnlen|copy_from_user|copy_to_user)\s*\(", stripped))
                ) and not _looks_like_declaration_or_signature(stripped)
        if not risky:
            continue
        if _is_null_dereference_rule(bug_rule, desc):
            justification = "Heuristic fallback: this line performs a dereference-like operation relevant to the bug rule."
        elif _is_oob_read_rule(bug_rule, desc):
            justification = "Heuristic fallback: this line performs an indexed or size-driven memory access relevant to out-of-bounds read analysis."
        else:
            justification = "Heuristic fallback: this line performs a risky operation relevant to the bug rule."
        candidates.append({
            "line_number": ln,
            "line_content": line,
            "candidate": stripped,
            "sink_point_justification": justification,
        })
    return candidates

def call_llm(system_prompt: str, bug_rule: str,
             method: MethodInfo, full_java_code: str,
             model_cfg: dict, prompt_tag: str,
             secondary_summary: str | None = None,
             scanned_file: str = "",
             language: str = "java",
             attribute_mode: str = "default") -> dict:
    usr_p = build_user_prompt(
        method.snippet,
        secondary_summary,
        language=language,
        attribute_mode=attribute_mode,
    )
    log_prompt(SCRIPT_DIR, bug_rule, f"user_prompt_{prompt_tag}", usr_p)
    ts = timestamp()
    text = models.generate(system_prompt, usr_p, model_cfg, max_new_tokens=2000)
    log_llm_exchange(SCRIPT_DIR, "sink_point", scanned_file, ts, system_prompt, usr_p, text)
    log_prompt(SCRIPT_DIR, bug_rule, f"raw_response_{prompt_tag}", text)
    data = load_llm_json_object(text)
    if not isinstance(data, dict):
        raise ValueError("Invalid LLM output")
    candidates = data.get("candidates")
    if not isinstance(candidates, list):
        raise ValueError("LLM output missing candidates list")

    # Reconcile with the real file: fix line_number and line_content
    candidates = _resolve_candidates_with_real_lines(candidates, method, full_java_code)
    return {"candidates": candidates}

def main():
    ap = argparse.ArgumentParser(description="Sink Point Agent")
    ap.add_argument("--bug", required=True, help="Bug rule title")
    ap.add_argument("--file", required=True, help="Path to source file")
    ap.add_argument("--model", default="qwen", help="LLM backend to use (default: qwen)")
    ap.add_argument("--knowledge-base", default="knowledge_base/knowledge_base.json",
                    help="Path to the knowledge base JSON (default: knowledge_base/knowledge_base.json)")
    ap.add_argument("--target-method", default="", help="Optional method name hint to run method-first scanning.")
    ap.add_argument("--code-base-path", default="", help="Optional local repository root for resolving external methods.")
    ap.add_argument("--source-rel-path", default="", help="Optional source path relative to code base root.")
    ap.add_argument("--cfg-prefilter", action="store_true",
                    help="Drop KB patterns whose cfg_shape.nodes are not present in the source file (lite KB only).")
    ap.add_argument("--attribute-mode", default="default", choices=["default", "diff"],
                    help="How to interpret knowledge-base attributes: default=current flow, diff=buggy/fixed comparison flow.")
    args = ap.parse_args()

    kb_path = Path(args.knowledge_base)
    if not kb_path.is_file():
        print(f"[ERROR] Knowledge base not found: {kb_path}")
        sys.exit(2)

    source_path = Path(args.file)
    if not source_path.is_file():
        print(f"[ERROR] Source file not found: {source_path}")
        sys.exit(2)
    language = detect_language_from_path(source_path)

    source_rel_path = (args.source_rel_path or "").strip().lstrip("/")
    code_base_path: Path | None = None
    if args.code_base_path:
        candidate_root = Path(args.code_base_path).expanduser().resolve()
        if candidate_root.is_dir():
            code_base_path = candidate_root
        else:
            print(f"[WARN] Ignoring invalid code base path: {candidate_root}", file=sys.stderr)

    kb = json.loads(kb_path.read_text(encoding="utf-8"))
    entry = kb.get(args.bug)
    if not entry:
        print(f"[WARN] Rule not found in knowledge base: {args.bug}")
        _write_no_rule_payload(
            args.bug,
            source_path.name,
            source_rel_path=source_rel_path,
            code_base_path=str(code_base_path) if code_base_path else "",
        )
        return

    # Lite-KB adapter: handle both the rich legacy schema (description string +
    # attributes/filtered list) AND the new lite schema
    # (description dict + program_patterns.patterns[]).
    desc_raw = entry.get("description", "")
    program_patterns = entry.get("program_patterns") or {}
    lite_patterns = program_patterns.get("patterns") or []
    if isinstance(desc_raw, dict) or lite_patterns:
        # New lite schema. Sink-point gets minimal CWE framing plus the
        # authoritative MITRE demonstrative examples (concrete bug/fix code that
        # helps anchor candidate identification). Mitigations are dropped —
        # their content is already encoded in pattern FIXED prototypes.
        desc_dict = desc_raw if isinstance(desc_raw, dict) else {}
        desc_parts: list[str] = []
        if desc_dict.get("cwe_summary"):
            desc_parts.append((desc_dict["cwe_summary"] or "")[:600])
        if desc_dict.get("demonstrative_examples"):
            desc_parts.append(
                "Concrete bug/fix examples (use as analogy anchors when scanning):\n"
                + (desc_dict["demonstrative_examples"] or "")[:1800]
            )
        desc = "\n\n".join(desc_parts)

        # Optional CFG pre-filter: drop patterns whose cfg_shape.nodes are not
        # present in the source file. Empty cfg_shape => no filter (passthrough).
        eligible_patterns = lite_patterns
        if getattr(args, "cfg_prefilter", False):
            try:
                source_text_for_cfg = read_program_file(source_path)
            except Exception:
                source_text_for_cfg = ""
            method_tokens = extract_semantic_tokens(source_text_for_cfg)
            filtered_in: list[dict] = []
            for pat in lite_patterns:
                if not isinstance(pat, dict):
                    continue
                if pattern_eligible_by_cfg(method_tokens, pat.get("cfg_shape") or {}):
                    filtered_in.append(pat)
            print(f"[INFO] CFG pre-filter: {len(filtered_in)}/{len(lite_patterns)} patterns eligible")
            if filtered_in:
                eligible_patterns = filtered_in

        def _prototype_preview(value: Any) -> str:
            if isinstance(value, list):
                text = "\n".join(str(item).strip() for item in value if str(item).strip())
            elif isinstance(value, str):
                text = value
            else:
                text = str(value or "")
            return text[:220]

        attributes = []
        registry = entry.get("library_safety_registry") if isinstance(entry, dict) else None
        if isinstance(registry, dict) and registry:
            cache_line = ", ".join(f"{k}->{v}" for k, v in sorted(registry.items()))[:1400]
            attributes.append(
                "LIBRARY SAFETY REGISTRY (unsafe->safe_sibling; treat as authoritative API contracts when scanning for candidates): "
                + cache_line
            )
        for pat in eligible_patterns:
            if not isinstance(pat, dict):
                continue
            pid = (pat.get("pattern_id") or "").strip()
            shape = (pat.get("shape") or "").strip()
            proto = pat.get("prototype") or {}
            proto_b = _prototype_preview(proto.get("buggy"))
            proto_f = _prototype_preview(proto.get("fixed"))
            cfg = pat.get("cfg_shape") or {}
            constraint = (cfg.get("constraint") or "").strip()[:200]
            sink_role = str(pat.get("sink_role") or "deref").strip().lower() or "deref"
            block = [f"[{pid}] sink_role={sink_role}  {shape}"]
            if proto_b:
                block.append(f"  BUGGY:  {proto_b.replace(chr(10), ' | ')}")
            if proto_f:
                block.append(f"  FIXED (reference only): {proto_f.replace(chr(10), ' | ')}")
            if constraint:
                block.append(f"  CFG: {constraint}")
            attributes.append("\n".join(block))
        attribute_key = "program_patterns"
    else:
        # Legacy schema.
        desc = desc_raw or ""
        attributes = entry.get("filtered") or entry.get("attributes") or entry.get("statements") or []
        attribute_key = "filtered" if entry.get("filtered") else ("attributes" if entry.get("attributes") else "statements")
    rule_specific_instructions = entry.get("rule-specific-instructions")
    if not attributes:
        print(f"[WARN] No attributes found for {args.bug}")
        _write_no_rule_payload(
            args.bug,
            source_path.name,
            source_rel_path=source_rel_path,
            code_base_path=str(code_base_path) if code_base_path else "",
        )
        return

    java_code = read_program_file(source_path)
    file_name = source_path.name
    print(f"[INFO] Processing {args.bug} on {source_path.name} (language={language}, kb_key={attribute_key}) ...")

    # Build method map and extract methods for per-method processing
    method_map, methods = build_class_method_map(java_code, source_path, language=language)
    scan_methods = methods
    target_resolution_failed = False
    target_method_input = (args.target_method or "").strip()
    if target_method_input:
        target_norms = parse_target_method_norms(target_method_input)
        target_norm_set = set(target_norms)
        if target_norms:
            matched_methods = [m for m in methods if normalize_method_name(m.name) in target_norm_set]
            if not matched_methods:
                # Spoon can miss nested-class methods in some files; recover only target
                # method candidates from regex mapping to avoid widening scan scope.
                _regex_map, regex_methods = build_class_method_map_regex(java_code, language=language)
                regex_matches = [m for m in regex_methods if normalize_method_name(m.name) in target_norm_set]
                if regex_matches:
                    existing_keys = {
                        (m.name, m.start_line, m.end_line, m.class_path)
                        for m in methods
                    }
                    added = 0
                    for method in regex_matches:
                        key = (method.name, method.start_line, method.end_line, method.class_path)
                        if key in existing_keys:
                            continue
                        methods.append(method)
                        existing_keys.add(key)
                        added += 1
                        for ln in range(method.start_line, method.end_line + 1):
                            method_map[ln] = {"name": method.name, "start_line": method.start_line}
                    matched_methods = regex_matches
                    if added:
                        print(
                            f"[INFO] Recovered {added} target-method entries from regex mapping for '{target_method_input}'.",
                            file=sys.stderr,
                        )
            if matched_methods:
                scan_methods = matched_methods
                matched_names = sorted({m.name for m in matched_methods})
                print(
                    f"[INFO] Target-method scan enabled for '{target_method_input}' -> matched {len(matched_methods)} method(s): {', '.join(matched_names)}"
                )
            else:
                # Fallback: target method name was unresolvable (e.g., K&R-style
                # C definition with the return type on a separate forward decl,
                # or a test-framework macro like TEST_P/TEST_F that doesn't
                # parse as a regular function). Widening to all extracted
                # methods is safer than skipping the whole file — the LLM scan
                # still uses the bug-pattern shapes to filter candidates.
                print(
                    f"[INFO] Target method(s) '{target_method_input}' not found in class; widening to full-method scan as fallback (likely K&R-style C definition or test-framework macro).",
                    file=sys.stderr,
                )
                scan_methods = methods
        else:
            print(
                f"[WARN] Target method token(s) '{target_method_input}' are invalid; skipping LLM scan.",
                file=sys.stderr,
            )
            target_resolution_failed = True
            scan_methods = []
    methods_by_name: dict[str, list[MethodInfo]] = {}
    for method in methods:
        methods_by_name.setdefault(method.name, []).append(method)
    system_prompt = build_system_prompt(
        args.bug,
        desc,
        attributes,
        rule_specific_instructions,
        language=language,
        attribute_mode=args.attribute_mode,
    )
    log_prompt(SCRIPT_DIR, args.bug, "system_prompt", system_prompt)

    model_cfg = models.resolve_model(args.model)

    aggregated_candidates: list[dict] = []
    out_path = Path("sink_point_agent/sink_point_candidates.json")
    # initialize file with empty structure
    payload = {
        args.bug: {
            "description": desc,
            "scanned_file": source_path.name,
            "language": language,
            "attribute_mode": args.attribute_mode,
            "knowledge_base_attribute_key": attribute_key,
            "source_rel_path": source_rel_path,
            "code_base_path": str(code_base_path) if code_base_path else "",
            "candidates": [],
        }
    }
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    if target_resolution_failed:
        payload[args.bug]["target_method"] = target_method_input
        payload[args.bug]["target_resolution"] = "not_found"
        out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print("[NO CANDIDATES FOUND]")
        print(f"[DONE] Results saved to: {out_path}")
        return

    for idx, method in enumerate(scan_methods, 1):
        prompt_tag = f"{method.name}_{method.start_line}"
        try:
            secondary_methods = build_secondary_methods_for_prompt(method, methods_by_name)
            secondary_summary = summarize_secondary_methods(secondary_methods) if secondary_methods else None
            method_result = call_llm(
                system_prompt,
                args.bug,
                method,
                java_code,
                model_cfg,
                prompt_tag,
                secondary_summary,
                source_path.name,
                language,
                args.attribute_mode,
            )
        except Exception as e:
            print(f"[WARN] LLM failed for method {prompt_tag}; using heuristic fallback: {e}", file=sys.stderr)
            method_result = {
                "candidates": heuristic_candidates_for_method(method, args.bug, desc, language)
            }
        new_candidates = method_result.get("candidates", [])
        if new_candidates:
            aggregated_candidates.extend(new_candidates)
            # update payload and append to file
            payload[args.bug]["candidates"] = aggregated_candidates
            out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    merged_candidates = _merge_duplicate_candidates(aggregated_candidates)
    results = {"candidates": merged_candidates}

    method_info_by_start = {m.start_line: m for m in methods}
    if language == "java":
        package_name, explicit_imports, wildcard_packages = parse_package_and_imports(java_code)
        local_class_names = {m.class_path.split("::")[-1] for m in methods if m.class_path and m.class_path != "Global"}
        field_type_map = extract_field_type_map(java_code)
    else:
        package_name, explicit_imports, wildcard_packages = "", {}, []
        local_class_names = set()
        field_type_map = {}
    simple_lookup_cache: dict[str, list[Path]] = {}
    file_method_cache: dict[Path, list[MethodInfo]] = {}
    file_code_cache: dict[Path, str] = {}
    source_file_cache: dict[str, list[Path]] = {}

    # Attach method info and content to each candidate using reconciled line_number
    for cand in results.get("candidates", []):
        ln = cand.get("line_number")
        meta = method_map.get(ln)
        if meta:
            cand["method_name"] = meta.get("name")
            start_line = meta.get("start_line")
            if start_line:
                cand["method_line_number"] = max(1, ln - start_line + 1)
                method_info = method_info_by_start.get(start_line)
                if method_info:
                    cand["method_class_path"] = method_info.class_path
                    snippet_lines = [line for _, line in method_info.snippet]
                    cand["method_signature"] = (method_info.signature_line or (snippet_lines[0] if snippet_lines else "")).strip()
                    cand["method_body"] = "\n".join(snippet_lines[1:]).strip() if len(snippet_lines) > 1 else ""
                    cand["method_content"] = "\n".join(snippet_lines).strip()
        else:
            cand.setdefault("method_name", None)
            cand.setdefault("method_line_number", None)
            cand.setdefault("method_class_path", "")
            cand.setdefault("method_signature", "")
            cand.setdefault("method_body", "")
            cand.setdefault("method_content", "")

    for cand in results.get("candidates", []):
        secondary_methods: list[dict] = []
        cand_method_name = cand.get("method_name")
        cand_sig_norm = normalize_signature(cand.get("method_signature"))
        cand_content = (cand.get("method_content") or "").strip()
        cand_class_path = cand.get("method_class_path") or ""
        seen = set()
        method_info = None
        meta = method_map.get(cand.get("line_number"))
        if meta:
            start_line = meta.get("start_line")
            if start_line:
                method_info = method_info_by_start.get(start_line)
        if method_info:
            calls = iter_method_calls(method_info.snippet)
            method_class_path = method_info.class_path
        else:
            calls = []
            for line in (cand.get("method_content") or "").splitlines():
                for call_name in parse_call_names(line):
                    calls.append((cand.get("line_number"), line, call_name))
            method_class_path = cand_class_path

        for called_line_num, called_line_content, call_name in calls:
            overloads = methods_by_name.get(call_name, [])
            if method_class_path:
                overloads = [m for m in overloads if m.class_path == method_class_path]
            if not overloads:
                continue
            for m in overloads:
                content = "\n".join([line for _, line in m.snippet]).strip()
                if cand_method_name and m.name == cand_method_name:
                    sig_norm = normalize_signature(m.signature_line or (m.snippet[0][1] if m.snippet else ""))
                    if cand_sig_norm and sig_norm and sig_norm == cand_sig_norm:
                        continue
                    if not cand_sig_norm and cand_content and content == cand_content:
                        continue
                entry: dict[str, Any] = {
                    "method_name": m.name,
                    "called_at_line_number": called_line_num,
                    "called_at_line_content": called_line_content,
                }
                signature = (m.signature_line or (m.snippet[0][1] if m.snippet else "")).strip()
                if signature:
                    entry["method_signature"] = signature
                param_count = param_count_from_method(m)
                if param_count is not None:
                    entry["param_count"] = param_count
                key = (
                    entry["method_name"],
                    entry.get("method_signature", ""),
                    entry["called_at_line_number"],
                    entry["called_at_line_content"],
                )
                if key in seen:
                    continue
                seen.add(key)
                secondary_methods.append(entry)

        external_methods = build_external_methods_for_candidate(
            method_info=method_info,
            method_content=cand.get("method_content") or "",
            local_methods_by_name=methods_by_name,
            package_name=package_name,
            explicit_imports=explicit_imports,
            wildcard_packages=wildcard_packages,
            local_class_names=local_class_names,
            field_type_map=field_type_map,
            code_base_path=code_base_path,
            source_rel_path=source_rel_path,
            simple_lookup_cache=simple_lookup_cache,
            file_method_cache=file_method_cache,
            file_code_cache=file_code_cache,
            language=language,
            source_file_cache=source_file_cache,
        )
        cand["supporting_context"] = {
            "secondary_methods": secondary_methods,
            "external_methods": external_methods,
        }
        cand.pop("secondary_methods", None)

    payload = {
        args.bug: {
            "description": desc,
            "scanned_file": source_path.name,
            "language": language,
            "source_rel_path": source_rel_path,
            "code_base_path": str(code_base_path) if code_base_path else "",
            "candidates": results.get("candidates", []),
        }
    }

    # final write ensures consistency
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[DONE] Results saved to: {out_path}")

if __name__ == "__main__":
    main()
