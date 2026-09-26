#!/usr/bin/env python3

from __future__ import annotations
from pathlib import Path
import argparse, json, sys

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.append(str(SCRIPT_DIR))
BASE_DIR = SCRIPT_DIR.parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))
from agents.libs import models
from agents.libs.evidence import compact_method_refs, get_supporting_context
from agents.libs.jsonio import read_json, write_json
from agents.libs.logging_utils import log_prompt

TOOLS = [
    {
        "name": "AST",
        "description": (
            "Abstract Syntax Tree. Structural representation of source code. "
            "Use when the bug can be confirmed by syntax or structure alone, such as "
            "dereference expressions, missing null checks, incorrect API usage, "
            "invalid modifiers, or local structural patterns that do not depend on "
            "execution paths or value propagation."
        )
    },
    {
        "name": "CFG",
        "description": (
            "Control Flow Graph. Represents all possible execution paths through code. "
            "Use when confirming the bug requires path sensitivity, including conditional "
            "branches, exception paths, early returns, missing or ineffective guards, "
            "or resource leaks or null dereferences that occur only on specific paths."
        )
    },
    {
        "name": "DFG",
        "description": (
            "Data Flow Graph. Represents value propagation via def-use chains, aliasing, "
            "and interprocedural flow. Use when confirming the bug requires tracking how "
            "values (e.g., nulls, resources, states) propagate across variables, fields, "
            "or method boundaries, including ownership or lifetime reasoning."
        )
    }
]

def build_system_prompt() -> str:  # v2: best-match selection
    tool_lines = "\n".join(f"- {t['name']}: {t['description']}" for t in TOOLS)
    return (
        "You are a static-analysis planning agent.\n\n"
        "Goal: choose EXACTLY ONE analysis graph (AST, CFG, or DFG) that is the BEST fit "
        "for confirming whether a sink-point candidate is a true bug.\n\n"
        "Available analysis graphs:\n"
        f"{tool_lines}\n\n"
        "Selection approach:\n"
        "- Evaluate ALL three tools against the candidate evidence and bug rule.\n"
        "- Select the tool whose capabilities most directly address the specific confirmation "
        "needed for this candidate — not simply the first tool whose criteria technically apply.\n"
        "- A tool is the best fit when its output would be both necessary and sufficient to "
        "confirm or refute the bug, and the other two tools would provide less decisive evidence.\n\n"
        "Hard constraints:\n"
        "- Use only evidence present in the input.\n"
        "- Do not invent facts.\n"
        "- Output JSON only, exactly matching the schema below.\n\n"
        "Output schema:\n"
        "{\n"
        "  \"analysis_decisions\": {\n"
        "    \"analysis_tool\": \"AST|CFG|DFG\",\n"
        "    \"selected_analysis_justification\": [\"...\"]\n"
        "  }\n"
        "}\n\n"
        "Justification rules:\n"
        "- 2–4 short bullets.\n"
        "- Must cite evidence from the provided candidate/supporting context and tie it to the bug rule semantics.\n"
        "- Must state why the selected tool is the best fit and why the other two are less appropriate.\n"
    )


def build_user_prompt_single(bug_rule: str, desc: str, candidate: dict) -> str:
    """
    Compact evidence payload for deterministic tool selection.
    """
    supporting = get_supporting_context(candidate)
    secondary_methods = supporting["secondary_methods"]
    external_methods = supporting["external_methods"]
    secondary_compact = compact_method_refs(secondary_methods, is_external=False)
    external_compact = compact_method_refs(external_methods, is_external=True)

    sink_stmt = candidate.get("candidate") or candidate.get("matched_statement") or ""

    return (
        f"BUG RULE TITLE:\n{bug_rule}\n\n"
        f"BUG RULE DESCRIPTION:\n{desc}\n\n"
        "CANDIDATE EVIDENCE:\n"
        f"- sink_point_justification: {candidate.get('sink_point_justification')}\n"
        f"- sink_statement: {sink_stmt}\n"
        f"- line_number: {candidate.get('line_number')}\n"
        f"- line_content: {candidate.get('line_content')}\n"
        f"- candidate_method_name: {candidate.get('method_name')}\n\n"
        "SUPPORTING CONTEXT:\n"
        f"- secondary_methods: {json.dumps(secondary_compact, ensure_ascii=False)}\n"
        f"- external_methods: {json.dumps(external_compact, ensure_ascii=False)}\n"
    )
 

def heuristic_plan_single(bug_rule: str, desc: str, candidate: dict) -> list[dict]:
    text = " ".join([
        str(bug_rule or ""),
        str(desc or ""),
        str(candidate.get("sink_point_justification") or ""),
        str(candidate.get("candidate") or candidate.get("matched_statement") or ""),
        str(candidate.get("line_content") or ""),
    ]).lower()
    supporting = get_supporting_context(candidate)
    secondary_methods = supporting["secondary_methods"]
    external_methods = supporting["external_methods"]

    dfg_signals = [
        "propagat", "flow", "alias", "reassign", "ownership", "lifetime",
        "returned by", "comes from", "passed into", "interprocedural",
    ]
    cfg_signals = [
        "path", "branch", "guard", "error-path", "error path", "reachability",
        "early return", "conditional", "only if", "under certain", "dominating null check",
    ]

    if secondary_methods or external_methods or any(sig in text for sig in dfg_signals):
        return [{
            "analysis_tool": "DFG",
            "selected_analysis_justification": [
                "Heuristic fallback selected DFG because confirmation appears to depend on value propagation across variables or calls.",
                "Supporting context includes secondary or external method evidence, which usually requires def-use style reasoning.",
            ],
        }]

    if any(sig in text for sig in cfg_signals):
        return [{
            "analysis_tool": "CFG",
            "selected_analysis_justification": [
                "Heuristic fallback selected CFG because the candidate description refers to control-flow conditions or guard effectiveness.",
                "This bug appears to depend on whether a risky state can reach the sink on a specific path.",
            ],
        }]

    return [{
        "analysis_tool": "AST",
        "selected_analysis_justification": [
            "Heuristic fallback selected AST because the visible evidence looks like a local structural sink pattern.",
            "No strong path-sensitive or value-propagation signal was present in the candidate input.",
        ],
    }]


def call_llm_single(bug_rule: str, desc: str, candidate: dict,
                    model_cfg: dict, idx: int, scanned_file: str):
    sys_p = build_system_prompt()
    usr_p = build_user_prompt_single(bug_rule, desc, candidate)
    log_prompt(SCRIPT_DIR, bug_rule, f"system_prompt_candidate_{idx}", sys_p)
    log_prompt(SCRIPT_DIR, bug_rule, f"user_prompt_candidate_{idx}", usr_p)
    text = models.chat(SCRIPT_DIR, "planner", scanned_file, sys_p, usr_p,
                       model_cfg, max_new_tokens=800)
    s, e = text.find("{"), text.rfind("}")
    if s != -1 and e != -1 and e > s:
        text = text[s:e+1]

    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("LLM output is not an object")

    decisions = data.get("analysis_decisions")
    if isinstance(decisions, dict):
        decisions = [decisions]
    if not isinstance(decisions, list):
        raise ValueError("Missing analysis_decisions in LLM output")

    for item in decisions:
        if "analysis_tool" not in item:
            raise ValueError("Missing analysis_tool in an item")
        if "selected_analysis_justification" not in item or not isinstance(item["selected_analysis_justification"], list):
            raise ValueError("Missing selected analysis justification list in an item")

    return decisions

def main():
    ap = argparse.ArgumentParser(description="Planner agent")
    ap.add_argument("--input", default="sink_point_agent/sink_point_candidates.json")
    ap.add_argument("--output", default="planner_agent/planner_decision.json")
    ap.add_argument("--model", default="qwen", help="LLM backend to use (default: qwen)")
    args = ap.parse_args()

    inp_path = Path(args.input)
    if not inp_path.is_file():
        print(f"[ERROR] Input not found: {inp_path}", file=sys.stderr)
        sys.exit(2)

    data = read_json(inp_path)
    if not isinstance(data, dict) or len(data) != 1:
        print("[ERROR] Expected a single bug rule object in input JSON", file=sys.stderr)
        sys.exit(2)

    bug_rule, payload = next(iter(data.items()))
    desc = payload.get("description", "")
    scanned_file = payload.get("scanned_file", "")
    candidates = payload.get("candidates", [])
    source_rel_path = payload.get("source_rel_path", "")
    code_base_path = payload.get("code_base_path", "")

    print(f"[INFO] Processing {bug_rule} (candidates: {len(candidates)}) ...")

    out_obj = {
        bug_rule: {
            "description": desc,
            "scanned_file": scanned_file,
            "source_rel_path": source_rel_path,
            "code_base_path": code_base_path,
            "candidates": [],
        }
    }
    out_path = Path(args.output)
    write_json(out_path, out_obj)

    if candidates:
        model_cfg = models.resolve_model(args.model)
        for idx, cand in enumerate(candidates, 1):
            try:
                decisions = call_llm_single(bug_rule, desc, cand, model_cfg, idx, scanned_file)
            except Exception as e:
                print(f"[ERROR] LLM failed for candidate {idx}: {e}", file=sys.stderr)
                decisions = heuristic_plan_single(bug_rule, desc, cand)
            dec = decisions[0] if decisions else {"analysis_tool": "AST", "selected_analysis_justification": ["No response"]}
            tool = dec.get("analysis_tool") or "AST"
            selected_analysis_justification = dec.get("selected_analysis_justification", ["No analysis selection justification provided"])
            out_obj[bug_rule]["candidates"].append({**cand, "analysis_tool": tool, "selected_analysis_justification": selected_analysis_justification})
            write_json(out_path, out_obj)

    print(f"[DONE] Decisions saved to: {out_path}")

if __name__ == "__main__":
    main()
