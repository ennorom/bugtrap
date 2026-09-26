#!/usr/bin/env python3

from __future__ import annotations
from pathlib import Path
import argparse, json, re, sys
from typing import Dict, Any, List

TOOL_MAP = {"CFG": "cfg", "AST": "ast", "DFG": "dfg"}
JOERN_TIMEOUT_SECONDS = 120

# Tool selection per language: C/C++ has one tool and no fallback; Java falls
# back along an ordered chain ending in the heuristic stand-in.
C_DRIVER = "joern"
JAVA_AST_DRIVER = "spoon"
JAVA_GRAPH_CHAIN = ("soot", "comex")
FALLBACK_DRIVER = "heuristic"

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.append(str(SCRIPT_DIR))
BASE_DIR = SCRIPT_DIR.parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))
from agents.libs.language_support import detect_language_from_path, read_source_file
from agents.libs import drivers
from agents.libs.drivers.java_runtime import configure_timeouts, ensure_driver_compiled, has_methods_payload
from agents.libs.jsonio import read_json
from agents.libs.method_index import (
    MethodEntry,
    build_method_index,
    detect_real_class_name,
    detect_top_level_class,
    find_method_entry,
    resolve_external_source_path,
)
from agents.libs.method_match import (
    candidate_method_probe_content,
    candidate_target_line,
    filter_method_only,
    has_method_entry,
    normalize_tool_label,
    summarize_methods,
)


def run_joern(source_path: Path, mode: str, scanned_file: str,
              cache: Dict[tuple, Dict[str, Any]], language: str = "c") -> Dict[str, Any]:
    """C/C++: one tool, one run per (file, mode).

    There is no second C/C++ tool, so a failure is not substituted — the error
    payload comes back and the caller logs it.
    """
    key = (str(source_path), mode)
    if key not in cache:
        print(f"[INFO] {mode}: running Joern on {Path(source_path).name} (language={language})")
        cache[key] = drivers.get(C_DRIVER).analyze(
            Path(source_path), mode, scanned_file=scanned_file, timeout=JOERN_TIMEOUT_SECONDS
        )
    return cache[key]


def run_java_ast(source_path: Path, source_code: str, scanned_file: str,
                 cache: Dict[str, Dict[str, Any]], key: str = "ast") -> Dict[str, Any]:
    if key not in cache:
        cache[key] = normalize_tool_label(
            drivers.get(JAVA_AST_DRIVER).analyze(
                Path(source_path), "ast", source_code=source_code, scanned_file=scanned_file
            ),
            JAVA_AST_DRIVER,
        )
    return cache[key]


def run_java_graph(source_path: Path, mode: str, class_name: str, scanned_file: str,
                   engine_mode: str, cache: Dict[tuple, Dict[str, Any]]) -> Dict[str, Any]:
    """Java CFG/DFG: soot then comex when the engine is `auto`.

    A pinned engine runs alone. The last driver's payload is returned even when
    it is empty, so the caller can decide to fall back to the heuristic.
    """
    names = (engine_mode,) if engine_mode in JAVA_GRAPH_CHAIN else JAVA_GRAPH_CHAIN
    result: Dict[str, Any] = {}
    for idx, name in enumerate(names):
        key = (mode, class_name, name)
        if key not in cache:
            print(f"[INFO] {mode}: running {name.capitalize()}Driver (engine={engine_mode})")
            try:
                cache[key] = drivers.get(name).analyze(
                    Path(source_path), mode, class_name=class_name, scanned_file=scanned_file
                )
            except Exception as exc:
                if idx + 1 < len(names):
                    print(f"[WARN] {mode}: {name.capitalize()}Driver raised {exc}; "
                          f"falling back to {names[idx + 1].capitalize()}Driver")
                    continue
                cache[key] = drivers.error_payload(name, str(exc))
        result = cache[key]
        if not drivers.is_error(result) and has_methods_payload(result):
            return result
        if idx + 1 < len(names):
            print(f"[WARN] {mode}: {name.capitalize()}Driver failed or returned empty methods; "
                  f"falling back to {names[idx + 1].capitalize()}Driver")
    return result


def run_heuristic(source_path: Path, mode: str, method_entry: Any) -> Dict[str, Any]:
    return drivers.get(FALLBACK_DRIVER).analyze(Path(source_path), mode, method_entry=method_entry)


def stream_internal_analysis(decisions, java_path: Path, java_code: str, out_path: Path,
                             engine: str = "auto", language: str = "java"):
    bug, payload = next(iter(decisions.items()))
    scanned_file = payload.get("scanned_file", "")
    code_base_path = payload.get("code_base_path", "")
    engine_mode = (engine or "auto").strip().lower()
    if engine_mode not in {"auto", "soot", "comex"}:
        raise ValueError(f"Unsupported engine: {engine_mode}")
    out_obj = {
        bug: {
            "description": payload["description"],
            "scanned_file": scanned_file,
            "language": language,
            "source_rel_path": payload.get("source_rel_path", ""),
            "code_base_path": payload.get("code_base_path", ""),
            "candidates": [],
        }
    }
    out_path.write_text(json.dumps(out_obj, indent=2), encoding="utf-8")

    line_map, methods = build_method_index(java_code, language=language)
    ast_cache: Dict[str, Dict[str, Any]] = {}
    graph_cache: Dict[tuple[str, str, str], Dict[str, Any]] = {}
    external_ast_cache: Dict[str, Dict[str, Any]] = {}
    external_graph_cache: Dict[tuple[str, str, str, str], Dict[str, Any]] = {}
    external_code_cache: Dict[Path, str] = {}
    # Keyed by (str(file_path), mode) — one Joern run per file per mode for C/C++.
    joern_cache: Dict[tuple, Dict[str, Any]] = {}

    for c in payload["candidates"]:
        method_name = c.get("method_name")
        method_signature = c.get("method_signature")
        line_number = c.get("line_number")
        method_probe_content = candidate_method_probe_content(c)

        entry = find_method_entry(line_map, methods, line_number, method_name)

        tool = TOOL_MAP.get((c.get("analysis_tool") or "").upper(), "ast")

        if language != "java":
            joern_base = run_joern(java_path, tool, scanned_file, joern_cache, language)
            if joern_base.get("status") != "error":
                final = filter_method_only(
                    joern_base, method_name, None, method_signature, method_probe_content, line_number
                )
                if has_method_entry(final):
                    final = normalize_tool_label(final, "joern")
                else:
                    final = {
                        "tool": "joern",
                        "status": "error",
                        "message": f"Joern method not found: {method_name}",
                        "available_methods": summarize_methods(joern_base.get("classes")),
                    }
            else:
                print(f"[WARN] Joern failed: {joern_base.get('message', '')[:120]}")
                final = joern_base

            # Attach declared member types for parent->field / parent.field
            # accesses in the candidate's enclosing method. The decision agent
            # uses this to stop hedging between "pointer" and "inline array"
            # when judging nested-member dereference sinks.
            mt_result = run_joern(java_path, "member_types", scanned_file, joern_cache, language)
            if isinstance(final, dict) and mt_result.get("status") == "ok":
                accesses = mt_result.get("accesses") or []
                method_block = final.get("method") if isinstance(final.get("method"), dict) else {}
                m_start = int(method_block.get("start_line") or 0)
                m_end = int(method_block.get("end_line") or 0)
                if m_start and m_end and accesses:
                    scoped = [
                        a for a in accesses
                        if isinstance(a, dict) and m_start <= int(a.get("line") or -1) <= m_end
                    ]
                    if scoped:
                        final = {**final, "member_types": scoped}
        else:
            if tool == "ast":
                base_result = run_java_ast(java_path, java_code, scanned_file, ast_cache)
            else:
                class_name = entry.binary_class if entry else detect_real_class_name(java_path)
                base_result = run_java_graph(java_path, tool, class_name, scanned_file,
                                             engine_mode, graph_cache)

            class_hint = entry.simple_class if entry else None
            if tool == "ast":
                final = filter_method_only(
                    base_result, method_name, class_hint, method_signature, method_probe_content, line_number
                )
                final = normalize_tool_label(final, "spoon")
                if not has_method_entry(final):
                    final = run_heuristic(java_path, tool, entry)
            else:
                final = filter_method_only(
                    base_result, method_name, class_hint, method_signature, method_probe_content, line_number
                )
                # In auto mode, if Soot parsed classes but method-level selection failed,
                # retry method extraction against Comex before returning incomplete data.
                if (
                    engine_mode == "auto"
                    and not has_method_entry(final)
                    and (base_result.get("tool") or "").lower() != "comex"
                ):
                    comex_base = run_java_graph(java_path, tool, class_name, scanned_file,
                                                "comex", graph_cache)
                    comex_final = filter_method_only(
                        comex_base,
                        method_name,
                        class_hint,
                        method_signature,
                        method_probe_content,
                        line_number,
                    )
                    if has_method_entry(comex_final):
                        final = normalize_tool_label(comex_final, comex_base.get("tool") or "comex")
                    else:
                        final = run_heuristic(java_path, tool, entry)
                elif not has_method_entry(final):
                    final = run_heuristic(java_path, tool, entry)
                else:
                    final = normalize_tool_label(final, base_result.get("tool") or "soot")

        candidate_out = {**c, "internal_analysis_result": final}
        supporting_context = candidate_out.get("supporting_context")
        if not isinstance(supporting_context, dict):
            supporting_context = {}
        sec_methods = supporting_context.get("secondary_methods")
        if not isinstance(sec_methods, list):
            # Backward compatibility with older sink outputs.
            sec_methods = candidate_out.get("secondary_methods")
        if isinstance(sec_methods, list):
            for sec in sec_methods:
                if not isinstance(sec, dict):
                    continue
                sec_name = (sec.get("method_name") or "").strip()
                if not sec_name:
                    sec["internal_analysis_result"] = {
                        "tool": base_result.get("tool") or ("spoon" if tool == "ast" else "soot"),
                        "status": "error",
                        "message": "missing secondary method_name",
                    }
                    continue
                sec_signature = sec.get("method_signature")
                sec_probe_content = candidate_method_probe_content(sec)
                sec_line_number = candidate_target_line(sec)
                if language != "java":
                    joern_key = (str(java_path), tool)
                    joern_sec_base = joern_cache.get(joern_key)
                    if joern_sec_base and joern_sec_base.get("status") != "error":
                        sec_final = filter_method_only(
                            joern_sec_base, sec_name, None, sec_signature, sec_probe_content, sec_line_number
                        )
                        if has_method_entry(sec_final):
                            sec_final = normalize_tool_label(sec_final, "joern")
                        else:
                            sec_final = {
                                "tool": "joern",
                                "status": "error",
                                "message": f"Joern secondary method not found: {sec_name}",
                                "available_methods": summarize_methods(joern_sec_base.get("classes")),
                            }
                    else:
                        sec_final = joern_sec_base or {
                            "tool": "joern",
                            "status": "error",
                            "message": "Joern secondary analysis unavailable",
                        }
                else:
                    sec_final = filter_method_only(
                        base_result,
                        sec_name,
                        class_hint,
                        sec_signature,
                        sec_probe_content,
                        sec_line_number,
                    )
                    if (
                        tool != "ast"
                        and engine_mode == "auto"
                        and not has_method_entry(sec_final)
                        and (base_result.get("tool") or "").lower() != "comex"
                    ):
                        comex_base = run_java_graph(java_path, tool, class_name, scanned_file,
                                                    "comex", graph_cache)
                        comex_sec_final = filter_method_only(
                            comex_base,
                            sec_name,
                            class_hint,
                            sec_signature,
                            sec_probe_content,
                            sec_line_number,
                        )
                        if has_method_entry(comex_sec_final):
                            sec_final = normalize_tool_label(comex_sec_final, comex_base.get("tool") or "comex")
                    elif not has_method_entry(sec_final):
                        sec_entry = next((m for m in methods if m.name == sec_name), None)
                        sec_final = run_heuristic(java_path, tool, sec_entry)
                _c_tool_label = (
                    sec_final.get("tool") or "joern"
                    if language != "java" and isinstance(sec_final, dict)
                    else ("spoon" if tool == "ast" else "soot")
                ) if language != "java" else (base_result.get("tool") or ("spoon" if tool == "ast" else "soot"))
                if not has_method_entry(sec_final):
                    sec["internal_analysis_result"] = {
                        "tool": _c_tool_label,
                        "status": "error",
                        "message": f"secondary method not found: {sec_name}",
                    }
                else:
                    sec["internal_analysis_result"] = normalize_tool_label(sec_final, _c_tool_label)
            supporting_context["secondary_methods"] = sec_methods

        ext_methods = supporting_context.get("external_methods")
        if not isinstance(ext_methods, list):
            ext_methods = candidate_out.get("external_methods")
            if isinstance(ext_methods, list):
                supporting_context["external_methods"] = ext_methods
        if isinstance(ext_methods, list):
            chosen_external = None
            # Analyze only one external method to keep runtime/tokens bounded.
            for ext in ext_methods:
                if not isinstance(ext, dict):
                    continue
                if not (ext.get("method_name") or "").strip():
                    continue
                if chosen_external is None:
                    chosen_external = ext
                if (ext.get("method_content") or "").strip():
                    chosen_external = ext
                    break

            if isinstance(chosen_external, dict):
                ext_name = (chosen_external.get("method_name") or "").strip()
                ext_signature = chosen_external.get("method_signature")
                ext_probe_content = candidate_method_probe_content(chosen_external)
                ext_line_number = candidate_target_line(chosen_external)
                ext_file = resolve_external_source_path(code_base_path, chosen_external.get("source_rel_path"))
                default_tool = "joern" if language != "java" else ("spoon" if tool == "ast" else "soot")

                if not ext_name:
                    chosen_external["internal_analysis_result"] = {
                        "tool": default_tool,
                        "status": "error",
                        "message": "missing external method_name",
                    }
                elif ext_file is None:
                    chosen_external["internal_analysis_result"] = {
                        "tool": default_tool,
                        "status": "error",
                        "message": "external source file not found",
                    }
                else:
                    try:
                        if language != "java":
                            ext_base_result = run_joern(
                                ext_file, tool, f"{scanned_file}::external::{ext_file.name}",
                                external_graph_cache, language,
                            )
                        else:
                            if tool == "ast":
                                ext_code = external_code_cache.get(ext_file)
                                if ext_code is None:
                                    ext_code = ext_file.read_text(encoding="utf-8", errors="replace")
                                    external_code_cache[ext_file] = ext_code
                                ext_base_result = run_java_ast(
                                    ext_file, ext_code,
                                    f"{scanned_file}::external::{ext_file.name}",
                                    external_ast_cache, key=str(ext_file),
                                )
                            else:
                                ext_class_name = detect_real_class_name(ext_file)
                                ext_base_result = run_java_graph(
                                    ext_file, tool, ext_class_name,
                                    f"{scanned_file}::external::{ext_file.name}",
                                    engine_mode, external_graph_cache,
                                )

                        fqcn = (chosen_external.get("fqcn") or "").strip()
                        ext_class_hint = fqcn.split(".")[-1].split("$")[-1] if (language == "java" and fqcn) else None
                        ext_final = filter_method_only(
                            ext_base_result,
                            ext_name,
                            ext_class_hint,
                            ext_signature,
                            ext_probe_content,
                            ext_line_number,
                        )
                        if (
                            language == "java"
                            and tool != "ast"
                            and engine_mode == "auto"
                            and not has_method_entry(ext_final)
                            and (ext_base_result.get("tool") or "").lower() != "comex"
                        ):
                            comex_ext_base = run_java_graph(
                                ext_file, tool, ext_class_name,
                                f"{scanned_file}::external::{ext_file.name}",
                                "comex", external_graph_cache,
                            )
                            comex_ext_final = filter_method_only(
                                comex_ext_base,
                                ext_name,
                                ext_class_hint,
                                ext_signature,
                                ext_probe_content,
                                ext_line_number,
                            )
                            if has_method_entry(comex_ext_final):
                                ext_final = normalize_tool_label(comex_ext_final, comex_ext_base.get("tool") or "comex")
                        if not has_method_entry(ext_final):
                            chosen_external["internal_analysis_result"] = {
                                "tool": ext_base_result.get("tool") or default_tool,
                                "status": "error",
                                "message": f"external method not found: {ext_name}",
                            }
                        else:
                            chosen_external["internal_analysis_result"] = normalize_tool_label(
                                ext_final,
                                ext_base_result.get("tool") or default_tool,
                            )
                    except Exception as exc:
                        chosen_external["internal_analysis_result"] = {
                            "tool": default_tool,
                            "status": "error",
                            "message": f"external analysis failed: {exc}",
                        }
            supporting_context["external_methods"] = ext_methods

        candidate_out["supporting_context"] = supporting_context
        candidate_out.pop("secondary_methods", None)
        candidate_out.pop("external_methods", None)

        out_obj[bug]["candidates"].append(candidate_out)
        out_path.write_text(json.dumps(out_obj, indent=2), encoding="utf-8")

def main():
    ap = argparse.ArgumentParser()

    ap.add_argument("--input", default="planner_agent/planner_decision.json")
    ap.add_argument("--file")
    ap.add_argument("--output", default="internal_analysis_agent/internal_analysis_decision.json")
    ap.add_argument("--engine", choices=["auto", "soot", "comex"], default="auto")
    ap.add_argument(
        "--driver-timeout-seconds",
        type=int,
        default=0,
        help="Optional timeout for each Java driver invocation (0 disables).",
    )
    ap.add_argument(
        "--comex-timeout-seconds",
        type=int,
        default=180,
        help="Timeout for the nested comex CLI process in ComexDriver (0 disables).",
    )
    ap.add_argument(
        "--joern-timeout-seconds",
        type=int,
        default=120,
        help="Timeout in seconds for each Joern invocation on C/C++ files (0 disables).",
    )

    a = ap.parse_args()
    global JOERN_TIMEOUT_SECONDS
    configure_timeouts(a.driver_timeout_seconds, a.comex_timeout_seconds)
    JOERN_TIMEOUT_SECONDS = max(0, int(a.joern_timeout_seconds or 0))
    decisions = read_json(Path(a.input))
    java_path = Path(a.file)
    language = detect_language_from_path(java_path)
    java_code = read_source_file(java_path)

    if language == "java":
        ensure_driver_compiled()
    stream_internal_analysis(decisions, java_path, java_code, Path(a.output), engine=a.engine, language=language)

if __name__ == "__main__":
    main()
