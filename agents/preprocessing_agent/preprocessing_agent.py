#!/usr/bin/env python3
from __future__ import annotations

import argparse, csv, difflib, json, re, sys, random
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.append(str(SCRIPT_DIR))
BASE_DIR = SCRIPT_DIR.parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))
from agents.libs.language_support import detect_language_from_path, extract_brace_methods, read_source_lines
from agents.libs import models
from agents.libs.source_parsing import (
    CALL_IGNORE,
    extract_call_args,
    normalize_signature,
    parse_call_names,
    top_level_arg_count,
)

TOOL_DEFAULT = "infer"
TOOL = TOOL_DEFAULT
def _build_processed_regex(tool: str) -> re.Pattern:
    return re.compile(rf"\bseed_{tool.title()}_(\d+)_Original\.java\b", re.IGNORECASE)


_SPOT_ORIG_RE = _build_processed_regex(TOOL)
CONTROL_WORDS = {"if","for","while","switch","catch","do","synchronized","try"}
_BLOCK = re.compile(r"/\*.*?\*/", re.S)
CONTROL_HEADER_RE = re.compile(r"^(if|for|while|switch|catch)\s*\(", re.IGNORECASE)


# ------------- basic helpers -------------
def configure_csv_field_limit() -> None:
    limit = sys.maxsize
    while True:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


def detect_delimiter(p: Path) -> str:
    head = p.read_text(encoding="utf-8", errors="replace")[:8000]
    for d in [",","\t",";","|"]:
        if d in head:
            return d
    return ","


def norm(s: str) -> str:
    return re.sub(r"\s+"," ", (s or "").strip().lower())


def find_col(headers: List[str], names: List[str]) -> Optional[str]:
    want = {norm(x) for x in names}
    for h in headers or []:
        if norm(h) in want:
            return h
    return None


def parse_lines_field(s: str) -> List[int]:
    return list(dict.fromkeys(int(x) for x in re.findall(r"\d+", s or "")))


def parse_changed_lines(value: Any) -> List[int]:
    raw = value
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = []
    out: List[int] = []
    for item in raw or []:
        if isinstance(item, list) and item:
            try:
                out.append(int(item[0]))
            except Exception:
                continue
    return out


def configure_tool(tool: str) -> None:
    global TOOL, _SPOT_ORIG_RE
    TOOL = tool
    _SPOT_ORIG_RE = _build_processed_regex(tool)


def resolve_code_path(processed_file: str) -> Optional[Path]:
    m = _SPOT_ORIG_RE.search(processed_file or "")
    if not m:
        return None
    idx = int(m.group(1))
    p = Path(".") / f"{TOOL}_clean_java_code_filtered" / f"result_{TOOL.title()}_{idx}" / processed_file
    return p if p.is_file() else None


def strip_block_keep_lines(text: str) -> str:
    return _BLOCK.sub(lambda m: "\n"*m.group(0).count("\n"), text)


def strip_line_comment(line: str) -> str:
    i = line.find("//")
    return line if i < 0 else line[:i]


def read_lines(p: Path) -> List[str]:
    return read_source_lines(p)

def normalize_method_token(raw: Any) -> str:
    token = str(raw or "").strip()
    if not token:
        return ""
    token = token.split("::")[-1].split(".")[-1].strip()
    match = re.search(r"([A-Za-z_$][\w$]*)\s*(?:\(|$)", token)
    return match.group(1).lower() if match else ""

def _param_count_from_method(method: Dict[str, Any]) -> int | None:
    raw = method.get("param_count")
    if raw is not None:
        try:
            return int(raw)
        except (TypeError, ValueError):
            pass
    sig_line = method.get("signature") or ""
    inside = extract_call_args(sig_line, method.get("name") or "")
    return top_level_arg_count(inside)


# ------------- method extraction -------------
def _find_methods_with_sink_ast(lines: List[str], source_path: Path | None) -> List[Dict[str, Any]]:
    if source_path is None or not source_path.is_file():
        return []
    language = detect_language_from_path(source_path)
    methods = extract_brace_methods(lines, language=language)
    extracted: List[Dict[str, Any]] = []
    for method in methods or []:
        name = str(method.get("name", "") or "").strip()
        if not name or name == "ENTIRE_FILE":
            continue
        code = str(method.get("code", "") or "")
        snippet = code.splitlines()
        start_line = int(method.get("start_line", 1))
        end_line = int(method.get("end_line", start_line))
        if start_line < 1:
            start_line = 1
        if end_line < start_line:
            end_line = start_line
        if start_line > len(lines):
            continue
        if end_line > len(lines):
            end_line = len(lines)

        signature = str(method.get("signature", "") or "").strip()
        if not signature:
            signature = snippet[0].strip() if snippet else ""

        class_path = str(method.get("class_path", "") or "").strip() or "Global"
        record: Dict[str, Any] = {
            "name": name,
            "kind": "method",
            "start_line": start_line,
            "end_line": end_line,
            "signature": signature,
            "class_path": class_path,
            "code": code,
        }
        param_count = method.get("param_count")
        if param_count is not None:
            try:
                record["param_count"] = int(param_count)
            except (TypeError, ValueError):
                pass
        extracted.append(record)

    extracted.sort(key=lambda m: (m["start_line"], m["end_line"], m["name"]))
    return extracted


def find_methods(lines: List[str], source_path: Path | None = None) -> List[Dict[str, Any]]:
    ast_methods = _find_methods_with_sink_ast(lines, source_path)
    if ast_methods:
        return ast_methods

    methods: List[Dict[str, Any]] = []
    n, i = len(lines), 0
    while i < n:
        line = lines[i].strip()
        if not line:
            i += 1
            continue

        start_idx = i
        sig_lines: List[str] = []

        # Capture annotations above the signature.
        while i < n and lines[i].strip().startswith("@"):
            sig_lines.append(lines[i])
            i += 1

        if i >= n:
            break

        # Build signature across lines until "{" or ";" with balanced parentheses.
        paren_depth = 0
        found_paren = False
        j = i
        while j < n:
            part = lines[j]
            paren_depth += part.count("(") - part.count(")")
            if part.count("(") > 0:
                found_paren = True
            sig_lines.append(part)
            if "{" in part or (found_paren and paren_depth == 0 and ";" in part):
                break
            j += 1

        signature_text = " ".join(sig_lines).strip()
        token = re.split(r"[^\w$]+", signature_text)[0] if signature_text else ""
        if not found_paren or token in CONTROL_WORDS:
            i = max(j + 1, start_idx + 1)
            continue
        if "class " in signature_text or "interface " in signature_text or "enum " in signature_text:
            i = max(j + 1, start_idx + 1)
            continue
        if ";" in sig_lines[-1] and "{" not in sig_lines[-1]:
            i = j + 1
            continue

        m = re.search(r"([A-Za-z_$][\w$]*)\s*\(", signature_text)
        name = m.group(1) if m else "unknown"

        depth, k, started = 0, start_idx, False
        while k < n:
            for ch in lines[k]:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
            if started and depth == 0:
                end = k + 1
                signature_line = lines[i].strip()
                methods.append({
                    "name": name,
                    "kind": "method",
                    "start_line": start_idx + 1,
                    "end_line": end,
                    "signature": signature_line,
                    "class_path": "Global",
                    "code": "\n".join(lines[start_idx:end])
                })
                i = end
                break
            k += 1
        else:
            end = min(n, start_idx + 120)
            signature_line = lines[i].strip()
            methods.append({
                "name": name,
                "kind": "method",
                "start_line": start_idx + 1,
                "end_line": end,
                "signature": signature_line,
                "class_path": "Global",
                "code": "\n".join(lines[start_idx:end])
            })
            i = end
            continue
    return methods


def _build_methods_by_name(methods: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    methods_by_name: Dict[str, List[Dict[str, Any]]] = {}
    for method in methods:
        methods_by_name.setdefault(method.get("name", ""), []).append(method)
    return methods_by_name


def _extract_named_method_direct(lines: List[str], target_method: str, hits: List[int]) -> Optional[Dict[str, Any]]:
    if not target_method:
        return None
    name_pat = re.compile(rf"\b{re.escape(target_method)}\s*\(", re.IGNORECASE)
    n = len(lines)
    fallback_match: Optional[Dict[str, Any]] = None
    for idx, line in enumerate(lines):
        if not name_pat.search(line):
            continue
        start = idx
        while start > 0:
            prev = lines[start - 1].strip()
            if not prev:
                break
            if prev.endswith(";") or prev.endswith("}") or prev.startswith("#"):
                break
            start -= 1

        end_sig = idx
        brace_line = None
        while end_sig < n and end_sig - start <= 25:
            part = lines[end_sig]
            if "{" in part:
                brace_line = end_sig
                break
            if ";" in part:
                break
            end_sig += 1
        if brace_line is None:
            continue

        depth = 0
        started = False
        end = None
        for k in range(brace_line, n):
            for ch in lines[k]:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
            if started and depth == 0:
                end = k + 1
                break
        if end is None:
            continue

        start_line = start + 1
        end_line = end
        signature = " ".join(line.strip() for line in lines[start:brace_line + 1]).strip()
        if CONTROL_HEADER_RE.match(signature.lstrip("!")):
            continue
        code = "\n".join(lines[start:end])
        hit_lines_in_method = sorted(
            {
                max(1, hit - start_line + 1)
                for hit in hits
                if start_line <= hit <= end_line
            }
        )
        record = {
            "name": target_method,
            "kind": "method",
            "start_line": start_line,
            "end_line": end_line,
            "signature": signature,
            "class_path": "Global",
            "code": code,
            "hit_lines_in_method": hit_lines_in_method,
        }
        if hits and not any(start_line <= hit <= end_line for hit in hits):
            fallback_match = fallback_match or record
            continue
        return record
    return fallback_match


def _extract_enclosing_method_from_hits(lines: List[str], target_method: str, hits: List[int]) -> Optional[Dict[str, Any]]:
    if not hits:
        return None
    normalized_target = normalize_method_token(target_method)
    raw_target = str(target_method or "").strip()
    n = len(lines)
    for hit in sorted(h for h in hits if 1 <= h <= n):
        for brace_line in range(hit - 1, -1, -1):
            if "{" not in lines[brace_line]:
                continue
            start = brace_line
            while start > 0 and brace_line - start < 25:
                prev = lines[start - 1].strip()
                if not prev or prev.endswith(";") or prev.endswith("}") or prev.startswith("#"):
                    break
                start -= 1
            signature_text = " ".join(line.strip() for line in lines[start:brace_line + 1]).strip()
            if "(" not in signature_text:
                continue
            if CONTROL_HEADER_RE.match(signature_text.lstrip("!")):
                continue
            if normalized_target:
                norm_sig = normalize_method_token(signature_text)
                target_in_sig = bool(raw_target) and raw_target.lower() in signature_text.lower()
                if norm_sig != normalized_target and not target_in_sig:
                    continue
            depth = 0
            started = False
            end = None
            for k in range(brace_line, n):
                for ch in lines[k]:
                    if ch == "{":
                        depth += 1
                        started = True
                    elif ch == "}":
                        depth -= 1
                if started and depth == 0:
                    end = k + 1
                    break
            if end is None or not (start + 1 <= hit <= end):
                continue
            name = normalized_target or normalize_method_token(signature_text) or "unknown"
            hit_lines_in_method = sorted(
                {
                    max(1, candidate_hit - start)
                    for candidate_hit in hits
                    if start + 1 <= candidate_hit <= end
                }
            )
            return {
                "name": name,
                "kind": "method",
                "start_line": start + 1,
                "end_line": end,
                "signature": signature_text,
                "class_path": "Global",
                "code": "\n".join(lines[start:end]),
                "hit_lines_in_method": hit_lines_in_method,
            }
    return None


def _filter_overloads_for_primary(primary: Dict[str, Any],
                                  overloads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not overloads:
        return []
    primary_class = str(primary.get("class_path") or "").strip()
    if not primary_class:
        return overloads
    same_class = [
        cand for cand in overloads
        if str(cand.get("class_path") or "").strip() == primary_class
    ]
    return same_class if same_class else overloads


def _collect_secondary_methods(lines: List[str],
                               primary: Dict[str, Any],
                               methods_by_name: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    secondary_methods: List[Dict[str, Any]] = []
    sig_norm = normalize_signature(primary.get("signature"))
    hit_lines = primary.get("hit_lines_in_method", [])
    seen_keys = set()
    for rel_line in hit_lines:
        abs_line = primary["start_line"] + rel_line - 1
        if abs_line < 1 or abs_line > len(lines):
            continue
        line_content = lines[abs_line - 1]
        for call_name in parse_call_names(line_content):
            overloads = methods_by_name.get(call_name, [])
            overloads = _filter_overloads_for_primary(primary, overloads)
            if not overloads:
                continue
            args_str = extract_call_args(line_content, call_name)
            arg_count = top_level_arg_count(args_str)
            selected = []
            if arg_count is not None:
                for cand in overloads:
                    param_count = _param_count_from_method(cand)
                    if param_count is not None and param_count == arg_count:
                        selected.append(cand)
            if not selected:
                selected = overloads
            for cand in selected:
                if cand.get("name") == primary.get("name"):
                    cand_sig = normalize_signature(cand.get("signature"))
                    if sig_norm and cand_sig and cand_sig == sig_norm:
                        continue
                    if not sig_norm and cand.get("code") == primary.get("code"):
                        continue
                entry = {
                    "method_name": cand.get("name"),
                    "called_at_line_number": abs_line,
                    "called_at_line_content": line_content,
                    "method_content": cand.get("code", ""),
                }
                cand_sig = cand.get("signature") or ""
                if cand_sig:
                    entry["method_signature"] = cand_sig
                    param_count = _param_count_from_method(cand)
                    if param_count is not None:
                        entry["param_count"] = param_count
                key = (entry["method_name"], entry.get("method_signature", ""), abs_line)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                secondary_methods.append(entry)
    return secondary_methods


def pick_methods_with_hits(lines: List[str], methods: List[Dict[str, Any]], hits: List[int]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for h in sorted(set(hits)):
        cands = [m for m in methods if m["start_line"] <= h <= m["end_line"]]
        if not cands:
            continue
        m = min(cands, key=lambda x: (x["end_line"]-x["start_line"], x["start_line"]))
        rec = next((e for e in out if e["name"]==m["name"] and e["start_line"]==m["start_line"]), None)
        rel_line = max(1, h - m["start_line"] + 1)
        if not rec:
            out.append({**m, "hit_lines_in_method":[rel_line]})
        elif rel_line not in rec["hit_lines_in_method"]:
            rec["hit_lines_in_method"].append(rel_line)
    for e in out:
        e["hit_lines_in_method"].sort()
    return out


def _process_file(processed: str, path_str: str, hits: List[int]) -> List[Dict[str, Any]]:
    path = Path(path_str)
    lines = read_lines(path)
    methods = find_methods(lines, source_path=path)
    sel = pick_methods_with_hits(lines, methods, hits)
    results = []
    methods_by_name = _build_methods_by_name(methods)
    for m in sel:
        secondary_methods = _collect_secondary_methods(lines, m, methods_by_name)
        results.append({
            "file_name": processed,
            "language": detect_language_from_path(path),
            "name": m["name"],
            "kind": m["kind"],
            "signature": m["signature"],
            "class_path": m.get("class_path", "Global"),
            "start_line": m["start_line"],
            "end_line": m["end_line"],
            "hit_lines_in_method": m["hit_lines_in_method"],
            "code": m["code"],
            "secondary_methods": secondary_methods,
        })
    return results


# NOTE: the SpotBugs-style learning collector `collect_examples_for_bug(csv_path, ...)`
# was REMOVED in this version (paper/CWE workflow no longer uses it). The full function,
# and the `--flow`/`--tool` flags that drove it, are preserved in
# preprocessing_agent_lite_spotbugs_backup.py (see that file's header).


def _resolve_manifest_metadata_path(row: Dict[str, str], agents_dir: Path) -> Optional[Path]:
    metadata_path = str(row.get("metadata_path") or "").strip()
    if metadata_path:
        candidate = Path(metadata_path)
        if candidate.is_file():
            return candidate
    search_dirs: List[Path] = []
    result_dir = str(row.get("result_dir") or "").strip()
    if result_dir:
        search_dirs.append(Path(result_dir))
    snippet_abs_path = str(row.get("snippet_abs_path") or "").strip()
    if snippet_abs_path:
        search_dirs.append(Path(snippet_abs_path).parent)
    for directory in search_dirs:
        if not directory.is_dir():
            continue
        candidates = sorted(directory.glob("data_*.json"))
        if len(candidates) == 1 and candidates[0].is_file():
            return candidates[0]
    return None


def _resolve_source_from_metadata(row: Dict[str, str], agents_dir: Path) -> Optional[Path]:
    meta_path = _resolve_manifest_metadata_path(row, agents_dir)
    if meta_path is None:
        return None
    try:
        entry = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    file_name = str(
        entry.get("file_name")
        or entry.get("source_file")
        or entry.get("snippet_file")
        or ""
    ).strip()
    if not file_name:
        return None
    candidate = meta_path.parent / file_name
    return candidate if candidate.is_file() else None


def _extract_labeled_buggy_lines(metadata: Dict[str, Any]) -> List[List[Any]]:
    """Flatten metadata.tool_scan_list[*].line_content into [[line, code], ...].

    tool_scan_list entries each carry a JSON-string `line_content` of the form
    `[[line, "code"], ...]` listing SecVulEval-labelled buggy statements. We
    flatten to a single ordered list so the LLM can use it as ground truth.
    """
    tsl = metadata.get("tool_scan_list") if isinstance(metadata, dict) else None
    if not isinstance(tsl, list):
        return []
    out: List[List[Any]] = []
    seen: set = set()
    for entry in tsl:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("line_content")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                raw = []
        if not isinstance(raw, list):
            continue
        for item in raw:
            if isinstance(item, list) and len(item) >= 2:
                try:
                    ln = int(item[0])
                except Exception:
                    continue
                code = str(item[1] or "").strip()
                key = (ln, code)
                if key not in seen:
                    seen.add(key)
                    out.append([ln, code])
    return out


def load_paper_metadata(row: Dict[str, str], agents_dir: Path) -> Dict[str, Any]:
    meta_path = _resolve_manifest_metadata_path(row, agents_dir)
    if meta_path is None:
        return {}
    try:
        payload = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _metadata_target_method(row: Dict[str, str], metadata: Dict[str, Any]) -> str:
    return normalize_method_token(
        metadata.get("func_name")
        or metadata.get("procedure")
        or metadata.get("target_method")
        or row.get("procedure")
        or row.get("target_method")
    )


def _normalize_alignment_line(line: str) -> str:
    text = strip_line_comment(line or "")
    text = re.sub(r"/\*.*?\*/", " ", text)
    return re.sub(r"\s+", " ", text.strip())


def _is_executable_method_line(line: str) -> bool:
    text = _normalize_alignment_line(line)
    if not text:
        return False
    if text in {"{", "}", "};"}:
        return False
    if text.startswith(("@", "#")):
        return False
    if re.match(r"^(class|struct|enum|interface)\b", text):
        return False
    if (
        "(" in text
        and text.endswith("{")
        and not CONTROL_HEADER_RE.match(text)
        and not re.match(r"^(else\b|do\b|try\b|finally\b|synchronized\b)", text)
    ):
        return False
    return True


def _ordered_indices(center: int, start: int, stop: int) -> List[int]:
    if start >= stop:
        return []
    center = max(start, min(center, stop - 1))
    ordered = [center]
    left = center - 1
    right = center + 1
    while left >= start or right < stop:
        if left >= start:
            ordered.append(left)
            left -= 1
        if right < stop:
            ordered.append(right)
            right += 1
    return ordered


def _pick_executable_line_index(lines: List[str],
                                preferred_idx: Optional[int],
                                preferred_range: Optional[Tuple[int, int]] = None) -> Optional[int]:
    if not lines:
        return None
    center = preferred_idx if preferred_idx is not None else 0
    if preferred_range is not None:
        start, stop = preferred_range
        for idx in _ordered_indices(center, max(0, start), min(len(lines), stop)):
            if _is_executable_method_line(lines[idx]):
                return idx
    for idx in _ordered_indices(center, 0, len(lines)):
        if _is_executable_method_line(lines[idx]):
            return idx
    return None


def _align_buggy_line_to_fixed(buggy_lines: List[str],
                               fixed_lines: List[str],
                               buggy_idx: int) -> Tuple[Optional[int], Optional[Tuple[int, int]]]:
    matcher = difflib.SequenceMatcher(
        a=[_normalize_alignment_line(line) for line in buggy_lines],
        b=[_normalize_alignment_line(line) for line in fixed_lines],
        autojunk=False,
    )
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if i1 <= buggy_idx < i2:
            if tag == "equal":
                return j1 + (buggy_idx - i1), (j1, j2)
            if tag == "replace":
                if j1 < j2:
                    local = min(buggy_idx - i1, j2 - j1 - 1)
                    return j1 + local, (j1, j2)
                return j1, None
            if tag == "delete":
                return j1, None
    if fixed_lines:
        return min(buggy_idx, len(fixed_lines) - 1), None
    return None, None


def _derive_fixed_target_lines(buggy_method: Dict[str, Any],
                               fixed_method: Dict[str, Any],
                               buggy_target_lines: Optional[List[int]] = None) -> List[int]:
    buggy_start = int(buggy_method.get("start_line") or 1)
    buggy_end = int(buggy_method.get("end_line") or buggy_start)
    fixed_start = int(fixed_method.get("start_line") or 1)
    candidate_buggy_targets = list(buggy_target_lines or buggy_method.get("combined_target_lines") or buggy_method.get("manifest_target_lines") or [])
    buggy_targets = [
        int(line) for line in candidate_buggy_targets
        if buggy_start <= int(line) <= buggy_end
    ]
    if not buggy_targets:
        return []

    buggy_lines = str(buggy_method.get("code") or "").splitlines()
    fixed_lines = str(fixed_method.get("code") or "").splitlines()
    if not buggy_lines or not fixed_lines:
        return []

    mapped_fixed: List[int] = []
    for buggy_target in buggy_targets:
        buggy_idx = buggy_target - buggy_start
        if buggy_idx < 0 or buggy_idx >= len(buggy_lines):
            continue
        mapped_idx, mapped_range = _align_buggy_line_to_fixed(buggy_lines, fixed_lines, buggy_idx)
        fixed_idx = _pick_executable_line_index(fixed_lines, mapped_idx, mapped_range)
        if fixed_idx is not None:
            mapped_fixed.append(fixed_start + fixed_idx)
    return sorted(set(mapped_fixed))


def _method_abs_lines(method_entry: Dict[str, Any], abs_lines: List[int]) -> List[int]:
    start_line = int(method_entry.get("start_line") or 1)
    end_line = int(method_entry.get("end_line") or start_line)
    return sorted({int(ln) for ln in abs_lines if start_line <= int(ln) <= end_line})


def _method_rel_lines(method_entry: Dict[str, Any], abs_lines: List[int]) -> List[int]:
    start_line = int(method_entry.get("start_line") or 1)
    return [int(ln) - start_line + 1 for ln in abs_lines]


def _line_context(source_path: Path, abs_lines: List[int], limit: int = 12) -> List[Dict[str, Any]]:
    file_lines = read_lines(source_path)
    context: List[Dict[str, Any]] = []
    for line_no in abs_lines[:limit]:
        if 1 <= int(line_no) <= len(file_lines):
            stmt = file_lines[int(line_no) - 1].strip()
            if stmt:
                context.append({"line": int(line_no), "code": stmt})
    return context


def _executable_abs_lines(source_path: Path,
                          method_entry: Dict[str, Any],
                          abs_lines: List[int]) -> List[int]:
    start_line = int(method_entry.get("start_line") or 1)
    end_line = int(method_entry.get("end_line") or start_line)
    file_lines = read_lines(source_path)
    in_method = []
    executable = []
    for line_no in sorted({int(ln) for ln in abs_lines if start_line <= int(ln) <= end_line}):
        in_method.append(line_no)
        idx = line_no - 1
        if 0 <= idx < len(file_lines) and _is_executable_method_line(file_lines[idx]):
            executable.append(line_no)
    return executable or in_method


def _compress_target_lines(lines: List[int],
                           preferred_lines: Optional[List[int]] = None,
                           max_total: int = 12) -> List[int]:
    ordered = sorted({int(ln) for ln in lines})
    if not ordered:
        return []
    preferred = [int(ln) for ln in (preferred_lines or []) if int(ln) in set(ordered)]
    selected: List[int] = []
    for line_no in preferred:
        if line_no not in selected:
            selected.append(line_no)
    runs: List[List[int]] = []
    current_run: List[int] = []
    for line_no in ordered:
        if not current_run or line_no == current_run[-1] + 1:
            current_run.append(line_no)
        else:
            runs.append(current_run)
            current_run = [line_no]
    if current_run:
        runs.append(current_run)
    for run in runs:
        candidates = run if len(run) <= 2 else [run[0], run[len(run) // 2], run[-1]]
        for line_no in candidates:
            if line_no not in selected:
                selected.append(line_no)
            if len(selected) >= max_total:
                return sorted(selected[:max_total])
    return sorted(selected[:max_total])


def _manifest_target_lines(row: Dict[str, str], line_col: Optional[str]) -> List[int]:
    if line_col:
        lines = parse_lines_field(row.get(line_col, "") or "")
        if lines:
            return lines
    for key in ("line", "line_numbers", "lines"):
        value = row.get(key)
        if value:
            lines = parse_lines_field(str(value))
            if lines:
                return lines
    return []


def _metadata_target_lines(row: Dict[str, str], metadata: Dict[str, Any], line_col: Optional[str]) -> List[int]:
    hits = parse_changed_lines(metadata.get("changed_lines"))
    if hits:
        return hits
    for key in ("line_numbers", "lines"):
        value = metadata.get(key)
        if isinstance(value, list):
            out: List[int] = []
            for item in value:
                try:
                    out.append(int(item))
                except Exception:
                    continue
            if out:
                return out
    if line_col:
        return parse_lines_field(row.get(line_col, "") or "")
    return []


def resolve_paper_source_path(row: Dict[str, str], agents_dir: Path) -> Optional[Path]:
    metadata_source = _resolve_source_from_metadata(row, agents_dir)
    if metadata_source is not None:
        return metadata_source
    snippet_abs_path = str(row.get("snippet_abs_path") or "").strip()
    if snippet_abs_path:
        candidate = Path(snippet_abs_path)
        if candidate.is_file():
            return candidate
    return None


def _process_paper_row(row: Dict[str, str], bug_rule: str, line_col: Optional[str],
                       source_path: Path, metadata: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    lines = read_lines(source_path)
    metadata = metadata or {}
    hits = _metadata_target_lines(row, metadata, line_col)
    manifest_lines = _manifest_target_lines(row, line_col)
    target_method = _metadata_target_method(row, metadata)
    direct_method = _extract_enclosing_method_from_hits(lines, target_method, hits)
    if direct_method is None:
        direct_method = _extract_named_method_direct(lines, target_method, hits)
    methods = find_methods(lines, source_path=source_path)
    if direct_method:
        methods = [direct_method] + [
            m for m in methods
            if not (
                normalize_method_token(m.get("name")) == normalize_method_token(direct_method.get("name"))
                and int(m.get("start_line", 0) or 0) == int(direct_method.get("start_line", 0) or 0)
            )
        ]
    if not methods:
        return []
    if target_method:
        named_methods = [m for m in methods if normalize_method_token(m.get("name")) == target_method]
        if named_methods:
            methods = named_methods
    if direct_method is not None:
        selected = [direct_method]
    elif hits:
        selected = pick_methods_with_hits(lines, methods, hits)
        if not selected:
            selected = methods[:1]
    else:
        selected = methods[:1]
    results = []
    methods_by_name = _build_methods_by_name(methods)
    for m in selected:
        secondary_methods = _collect_secondary_methods(lines, m, methods_by_name)
        results.append({
            "file_name": source_path.name,
            "name": m["name"],
            "kind": m["kind"],
            "signature": m["signature"],
            "class_path": m.get("class_path", "Global"),
            "start_line": m["start_line"],
            "end_line": m["end_line"],
            "hit_lines_in_method": m.get("hit_lines_in_method", []),
            "manifest_target_lines": manifest_lines,
            "code": m["code"],
            "language": detect_language_from_path(source_path),
            "secondary_methods": secondary_methods,
            "commit_message": str(metadata.get("commit_message") or ""),
            "failure_description": str(row.get("failure_description") or ""),
            "buggy_explanation": str(row.get("buggy_explanation") or ""),
            "category": str(row.get("category") or "decision_fn"),
            "labeled_buggy_lines": _extract_labeled_buggy_lines(metadata),
        })
    return results


def _variant_source_path(metadata: Dict[str, Any], source_path: Path, variant: str) -> Optional[Path]:
    file_name = str(metadata.get(f"{variant}_file_name") or "").strip()
    if not file_name:
        return None
    candidate = source_path.parent / file_name
    return candidate if candidate.is_file() else None


def _fallback_method_from_metadata_snippet(metadata: Dict[str, Any],
                                           variant: str,
                                           target_method: str,
                                           hits: List[int],
                                           fallback_name: str) -> Optional[Dict[str, Any]]:
    snippet = str(
        metadata.get(f"{variant}_func_body")
        or metadata.get("func_body")
        or ""
    )
    if not snippet.strip():
        return None
    lines = snippet.splitlines()
    direct_method = _extract_enclosing_method_from_hits(lines, target_method, hits)
    if direct_method is None:
        direct_method = _extract_named_method_direct(lines, target_method, hits)
    methods = find_methods(lines, source_path=None)
    if direct_method is None and target_method:
        named_methods = [m for m in methods if normalize_method_token(m.get("name")) == target_method]
        if named_methods:
            direct_method = named_methods[0]
    if direct_method is None and methods:
        direct_method = methods[0]
    if direct_method is None:
        return None
    return {
        "file_name": fallback_name,
        "name": direct_method["name"],
        "kind": direct_method["kind"],
        "signature": direct_method["signature"],
        "class_path": direct_method.get("class_path", "Global"),
        "start_line": direct_method["start_line"],
        "end_line": direct_method["end_line"],
        "hit_lines_in_method": direct_method.get("hit_lines_in_method", []),
        "code": direct_method["code"],
        "language": metadata.get("language") or "c",
        "secondary_methods": [],
    }


def _load_partner_metadata(metadata: Dict[str, Any], variant: str) -> Dict[str, Any]:
    result_dir = Path(str(metadata.get("result_dir") or "")).expanduser()
    partner_paper_idx = metadata.get(f"{variant}_paper_idx")
    if not result_dir.is_dir() or partner_paper_idx in (None, ""):
        return {}
    try:
        partner_idx = int(partner_paper_idx)
    except Exception:
        return {}
    partner_meta = result_dir.parent / f"result_Paper_{partner_idx}" / f"data_Paper_{partner_idx}.json"
    if not partner_meta.is_file():
        return {}
    try:
        payload = json.loads(partner_meta.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _diff_changed_lines(buggy_path: Path, fixed_path: Path) -> Tuple[List[int], List[int]]:
    """Return (buggy_changed_abs_lines, fixed_changed_abs_lines) by diffing the
    two source files with difflib. Used as a fallback when upstream metadata's
    changed_lines is empty/malformed.
    """
    buggy_lines = read_lines(buggy_path)
    fixed_lines = read_lines(fixed_path)
    matcher = difflib.SequenceMatcher(a=buggy_lines, b=fixed_lines, autojunk=False)
    buggy_changed: List[int] = []
    fixed_changed: List[int] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        # Replace/delete: lines actually present in buggy. Insert: bug locus is
        # the buggy line immediately following the would-be insertion point
        # (the statement that should have been guarded by what the fix adds).
        if i2 > i1:
            buggy_changed.extend(range(i1 + 1, i2 + 1))
        elif buggy_lines:
            buggy_changed.append(min(max(1, i1 + 1), len(buggy_lines)))
        # Symmetric handling for fixed side.
        if j2 > j1:
            fixed_changed.extend(range(j1 + 1, j2 + 1))
        elif fixed_lines:
            fixed_changed.append(min(max(1, j1 + 1), len(fixed_lines)))
    return buggy_changed, fixed_changed


def _annotate_training_targets(buggy_method: Dict[str, Any],
                               fixed_method: Dict[str, Any],
                               buggy_path: Path,
                               fixed_path: Path) -> None:
    """Attach labelled manifest/diff/combined/slice target lines to both sides.

    The goal is to preserve the full supervision signal for KB training:
    - manifest lines are weak location hints from the benchmark
    - diff lines are stronger evidence of what changed between buggy/fixed
    - slice_target_lines is the compressed executable subset used for slicing
    """
    buggy_diff_abs, fixed_diff_abs = _diff_changed_lines(buggy_path, fixed_path)

    buggy_manifest_abs = _method_abs_lines(
        buggy_method,
        list(buggy_method.get("manifest_target_lines") or []),
    )
    buggy_diff_abs = _method_abs_lines(buggy_method, buggy_diff_abs)
    buggy_combined_abs = sorted(set(buggy_manifest_abs) | set(buggy_diff_abs))
    buggy_executable_abs = _executable_abs_lines(buggy_path, buggy_method, buggy_combined_abs)
    buggy_slice_targets = _compress_target_lines(
        buggy_executable_abs,
        preferred_lines=buggy_manifest_abs + buggy_diff_abs,
    )

    fixed_manifest_abs = _derive_fixed_target_lines(
        buggy_method,
        fixed_method,
        buggy_target_lines=buggy_manifest_abs,
    )
    fixed_manifest_abs = _method_abs_lines(fixed_method, fixed_manifest_abs)
    fixed_diff_abs = _method_abs_lines(fixed_method, fixed_diff_abs)
    fixed_combined_abs = sorted(set(fixed_manifest_abs) | set(fixed_diff_abs))
    fixed_executable_abs = _executable_abs_lines(fixed_path, fixed_method, fixed_combined_abs)
    fixed_slice_targets = _compress_target_lines(
        fixed_executable_abs,
        preferred_lines=fixed_manifest_abs + fixed_diff_abs,
    )

    def _apply(method: Dict[str, Any],
               source_path: Path,
               manifest_abs: List[int],
               diff_abs: List[int],
               combined_abs: List[int],
               slice_targets: List[int]) -> None:
        original_hits = list(method.get("hit_lines_in_method") or [])
        method["metadata_hit_lines_in_method"] = original_hits
        method["manifest_target_lines"] = manifest_abs
        method["diff_target_lines"] = diff_abs
        method["combined_target_lines"] = combined_abs
        method["slice_target_lines"] = slice_targets or combined_abs
        method["manifest_target_context"] = _line_context(source_path, manifest_abs)
        method["diff_target_context"] = _line_context(source_path, diff_abs)
        method["slice_target_context"] = _line_context(source_path, method["slice_target_lines"])
        if method["slice_target_lines"]:
            method["hit_lines_in_method"] = _method_rel_lines(method, method["slice_target_lines"])
        elif combined_abs:
            method["hit_lines_in_method"] = _method_rel_lines(method, combined_abs)

    _apply(
        buggy_method,
        buggy_path,
        buggy_manifest_abs,
        buggy_diff_abs,
        buggy_combined_abs,
        buggy_slice_targets,
    )
    _apply(
        fixed_method,
        fixed_path,
        fixed_manifest_abs,
        fixed_diff_abs,
        fixed_combined_abs,
        fixed_slice_targets,
    )


def _collect_criterion_lines(method_entry: Dict[str, Any]) -> Tuple[int, int, List[int]]:
    start_line = int(method_entry.get("start_line") or 1)
    end_line = int(method_entry.get("end_line") or start_line)
    hit_rels = list(method_entry.get("hit_lines_in_method") or [])
    manifest_lines = list(method_entry.get("manifest_target_lines") or [])
    diff_lines = list(method_entry.get("diff_target_lines") or [])
    combined_lines = list(method_entry.get("combined_target_lines") or [])
    slice_target_lines = list(method_entry.get("slice_target_lines") or [])

    criterion_set = {
        int(ln) for ln in slice_target_lines
        if start_line <= int(ln) <= end_line
    }
    if not criterion_set:
        criterion_set = {
            int(ln) for ln in combined_lines
            if start_line <= int(ln) <= end_line
        }
    if not criterion_set:
        criterion_set = {int(ln) for ln in manifest_lines if start_line <= int(ln) <= end_line}
    criterion_set.update(int(ln) for ln in diff_lines if start_line <= int(ln) <= end_line)
    for rel in hit_rels:
        abs_line = start_line + int(rel) - 1
        if start_line <= abs_line <= end_line:
            criterion_set.add(abs_line)
    criterion_lines = sorted(criterion_set)

    return start_line, end_line, criterion_lines


def _build_method_slice(source_path: Path,
                        method_entry: Dict[str, Any],
                        slice_cache: Dict[Tuple[str, str, str, str], Dict[str, Any]],
                        direction: str = "backward",
                        joern_widen: int = 0) -> Dict[str, Any]:
    """Slice the criterion line(s) of *method_entry* in *source_path*.

    `direction=backward` captures data/control dependencies influencing the
    vulnerable location. `direction=forward` captures how the vulnerable state
    or control decision propagates after that location.

    `joern_widen` (default 0 = disabled) is forwarded to the Joern slice
    script as an opt-in fallback radius for cases where the exact seed line
    has no CFG node attached (see slice.sc docs). When > 0 the radius is
    included in the cache key so a prior widen=0 empty result does not
    shadow a widen>0 retry.
    """
    from agents.libs.drivers import get as get_driver

    language = detect_language_from_path(source_path)
    start_line, end_line, criterion_lines = _collect_criterion_lines(method_entry)

    method_span = max(1, end_line - start_line + 1)
    if not criterion_lines or len(criterion_lines) >= 0.8 * method_span:
        return {
            "tool": "joern",
            "status": "error",
            "language": language,
            "direction": direction,
            "criterion": {"lines": criterion_lines, "var": ""},
            "message": (
                "no usable slicing criterion: empty hit lines"
                if not criterion_lines
                else f"degenerate criterion: {len(criterion_lines)}/{method_span} lines flagged"
            ),
        }

    widen_tag = f"w{int(joern_widen)}" if int(joern_widen) > 0 else ""
    cache_key = (str(source_path), direction, ",".join(str(x) for x in criterion_lines), widen_tag)
    slice_result = slice_cache.get(cache_key)
    if slice_result is None:
        mode = "forward_slice" if direction == "forward" else "slice"
        slice_result = get_driver("joern").analyze(
            source_path, mode, lines=criterion_lines, var_name="",
            scanned_file=source_path.name, widen=int(joern_widen),
        )
        slice_cache[cache_key] = slice_result

    result: Dict[str, Any] = {
        "tool": slice_result.get("tool"),
        "status": slice_result.get("status"),
        "language": language,
        "direction": direction,
        "criterion": slice_result.get("criterion") or {"lines": criterion_lines, "var": ""},
    }
    if slice_result.get("status") != "ok":
        result["message"] = slice_result.get("message", "slice failed")
        return result

    slice_lines = slice_result.get("slice_lines") or []
    if not slice_lines:
        result["status"] = "error"
        result["message"] = f"empty slice at lines {criterion_lines}"
        return result

    result["slice_lines"] = slice_lines
    result["slice_stmts"] = slice_result.get("slice_stmts") or []
    result["slice_code"] = slice_result.get("slice_code") or ""
    result["seed_count"] = slice_result.get("seed_count", 0)
    return result


def _build_linear_slice_cfg(source_path: Path,
                            slice_lines: List[int],
                            language: str) -> Dict[str, Any]:
    file_lines = read_source_lines(source_path)
    unique_lines = sorted({int(ln) for ln in slice_lines if int(ln) > 0})
    nodes: List[Dict[str, Any]] = []
    for idx, ln in enumerate(unique_lines, 1):
        stmt = file_lines[ln - 1].strip() if 1 <= ln <= len(file_lines) else ""
        if not stmt:
            continue
        nodes.append({"id": idx, "line": ln, "stmt": stmt, "successors": []})
    for idx in range(len(nodes) - 1):
        nodes[idx]["successors"] = [nodes[idx + 1]["id"]]
    edges = [[node["id"], succ] for node in nodes for succ in node.get("successors", [])]
    return {
        "tool": "heuristic",
        "status": "ok",
        "language": language,
        "scope": "slice",
        "nodes": nodes,
        "edges": edges,
        "slice_lines": [node["line"] for node in nodes],
    }


def _select_cfg_method(cfg_result: Dict[str, Any],
                       method_entry: Dict[str, Any]) -> Dict[str, Any] | None:
    target_name = str(method_entry.get("name") or "").strip()
    target_start = int(method_entry.get("start_line") or 1)
    target_end = int(method_entry.get("end_line") or target_start)
    methods: List[Dict[str, Any]] = []
    for cls in cfg_result.get("classes") or []:
        for method in cls.get("methods") or []:
            if isinstance(method, dict):
                methods.append(method)
    for method in methods:
        if (
            str(method.get("name") or "").strip() == target_name
            and int(method.get("start_line") or -1) == target_start
        ):
            return method
    for method in methods:
        if (
            str(method.get("name") or "").strip() == target_name
            and target_start <= int(method.get("start_line") or target_start) <= target_end
        ):
            return method
    for method in methods:
        if str(method.get("name") or "").strip() == target_name:
            return method
    return None


def _build_slice_cfg(source_path: Path,
                     method_entry: Dict[str, Any],
                     slice_lines: List[int],
                     cfg_cache: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    language = detect_language_from_path(source_path)
    if not slice_lines:
        return {
            "tool": "heuristic",
            "status": "error",
            "language": language,
            "scope": "slice",
            "message": "no slice lines for cfg extraction",
        }

    if language != "c":
        return _build_linear_slice_cfg(source_path, slice_lines, language)

    from agents.libs.drivers import get as get_driver

    cache_key = str(source_path)
    cfg_result = cfg_cache.get(cache_key)
    if cfg_result is None:
        cfg_result = get_driver("joern").analyze(source_path, "cfg", scanned_file=source_path.name)
        cfg_cache[cache_key] = cfg_result

    method_cfg = _select_cfg_method(cfg_result or {}, method_entry)
    cfg_nodes = (method_cfg or {}).get("cfg") or []
    if not isinstance(cfg_nodes, list) or not cfg_nodes:
        return _build_linear_slice_cfg(source_path, slice_lines, language)

    slice_line_set = {int(ln) for ln in slice_lines if int(ln) > 0}
    selected: List[Dict[str, Any]] = []
    id_map: Dict[Any, Any] = {}
    for idx, node in enumerate(cfg_nodes):
        if not isinstance(node, dict):
            continue
        line = node.get("line")
        if line is None or int(line) not in slice_line_set:
            continue
        node_id = node.get("id", idx)
        normalized = {
            "id": node_id,
            "line": int(line),
            "stmt": str(node.get("stmt") or "").strip(),
            "successors": [],
        }
        selected.append(normalized)
        id_map[node_id] = normalized

    if not selected:
        return _build_linear_slice_cfg(source_path, slice_lines, language)

    edges: List[List[Any]] = []
    for idx, node in enumerate(cfg_nodes):
        if not isinstance(node, dict):
            continue
        node_id = node.get("id", idx)
        current = id_map.get(node_id)
        if current is None:
            continue
        succs = []
        for succ in node.get("successors") or []:
            if succ in id_map:
                succs.append(succ)
                edges.append([node_id, succ])
        current["successors"] = succs

    return {
        "tool": cfg_result.get("tool", "joern"),
        "status": "ok",
        "language": language,
        "scope": "slice",
        "nodes": selected,
        "edges": edges,
        "slice_lines": sorted(slice_line_set),
    }


def collect_examples_for_bug_paper_diff(rows: List[Dict[str, str]], bug_rule: str,
                                        line_col: Optional[str], agents_dir: Path,
                                        limit: Optional[int]) -> List[Dict[str, Any]]:
    examples: List[Dict[str, Any]] = []
    for idx, row in enumerate(rows, 1):
        if (row.get("bug_type") or row.get("bug-rule") or row.get("bug rule") or "").strip() != bug_rule:
            continue
        metadata = load_paper_metadata(row, agents_dir)
        if not metadata or not bool(metadata.get("is_vulnerable")):
            continue
        metadata_bug_rule = str(metadata.get("bug_rule") or "").strip()
        if metadata_bug_rule and metadata_bug_rule != bug_rule:
            continue
        canonical_source = resolve_paper_source_path(row, agents_dir)
        if not canonical_source:
            print(f"[WARN] Missing or unreadable source for row {row.get('_source_row') or idx}")
            continue
        buggy_path = _variant_source_path(metadata, canonical_source, "buggy") or canonical_source
        fixed_path = _variant_source_path(metadata, canonical_source, "fixed")
        if fixed_path is None:
            print(f"[WARN] Missing fixed variant for row {row.get('_source_row') or idx}")
            continue
        fixed_metadata = _load_partner_metadata(metadata, "fixed") or metadata

        buggy_methods = _process_paper_row(row, bug_rule, line_col, buggy_path, metadata=metadata)
        fixed_methods = _process_paper_row(row, bug_rule, line_col, fixed_path, metadata=fixed_metadata)
        target_method = _metadata_target_method(row, metadata)
        buggy_name = normalize_method_token(buggy_methods[0].get("name")) if buggy_methods else ""
        fixed_name = normalize_method_token(fixed_methods[0].get("name")) if fixed_methods else ""
        if target_method and buggy_name != target_method:
            buggy_fallback = _fallback_method_from_metadata_snippet(
                metadata,
                "buggy",
                target_method,
                _metadata_target_lines(row, metadata, line_col),
                buggy_path.name,
            )
            if buggy_fallback is not None:
                buggy_methods = [buggy_fallback]
                buggy_name = normalize_method_token(buggy_fallback.get("name"))
        if target_method and fixed_name != target_method:
            fixed_fallback = _fallback_method_from_metadata_snippet(
                fixed_metadata,
                "fixed",
                target_method,
                _metadata_target_lines(row, fixed_metadata, line_col),
                fixed_path.name,
            )
            if fixed_fallback is not None:
                fixed_methods = [fixed_fallback]
                fixed_name = normalize_method_token(fixed_fallback.get("name"))
        if not buggy_methods or not fixed_methods:
            print(f"[WARN] Missing buggy/fixed method pair for row {row.get('_source_row') or idx}")
            continue

        buggy_method = buggy_methods[0]
        fixed_method = fixed_methods[0]
        manifest_lines = _manifest_target_lines(row, line_col)
        buggy_method["manifest_target_lines"] = manifest_lines
        fixed_method["manifest_target_lines"] = _derive_fixed_target_lines(
            buggy_method, fixed_method, buggy_target_lines=manifest_lines
        )
        _annotate_training_targets(buggy_method, fixed_method, buggy_path, fixed_path)
        examples.append({
            "file_name": buggy_path.name,
            "language": buggy_method.get("language") or detect_language_from_path(buggy_path),
            "name": buggy_method.get("name"),
            "kind": buggy_method.get("kind"),
            "signature": buggy_method.get("signature"),
            "class_path": buggy_method.get("class_path", "Global"),
            "start_line": buggy_method.get("start_line"),
            "end_line": buggy_method.get("end_line"),
            "hit_lines_in_method": buggy_method.get("hit_lines_in_method", []),
            "code": buggy_method.get("code", ""),
            "secondary_methods": buggy_method.get("secondary_methods", []),
            "buggy_method": buggy_method,
            "fixed_method": fixed_method,
            "buggy_manifest_target_lines": list(buggy_method.get("manifest_target_lines") or []),
            "buggy_diff_target_lines": list(buggy_method.get("diff_target_lines") or []),
            "buggy_slice_target_lines": list(buggy_method.get("slice_target_lines") or []),
            "fixed_manifest_target_lines": list(fixed_method.get("manifest_target_lines") or []),
            "fixed_diff_target_lines": list(fixed_method.get("diff_target_lines") or []),
            "fixed_slice_target_lines": list(fixed_method.get("slice_target_lines") or []),
            "metadata_path": str(_resolve_manifest_metadata_path(row, agents_dir) or ""),
            "source_row": row.get("_source_row") or idx,
            "commit_message": str(metadata.get("commit_message") or ""),
            "failure_description": str(row.get("failure_description") or ""),
            "buggy_explanation": str(row.get("buggy_explanation") or ""),
            "category": str(row.get("category") or "decision_fn"),
            "labeled_buggy_lines": _extract_labeled_buggy_lines(metadata),
        })
        if limit is not None and len(examples) >= limit:
            return examples
    return examples


def collect_examples_for_bug_paper(rows: List[Dict[str, str]], bug_rule: str,
                                   line_col: Optional[str], agents_dir: Path,
                                   limit: Optional[int]) -> List[Dict[str, Any]]:
    examples: List[Dict[str, Any]] = []
    for idx, row in enumerate(rows, 1):
        if (row.get("bug_type") or row.get("bug-rule") or row.get("bug rule") or "").strip() != bug_rule:
            continue
        source_row = row.get("_source_row") or idx
        metadata = load_paper_metadata(row, agents_dir)
        metadata_bug_rule = str(metadata.get("bug_rule") or "").strip()
        if metadata_bug_rule and metadata_bug_rule != bug_rule:
            continue
        source_path = resolve_paper_source_path(row, agents_dir)
        if not source_path:
            print(f"[WARN] Missing or unreadable source for row {source_row}")
            continue
        res = _process_paper_row(row, bug_rule, line_col, source_path, metadata=metadata)
        if not res:
            print(f"[WARN] No methods found in source for row {source_row} (path={source_path})")
        for m in res:
            examples.append(m)
            if limit is not None and len(examples) >= limit:
                return examples
    return examples


# ------------- LLM selection -------------
def build_system_prompt(bug_rule: str) -> str:
    return (
        "You are selecting a diverse set of confirmed-positive source methods for a bug rule.\n"
        f"Bug rule: {bug_rule}\n\n"
        "Two methods are near-duplicates if they have almost identical control flow, "
        "usage, and null-handling, differing only in trivial details like variable names or formatting.\n\n"
        "Be LENIENT:\n"
        "- ACCEPT the candidate if it shows any notable difference in structure, control flow, usage, or where/how the bug condition is introduced and triggered.\n"
        "- REJECT only if the candidate is clearly redundant with ALL selected examples (near-duplicate).\n"
        "- If unsure, you MUST accept.\n\n"
        "Return ONLY a JSON object like:\n"
        "{ \"accept\": true or false, \"reason\": \"<very short>\" }"
    )


def build_user_prompt(candidate: Dict[str, Any], selected: List[Dict[str, Any]]) -> str:
    sel_list = []
    for ex in selected:
        sel_list.append({
            "file_name": ex.get("file_name",""),
            "signature": ex.get("signature",""),
            "snippet": ex.get("code","")[:300]
        })
    payload = {
        "selected_examples": sel_list if sel_list else "None yet",
        "candidate": {
            "file_name": candidate.get("file_name",""),
            "signature": candidate.get("signature",""),
            "snippet": candidate.get("code","")[:800]
        }
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def judge_candidate(model_cfg: Dict[str, Any], pipe: Any,
                    bug_rule: str, idx: int,
                    system_prompt: str, user_prompt: str,
                    candidate: Dict[str, Any]) -> bool:
    print(f"\n[LLM] bug={bug_rule} candidate#{idx} file={candidate.get('file_name','')}")
    text = models.generate(system_prompt, user_prompt, model_cfg, max_new_tokens=300, pipe=pipe)

    # print("[LLM RAW]:", text[:300].replace("\n"," "))

    s, e = text.find("{"), text.rfind("}")
    if s != -1 and e != -1 and e > s:
        text = text[s:e+1]
    try:
        obj = json.loads(text)
        accept = bool(obj.get("accept", True))
    except Exception:
        accept = True
    return accept


# ------------- main -------------
def _strip_empty_fd_be(obj: Any) -> None:
    """Recursively drop empty failure_description / buggy_explanation keys so
    first-time learning output isn't cluttered with empty strings (they are
    only meaningful in --mode relearn, where they are populated)."""
    if isinstance(obj, dict):
        for k in ("failure_description", "buggy_explanation"):
            if k in obj and not str(obj.get(k) or "").strip():
                del obj[k]
        for v in obj.values():
            _strip_empty_fd_be(v)
    elif isinstance(obj, list):
        for v in obj:
            _strip_empty_fd_be(v)


def _sniff_json_training_kind(entries: List[Any]) -> str:
    """Classify a JSON training list as 'my_rf' (failure-explanation rules) or
    'manifest' (positive-example rows). The two schemas have disjoint markers."""
    for e in entries:
        if not isinstance(e, dict):
            continue
        if "failure_description" in e or "category" in e:
            return "my_rf"
        if "_source_row" in e or "metadata_path" in e or "snippet_abs_path" in e or "bug_type" in e:
            return "manifest"
        if "target_method" in e and "procedure" not in e:
            return "my_rf"
    return "manifest"


def load_training_rows(training_file: str, mode: str):
    """Route a single --training-file to (rows, bug_col, line_col).

    Extension picks the reader; JSON content picks manifest-vs-my_rf:
      * <name>.csv            -> paper CSV rows          (mode single/diff)
      * <name>.json manifest  -> positive-example rows   (mode single/diff)
      * <name>.json my_rf*    -> failure-rule rows       (mode relearn)
    """
    p = Path(training_file)
    if not p.is_file():
        raise SystemExit(f"Training file not found: {p}")
    if re.search(r"\.csv$", p.name, re.IGNORECASE):
        if mode == "relearn":
            raise SystemExit("--mode relearn needs a my_rf*.json file, not a CSV.")
        configure_csv_field_limit()
        delim = detect_delimiter(p)
        with p.open("r", encoding="utf-8", errors="replace") as f:
            r = csv.DictReader(f, delimiter=delim)
            rows = list(r)
            bug_col = find_col(r.fieldnames, ["bug-rule", "bug rule", "bug_type", "rule"])
            line_col = find_col(r.fieldnames, ["line", "line number", "line numbers", "lines"])
        if not bug_col:
            raise SystemExit("Missing bug rule column in CSV")
        return rows, bug_col, line_col
    if re.search(r"\.json$", p.name, re.IGNORECASE):
        try:
            entries = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            raise SystemExit(f"Failed to parse JSON {p}: {exc}")
        if not isinstance(entries, list):
            raise SystemExit("Training JSON must be a list of entries")
        kind = _sniff_json_training_kind(entries)
        if kind == "my_rf":
            if mode != "relearn":
                raise SystemExit(f"{p.name} looks like a my_rf failure file; use --mode relearn.")
            rows = []
            for i, entry in enumerate(entries, 1):
                if not isinstance(entry, dict):
                    continue
                rows.append({
                    "bug-rule": str(entry.get("bug_rule") or "").strip(),
                    "result_dir": str(entry.get("result_dir") or "").strip(),
                    "target_method": str(entry.get("target_method") or "").strip(),
                    "failure_description": str(entry.get("failure_description") or ""),
                    "buggy_explanation": str(entry.get("buggy_explanation") or ""),
                    "category": str(entry.get("category") or "decision_fn").strip() or "decision_fn",
                    "_source_row": i,
                })
            return rows, "bug-rule", None
        # positive-example manifest
        if mode == "relearn":
            raise SystemExit(f"{p.name} looks like a positive manifest; use --mode single or diff.")
        rows = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            row = dict(entry)
            ln = entry.get("line_numbers")
            if isinstance(ln, list):
                row["line_numbers"] = " ".join(str(x) for x in ln)
            if entry.get("line") is not None:
                row["line"] = str(entry.get("line"))
            if entry.get("_source_row") is not None:
                row["_source_row"] = str(entry.get("_source_row"))
            rows.append(row)
        if not rows:
            raise SystemExit("Manifest JSON has no usable entries")
        keys = list(rows[0].keys())
        bug_col = find_col(keys, ["bug-rule", "bug rule", "bug_type", "rule"])
        line_col = find_col(keys, ["line", "line number", "line numbers", "lines"])
        if not bug_col:
            raise SystemExit("Missing bug rule field in manifest JSON")
        return rows, bug_col, line_col
    raise SystemExit(f"Unsupported training file extension (want .csv or .json): {p.name}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Preprocessing agent: select diverse source examples per bug rule.")
    ap.add_argument("--training-file", dest="training_file", required=True,
                    help="Training input file, routed by extension (.csv or .json). "
                         "For --mode single/diff pass a positive-example paper CSV or manifest JSON; "
                         "for --mode relearn pass a my_rf*.json failure-explanation file.")
    ap.add_argument("--count", type=int, default=None, help="Target number of examples per bug rule (default: all).")
    ap.add_argument("--model", default="", help="Model backend: qwen, gpt, or gpt-4mini (omit to skip LLM).")
    ap.add_argument("--output", default=str(SCRIPT_DIR / "preprocessing_output.json"))
    ap.add_argument("--mode", default="single", choices=["single", "diff", "relearn"],
                    help="single=first-time single-method learning; diff=first-time paired buggy/fixed learning; "
                         "relearn=failure-driven relearning from a my_rf*.json (paired buggy/fixed, accept-all).")
    ap.add_argument("--joern-widen", dest="joern_widen", type=int, default=3,
                    help="Joern slice fallback radius (default 3; pass 0 to disable). "
                         "When >0 and the exact seed line yields no CFG nodes, the slice "
                         "script widens the seed search to lines within +/-N of the seed, "
                         "bounded to the seed's enclosing user method. Bitwise identical "
                         "output when exact match succeeds.")
    ap.add_argument("--accept-all", dest="accept_all", action="store_true",
                    help="Skip the LLM diversity judge and accept every collected example. "
                         "Forced ON when --mode relearn is used.")
    args = ap.parse_args()

    if args.mode == "relearn" and not args.accept_all:
        print("[INFO] --mode relearn forces --accept-all")
        args.accept_all = True
    use_llm = bool(args.model) and not args.accept_all
    model_cfg = models.resolve_model(args.model) if use_llm else {}
    pipe = None
    if use_llm and model_cfg.get("backend") == "qwen":
        pipe = models.qwen_pipe(model_cfg)

    rows, bug_col, line_col = load_training_rows(args.training_file, args.mode)

    bug_rules = sorted({(row.get(bug_col) or "").strip() for row in rows if row.get(bug_col)})
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.is_file():
        try:
            result_data = json.loads(out_path.read_text(encoding="utf-8"))
        except Exception:
            result_data = {}
    else:
        result_data = {}

    for bug_rule in bug_rules:
        if not bug_rule:
            continue
        print(f"\n====================\n[BUG] {bug_rule}\n====================")
        raw_limit = args.count * 10 if args.count is not None else None
        if args.mode == "single":
            examples = collect_examples_for_bug_paper(rows, bug_rule, line_col, SCRIPT_DIR.parent, raw_limit)
        else:  # "diff" (positive buggy/fixed) or "relearn" (my_rf failure buggy/fixed)
            examples = collect_examples_for_bug_paper_diff(rows, bug_rule, line_col, SCRIPT_DIR.parent, raw_limit)
        if not examples:
            print("[NO CANDIDATES FOUND]")
            result_data[bug_rule] = []
            out_path.write_text(json.dumps(result_data, indent=2, ensure_ascii=False), encoding="utf-8")
            continue

        random.shuffle(examples)
        selected: List[Dict[str, Any]] = []
        system_prompt = build_system_prompt(bug_rule)

        for idx, ex in enumerate(examples, 1):
            if len(selected) == 0:
                selected.append(ex)
                print(f"[ACCEPT] first example ({ex.get('file_name','')})")
                if args.count is not None and len(selected) >= args.count:
                    break
                continue

            if len(selected) < 3:
                selected.append(ex)
                print(f"[ACCEPT] bootstrap example #{idx} ({ex.get('file_name','')})")
                if args.count is not None and len(selected) >= args.count:
                    break
                continue

            if not use_llm:
                selected.append(ex)
                print(f"[ACCEPT] #{idx} ({ex.get('file_name','')})")
            else:
                user_prompt = build_user_prompt(ex, selected)
                accept = judge_candidate(model_cfg, pipe, bug_rule, idx, system_prompt, user_prompt, ex)
                if accept:
                    selected.append(ex)
                    print(f"[ACCEPT] #{idx} ({ex.get('file_name','')})")
                else:
                    print(f"[REJECT] #{idx} ({ex.get('file_name','')})")

            if args.count is not None and len(selected) >= args.count:
                break

        cleaned = []
        slice_cache: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
        cfg_cache: Dict[str, Dict[str, Any]] = {}
        for idx, ex in enumerate(selected, 1):
            if args.mode == "diff":
                print(f"[SLICE] {idx}/{len(selected)} ({ex.get('file_name','')})")
            record = {
                "example_index": idx,
                "file_name": ex["file_name"],
                "language": ex.get("language") or "unknown",
                "name": ex["name"],
                "kind": ex["kind"],
                "signature": ex["signature"],
                "class_path": ex.get("class_path", "Global"),
                "start_line": ex.get("start_line"),
                "end_line": ex.get("end_line"),
                "hit_lines_in_method": ex.get("hit_lines_in_method", []),
                "code": ex["code"],
                "secondary_methods": ex.get("secondary_methods", []),
                "source_row": ex.get("source_row"),
                "metadata_path": ex.get("metadata_path", ""),
                "commit_message": ex.get("commit_message", ""),
                "category": ex.get("category", "decision_fn"),
                "labeled_buggy_lines": ex.get("labeled_buggy_lines", []),
            }
            # Only carry failure_description / buggy_explanation when populated
            # (i.e. --mode relearn). During first-time learning they are empty, so
            # omit the keys entirely instead of writing empty strings.
            if (ex.get("failure_description") or "").strip():
                record["failure_description"] = ex["failure_description"]
            if (ex.get("buggy_explanation") or "").strip():
                record["buggy_explanation"] = ex["buggy_explanation"]
            if args.mode == "diff":
                for key in (
                    "buggy_manifest_target_lines",
                    "buggy_diff_target_lines",
                    "buggy_slice_target_lines",
                    "fixed_manifest_target_lines",
                    "fixed_diff_target_lines",
                    "fixed_slice_target_lines",
                ):
                    if key in ex:
                        record[key] = ex.get(key)
                metadata_path = Path(str(ex.get("metadata_path") or "")).expanduser()
                if metadata_path.is_file():
                    base_dir = metadata_path.parent
                    try:
                        metadata_payload = json.loads(metadata_path.read_text(encoding="utf-8"))
                    except Exception:
                        metadata_payload = {}
                    buggy_method = ex.get("buggy_method") or {}
                    fixed_method = ex.get("fixed_method") or {}
                    buggy_file = base_dir / str(metadata_payload.get("buggy_file_name") or "")
                    fixed_file = base_dir / str(metadata_payload.get("fixed_file_name") or "")
                    if buggy_file.is_file() and isinstance(buggy_method, dict):
                        record["buggy_file_name"] = buggy_file.name
                        record["buggy_method"] = buggy_method
                        record["buggy_slice"] = _build_method_slice(
                            buggy_file, buggy_method, slice_cache, direction="backward",
                            joern_widen=args.joern_widen,
                        )
                        record["buggy_forward_slice"] = _build_method_slice(
                            buggy_file, buggy_method, slice_cache, direction="forward",
                            joern_widen=args.joern_widen,
                        )
                        buggy_cfg_lines = sorted({
                            *(record.get("buggy_slice") or {}).get("slice_lines", []),
                            *(record.get("buggy_forward_slice") or {}).get("slice_lines", []),
                        })
                        record["buggy_slice_cfg"] = _build_slice_cfg(
                            buggy_file, buggy_method, buggy_cfg_lines, cfg_cache
                        )
                    if fixed_file.is_file() and isinstance(fixed_method, dict):
                        record["fixed_file_name"] = fixed_file.name
                        record["fixed_method"] = fixed_method
                        record["fixed_slice"] = _build_method_slice(
                            fixed_file, fixed_method, slice_cache, direction="backward",
                            joern_widen=args.joern_widen,
                        )
                        record["fixed_forward_slice"] = _build_method_slice(
                            fixed_file, fixed_method, slice_cache, direction="forward",
                            joern_widen=args.joern_widen,
                        )
                        fixed_cfg_lines = sorted({
                            *(record.get("fixed_slice") or {}).get("slice_lines", []),
                            *(record.get("fixed_forward_slice") or {}).get("slice_lines", []),
                        })
                        record["fixed_slice_cfg"] = _build_slice_cfg(
                            fixed_file, fixed_method, fixed_cfg_lines, cfg_cache
                        )
                record["mode"] = "diff"
                buggy_code = str((record.get("buggy_method") or {}).get("code") or "").strip()
                fixed_code = str((record.get("fixed_method") or {}).get("code") or "").strip()
                buggy_slice_ok = (
                    (record.get("buggy_slice") or {}).get("status") == "ok"
                    or (record.get("buggy_forward_slice") or {}).get("status") == "ok"
                )
                fixed_slice_ok = (
                    (record.get("fixed_slice") or {}).get("status") == "ok"
                    or (record.get("fixed_forward_slice") or {}).get("status") == "ok"
                )
                if not buggy_code or not fixed_code:
                    print(f"[SKIP] Missing buggy/fixed method code for {record.get('file_name','')}")
                    continue
                if buggy_code == fixed_code:
                    print(f"[SKIP] No buggy/fixed method diff for {record.get('file_name','')}")
                    continue
                if not buggy_slice_ok or not fixed_slice_ok:
                    print(f"[SKIP] Missing slice evidence for {record.get('file_name','')}")
                    continue
            _strip_empty_fd_be(record)
            cleaned.append(record)

        result_data[bug_rule] = cleaned
        out_path.write_text(json.dumps(result_data, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[SAVE] {len(cleaned)} examples for bug={bug_rule}")

    print(f"\n[DONE] preprocessing output → {out_path}")


if __name__ == "__main__":
    main()
