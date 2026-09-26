"""Selecting the candidate's method inside a driver payload.

Drivers return every method in the file; the agent needs the one the candidate
sits in. Matching goes by name, then enclosing line range, then parameter
count, then exact signature, then a statement probe for the ambiguous rest.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from agents.libs.graph_payloads import _safe_int, normalize_method_payload
from agents.libs.source_parsing import normalize_signature as _normalize_signature


def _count_params_from_inside(inside: str | None) -> int | None:
    if inside is None:
        return None
    inside = inside.strip()
    if not inside:
        return 0
    count = 1
    depth = 0
    for ch in inside:
        if ch in "<([":  # best-effort nesting
            depth += 1
        elif ch in ">)]":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            count += 1
    return count


def _extract_decl_name_and_params(sig: str | None) -> tuple[str | None, str | None]:
    text = str(sig or "")
    if not text:
        return None, None

    depth = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "(":
            if depth == 0:
                prefix = text[:i]
                name_match = re.search(r"([A-Za-z_$][\w$]*)\s*$", prefix)
                if not name_match:
                    depth += 1
                    i += 1
                    continue
                name = name_match.group(1)
                prev = name_match.start(1) - 1
                while prev >= 0 and prefix[prev].isspace():
                    prev -= 1
                # Skip annotation invocations like @GetMapping(...).
                if prev >= 0 and prefix[prev] == "@":
                    depth += 1
                    i += 1
                    continue

                # Parse this top-level parameter list with nesting support.
                inner_depth = 1
                j = i + 1
                while j < len(text) and inner_depth > 0:
                    if text[j] == "(":
                        inner_depth += 1
                    elif text[j] == ")":
                        inner_depth -= 1
                    j += 1
                if inner_depth != 0:
                    return name, None
                return name, text[i + 1:j - 1]
            depth += 1
        elif ch == ")" and depth > 0:
            depth -= 1
        i += 1
    return None, None


def _extract_param_count(sig: str | None) -> int | None:
    _, inside = _extract_decl_name_and_params(sig)
    return _count_params_from_inside(inside)


def _extract_signature_name_and_param_count(sig: str | None) -> tuple[str | None, int | None]:
    name, inside = _extract_decl_name_and_params(sig)
    return name, _count_params_from_inside(inside)


def _canonical_method_name(name: str | None) -> str | None:
    token = str(name or "").strip()
    if not token:
        return None
    token = token.split("(")[0].strip()
    token = token.split("::")[-1].split(".")[-1].strip()
    if not token:
        return None
    return token


def candidate_target_line(payload: Dict[str, Any] | None) -> int | None:
    if not isinstance(payload, dict):
        return None
    for key in ("line_number", "called_at_line_number", "line"):
        line = _safe_int(payload.get(key))
        if line is not None:
            return line
    return None


def _normalize_ws(text: str | None) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())


def _extract_probe_line(method_content: str | None) -> str | None:
    if not method_content:
        return None
    lines = [line.strip() for line in method_content.splitlines()]
    if not lines:
        return None

    # Primary strategy: skip signature line and find the first meaningful
    # executable statement (prefer statement-like lines).
    body_lines = lines[1:] if len(lines) > 1 else []
    first_non_empty: str | None = None
    for line in body_lines:
        if not line or line in {"{", "}"}:
            continue
        if first_non_empty is None:
            first_non_empty = line
        if ";" in line:
            return line
        if "=" in line or line.startswith("return ") or line.startswith("throw "):
            return line

    if first_non_empty:
        return first_non_empty

    # Backward-compatible fallback.
    for line in lines:
        if line and line not in {"{", "}"}:
            return line
    return None


def candidate_method_probe_content(item: Dict[str, Any]) -> str | None:
    method_content = (item.get("method_content") or "").strip()
    if method_content:
        return method_content

    # Backward compatibility: older payloads may include only signature/body.
    method_signature = (item.get("method_signature") or "").strip()
    method_body = (item.get("method_body") or "").strip()
    if method_signature or method_body:
        return f"{method_signature}\n{method_body}".strip()

    # Last-resort probe for ambiguous graph outputs.
    line_content = (item.get("line_content") or "").strip()
    if line_content:
        return line_content
    return None


def _method_entry_contains_stmt(entry: Dict[str, Any], probe_line: str) -> bool:
    if not probe_line:
        return False
    probe_norm = _normalize_ws(probe_line)
    if not probe_norm:
        return False
    for key in ("cfg", "dfg"):
        blocks = entry.get(key)
        if isinstance(blocks, list):
            for block in blocks:
                texts: list[str] = []
                if isinstance(block, dict):
                    for field in ("stmt", "label", "use"):
                        value = block.get(field)
                        if value:
                            texts.append(str(value))
                    defs_value = block.get("defs")
                    if isinstance(defs_value, list):
                        for item in defs_value:
                            if item is not None:
                                texts.append(str(item))
                else:
                    texts.append(str(block))
                for text in texts:
                    stmt_norm = _normalize_ws(text)
                    if not stmt_norm:
                        continue
                    if probe_norm in stmt_norm or stmt_norm in probe_norm:
                        return True
    return False


def _method_matches(entry: Dict[str, Any], target: str,
                    target_signature: str | None = None) -> bool:
    if not isinstance(entry, dict) or not target:
        return False
    entry_sig = entry.get("signature") or entry.get("method_signature") or entry.get("subsignature")
    target_name = _canonical_method_name(target)
    target_sig_name, target_sig_param = _extract_signature_name_and_param_count(target_signature)
    effective_target_name = target_sig_name or target_name
    if not effective_target_name:
        return False

    entry_name = _canonical_method_name(entry.get("method") or entry.get("name"))
    entry_sig_name, entry_sig_param = _extract_signature_name_and_param_count(entry_sig)
    if entry_name != effective_target_name and entry_sig_name != effective_target_name:
        return False

    target_param = target_sig_param if target_sig_param is not None else _extract_param_count(target_signature)
    entry_param = _safe_int(entry.get("param_count"))
    if entry_param is None:
        entry_param = entry_sig_param
    # Keep parameter mismatches as weak matches; _find_method_entry ranks exact
    # parameter matches first and then uses statement probe for disambiguation.

    if target_signature and entry_sig:
        # Fast path: exact normalized signature match.
        if _normalize_signature(entry_sig) == _normalize_signature(target_signature):
            return True
        # Robust path for AST formats (e.g., "int foo(int x) {" vs "foo(int)").
        if target_sig_name and entry_sig_name and target_sig_name == entry_sig_name:
            return True

    return True


def _method_contains_line(entry: Dict[str, Any], target_line: int | None) -> bool:
    if target_line is None:
        return False
    start_line = _safe_int(entry.get("start_line"))
    end_line = _safe_int(entry.get("end_line"))
    if start_line is None or end_line is None:
        return False
    return start_line <= target_line <= end_line


def _dedupe_method_entries(entries: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    deduped: list[Dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        sig = entry.get("signature") or entry.get("method_signature") or entry.get("subsignature") or ""
        key = (
            _canonical_method_name(entry.get("method") or entry.get("name")),
            _normalize_signature(str(sig)),
            _safe_int(entry.get("start_line")),
            _safe_int(entry.get("end_line")),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)
    return deduped


def _find_method_matches(classes: List[Dict[str, Any]] | None,
                         target_method: str,
                         target_class: str | None = None,
                         target_signature: str | None = None,
                         method_probe: str | None = None,
                         target_line: int | None = None) -> list[Dict[str, Any]]:
    if not classes:
        return []

    target_simple = None
    if target_class:
        target_simple = target_class.split(".")[-1].split("$")[-1]

    def collect_matches(class_filter: str | None) -> list[Dict[str, Any]]:
        matches: list[Dict[str, Any]] = []
        for cls in classes:
            if class_filter:
                cls_name = cls.get("simple_name") or cls.get("name") or cls.get("class")
                cls_simple = str(cls_name).split(".")[-1].split("$")[-1]
                if cls_simple != class_filter:
                    continue
            methods = cls.get("methods")
            if isinstance(methods, list):
                for m in methods:
                    if _method_matches(m, target_method, target_signature):
                        matches.append(m)
        return matches

    matches = collect_matches(target_simple) if target_simple else []
    if not matches:
        matches = collect_matches(None)
    if not matches and method_probe:
        probe_line = _extract_probe_line(method_probe)
        if probe_line:
            probe_matches: list[Dict[str, Any]] = []
            for cls in classes:
                methods = cls.get("methods") if isinstance(cls, dict) else None
                if not isinstance(methods, list):
                    continue
                for m in methods:
                    if isinstance(m, dict) and _method_entry_contains_stmt(m, probe_line):
                        probe_matches.append(m)
            if probe_matches:
                matches = probe_matches
    if not matches:
        return []

    if target_line is not None:
        line_matches = [m for m in matches if _method_contains_line(m, target_line)]
        if line_matches:
            matches = line_matches

    target_param = _extract_param_count(target_signature) if target_signature else None
    if target_param is not None:
        param_matches = []
        for m in matches:
            entry_param = _safe_int(m.get("param_count"))
            if entry_param is not None and entry_param == target_param:
                param_matches.append(m)
        if param_matches:
            matches = param_matches

    if target_signature:
        target_sig_norm = _normalize_signature(target_signature)
        sig_matches = []
        for m in matches:
            entry_sig = m.get("signature") or m.get("method_signature") or m.get("subsignature")
            if entry_sig and _normalize_signature(entry_sig) == target_sig_norm:
                sig_matches.append(m)
        if sig_matches:
            matches = sig_matches

    if method_probe and len(matches) > 1:
        probe_line = _extract_probe_line(method_probe)
        if probe_line:
            stmt_matches = [m for m in matches if _method_entry_contains_stmt(m, probe_line)]
            if stmt_matches:
                matches = stmt_matches

    return _dedupe_method_entries(matches)


def _pick_single_method(classes: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    methods: list[Dict[str, Any]] = []
    for cls in classes:
        entries = cls.get("methods")
        if isinstance(entries, list):
            methods.extend([m for m in entries if isinstance(m, dict)])
    if len(methods) == 1:
        return methods[0]
    return None


def summarize_methods(classes: List[Dict[str, Any]] | None) -> list[Dict[str, Any]]:
    summaries: list[Dict[str, Any]] = []
    if not classes:
        return summaries
    for cls in classes:
        methods = cls.get("methods")
        if not isinstance(methods, list):
            continue
        for method in methods:
            if not isinstance(method, dict):
                continue
            sig = method.get("signature") or method.get("method_signature") or method.get("subsignature")
            summaries.append({
                "name": method.get("name") or method.get("method"),
                "signature": sig,
                "start_line": _safe_int(method.get("start_line")),
                "end_line": _safe_int(method.get("end_line")),
            })
    return summaries


def normalize_tool_label(result: Dict[str, Any], tool_label: str) -> Dict[str, Any]:
    if isinstance(result, dict):
        result["tool"] = tool_label
    return result


def has_method_entry(result: Dict[str, Any] | None) -> bool:
    return (
        isinstance(result, dict)
        and (
            isinstance(result.get("method"), dict)
            or (isinstance(result.get("matching_methods"), list) and bool(result.get("matching_methods")))
        )
    )


def filter_method_only(result: Dict[str, Any], method_name: str | None,
                       class_name: str | None, method_signature: str | None = None,
                       method_content: str | None = None,
                       target_line: int | None = None) -> Dict[str, Any]:
    if not isinstance(result, dict):
        return result

    # Drivers answer `classes` at the top level; see drivers.base.
    classes_root = result.get("classes")
    if isinstance(classes_root, list):
        matches = _find_method_matches(
            classes_root, method_name, class_name, method_signature, method_content, target_line
        )
        if len(matches) == 1:
            return normalize_method_payload({
                "tool": result.get("tool"),
                "status": result.get("status"),
                "method": matches[0],
            })
        if len(matches) > 1:
            return normalize_method_payload({
                "tool": result.get("tool"),
                "status": result.get("status"),
                "matching_methods": matches,
                "message": f"Ambiguous method match: {len(matches)} matches for {method_name}",
            })
        if not any((method_name, class_name, method_signature, method_content)):
            method_entry = _pick_single_method(classes_root)
            if method_entry:
                return normalize_method_payload({
                    "tool": result.get("tool"),
                    "status": result.get("status"),
                    "method": method_entry,
                })

    # If no specific method found, return as-is
    return result
