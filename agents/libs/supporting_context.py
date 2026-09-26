from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from agents.libs.source_parsing import (
    CALL_IGNORE,
    MethodInfo,
    RECEIVER_CALL_RE,
    extract_field_type_map,
    iter_method_calls,
    normalize_signature,
    param_count_from_method,
    parse_call_names,
    _extract_type_map_from_method,
    _is_plausible_non_java_external_call,
    _lookup_fqcn,
    _resolve_method_signature_for_call,
    _resolve_non_java_method_path,
    _extract_param_names,
)


def build_external_methods_for_candidate(method_info: MethodInfo | None,
                                          method_content: str,
                                          local_methods_by_name: dict[str, list[MethodInfo]],
                                          package_name: str,
                                          explicit_imports: dict[str, str],
                                          wildcard_packages: list[str],
                                          local_class_names: set[str],
                                          field_type_map: dict[str, str],
                                          code_base_path: Path | None,
                                          source_rel_path: str,
                                          simple_lookup_cache: dict[str, list[Path]],
                                          file_method_cache: dict[Path, list[MethodInfo]],
                                          file_code_cache: dict[Path, str],
                                          language: str,
                                          source_file_cache: dict[str, list[Path]]) -> list[dict]:
    if code_base_path is None:
        return []
    calls: list[tuple[int, str]] = []
    if method_info is not None:
        calls = method_info.snippet
    else:
        base_ln = 0
        for idx, line in enumerate((method_content or "").splitlines(), 1):
            calls.append((base_ln + idx, line))
    local_method_names = set(local_methods_by_name.keys())
    var_type_map = _extract_type_map_from_method(method_info) if method_info else {}
    seen: set[tuple[str, str, int, str]] = set()
    external_methods: list[dict[str, Any]] = []
    attached_external_method_content = False
    for line_num, line_content in calls:
        if language != "java":
            for called_method in parse_call_names(line_content or ""):
                if not _is_plausible_non_java_external_call(called_method):
                    continue
                if called_method in local_method_names:
                    continue
                resolved_path = _resolve_non_java_method_path(
                    code_base_path,
                    source_rel_path,
                    called_method,
                    file_method_cache,
                    file_code_cache,
                    source_file_cache,
                )
                if resolved_path is None:
                    continue
                signature, param_count, resolved_method_content = _resolve_method_signature_for_call(
                    resolved_path,
                    called_method,
                    line_content,
                    file_method_cache,
                    file_code_cache,
                )
                if not signature or signature.startswith(("/*", "*", "//")):
                    continue
                if not resolved_method_content.strip():
                    continue
                try:
                    rel_path = str(resolved_path.relative_to(code_base_path)).replace("\\", "/")
                except ValueError:
                    rel_path = str(resolved_path)
                key = (rel_path, called_method, int(line_num), line_content.strip())
                if key in seen:
                    continue
                seen.add(key)
                entry: dict[str, Any] = {
                    "source_rel_path": rel_path,
                    "method_name": called_method,
                    "called_at_line_number": line_num,
                    "called_at_line_content": line_content.strip(),
                }
                if signature:
                    entry["method_signature"] = signature
                if param_count is not None:
                    entry["param_count"] = param_count
                if (not attached_external_method_content) and resolved_method_content:
                    entry["method_content"] = resolved_method_content
                    attached_external_method_content = True
                external_methods.append(entry)
            continue
        for receiver, called_method in RECEIVER_CALL_RE.findall(line_content or ""):
            if receiver in {"this", "super"}:
                continue
            if called_method in CALL_IGNORE:
                continue
            receiver_type = ""
            if re.match(r"[A-Z_]", receiver):
                receiver_type = receiver
            else:
                receiver_type = var_type_map.get(receiver) or field_type_map.get(receiver) or ""
            if not receiver_type:
                continue
            fqcn, resolved_path = _lookup_fqcn(
                receiver_type,
                package_name,
                explicit_imports,
                wildcard_packages,
                local_class_names,
                code_base_path,
                simple_lookup_cache,
            )
            if not fqcn or resolved_path is None:
                continue
            if source_rel_path:
                try:
                    current_path = (code_base_path / source_rel_path).resolve()
                except Exception:
                    current_path = None
                if current_path and resolved_path.resolve() == current_path:
                    continue
            signature, param_count, resolved_method_content = _resolve_method_signature_for_call(
                resolved_path,
                called_method,
                line_content,
                file_method_cache,
                file_code_cache,
            )
            try:
                rel_path = str(resolved_path.relative_to(code_base_path)).replace("\\", "/")
            except ValueError:
                rel_path = str(resolved_path)
            key = (fqcn, called_method, int(line_num), rel_path)
            if key in seen:
                continue
            seen.add(key)
            entry: dict[str, Any] = {
                "fqcn": fqcn,
                "source_rel_path": rel_path,
                "method_name": called_method,
                "called_at_line_number": line_num,
                "called_at_line_content": line_content.strip(),
            }
            if signature:
                entry["method_signature"] = signature
            if param_count is not None:
                entry["param_count"] = param_count
            # Keep token usage bounded: attach full external method content for only one resolved method.
            if (not attached_external_method_content) and resolved_method_content:
                entry["method_content"] = resolved_method_content
                attached_external_method_content = True
            external_methods.append(entry)
    return external_methods


def build_secondary_methods_for_prompt(method: MethodInfo,
                                        methods_by_name: dict[str, list[MethodInfo]]) -> list[dict]:
    secondary_methods: list[dict] = []
    seen = set()
    sig_norm = normalize_signature(method.snippet[0][1] if method.snippet else "")
    method_content = "\n".join([line for _, line in method.snippet]).strip()

    for _, line_content, call_name in iter_method_calls(method.snippet):
        overloads = methods_by_name.get(call_name, [])
        overloads = [m for m in overloads if m.class_path == method.class_path]
        if not overloads:
            continue
        for m in overloads:
            if m.name == method.name and m.start_line == method.start_line:
                continue
            content = "\n".join([line for _, line in m.snippet]).strip()
            if m.name == method.name:
                sig_candidate = normalize_signature(m.snippet[0][1] if m.snippet else "")
                if sig_norm and sig_candidate and sig_candidate == sig_norm:
                    continue
                if not sig_norm and method_content and content == method_content:
                    continue
            entry = {
                "method_name": m.name,
                "called_at_line_content": line_content,
                "method_content": content,
            }
            if m.snippet:
                signature = m.snippet[0][1].strip()
                if signature:
                    entry["method_signature"] = signature
            key = (entry["method_name"], entry.get("method_signature", ""), entry["called_at_line_content"])
            if key in seen:
                continue
            seen.add(key)
            secondary_methods.append(entry)
    return secondary_methods


def _summarize_secondary_method(entry: dict) -> str:
    name = (entry.get("method_name") or "").strip()
    signature = (entry.get("method_signature") or "").strip()
    called_at = (entry.get("called_at_line_content") or "").strip()
    content = entry.get("method_content") or ""
    content_lower = content.lower()
    observations = []

    if "return" in content_lower:
        observations.append("contains return statements")
    if re.search(r"\bnew\s+[A-Za-z_$]", content):
        observations.append("allocates objects via new")
    if ".close(" in content:
        observations.append("invokes close()")

    params = _extract_param_names(signature)
    if params:
        forwarded = any(re.search(rf"\b\w+\s*\([^)]*\b{re.escape(p)}\b", content) for p in params)
        deref = any(re.search(rf"\b{re.escape(p)}\b\s*\.\s*\w+", content) for p in params)
        returned = any(re.search(rf"\breturn\b[^;]*\b{re.escape(p)}\b", content) for p in params)
        closed = any(re.search(rf"\b{re.escape(p)}\b\s*\.\s*close\s*\(", content) for p in params)
        if forwarded:
            observations.append("forwards parameter(s) into calls")
        if deref:
            observations.append("dereferences parameter(s)")
        if returned:
            observations.append("returns parameter(s)")
        if closed:
            observations.append("closes parameter(s)")

    head = name
    if signature:
        head = f"{name} {signature}"
    summary = head
    if called_at:
        summary += f" | called_at: {called_at}"
    if observations:
        summary += f" | observations: {', '.join(observations)}"
    return summary


def summarize_secondary_methods(secondary_methods: list[dict]) -> str:
    summaries = []
    for entry in secondary_methods:
        if not isinstance(entry, dict):
            continue
        summary = _summarize_secondary_method(entry)
        if summary:
            summaries.append(f"- {summary}")
    return "\n".join(summaries)
