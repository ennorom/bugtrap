"""Normalising driver graph output, and the heuristic fallback graphs.

Soot, Comex and Joern each emit CFG/DFG nodes in their own shape; these helpers
reduce them to one form (`{id, line, stmt, successors}` for CFG,
`{var, use, defs}` for DFG) and build a line-by-line stand-in when no driver
produced a usable graph.
"""
from __future__ import annotations

import re
from typing import Any, Dict


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    token = str(value).strip()
    if not token:
        return None
    try:
        return int(token)
    except ValueError:
        return None


def _stmt_text(value: Any) -> str:
    return " ".join(str(value or "").strip().split())


def _is_meaningful_cfg_stmt(stmt: str) -> bool:
    if not stmt:
        return False
    if stmt in {"<empty>", "{", "}"}:
        return False
    if stmt.startswith("{ ") and len(stmt) > 120:
        return False
    if re.fullmatch(r"[A-Za-z_]\w*", stmt):
        return False
    if re.fullmatch(r"\$?[A-Za-z_]\w*", stmt):
        return False
    if re.fullmatch(r"[-+*/%&|^!=<>~?:]+", stmt):
        return False
    return True


def _cfg_stmt_score(stmt: str) -> int:
    text = stmt.strip()
    score = 0
    if text.startswith(("if ", "if(", "switch", "for ", "for(", "while ", "while(", "do ", "goto ", "return", "throw")):
        score += 10
    if ":" in text and not text.startswith(("http:", "https:")):
        score += 6
    if any(op in text for op in (" = ", " +=", " -=", " *=", " /=", " &= ", " |= ", " ^= ", " <<= ", " >>= ", "++", "--")):
        score += 8
    if "(" in text and ")" in text:
        score += 4
    if text.endswith(";"):
        score += 2
    score += min(len(text), 120) // 40
    return score


def _is_terminal_stmt(stmt: str) -> bool:
    text = stmt.strip()
    return (
        text.startswith("return")
        or text.startswith("throw")
        or text == "break"
        or text == "continue"
        or text.startswith("goto ")
    )


def _normalize_cfg_entries(method: Dict[str, Any]) -> None:
    cfg = method.get("cfg")
    if not isinstance(cfg, list) or not cfg:
        return

    normalized: list[dict[str, Any]] = []
    if all(isinstance(item, dict) and "successors" not in item for item in cfg):
        for idx, item in enumerate(cfg):
            if not isinstance(item, dict):
                continue
            stmt = _stmt_text(item.get("stmt"))
            if not _is_meaningful_cfg_stmt(stmt):
                continue
            line = _safe_int(item.get("line"))
            out: dict[str, Any] = {"id": len(normalized), "stmt": stmt}
            if line is not None:
                out["line"] = line
            out["successors"] = [] if _is_terminal_stmt(stmt) else ([len(normalized) + 1] if idx < len(cfg) - 1 else [])
            normalized.append(out)
        method["cfg"] = normalized
        return

    raw_nodes: list[dict[str, Any]] = []
    by_id: dict[Any, dict[str, Any]] = {}
    for item in cfg:
        if not isinstance(item, dict):
            continue
        stmt = _stmt_text(item.get("stmt"))
        raw = {
            "raw_id": item.get("id"),
            "line": _safe_int(item.get("line")),
            "stmt": stmt,
            "successors": item.get("successors") if isinstance(item.get("successors"), list) else [],
        }
        raw_nodes.append(raw)
        by_id[raw["raw_id"]] = raw

    best_by_line: dict[int, dict[str, Any]] = {}
    floating_kept: list[dict[str, Any]] = []
    seen_stmt_keys: set[tuple[int | None, str]] = set()
    for raw in raw_nodes:
        stmt = raw["stmt"]
        if not _is_meaningful_cfg_stmt(stmt):
            continue
        dedupe_key = (raw["line"], stmt)
        if dedupe_key in seen_stmt_keys:
            continue
        seen_stmt_keys.add(dedupe_key)
        line = raw["line"]
        if line is None or line < 0:
            floating_kept.append(raw)
            continue
        prior = best_by_line.get(line)
        if prior is None or _cfg_stmt_score(stmt) > _cfg_stmt_score(prior["stmt"]):
            best_by_line[line] = raw

    kept_raw_nodes = sorted(best_by_line.values(), key=lambda item: ((item["line"] if item["line"] is not None else 10**9), raw_nodes.index(item)))
    kept_raw_nodes.extend(floating_kept)
    kept_raw_ids: list[Any] = []
    kept_index_by_raw_id: dict[Any, int] = {}
    for raw in kept_raw_nodes:
        kept_index_by_raw_id[raw["raw_id"]] = len(kept_raw_ids)
        kept_raw_ids.append(raw["raw_id"])

    def next_kept_successors(start_ids: list[Any]) -> list[int]:
        found: list[int] = []
        queue = list(start_ids)
        visited: set[Any] = set()
        while queue:
            current_id = queue.pop(0)
            if current_id in visited:
                continue
            visited.add(current_id)
            if current_id in kept_index_by_raw_id:
                idx = kept_index_by_raw_id[current_id]
                if idx not in found:
                    found.append(idx)
                continue
            current = by_id.get(current_id)
            if not current:
                continue
            for nxt in current.get("successors") or []:
                if nxt not in visited:
                    queue.append(nxt)
        return found

    for idx, raw_id in enumerate(kept_raw_ids):
        raw = by_id[raw_id]
        stmt = raw["stmt"]
        successors = next_kept_successors(list(raw.get("successors") or []))
        if not successors and not _is_terminal_stmt(stmt) and idx + 1 < len(kept_raw_ids):
            successors = [idx + 1]
        out: dict[str, Any] = {"id": idx, "stmt": stmt, "successors": successors}
        if raw["line"] is not None:
            out["line"] = raw["line"]
        normalized.append(out)

    method["cfg"] = normalized


def _looks_like_pseudo_var(token: str) -> bool:
    if not token:
        return True
    if token.startswith("<operator>."):
        return True
    if token in {"this", "self", "<empty>", "<value>"}:
        return True
    if re.fullmatch(r"[-+]?(\d+|\d+\.\d+)", token):
        return True
    if (token.startswith('"') and token.endswith('"')) or (token.startswith("'") and token.endswith("'")):
        return True
    if re.fullmatch(r"[A-Z][A-Z0-9_]*", token):
        return True
    return False


def _stmt_defines_var(stmt: str, var: str) -> bool:
    text = stmt.strip()
    return (
        text.startswith(f"{var} =")
        or text.startswith(f"{var}=")
        or text.startswith(f"{var} +=")
        or text.startswith(f"{var} -=")
        or text.startswith(f"{var} *=")
        or text.startswith(f"{var} /=")
        or text.startswith(f"{var} %=")
        or text.startswith(f"{var} &=")
        or text.startswith(f"{var} |=")
        or text.startswith(f"{var} ^=")
        or text.startswith(f"{var} <<=")
        or text.startswith(f"{var} >>=")
        or text.startswith(f"++{var}")
        or text.startswith(f"--{var}")
        or text.endswith(f"{var}++")
        or text.endswith(f"{var}--")
    )


def _normalize_dfg_entries(method: Dict[str, Any]) -> None:
    dfg = method.get("dfg")
    if not isinstance(dfg, list) or not dfg:
        return

    if all(isinstance(item, dict) and isinstance(item.get("defs"), list) and any("=" in str(v) or "return" in str(v) for v in item.get("defs", [])) for item in dfg if isinstance(item, dict) and item.get("defs")):
        normalized_java: list[dict[str, Any]] = []
        seen_java: set[tuple[str, str, tuple[str, ...]]] = set()
        for item in dfg:
            if not isinstance(item, dict):
                continue
            var = str(item.get("var") or "").strip()
            use_stmt = _stmt_text(item.get("use"))
            defs = [_stmt_text(v) for v in item.get("defs") if _stmt_text(v)]
            if not var or not use_stmt or not defs:
                continue
            key = (var, use_stmt, tuple(defs))
            if key in seen_java:
                continue
            seen_java.add(key)
            normalized_java.append({"var": var, "use": use_stmt, "defs": defs})
        method["dfg"] = normalized_java
        return

    line_to_stmt: dict[int, str] = {}
    for item in dfg:
        if not isinstance(item, dict):
            continue
        line = _safe_int(item.get("line"))
        stmt = _stmt_text(item.get("stmt"))
        if line is not None and stmt and _is_meaningful_cfg_stmt(stmt):
            line_to_stmt.setdefault(line, stmt)

    grouped: dict[tuple[int | None, str, str], set[str]] = {}
    for item in dfg:
        if not isinstance(item, dict):
            continue
        var = str(item.get("var") or "").strip()
        if _looks_like_pseudo_var(var):
            continue
        use_stmt = _stmt_text(item.get("stmt") or item.get("use"))
        if not use_stmt or not _is_meaningful_cfg_stmt(use_stmt):
            continue
        if use_stmt.startswith("<global> "):
            continue
        line = _safe_int(item.get("line"))
        def_line = _safe_int(item.get("def_line"))
        defs = grouped.setdefault((line, var, use_stmt), set())
        if def_line is not None and def_line >= 0:
            def_stmt = line_to_stmt.get(def_line)
            if def_stmt:
                if def_line != line or _stmt_defines_var(use_stmt, var):
                    defs.add(def_stmt)
        for raw_def in item.get("defs") or []:
            raw_def_text = _stmt_text(raw_def)
            if raw_def_text and not _looks_like_pseudo_var(raw_def_text) and raw_def_text != var:
                defs.add(raw_def_text)

    normalized_c: list[dict[str, Any]] = []
    for (line, var, use_stmt), defs in sorted(grouped.items(), key=lambda x: ((x[0][0] if x[0][0] is not None else 10**9), x[0][1], x[0][2])):
        defs_list = sorted(defs)
        if not defs_list:
            continue
        out: dict[str, Any] = {"var": var, "use": use_stmt, "defs": defs_list}
        if line is not None:
            out["line"] = line
        normalized_c.append(out)
    method["dfg"] = normalized_c


def normalize_method_payload(result: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(result, dict):
        return result
    method = result.get("method")
    if not isinstance(method, dict):
        method = None
    if method:
        if "cfg" in method:
            _normalize_cfg_entries(method)
        if "dfg" in method:
            _normalize_dfg_entries(method)
    matching_methods = result.get("matching_methods")
    if isinstance(matching_methods, list):
        for entry in matching_methods:
            if not isinstance(entry, dict):
                continue
            if "cfg" in entry:
                _normalize_cfg_entries(entry)
            if "dfg" in entry:
                _normalize_dfg_entries(entry)
    return result


IDENT_RE = re.compile(r"\b[A-Za-z_][\w]*\b")


DFG_SKIP_WORDS = {
    "if", "for", "while", "switch", "return", "sizeof", "struct", "class",
    "static", "const", "void", "int", "char", "long", "short", "float",
    "double", "signed", "unsigned", "else", "case", "break", "continue",
    "NULL", "nullptr", "true", "false",
}


def _method_signature(entry: Any) -> str:
    return entry.snippet[0][1].strip() if entry.snippet else ""


def _method_body(entry: Any) -> str:
    return "\n".join(line for _, line in entry.snippet).strip()


def _build_heuristic_cfg(entry: Any) -> list[dict[str, Any]]:
    cfg: list[dict[str, Any]] = []
    for idx, (line_no, line) in enumerate(entry.snippet, 1):
        stmt = line.strip()
        if not stmt or stmt in {"{", "}"}:
            continue
        cfg.append({
            "id": idx,
            "line": line_no,
            "stmt": stmt,
        })
    return cfg


def _build_heuristic_dfg(entry: Any) -> list[dict[str, Any]]:
    dfg: list[dict[str, Any]] = []
    for line_no, line in entry.snippet:
        stmt = line.strip()
        if not stmt or stmt.startswith("#"):
            continue
        defs: list[str] = []
        uses: list[str] = []
        match = re.match(r"(?:[A-Za-z_][\w\s\*]*\s+)?([A-Za-z_][\w]*)\s*=\s*(.+?);?$", stmt)
        if match:
            defs.append(match.group(1))
            uses = [tok for tok in IDENT_RE.findall(match.group(2)) if tok not in DFG_SKIP_WORDS and tok != match.group(1)]
        elif "->" in stmt or "." in stmt or "(" in stmt:
            uses = [tok for tok in IDENT_RE.findall(stmt) if tok not in DFG_SKIP_WORDS]
        if defs:
            for used in uses or ["<value>"]:
                dfg.append({
                    "line": line_no,
                    "stmt": stmt,
                    "defs": defs,
                    "var": defs[0],
                    "use": used,
                })
        elif uses:
            dfg.append({
                "line": line_no,
                "stmt": stmt,
                "defs": [],
                "var": uses[0],
                "use": uses[-1],
            })
    return dfg


def heuristic_analysis_result(entry: Any | None, tool: str) -> Dict[str, Any]:
    if entry is None:
        return {"tool": "heuristic", "status": "error", "message": "method not found"}
    method: Dict[str, Any] = {
        "name": entry.name,
        "signature": _method_signature(entry),
        "start_line": entry.start_line,
        "end_line": entry.end_line,
    }
    if tool == "ast":
        method["body"] = _method_body(entry)
    elif tool == "cfg":
        method["cfg"] = _build_heuristic_cfg(entry)
    elif tool == "dfg":
        method["dfg"] = _build_heuristic_dfg(entry)
    return {"tool": "heuristic", "status": "ok", "method": method}
