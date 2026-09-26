"""Source parsing shared by the sink point agent.

Method boundaries (Spoon for Java, brace matching otherwise), signature and
parameter parsing, declared-type maps, and resolving a called name to the file
that defines it (imports/package for Java, #include and path proximity for C).
"""
from __future__ import annotations

import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agents.libs.language_support import detect_language_from_path, extract_brace_methods
from agents.libs.drivers import get as get_driver, is_error as driver_error

# Java method boundaries come from Spoon; without it the regex mapping below is
# the fallback, which is why a failure here is not fatal.
METHOD_MAP_DRIVER = "spoon"


def _spoon_method_map(source_path):
    payload = get_driver(METHOD_MAP_DRIVER).analyze(source_path, "method_map")
    if driver_error(payload):
        return None
    methods = payload.get("methods")
    return methods if isinstance(methods, list) else None


# Matches standard method signatures like:
#   int f() { ... }
#   public static Object foo(...) { ... }
METHOD_SIG_RE = re.compile(
    r'^\s*'                                  # line start
    r'(?:@\w+(?:\([^)]*\))?\s+)*'            # optional annotations
    r'(?:public|private|protected)?\s*'      # optional access modifier
    r'(?:static\s+)?'                        # optional static
    r'(?:final\s+|synchronized\s+|abstract\s+|native\s+|strictfp\s+)*'  # optional modifiers
    r'(?:<[^>]+>\s+)?'                       # optional generic decl
    r'[A-Za-z_$][\w$<>\[\].]*\s+'            # return type
    r'([A-Za-z_$][\w$]*)\s*\('               # method name
)


CALL_IGNORE = {"if","for","while","switch","catch","return","throw","new","super","synchronized","try"}


NON_JAVA_CALL_IGNORE = CALL_IGNORE | {
    "sizeof", "alignof", "typeof", "decltype",
    "__builtin_expect", "__builtin_types_compatible_p", "__builtin_offsetof",
}


PACKAGE_RE = re.compile(r"^\s*package\s+([A-Za-z_$][\w$.]*)\s*;")


IMPORT_RE = re.compile(r"^\s*import\s+(?:static\s+)?([A-Za-z_$][\w$.*]*)\s*;")


RECEIVER_CALL_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\s*\(")


TYPE_DECL_RE = re.compile(r"\b([A-Za-z_$][\w$<>.\[\]]*)\s+([A-Za-z_$][\w$]*)\s*(?:=|;|,)")


INCLUDE_RE = re.compile(r'^\s*#\s*include\s*[<"]([^">]+)[">]')


@dataclass
class MethodInfo:
    name: str
    start_line: int
    end_line: int
    class_path: str
    snippet: list[tuple[int, str]]
    signature_line: str = ""
    param_count: int | None = None
    param_type_map: dict[str, str] | None = None


def build_class_method_map_regex(source_code: str, language: str = "java") -> tuple[dict[int, dict], list[MethodInfo]]:
    lines = source_code.splitlines()
    if language != "java":
        generic_methods = extract_brace_methods(lines, language=language)
        method_info: list[MethodInfo] = []
        method_map: dict[int, dict[str, int]] = {}
        for item in generic_methods:
            snippet_lines = item.get("code", "").splitlines()
            start = int(item.get("start_line", 1))
            end = int(item.get("end_line", start))
            snippet = [(start + idx, text) for idx, text in enumerate(snippet_lines)]
            method = MethodInfo(
                name=str(item.get("name") or "UNKNOWN_METHOD"),
                start_line=start,
                end_line=end,
                class_path=str(item.get("class_path") or "Global"),
                snippet=snippet,
                signature_line=str(item.get("signature") or "").strip(),
                param_count=item.get("param_count"),
            )
            method_info.append(method)
            for ln in range(start, end + 1):
                method_map[ln] = {"name": method.name, "start_line": start}
        return method_map, method_info

    class_stack: list[tuple[str, int]] = []
    method_info: list[MethodInfo] = []
    method_map: dict[int, dict[str, int]] = {}

    i = 0
    while i < len(lines):
        raw_line = lines[i]
        stripped = raw_line.strip()

        if "class " in stripped and "(" not in stripped:
            class_name_match = re.search(r"class\s+([A-Za-z_$][\w$]*)", stripped)
            if class_name_match:
                class_name = class_name_match.group(1)
                brace_delta = stripped.count("{") - stripped.count("}")
                if brace_delta != 0:
                    class_stack.append((class_name, i + 1))
                i += 1
                continue

        method_match = METHOD_SIG_RE.search(stripped)
        if method_match:
            start = i + 1
            name = method_match.group(1)
            brace = 0
            saw_open_brace = False
            paren_balance = 0
            end_line = start
            j = i
            while j < len(lines):
                line = lines[j]
                for ch in line:
                    if ch == "(":
                        paren_balance += 1
                    elif ch == ")" and paren_balance > 0:
                        paren_balance -= 1
                    elif ch == "{":
                        brace += 1
                        saw_open_brace = True
                    elif ch == "}" and saw_open_brace:
                        brace -= 1
                if not saw_open_brace:
                    if ";" in line and paren_balance <= 0:
                        break
                    j += 1
                    continue
                if brace <= 0:
                    end_line = j + 1
                    break
                j += 1
            if not saw_open_brace:
                i += 1
                continue
            if brace > 0:
                end_line = len(lines)
            snippet = [(ln_idx + 1, lines[ln_idx]) for ln_idx in range(i, min(end_line, len(lines)))]
            class_path = "::".join(name for name, _ in class_stack) or "Global"
            method_info.append(
                MethodInfo(
                    name=name,
                    start_line=start,
                    end_line=snippet[-1][0] if snippet else start,
                    class_path=class_path,
                    snippet=snippet,
                )
            )
            for ln in range(start, snippet[-1][0] + 1 if snippet else start + 1):
                method_map[ln] = {"name": name, "start_line": start}
            i = end_line
            continue

        if stripped.count("}") > stripped.count("{") and class_stack:
            class_stack.pop()

        i += 1

    if not method_info:
        snippet = [(idx + 1, line) for idx, line in enumerate(lines)]
        method_info.append(MethodInfo(name="ENTIRE_FILE", start_line=1, end_line=len(lines), class_path="Global", snippet=snippet))

    return method_map, method_info


def build_class_method_map(source_code: str, source_path: Path | None = None,
                           language: str | None = None) -> tuple[dict[int, dict], list[MethodInfo]]:
    language_name = language or detect_language_from_path(source_path)
    lines = source_code.splitlines()
    tmp_path: Path | None = None
    source_candidate = source_path
    spoon_entries: list[dict[str, Any]] | None = None
    regex_method_map, regex_methods = build_class_method_map_regex(source_code, language=language_name)
    try:
        if language_name == "java" and source_candidate is None:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".java") as tmp:
                tmp.write(source_code.encode("utf-8"))
                tmp.flush()
                tmp_path = Path(tmp.name)
                source_candidate = tmp_path
        if language_name == "java" and source_candidate is not None and source_candidate.is_file():
            spoon_entries = _spoon_method_map(source_candidate)
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)

    if spoon_entries:
        method_info: list[MethodInfo] = []
        method_map: dict[int, dict[str, int]] = {}
        for item in spoon_entries:
            try:
                start_line = int(item.get("start_line"))
            except (TypeError, ValueError):
                continue
            try:
                end_line = int(item.get("end_line"))
            except (TypeError, ValueError):
                end_line = start_line
            if start_line < 1:
                start_line = 1
            if end_line < start_line:
                end_line = start_line
            if start_line > len(lines):
                continue
            if end_line > len(lines):
                end_line = len(lines)
            snippet = [(ln, lines[ln - 1]) for ln in range(start_line, end_line + 1)]
            if not snippet:
                continue
            name = str(item.get("name") or "").strip() or "UNKNOWN_METHOD"
            class_path = str(item.get("class_path") or "").strip() or "Global"
            signature_line = str(item.get("signature_source") or "").strip()
            param_count = None
            try:
                if item.get("param_count") is not None:
                    param_count = int(item.get("param_count"))
            except (TypeError, ValueError):
                param_count = None
            param_type_map: dict[str, str] = {}
            raw_param_types = item.get("param_types")
            if isinstance(raw_param_types, list):
                for p in raw_param_types:
                    if not isinstance(p, dict):
                        continue
                    p_name = str(p.get("name") or "").strip()
                    p_type = _simplify_type(str(p.get("type") or ""))
                    if p_name and p_type:
                        param_type_map[p_name] = p_type
            method_info.append(
                MethodInfo(
                    name=name,
                    start_line=start_line,
                    end_line=end_line,
                    class_path=class_path,
                    snippet=snippet,
                    signature_line=signature_line,
                    param_count=param_count,
                    param_type_map=param_type_map or None,
                )
            )
            for ln in range(start_line, end_line + 1):
                method_map[ln] = {"name": name, "start_line": start_line}
        if method_info:
            existing_keys = {(m.name, m.start_line, m.end_line) for m in method_info}
            added_regex_count = 0
            for method in regex_methods:
                if method.name == "ENTIRE_FILE":
                    continue
                key = (method.name, method.start_line, method.end_line)
                if key in existing_keys:
                    continue
                method_info.append(method)
                existing_keys.add(key)
                added_regex_count += 1
                for ln in range(method.start_line, method.end_line + 1):
                    method_map.setdefault(ln, {"name": method.name, "start_line": method.start_line})
            if added_regex_count:
                print(
                    f"[INFO] Added {added_regex_count} regex-discovered method entries missing from Spoon map.",
                    file=sys.stderr,
                )
            method_info.sort(key=lambda m: (m.start_line, m.end_line))
            return method_map, method_info

    return regex_method_map, regex_methods


def top_level_arg_count(text: str) -> int | None:
    # language_support._top_level_arg_count is the C++-aware variant: it also
    # nests on <>, which changes the count for generic parameters.
    if text is None:
        return None
    s = text.strip()
    if not s:
        return 0
    count = 1
    depth = 0
    in_str = False
    str_char = ""
    escape = False
    for ch in s:
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if in_str:
            if ch == str_char:
                in_str = False
            continue
        if ch in ("\"", "'"):
            in_str = True
            str_char = ch
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            count += 1
    return count


def extract_call_args(line: str, name: str) -> str:
    if not line or not name:
        return ""
    idx = line.find(name)
    while idx != -1:
        next_idx = idx + len(name)
        if next_idx < len(line) and line[next_idx].isalnum():
            idx = line.find(name, next_idx)
            continue
        paren = line.find("(", next_idx)
        if paren == -1:
            return ""
        if line[paren - 1].isspace() or line[paren - 1] == name[-1]:
            depth = 0
            for i in range(paren, len(line)):
                ch = line[i]
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        return line[paren + 1:i]
            return line[paren + 1:]
        idx = line.find(name, next_idx)
    return ""


def parse_call_names(line: str) -> list[str]:
    if not line:
        return []
    candidates = re.findall(r"(?:\bthis\.)?([A-Za-z_$][\w$]*)\s*\(", line)
    names = []
    for name in candidates:
        if name in CALL_IGNORE:
            continue
        names.append(name)
    return names


def _is_plausible_non_java_external_call(name: str) -> bool:
    token = (name or "").strip()
    if not token:
        return False
    if token in NON_JAVA_CALL_IGNORE:
        return False
    if token.startswith("__builtin_"):
        return False
    if token.isupper():
        return False
    return True


def _extract_include_targets(code_base_path: Path,
                             current_abs: Path | None,
                             file_code_cache: dict[Path, str]) -> set[str]:
    if current_abs is None:
        return set()
    try:
        code = file_code_cache.get(current_abs)
        if code is None:
            code = current_abs.read_text(encoding="utf-8", errors="replace")
            file_code_cache[current_abs] = code
    except Exception:
        return set()
    targets: set[str] = set()
    current_dir = current_abs.parent
    for line in code.splitlines():
        m = INCLUDE_RE.match(line)
        if not m:
            continue
        inc = m.group(1).strip()
        if not inc:
            continue
        candidates = [
            code_base_path / inc,
            current_dir / inc,
        ]
        for candidate in candidates:
            try:
                if candidate.is_file():
                    rel = candidate.resolve().relative_to(code_base_path.resolve())
                    targets.add(rel.as_posix())
            except Exception:
                continue
    return targets


def _shared_path_prefix_len(a: str, b: str) -> int:
    a_parts = [part for part in a.split("/") if part]
    b_parts = [part for part in b.split("/") if part]
    count = 0
    for left, right in zip(a_parts, b_parts):
        if left != right:
            break
        count += 1
    return count


def param_count_from_method(method: MethodInfo) -> int | None:
    if method.param_count is not None:
        return method.param_count
    if not method.snippet:
        return None
    sig_line = method.signature_line or method.snippet[0][1]
    inside = extract_call_args(sig_line, method.name)
    return top_level_arg_count(inside)


def iter_method_calls(snippet: list[tuple[int, str]]) -> list[tuple[int, str, str]]:
    calls: list[tuple[int, str, str]] = []
    for ln, line_content in snippet:
        for call_name in parse_call_names(line_content):
            calls.append((ln, line_content, call_name))
    return calls


def _split_top_level_csv(text: str) -> list[str]:
    if not text:
        return []
    parts: list[str] = []
    token: list[str] = []
    depth = 0
    for ch in text:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            part = "".join(token).strip()
            if part:
                parts.append(part)
            token = []
            continue
        token.append(ch)
    part = "".join(token).strip()
    if part:
        parts.append(part)
    return parts


def _simplify_type(type_token: str) -> str:
    if not type_token:
        return ""
    cleaned = type_token.strip()
    cleaned = cleaned.replace("...", "[]")
    while True:
        next_cleaned = re.sub(r"<[^<>]*>", "", cleaned)
        if next_cleaned == cleaned:
            break
        cleaned = next_cleaned
    cleaned = cleaned.replace("[]", "").strip()
    if not cleaned:
        return ""
    cleaned = cleaned.split()[-1]
    if "." in cleaned:
        cleaned = cleaned.split(".")[-1]
    return cleaned


def parse_package_and_imports(java_code: str) -> tuple[str, dict[str, str], list[str]]:
    package_name = ""
    explicit_imports: dict[str, str] = {}
    wildcard_packages: list[str] = []
    for line in java_code.splitlines():
        if not package_name:
            pkg_match = PACKAGE_RE.match(line)
            if pkg_match:
                package_name = pkg_match.group(1).strip()
                continue
        imp_match = IMPORT_RE.match(line)
        if not imp_match:
            continue
        target = imp_match.group(1).strip()
        if target.endswith(".*"):
            wildcard_packages.append(target[:-2])
        else:
            explicit_imports[target.split(".")[-1]] = target
    return package_name, explicit_imports, wildcard_packages


def _parse_param_type_map(signature: str | None) -> dict[str, str]:
    result: dict[str, str] = {}
    if not signature:
        return result
    open_idx = signature.find("(")
    close_idx = signature.find(")", open_idx + 1)
    if open_idx < 0 or close_idx < 0 or close_idx <= open_idx:
        return result
    inside = signature[open_idx + 1:close_idx].strip()
    if not inside:
        return result
    for item in _split_top_level_csv(inside):
        token = re.sub(r"@\w+(\([^)]*\))?", "", item)
        token = re.sub(r"\b(final|volatile|transient)\b", "", token)
        token = token.strip()
        pieces = token.split()
        if len(pieces) < 2:
            continue
        var_name = pieces[-1].replace(",", "").strip()
        type_name = _simplify_type(" ".join(pieces[:-1]))
        if not var_name or not type_name:
            continue
        result[var_name] = type_name
    return result


def _extract_type_map_from_method(method: MethodInfo | None) -> dict[str, str]:
    if method is None:
        return {}
    if method.param_type_map:
        var_types = dict(method.param_type_map)
    else:
        signature = method.signature_line or (method.snippet[0][1] if method.snippet else "")
        var_types = _parse_param_type_map(signature)
    for _, line in method.snippet[1:] if len(method.snippet) > 1 else []:
        for declared_type, var_name in TYPE_DECL_RE.findall(line):
            type_name = _simplify_type(declared_type)
            if not type_name:
                continue
            if not re.match(r"[A-Z_]", type_name):
                continue
            var_types.setdefault(var_name, type_name)
    return var_types


def extract_field_type_map(java_code: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in java_code.splitlines():
        stripped = line.strip()
        if not stripped or "(" in stripped:
            continue
        for declared_type, var_name in TYPE_DECL_RE.findall(stripped):
            type_name = _simplify_type(declared_type)
            if not type_name:
                continue
            if not re.match(r"[A-Z_]", type_name):
                continue
            fields.setdefault(var_name, type_name)
    return fields


def _fqcn_from_rel_path(relative_path: Path) -> str:
    no_suffix = relative_path.with_suffix("")
    parts = list(no_suffix.parts)
    for marker in ("java", "kotlin"):
        if marker in parts:
            idx = parts.index(marker) + 1
            parts = parts[idx:]
            break
    return ".".join(parts)


def _resolve_java_path_for_fqcn(code_base_path: Path, fqcn: str,
                                simple_lookup_cache: dict[str, list[Path]]) -> Path | None:
    if not fqcn:
        return None
    direct = code_base_path / (fqcn.replace(".", "/") + ".java")
    if direct.is_file():
        return direct
    simple = fqcn.split(".")[-1]
    if simple not in simple_lookup_cache:
        simple_lookup_cache[simple] = list(code_base_path.rglob(f"{simple}.java"))
    candidates = simple_lookup_cache.get(simple) or []
    if not candidates:
        return None
    suffix = Path(*fqcn.split(".")).with_suffix(".java")
    for candidate in candidates:
        try:
            rel = candidate.relative_to(code_base_path)
        except ValueError:
            continue
        if rel.as_posix().endswith(suffix.as_posix()):
            return candidate
    return candidates[0]


def _lookup_fqcn(simple_type: str,
                 package_name: str,
                 explicit_imports: dict[str, str],
                 wildcard_packages: list[str],
                 local_class_names: set[str],
                 code_base_path: Path | None,
                 simple_lookup_cache: dict[str, list[Path]]) -> tuple[str, Path | None]:
    if not simple_type or simple_type in local_class_names:
        return "", None
    if "." in simple_type:
        fqcn = simple_type
        if code_base_path is None:
            return fqcn, None
        return fqcn, _resolve_java_path_for_fqcn(code_base_path, fqcn, simple_lookup_cache)
    if simple_type in explicit_imports:
        fqcn = explicit_imports[simple_type]
        if code_base_path is None:
            return fqcn, None
        return fqcn, _resolve_java_path_for_fqcn(code_base_path, fqcn, simple_lookup_cache)
    if code_base_path is None:
        return "", None
    if package_name:
        fqcn = f"{package_name}.{simple_type}"
        path = _resolve_java_path_for_fqcn(code_base_path, fqcn, simple_lookup_cache)
        if path:
            return fqcn, path
    for pkg in wildcard_packages:
        fqcn = f"{pkg}.{simple_type}"
        path = _resolve_java_path_for_fqcn(code_base_path, fqcn, simple_lookup_cache)
        if path:
            return fqcn, path
    if simple_type not in simple_lookup_cache:
        simple_lookup_cache[simple_type] = list(code_base_path.rglob(f"{simple_type}.java"))
    candidates = simple_lookup_cache.get(simple_type) or []
    if not candidates:
        return "", None
    path = candidates[0]
    try:
        rel = path.relative_to(code_base_path)
        return _fqcn_from_rel_path(rel), path
    except ValueError:
        return "", path


def _load_methods_for_file(java_path: Path,
                           file_method_cache: dict[Path, list[MethodInfo]],
                           file_code_cache: dict[Path, str]) -> list[MethodInfo]:
    methods = file_method_cache.get(java_path)
    if methods is not None:
        return methods
    try:
        code = java_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        file_method_cache[java_path] = []
        return []
    file_code_cache[java_path] = code
    _, methods = build_class_method_map(code, java_path)
    file_method_cache[java_path] = methods
    return methods


def _resolve_method_signature_for_call(java_path: Path,
                                       method_name: str,
                                       call_line_content: str,
                                       file_method_cache: dict[Path, list[MethodInfo]],
                                       file_code_cache: dict[Path, str]) -> tuple[str, int | None, str]:
    methods = _load_methods_for_file(java_path, file_method_cache, file_code_cache)
    if not methods:
        return "", None, ""
    matches = [m for m in methods if m.name == method_name]
    if not matches:
        return "", None, ""
    arg_count = top_level_arg_count(extract_call_args(call_line_content or "", method_name))
    if arg_count is not None:
        filtered: list[MethodInfo] = []
        for method in matches:
            param_count = param_count_from_method(method)
            if param_count is not None and param_count == arg_count:
                filtered.append(method)
        if filtered:
            matches = filtered
    selected = matches[0]
    signature = (selected.signature_line or (selected.snippet[0][1] if selected.snippet else "")).strip()
    param_count = param_count_from_method(selected)
    method_content = "\n".join([line for _, line in selected.snippet]).strip()
    return signature, param_count, method_content


def _candidate_source_files(code_base_path: Path) -> list[Path]:
    exts = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx"}
    out: list[Path] = []
    for path in code_base_path.rglob("*"):
        if path.is_file() and path.suffix.lower() in exts:
            out.append(path)
    return out


def _resolve_non_java_method_path(
    code_base_path: Path,
    current_rel_path: str,
    method_name: str,
    file_method_cache: dict[Path, list[MethodInfo]],
    file_code_cache: dict[Path, str],
    source_file_cache: dict[str, list[Path]],
) -> Path | None:
    if not _is_plausible_non_java_external_call(method_name):
        return None
    cache_key = str(code_base_path)
    candidates = source_file_cache.get(cache_key)
    if candidates is None:
        candidates = _candidate_source_files(code_base_path)
        source_file_cache[cache_key] = candidates
    current_abs: Path | None = None
    if current_rel_path:
        try:
            current_abs = (code_base_path / current_rel_path).resolve()
        except Exception:
            current_abs = None
    include_targets = _extract_include_targets(code_base_path, current_abs, file_code_cache)
    scored: list[tuple[int, Path]] = []
    for path in candidates:
        try:
            if current_abs is not None and path.resolve() == current_abs:
                continue
        except Exception:
            pass
        methods = _load_methods_for_file(path, file_method_cache, file_code_cache)
        for method in methods:
            signature = (method.signature_line or (method.snippet[0][1] if method.snippet else "")).strip()
            if method.name != method_name:
                continue
            if not signature or signature.startswith(("/*", "*", "//")):
                continue
            if f"{method_name}(" not in signature:
                continue
            try:
                candidate_rel = path.resolve().relative_to(code_base_path.resolve()).as_posix()
            except Exception:
                candidate_rel = ""
            score = 0
            if candidate_rel and candidate_rel in include_targets:
                score = 100
            elif current_rel_path:
                shared = _shared_path_prefix_len(current_rel_path, candidate_rel)
                if shared >= 3:
                    score = 50 + shared
                elif shared >= 1 and candidate_rel.startswith("include/"):
                    score = 20 + shared
            if score > 0:
                scored.append((score, path))
                break
    if not scored:
        return None
    scored.sort(key=lambda item: item[0], reverse=True)
    best_score = scored[0][0]
    best_paths = []
    seen_paths = set()
    for score, path in scored:
        if score != best_score:
            break
        key = str(path)
        if key in seen_paths:
            continue
        seen_paths.add(key)
        best_paths.append(path)
    if len(best_paths) != 1:
        return None
    return best_paths[0]


def normalize_method_name(value: str | None) -> str:
    token = (value or "").strip()
    if not token:
        return ""
    token = token.split("::")[-1].split(".")[-1].strip()
    match = re.search(r"([A-Za-z_$][\w$]*)\s*(?:\(|$)", token)
    if not match:
        return ""
    return match.group(1).lower()


def parse_target_method_norms(raw: str | None) -> list[str]:
    tokens = re.split(r"[,\n]+", (raw or "").strip())
    out: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        norm = normalize_method_name(token)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
    return out


def normalize_signature(sig: str | None) -> str:
    return re.sub(r"\s+", " ", (sig or "").strip())


def _extract_param_names(signature: str | None) -> list[str]:
    if not signature:
        return []
    open_idx = signature.find("(")
    close_idx = signature.find(")", open_idx + 1)
    if open_idx < 0 or close_idx < 0 or close_idx <= open_idx:
        return []
    inside = signature[open_idx + 1:close_idx].strip()
    if not inside:
        return []
    names = []
    for part in inside.split(","):
        cleaned = re.sub(r"@\w+(\([^)]*\))?", "", part).strip()
        tokens = cleaned.replace("...", " ").replace("[]", " ").split()
        if tokens:
            names.append(tokens[-1])
    return names
