"""Line-to-method index and class-name detection for a source file.

Brace matching (via language_support) gives the method boundaries the internal
analysis agent needs to locate a candidate and to name the class the Java graph
drivers must be pointed at.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from agents.libs.language_support import extract_brace_methods


TYPE_DECL_RE = re.compile(r"\b(class|interface|enum|record)\s+([A-Za-z_$][\w$]*)\b")


PACKAGE_RE = re.compile(r"^\s*package\s+([A-Za-z_][\w.]*)\s*;", re.MULTILINE)


@dataclass
class MethodEntry:
    name: str
    class_path: str
    binary_class: str
    simple_class: str
    start_line: int
    end_line: int
    snippet: list[tuple[int, str]]


def detect_top_level_class(java_code: str) -> str:
    m = TYPE_DECL_RE.search(_strip_java_comments(java_code))
    return m.group(2) if m else "Global"


def build_method_index(java_code: str, language: str = "java") -> tuple[dict[int, MethodEntry], list[MethodEntry]]:
    extracted = extract_brace_methods(java_code.splitlines(), language=language)
    line_map: dict[int, MethodEntry] = {}
    method_info: list[MethodEntry] = []
    for item in extracted:
        start_line = int(item.get("start_line", 1))
        end_line = int(item.get("end_line", start_line))
        class_path = str(item.get("class_path") or "Global")
        simple_class = class_path.split("::")[-1] if class_path and class_path != "Global" else "Global"
        binary_class = class_path.replace("::", "$") if class_path and class_path != "Global" else detect_top_level_class(java_code)
        snippet = [
            (start_line + idx, line)
            for idx, line in enumerate(str(item.get("code") or "").splitlines())
        ]
        entry = MethodEntry(
            name=str(item.get("name") or "ENTIRE_FILE"),
            class_path=class_path,
            binary_class=binary_class,
            simple_class=simple_class,
            start_line=start_line,
            end_line=end_line,
            snippet=snippet,
        )
        method_info.append(entry)
        for ln in range(start_line, end_line + 1):
            line_map[ln] = entry

    return line_map, method_info


def _strip_java_comments(text: str) -> str:
    # Best-effort comment stripping for declaration discovery.
    no_block = re.sub(r"/\*.*?\*/", " ", text or "", flags=re.DOTALL)
    out_lines: list[str] = []
    for line in no_block.splitlines():
        cut = line.find("//")
        if cut >= 0:
            line = line[:cut]
        out_lines.append(line)
    return "\n".join(out_lines)


def _extract_primary_type_name(java_code: str) -> str | None:
    stripped = _strip_java_comments(java_code)
    m = TYPE_DECL_RE.search(stripped)
    if not m:
        return None
    return m.group(2)


def _extract_package_name(java_code: str) -> str | None:
    m = PACKAGE_RE.search(java_code or "")
    if not m:
        return None
    return m.group(1).strip() or None


def detect_real_class_name(java_file: Path) -> str:
    # Prefer the target file itself; avoids false matches from comments in siblings.
    try:
        text = java_file.read_text(errors="replace")
        primary = _extract_primary_type_name(text)
        if primary:
            pkg = _extract_package_name(text)
            return f"{pkg}.{primary}" if pkg else primary
    except OSError:
        pass

    # Backward-compatible fallback: scan sibling files.
    folder = java_file.parent
    for f in folder.glob("*.java"):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        primary = _extract_primary_type_name(text)
        if primary:
            pkg = _extract_package_name(text)
            return f"{pkg}.{primary}" if pkg else primary
    raise RuntimeError("Cannot detect class name")


def find_method_entry(line_map: dict[int, MethodEntry],
                      methods: list[MethodEntry],
                      line_number: int | None,
                      method_name: str | None) -> MethodEntry | None:
    if line_number and line_number in line_map:
        return line_map[line_number]
    for m in methods:
        if method_name and m.name == method_name:
            return m
    return None


def resolve_external_source_path(code_base_path: str | None, source_rel_path: str | None) -> Path | None:
    base_token = str(code_base_path or "").strip()
    rel = str(source_rel_path or "").strip().lstrip("/")
    if not base_token or not rel:
        return None
    base = Path(base_token).expanduser()
    candidate = (base / rel).resolve()
    if candidate.is_file():
        return candidate
    return None
