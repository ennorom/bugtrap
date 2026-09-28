from __future__ import annotations

from pathlib import Path
import re
from typing import Any


C_FAMILY_EXTENSIONS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx"}
JAVA_EXTENSIONS = {".java"}
CONTROL_WORDS = {"if", "for", "while", "switch", "catch", "do", "synchronized", "try"}
BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
TYPE_DECL_RE = re.compile(r"\b(class|interface|enum|record)\s+([A-Za-z_$][\w$]*)\b")
# C/C++ aggregate type definition opener: optional typedef, then struct/union/enum.
# Matches "struct foo", "typedef struct {", "union bar {", "enum E {", etc.
STRUCT_DECL_RE = re.compile(r"^(typedef\s+)?(struct|union|enum)\b")
CPP_SCOPE_NAME_RE = re.compile(r"([A-Za-z_$][\w$]*(?:::[A-Za-z_$][\w$]*)*)\s*$")
BAD_SIGNATURE_PREFIXES = ("#", "typedef ", "return ", "case ", "goto ")
BAD_SIGNATURE_SUBSTRINGS = (" = {", "};")


def detect_language_from_path(path: Path | str | None) -> str:
    suffix = Path(path or "").suffix.lower()
    if suffix in JAVA_EXTENSIONS:
        return "java"
    if suffix in C_FAMILY_EXTENSIONS:
        return "c"
    return "unknown"


def language_display_name(language: str) -> str:
    if language == "java":
        return "Java"
    if language == "c":
        return "C/C++"
    return "source"


def read_source_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def strip_block_keep_lines(text: str) -> str:
    return BLOCK_COMMENT_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text or "")


def strip_line_comment(line: str) -> str:
    in_str = False
    str_char = ""
    escape = False
    for idx, ch in enumerate(line):
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
        if ch in {"'", '"'}:
            in_str = True
            str_char = ch
            continue
        if ch == "/" and idx + 1 < len(line) and line[idx + 1] == "/":
            return line[:idx]
    return line


def read_source_lines(path: Path) -> list[str]:
    raw = strip_block_keep_lines(read_source_file(path))
    return [strip_line_comment(line) for line in raw.splitlines()]


def _top_level_arg_count(text: str | None) -> int | None:
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
        if ch in {"'", '"'}:
            in_str = True
            str_char = ch
            continue
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            count += 1
    return count


def _extract_decl_name_and_params(signature: str | None) -> tuple[str | None, str | None]:
    text = str(signature or "")
    if not text:
        return None, None
    depth = 0
    for idx, ch in enumerate(text):
        if ch != "(":
            continue
        prefix = text[:idx]
        match = CPP_SCOPE_NAME_RE.search(prefix)
        if not match:
            continue
        scoped_name = match.group(1)
        name = scoped_name.split("::")[-1]
        if name in CONTROL_WORDS:
            continue
        prev = match.start(1) - 1
        while prev >= 0 and prefix[prev].isspace():
            prev -= 1
        if prev >= 0 and prefix[prev] == "@":
            continue
        depth = 1
        j = idx + 1
        while j < len(text) and depth > 0:
            if text[j] == "(":
                depth += 1
            elif text[j] == ")":
                depth -= 1
            j += 1
        if depth == 0:
            return name, text[idx + 1:j - 1]
    return None, None


def _looks_like_function_signature(signature_text: str, name: str | None, language: str) -> bool:
    text = " ".join((signature_text or "").strip().split())
    if not text or not name:
        return False
    low = text.lower()
    if any(low.startswith(prefix) for prefix in BAD_SIGNATURE_PREFIXES):
        return False
    if any(token in low for token in BAD_SIGNATURE_SUBSTRINGS):
        return False
    if low.startswith(("struct ", "enum ", "union ")) and "(" not in text:
        return False
    if text.endswith(";") and "{" not in text:
        return False
    open_paren = text.find("(")
    if open_paren == -1:
        return False
    prefix = text[:open_paren]
    if "=" in prefix:
        return False
    if language == "c":
        if "typedef" in low:
            return False
        # Require something declaration-like before the function name.
        decl_prefix = prefix.rsplit(name, 1)[0].strip()
        if not decl_prefix:
            return False
        if re.search(r"\b(?:if|for|while|switch|return|case|goto|sizeof)\b", decl_prefix):
            return False
    return True


def extract_param_count_from_signature(signature: str | None) -> int | None:
    _, inside = _extract_decl_name_and_params(signature)
    return _top_level_arg_count(inside)


def _skip_braced_block(lines: list[str], start: int) -> int:
    """Advance past a brace-delimited block beginning at or after *start*.

    Returns the index of the line after the block's matching close brace. If no
    opening brace is found within a short lookahead (e.g. a forward declaration
    like ``struct foo;``), returns ``start`` so the caller can fall through to
    normal handling. The trailing ``};`` (and any ``typedef`` alias) is consumed.
    """
    n = len(lines)
    # Locate the opening brace, allowing a few lines for a multi-line header.
    open_idx = -1
    look = start
    while look < n and look <= start + 4:
        if "{" in lines[look]:
            open_idx = look
            break
        # A ';' before any '{' means this was a forward decl / variable, not a block.
        if ";" in lines[look]:
            return start
        look += 1
    if open_idx == -1:
        return start
    depth = 0
    started = False
    k = open_idx
    while k < n:
        for ch in lines[k]:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
        if started and depth == 0:
            return k + 1
        k += 1
    return start


def extract_brace_methods(lines: list[str], language: str = "unknown") -> list[dict[str, Any]]:
    methods: list[dict[str, Any]] = []
    class_stack: list[str] = []
    n = len(lines)
    i = 0

    while i < n:
        line = lines[i]
        stripped = line.strip()
        if (
            not stripped
            or stripped.startswith("#")
            or stripped.startswith("//")
            or stripped.startswith("/*")
            or stripped.startswith("*/")
            or stripped.startswith("*")
        ):
            i += 1
            continue
        # Skip standalone or trailing block closers before attempting to
        # interpret the following lines as a new declaration. Otherwise the
        # scanner can start a "signature" on a previous function's closing
        # brace and merge adjacent C functions together.
        if stripped.startswith("}") and "(" not in stripped:
            i += 1
            continue

        # C-family files frequently place ordinary statements or declarations
        # immediately before the next function definition. If we start the
        # signature scanner on a plain semicolon-terminated line such as
        # ``return foo;`` or ``unsigned char header[18];``, the scanner can
        # greedily merge that line into the following function signature and
        # drop the real method. Skip those obvious non-signature starts early.
        if language in ("c", "unknown") and ";" in stripped and "(" not in stripped and "{" not in stripped:
            i += 1
            continue

        if language == "java":
            class_match = TYPE_DECL_RE.search(stripped)
            if class_match and "(" not in stripped:
                brace_delta = stripped.count("{") - stripped.count("}")
                if brace_delta > 0:
                    class_stack.append(class_match.group(2))
                i += 1
                continue

        # C/C++: skip aggregate type declarations (struct/union/enum). Two shapes:
        #   1) a definition with a brace body: struct foo { ... };  (or typedef ...)
        #   2) a single-line forward decl / typedef alias: typedef struct X Y;
        # Both must be consumed without entering the function-signature scanner;
        # otherwise the brace body desyncs the scanner, or the trailing ';' line is
        # greedily merged into the *next* function's signature and that function is
        # dropped.
        if language in ("c", "unknown") and STRUCT_DECL_RE.match(stripped) and "(" not in stripped:
            block_end = _skip_braced_block(lines, i)
            if block_end > i:
                i = block_end
                continue
            # No brace body found within lookahead -> single-line decl. Advance past
            # it (consuming continuation lines up to its terminating ';').
            if "{" not in stripped:
                k = i
                while k < n and ";" not in lines[k] and "{" not in lines[k]:
                    k += 1
                i = k + 1 if k < n else n
                continue

        start_idx = i
        sig_lines: list[str] = []
        while i < n and lines[i].strip().startswith("@"):
            sig_lines.append(lines[i])
            i += 1
        if i >= n:
            break

        found_paren = False
        paren_depth = 0
        j = i
        while j < n:
            part = lines[j]
            sig_lines.append(part)
            paren_depth += part.count("(") - part.count(")")
            if "(" in part:
                found_paren = True
            if "{" in part or (found_paren and paren_depth == 0 and ";" in part):
                break
            j += 1

        signature_text = " ".join(sig_lines).strip()
        name, _inside = _extract_decl_name_and_params(signature_text)
        if not found_paren or not name or name in CONTROL_WORDS:
            close_braces = stripped.count("}")
            for _ in range(close_braces):
                if class_stack:
                    class_stack.pop()
            i = max(j + 1, start_idx + 1)
            continue
        if not _looks_like_function_signature(signature_text, name, language):
            i = max(j + 1, start_idx + 1)
            continue
        # Type declarations, not methods. `enum` and `record` are left out on
        # purpose: they are ordinary identifiers in C, and a parameter such as
        # `struct record *r` would otherwise discard the whole function.
        if "class " in signature_text or "interface " in signature_text or "abstract " in signature_text:
            i = max(j + 1, start_idx + 1)
            continue
        if ";" in sig_lines[-1] and "{" not in sig_lines[-1]:
            i = j + 1
            continue

        depth = 0
        started = False
        k = start_idx
        while k < n:
            for ch in lines[k]:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
            if started and depth == 0:
                end = k + 1
                snippet = lines[start_idx:end]
                class_path = "::".join(class_stack) if class_stack else "Global"
                methods.append(
                    {
                        "name": name,
                        "start_line": start_idx + 1,
                        "end_line": end,
                        "signature": lines[i].strip(),
                        "class_path": class_path,
                        "code": "\n".join(snippet),
                        "param_count": extract_param_count_from_signature(signature_text),
                    }
                )
                i = end
                break
            k += 1
        else:
            end = min(n, start_idx + 120)
            snippet = lines[start_idx:end]
            methods.append(
                {
                    "name": name,
                    "start_line": start_idx + 1,
                    "end_line": end,
                    "signature": lines[i].strip(),
                    "class_path": "::".join(class_stack) if class_stack else "Global",
                    "code": "\n".join(snippet),
                    "param_count": extract_param_count_from_signature(signature_text),
                }
            )
            i = end
            continue

    if not methods:
        methods.append(
            {
                "name": "ENTIRE_FILE",
                "start_line": 1,
                "end_line": n,
                "signature": "",
                "class_path": "Global",
                "code": "\n".join(lines),
                "param_count": 0,
            }
        )
    return methods
