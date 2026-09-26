"""JSON I/O and LLM-output repair.

Reads and writes the agent hand-off files, and salvages a JSON object from a
model reply that arrived fenced, truncated, or with raw control characters in
its strings.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List


def dump_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def strip_markdown_fences(text: str) -> str:
    cleaned = (text or "").strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    return cleaned.strip()


def extract_first_balanced_json_object(text: str) -> str | None:
    if not text:
        return None
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    escape = False
    for idx in range(start, len(text)):
        ch = text[idx]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:idx + 1]
    return None


def escape_control_chars_in_json_strings(text: str) -> str:
    if not text:
        return text
    out: list[str] = []
    in_str = False
    escape = False
    for ch in text:
        if escape:
            out.append(ch)
            escape = False
            continue
        if ch == "\\":
            out.append(ch)
            escape = True
            continue
        if ch == '"':
            out.append(ch)
            in_str = not in_str
            continue
        if in_str:
            if ch == "\n":
                out.append("\\n")
                continue
            if ch == "\r":
                out.append("\\r")
                continue
            if ch == "\t":
                out.append("\\t")
                continue
            if ord(ch) < 0x20:
                out.append(f"\\u{ord(ch):04x}")
                continue
        out.append(ch)
    return "".join(out)


def recover_candidate_list_object(text: str) -> Dict[str, Any] | None:
    cleaned = escape_control_chars_in_json_strings(strip_markdown_fences(text))
    key_idx = cleaned.find('"candidates"')
    if key_idx == -1:
        return None
    list_idx = cleaned.find("[", key_idx)
    if list_idx == -1:
        return None
    decoder = json.JSONDecoder()
    items: List[Dict[str, Any]] = []
    rest = cleaned[list_idx + 1:]
    while rest:
        rest = rest.lstrip()
        if not rest or rest[0] == "]":
            break
        if rest[0] == ",":
            rest = rest[1:]
            continue
        try:
            item, end = decoder.raw_decode(rest)
        except Exception:
            break
        if not isinstance(item, dict):
            break
        items.append(item)
        rest = rest[end:]
    if not items:
        return None
    return {"candidates": items}


def load_llm_json_object(text: str) -> Dict[str, Any]:
    cleaned = strip_markdown_fences(text)

    candidates: List[str] = []
    if cleaned:
        candidates.append(cleaned)
        balanced = extract_first_balanced_json_object(cleaned)
        if balanced:
            candidates.append(balanced)
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1:
            candidates.append(cleaned[start:])
            if end != -1 and end > start:
                candidates.append(cleaned[start:end + 1])

    decoder = json.JSONDecoder()
    last_exc: Exception | None = None
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized = escape_control_chars_in_json_strings(candidate)
        for attempt in (
            normalized,
            re.sub(r",(\s*[}\]])", r"\1", normalized),
        ):
            try:
                data, _ = decoder.raw_decode(attempt.lstrip())
                if isinstance(data, dict):
                    return data
                last_exc = ValueError("LLM output root must be a JSON object")
            except Exception as exc:
                last_exc = exc
    recovered = recover_candidate_list_object(text)
    if recovered is not None:
        return recovered
    if last_exc:
        raise last_exc
    raise ValueError("Empty LLM output")


# ---------- JSON parsing ----------
def extract_json_object(text: str) -> Dict[str, Any] | None:
    s, e = text.find("{"), text.rfind("}")
    if s < 0 or e <= s:
        return None
    try:
        return json.loads(text[s:e + 1])
    except Exception:
        return None


def extract_json_array(text: str) -> List[Any] | None:
    s, e = text.find("["), text.rfind("]")
    if s < 0 or e <= s:
        return None
    try:
        return json.loads(text[s:e + 1])
    except Exception:
        return None


def atomic_write(path: Path, obj: Any) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def read_json(p: Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
