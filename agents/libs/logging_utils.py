"""Prompt and tool-output logging shared by the lite agents.

Each agent keeps its own artefact directories, so the agent's own directory is
passed in as *base_dir*: prompts land in <base_dir>/prompts/<bug_rule>/ and
LLM / tool transcripts in <base_dir>/logs/, exactly as before.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path


def safe_bug_name(bug: str) -> str:
    return re.sub(r"[^\w.-]", "_", bug or "unknown")


def safe_file_name(name: str) -> str:
    return re.sub(r"[^\w.-]", "_", name or "unknown")


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def log_prompt(base_dir: Path, bug_rule: str, label: str, content: str) -> None:
    out_dir = Path(base_dir) / "prompts" / safe_bug_name(bug_rule)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{label}_{timestamp()}.txt").write_text(content, encoding="utf-8")


def log_llm_exchange(base_dir: Path, agent: str, scanned_file: str, ts: str,
                     system_prompt: str, user_prompt: str,
                     raw_response: str) -> None:
    log_dir = Path(base_dir) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    safe_file = safe_file_name(scanned_file)
    (log_dir / f"{agent}_prompt_{ts}_{safe_file}.txt").write_text(
        f"scanned_file: {scanned_file}\n\nSYSTEM PROMPT:\n{system_prompt}\n\nUSER PROMPT:\n{user_prompt}\n",
        encoding="utf-8",
    )
    (log_dir / f"{agent}_raw_{ts}_{safe_file}.txt").write_text(
        f"scanned_file: {scanned_file}\n\nRAW RESPONSE:\n{raw_response}\n",
        encoding="utf-8",
    )


def log_raw_tool_output(base_dir: Path, agent: str, tool: str, scanned_file: str,
                        ts: str, stdout: str, stderr: str) -> None:
    log_dir = Path(base_dir) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    safe_file = safe_file_name(scanned_file)
    out_path = log_dir / f"{agent}_{tool}_raw_{ts}_{safe_file}.txt"
    out_path.write_text(
        f"scanned_file: {scanned_file}\n"
        f"tool: {tool}\n\n"
        f"STDOUT:\n{stdout}\n\nSTDERR:\n{stderr}\n",
        encoding="utf-8",
    )
