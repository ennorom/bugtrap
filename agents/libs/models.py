"""Model resolution, LLM dispatch, and context-window budgeting.

The backend helpers live in agents/utils/llm and are imported lazily, so a run
that never touches a backend does not need its dependencies installed.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from agents.libs.logging_utils import log_llm_exchange, timestamp

QWEN_MODEL_NAME = "Qwen/Qwen2.5-Coder-32B-Instruct"
QWEN_MODEL_CACHE = "/local/home/ennorom/projects/model_cache"

GPT_ALIASES = {
    "gpt": "gpt-5.4",
    "gpt-5.4": "gpt-5.4",
    "gpt4mini": "gpt-4.1-mini",
    "gpt5mini": "gpt-5-mini"
}

# Context windows used to size the prompt. Unknown models get the default.
DEFAULT_MODEL_CONTEXT_TOKENS = 128000
MODEL_CONTEXT_TOKENS = {
    "gpt-5.4": 400000,
    "gpt-5-mini": 400000,
    "gpt-4.1-mini": 1000000,
    QWEN_MODEL_NAME: 32768,
}


class QwenPromptTooLong(RuntimeError):
    pass


def resolve_model(name: str | None, cache_override: str | None = None,
                  strict: bool = True) -> Dict[str, Any]:
    """Map a CLI model token onto a backend config.

    strict=True raises on an unknown token (the behaviour of the sink, planner,
    internal and decision agents). strict=False falls back to Qwen, which is
    what the knowledge-base builder has always done.
    """
    token = (name or "qwen").strip().lower()
    qwen = {"backend": "qwen", "model": QWEN_MODEL_NAME,
            "cache": cache_override or QWEN_MODEL_CACHE}
    if token in GPT_ALIASES:
        return {"backend": "gpt", "model": GPT_ALIASES[token]}
    if not strict:
        return qwen
    if token == "claude":
        return {"backend": "claude", "model": "claude-3-5-sonnet-latest"}
    if token == "gemini":
        return {"backend": "gemini", "model": "gemini-1.5-pro"}
    if token == "qwen":
        return qwen
    raise ValueError(f"Unsupported model backend: {name}")


def qwen_pipe(model_cfg: Dict[str, Any], pipe: Any | None = None):
    if pipe is not None:
        return pipe
    try:
        from agents.utils.llm.llm_utils import get_pipe
    except Exception as exc:
        raise RuntimeError(
            "Qwen backend dependencies are unavailable. Install transformers/torch or use --model gpt."
        ) from exc
    return get_pipe(model_cfg["model"], model_cfg.get("cache") or QWEN_MODEL_CACHE)


def _check_qwen_prompt_length(pipe: Any, system_prompt: str, user_prompt: str,
                              max_new_tokens: int) -> None:
    """Refuse a Qwen prompt that cannot fit alongside the requested output."""
    tokenizer = pipe.tokenizer
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}]
    try:
        prompt_len = len(tokenizer.apply_chat_template(
            messages, tokenize=True, add_generation_prompt=True))
    except Exception:
        prompt_len = len(tokenizer(system_prompt + "\n\n" + user_prompt,
                                   add_special_tokens=True,
                                   truncation=False)["input_ids"])
    model_limit = getattr(tokenizer, "model_max_length", 4096) or 4096
    if model_limit > 1000000:
        model_limit = 4096
    if prompt_len + max_new_tokens > model_limit:
        raise QwenPromptTooLong(
            f"qwen prompt too long: prompt_tokens={prompt_len}, "
            f"max_new_tokens={max_new_tokens}, model_limit={model_limit}"
        )


def generate(system_prompt: str, user_prompt: str, model_cfg: Dict[str, Any],
             max_new_tokens: int, pipe: Any | None = None,
             guard_prompt_length: bool = False) -> str:
    """Send one system+user exchange to the configured backend, return raw text.

    Callers keep their own logging, JSON extraction and validation.
    """
    backend = model_cfg.get("backend")
    if backend == "gpt":
        from agents.utils.llm.openai_utils import call_chat_completion
        return call_chat_completion(system_prompt, user_prompt, model_cfg["model"],
                                    max_new_tokens=max_new_tokens)
    if backend == "qwen":
        pipe = qwen_pipe(model_cfg, pipe)
        if guard_prompt_length:
            _check_qwen_prompt_length(pipe, system_prompt, user_prompt, max_new_tokens)
        messages = [{"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}]
        out = pipe(messages, max_new_tokens=max_new_tokens, batch_size=1)
        return out[0]["generated_text"][-1]["content"]
    if backend == "claude":
        from agents.utils.llm import claude_utils
        caller = getattr(claude_utils, "call_claude_chat_completion", None)
        if caller is not None:
            return caller(system_prompt, user_prompt, model_cfg["model"],
                          max_tokens=max_new_tokens)
        return claude_utils.call_chat_completion(system_prompt, user_prompt,
                                                model_cfg["model"],
                                                max_new_tokens=max_new_tokens)
    if backend == "gemini":
        from agents.utils.llm.gemini_utils import call_gemini_chat_completion
        return call_gemini_chat_completion(system_prompt, user_prompt, model_cfg["model"],
                                          max_tokens=max_new_tokens)
    raise ValueError(f"Unsupported model backend: {backend}")


# --- context-window budgeting ---------------------------------------------
_ENCODER_CACHE: Dict[str, Any] = {}


def _get_encoder(model: str):
    key = model or ""
    if key in _ENCODER_CACHE:
        return _ENCODER_CACHE[key]
    encoder = None
    try:
        import tiktoken
        try:
            encoder = tiktoken.encoding_for_model(model)
        except Exception:
            for name in ("o200k_base", "cl100k_base"):
                try:
                    encoder = tiktoken.get_encoding(name)
                    break
                except Exception:
                    continue
    except Exception:
        encoder = None
    _ENCODER_CACHE[key] = encoder
    return encoder


def estimate_tokens(text: str, model: str = "") -> int:
    """Token count for *text*, exact via tiktoken when available.

    Falls back to the standard ~4 chars/token approximation, which runs a
    little high for code and therefore errs toward a smaller prompt.
    """
    if not text:
        return 0
    encoder = _get_encoder(model)
    if encoder is not None:
        try:
            return len(encoder.encode(text))
        except Exception:
            pass
    return max(1, len(text) // 4)


def model_context_window(model: str) -> int:
    return MODEL_CONTEXT_TOKENS.get(model, DEFAULT_MODEL_CONTEXT_TOKENS)


def chat(base_dir: Path, agent: str, scanned_file: str, system_prompt: str,
         user_prompt: str, model_cfg: Dict[str, Any], max_new_tokens: int,
         pipe: Any | None = None, guard_prompt_length: bool = False) -> str:
    """generate() plus the transcript the agents write for each exchange.

    Parsing and validation stay with the caller: each agent expects a different
    JSON shape back.
    """
    ts = timestamp()
    text = generate(system_prompt, user_prompt, model_cfg, max_new_tokens,
                    pipe=pipe, guard_prompt_length=guard_prompt_length)
    log_llm_exchange(base_dir, agent, scanned_file, ts, system_prompt, user_prompt, text)
    return text
