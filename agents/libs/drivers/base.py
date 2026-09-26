"""The analysis-driver contract.

Every tool the pipeline calls — Spoon, Soot, Comex, Joern, the heuristic
fallback — is wrapped as a driver with the same call shape and the same reply
shape, so a new tool can be added by writing one class and registering it.

    @register
    class MyDriver(AnalysisDriver):
        name = "mytool"                 # lands in payload["tool"]
        languages = frozenset({"c"})    # or {"*"} for any
        modes = frozenset({"cfg"})      # see MODES below

        def analyze(self, source_path, mode, **kw) -> dict: ...

Reply shape: always a dict carrying `tool` and `status`. On success the body
key is fixed per mode, so callers never branch on which driver answered:

    ast | cfg | dfg   -> {"classes": [{"name": ..., "methods": [...]}]}
    method_map        -> {"methods": [...]}
    member_types      -> {"accesses": [...]}
    slice | forward_slice -> {"slice_lines", "slice_stmts", "slice_code", ...}

On failure: {"tool", "status": "error", "message"} plus whatever context the
driver wants to add. Callers decide what to do about it; the agent for a
language with a fallback tries the next driver, and one without a fallback
logs the message and passes the error payload through.

The language-to-driver mapping lives in the agents, not in this registry.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable

MODES = ("ast", "cfg", "dfg", "method_map", "member_types", "slice", "forward_slice")

# Body key each mode answers with, used to check a driver kept the contract.
MODE_BODY_KEY = {
    "ast": "classes",
    "cfg": "classes",
    "dfg": "classes",
    "method_map": "methods",
    "member_types": "accesses",
    "slice": "slice_code",
    "forward_slice": "slice_code",
}


class AnalysisDriver:
    """One tool. Subclasses set name/languages/modes and implement analyze()."""

    name: str = ""
    languages: frozenset[str] = frozenset({"*"})
    modes: frozenset[str] = frozenset()

    def supports(self, language: str, mode: str) -> bool:
        lang_ok = "*" in self.languages or (language or "") in self.languages
        return lang_ok and mode in self.modes

    def ensure_ready(self) -> bool:
        """Build/compile whatever the tool needs. False means unavailable."""
        return True

    def analyze(self, source_path: Path, mode: str, **kwargs: Any) -> Dict[str, Any]:
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<driver {self.name} languages={sorted(self.languages)} modes={sorted(self.modes)}>"


_REGISTRY: Dict[str, AnalysisDriver] = {}


def register(cls):
    """Class decorator: instantiate and register the driver under its name."""
    driver = cls()
    if not driver.name:
        raise ValueError(f"{cls.__name__} must set a name")
    unknown = set(driver.modes) - set(MODES)
    if unknown:
        raise ValueError(f"{driver.name} declares unknown modes: {sorted(unknown)}")
    _REGISTRY[driver.name] = driver
    return cls


def get(name: str) -> AnalysisDriver:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"No driver named {name!r}; registered: {sorted(_REGISTRY)}") from None


def registered(language: str | None = None, mode: str | None = None) -> list[AnalysisDriver]:
    """Drivers, optionally filtered — for diagnostics and `--list-drivers`."""
    out = list(_REGISTRY.values())
    if language is not None or mode is not None:
        out = [d for d in out if d.supports(language or "*", mode or next(iter(d.modes), ""))]
    return sorted(out, key=lambda d: d.name)


def chain(names: Iterable[str]) -> list[AnalysisDriver]:
    """Resolve an ordered fallback list of driver names."""
    return [get(n) for n in names]


# --- reply helpers --------------------------------------------------------
def error_payload(tool: str, message: str, **extra: Any) -> Dict[str, Any]:
    payload = {"tool": tool, "status": "error", "message": message}
    payload.update({k: v for k, v in extra.items() if v not in (None, "", [], {})})
    return payload


def normalize_envelope(payload: Any, tool: str) -> Dict[str, Any]:
    """Coerce a tool's raw reply into the contract.

    Stamps `tool`, and lifts the `data` wrapper some tools use (Spoon) so every
    driver answers `classes` at the top level — that is what lets the
    method-selection code stop knowing two shapes.

    `status` is passed through as the tool reported it; the tools do not agree on
    its vocabulary ("ok" vs "success").
    """
    if not isinstance(payload, dict):
        return error_payload(tool, "driver returned a non-dict payload")
    out = dict(payload)
    out.setdefault("tool", tool)
    data = out.get("data")
    if isinstance(data, dict):
        lifted = False
        for key in ("classes", "methods", "accesses"):
            if key in data and key not in out:
                out[key] = data[key]
                lifted = True
        if lifted:
            out.pop("data", None)
    return out


def is_error(payload: Any) -> bool:
    """True when a driver reported failure, whatever status word it used."""
    return not isinstance(payload, dict) or str(payload.get("status") or "").strip().lower() == "error"
