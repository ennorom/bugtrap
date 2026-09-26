"""Analysis drivers.

Importing this package registers every built-in driver. To add a tool: write
`libs/drivers/<yourtool>.py` with a class decorated `@register` (see
`base.AnalysisDriver` for the contract), then add one import line below.

    from agents.libs.drivers import get, registered
    get("comex").analyze(path, "cfg", class_name="Foo", scanned_file="Foo.java")

Which driver an agent uses for a given language stays written out in that
agent, so the tool choice per language remains explicit and reviewable.

Layout: one module per tool, named after it — `spoon`, `soot`, `comex`,
`joern`, `heuristic` — over the shared `java_runtime` plumbing and the `base`
contract.
"""
from __future__ import annotations

from agents.libs.drivers.base import (  # noqa: F401
    MODES,
    AnalysisDriver,
    error_payload,
    get,
    is_error,
    normalize_envelope,
    register,
    registered,
)

# --- built-in drivers (importing registers them) ---
from agents.libs.drivers import comex as _comex  # noqa: F401,E402
from agents.libs.drivers import heuristic as _heuristic  # noqa: F401,E402
from agents.libs.drivers import joern as _joern  # noqa: F401,E402
from agents.libs.drivers import soot as _soot  # noqa: F401,E402
from agents.libs.drivers import spoon as _spoon  # noqa: F401,E402

__all__ = ["AnalysisDriver", "MODES", "error_payload", "get", "is_error",
           "normalize_envelope", "register", "registered"]
