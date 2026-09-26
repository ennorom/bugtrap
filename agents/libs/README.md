# agents/libs

Shared code for the lite agent pipeline. The agents keep their own algorithm —
prompt construction, the per-candidate loop, the learning loop, and the decision
rules — and the runner keeps the orchestration. Everything else comes from here.

## General libraries

| module | what it holds |
|---|---|
| `language_support.py` | language detection, comment-aware source reading, brace-matched method extraction |
| `jsonio.py` | reading/writing the hand-off files, and salvaging a JSON object from a fenced, truncated or control-char-laden model reply |
| `logging_utils.py` | prompt and transcript logging; each agent passes its own directory, so artefacts stay under `<agent>/prompts/` and `<agent>/logs/` |
| `models.py` | model-token resolution, `generate()` / `chat()` dispatch for gpt/qwen/claude/gemini, token counting, context-window sizes |
| `source_parsing.py` | method boundaries, signatures, declared-type maps, and resolving a callee name to the file that defines it |
| `method_index.py` | line→method index and class-name detection for a file (what the internal agent needs to locate a candidate) |
| `method_match.py` | picking the candidate's method out of a driver payload (name → line range → param count → signature → statement probe) |
| `graph_payloads.py` | normalising CFG/DFG output from any driver into one shape, plus the heuristic stand-in graphs |
| `supporting_context.py` | the `secondary_methods` / `external_methods` block attached to each sink candidate |
| `evidence.py` | compact vs full shaping of candidate evidence for the decision and planner prompts |
| `kb_context.py` | the KB block the decision agent judges against, sized to the model's remaining context window |
| `kb_schema.py` | the knowledge-base entry shape and tag-overlap retrieval over it |
| `kb_evidence.py` | rendering one training example (targets, slices, relearning context) for the KB prompts |
| `pattern_filter.py` | cheap regex pre-filter for KB patterns by their `cfg_shape.nodes` |
| `slice_context.py` | backward/forward slice context for one candidate, with line probing and window fallback |
| `manifest.py` | manifest/CSV row selection for a run (row windows, explicit rows, vulnerable-only training filter) |
| `case_sources.py` | locating one manifest case's source file and its code base, including the cached git checkout |
| `fsutil.py` | the runner's small filesystem helpers |

The backend modules `openai_utils`, `llm_utils`, `claude_utils` and
`gemini_utils` are deliberately **not** here: each agent directory holds its own
copy and they are not identical, so `models.generate()` imports them by bare
name and lets each agent's `sys.path` decide which copy is used.

## Tool drivers (`libs/drivers/`)

Every tool is a driver with one call shape and one reply shape, registered by
name in `base.py`. To add a tool: write `libs/drivers/<yourtool>.py` with a
class decorated `@register`, then add one import line to `drivers/__init__.py`.

```python
from agents.libs.drivers import get
get("comex").analyze(path, "cfg", class_name="Foo", scanned_file="Foo.java")
```

Reply: always `{"tool", "status", ...}`, with the body key fixed per mode —
`classes` for ast/cfg/dfg, `methods` for method_map, `accesses` for
member_types, slice fields for slice/forward_slice. `status` is passed through
as the tool reported it ("ok" vs "success" differ between tools and rewriting
it would change payloads already recorded in past runs).

**Which driver serves which language stays in the agents**, not in the
registry: the internal analysis agent names `joern` for C/C++ (one tool, no
fallback — a failure is logged and returned) and `spoon` / `soot` → `comex` →
`heuristic` for Java.

| module | what it is | assets |
|---|---|---|
| `base.py` | the contract, the registry, reply helpers | — |
| `java_runtime.py` | shared JVM plumbing: classpaths, on-demand compile, subprocess call | driver sources and JARs in `internal_analysis_agent/{build,libs}/` |
| `spoon.py` | `spoon` driver — Java `ast` and `method_map` | `sink_point_agent/build/SpoonMethodMapDriver.java` |
| `soot.py` | `soot` driver — Java `cfg`, `dfg` | via `java_runtime` |
| `comex.py` | `comex` driver — Java `cfg`, `dfg`, with its interface-compat retry | via `java_runtime` |
| `joern.py` | `joern` driver — C/C++ `ast`/`cfg`/`dfg`/`member_types`/`slice`/`forward_slice` | `joern_scripts/*.sc` next to it |
| `heuristic.py` | `heuristic` driver — line-by-line stand-in, end of the Java chain | — |

One module per tool, named after the tool; class `<Tool>Driver`; registry name
the lowercase tool name. `libs/slice_context.py` is *not* a driver — it is the
candidate-level slice context the decision agent builds *using* the joern
driver, so it sits with the other libraries.

Java sources and JARs were left where they are on purpose — they are large
binaries owned by the internal analysis agent, and the non-lite agents still
compile against those paths.

## Imports

Agents add the repository root to `sys.path` and import absolutely:

```python
from agents.libs import models
from agents.libs.jsonio import read_json, write_json
from agents.libs.language_support import detect_language_from_path
from agents.libs.drivers.joern import invoke_joern_file
```

Two re-export shims remain so the superseded non-lite agents keep importing
successfully — `agents/language_support.py` and
`agents/internal_analysis_agent/joern_driver.py`. Both can go once those agents
are removed.
