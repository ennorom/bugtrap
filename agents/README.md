# Analyzer agents

This directory holds the agent pipeline that decides whether a line flagged for a
CWE is a real instance of that bug. Each decision comes from a language model, but
the model never sees raw source alone: every candidate is backed by static analysis
evidence (Joern for C/C++, Spoon/Soot/Comex for Java) and judged against a
knowledge base of bug patterns learned from real fixes.

There are two halves. **Training** turns labelled buggy/fixed pairs into reusable
bug patterns. **Testing** runs four agents over a source file and produces one
verdict per candidate line.

```
TRAINING
  preprocessing_agent_lite.py  ->  preprocessing_output.json
  knowledge_base_lite.py       ->  knowledge_base_lite.json

TESTING (per source file)
  sink_point_agent_lite.py     ->  sink_point_candidates.json
  planner_agent_lite.py        ->  planner_decision.json
  internal_anlaysis_agent_lite.py -> internal_analysis_decision.json
  decision_agent_lite.py       ->  decision.json
```

Each stage reads the previous stage's JSON and adds fields to the same candidate
records, so a finished decision file still carries the sink justification, the
chosen analysis tool, the graph evidence and the slices that produced it.

## Training agents

**`preprocessing_agent/preprocessing_agent_lite.py`** takes a training manifest of
CWE cases, each with a buggy and a fixed revision, and builds one learning example
per case: the changed lines on both sides, the enclosing method, backward and
forward slices rooted at those lines, and a slice-local CFG summary. In diff mode
the buggy and fixed sides are paired so the learner can see what the fix changed.
Output is `preprocessing_output.json`.

**`knowledge_base/knowledge_base_lite.py`** reads those examples and grows the
knowledge base incrementally. For each example it extracts retrieval tags, fetches
the closest existing patterns by tag overlap, then asks the model to MATCH an
existing pattern, REFINE one, or declare NO_MATCH. Unmatched examples accumulate
until there are enough to propose a new pattern. Relearning is the same pass with
extra context attached: the labelled buggy lines, a human description of the
failure, and the previous agent's incorrect reasoning.

A knowledge base entry, keyed by CWE, holds:

| field | contents |
|---|---|
| `description` | CWE summary, mitigations, demonstrative examples, CVE corpus |
| `program_patterns.patterns[]` | `pattern_id`, `shape`, `sink_role`, `prototype` (buggy/fixed), `cfg_shape` with the `constraint` used as the violation criterion, `tags`, `support` |
| `program_patterns.uncategorized[]` | examples still waiting to form a pattern |
| `library_safety_registry` | unsafe API to safe sibling, e.g. `dyn_cast` to `dyn_cast_or_null` |

## Testing agents

**`sink_point_agent/sink_point_agent_lite.py`** scans a file method by method and
proposes candidate lines. The prompt carries the pattern catalog for the rule, and
the agent is deliberately generous: it surfaces anything that resembles a pattern
and leaves the filtering to the decision agent. Returned line numbers are
reconciled against the real source, so a hallucinated line is dropped rather than
trusted. Each candidate is then enriched with the methods it calls
(`secondary_methods`) and callees resolved in other files (`external_methods`).

**`planner_agent/planner_agent_lite.py`** picks one analysis graph per candidate:
AST for structural checks, CFG when the verdict depends on paths and guards, DFG
when it depends on how a value propagates. It sees the justification and the call
context, not the code.

**`internal_analysis_agent/internal_anlaysis_agent_lite.py`** runs that graph. C
and C++ go to Joern, which also supplies declared member types for nested field
accesses. Java goes to Spoon for AST and Soot for CFG/DFG, falling back to Comex
and then to a line-by-line stand-in if both fail. Whatever the tool, the output is
normalised to one shape and reduced to the single method the candidate sits in.

**`decision_agent/decision_agent_lite.py`** returns `Yes`, `No` or `Unknown` per
candidate. It matches the candidate to the pattern whose violation criterion fits,
then tests three things: whether the candidate performs the dangerous operation on
a named value, whether a complete protection for that exact value exists and
dominates the site, and whether any path can bypass or invalidate it. A `No`
requires all three, each with a line citation. `Unknown` is reserved for
candidates whose analysis evidence is missing, which are not sent to the model at
all.

## runner.py

`runner.py` drives the test side over a manifest. For each selected row it
resolves the case source and its code base, runs the four agents in order as
subprocesses, and copies the decision file out under a per-run name. All commands
run from `agents/`:

```
python3 runner.py --manifest-dir ../secvuleval/cwe_416_manifest --test-manifest ../secvuleval/cwe_416_manifest/testing_high_quality_v1_cwe_416.json --kb knowledge_base/knowledge_base_lite.json --model gpt-4mini --mode diff --decision-context slice --test-only --start-row 1 --stop-row 5 --decision-output output-416-p1
```

Rows are selected by 1-based position with `--start-row/--stop-row` or an explicit
`--rows 3,7,12`. `--decision-context slice` gives the decision agent a Joern slice
rooted at each candidate instead of the whole method, which is more precise and
considerably slower. `--engine` only affects Java. Training is run by invoking the
two training scripts directly; see `documentation/` for those recipes and for the
scoring step in `classification/`.

## Folders

| path | contents |
|---|---|
| `sink_point_agent/` | the sink agent, plus `build/` with the Spoon method-map driver |
| `planner_agent/` | the planner agent |
| `internal_analysis_agent/` | the analysis agent, `build/` with the Java driver sources, and `libs/` with their JARs |
| `decision_agent/` | the decision agent and the per-run output directories |
| `knowledge_base/` | the knowledge base builder and the `knowledge_base_lite*.json` files |
| `preprocessing_agent/` | the training-example builder |
| `libs/` | shared code: language detection and source parsing, JSON and prompt-log helpers, model dispatch and token budgeting, driver payload normalisation, method matching, slice context, and the knowledge-base rendering used by the prompts |
| `libs/drivers/` | one module per tool (`spoon`, `soot`, `comex`, `joern`, `heuristic`) behind a single contract, plus `joern_scripts/` with the Joern queries |
| `classification/` | scores decision files against the labelled sinks and reports TP/FP/FN |
| `files/` | CWE rule definitions, including `bug_rules_cwe.json` |
| `cwe_code_paper/` | extracted buggy/fixed snippets referenced by the manifests |
| `documentation/` | command recipes for training, testing and scoring |
| `utils/` | standalone helper scripts, not part of the pipeline |

## Adding a tool

Drivers are registered by name and share one call and reply shape, described in
`libs/drivers/base.py`. Write `libs/drivers/<yourtool>.py` with a class decorated
`@register`, add one import line to `libs/drivers/__init__.py`, and name it in the
agent that should use it. The language-to-tool mapping is written out in
`internal_anlaysis_agent_lite.py` rather than inferred, so the choice stays
reviewable.

## Requirements

- Python 3.12 with the `openai` package, and `OPENAI_API_KEY` in the environment.
- Joern on `PATH` for C and C++ analysis.
- JDK 17 for the Spoon, Soot and Comex drivers. They are compiled on first use;
  a mismatched `java` silently falls back to weaker analysis.
