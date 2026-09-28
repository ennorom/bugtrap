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
  preprocessing agent   ->  preprocessing_output.json
  knowledge base        ->  knowledge_base_lite.json

TESTING (per source file)
  sink point agent      ->  sink_point_candidates.json
  planner agent         ->  planner_decision.json
  internal analysis     ->  internal_analysis_decision.json
  decision agent        ->  decision.json
```

Each stage reads the previous stage's JSON and adds fields to the same candidate
records, so a finished decision file still carries the sink justification, the
chosen analysis tool, the graph evidence and the slices that produced it.

## Training agents

**The preprocessing agent** takes a training manifest of
CWE cases, each with a buggy and a fixed revision, and builds one learning example
per case: the changed lines on both sides, the enclosing method, backward and
forward slices rooted at those lines, and a slice-local CFG summary. In diff mode
the buggy and fixed sides are paired so the learner can see what the fix changed.
Output is `preprocessing_output.json`.

**The knowledge base builder** reads those examples and grows the
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

**The sink point agent** scans a file method by method and
proposes candidate lines. The prompt carries the pattern catalog for the rule, and
the agent is deliberately generous: it surfaces anything that resembles a pattern
and leaves the filtering to the decision agent. Returned line numbers are
reconciled against the real source, so a hallucinated line is dropped rather than
trusted. Each candidate is then enriched with the methods it calls
(`secondary_methods`) and callees resolved in other files (`external_methods`).

**The planner agent** picks one analysis graph per candidate:
AST for structural checks, CFG when the verdict depends on paths and guards, DFG
when it depends on how a value propagates. It sees the justification and the call
context, not the code.

**The internal analysis agent** runs that graph. C
and C++ go to Joern, which also supplies declared member types for nested field
accesses. Java goes to Spoon for AST and Soot for CFG/DFG, falling back to Comex
and then to a line-by-line stand-in if both fail. Whatever the tool, the output is
normalised to one shape and reduced to the single method the candidate sits in.

**The decision agent** returns `Yes`, `No` or `Unknown` per
candidate. It matches the candidate to the pattern whose violation criterion fits,
then tests three things: whether the candidate performs the dangerous operation on
a named value, whether a complete protection for that exact value exists and
dominates the site, and whether any path can bypass or invalidate it. A `No`
requires all three, each with a line citation. `Unknown` is reserved for
candidates whose analysis evidence is missing, which are not sent to the model at
all.

## runner.py

`runner.py` runs the four testing agents. It takes either a single source file or
a manifest of cases, resolves the code base so callees in other files can be
found, runs the agents in order as subprocesses, and copies the decision out under
a per-run name. All commands run from `agents/`.

### One file

Point it at any C or C++ file and name the rule to judge it against:

```
python3 runner.py --file /path/to/parse.c --bug CWE-125 --model gpt-4mini --mode diff --decision-output output-adhoc
```

The verdict lands in `decision_agent/output-adhoc/decision_agent_gpt_CWE-125_parse.json`,
with a summary next to the source in `agent_runs/`. Every function in the file is
scanned unless `--target-method read_entry` narrows it. The code base defaults to
the file's own directory, which is what lets callees in sibling files and headers
be resolved; `--code-base-path /path/to/project` widens that to a project root.

`--bug` has to name a rule that exists in the knowledge base, since that is where
the patterns and the violation criteria come from. Check what a knowledge base
covers with:

```
python3 -c "import json;kb=json.load(open('knowledge_base/knowledge_base_lite.json'));print(sorted(r for r,e in kb.items() if (e.get('program_patterns') or {}).get('patterns')))"
```

### A manifest of cases

For batches, a manifest is a JSON list with one entry per case:

```json
[{"_source_row": 1, "bug_type": "CWE-190", "language": "c",
  "procedure": "alloc_items", "is_vulnerable": true,
  "snippet_abs_path": "examples/cwe190/overflow.c"}]
```

`examples/` ships that manifest and a small C file with an integer overflow, so
the pipeline can be exercised without any dataset:

```
python3 runner.py --manifest-dir examples --test-manifest examples/manifest.json --kb knowledge_base/knowledge_base_lite.json --model gpt-4mini --mode diff --test-only --rows 1 --decision-output output-example --output-dir examples/agent_runs
```

`bug_type` selects the rule per case and `procedure` restricts that case to one
function; omit it to scan the whole file.

For a one-off run without the runner, the four agents can be invoked directly:

```
python3 sink_point_agent/sink_point_agent_lite.py --bug CWE-190 --file examples/cwe190/overflow.c --knowledge-base knowledge_base/knowledge_base_lite.json --model gpt-4mini --attribute-mode diff --target-method alloc_items
python3 planner_agent/planner_agent_lite.py --input sink_point_agent/sink_point_candidates.json --output planner_agent/planner_decision.json --model gpt-4mini
python3 internal_analysis_agent/internal_anlaysis_agent_lite.py --input planner_agent/planner_decision.json --file examples/cwe190/overflow.c --output internal_analysis_agent/internal_analysis_decision.json
python3 decision_agent/decision_agent_lite.py --file examples/cwe190/overflow.c --input internal_analysis_agent/internal_analysis_decision.json --output decision.json --model gpt-4mini --knowledge-base knowledge_base/knowledge_base_lite.json
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
| `files/` | CWE rule definitions, including `bug_rules_cwe.json` |
| `utils/` | standalone helper scripts, not part of the pipeline |

## Adding a tool

Drivers are registered by name and share one call and reply shape, described in
`libs/drivers/base.py`. Write `libs/drivers/<yourtool>.py` with a class decorated
`@register`, add one import line to `libs/drivers/__init__.py`, and name it in the
agent that should use it. The language-to-tool mapping is written out in the
internal analysis agent rather than inferred, so the choice stays
reviewable.

## Requirements

- Python 3.12 with the `openai` package, and `OPENAI_API_KEY` in the environment.
- Joern on `PATH` for C and C++ analysis.
- JDK 17 for the Spoon, Soot and Comex drivers. They are compiled on first use;
  a mismatched `java` silently falls back to weaker analysis.
