#!/usr/bin/env python3

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

PYTHON = sys.executable or "python"
from agents.libs.case_sources import (
    derive_external_resolution_inputs,
    resolve_case_source_path,
    sanitize_token,
)
from agents.libs.fsutil import maybe_copy, remove_if_exists
from agents.libs.jsonio import read_json, write_json
from agents.libs.manifest import (
    apply_subset_for_mode,
    filter_test_manifest_to_temp,
    filter_train_csv_to_temp,
    filter_training_csv_to_true_temp,
    parse_rows_arg,
    resolve_manifest_inputs,
)

SCRIPT_DIR = Path(__file__).resolve().parent
DECISION_AGENT_DIR = SCRIPT_DIR / "decision_agent"
DEFAULT_MANIFEST_DIR = SCRIPT_DIR / "cwe_code_paper_manifest_v1"
DEFAULT_TRAIN_CSV = DEFAULT_MANIFEST_DIR / "cwe_manifest_v1_training.csv"
DEFAULT_TEST_JSON = DEFAULT_MANIFEST_DIR / "testing_manifest.json"
DEFAULT_BUGS = SCRIPT_DIR / "files" / "bug_rules_cwe.json"
DEFAULT_OUTPUT_DIR = DEFAULT_MANIFEST_DIR / "agent_runs"
DEFAULT_SINK_FILE = SCRIPT_DIR / "sink_point_agent" / "sink_point_candidates.json"
DEFAULT_PLANNER_FILE = SCRIPT_DIR / "planner_agent" / "planner_decision.json"
DEFAULT_INTERNAL_FILE = SCRIPT_DIR / "internal_analysis_agent" / "internal_analysis_decision.json"
DEFAULT_PREPROCESSING_FILE = SCRIPT_DIR / "preprocessing_agent" / "preprocessing_output.json"
DEFAULT_KB_FILE = SCRIPT_DIR / "knowledge_base" / "knowledge_base_lite.json"
DEFAULT_DECISION_FILE = SCRIPT_DIR / "decision_agent" / "decision.json"
SINK_AGENT_SCRIPT = SCRIPT_DIR / "sink_point_agent" / "sink_point_agent_lite.py"
PLANNER_AGENT_SCRIPT = SCRIPT_DIR / "planner_agent" / "planner_agent_lite.py"
INTERNAL_AGENT_SCRIPT = SCRIPT_DIR / "internal_analysis_agent" / "internal_anlaysis_agent_lite.py"
DECISION_AGENT_SCRIPT = SCRIPT_DIR / "decision_agent" / "decision_agent_lite.py"
PREPROCESSING_AGENT_SCRIPT = SCRIPT_DIR / "preprocessing_agent" / "preprocessing_agent.py"
KNOWLEDGE_BASE_SCRIPT = SCRIPT_DIR / "knowledge_base" / "knowledge_base_lite.py"
LOG_DIR = SCRIPT_DIR / "logs"
LOG_FP = None


def log(message: str) -> None:
    print(message)
    if LOG_FP:
        LOG_FP.write(message + "\n")
        LOG_FP.flush()


def run_step(label: str, cmd: list[str]) -> None:
    log(f"[INFO] Running {label}: {' '.join(str(part) for part in cmd)}")
    subprocess.run(cmd, check=True, cwd=str(SCRIPT_DIR))


def shlex_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def resolve_decision_output_dir(relative_path: str) -> Path:
    base_dir = DECISION_AGENT_DIR.resolve()
    token = (relative_path or "").strip()
    if not token:
        base_dir.mkdir(parents=True, exist_ok=True)
        return base_dir
    raw_path = Path(token)
    if raw_path.is_absolute():
        raise SystemExit("--decision-output must be a relative path under decision_agent.")
    output_dir = (base_dir / raw_path).resolve()
    if output_dir != base_dir and base_dir not in output_dir.parents:
        raise SystemExit("--decision-output must resolve inside decision_agent.")
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def train_agents(train_csv: Path, bug_rules: Path, model: str, mode: str) -> None:
    run_step(
        "preprocessing",
        [
            PYTHON,
            str(PREPROCESSING_AGENT_SCRIPT),
            "--csv",
            str(train_csv),
            "--output",
            str(DEFAULT_PREPROCESSING_FILE),
            "--flow",
            "relearning",
            "--mode",
            str(mode),
        ],
    )
    run_step(
        "knowledge_base",
        [
            PYTHON,
            str(KNOWLEDGE_BASE_SCRIPT),
            "--examples",
            str(DEFAULT_PREPROCESSING_FILE),
            "--bugs",
            str(bug_rules),
            "--output",
            str(DEFAULT_KB_FILE),
            "--model",
            str(model),
            "--mode",
            str(mode),
        ],
    )


def run_case(entry: dict, output_root: Path, decision_output_dir: Path,
             model: str, engine: str,
             decision_analysis_prompt_mode: str,
             sink_attribute_mode: str,
             decision_context: str,
             joern_widen: int = 3,
             kb_path: Path = DEFAULT_KB_FILE) -> dict:
    source_row = entry["_source_row"]
    bug_type = entry["bug_type"]
    source_path = resolve_case_source_path(entry, prefer_buggy=True)
    code_base_path, source_rel_path = derive_external_resolution_inputs(source_path, entry)
    target_method = str(entry.get("procedure") or "").strip()
    case_dir = output_root / f"result_Paper_{source_row}__{sanitize_token(bug_type)}"
    case_dir.mkdir(parents=True, exist_ok=True)
    for legacy_name in ("sink_point_candidates.json", "planner_decision.json", "internal_analysis_decision.json", "decision.json"):
        remove_if_exists(case_dir / legacy_name)

    decision_name = f"decision_agent_gpt_{sanitize_token(bug_type)}_{source_row}.json"
    decision_copy = decision_output_dir / decision_name

    run_step(
        "sink_point_agent",
        [
            PYTHON,
            str(SINK_AGENT_SCRIPT),
            "--bug",
            str(bug_type),
            "--file",
            str(source_path),
            "--knowledge-base",
            str(kb_path),
            "--attribute-mode",
            str(sink_attribute_mode),
            "--target-method",
            str(target_method),
            "--code-base-path",
            str(code_base_path),
            "--source-rel-path",
            str(source_rel_path),
            "--model",
            str(model),
        ],
    )

    run_step(
        "planner_agent",
        [
            PYTHON,
            str(PLANNER_AGENT_SCRIPT),
            "--input",
            str(DEFAULT_SINK_FILE),
            "--output",
            str(DEFAULT_PLANNER_FILE),
            "--model",
            str(model),
        ],
    )
    run_step(
        "internal_analysis_agent",
        [
            PYTHON,
            str(INTERNAL_AGENT_SCRIPT),
            "--input",
            str(DEFAULT_PLANNER_FILE),
            "--file",
            str(source_path),
            "--output",
            str(DEFAULT_INTERNAL_FILE),
            "--engine",
            str(engine),
        ],
    )
    run_step(
        "decision_agent",
        [
            PYTHON,
            str(DECISION_AGENT_SCRIPT),
            "--file",
            str(source_path),
            "--input",
            str(DEFAULT_INTERNAL_FILE),
            "--output",
            str(DEFAULT_DECISION_FILE),
            "--model",
            str(model),
            "--knowledge-base",
            str(kb_path),
            "--analysis-prompt-mode",
            str(decision_analysis_prompt_mode),
            "--decision-context",
            str(decision_context),
            "--joern-widen",
            str(int(joern_widen)),
        ],
    )
    maybe_copy(DEFAULT_DECISION_FILE, decision_copy)
    if not decision_copy.is_file():
        raise FileNotFoundError(f"Expected copied decision output not found: {decision_copy}")

    return {
        "source_row": source_row,
        "bug_type": bug_type,
        "is_vulnerable": entry.get("is_vulnerable"),
        "language": entry.get("language"),
        "snippet_abs_path": str(source_path),
        "target_method": target_method,
        "case_dir": str(case_dir),
        "sink_output": str(DEFAULT_SINK_FILE),
        "planner_output": str(DEFAULT_PLANNER_FILE),
        "internal_output": str(DEFAULT_INTERNAL_FILE),
        "decision_output": str(DEFAULT_DECISION_FILE),
        "decision_copy": str(decision_copy),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Train/test wrapper for the CWE manifest v1 flow.")
    ap.add_argument("--manifest-dir", default=str(DEFAULT_MANIFEST_DIR))
    ap.add_argument("--train-csv", default="", help="Optional explicit training CSV path. Defaults to a CSV inside --manifest-dir.")
    ap.add_argument("--test-manifest", default="", help="Optional explicit testing manifest JSON path. Defaults to a JSON inside --manifest-dir.")
    ap.add_argument("--bugs", default=str(DEFAULT_BUGS))
    ap.add_argument("--kb", default="", help=f"Optional path to the knowledge base JSON for the agents to use. Defaults to {DEFAULT_KB_FILE} when empty.")
    ap.add_argument("--output-dir", default="", help="Optional explicit output directory. Defaults to <manifest-dir>/agent_runs.")
    ap.add_argument("--model", default="gpt", choices=["gpt","gptmini","gpt-4mini","gpt-5mini"])
    ap.add_argument("--engine", default="auto", choices=["auto", "soot", "comex"])
    ap.add_argument("--mode", default="default", choices=["default", "diff"])
    ap.add_argument("--sink-attribute-mode", default="auto", choices=["auto", "default", "diff"],
                    help="How the sink agent should interpret KB attributes: auto follows --mode, diff enables buggy/fixed interpretation.")
    ap.add_argument("--decision-analysis-prompt-mode", default="full", choices=["compact", "full"],
                    help="How much internal-analysis evidence to send to the decision agent. full uses the full internal_analysis_result JSON; compact preserves the previous summarized prompt.")
    ap.add_argument("--decision-context", default="method", choices=["method", "slice"],
                    help="Primary local code context for the decision agent. method passes the full method body; slice passes a backward slice rooted at the candidate line.")
    ap.add_argument("--decision-output", default="", help="Relative subfolder under decision_agent for per-row decision outputs.")
    ap.add_argument("--joern-widen", dest="joern_widen", type=int, default=3,
                    help="Forwarded to decision_agent_lite.py --joern-widen (default 3; pass 0 to disable). "
                         "Same name/semantics as the underlying agent flag.")
    ap.add_argument("--skip-train", action="store_true")
    ap.add_argument("--train-only", action="store_true")
    ap.add_argument("--test-only", action="store_true")
    ap.add_argument("--rows", default="", help="Comma-separated 1-based row positions to process. Uses the same positional semantics as --start-row/--stop-row.")
    ap.add_argument("--start-row", type=int, default=1)
    ap.add_argument("--stop-row", type=int, default=None)
    args = ap.parse_args()
    kb_path = Path(args.kb).expanduser() if args.kb else DEFAULT_KB_FILE
    log(f"[INFO] Knowledge base: {kb_path}")
    if args.train_only and args.test_only:
        raise SystemExit("--train-only and --test-only cannot be used together.")
    if args.start_row < 1:
        raise SystemExit("--start-row must be >= 1.")
    if args.stop_row is not None and args.stop_row < args.start_row:
        raise SystemExit("--stop-row must be >= --start-row.")
    if args.test_only:
        args.skip_train = True
    manifest_dir = Path(args.manifest_dir).expanduser()
    train_csv_default, test_manifest_default, output_dir = resolve_manifest_inputs(
        manifest_dir,
        args.train_csv,
        args.test_manifest,
        args.output_dir,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    decision_output_dir = resolve_decision_output_dir(args.decision_output)
    log_path = LOG_DIR / f"run_agents_on_cwe_manifest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    global LOG_FP
    LOG_FP = log_path.open("w", encoding="utf-8")
    temp_paths: list[Path] = []

    try:
        train_csv_path = train_csv_default
        test_manifest_path = test_manifest_default
        if args.rows:
            selected_rows = parse_rows_arg(args.rows)
            if args.train_only:
                train_csv_path, sliced_count = filter_train_csv_to_temp(train_csv_path, selected_rows)
                temp_paths.append(train_csv_path)
                log(f"[INFO] Training selected _source_row values: {selected_rows} (matched={sliced_count})")
            else:
                test_manifest_path, sliced_count = filter_test_manifest_to_temp(test_manifest_path, selected_rows)
                temp_paths.append(test_manifest_path)
                log(f"[INFO] Testing selected _source_row values: {selected_rows} (matched={sliced_count})")
        else:
            train_csv_path, test_manifest_path, temp_path, sliced_count = apply_subset_for_mode(
                args.train_only,
                train_csv_path,
                test_manifest_path,
                args.start_row,
                args.stop_row,
            )
            if temp_path is not None:
                temp_paths.append(temp_path)
                subset_label = "Training" if args.train_only else "Testing"
                log(f"[INFO] {subset_label} subset rows selected: {sliced_count} (start={args.start_row}, stop={args.stop_row})")

        _model_label = {
            "gpt": "gpt-5.4", "gpt-5.4": "gpt-5.4",
            "gptmini": "gpt-4.1-mini", "gpt-mini": "gpt-4.1-mini", "gpt4mini": "gpt-4.1-mini",
            "gpt-4mini": "gpt-4.1-mini", "gpt-4-mini": "gpt-4.1-mini", "gpt-4.1-mini": "gpt-4.1-mini",
            "gpt5mini": "gpt-5-mini", "gpt-5mini": "gpt-5-mini", "gpt-5-mini": "gpt-5-mini",
        }.get(str(args.model).lower(), str(args.model))
        log(f"[INFO] Model selection: {args.model} -> {_model_label}")

        if not args.skip_train:
            true_only_train_csv, true_count, original_count = filter_training_csv_to_true_temp(train_csv_path)
            temp_paths.append(true_only_train_csv)
            train_csv_path = true_only_train_csv
            log(f"[INFO] Training rows filtered to is_vulnerable=true: {true_count}/{original_count}")
            if true_count == 0:
                raise SystemExit("No is_vulnerable=true rows remain in the selected training CSV.")
            train_agents(train_csv_path, Path(args.bugs), args.model, args.mode)
        elif not kb_path.is_file():
            raise SystemExit(f"--skip-train was used but the expected knowledge base does not exist at {kb_path}.")

        if args.train_only:
            log(f"\n[DONE] Training outputs written to: {DEFAULT_PREPROCESSING_FILE} and {DEFAULT_KB_FILE}")
            return

        test_entries = read_json(test_manifest_path)
        if not isinstance(test_entries, list):
            raise SystemExit("Testing manifest must be a JSON list.")

        results: list[dict] = []
        summary_path = output_dir / "testing_summary.json"
        sink_attribute_mode = args.mode if args.sink_attribute_mode == "auto" else args.sink_attribute_mode
        for idx, entry in enumerate(test_entries, 1):
            log(f"\n[CASE] {idx}/{len(test_entries)} row={entry.get('_source_row')} bug={entry.get('bug_type')}")
            try:
                result = run_case(
                    entry,
                    output_dir / "testing",
                    decision_output_dir,
                    args.model,
                    args.engine,
                    args.decision_analysis_prompt_mode,
                    sink_attribute_mode,
                    args.decision_context,
                    joern_widen=args.joern_widen,
                    kb_path=kb_path,
                )
                result["status"] = "ok"
            except subprocess.CalledProcessError as exc:
                result = {
                    "source_row": entry.get("_source_row"),
                    "bug_type": entry.get("bug_type"),
                    "status": "error",
                    "message": str(exc),
                }
            results.append(result)
            write_json(summary_path, results)

        log(f"\n[DONE] Summary written to: {summary_path}")
    finally:
        for temp_path in temp_paths:
            temp_path.unlink(missing_ok=True)
        if LOG_FP:
            LOG_FP.close()


if __name__ == "__main__":
    main()
