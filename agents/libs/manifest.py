"""Manifest and training-CSV selection for a pipeline run.

Row windows (--start-row/--stop-row), explicit row lists (--rows) and the
"vulnerable only" training filter are all applied by writing a temporary
manifest/CSV and handing that to the agents, so the agents themselves never
need to know about subsetting.
"""
from __future__ import annotations

import csv
import sys
import tempfile
from pathlib import Path

from agents.libs.jsonio import read_json, write_json

# Manifest rows carry whole source files; the default CSV field cap is too small.
try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(10**7)


def slice_rows(rows: list, start: int, end: int | None) -> list:
    if start < 1:
        start = 1
    begin = start - 1
    if end is None or end < start:
        return rows[begin:]
    return rows[begin:end]


def slice_csv_to_temp(path: Path, start: int, end: int | None) -> tuple[Path, int]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fp:
        reader = csv.DictReader(fp)
        rows = list(reader)
        fieldnames = reader.fieldnames or []
    sliced = slice_rows(rows, start, end)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".csv", prefix="cwe_train_subset_")
    tmp_path = Path(tmp.name)
    tmp.close()
    with tmp_path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for row in sliced:
            writer.writerow(row)
    return tmp_path, len(sliced)


def truthy_token(raw: object) -> bool:
    return str(raw or "").strip().lower() in {"true", "1", "yes", "y"}


def filter_training_csv_to_true_temp(path: Path) -> tuple[Path, int, int]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fp:
        reader = csv.DictReader(fp)
        rows = list(reader)
        fieldnames = reader.fieldnames or []
    filtered = [row for row in rows if truthy_token(row.get("is_vulnerable"))]
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".csv", prefix="cwe_train_true_only_")
    tmp_path = Path(tmp.name)
    tmp.close()
    with tmp_path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for row in filtered:
            writer.writerow(row)
    return tmp_path, len(filtered), len(rows)


def slice_json_to_temp(path: Path, start: int, end: int | None) -> tuple[Path, int]:
    rows = read_json(path)
    if not isinstance(rows, list):
        raise SystemExit("Testing manifest must be a JSON list.")
    sliced = slice_rows(rows, start, end)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json", prefix="cwe_test_subset_")
    tmp_path = Path(tmp.name)
    tmp.close()
    write_json(tmp_path, sliced)
    return tmp_path, len(sliced)


def apply_subset_for_mode(
    train_only: bool,
    train_csv_path: Path,
    test_manifest_path: Path,
    start_row: int,
    stop_row: int | None,
) -> tuple[Path, Path, Path | None, int | None]:
    if start_row == 1 and stop_row is None:
        return train_csv_path, test_manifest_path, None, None
    if train_only:
        sliced_path, sliced_count = slice_csv_to_temp(train_csv_path, start_row, stop_row)
        return sliced_path, test_manifest_path, sliced_path, sliced_count
    sliced_path, sliced_count = slice_json_to_temp(test_manifest_path, start_row, stop_row)
    return train_csv_path, sliced_path, sliced_path, sliced_count


def parse_rows_arg(raw: str) -> list[int]:
    values: list[int] = []
    for part in (raw or "").split(","):
        token = part.strip()
        if not token:
            continue
        try:
            values.append(int(token))
        except ValueError:
            raise SystemExit(f"Invalid row in --rows: {token}")
    return values


def resolve_manifest_inputs(manifest_dir: Path, train_csv_arg: str, test_manifest_arg: str, output_dir_arg: str) -> tuple[Path, Path, Path]:
    train_csv = Path(train_csv_arg).expanduser()
    test_manifest = Path(test_manifest_arg).expanduser()
    output_dir = Path(output_dir_arg).expanduser()

    if not train_csv_arg:
        candidates = [
            manifest_dir / "training.csv",
            manifest_dir / "cwe_manifest_v1_training.csv",
        ]
        train_csv = next((p for p in candidates if p.is_file()), candidates[0])
    if not test_manifest_arg:
        candidates = [
            manifest_dir / "testing_manifest.json",
            manifest_dir / "testing.json",
        ]
        test_manifest = next((p for p in candidates if p.is_file()), candidates[0])
    if not output_dir_arg:
        output_dir = manifest_dir / "agent_runs"

    return train_csv, test_manifest, output_dir


def filter_test_manifest_to_temp(path: Path, selected_rows: list[int]) -> tuple[Path, int]:
    rows = read_json(path)
    if not isinstance(rows, list):
        raise SystemExit("Testing manifest must be a JSON list.")
    selected = set(selected_rows)
    filtered = [row for position, row in enumerate(rows, start=1) if position in selected]
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json", prefix="cwe_test_rows_")
    tmp_path = Path(tmp.name)
    tmp.close()
    write_json(tmp_path, filtered)
    return tmp_path, len(filtered)


def filter_train_csv_to_temp(path: Path, selected_rows: list[int]) -> tuple[Path, int]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fp:
        reader = csv.DictReader(fp)
        rows = list(reader)
        fieldnames = reader.fieldnames or []
    selected = set(selected_rows)
    filtered = [row for position, row in enumerate(rows, start=1) if position in selected]
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".csv", prefix="cwe_train_rows_")
    tmp_path = Path(tmp.name)
    tmp.close()
    with tmp_path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for row in filtered:
            writer.writerow(row)
    return tmp_path, len(filtered)
