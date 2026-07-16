"""Reproduce the published data split and report leakage checks as JSON.

This audit intentionally uses the same normalisation, label mapping, grouping,
random seeds and synthetic-row generator as ``training/train_url_model.py``.
It does not train a model, so it is inexpensive to rerun whenever the dataset
or split implementation changes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "training"))
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from phishguard_ml_features import normalise_for_model  # noqa: E402
from train_url_model import (  # noqa: E402
    LABEL_CANDIDATES,
    URL_CANDIDATES,
    make_lookalike_rows,
    read_dataset,
    resolve_column,
    root_group,
    stratified_cap,
    to_binary_label,
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit PhishGuard split integrity.")
    parser.add_argument(
        "--data",
        default=str(PROJECT_ROOT / "dataset" / "PhiUSIIL_Phishing_URL_Dataset.csv"),
    )
    parser.add_argument("--url-column", default=None)
    parser.add_argument("--label-column", default=None)
    parser.add_argument("--phishing-value", default="1")
    parser.add_argument("--max-rows", type=int, default=1_000_000)
    parser.add_argument("--test-size", type=float, default=0.20)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--synthetic-lookalikes", type=int, default=50_000)
    parser.add_argument(
        "--output",
        default=str(PROJECT_ROOT / "evaluation" / "results" / "split_integrity.json"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    data_path = Path(args.data).expanduser().resolve()
    source = read_dataset(data_path)
    url_column = resolve_column(source, args.url_column, URL_CANDIDATES, "url")
    label_column = resolve_column(source, args.label_column, LABEL_CANDIDATES, "label")

    working = pd.DataFrame(
        {
            "url": source[url_column].map(normalise_for_model),
            "raw_label": source[label_column],
        }
    )
    working["label"] = working["raw_label"].map(
        lambda value: to_binary_label(value, args.phishing_value)
    )
    working = working.dropna(subset=["url", "label"])
    working = working[working["url"].str.len() >= 8].copy()
    working["label"] = working["label"].astype(int)

    rows_before_url_deduplication = int(len(working))
    duplicated_url_rows = int(working.duplicated(subset=["url"], keep=False).sum())
    conflicting_urls = (
        working.groupby("url", sort=False)["label"].nunique().loc[lambda values: values > 1]
    )
    conflicting_url_count = int(len(conflicting_urls))

    working = working.drop_duplicates(subset=["url"]).reset_index(drop=True)
    working["group"] = working["url"].map(root_group)
    working = stratified_cap(working, args.max_rows, args.seed)

    splitter = GroupShuffleSplit(
        n_splits=1, test_size=args.test_size, random_state=args.seed
    )
    train_index, holdout_index = next(
        splitter.split(working["url"], working["label"], groups=working["group"])
    )
    source_train = working.iloc[train_index].copy()
    holdout = working.iloc[holdout_index].copy()

    calibration_splitter = GroupShuffleSplit(
        n_splits=1, test_size=0.50, random_state=args.seed + 1
    )
    calibration_index, evaluation_index = next(
        calibration_splitter.split(
            holdout["url"], holdout["label"], groups=holdout["group"]
        )
    )
    calibration = holdout.iloc[calibration_index].copy()
    calibration_evaluation = holdout.iloc[evaluation_index].copy()

    synthetic = make_lookalike_rows(args.synthetic_lookalikes, args.seed)
    synthetic_urls = set(synthetic["url"]) if not synthetic.empty else set()
    source_train_urls = set(source_train["url"])
    holdout_urls = set(holdout["url"])
    train_groups = set(source_train["group"])
    holdout_groups = set(holdout["group"])
    calibration_groups = set(calibration["group"])
    evaluation_groups = set(calibration_evaluation["group"])

    checks = {
        "source_train_vs_holdout_group_overlap": len(train_groups & holdout_groups),
        "source_train_vs_holdout_normalised_url_overlap": len(source_train_urls & holdout_urls),
        "calibration_vs_evaluation_group_overlap": len(calibration_groups & evaluation_groups),
        "calibration_vs_evaluation_normalised_url_overlap": len(
            set(calibration["url"]) & set(calibration_evaluation["url"])
        ),
        "synthetic_train_vs_holdout_normalised_url_overlap": len(synthetic_urls & holdout_urls),
        "empty_root_group_rows": int((working["group"] == "").sum()),
        "conflicting_label_normalised_url_count_before_deduplication": conflicting_url_count,
    }
    zero_required = (
        "source_train_vs_holdout_group_overlap",
        "source_train_vs_holdout_normalised_url_overlap",
        "calibration_vs_evaluation_group_overlap",
        "calibration_vs_evaluation_normalised_url_overlap",
        "synthetic_train_vs_holdout_normalised_url_overlap",
        "empty_root_group_rows",
        "conflicting_label_normalised_url_count_before_deduplication",
    )
    passed = all(checks[name] == 0 for name in zero_required)

    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "audit_status": "PASS" if passed else "FAIL",
        "dataset": {
            "path": data_path.name,
            "sha256": sha256(data_path),
            "source_rows": int(len(source)),
            "rows_before_url_deduplication": rows_before_url_deduplication,
            "rows_after_cleaning_and_url_deduplication": int(len(working)),
            "duplicated_url_rows_before_deduplication": duplicated_url_rows,
            "conflicting_label_normalised_url_count_before_deduplication": conflicting_url_count,
        },
        "protocol": {
            "outer_split": "GroupShuffleSplit by registered root-like domain",
            "outer_test_size": args.test_size,
            "outer_random_state": args.seed,
            "calibration_split": "50/50 GroupShuffleSplit within untouched outer holdout",
            "calibration_random_state": args.seed + 1,
            "synthetic_policy": "Generated only after the outer split and appended only to training",
        },
        "partitions": {
            "source_train_rows": int(len(source_train)),
            "source_train_groups": int(source_train["group"].nunique()),
            "synthetic_train_only_rows": int(len(synthetic)),
            "holdout_rows": int(len(holdout)),
            "holdout_groups": int(holdout["group"].nunique()),
            "calibration_rows": int(len(calibration)),
            "calibration_groups": int(calibration["group"].nunique()),
            "calibration_evaluation_rows": int(len(calibration_evaluation)),
            "calibration_evaluation_groups": int(calibration_evaluation["group"].nunique()),
        },
        "checks": checks,
        "interpretation": (
            "PASS means no group or exact normalised-URL intersection was found between the "
            "reproduced partitions, no synthetic training URL appeared in the holdout, and no "
            "conflicting label remained for the same normalised URL before deduplication. This "
            "does not replace future temporal or independent-source external validation."
        ),
    }

    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    if not passed:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
