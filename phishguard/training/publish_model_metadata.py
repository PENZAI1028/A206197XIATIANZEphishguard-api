"""Generate public model metadata from the deployed bundle and fresh results."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import GroupShuffleSplit

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path[:0] = [str(BACKEND), str(ROOT / "training")]

from phishguard_ml_features import LEXICAL_FEATURE_NAMES, normalise_for_model  # noqa: E402
from train_url_model import (  # noqa: E402
    LABEL_CANDIDATES,
    URL_CANDIDATES,
    read_dataset,
    resolve_column,
    root_group,
    stratified_cap,
    to_binary_label,
)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def main() -> None:
    artifact = BACKEND / "phishing_web_model.pkl"
    dataset = ROOT / "dataset" / "PhiUSIIL_Phishing_URL_Dataset.csv"
    output = BACKEND / "phishing_web_model_metadata.json"
    bundle = joblib.load(artifact)
    embedded = bundle["metadata"]

    source = read_dataset(dataset)
    url_column = resolve_column(source, None, URL_CANDIDATES, "url")
    label_column = resolve_column(source, None, LABEL_CANDIDATES, "label")
    frame = pd.DataFrame(
        {"url": source[url_column].map(normalise_for_model), "raw_label": source[label_column]}
    )
    frame["label"] = frame["raw_label"].map(lambda value: to_binary_label(value, "0"))
    frame = frame.dropna(subset=["url", "label"])
    frame = frame[frame["url"].str.len() >= 8].copy()
    frame["label"] = frame["label"].astype(int)
    frame = frame.drop_duplicates(subset=["url"]).reset_index(drop=True)
    frame["group"] = frame["url"].map(root_group)
    frame = stratified_cap(frame, 1_000_000, 42)
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    _, holdout_index = next(splitter.split(frame["url"], frame["label"], groups=frame["group"]))
    holdout = frame.iloc[holdout_index]

    pipeline = bundle["pipeline"]
    probabilities = pipeline.predict_proba(holdout["url"].tolist())[:, list(pipeline.classes_).index(1)]
    predictions = (probabilities >= 0.50).astype(int)
    labels = holdout["label"].to_numpy()
    holdout_metrics = {
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "confusion_matrix": confusion_matrix(labels, predictions, labels=[0, 1]).tolist(),
    }
    system = json.loads((ROOT / "evaluation" / "results" / "system_regression_current.json").read_text(encoding="utf-8"))
    performance = json.loads((ROOT / "evaluation" / "results" / "http_performance.json").read_text(encoding="utf-8"))
    raw_counts = source[label_column].value_counts().sort_index()

    report = {
        "format": bundle["format"],
        "model_name": bundle["model_name"],
        "generated_at_utc": embedded["generated_at_utc"],
        "artifact": artifact.name,
        "artifact_sha256": digest(artifact),
        "source_data": "dataset/PhiUSIIL_Phishing_URL_Dataset.csv",
        "source_data_sha256": digest(dataset),
        "label_contract": {
            "uci_phiusiil_source": {"0": "phishing", "1": "legitimate"},
            "project_canonical": {"0": "safe_or_legitimate", "1": "phishing"},
            "mapping": "source 0 -> canonical 1; source 1 -> canonical 0",
            "synthetic_lookalikes": "canonical label 1 (phishing), appended only to training",
        },
        "source_raw_class_counts": {str(int(key)): int(value) for key, value in raw_counts.items()},
        "source_rows_after_cleaning": int(len(frame)),
        "canonical_class_counts_after_cleaning": {
            "0_safe_or_legitimate": int((frame["label"] == 0).sum()),
            "1_phishing": int((frame["label"] == 1).sum()),
        },
        "split": {
            "method": "GroupShuffleSplit",
            "group": "registered root-like domain",
            "random_state": 42,
            "test_size": 0.20,
            "train_rows_before_synthetic": embedded["train_rows_before_synthetic"],
            "synthetic_lookalike_rows_train_only": embedded["synthetic_lookalike_rows_train_only"],
            "train_rows_total": embedded["train_rows_total"],
            "holdout_rows": embedded["holdout_rows_group_split"],
            "holdout_distinct_root_domains": embedded["holdout_distinct_root_domains"],
            "leakage_control": "Group split before augmentation; synthetic canonical-label-1 phishing URLs added only to training.",
        },
        "model": {
            "text_features": "TF-IDF character n-grams (3-5)",
            "lexical_feature_count": len(LEXICAL_FEATURE_NAMES),
            "lexical_feature_names": list(LEXICAL_FEATURE_NAMES),
            "classifier": "SGDClassifier(loss=log_loss, alpha=0.000004, class_weight=balanced, early_stopping=true, n_iter_no_change=8, random_state=42)",
        },
        "holdout_metrics": holdout_metrics,
        "probability_calibration": embedded["probability_calibration"],
        "api_regression_test": {
            "dataset": "backend/test_urls.csv",
            "rows": system["rows"],
            "accuracy": system["accuracy"],
            "precision": system["precision"],
            "recall": system["recall"],
            "f1": system["f1"],
            "confusion_matrix": system["confusion_matrix_label_order_safe_phishing"],
            "scope": "End-to-end loopback HTTP POST /predict regression; separate from the grouped model holdout.",
            "result_files": ["evaluation/results/system_regression_current.json", "evaluation/results/system_regression_current.csv"],
        },
        "http_performance": performance,
        "training_environment": {
            "python": platform.python_version(),
            "joblib": importlib.metadata.version("joblib"),
            "numpy": importlib.metadata.version("numpy"),
            "pandas": importlib.metadata.version("pandas"),
            "scipy": importlib.metadata.version("scipy"),
            "scikit-learn": importlib.metadata.version("scikit-learn"),
        },
        "verification": {
            "model_alignment_audit": "evaluation/results/model_alignment.json",
            "split_integrity_audit": "evaluation/results/split_integrity.json",
        },
    }
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
