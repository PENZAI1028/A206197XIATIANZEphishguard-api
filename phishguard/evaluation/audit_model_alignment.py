"""Verify that the deployed model, code, metadata and published metrics agree."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import GroupShuffleSplit

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND = PROJECT_ROOT / "backend"
TRAINING = PROJECT_ROOT / "training"
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(TRAINING))

from phishguard_ml_features import LEXICAL_FEATURE_NAMES, lexical_url_matrix, normalise_for_model  # noqa: E402
from train_url_model import (  # noqa: E402
    LABEL_CANDIDATES,
    URL_CANDIDATES,
    read_dataset,
    resolve_column,
    root_group,
    stratified_cap,
    to_binary_label,
)

ARTIFACT = BACKEND / "phishing_web_model.pkl"
METADATA_FILE = BACKEND / "phishing_web_model_metadata.json"
DATASET = PROJECT_ROOT / "dataset" / "PhiUSIIL_Phishing_URL_Dataset.csv"
OUTPUT = PROJECT_ROOT / "evaluation" / "results" / "model_alignment.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def close(left, right, tolerance=1e-12) -> bool:
    return math.isclose(float(left), float(right), rel_tol=tolerance, abs_tol=tolerance)


def reconstruct_holdout() -> pd.DataFrame:
    source = read_dataset(DATASET)
    url_column = resolve_column(source, None, URL_CANDIDATES, "url")
    label_column = resolve_column(source, None, LABEL_CANDIDATES, "label")
    frame = pd.DataFrame(
        {
            "url": source[url_column].map(normalise_for_model),
            "raw_label": source[label_column],
        }
    )
    frame["label"] = frame["raw_label"].map(lambda value: to_binary_label(value, "1"))
    frame = frame.dropna(subset=["url", "label"])
    frame = frame[frame["url"].str.len() >= 8].copy()
    frame["label"] = frame["label"].astype(int)
    frame = frame.drop_duplicates(subset=["url"]).reset_index(drop=True)
    frame["group"] = frame["url"].map(root_group)
    frame = stratified_cap(frame, 1_000_000, 42)
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    _, holdout_index = next(splitter.split(frame["url"], frame["label"], groups=frame["group"]))
    return frame.iloc[holdout_index].copy()


def check(name: str, passed: bool, observed, expected, results: list[dict]) -> None:
    results.append(
        {"check": name, "status": "PASS" if passed else "FAIL", "observed": observed, "expected": expected}
    )


def main() -> None:
    results: list[dict] = []
    metadata = json.loads(METADATA_FILE.read_text(encoding="utf-8"))
    bundle = joblib.load(ARTIFACT)
    pipeline = bundle["pipeline"]
    union = pipeline.named_steps["features"]
    transformers = dict(union.transformer_list)
    vectorizer = transformers["character_ngrams"]
    classifier = pipeline.named_steps["classifier"]

    artifact_hash = sha256(ARTIFACT)
    check("artifact filename", ARTIFACT.name == "phishing_web_model.pkl", ARTIFACT.name, "phishing_web_model.pkl", results)
    check("artifact SHA-256", artifact_hash == metadata["artifact_sha256"], artifact_hash, metadata["artifact_sha256"], results)
    check("bundle format", bundle.get("format") == "phishguard_url_pipeline_v4", bundle.get("format"), "phishguard_url_pipeline_v4", results)
    check("model name", bundle.get("model_name") == metadata["model_name"], bundle.get("model_name"), metadata["model_name"], results)
    check("TF-IDF analyzer", vectorizer.analyzer == "char", vectorizer.analyzer, "char", results)
    check("TF-IDF n-gram range", tuple(vectorizer.ngram_range) == (3, 5), list(vectorizer.ngram_range), [3, 5], results)
    check("lexical feature count", len(LEXICAL_FEATURE_NAMES) == 21, len(LEXICAL_FEATURE_NAMES), 21, results)
    check("lexical transformer output", lexical_url_matrix(["https://example.com/a?x=1"]).shape == (1, 21), list(lexical_url_matrix(["https://example.com/a?x=1"]).shape), [1, 21], results)
    check("metadata lexical names", metadata["model"].get("lexical_feature_names") == list(LEXICAL_FEATURE_NAMES), metadata["model"].get("lexical_feature_names"), list(LEXICAL_FEATURE_NAMES), results)
    check("classifier type", classifier.__class__.__name__ == "SGDClassifier", classifier.__class__.__name__, "SGDClassifier", results)
    expected_params = {"loss": "log_loss", "alpha": 4e-6, "class_weight": "balanced", "early_stopping": True, "n_iter_no_change": 8, "random_state": 42}
    observed_params = {name: classifier.get_params()[name] for name in expected_params}
    check("classifier parameters", observed_params == expected_params, observed_params, expected_params, results)
    check("formal calibrator present", bundle.get("probability_calibrator").__class__.__name__ == "LogisticRegression", bundle.get("probability_calibrator").__class__.__name__, "LogisticRegression", results)

    requirements = {}
    for raw in (TRAINING / "requirements-training.txt").read_text(encoding="utf-8").splitlines():
        if "==" in raw and not raw.lstrip().startswith("#"):
            package, version = raw.strip().split("==", 1)
            requirements[package] = version
    installed = {package: importlib.metadata.version(package) for package in requirements}
    check("training requirements installed", installed == requirements, installed, requirements, results)
    check("Python runtime", platform.python_version() == metadata["training_environment"]["python"], platform.python_version(), metadata["training_environment"]["python"], results)

    holdout = reconstruct_holdout()
    probabilities = pipeline.predict_proba(holdout["url"].tolist())[:, list(pipeline.classes_).index(1)]
    predictions = (probabilities >= 0.50).astype(int)
    labels = holdout["label"].to_numpy()
    observed_metrics = {
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
    }
    expected_metrics = metadata["holdout_metrics"]
    check("holdout row count", len(holdout) == metadata["split"]["holdout_rows"], len(holdout), metadata["split"]["holdout_rows"], results)
    for metric in ("accuracy", "precision", "recall", "f1"):
        check(f"holdout {metric}", close(observed_metrics[metric], expected_metrics[metric]), observed_metrics[metric], expected_metrics[metric], results)
    observed_matrix = confusion_matrix(labels, predictions, labels=[0, 1]).tolist()
    check("holdout confusion matrix", observed_matrix == expected_metrics["confusion_matrix"], observed_matrix, expected_metrics["confusion_matrix"], results)

    split = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=43)
    calibration_index, evaluation_index = next(split.split(holdout["url"], labels, groups=holdout["group"]))
    check("calibration/evaluation group overlap", len(set(holdout.iloc[calibration_index]["group"]) & set(holdout.iloc[evaluation_index]["group"])) == 0, 0, 0, results)
    check("calibration row count", len(calibration_index) == metadata["probability_calibration"]["calibration_rows"], len(calibration_index), metadata["probability_calibration"]["calibration_rows"], results)
    check("calibration evaluation row count", len(evaluation_index) == metadata["probability_calibration"]["evaluation_rows"], len(evaluation_index), metadata["probability_calibration"]["evaluation_rows"], results)

    sys.path.insert(0, str(BACKEND))
    import app as backend_app  # noqa: E402
    client = backend_app.app.test_client()
    response = client.post("/predict", json={"url": "https://example.com"})
    payload = response.get_json() or {}
    check("API prediction HTTP status", response.status_code == 200, response.status_code, 200, results)
    check("API analysis mode", payload.get("analysis_mode") == "full_model", payload.get("analysis_mode"), "full_model", results)
    check("API model name", payload.get("model_name") == bundle["model_name"], payload.get("model_name"), bundle["model_name"], results)
    check("API raw model probability exposed", payload.get("raw_ai_phishing_probability") is not None, payload.get("raw_ai_phishing_probability"), "non-null", results)
    check("API calibrated probability exposed", payload.get("calibrated_ai_phishing_probability") is not None, payload.get("calibrated_ai_phishing_probability"), "non-null", results)

    failed = [item for item in results if item["status"] == "FAIL"]
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "audit_status": "PASS" if not failed else "FAIL",
        "scope": "Deployed artifact, feature contract, classifier, runtime dependencies, reproduced grouped holdout, calibration partition and Flask inference",
        "checks_passed": len(results) - len(failed),
        "checks_failed": len(failed),
        "checks": results,
        "metric_boundaries": {
            "model_holdout": "42,399 source URLs; raw SGD probability at threshold 0.50",
            "calibration": "Platt fit on 22,330 grouped rows; calibration metrics evaluated on a disjoint 20,069-row grouped subset",
            "system_regression": "Separate 100-URL loopback HTTP hybrid-system test; not a model holdout metric",
        },
    }
    OUTPUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    if failed:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
