"""
Train the PhishGuard v4 URL model on 100,000 to 1,000,000 labelled URLs.

Examples (PowerShell, from the project root):
  python training/train_url_model.py `
    --data dataset/PhiUSIIL_Phishing_URL_Dataset.csv `
    --min-rows 100000 --max-rows 1000000

  # Only use the model as the production backend model when all holdout
  # metrics meet the threshold:
  python training/train_url_model.py `
    --data dataset/PhiUSIIL_Phishing_URL_Dataset.csv `
    --min-rows 100000 --max-rows 1000000 --target 0.99
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    classification_report,
    f1_score,
    log_loss,
    precision_recall_curve,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer, MaxAbsScaler

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from phishguard_ml_features import lexical_url_matrix, normalise_for_model  # noqa: E402


URL_CANDIDATES = ("url", "URL", "Url", "link", "Link", "domain", "Domain")
LABEL_CANDIDATES = ("label", "Label", "class", "Class", "result", "Result", "status", "Status", "is_phishing")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Train a URL character-ngram + lexical phishing classifier."
    )
    parser.add_argument("--data", required=True, help="CSV or Parquet dataset containing URL and label columns.")
    parser.add_argument("--url-column", default=None, help="Override URL column name.")
    parser.add_argument("--label-column", default=None, help="Override label column name.")
    parser.add_argument(
        "--phishing-value",
        default="1",
        help="Value in a numeric label column that means phishing (default: 1)."
    )
    parser.add_argument("--min-rows", type=int, default=100_000)
    parser.add_argument("--max-rows", type=int, default=1_000_000)
    parser.add_argument("--test-size", type=float, default=0.20)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-features", type=int, default=350_000)
    parser.add_argument("--synthetic-lookalikes", type=int, default=50_000)
    parser.add_argument("--target", type=float, default=0.99, help="Minimum required accuracy, precision, recall and F1.")
    parser.add_argument(
        "--output",
        default=str(BACKEND_DIR / "phishing_web_model.pkl"),
        help="Output model path. It is only overwritten when target is met unless --save-below-target is used."
    )
    parser.add_argument(
        "--report",
        default=str(PROJECT_ROOT / "training" / "reports" / "model_metrics.json"),
        help="JSON report path."
    )
    parser.add_argument(
        "--save-below-target",
        action="store_true",
        help="Save a model even when holdout metrics fail the target. Do not deploy that model."
    )
    return parser.parse_args()


def read_dataset(path: Path) -> pd.DataFrame:
    suffix = path.suffix.lower()
    if suffix in {".parquet", ".pq"}:
        return pd.read_parquet(path)
    return pd.read_csv(path, low_memory=False)


def resolve_column(frame: pd.DataFrame, requested: str | None, candidates: Iterable[str], kind: str) -> str:
    if requested:
        if requested not in frame.columns:
            raise ValueError(f"{kind} column '{requested}' does not exist. Available columns: {list(frame.columns)}")
        return requested

    for candidate in candidates:
        if candidate in frame.columns:
            return candidate

    lowered = {str(column).lower(): str(column) for column in frame.columns}
    for candidate in candidates:
        if candidate.lower() in lowered:
            return lowered[candidate.lower()]

    raise ValueError(f"Cannot identify a {kind} column. Use --{kind}-column explicitly.")


def to_binary_label(value: object, phishing_value: str) -> int | None:
    if pd.isna(value):
        return None

    raw = str(value).strip().lower()
    positive = str(phishing_value).strip().lower()

    if raw == positive:
        return 1

    if raw in {"0", "0.0", "false", "benign", "legitimate", "safe", "good", "normal"}:
        return 0

    if raw in {"1", "1.0", "true", "phishing", "malicious", "fraud", "bad", "unsafe", "phish"}:
        return 1

    if any(token in raw for token in ("phish", "malicious", "fraud", "scam", "unsafe")):
        return 1

    if any(token in raw for token in ("benign", "legitimate", "safe", "normal")):
        return 0

    return None


def root_group(url: str) -> str:
    host = (urlparse(url).hostname or "").lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    suffix2 = ".".join(parts[-2:])
    two_level = {"com.my", "edu.my", "gov.my", "org.my", "co.uk", "com.au", "com.sg"}
    if suffix2 in two_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def stratified_cap(frame: pd.DataFrame, cap: int, seed: int) -> pd.DataFrame:
    if len(frame) <= cap:
        return frame

    fractions = frame["label"].value_counts(normalize=True).to_dict()
    parts = []
    for label, fraction in fractions.items():
        count = max(1, int(round(cap * fraction)))
        subset = frame[frame["label"] == label]
        count = min(count, len(subset))
        parts.append(subset.sample(n=count, random_state=seed))
    result = pd.concat(parts, ignore_index=True)

    if len(result) > cap:
        result = result.sample(n=cap, random_state=seed)
    return result.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def load_trusted_domains() -> list[str]:
    config_file = BACKEND_DIR / "trusted_domains.json"
    with config_file.open("r", encoding="utf-8") as fp:
        config = json.load(fp)
    domains = []
    for values in config.get("official_domains", {}).values():
        domains.extend(str(item).lower() for item in values)
    return sorted(set(domains))


def mutate_visual_label(label: str) -> list[str]:
    """Generate one/two-character confusable variants without mutating the TLD."""
    substitutions = {
        "o": ("0",),
        "i": ("1", "l"),
        "l": ("1", "i"),
        "e": ("3",),
        "a": ("4",),
        "s": ("5",),
        "t": ("7",),
        "g": ("9",),
    }
    variants = set()
    for index, char in enumerate(label.lower()):
        for replacement in substitutions.get(char, ()):
            variants.add(label[:index] + replacement + label[index + 1:])
    return sorted(variants)


def make_lookalike_rows(limit: int, seed: int) -> pd.DataFrame:
    """
    Generate phishing-labelled variants from the verified-domain catalogue.
    They are added to TRAIN ONLY, so no synthetic family leaks into holdout
    metrics. This explicitly teaches 0/o and 1/i/l substitution patterns.
    """
    rng = random.Random(seed)
    rows = []
    prefixes = ("", "www.", "login.", "secure.", "account.", "m.")
    paths = ("/", "/login", "/verify", "/account/secure", "/signin")
    seen = set()

    for domain in load_trusted_domains():
        parts = domain.split(".")
        if len(parts) < 2:
            continue
        label = parts[0]
        suffix = ".".join(parts[1:])

        variants = mutate_visual_label(label)
        # A small sample of two substitutions gives cases such as g00gle.
        for first in mutate_visual_label(label):
            for second in mutate_visual_label(first):
                if first != second and len(variants) < 40:
                    variants.append(second)

        for fake_label in variants:
            if fake_label == label or len(fake_label) < 3:
                continue
            for prefix in prefixes:
                for path in paths:
                    url = f"https://{prefix}{fake_label}.{suffix}{path}"
                    if url not in seen:
                        seen.add(url)
                        rows.append({"url": url, "label": 1, "group": f"synthetic:{domain}"})
                    if len(rows) >= limit:
                        return pd.DataFrame(rows)

    rng.shuffle(rows)
    return pd.DataFrame(rows[:limit])


def build_pipeline(max_features: int, seed: int) -> Pipeline:
    features = FeatureUnion([
        (
            "character_ngrams",
            TfidfVectorizer(
                analyzer="char",
                ngram_range=(3, 5),
                min_df=2,
                max_features=max_features,
                sublinear_tf=True,
                lowercase=True,
                dtype=np.float32
            )
        ),
        (
            "lexical_features",
            Pipeline([
                ("extract", FunctionTransformer(lexical_url_matrix, validate=False)),
                ("scale", MaxAbsScaler())
            ])
        )
    ])

    classifier = SGDClassifier(
        loss="log_loss",
        alpha=4e-6,
        penalty="l2",
        max_iter=1000,
        tol=1e-3,
        early_stopping=True,
        validation_fraction=0.10,
        n_iter_no_change=8,
        class_weight="balanced",
        random_state=seed
    )
    return Pipeline([
        ("features", features),
        ("classifier", classifier)
    ])


def positive_probability(pipeline: Pipeline, urls: pd.Series) -> np.ndarray:
    probabilities = pipeline.predict_proba(urls.tolist())
    classes = list(pipeline.classes_)
    index = classes.index(1) if 1 in classes else -1
    return probabilities[:, index]


def probability_logit(values: np.ndarray) -> np.ndarray:
    clipped = np.clip(np.asarray(values, dtype=float), 1e-6, 1 - 1e-6)
    return np.log(clipped / (1 - clipped)).reshape(-1, 1)


def expected_calibration_error(labels: np.ndarray, probabilities: np.ndarray, bins: int = 10) -> float:
    labels = np.asarray(labels, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    total = len(labels)
    ece = 0.0
    for index in range(bins):
        lower, upper = edges[index], edges[index + 1]
        selected = (probabilities >= lower) & (
            probabilities <= upper if index == bins - 1 else probabilities < upper
        )
        if not selected.any():
            continue
        confidence = probabilities[selected].mean()
        observed = labels[selected].mean()
        ece += (selected.sum() / total) * abs(confidence - observed)
    return float(ece)


def select_f1_threshold(labels: np.ndarray, probabilities: np.ndarray) -> float:
    precision, recall, thresholds = precision_recall_curve(labels, probabilities)
    scores = (2 * precision[:-1] * recall[:-1]) / np.maximum(precision[:-1] + recall[:-1], 1e-12)
    return float(thresholds[int(np.argmax(scores))])


def fit_platt_calibrator(test: pd.DataFrame, raw_probabilities: np.ndarray, seed: int):
    """Fit on one domain-group subset and evaluate on a disjoint subset."""
    split = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=seed + 1)
    calibration_index, evaluation_index = next(
        split.split(test["url"], test["label"], groups=test["group"])
    )
    calibrator = LogisticRegression(random_state=seed, solver="lbfgs")
    calibrator.fit(
        probability_logit(raw_probabilities[calibration_index]),
        test.iloc[calibration_index]["label"].to_numpy(),
    )
    calibration_labels = test.iloc[calibration_index]["label"].to_numpy()
    calibration_probabilities = calibrator.predict_proba(
        probability_logit(raw_probabilities[calibration_index])
    )[:, 1]
    decision_threshold = select_f1_threshold(calibration_labels, calibration_probabilities)
    evaluation_labels = test.iloc[evaluation_index]["label"].to_numpy()
    before = raw_probabilities[evaluation_index]
    after = calibrator.predict_proba(probability_logit(before))[:, 1]
    metrics = {
        "method": "Platt scaling (logistic regression on raw-probability logits)",
        "group_split_random_state": seed + 1,
        "calibration_rows": int(len(calibration_index)),
        "evaluation_rows": int(len(evaluation_index)),
        "calibration_distinct_root_domains": int(test.iloc[calibration_index]["group"].nunique()),
        "evaluation_distinct_root_domains": int(test.iloc[evaluation_index]["group"].nunique()),
        "brier_before": float(brier_score_loss(evaluation_labels, before)),
        "brier_after": float(brier_score_loss(evaluation_labels, after)),
        "ece_10_bins_before": expected_calibration_error(evaluation_labels, before),
        "ece_10_bins_after": expected_calibration_error(evaluation_labels, after),
        "log_loss_before": float(log_loss(evaluation_labels, before, labels=[0, 1])),
        "log_loss_after": float(log_loss(evaluation_labels, after, labels=[0, 1])),
        "decision_threshold": decision_threshold,
    }
    return calibrator, metrics


def main():
    args = parse_args()
    if not 0 < args.test_size < 0.5:
        raise ValueError("--test-size must be between 0 and 0.5")
    if args.max_rows < args.min_rows:
        raise ValueError("--max-rows must be greater than or equal to --min-rows")

    data_file = Path(args.data).expanduser().resolve()
    if not data_file.exists():
        raise FileNotFoundError(data_file)

    frame = read_dataset(data_file)
    url_column = resolve_column(frame, args.url_column, URL_CANDIDATES, "url")
    label_column = resolve_column(frame, args.label_column, LABEL_CANDIDATES, "label")

    working = pd.DataFrame({
        "url": frame[url_column].map(normalise_for_model),
        "raw_label": frame[label_column]
    })
    working["label"] = working["raw_label"].map(
        lambda value: to_binary_label(value, args.phishing_value)
    )
    working = working.dropna(subset=["url", "label"])
    working = working[working["url"].str.len() >= 8].copy()
    working["label"] = working["label"].astype(int)
    working = working.drop_duplicates(subset=["url"]).reset_index(drop=True)
    working["group"] = working["url"].map(root_group)

    if len(working) < args.min_rows:
        raise ValueError(
            f"Only {len(working):,} usable labelled URLs were found. "
            f"At least {args.min_rows:,} are required."
        )

    working = stratified_cap(working, args.max_rows, args.seed)
    class_counts = Counter(working["label"])

    splitter = GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=args.seed)
    train_index, test_index = next(splitter.split(working["url"], working["label"], groups=working["group"]))
    train = working.iloc[train_index].copy()
    test = working.iloc[test_index].copy()

    # Guard against accidental single-class splits.
    if train["label"].nunique() < 2 or test["label"].nunique() < 2:
        raise ValueError("Group split produced a single-class partition. Use a larger/more diverse dataset.")

    synthetic = make_lookalike_rows(args.synthetic_lookalikes, args.seed)
    if not synthetic.empty:
        train = pd.concat([train, synthetic], ignore_index=True)
    train = train.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)

    pipeline = build_pipeline(args.max_features, args.seed)
    pipeline.fit(train["url"].tolist(), train["label"].to_numpy())

    probabilities = positive_probability(pipeline, test["url"])
    predictions = (probabilities >= 0.50).astype(int)
    probability_calibrator, calibration_metrics = fit_platt_calibrator(
        test, probabilities, args.seed
    )

    metrics = {
        "accuracy": float(accuracy_score(test["label"], predictions)),
        "precision": float(precision_score(test["label"], predictions, zero_division=0)),
        "recall": float(recall_score(test["label"], predictions, zero_division=0)),
        "f1": float(f1_score(test["label"], predictions, zero_division=0)),
    }
    meets_target = all(value >= args.target for value in metrics.values())

    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        # Keep published artifacts reproducible without embedding a developer's
        # machine-specific absolute path in the model metadata.
        "source_data": data_file.relative_to(PROJECT_ROOT).as_posix()
        if data_file.is_relative_to(PROJECT_ROOT)
        else data_file.name,
        "url_column": url_column,
        "label_column": label_column,
        "phishing_value": args.phishing_value,
        "source_rows_after_cleaning": int(len(working)),
        "source_class_counts": {str(key): int(value) for key, value in class_counts.items()},
        "train_rows_before_synthetic": int(len(train) - len(synthetic)),
        "synthetic_lookalike_rows_train_only": int(len(synthetic)),
        "train_rows_total": int(len(train)),
        "holdout_rows_group_split": int(len(test)),
        "holdout_distinct_root_domains": int(test["group"].nunique()),
        "target_metric_floor": args.target,
        "holdout_metrics": metrics,
        "probability_calibration": calibration_metrics,
        "meets_target": meets_target,
        "model_type": "Tfidf character 3-5 gram + lexical URL features + SGD logistic classifier",
        "holdout_protocol": (
            "GroupShuffleSplit by registered root-like domain before synthetic augmentation. "
            "Synthetic 0/o and 1/i/l lookalikes were added only to training."
        ),
        "classification_report": classification_report(
            test["label"], predictions, output_dict=True, zero_division=0
        )
    }

    report_path = Path(args.report).expanduser().resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps({
        "source_rows": report["source_rows_after_cleaning"],
        "train_rows": report["train_rows_total"],
        "holdout_rows": report["holdout_rows_group_split"],
        "metrics": metrics,
        "meets_target": meets_target,
        "report": str(report_path)
    }, indent=2))

    if meets_target or args.save_below_target:
        bundle = {
            "format": "phishguard_url_pipeline_v4",
            "model_name": "PhishGuard Character-Ngram + Lexical URL Classifier",
            "pipeline": pipeline,
            "probability_calibrator": probability_calibrator,
            "probability_calibrator_input": "raw_probability_logit",
            "metadata": report,
            "feature_manifest": [
                {
                    "name": "character_ngrams",
                    "value": "TF-IDF character n-grams (3-5) across submitted URLs",
                    "used_by_model": True,
                    "model_importance": None,
                    "model_importance_percent": None
                },
                {
                    "name": "lexical_url_features",
                    "value": "URL length, host/path/query structure, punctuation, digits, HTTPS, IP and token signals",
                    "used_by_model": True,
                    "model_importance": None,
                    "model_importance_percent": None
                }
            ]
        }
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(bundle, output_path)
        print(f"Model saved: {output_path}")
        if not meets_target:
            print("WARNING: --save-below-target was used. Do not claim or deploy a 99% model.")
    else:
        print(
            "Model was NOT saved as production model because at least one grouped-holdout "
            f"metric is below {args.target:.2%}. Improve data quality/diversity, then retrain."
        )
        raise SystemExit(2)


if __name__ == "__main__":
    main()
