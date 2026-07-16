"""Fit and attach a formal Platt calibrator to an existing PhishGuard bundle."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import brier_score_loss, log_loss
from sklearn.model_selection import GroupShuffleSplit

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from phishguard_ml_features import normalise_for_model  # noqa: E402
from train_url_model import (  # noqa: E402
    expected_calibration_error,
    probability_logit,
    read_dataset,
    resolve_column,
    root_group,
    stratified_cap,
    select_f1_threshold,
    to_binary_label,
    URL_CANDIDATES,
    LABEL_CANDIDATES,
)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=str(PROJECT_ROOT / "dataset" / "PhiUSIIL_Phishing_URL_Dataset.csv"))
    parser.add_argument("--model", default=str(BACKEND_DIR / "phishing_web_model.pkl"))
    parser.add_argument("--output-dir", default=str(PROJECT_ROOT / "evaluation" / "results"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--write-bundle", action="store_true")
    return parser.parse_args()


def reliability_rows(labels, before, after, bins=10):
    edges = np.linspace(0.0, 1.0, bins + 1)
    rows = []
    for index in range(bins):
        selected = (before >= edges[index]) & (before <= edges[index + 1] if index == bins - 1 else before < edges[index + 1])
        selected_after = (after >= edges[index]) & (after <= edges[index + 1] if index == bins - 1 else after < edges[index + 1])
        rows.append({
            "bin": index + 1,
            "lower": edges[index],
            "upper": edges[index + 1],
            "before_count": int(selected.sum()),
            "before_mean_probability": float(before[selected].mean()) if selected.any() else None,
            "before_observed_rate": float(labels[selected].mean()) if selected.any() else None,
            "after_count": int(selected_after.sum()),
            "after_mean_probability": float(after[selected_after].mean()) if selected_after.any() else None,
            "after_observed_rate": float(labels[selected_after].mean()) if selected_after.any() else None,
        })
    return rows


def write_reliability_svg(rows, path):
    def point(x, y):
        return f"{60 + x * 500:.1f},{560 - y * 500:.1f}"
    before = " ".join(point(row["before_mean_probability"], row["before_observed_rate"]) for row in rows if row["before_count"])
    after = " ".join(point(row["after_mean_probability"], row["after_observed_rate"]) for row in rows if row["after_count"])
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="680" height="640" viewBox="0 0 680 640">
<rect width="100%" height="100%" fill="white"/><text x="340" y="28" text-anchor="middle" font-family="Arial" font-size="20">Probability calibration reliability curve</text>
<line x1="60" y1="560" x2="560" y2="60" stroke="#777" stroke-dasharray="6 6"/><line x1="60" y1="560" x2="560" y2="560" stroke="black"/><line x1="60" y1="560" x2="60" y2="60" stroke="black"/>
<polyline points="{before}" fill="none" stroke="#d55e00" stroke-width="3"/><polyline points="{after}" fill="none" stroke="#0072b2" stroke-width="3"/>
<text x="310" y="610" text-anchor="middle" font-family="Arial">Mean predicted probability</text><text x="18" y="310" text-anchor="middle" transform="rotate(-90 18 310)" font-family="Arial">Observed phishing frequency</text>
<line x1="575" y1="90" x2="610" y2="90" stroke="#d55e00" stroke-width="3"/><text x="615" y="95" font-family="Arial" font-size="13">Before</text><line x1="575" y1="118" x2="610" y2="118" stroke="#0072b2" stroke-width="3"/><text x="615" y="123" font-family="Arial" font-size="13">After</text>
</svg>'''
    path.write_text(svg, encoding="utf-8")


def main():
    args = parse_args()
    data_path = Path(args.data).resolve()
    model_path = Path(args.model).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    frame = read_dataset(data_path)
    url_column = resolve_column(frame, None, URL_CANDIDATES, "url")
    label_column = resolve_column(frame, None, LABEL_CANDIDATES, "label")
    working = pd.DataFrame({"url": frame[url_column].map(normalise_for_model), "raw_label": frame[label_column]})
    working["label"] = working["raw_label"].map(lambda value: to_binary_label(value, "0"))
    working = working.dropna(subset=["url", "label"])
    working = working[working["url"].str.len() >= 8].copy()
    working["label"] = working["label"].astype(int)
    working = working.drop_duplicates(subset=["url"]).reset_index(drop=True)
    working["group"] = working["url"].map(root_group)
    working = stratified_cap(working, 1_000_000, args.seed)

    outer = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=args.seed)
    _, holdout_index = next(outer.split(working["url"], working["label"], groups=working["group"]))
    holdout = working.iloc[holdout_index].copy().reset_index(drop=True)
    inner = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=args.seed + 1)
    calibration_index, evaluation_index = next(inner.split(holdout["url"], holdout["label"], groups=holdout["group"]))

    bundle = joblib.load(model_path)
    pipeline = bundle["pipeline"]
    raw = pipeline.predict_proba(holdout["url"].tolist())[:, list(pipeline.classes_).index(1)]
    from sklearn.linear_model import LogisticRegression
    calibrator = LogisticRegression(random_state=args.seed, solver="lbfgs")
    calibrator.fit(probability_logit(raw[calibration_index]), holdout.iloc[calibration_index]["label"].to_numpy())
    calibration_labels = holdout.iloc[calibration_index]["label"].to_numpy()
    calibration_probabilities = calibrator.predict_proba(probability_logit(raw[calibration_index]))[:, 1]
    decision_threshold = select_f1_threshold(calibration_labels, calibration_probabilities)
    labels = holdout.iloc[evaluation_index]["label"].to_numpy()
    before = raw[evaluation_index]
    after = calibrator.predict_proba(probability_logit(before))[:, 1]
    metrics = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "method": "Platt scaling (logistic regression on raw-probability logits)",
        "source_model_sha256_before_calibration": hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "outer_holdout_rows": int(len(holdout)),
        "calibration_rows": int(len(calibration_index)),
        "evaluation_rows": int(len(evaluation_index)),
        "calibration_distinct_root_domains": int(holdout.iloc[calibration_index]["group"].nunique()),
        "evaluation_distinct_root_domains": int(holdout.iloc[evaluation_index]["group"].nunique()),
        "brier_before": float(brier_score_loss(labels, before)),
        "brier_after": float(brier_score_loss(labels, after)),
        "ece_10_bins_before": expected_calibration_error(labels, before),
        "ece_10_bins_after": expected_calibration_error(labels, after),
        "log_loss_before": float(log_loss(labels, before, labels=[0, 1])),
        "log_loss_after": float(log_loss(labels, after, labels=[0, 1])),
        "decision_threshold": decision_threshold,
    }
    rows = reliability_rows(labels, before, after)
    (output_dir / "calibration_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    with (output_dir / "calibration_reliability.csv").open("w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=rows[0].keys())
        writer.writeheader(); writer.writerows(rows)
    write_reliability_svg(rows, output_dir / "calibration_reliability.svg")

    if args.write_bundle:
        bundle["probability_calibrator"] = calibrator
        bundle["probability_calibrator_input"] = "raw_probability_logit"
        bundle["metadata"]["probability_calibration"] = metrics
        bundle["metadata"]["decision_threshold"] = decision_threshold
        joblib.dump(bundle, model_path)
        metrics["artifact_sha256_after_calibration"] = hashlib.sha256(model_path.read_bytes()).hexdigest()
        (output_dir / "calibration_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
