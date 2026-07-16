"""Run the 100-URL regression through a real loopback HTTP /predict endpoint."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from urllib.request import Request, urlopen
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from werkzeug.serving import make_server


HERE = Path(__file__).resolve().parent


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=str(HERE / "test_urls.csv"))
    parser.add_argument("--base-url", default=None, help="Existing API base URL; omitted starts a local loopback HTTP server.")
    parser.add_argument("--output-dir", default=str(HERE.parent / "evaluation" / "results"))
    parser.add_argument("--result-stem", default="system_regression_current")
    return parser.parse_args()


def main():
    args = parse_args()
    server = None
    if args.base_url:
        base_url = args.base_url.rstrip("/")
    else:
        import app as backend
        server = make_server("127.0.0.1", 0, backend.app)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base_url = f"http://127.0.0.1:{server.server_port}"

    data_path = Path(args.data).resolve()
    rows = list(csv.DictReader(data_path.open(encoding="utf-8")))
    records, expected, predicted = [], [], []
    try:
        for index, row in enumerate(rows, 1):
            body = json.dumps({"url": row["url"]}).encode("utf-8")
            request = Request(f"{base_url}/predict", data=body, headers={"Content-Type": "application/json"}, method="POST")
            with urlopen(request, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))
            actual = int(row["label"])
            guess = int(payload["prediction"])
            expected.append(actual); predicted.append(guess)
            records.append({
                "case": index,
                "url": row["url"],
                "expected": actual,
                "predicted": guess,
                "correct": actual == guess,
                "decision": payload["decision"],
                "risk_score": payload["risk_score"],
                "analysis_mode": payload["analysis_mode"],
                "model_available": payload["model_available"],
                "raw_probability": payload["raw_ai_phishing_probability"],
                "calibrated_probability": payload["calibrated_ai_phishing_probability"],
                "analysis_time_ms": payload["analysis_time_ms"],
            })
    finally:
        if server is not None:
            server.shutdown()

    matrix = confusion_matrix(expected, predicted, labels=[0, 1]).tolist()
    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "execution": "HTTP POST requests to /predict over a loopback TCP endpoint",
        "dataset": data_path.name,
        "dataset_sha256": hashlib.sha256(data_path.read_bytes()).hexdigest(),
        "rows": len(rows),
        "safe_rows": expected.count(0),
        "phishing_rows": expected.count(1),
        "accuracy": accuracy_score(expected, predicted),
        "precision": precision_score(expected, predicted, zero_division=0),
        "recall": recall_score(expected, predicted, zero_division=0),
        "f1": f1_score(expected, predicted, zero_division=0),
        "confusion_matrix_label_order_safe_phishing": matrix,
        "incorrect_cases": [item for item in records if not item["correct"]],
        "records": records,
    }
    output_dir = Path(args.output_dir).resolve(); output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / f"{args.result_stem}.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    with (output_dir / f"{args.result_stem}.csv").open("w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=records[0].keys()); writer.writeheader(); writer.writerows(records)
    print(json.dumps({key: value for key, value in summary.items() if key != "records"}, indent=2))


if __name__ == "__main__":
    main()
