"""Measure warmed sequential HTTP /predict latency over loopback TCP."""

import argparse
import json
import statistics
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
import sys

from urllib.request import Request, urlopen
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))
import app as backend  # noqa: E402


def percentile(values, fraction):
    ordered = sorted(values)
    index = (len(ordered) - 1) * fraction
    lower = int(index); upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--requests", type=int, default=100); parser.add_argument("--warmup", type=int, default=10); parser.add_argument("--output", default=str(ROOT / "evaluation" / "results" / "http_performance.json")); args = parser.parse_args()
    server = make_server("127.0.0.1", 0, backend.app); threading.Thread(target=server.serve_forever, daemon=True).start(); endpoint=f"http://127.0.0.1:{server.server_port}/predict"
    body=json.dumps({"url":"https://www.google.com/account/security"}).encode("utf-8")
    def submit():
        request=Request(endpoint,data=body,headers={"Content-Type":"application/json"},method="POST")
        with urlopen(request,timeout=30) as response: return response.read()
    try:
        for _ in range(args.warmup): submit()
        samples=[]
        for _ in range(args.requests):
            start=time.perf_counter(); submit(); samples.append((time.perf_counter()-start)*1000)
    finally: server.shutdown()
    result={"generated_at_utc":datetime.now(timezone.utc).isoformat(),"target":"warmed loopback HTTP POST /predict","warmup_requests":args.warmup,"measured_requests":args.requests,"mean_ms":statistics.mean(samples),"median_ms":statistics.median(samples),"p95_ms":percentile(samples,.95),"min_ms":min(samples),"max_ms":max(samples),"nfr_threshold_ms":250,"passes_nfr":percentile(samples,.95)<250}
    out=Path(args.output); out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(result,indent=2),encoding="utf-8"); print(json.dumps(result,indent=2))


if __name__ == "__main__": main()
