"""Offline reputation lookup with false-positive-safe matching policy.

The source feeds are historical evidence.  They are valuable for an exact URL
or a dedicated malicious hostname, but a host/root record must not automatically
block a well-known provider, a reclaimed root, or every sibling subdomain.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

STORE_FILE = Path(__file__).with_name("reputation_store.json")

TWO_LEVEL_SUFFIXES = {
    "com.my", "edu.my", "gov.my", "org.my", "net.my",
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp",
    "co.id", "or.id", "ac.id",
    "com.sg", "org.sg", "edu.sg",
}


def strip_www(host: str) -> str:
    host = (host or "").strip().lower().strip(".")
    return host[4:] if host.startswith("www.") else host


def _host_from_netloc(netloc: str) -> str:
    host = (netloc or "").strip().lower()
    if "@" in host:
        host = host.rsplit("@", 1)[-1]
    if host.startswith("[") and "]" in host:
        host = host[1:host.index("]")]
    elif ":" in host:
        host = host.split(":", 1)[0]
    try:
        host = host.encode("idna").decode("ascii")
    except Exception:
        pass
    return strip_www(host)


def get_root_domain(host: str) -> str:
    host = strip_www(host)
    parts = [part for part in host.split(".") if part]
    if len(parts) <= 2:
        return host
    last_two = ".".join(parts[-2:])
    if last_two in TWO_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def canonicalize_url(url: str) -> dict[str, str]:
    raw = str(url or "").strip()
    if not raw:
        return {"url": "", "host": "", "fingerprint": "", "root": ""}
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    host = _host_from_netloc(parsed.netloc)
    path = parsed.path or "/"
    query = ("?" + parsed.query) if parsed.query else ""
    fingerprint = f"{host}{path}{query}".lower()
    return {
        "url": f"{parsed.scheme.lower() or 'https'}://{fingerprint}",
        "host": host,
        "fingerprint": fingerprint,
        "root": get_root_domain(host),
    }


def fingerprint_hash(fingerprint: str) -> str:
    return hashlib.sha256((fingerprint or "").encode("utf-8")).hexdigest()


def _empty_store(error: str | None = None) -> dict[str, Any]:
    return {
        "format_version": 1,
        "generated_at_utc": None,
        "source_files": [],
        "counts": {"url_fingerprints": 0, "hosts": 0, "roots": 0},
        "url_fingerprints": {},
        "hosts": {},
        "roots": {},
        "load_error": error,
    }


def load_store(path: Path | None = None) -> dict[str, Any]:
    path = path or STORE_FILE
    try:
        with path.open("r", encoding="utf-8") as fp:
            store = json.load(fp)
        if not isinstance(store, dict):
            raise ValueError("reputation store JSON must be an object")
        for key in ("url_fingerprints", "hosts", "roots"):
            if not isinstance(store.get(key), dict):
                store[key] = {}
        if not isinstance(store.get("counts"), dict):
            store["counts"] = {
                "url_fingerprints": len(store["url_fingerprints"]),
                "hosts": len(store["hosts"]),
                "roots": len(store["roots"]),
            }
        store["load_error"] = None
        return store
    except FileNotFoundError:
        return _empty_store("reputation_store.json is not built yet")
    except Exception as exc:
        return _empty_store(str(exc))


_STORE = load_store()


def reload_store() -> dict[str, Any]:
    global _STORE
    _STORE = load_store()
    return _STORE


def _age_days(generated_at_utc: str | None) -> int | None:
    if not generated_at_utc:
        return None
    try:
        created = datetime.fromisoformat(generated_at_utc.replace("Z", "+00:00"))
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return max(0, int((datetime.now(timezone.utc) - created).total_seconds() // 86400))
    except Exception:
        return None


def get_store_metadata() -> dict[str, Any]:
    counts = _STORE.get("counts", {})
    generated = _STORE.get("generated_at_utc")
    age = _age_days(generated)
    return {
        "available": _STORE.get("load_error") is None and bool(_STORE.get("hosts")),
        "generated_at_utc": generated,
        "age_days": age,
        "stale": bool(age is not None and age > 30),
        "counts": {
            "url_fingerprints": int(counts.get("url_fingerprints", len(_STORE.get("url_fingerprints", {})))),
            "hosts": int(counts.get("hosts", len(_STORE.get("hosts", {})))),
            "roots": int(counts.get("roots", len(_STORE.get("roots", {})))),
        },
        "load_error": _STORE.get("load_error"),
        "policy": "v12.1: exact-url and dedicated-host evidence; root-only records are context only",
    }


def _record_sources(record: Any) -> list[str]:
    value = record.get("sources", []) if isinstance(record, dict) else (record or [])
    if not isinstance(value, list):
        value = [value]
    return sorted({str(item).strip().lower() for item in value if str(item).strip()})


def _record_url_count(record: Any) -> int:
    if not isinstance(record, dict):
        return 0
    try:
        return max(0, int(record.get("url_count", 0)))
    except (TypeError, ValueError):
        return 0


def _score_for_exact_url(sources: list[str], stale: bool) -> int:
    score = 100
    if stale:
        score = 85
    return score


def _score_for_host(host: str, root: str, sources: list[str], stale: bool) -> tuple[int, str]:
    """Return score and evidence class for an exact hostname record.

    A single historical record on the registrable root is weak: public sites,
    expired domains and historical false reports exist.  Dedicated subdomain
    records remain strong; an unrelated sibling will never inherit a root hit.
    """
    if host == root:
        # Root hostname reported by exactly one historical feed: do not block.
        # Multiple independent feeds or URLHaus evidence are stronger.
        if "urlhaus" in sources or len(sources) >= 2:
            score, evidence_class = 90, "root_host_multi_source"
        else:
            score, evidence_class = 35, "root_host_single_source"
    else:
        score, evidence_class = 98, "dedicated_host"
    if stale:
        score = min(score, 75 if evidence_class == "dedicated_host" else 30)
    return score, evidence_class


def _base_result(metadata: dict[str, Any], normalized: dict[str, str]) -> dict[str, Any]:
    return {
        **metadata,
        "match": False,
        "match_type": None,
        "score": 0,
        "sources": [],
        "normalized_host": normalized["host"],
        "root_domain": normalized["root"],
        "url_count": 0,
        "evidence_class": None,
        "context_match": False,
        "context_sources": [],
        "context_url_count": 0,
    }


def lookup_reputation(url: str) -> dict[str, Any]:
    """Look up historical evidence using a false-positive-safe policy.

    Priority:
      1) exact URL fingerprint — blocking evidence;
      2) exact hostname — strong for a dedicated subdomain, weaker for a root;
      3) registrable root — non-blocking context only (never inherited by a
         sibling host).
    """
    normalized = canonicalize_url(url)
    metadata = get_store_metadata()
    result = _base_result(metadata, normalized)
    if not normalized["host"] or not metadata["available"]:
        return result

    fingerprint_key = fingerprint_hash(normalized["fingerprint"])
    exact_url_record = _STORE["url_fingerprints"].get(fingerprint_key)
    if exact_url_record is not None:
        sources = _record_sources(exact_url_record)
        count = _record_url_count(exact_url_record)
        return {
            **result,
            "match": True,
            "match_type": "exact_url",
            "score": _score_for_exact_url(sources, bool(metadata["stale"])),
            "sources": sources,
            "url_count": count,
            "evidence_class": "exact_url",
        }

    host_record = _STORE["hosts"].get(normalized["host"])
    if host_record is not None:
        sources = _record_sources(host_record)
        count = _record_url_count(host_record)
        score, evidence_class = _score_for_host(
            normalized["host"], normalized["root"], sources, bool(metadata["stale"])
        )
        return {
            **result,
            "match": True,
            "match_type": "host",
            "score": score,
            "sources": sources,
            "url_count": count,
            "evidence_class": evidence_class,
        }

    # Never promote a registrable-root record to a match for an unseen sibling.
    # Keep it as transparent non-blocking context for the API/UI.
    root_record = _STORE["roots"].get(normalized["root"])
    if root_record is not None:
        return {
            **result,
            "context_match": True,
            "context_sources": _record_sources(root_record),
            "context_url_count": _record_url_count(root_record),
            "evidence_class": "root_context_only",
        }

    return result
