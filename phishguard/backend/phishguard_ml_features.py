"""
Reusable URL feature extractor for the v4 sklearn pipeline.

This module must stay next to app.py. joblib needs it when loading the
serialized training pipeline on Render.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

import numpy as np
from scipy import sparse


SUSPICIOUS_TOKENS = (
    "login", "signin", "verify", "secure", "account", "password", "payment",
    "wallet", "bank", "otp", "confirm", "update", "recover", "auth",
    "credential", "invoice", "refund", "crypto", "airdrop"
)


def normalise_for_model(value: object) -> str:
    url = str(value or "").strip().lower()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def lexical_url_matrix(urls):
    """
    Return a sparse numeric matrix. The function is deliberately top-level so
    it is safe to serialize inside sklearn's FunctionTransformer.
    """
    rows = []
    for item in urls:
        url = normalise_for_model(item)
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        combined = f"{host} {path} {query}"

        root_label = host.split(".")[0] if host else ""
        digit_count = sum(ch.isdigit() for ch in url)
        special_count = len(re.findall(r"[^a-z0-9]", url))
        keyword_count = sum(token in combined for token in SUSPICIOUS_TOKENS)
        ip_like = bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host))
        punycode = "xn--" in host

        rows.append([
            len(url),
            len(host),
            len(path),
            len(query),
            host.count("."),
            host.count("-"),
            url.count("@"),
            url.count("?"),
            url.count("="),
            url.count("%"),
            url.count("/"),
            digit_count,
            digit_count / max(len(url), 1),
            special_count,
            keyword_count,
            int(url.startswith("https://")),
            int(ip_like),
            int(punycode),
            int(any(ch.isdigit() for ch in root_label)),
            int(len(url) >= 80),
            int(len(url) >= 120),
        ])

    return sparse.csr_matrix(np.asarray(rows, dtype=np.float32))
