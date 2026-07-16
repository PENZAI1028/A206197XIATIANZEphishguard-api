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

# Ordered contract used by lexical_url_matrix and the published model audit.
LEXICAL_FEATURE_NAMES = (
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "host_dot_count",
    "host_hyphen_count",
    "at_count",
    "question_count",
    "equals_count",
    "percent_count",
    "slash_count",
    "digit_count",
    "digit_ratio",
    "special_character_count",
    "suspicious_token_count",
    "https_flag",
    "ip_host_flag",
    "punycode_flag",
    "root_label_digit_flag",
    "url_length_at_least_80_flag",
    "url_length_at_least_120_flag",
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

        row = [
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
        ]
        if len(row) != len(LEXICAL_FEATURE_NAMES):
            raise RuntimeError("Lexical feature implementation does not match its published contract.")
        rows.append(row)

    return sparse.csr_matrix(np.asarray(rows, dtype=np.float32))
