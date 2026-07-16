"""Streaming URL classifier used by PhishGuard v8 training and deployment.

The model uses character n-grams plus lexical URL features. It does not visit
submitted URLs, so prediction remains local and deterministic.
"""
from __future__ import annotations

import math
import re
from typing import Iterable, Sequence
from urllib.parse import urlparse

import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier


SUSPICIOUS_TERMS = (
    "login", "signin", "verify", "verification", "secure", "security", "account",
    "password", "payment", "wallet", "bank", "otp", "confirm", "update", "unlock",
    "suspend", "credential", "recover", "invoice", "refund", "kyc", "seed", "airdrop",
)

BAD_TLDS = {
    "xyz", "top", "click", "ru", "tk", "ml", "cf", "gq", "work", "loan",
    "monster", "rest", "fit", "buzz", "cam", "sbs", "cyou",
}


def _normalise_url(value: object) -> str:
    url = str(value or "").strip()
    if not url:
        return ""
    if not re.match(r"^https?://", url, flags=re.IGNORECASE):
        url = "https://" + url
    return url


def _host_and_parts(url: str) -> tuple[str, str, str, str]:
    parsed = urlparse(_normalise_url(url))
    host = (parsed.netloc or "").lower().split("@")[-1].split(":")[0].strip(".")
    return host, parsed.path or "", parsed.query or "", parsed.scheme.lower()


def _root_domain(host: str) -> str:
    parts = [part for part in host.split(".") if part]
    if len(parts) <= 2:
        return host
    two_level = {"com.my", "edu.my", "gov.my", "org.my", "co.uk", "org.uk", "com.au", "co.jp", "com.sg"}
    last_two = ".".join(parts[-2:])
    if last_two in two_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {char: text.count(char) for char in set(text)}
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def lexical_features(urls: Sequence[object]) -> np.ndarray:
    """Return numerical lexical features for a batch of URL strings."""
    rows: list[list[float]] = []
    for raw in urls:
        url = _normalise_url(raw)
        lower = url.lower()
        host, path, query, scheme = _host_and_parts(url)
        root = _root_domain(host)
        sld = root.split(".")[0] if root else ""
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        words = f"{host} {path} {query}".lower()
        keyword_hits = sum(term in words for term in SUSPICIOUS_TERMS)
        digit_count = sum(ch.isdigit() for ch in url)
        special_count = sum(not ch.isalnum() for ch in url)
        host_digit_ratio = digit_count / max(1, len(host))
        subdomain_depth = max(0, len([part for part in host.split(".") if part]) - 2)
        ip_flag = int(bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host)))
        punycode_flag = int("xn--" in host)
        encoded_flag = int("%" in path or "%" in query)
        rows.append([
            min(len(url), 300) / 300.0,
            min(len(host), 120) / 120.0,
            min(len(path), 220) / 220.0,
            min(len(query), 220) / 220.0,
            float(scheme == "https"),
            min(host.count("."), 8) / 8.0,
            min(subdomain_depth, 8) / 8.0,
            min(host.count("-"), 8) / 8.0,
            min(digit_count, 30) / 30.0,
            min(host_digit_ratio, 1.0),
            min(special_count, 40) / 40.0,
            min(keyword_hits, 6) / 6.0,
            float(ip_flag),
            float(punycode_flag),
            float(encoded_flag),
            float("@" in url),
            float(tld in BAD_TLDS),
            min(_entropy(sld), 5.0) / 5.0,
            float(len(sld) >= 20),
            float("//" in path),
            float("redirect" in words or "url=" in query or "next=" in query),
            float(any(token in words for token in ("login", "verify", "payment", "wallet", "password"))),
        ])
    return np.asarray(rows, dtype=np.float32)


class PhishGuardURLModelV8:
    """Incremental binary URL classifier compatible with joblib."""

    def __init__(
        self,
        n_features: int = 2 ** 20,
        alpha: float = 2e-6,
        random_state: int = 42,
    ) -> None:
        self.vectorizer = HashingVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            n_features=n_features,
            alternate_sign=False,
            norm="l2",
            lowercase=True,
            dtype=np.float32,
        )
        self.classifier = SGDClassifier(
            loss="log_loss",
            penalty="l2",
            alpha=alpha,
            average=True,
            random_state=random_state,
        )
        self._fitted = False
        self.feature_manifest = [
            {
                "name": "character_ngrams",
                "value": "3-5 character URL n-grams",
                "used_by_model": True,
                "model_importance": None,
                "model_importance_percent": None,
            },
            {
                "name": "lexical_url_features",
                "value": "URL length, host structure, entropy, digits, keywords, Punycode, TLD and redirect features",
                "used_by_model": True,
                "model_importance": None,
                "model_importance_percent": None,
            },
        ]

    @property
    def classes_(self):
        return getattr(self.classifier, "classes_", np.asarray([0, 1]))

    def _transform(self, urls: Sequence[object]):
        clean = [_normalise_url(value) for value in urls]
        char_matrix = self.vectorizer.transform(clean)
        lexical_matrix = csr_matrix(lexical_features(clean))
        return hstack([char_matrix, lexical_matrix], format="csr")

    def partial_fit(
        self,
        urls: Sequence[object],
        labels: Sequence[int],
        sample_weight: Sequence[float] | None = None,
        classes: Sequence[int] | None = None,
    ) -> "PhishGuardURLModelV8":
        x = self._transform(urls)
        y = np.asarray(labels, dtype=np.int64)
        kwargs = {"sample_weight": sample_weight}
        if not self._fitted:
            self.classifier.partial_fit(x, y, classes=np.asarray(classes if classes is not None else [0, 1]), **kwargs)
            self._fitted = True
        else:
            self.classifier.partial_fit(x, y, **kwargs)
        return self

    def predict_proba(self, urls: Sequence[object]) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError("PhishGuardURLModelV8 has not been trained")
        return self.classifier.predict_proba(self._transform(urls))
