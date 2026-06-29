"""PhishGuard v9 incremental URL model.

This model performs local URL-string analysis only. It does not fetch a URL,
follow redirects, access page contents, or query third-party services.
"""
from __future__ import annotations

import math
import re
import unicodedata
from typing import Sequence
from urllib.parse import urlparse

import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier

SUSPICIOUS_TERMS = (
    "login", "signin", "verify", "verification", "secure", "security", "account",
    "password", "payment", "wallet", "bank", "otp", "confirm", "update", "unlock",
    "suspend", "credential", "recover", "invoice", "refund", "kyc", "seed", "airdrop",
    "authorize", "billing", "support", "gift", "bonus", "crypto",
)

BRAND_TERMS = (
    "google", "microsoft", "apple", "openai", "chatgpt", "paypal", "binance",
    "coinbase", "maybank", "cimb", "touchngo", "shopee", "lazada", "grab",
    "amazon", "facebook", "instagram", "whatsapp", "netflix", "discord", "steam",
    "github", "linkedin", "tiktok", "telegram", "bankislam", "publicbank",
)

BAD_TLDS = {
    "xyz", "top", "click", "ru", "tk", "ml", "cf", "gq", "work", "loan",
    "monster", "rest", "fit", "buzz", "cam", "sbs", "cyou", "zip", "mov",
}

CONFUSABLE_MAP = {
    "0": "o", "o": "o", "O": "o", "ο": "o", "Ο": "o", "о": "o", "О": "o",
    "1": "l", "l": "l", "L": "l", "i": "l", "I": "l", "|": "l", "!": "l",
    "ı": "l", "İ": "l", "і": "l", "І": "l", "ӏ": "l",
    "3": "e", "e": "e", "E": "e", "€": "e",
    "4": "a", "a": "a", "A": "a", "@": "a",
    "5": "s", "s": "s", "S": "s", "$": "s",
    "7": "t", "t": "t", "T": "t", "8": "b", "b": "b", "B": "b",
    "9": "g", "g": "g", "G": "g",
    "а": "a", "А": "a", "α": "a", "Α": "a", "с": "c", "С": "c", "ϲ": "c",
    "е": "e", "Е": "e", "є": "e", "р": "p", "Р": "p", "ρ": "p",
    "х": "x", "Х": "x", "у": "y", "У": "y", "һ": "h", "Н": "h", "н": "h",
    "к": "k", "К": "k", "м": "m", "М": "m", "ν": "v", "ѵ": "v", "ʏ": "y",
}
CONFUSABLE_RE = re.compile(r"[01345789@!|$]|[οΟоОаАαΑсСϲеЕєрРρхуУһНнкКмМνѵʏıİіІӏ]", re.UNICODE)


def normalise_url(value: object) -> str:
    url = unicodedata.normalize("NFKC", str(value or "")).strip()
    if not url:
        return ""
    if not re.match(r"^https?://", url, flags=re.IGNORECASE):
        url = "https://" + url
    return url


def skeleton(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "")
    text = "".join(CONFUSABLE_MAP.get(ch, ch.lower()) for ch in text)
    return text.replace("rn", "m").replace("vv", "w")


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {c: text.count(c) for c in set(text)}
    n = len(text)
    return -sum((count / n) * math.log2(count / n) for count in counts.values())


def host_parts(url: str) -> tuple[str, str, str, str]:
    parsed = urlparse(normalise_url(url))
    host = (parsed.netloc or "").lower().split("@")[-1].split(":")[0].strip(".")
    return host, parsed.path or "", parsed.query or "", parsed.scheme.lower()


def root_and_sld(host: str) -> tuple[str, str]:
    parts = [x for x in host.split(".") if x]
    if len(parts) <= 2:
        root = host
    else:
        pair = ".".join(parts[-2:])
        two_level = {"com.my", "edu.my", "gov.my", "org.my", "net.my", "co.uk", "org.uk", "com.au", "co.jp", "com.sg", "co.id"}
        root = ".".join(parts[-3:]) if pair in two_level and len(parts) >= 3 else ".".join(parts[-2:])
    root_parts = [x for x in root.split(".") if x]
    return root, root_parts[0] if root_parts else ""


def edit_distance_one_or_less(a: str, b: str) -> bool:
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    i = j = differences = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1; j += 1
        else:
            differences += 1
            if differences > 1:
                return False
            if len(a) > len(b):
                i += 1
            elif len(b) > len(a):
                j += 1
            else:
                i += 1; j += 1
    return True


def lexical_features(urls: Sequence[object]) -> np.ndarray:
    rows: list[list[float]] = []
    for raw in urls:
        url = normalise_url(raw)
        lower = url.lower()
        host, path, query, scheme = host_parts(url)
        root, sld = root_and_sld(host)
        sld_skeleton = skeleton(sld)
        words = f"{host} {path} {query}".lower()
        labels = [x for x in host.split(".") if x]
        raw_tokens = [x for x in re.split(r"[^a-z0-9]+", sld) if len(x) >= 3]
        token_skeletons = [skeleton(x) for x in raw_tokens]
        keyword_hits = sum(term in words or skeleton(term) in skeleton(words) for term in SUSPICIOUS_TERMS)
        exact_brand = any(term in token_skeletons for term in BRAND_TERMS)
        near_brand = any(edit_distance_one_or_less(sld_skeleton, term) for term in BRAND_TERMS if len(sld_skeleton) >= 4)
        brand_in_root = any(term in skeleton(root) for term in BRAND_TERMS)
        digit_count = sum(ch.isdigit() for ch in url)
        host_digit_count = sum(ch.isdigit() for ch in host)
        special_count = sum(not ch.isalnum() for ch in url)
        ip_flag = int(bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host)))
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        suspicious_query = int(any(x in query.lower() for x in ("redirect", "return", "next", "continue", "url=", "target=")))
        rows.append([
            min(len(url), 300) / 300.0,
            min(len(host), 120) / 120.0,
            min(len(path), 220) / 220.0,
            min(len(query), 220) / 220.0,
            float(scheme == "https"),
            min(host.count("."), 8) / 8.0,
            min(max(len(labels) - 2, 0), 8) / 8.0,
            min(host.count("-"), 8) / 8.0,
            min(digit_count, 30) / 30.0,
            min(host_digit_count / max(1, len(host)), 1.0),
            min(special_count, 45) / 45.0,
            min(keyword_hits, 8) / 8.0,
            float(ip_flag),
            float("xn--" in host),
            float("%" in path or "%" in query),
            float("@" in url),
            float(tld in BAD_TLDS),
            min(entropy(sld), 5.0) / 5.0,
            float(len(sld) >= 20),
            float("//" in path),
            float(suspicious_query),
            float(any(x in words for x in ("login", "verify", "payment", "wallet", "password"))),
            float(bool(CONFUSABLE_RE.search(host))),
            min(sum(1 for ch in host if CONFUSABLE_RE.match(ch)), 10) / 10.0,
            float(exact_brand),
            float(near_brand),
            float(brand_in_root),
            float(any(token != skel for token, skel in zip(raw_tokens, token_skeletons))),
            float(len(raw_tokens) >= 2),
            float(host.endswith(".com") or host.endswith(".com.my")),
        ])
    return np.asarray(rows, dtype=np.float32)


class PhishGuardURLModelV9:
    """Incremental dual-vector URL classifier compatible with joblib."""

    def __init__(self, random_state: int = 42, char_features: int = 2 ** 20, word_features: int = 2 ** 18, alpha: float = 1.5e-6) -> None:
        self.char_vectorizer = HashingVectorizer(
            analyzer="char", ngram_range=(2, 6), n_features=char_features,
            alternate_sign=False, norm="l2", lowercase=True, dtype=np.float32,
        )
        self.word_vectorizer = HashingVectorizer(
            analyzer="word", ngram_range=(1, 2), token_pattern=r"(?u)[a-z0-9]{2,}",
            n_features=word_features, alternate_sign=False, norm="l2", lowercase=True, dtype=np.float32,
        )
        self.classifier = SGDClassifier(
            loss="log_loss", penalty="elasticnet", l1_ratio=0.05, alpha=alpha,
            average=True, random_state=random_state,
        )
        self._fitted = False
        self.feature_manifest = [
            {"name": "character_ngrams", "value": "2-6 character URL n-grams", "used_by_model": True, "model_importance": None, "model_importance_percent": None},
            {"name": "word_ngrams", "value": "1-2 token URL n-grams", "used_by_model": True, "model_importance": None, "model_importance_percent": None},
            {"name": "lexical_security_features", "value": "host depth, entropy, digits, Punycode, confusables, brand-like tokens, redirects and credential keywords", "used_by_model": True, "model_importance": None, "model_importance_percent": None},
        ]

    @property
    def classes_(self):
        return getattr(self.classifier, "classes_", np.asarray([0, 1]))

    def _transform(self, urls: Sequence[object]):
        clean = [normalise_url(x) for x in urls]
        char = self.char_vectorizer.transform(clean)
        words = self.word_vectorizer.transform(clean)
        lexical = csr_matrix(lexical_features(clean))
        return hstack([char, words, lexical], format="csr")

    def partial_fit(self, urls: Sequence[object], labels: Sequence[int], sample_weight: Sequence[float] | None = None, classes: Sequence[int] | None = None):
        x = self._transform(urls)
        y = np.asarray(labels, dtype=np.int64)
        kwargs = {"sample_weight": None if sample_weight is None else np.asarray(sample_weight, dtype=np.float64)}
        if not self._fitted:
            self.classifier.partial_fit(x, y, classes=np.asarray(classes or [0, 1]), **kwargs)
            self._fitted = True
        else:
            self.classifier.partial_fit(x, y, **kwargs)
        return self

    def predict_proba(self, urls: Sequence[object]) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError("PhishGuardURLModelV9 has not been trained")
        return self.classifier.predict_proba(self._transform(urls))
