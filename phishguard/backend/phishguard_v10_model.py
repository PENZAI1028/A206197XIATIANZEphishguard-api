"""PhishGuard v10 URL model.

Designed for local, URL-string-only classification. It never fetches a page,
follows redirects, or contacts a third-party reputation service.

v10 adds dynamic protected-brand features derived from trusted_domains.json and
keeps the lightweight HashingVectorizer + SGD architecture so it can train in
batches on a large URL dataset.
"""
from __future__ import annotations

import json
import math
import re
import unicodedata
from functools import lru_cache
from pathlib import Path
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
    "authorize", "billing", "support", "gift", "bonus", "crypto", "token", "webmail",
    "authentication", "twofactor", "2fa", "identity", "limited", "validate",
)
BAD_TLDS = {
    "xyz", "top", "click", "ru", "tk", "ml", "cf", "gq", "work", "loan",
    "monster", "rest", "fit", "buzz", "cam", "sbs", "cyou", "zip", "mov",
}
TWO_LEVEL_SUFFIXES = {
    "com.my", "edu.my", "gov.my", "org.my", "net.my", "co.uk", "org.uk", "ac.uk",
    "gov.uk", "com.au", "net.au", "org.au", "co.jp", "ne.jp", "or.jp", "co.id",
    "or.id", "ac.id", "com.sg", "org.sg", "edu.sg",
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
    value = "".join(CONFUSABLE_MAP.get(ch, ch.lower()) for ch in text)
    return value.replace("rn", "m").replace("vv", "w")


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {c: text.count(c) for c in set(text)}
    n = len(text)
    return -sum((count / n) * math.log2(count / n) for count in counts.values())


def host_parts(url: str) -> tuple[str, str, str, str]:
    parsed = urlparse(normalise_url(url))
    host = (parsed.netloc or "").lower().split("@")[-1].split(":")[0].strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host, parsed.path or "", parsed.query or "", parsed.scheme.lower()


def root_and_sld(host: str) -> tuple[str, str]:
    parts = [x for x in host.split(".") if x]
    if len(parts) <= 2:
        root = host
    else:
        pair = ".".join(parts[-2:])
        root = ".".join(parts[-3:]) if pair in TWO_LEVEL_SUFFIXES and len(parts) >= 3 else pair
    root_parts = [x for x in root.split(".") if x]
    if len(root_parts) >= 3 and ".".join(root_parts[-2:]) in TWO_LEVEL_SUFFIXES:
        return root, root_parts[-3]
    return root, root_parts[0] if root_parts else ""


def edit_distance_one_or_less(a: str, b: str) -> bool:
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    i = j = changes = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1; j += 1
            continue
        changes += 1
        if changes > 1:
            return False
        if len(a) > len(b):
            i += 1
        elif len(b) > len(a):
            j += 1
        else:
            i += 1; j += 1
    return True


@lru_cache(maxsize=1)
def brand_registry() -> tuple[frozenset[str], frozenset[str], dict[int, tuple[str, ...]]]:
    """Return protected term skeletons, verified roots and terms indexed by length.

    A broken/missing JSON file falls back to a small core list rather than
    failing model loading.
    """
    fallback = {
        "google": ["google.com"], "microsoft": ["microsoft.com"], "apple": ["apple.com"],
        "openai": ["openai.com", "chatgpt.com"], "paypal": ["paypal.com"],
        "binance": ["binance.com"], "maybank": ["maybank2u.com.my"],
        "cimb": ["cimb.com.my"], "touchngo": ["touchngo.com.my"],
    }
    path = Path(__file__).with_name("trusted_domains.json")
    try:
        content = json.loads(path.read_text(encoding="utf-8"))
        official = content.get("official_domains", fallback)
        if not isinstance(official, dict):
            official = fallback
    except Exception:
        official = fallback

    terms: set[str] = set()
    roots: set[str] = set()
    for brand, domains in official.items():
        if isinstance(brand, str) and len(brand) >= 4:
            terms.add(skeleton(brand))
        if not isinstance(domains, list):
            continue
        for domain in domains:
            if not isinstance(domain, str):
                continue
            domain = domain.lower().strip().lstrip(".")
            root, sld = root_and_sld(domain)
            if root:
                roots.add(root)
            if len(sld) >= 4:
                terms.add(skeleton(sld))
    terms = {x for x in terms if 4 <= len(x) <= 40}
    by_len: dict[int, tuple[str, ...]] = {}
    for term in terms:
        by_len.setdefault(len(term), tuple())
        by_len[len(term)] = tuple(sorted(set(by_len[len(term)]) | {term}))
    return frozenset(terms), frozenset(roots), by_len


def brand_signals(host: str) -> tuple[float, float, float, float, float]:
    """Return exact, confusable, near, unofficial-token and official-root flags."""
    terms, official_roots, by_len = brand_registry()
    root, sld = root_and_sld(host)
    root_skeleton = skeleton(root)
    sld_tokens = [x for x in re.split(r"[^a-z0-9]+", sld.lower()) if len(x) >= 4]
    token_skeletons = [skeleton(x) for x in sld_tokens]
    exact = any(token in terms for token in token_skeletons)
    official_root = root in official_roots
    # A true official root can naturally contain the letter i/l (for example
    # binance). Count a substitution signal only when it is in an unofficial
    # root; the official-root feature remains separate.
    confusable = any(raw != skel and skel in terms for raw, skel in zip(sld_tokens, token_skeletons)) and not official_root
    unofficial_token = bool(exact and not official_root)

    near = False
    # Near-typo matching is deliberately limited to abnormal tokens. This
    # avoids O(N_brands) edit-distance checks on every ordinary URL in a
    # million-row training set while still covering e.g. gooogle / paypall.
    for raw, skel in zip(sld_tokens, token_skeletons):
        if not (CONFUSABLE_RE.search(raw) or len(raw) >= 6):
            continue
        candidates = by_len.get(len(skel), ()) + by_len.get(len(skel) - 1, ()) + by_len.get(len(skel) + 1, ())
        if any(edit_distance_one_or_less(skel, term) for term in candidates):
            near = True
            break
    return float(exact), float(confusable), float(near), float(unofficial_token), float(official_root)


def lexical_features(urls: Sequence[object]) -> np.ndarray:
    rows: list[list[float]] = []
    for raw in urls:
        url = normalise_url(raw)
        lower = url.lower()
        host, path, query, scheme = host_parts(url)
        root, sld = root_and_sld(host)
        words = f"{host} {path} {query}".lower()
        words_skeleton = skeleton(words)
        labels = [x for x in host.split(".") if x]
        digit_count = sum(ch.isdigit() for ch in url)
        host_digit_count = sum(ch.isdigit() for ch in host)
        special_count = sum(not ch.isalnum() for ch in url)
        ip_flag = int(bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host)))
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        keyword_hits = sum(term in words or skeleton(term) in words_skeleton for term in SUSPICIOUS_TERMS)
        redirect_terms = ("redirect", "return", "next", "continue", "url=", "target=", "dest=", "callback=")
        exact_brand, confusable_brand, near_brand, unofficial_brand, official_root = brand_signals(host)
        root_token_count = len([x for x in re.split(r"[^a-z0-9]+", sld.lower()) if len(x) >= 3])
        rows.append([
            min(len(url), 320) / 320.0,
            min(len(host), 128) / 128.0,
            min(len(path), 240) / 240.0,
            min(len(query), 240) / 240.0,
            float(scheme == "https"),
            min(host.count("."), 8) / 8.0,
            min(max(len(labels) - 2, 0), 8) / 8.0,
            min(host.count("-"), 8) / 8.0,
            min(digit_count, 32) / 32.0,
            min(host_digit_count / max(1, len(host)), 1.0),
            min(special_count, 48) / 48.0,
            min(keyword_hits, 10) / 10.0,
            float(ip_flag),
            float("xn--" in host),
            float("%" in path or "%" in query),
            float("@" in url),
            float(tld in BAD_TLDS),
            min(entropy(sld), 5.0) / 5.0,
            float(len(sld) >= 20),
            float("//" in path),
            float(any(x in query.lower() for x in redirect_terms)),
            float(any(x in words for x in ("login", "verify", "payment", "wallet", "password", "otp"))),
            float(bool(CONFUSABLE_RE.search(host))),
            min(sum(1 for ch in host if CONFUSABLE_RE.match(ch)), 12) / 12.0,
            exact_brand,
            confusable_brand,
            near_brand,
            unofficial_brand,
            official_root,
            float(root_token_count >= 2),
            float(any(ch.isdigit() for ch in sld)),
            float("-" in sld),
            float(host.endswith(".com") or host.endswith(".com.my")),
            float(len(query) > 60),
            float(len(path.split("/")) > 5),
        ])
    return np.asarray(rows, dtype=np.float32)


class PhishGuardURLModelV10:
    """Batch-trainable URL classifier with dynamic brand-security features."""

    def __init__(
        self,
        random_state: int = 42,
        char_features: int = 2 ** 20,
        word_features: int = 2 ** 18,
        alpha: float = 1.0e-6,
    ) -> None:
        self.char_vectorizer = HashingVectorizer(
            analyzer="char", ngram_range=(2, 7), n_features=char_features,
            alternate_sign=False, norm="l2", lowercase=True, dtype=np.float32,
        )
        self.word_vectorizer = HashingVectorizer(
            analyzer="word", ngram_range=(1, 3), token_pattern=r"(?u)[a-z0-9]{2,}",
            n_features=word_features, alternate_sign=False, norm="l2", lowercase=True, dtype=np.float32,
        )
        self.classifier = SGDClassifier(
            loss="log_loss", penalty="elasticnet", l1_ratio=0.03, alpha=alpha,
            average=True, random_state=random_state,
        )
        self._fitted = False
        self.feature_manifest = [
            {"name": "character_ngrams", "value": "2-7 character URL n-grams", "used_by_model": True, "model_importance": None, "model_importance_percent": None},
            {"name": "word_ngrams", "value": "1-3 token URL n-grams", "used_by_model": True, "model_importance": None, "model_importance_percent": None},
            {"name": "dynamic_brand_security_features", "value": "trusted-domain brand skeletons, substitutions, root ownership, URL structure and credential/redirect indicators", "used_by_model": True, "model_importance": None, "model_importance_percent": None},
        ]

    @property
    def classes_(self):
        return getattr(self.classifier, "classes_", np.asarray([0, 1]))

    def _transform(self, urls: Sequence[object]):
        clean = [normalise_url(x) for x in urls]
        chars = self.char_vectorizer.transform(clean)
        words = self.word_vectorizer.transform(clean)
        lexical = csr_matrix(lexical_features(clean))
        return hstack([chars, words, lexical], format="csr")

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
            raise RuntimeError("PhishGuardURLModelV10 has not been trained")
        return self.classifier.predict_proba(self._transform(urls))
