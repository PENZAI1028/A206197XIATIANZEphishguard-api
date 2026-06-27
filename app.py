from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import re
import time
import unicodedata
from datetime import datetime
from urllib.parse import urlparse
from difflib import SequenceMatcher

app = Flask(__name__)
CORS(app)

# =========================
# Model loading
# =========================
try:
    model = joblib.load("phishing_web_model.pkl")
    MODEL_LOAD_ERROR = None
except Exception as e:
    model = None
    MODEL_LOAD_ERROR = str(e)

API_VERSION = "2.9"
MODEL_NAME = "Enhanced Extra Trees URL Classifier"
SCORE_METHOD = "Auditable 9-Indicator Weighted Scoring + Calibrated AI Probability"
AI_WEIGHT = 0.18

MODEL_FEATURE_NAMES = [
    "url_length",
    "uses_https",
    "netloc_length",
    "path_length",
    "dot_count",
    "hyphen_count",
    "at_count",
    "question_count",
    "equals_count",
    "slash_count",
    "digit_count",
    "special_character_count",
    "ip_address_flag",
    "suspicious_keyword_count",
    "brand_literal_count",
    "brand_confusable_count",
    "official_domain_flag",
    "domain_lookalike_flag",
    "minimum_brand_distance",
    "maximum_brand_similarity",
    "shortener_domain_flag",
    "shortener_brand_path_flag"
]

# Every indicator shown by the API has a real, non-zero role in the weighted score.
# The weights sum to 1.00. Critical and official-domain rules are applied afterwards
# and are reported separately in the score audit.
INDICATOR_WEIGHTS = {
    "officialDomain": 0.10,
    "aiModelProbability": AI_WEIGHT,
    "brandVerification": 0.18,
    "homographAttack": 0.18,
    "urlStructure": 0.10,
    "suspiciousKeywords": 0.10,
    "sslCertificate": 0.05,
    "urlLengthComplexity": 0.05,
    "domainReputation": 0.06
}

# =========================
# Official domains / protected brands
# Add your own verified domains here.
# =========================
OFFICIAL_DOMAINS = {
    "google": [
        "google.com", "google.com.my", "accounts.google.com", "mail.google.com"
    ],
    "paypal": [
        "paypal.com", "paypal.com.my"
    ],
    "render": [
        "render.com", "dashboard.render.com", "onrender.com"
    ],
    "figma": [
        "figma.com"
    ],
    "cisco": [
        "cisco.com", "webex.com"
    ],
    "apple": [
        "apple.com", "icloud.com"
    ],
    "microsoft": [
        "microsoft.com", "office.com", "live.com", "outlook.com",
        "login.microsoftonline.com"
    ],
    "amazon": [
        "amazon.com", "amazon.com.my"
    ],
    "facebook": [
        "facebook.com", "fb.com"
    ],
    "instagram": [
        "instagram.com"
    ],
    "netflix": [
        "netflix.com"
    ],
    "whatsapp": [
        "whatsapp.com"
    ],
    "github": [
        "github.com"
    ],
    "stackoverflow": [
        "stackoverflow.com"
    ],
    "openai": [
        "openai.com", "chatgpt.com"
    ],
    "ukm": [
        "ukm.my", "ukmfolio.ukm.my", "fism.ukm.my", "ftsm.ukm.my",
        "siswa.ukm.edu.my"
    ],
    "maybank": [
        "maybank2u.com.my", "maybank.com"
    ],
    "cimb": [
        "cimb.com.my", "cimbclicks.com.my"
    ],
    "rhb": [
        "rhbgroup.com"
    ],
    "touchngo": [
        "touchngo.com.my", "tngdigital.com.my"
    ],
    "tng": [
        "touchngo.com.my", "tngdigital.com.my"
    ]
}

# Some official hosts should be matched exactly only. For example,
# "dashb0ard.render.com" is under render.com but visually imitates
# "dashboard.render.com", so it must not be trusted just because the
# parent domain is official.
EXACT_ONLY_OFFICIAL_DOMAINS = {
    "render.com",
    "dashboard.render.com"
}

PROTECTED_SERVICE_LABELS = {
    "account", "accounts", "auth", "billing", "dashboard", "email", "elearning",
    "fism", "ftsm", "helpdesk", "lms", "login", "mail", "moodle", "my",
    "payment", "portal", "secure", "security", "service", "signin", "siswa",
    "support", "ukmfolio", "verify", "webmail"
}

SHORTENER_DOMAINS = {
    "goo.su", "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "rebrand.ly", "shorturl.at", "ow.ly", "buff.ly", "s.id",
    "lnkd.in", "tiny.cc", "rb.gy"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "security", "update", "account", "confirm",
    "payment", "password", "unlock", "suspend", "wallet", "support",
    "limited", "signin", "sign-in", "reset", "bank", "urgent", "locked",
    "email", "emails", "credential", "credentials", "otp", "auth",
    "recover", "verification", "validate"
]

BAD_TLDS = {
    "xyz": 80,
    "top": 80,
    "click": 80,
    "ru": 85,
    "tk": 80,
    "ml": 80,
    "cf": 75,
    "gq": 75,
    "info": 65,
    "work": 65,
    "loan": 80,
    "monster": 75,
    "rest": 70,
    "fit": 70
}

COMMON_TLDS = {
    "com", "net", "org", "edu", "gov", "my", "uk", "io", "ai", "co",
    "com.my", "edu.my", "gov.my", "org.my", "co.uk"
}

TWO_LEVEL_SUFFIXES = {
    "com.my", "edu.my", "gov.my", "org.my", "net.my",
    "co.uk", "org.uk", "ac.uk",
    "com.au", "net.au", "org.au",
    "co.jp", "ne.jp",
    "co.id", "or.id"
}

# =========================
# Confusable / look-alike mapping
# This fixes: goog1e, g00gle, paypaI, c0m, rn -> m, vv -> w
# =========================
CONFUSABLE_MAP = {
    # o / 0 / Greek omicron / Cyrillic o
    "0": "o", "o": "o", "O": "o",
    "ο": "o", "Ο": "o", "о": "o", "О": "o",

    # l / I / i / 1 / |
    "1": "l", "l": "l", "L": "l",
    "i": "l", "I": "l", "|": "l", "!": "l",
    "ı": "l", "İ": "l", "і": "l", "І": "l", "ӏ": "l",

    # e / 3
    "3": "e", "e": "e", "E": "e", "€": "e",

    # a / 4 / @
    "4": "a", "a": "a", "A": "a", "@": "a",

    # s / 5 / $
    "5": "s", "s": "s", "S": "s", "$": "s",

    # t / 7
    "7": "t", "t": "t", "T": "t",

    # b / 8
    "8": "b", "b": "b", "B": "b",

    # g / 9
    "9": "g", "g": "g", "G": "g",

    # common cross-script confusables
    "а": "a", "А": "a", "α": "a", "Α": "a",
    "с": "c", "С": "c", "ϲ": "c", "¢": "c",
    "е": "e", "Е": "e", "є": "e",
    "р": "p", "Р": "p",
    "х": "x", "Х": "x",
    "у": "y", "У": "y",
    "һ": "h", "Н": "h", "н": "h",
    "к": "k", "К": "k",
    "м": "m", "М": "m",
    "ν": "v", "ѵ": "v",
    "ʏ": "y",
}


# =========================
# Basic URL helpers
# =========================
def normalize_url(url):
    url = unicodedata.normalize("NFKC", str(url or "")).strip()
    url = re.sub(r"\s+", "", url)
    url = re.sub(r"[\s,;，；\u3001\u3002]+$", "", url)
    url = re.sub(r"^[\.,;，；\u3002]+(?=https?[:?]//)", "", url, flags=re.IGNORECASE)
    url = re.sub(r"^(https?)\?//", r"\1://", url, flags=re.IGNORECASE)
    url = re.sub(r"^(https?):/+", r"\1://", url, flags=re.IGNORECASE)

    # Recover scheme-smuggling mistakes produced by copy/paste or front-end auto-prefixing:
    # ".https://goo.su/..." -> "https://goo.su/..."
    # "https://https://goo.su/..." -> "https://goo.su/..."
    # "https://.https://goo.su/..." -> "https://goo.su/..."
    previous = None
    while previous != url:
        previous = url
        url = re.sub(r"^https?://[\.,;，；\u3002]*(https?://)", r"\1", url, flags=re.IGNORECASE)

    if not url:
        return ""

    lower_url = url.lower()
    if not lower_url.startswith("http://") and not lower_url.startswith("https://"):
        url = "https://" + url

    return url


def strip_www(host):
    host = host.strip().lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def parse_url(url):
    url = normalize_url(url)
    parsed = urlparse(url)

    host = parsed.netloc.strip().lower()

    # Remove username/password part if it exists
    if "@" in host:
        host = host.split("@")[-1]

    # Remove port
    if ":" in host:
        host = host.split(":")[0]

    host = strip_www(host)

    # Convert Unicode domains to IDNA form.
    # If the domain becomes xn--, it will be treated as high risk later.
    try:
        host_idna = host.encode("idna").decode("ascii").lower()
    except Exception:
        host_idna = host

    return {
        "url": url,
        "scheme": parsed.scheme.lower(),
        "domain": strip_www(host_idna),
        "raw_domain": host,
        "path": parsed.path or "",
        "query": parsed.query or "",
        "parsed": parsed
    }


def get_domain(url):
    return parse_url(url)["domain"]


def get_tld(domain):
    parts = domain.split(".")
    return parts[-1] if len(parts) > 1 else ""


def get_root_domain(domain):
    domain = strip_www(domain)
    parts = domain.split(".")

    if len(parts) <= 2:
        return domain

    last_two = ".".join(parts[-2:])
    if last_two in TWO_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def get_sld(domain):
    root = get_root_domain(domain)
    parts = root.split(".")

    if len(parts) < 2:
        return root

    # google.com.my -> google
    last_two = ".".join(parts[-2:])
    if last_two in TWO_LEVEL_SUFFIXES and len(parts) >= 3:
        return parts[-3]

    # google.com -> google
    return parts[-2]


def is_same_or_subdomain(domain, official):
    domain = strip_www(domain)
    official = strip_www(official)
    return domain == official or domain.endswith("." + official)


def subdomain_labels_before_official(domain, official):
    domain = strip_www(domain)
    official = strip_www(official)

    if domain == official or not domain.endswith("." + official):
        return []

    prefix = domain[:-(len(official) + 1)]
    return [label for label in prefix.split(".") if label]


def has_ascii_lookalike_marker(label):
    return bool(re.search(r"[01345789@!|$]", label or ""))


def suspicious_unverified_official_subdomain(domain, official):
    suspicious = []

    for label in subdomain_labels_before_official(domain, official):
        if not has_ascii_lookalike_marker(label):
            continue

        label_skeleton = normalize_confusable(label)

        for service_label in PROTECTED_SERVICE_LABELS:
            service_skeleton = normalize_confusable(service_label)
            distance = levenshtein_distance(label_skeleton, service_skeleton)
            similarity = similarity_ratio(label_skeleton, service_skeleton)

            if label_skeleton == service_skeleton or distance <= 1 or similarity >= 0.88:
                suspicious.append({
                    "label": label,
                    "label_skeleton": label_skeleton,
                    "matched_service": service_label,
                    "matched_service_skeleton": service_skeleton,
                    "distance": distance,
                    "similarity": round(similarity, 2)
                })
                break

    return suspicious


def is_official_domain_match(domain, official):
    domain = strip_www(domain)
    official = strip_www(official)

    if official in EXACT_ONLY_OFFICIAL_DOMAINS:
        return domain == official

    if suspicious_unverified_official_subdomain(domain, official):
        return False

    return is_same_or_subdomain(domain, official)


def normalize_confusable(text):
    if not text:
        return ""

    text = unicodedata.normalize("NFKC", str(text))

    chars = []
    for ch in text:
        chars.append(CONFUSABLE_MAP.get(ch, ch.lower()))

    result = "".join(chars)

    # Multi-character visual replacements
    result = result.replace("rn", "m")
    result = result.replace("vv", "w")

    return result


def similarity_ratio(a, b):
    return SequenceMatcher(None, a, b).ratio()


def levenshtein_distance(a, b):
    if a == b:
        return 0

    if len(a) < len(b):
        a, b = b, a

    previous = list(range(len(b) + 1))

    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (ca != cb)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current

    return previous[-1]


def domain_is_official(domain):
    domain = strip_www(domain)

    for brand, domains in OFFICIAL_DOMAINS.items():
        for official in domains:
            official = strip_www(official)
            if is_official_domain_match(domain, official):
                return True, brand, official

    return False, None, None


def find_suspicious_official_subdomain(domain):
    domain = strip_www(domain)

    for brand, domains in OFFICIAL_DOMAINS.items():
        for official in domains:
            official = strip_www(official)
            suspicious_labels = suspicious_unverified_official_subdomain(domain, official)

            if suspicious_labels:
                return True, brand, official, suspicious_labels

    return False, None, None, []


def domain_skeleton_matches_official(domain):
    domain = strip_www(domain)
    domain_skeleton = normalize_confusable(domain)

    for brand, domains in OFFICIAL_DOMAINS.items():
        for official in domains:
            official = strip_www(official)
            official_skeleton = normalize_confusable(official)

            if is_official_domain_match(domain_skeleton, official_skeleton):
                official_raw, _, _ = domain_is_official(domain)

                if not official_raw:
                    return True, brand, official

    return False, None, None


def is_shortener_domain(domain):
    domain = strip_www(domain)
    return any(domain == shortener or domain.endswith("." + shortener) for shortener in SHORTENER_DOMAINS)


def protected_brand_terms():
    terms = []

    for brand, domains in OFFICIAL_DOMAINS.items():
        brand_term = normalize_confusable(brand)
        if len(brand_term) >= 4:
            terms.append((brand, brand_term, brand))

        for official in domains:
            official_sld = normalize_confusable(get_sld(official))
            if len(official_sld) >= 4:
                terms.append((brand, official_sld, official))

    unique_terms = {}
    for brand, term, source in terms:
        unique_terms[(brand, term)] = source

    return [
        {"brand": brand, "term": term, "source": source}
        for (brand, term), source in unique_terms.items()
    ]


def find_brand_like_token(text, min_ratio=0.88):
    skeleton = normalize_confusable(text)
    tokens = [
        token
        for token in re.split(r"[^a-z0-9]+", skeleton)
        if len(token) >= 4
    ]

    for token in tokens:
        for entry in protected_brand_terms():
            term = entry["term"]

            if abs(len(token) - len(term)) > max(2, int(len(term) * 0.35)):
                continue

            if token == term or (len(term) >= 5 and term in token):
                return {
                    "brand": entry["brand"],
                    "matched_token": token,
                    "matched_term": term,
                    "source": entry["source"],
                    "distance": 0,
                    "similarity": 1.0
                }

            distance = levenshtein_distance(token, term)
            ratio = similarity_ratio(token, term)
            max_distance = 1 if len(term) <= 6 else 2

            if distance <= max_distance or ratio >= min_ratio:
                return {
                    "brand": entry["brand"],
                    "matched_token": token,
                    "matched_term": term,
                    "source": entry["source"],
                    "distance": distance,
                    "similarity": round(ratio, 3)
                }

    return None


def domain_brand_similarity_features(domain):
    official, _, _ = domain_is_official(domain)
    domain_root = get_root_domain(domain)
    domain_sld = get_sld(domain_root)
    domain_sld_skeleton = normalize_confusable(domain_sld)

    min_distance = 10
    max_similarity = 0.0
    lookalike = 0

    for entry in protected_brand_terms():
        term = entry["term"]
        distance = levenshtein_distance(domain_sld_skeleton, term)
        ratio = similarity_ratio(domain_sld_skeleton, term)
        min_distance = min(min_distance, distance)
        max_similarity = max(max_similarity, ratio)

        max_distance = 1 if len(term) <= 6 else 2
        exact_confusable_match = domain_sld_skeleton == term and domain_sld != term
        near_brand_match = domain_sld_skeleton != term and (distance <= max_distance or ratio >= 0.90)

        if not official and (exact_confusable_match or near_brand_match):
            lookalike = 1

    return lookalike, min_distance, round(max_similarity * 100, 2)


# =========================
# AI model functions
# =========================
def extract_url_features(url):
    url = normalize_url(url)
    lower = url.lower()
    parsed = urlparse(url)
    parsed_data = parse_url(url)
    domain = parsed_data["domain"]
    path = parsed_data["path"]
    query = parsed_data["query"]
    brands = list(OFFICIAL_DOMAINS.keys())
    url_skeleton = normalize_confusable(lower)
    official_flag = 1 if domain_is_official(domain)[0] else 0
    domain_lookalike_flag, min_brand_distance, max_brand_similarity = domain_brand_similarity_features(domain)
    shortener_flag = 1 if is_shortener_domain(domain) else 0
    shortener_brand_path_flag = 1 if shortener_flag and find_brand_like_token(f"{path} {query}") else 0

    # Feature layout must match train_web_model.py.
    return [[
        len(url),
        1 if lower.startswith("https://") else 0,
        len(parsed.netloc),
        len(parsed.path),
        url.count("."),
        url.count("-"),
        url.count("@"),
        url.count("?"),
        url.count("="),
        url.count("/"),
        sum(c.isdigit() for c in url),
        len(re.findall(r"[^a-zA-Z0-9]", url)),
        1 if re.search(r"(\d{1,3}\.){3}\d{1,3}", url) else 0,
        sum(word in lower for word in SUSPICIOUS_KEYWORDS),
        sum(brand in lower for brand in brands),
        sum(normalize_confusable(brand) in url_skeleton for brand in brands),
        official_flag,
        domain_lookalike_flag,
        min_brand_distance,
        max_brand_similarity,
        shortener_flag,
        shortener_brand_path_flag
    ]]


def build_model_feature_audit(features):
    values = list(features[0])
    importances = getattr(model, "feature_importances_", None)

    if len(values) != len(MODEL_FEATURE_NAMES):
        raise RuntimeError(
            f"Feature contract mismatch: extracted {len(values)} values for "
            f"{len(MODEL_FEATURE_NAMES)} feature names."
        )

    if hasattr(model, "n_features_in_") and int(model.n_features_in_) != len(values):
        raise RuntimeError(
            f"Model contract mismatch: model expects {model.n_features_in_} features, "
            f"but the API extracted {len(values)}."
        )

    audit = []
    for index, (name, value) in enumerate(zip(MODEL_FEATURE_NAMES, values)):
        importance = float(importances[index]) if importances is not None else None
        audit.append({
            "name": name,
            "value": value,
            "used_by_model": True,
            "model_importance": round(importance, 8) if importance is not None else None,
            "model_importance_percent": round(importance * 100, 4) if importance is not None else None
        })

    return audit


def get_phishing_probability(features):
    if model is None:
        raise RuntimeError(f"AI model is unavailable: {MODEL_LOAD_ERROR or 'unknown loading error'}")

    try:
        probability = model.predict_proba(features)[0]

        if hasattr(model, "classes_") and 1 in model.classes_:
            phishing_index = list(model.classes_).index(1)
            phishing_probability = float(probability[phishing_index])
        else:
            phishing_probability = float(probability[-1])

        confidence = float(max(probability))

        return phishing_probability, confidence

    except Exception as exc:
        raise RuntimeError(f"AI model prediction failed: {exc}") from exc


def estimate_feature_ai_probability(url, domain, scheme, path, query, official_domain):
    """Continuous lexical estimate used to calibrate over-confident Random Forest votes."""
    target = f"{domain} {path} {query}".lower()
    target_skeleton = normalize_confusable(target)
    path_query = f"{path} {query}"
    tld = get_tld(domain)
    tld_skeleton = normalize_confusable(tld)
    root = get_root_domain(domain)
    sld = get_sld(root)
    brand_path_match = find_brand_like_token(path_query)

    score = 4 if official_domain else 12

    if scheme != "https":
        score += 12

    if is_shortener_domain(domain):
        score += 22

        if brand_path_match:
            score += 48

    if re.search(r"(\d{1,3}\.){3}\d{1,3}", domain):
        score += 36

    if "@" in url:
        score += 36

    if tld in BAD_TLDS:
        score += min(22, BAD_TLDS[tld] * 0.25)

    if tld != tld_skeleton and tld_skeleton in COMMON_TLDS:
        score += 38

    keyword_hits = 0
    for word in SUSPICIOUS_KEYWORDS:
        word_skeleton = normalize_confusable(word)
        if word in target or word_skeleton in target_skeleton:
            keyword_hits += 1

    score += min(28, keyword_hits * 7)

    if not official_domain:
        skeleton_match, _, _ = domain_skeleton_matches_official(domain)
        if skeleton_match:
            score += 45

        domain_skeleton = normalize_confusable(domain)
        for brand in OFFICIAL_DOMAINS.keys():
            if normalize_confusable(brand) in domain_skeleton:
                score += 22
                break

        domain_root = get_root_domain(domain)
        domain_sld_skeleton = normalize_confusable(get_sld(domain_root))

        for _, official_list in OFFICIAL_DOMAINS.items():
            for official in official_list:
                official_root = get_root_domain(official)

                if domain_root == official_root:
                    continue

                official_sld_skeleton = normalize_confusable(get_sld(official_root))
                distance = levenshtein_distance(domain_sld_skeleton, official_sld_skeleton)
                ratio = similarity_ratio(domain_sld_skeleton, official_sld_skeleton)

                if distance == 1 or ratio >= 0.90:
                    score += 60
                    break

    digit_ratio = (sum(char.isdigit() for char in sld) / len(sld)) if sld else 0
    if digit_ratio >= 0.30:
        score += 12
    elif any(char.isdigit() for char in sld):
        score += 6

    hyphen_count = domain.count("-")
    if hyphen_count >= 3:
        score += 14
    elif hyphen_count > 0:
        score += 6

    if len(url) > 120:
        score += 16
    elif len(url) > 80:
        score += 10
    elif len(url) > 55 and not official_domain:
        score += 5

    if official_domain:
        score = min(score, 8)

    return float(max(0.02, min(0.95, score / 100)))


def calibrate_ai_probability(raw_probability, feature_probability):
    """Blend model probability with lexical evidence so the display is not a hard 0/100 switch."""
    estimator_count = len(model.estimators_) if model is not None and hasattr(model, "estimators_") else 100
    smoothed_model_probability = ((raw_probability * estimator_count) + 1) / (estimator_count + 2)

    if raw_probability <= 0.50 and feature_probability >= 0.70:
        calibrated = (feature_probability * 0.85) + (smoothed_model_probability * 0.15)
    elif raw_probability <= 0.02 or raw_probability >= 0.98:
        calibrated = (feature_probability * 0.70) + (smoothed_model_probability * 0.30)
    else:
        calibrated = (feature_probability * 0.40) + (smoothed_model_probability * 0.60)

    return float(max(0.02, min(0.95, calibrated)))


def indicator(name, score, status, explanation, value=None, weight=None):
    score = int(max(0, min(100, score)))

    return {
        "name": name,
        "score": score,
        "risk_points": score,
        "safety_score": 100 - score,
        "status": status,
        "explanation": explanation,
        "value": value,
        "weight": weight
    }


# =========================
# Indicator detection
# =========================
def detect_official_domain(domain):
    official, brand, matched = domain_is_official(domain)

    if official:
        return indicator(
            "officialDomain",
            0,
            "safe",
            f"The URL matches a verified official domain: {matched}.",
            domain,
            "12%"
        )

    suspicious_subdomain, suspicious_brand, parent_domain, suspicious_labels = find_suspicious_official_subdomain(domain)

    if suspicious_subdomain:
        return indicator(
            "officialDomain",
            95,
            "danger",
            (
                "Suspicious unverified subdomain under a protected official domain. "
                "The subdomain uses look-alike character substitution for a protected service name."
            ),
            {
                "domain": domain,
                "protected_parent_domain": parent_domain,
                "matched_brand": suspicious_brand,
                "suspicious_labels": suspicious_labels
            },
            "12%"
        )

    skeleton_match, skeleton_brand, skeleton_official = domain_skeleton_matches_official(domain)

    if skeleton_match:
        return indicator(
            "officialDomain",
            100,
            "danger",
            f"Look-alike official domain detected. This domain visually matches '{skeleton_official}' but is not the real official domain.",
            {
                "domain": domain,
                "matched_brand": skeleton_brand,
                "matched_official": skeleton_official,
                "domain_skeleton": normalize_confusable(domain)
            },
            "12%"
        )

    return indicator(
        "officialDomain",
        20,
        "warning",
        "The URL does not match the verified official-domain whitelist.",
        domain,
        "12%"
    )


def detect_brand_impersonation(domain, path="", query=""):
    official, official_brand, official_matched = domain_is_official(domain)

    if official:
        return indicator(
            "brandVerification",
            0,
            "safe",
            f"Official brand domain verified: {official_brand}.",
            official_brand,
            "20%"
        )

    domain_skeleton = normalize_confusable(domain)
    root = get_root_domain(domain)

    for brand, official_list in OFFICIAL_DOMAINS.items():
        brand_skeleton = normalize_confusable(brand)

        if brand_skeleton in domain_skeleton:
            return indicator(
                "brandVerification",
                100,
                "danger",
                f"Possible brand impersonation detected: '{brand}' appears in an unofficial or look-alike domain.",
                {
                    "brand": brand,
                    "domain": domain,
                    "domain_skeleton": domain_skeleton
                },
                "20%"
            )

        for official in official_list:
            official_root = get_root_domain(official)
            fake_sld = normalize_confusable(get_sld(root))
            official_sld = normalize_confusable(get_sld(official_root))

            distance = levenshtein_distance(fake_sld, official_sld)

            if distance == 1 and root != official_root:
                return indicator(
                    "brandVerification",
                    95,
                    "danger",
                    f"Possible brand typo-squatting detected. '{root}' is very similar to '{official_root}'.",
                    {
                        "brand": brand,
                        "domain": domain,
                        "official": official_root,
                        "distance": distance
                    },
                    "20%"
                )

    if is_shortener_domain(domain):
        brand_path_match = find_brand_like_token(f"{path} {query}")

        if brand_path_match:
            return indicator(
                "brandVerification",
                95,
                "danger",
                (
                    "Known URL shortener contains a look-alike protected brand in the redirect path. "
                    f"Matched '{brand_path_match['matched_token']}' to '{brand_path_match['source']}'."
                ),
                {
                    "shortener_domain": domain,
                    "matched_brand": brand_path_match["brand"],
                    "matched_token": brand_path_match["matched_token"],
                    "matched_term": brand_path_match["matched_term"],
                    "similarity": brand_path_match["similarity"],
                    "distance": brand_path_match["distance"]
                },
                "20%"
            )

    return indicator(
        "brandVerification",
        0,
        "safe",
        "No brand impersonation was detected.",
        "Not applicable",
        "20%"
    )


def detect_homograph_attack(domain):
    official, _, _ = domain_is_official(domain)

    if official:
        return indicator(
            "homographAttack",
            0,
            "safe",
            "No look-alike issue was detected because the domain is verified as official.",
            domain,
            "20%"
        )

    suspicious_subdomain, suspicious_brand, parent_domain, suspicious_labels = find_suspicious_official_subdomain(domain)

    if suspicious_subdomain:
        return indicator(
            "homographAttack",
            95,
            "danger",
            (
                "Look-alike subdomain detected under a protected official parent domain. "
                "This pattern is commonly used to impersonate trusted institutional services."
            ),
            {
                "domain": domain,
                "protected_parent_domain": parent_domain,
                "matched_brand": suspicious_brand,
                "suspicious_labels": suspicious_labels
            },
            "20%"
        )

    if "xn--" in domain:
        return indicator(
            "homographAttack",
            100,
            "danger",
            "Punycode domain detected. This may indicate an IDN homograph attack.",
            domain,
            "20%"
        )

    tld = get_tld(domain)
    tld_skeleton = normalize_confusable(tld)

    if tld != tld_skeleton and tld_skeleton in COMMON_TLDS:
        return indicator(
            "homographAttack",
            100,
            "danger",
            f"Confusable TLD detected: '.{tld}' visually looks like '.{tld_skeleton}'.",
            {
                "domain": domain,
                "tld": tld,
                "tld_skeleton": tld_skeleton
            },
            "20%"
        )

    skeleton_match, brand, official = domain_skeleton_matches_official(domain)

    if skeleton_match:
        return indicator(
            "homographAttack",
            100,
            "danger",
            f"Critical homograph/look-alike domain detected. The domain visually matches '{official}'.",
            {
                "domain": domain,
                "official": official,
                "brand": brand,
                "domain_skeleton": normalize_confusable(domain)
            },
            "20%"
        )

    domain_root = get_root_domain(domain)
    domain_sld_skeleton = normalize_confusable(get_sld(domain_root))

    for brand, official_list in OFFICIAL_DOMAINS.items():
        for official in official_list:
            official_root = get_root_domain(official)
            official_sld_skeleton = normalize_confusable(get_sld(official_root))

            if domain_root == official_root:
                continue

            ratio = similarity_ratio(domain_sld_skeleton, official_sld_skeleton)
            distance = levenshtein_distance(domain_sld_skeleton, official_sld_skeleton)

            if distance == 1 or ratio >= 0.90:
                return indicator(
                    "homographAttack",
                    90,
                    "danger",
                    f"Possible typo-squatting detected. '{domain_root}' is very similar to '{official_root}'.",
                    {
                        "domain": domain,
                        "official": official_root,
                        "brand": brand,
                        "similarity": round(ratio, 2),
                        "distance": distance
                    },
                    "20%"
                )

    return indicator(
        "homographAttack",
        0,
        "safe",
        "No strong look-alike domain pattern was detected.",
        domain,
        "20%"
    )


def detect_url_structure(url, domain, scheme, path, query):
    official, _, _ = domain_is_official(domain)

    structure_score = 0
    structure_reasons = []
    brand_path_match = find_brand_like_token(f"{path} {query}")

    if is_shortener_domain(domain):
        structure_score += 45
        structure_reasons.append("Known URL shortener hides the final destination")

        if brand_path_match:
            structure_score += 60
            structure_reasons.append(
                f"Short link path contains look-alike brand token '{brand_path_match['matched_token']}'"
            )

    if "@" in url:
        structure_score += 100
        structure_reasons.append("URL contains '@', which may hide the real destination")

    if re.search(r"(\d{1,3}\.){3}\d{1,3}", domain):
        structure_score += 100
        structure_reasons.append("URL uses an IP address instead of a normal domain")

    if "xn--" in domain:
        structure_score += 100
        structure_reasons.append("Punycode domain detected")

    tld = get_tld(domain)
    tld_skeleton = normalize_confusable(tld)

    if tld in BAD_TLDS:
        structure_score += BAD_TLDS[tld]
        structure_reasons.append(f"Suspicious TLD detected: .{tld}")

    if tld != tld_skeleton and tld_skeleton in COMMON_TLDS:
        structure_score += 100
        structure_reasons.append(f"Confusable TLD detected: .{tld} looks like .{tld_skeleton}")

    hyphen_count = domain.count("-")

    if hyphen_count >= 3:
        structure_score += 60
        structure_reasons.append("Excessive hyphens in domain")
    elif hyphen_count > 0:
        structure_score += 25
        structure_reasons.append("Domain contains hyphens")

    root_sld = get_sld(domain)
    if re.search(r"\d", root_sld):
        structure_score += 30
        structure_reasons.append("Main domain contains digits")

    if domain.count(".") >= 4:
        structure_score += 50
        structure_reasons.append("Excessive subdomain levels detected")

    if "%" in path or "%" in query:
        structure_score += 30
        structure_reasons.append("URL contains encoded characters")

    structure_score = min(100, structure_score)

    # For verified official domains, ordinary long paths or subdomains should not become phishing.
    # Keep only truly critical structure issues.
    if official and structure_score < 100:
        structure_score = 0
        structure_reasons = []

    return indicator(
        "urlStructure",
        structure_score,
        "danger" if structure_score >= 70 else "warning" if structure_score >= 30 else "safe",
        "URL structure issue(s): " + ", ".join(structure_reasons) if structure_reasons else "No abnormal URL structure was detected.",
        structure_reasons if structure_reasons else "None detected",
        "10%"
    )


def detect_suspicious_keywords(domain, path, query):
    official, _, _ = domain_is_official(domain)

    target = f"{domain} {path} {query}".lower()
    target_skeleton = normalize_confusable(target)

    found = []
    for word in SUSPICIOUS_KEYWORDS:
        normal_word = word.lower()
        skeleton_word = normalize_confusable(normal_word)

        if normal_word in target or skeleton_word in target_skeleton:
            if normal_word not in found:
                found.append(normal_word)

    if official:
        return indicator(
            "suspiciousKeywords",
            0,
            "safe",
            "No suspicious keyword risk was applied because the domain is verified as official.",
            found if found else "None detected",
            "10%"
        )

    if len(found) >= 3:
        score = 100
    elif len(found) == 2:
        score = 75
    elif len(found) == 1:
        score = 40
    else:
        score = 0

    return indicator(
        "suspiciousKeywords",
        score,
        "danger" if score >= 70 else "warning" if score >= 30 else "safe",
        "The URL contains suspicious keyword(s): " + ", ".join(found) if found else "No suspicious keyword was detected.",
        found if found else "None detected",
        "10%"
    )


def detect_ssl_indicator(scheme):
    if scheme == "https":
        return indicator(
            "sslCertificate",
            0,
            "safe",
            "The URL uses HTTPS.",
            "HTTPS",
            "5%"
        )

    return indicator(
        "sslCertificate",
        60,
        "warning",
        "The URL does not use HTTPS.",
        "HTTP",
        "5%"
    )


def detect_url_length_complexity(url, domain):
    official, _, _ = domain_is_official(domain)

    length_score = 0
    length_reasons = []

    if len(url) > 120:
        length_score += 80
        length_reasons.append("URL is extremely long")
    elif len(url) > 90:
        length_score += 50
        length_reasons.append("URL length is suspicious")
    elif len(url) > 70:
        length_score += 25
        length_reasons.append("URL is moderately long")

    special_count = len(re.findall(r"[^a-zA-Z0-9]", url))

    if special_count > 25:
        length_score += 35
        length_reasons.append("URL contains many special characters")

    length_score = min(100, length_score)

    # Official websites often have long dashboard/settings paths.
    if official:
        length_score = min(length_score, 10)
        if length_score == 0:
            length_reasons = []

    return indicator(
        "urlLengthComplexity",
        length_score,
        "danger" if length_score >= 70 else "warning" if length_score >= 30 else "safe",
        "URL length/complexity issue(s): " + ", ".join(length_reasons) if length_reasons else "URL length and complexity appear normal.",
        {
            "length": len(url),
            "special_characters": special_count
        },
        "5%"
    )


def detect_domain_reputation(domain):
    """Score transparent local reputation evidence without claiming an external lookup."""
    official, _, matched = domain_is_official(domain)
    evidence = []
    score = 0

    if official:
        return indicator(
            "domainReputation",
            0,
            "safe",
            f"Local reputation check matched verified official domain '{matched}'.",
            {
                "domain": domain,
                "source": "verified official-domain allowlist",
                "matched_entry": matched
            },
            "6%"
        )

    if is_shortener_domain(domain):
        score = max(score, 70)
        evidence.append("domain is listed as a URL-shortening or redirect service")

    if re.search(r"(\d{1,3}\.){3}\d{1,3}", domain):
        score = max(score, 90)
        evidence.append("host is an IP address rather than a registered domain name")

    if "xn--" in domain:
        score = max(score, 95)
        evidence.append("Punycode hostname requires homograph review")

    tld = get_tld(domain)
    tld_skeleton = normalize_confusable(tld)

    if tld in BAD_TLDS:
        score = max(score, BAD_TLDS[tld])
        evidence.append(f".{tld} is present in the local high-risk TLD table")

    if tld != tld_skeleton and tld_skeleton in COMMON_TLDS:
        score = max(score, 95)
        evidence.append(f".{tld} visually resembles common TLD .{tld_skeleton}")

    status = "danger" if score >= 70 else "warning" if score >= 30 else "safe"
    explanation = (
        "Local reputation evidence: " + "; ".join(evidence) + "."
        if evidence
        else "No entry matched the API's local allowlist or high-risk reputation tables."
    )

    return indicator(
        "domainReputation",
        score,
        status,
        explanation,
        {
            "domain": domain,
            "source": "local allowlist, redirect-service list, IP check, and high-risk TLD table",
            "matched_evidence": evidence if evidence else "None"
        },
        "6%"
    )


# =========================
# Main analysis
# =========================
def analyse_url(url):
    parsed_data = parse_url(url)

    url = parsed_data["url"]
    domain = parsed_data["domain"]
    scheme = parsed_data["scheme"]
    path = parsed_data["path"]
    query = parsed_data["query"]

    official_domain, official_brand, official_matched = domain_is_official(domain)

    indicators = []

    official_indicator = detect_official_domain(domain)
    indicators.append(official_indicator)

    # AI Model
    features = extract_url_features(url)
    model_feature_audit = build_model_feature_audit(features)
    raw_ai_phishing_probability, ai_confidence = get_phishing_probability(features)
    feature_ai_probability = estimate_feature_ai_probability(url, domain, scheme, path, query, official_domain)
    calibrated_ai_phishing_probability = calibrate_ai_probability(
        raw_ai_phishing_probability,
        feature_ai_probability
    )
    raw_ai_score = int(round(raw_ai_phishing_probability * 100))
    feature_ai_score = int(round(feature_ai_probability * 100))
    calibrated_ai_score = int(round(calibrated_ai_phishing_probability * 100))

    # For verified official domains, the AI score is kept in model_info,
    # but the effective risk is capped to prevent false positives like dashboard.render.com.
    if official_domain:
        ai_score = min(calibrated_ai_score, 15)
        effective_ai_probability = ai_score / 100
        ai_explanation = (
            f"Raw model probability: {raw_ai_phishing_probability * 100:.1f}%. "
            f"Calibrated AI-assisted probability: {calibrated_ai_phishing_probability * 100:.1f}%. "
            f"Verified official-domain correction sets the effective AI risk to {ai_score}/100."
        )
    else:
        ai_score = calibrated_ai_score
        effective_ai_probability = calibrated_ai_phishing_probability
        ai_explanation = (
            f"Raw model probability: {raw_ai_phishing_probability * 100:.1f}%. "
            f"Calibrated AI-assisted probability: {calibrated_ai_phishing_probability * 100:.1f}%. "
            f"Effective AI risk used for weighting: {ai_score}/100."
        )

    indicators.append(indicator(
        "aiModelProbability",
        ai_score,
        "danger" if ai_score >= 70 else "warning" if ai_score >= 35 else "safe",
        ai_explanation,
        {
            "phishing_probability": round(effective_ai_probability, 4),
            "phishing_probability_percent": round(effective_ai_probability * 100, 2),
            "effective_ai_probability": round(effective_ai_probability, 4),
            "effective_ai_probability_percent": round(effective_ai_probability * 100, 2),
            "feature_ai_probability": round(feature_ai_probability, 4),
            "feature_ai_probability_percent": round(feature_ai_probability * 100, 2),
            "calibrated_phishing_probability": round(calibrated_ai_phishing_probability, 4),
            "calibrated_phishing_probability_percent": round(calibrated_ai_phishing_probability * 100, 2),
            "raw_phishing_probability": round(raw_ai_phishing_probability, 4),
            "raw_phishing_probability_percent": round(raw_ai_phishing_probability * 100, 2),
            "raw_ai_risk_score": raw_ai_score,
            "feature_ai_risk_score": feature_ai_score,
            "calibrated_ai_risk_score": calibrated_ai_score,
            "effective_ai_risk_percent": ai_score,
            "adjusted_ai_risk_score": ai_score,
            "weight_percent": int(AI_WEIGHT * 100),
            "weighted_contribution_points": round(ai_score * AI_WEIGHT, 2),
            "confidence": round(ai_confidence, 4),
            "confidence_percent": round(ai_confidence * 100, 2),
            "model_feature_count": len(model_feature_audit),
            "model_features_used_count": sum(
                1 for item in model_feature_audit if item["used_by_model"]
            ),
            "model_feature_importance_sum_percent": round(
                sum(
                    item["model_importance_percent"] or 0
                    for item in model_feature_audit
                ),
                2
            )
        },
        f"{int(AI_WEIGHT * 100)}%"
    ))

    brand_indicator = detect_brand_impersonation(domain, path, query)
    homograph_indicator = detect_homograph_attack(domain)
    structure_indicator = detect_url_structure(url, domain, scheme, path, query)
    keyword_indicator = detect_suspicious_keywords(domain, path, query)
    ssl_indicator = detect_ssl_indicator(scheme)
    length_indicator = detect_url_length_complexity(url, domain)
    reputation_indicator = detect_domain_reputation(domain)

    indicators.extend([
        brand_indicator,
        homograph_indicator,
        structure_indicator,
        keyword_indicator,
        ssl_indicator,
        length_indicator,
        reputation_indicator
    ])

    score_by_name = {item["name"]: item["score"] for item in indicators}

    brand_score = score_by_name.get("brandVerification", 0)
    homograph_score = score_by_name.get("homographAttack", 0)
    structure_score = score_by_name.get("urlStructure", 0)
    keyword_score = score_by_name.get("suspiciousKeywords", 0)
    ssl_score = score_by_name.get("sslCertificate", 0)
    length_score = score_by_name.get("urlLengthComplexity", 0)
    official_score = score_by_name.get("officialDomain", 0)
    reputation_score = score_by_name.get("domainReputation", 0)

    official_clean = (
        official_domain
        and official_score == 0
        and brand_score == 0
        and homograph_score == 0
        and structure_score == 0
        and keyword_score == 0
        and ssl_score == 0
        and reputation_score == 0
    )

    if official_clean:
        ai_score = 0
        effective_ai_probability = 0
        score_by_name["aiModelProbability"] = 0

        for item in indicators:
            if item["name"] == "aiModelProbability":
                item["score"] = 0
                item["risk_points"] = 0
                item["safety_score"] = 100
                item["status"] = "safe"
                item["explanation"] = (
                    "The raw AI probability is shown for transparency, but effective AI risk is set to 0 "
                    "because the hostname is a verified official domain and no URL-level phishing indicators were detected."
                )
                if isinstance(item.get("value"), dict):
                    item["value"]["phishing_probability"] = 0
                    item["value"]["phishing_probability_percent"] = 0
                    item["value"]["effective_ai_probability"] = 0
                    item["value"]["effective_ai_probability_percent"] = 0
                    item["value"]["effective_ai_risk_percent"] = 0
                    item["value"]["adjusted_ai_risk_score"] = 0
                    item["value"]["weighted_contribution_points"] = 0
                    item["value"]["official_domain_correction"] = True
                break

    weighted_score = 0
    for item in indicators:
        name = item["name"]
        weight = INDICATOR_WEIGHTS.get(name)
        if weight is None:
            raise RuntimeError(f"Displayed indicator '{name}' is not connected to the scoring formula.")

        contribution = item["score"] * weight
        item["used_in_final_score"] = True
        item["weight"] = f"{weight * 100:g}%"
        item["weight_percent"] = round(weight * 100, 2)
        item["weighted_contribution_points"] = round(contribution, 2)
        weighted_score += contribution

    weighted_score_before_overrides = round(weighted_score, 2)
    rounded_weighted_score = int(round(weighted_score_before_overrides))
    risk_score = rounded_weighted_score

    # Critical override rules
    critical_reasons = []

    if official_score >= 90:
        critical_reasons.append("look-alike official domain")

    if homograph_score >= 90:
        critical_reasons.append("homograph or typo-squatting domain")

    if brand_score >= 90:
        critical_reasons.append("brand impersonation")

    if structure_score >= 90:
        critical_reasons.append("critical URL structure issue")

    if is_shortener_domain(domain) and brand_score >= 90:
        critical_reasons.append("shortened URL contains look-alike brand")

    if brand_score >= 90 and keyword_score >= 40:
        critical_reasons.append("brand name combined with phishing keyword")

    if ssl_score >= 60 and keyword_score >= 70:
        critical_reasons.append("HTTP combined with phishing keywords")

    if "@" in url:
        critical_reasons.append("URL contains @ redirection pattern")

    if re.search(r"(\d{1,3}\.){3}\d{1,3}", domain):
        critical_reasons.append("IP address used as domain")

    critical = len(critical_reasons) > 0
    applied_overrides = []

    if critical:
        overridden_score = max(risk_score, 90)
        if overridden_score != risk_score:
            applied_overrides.append("critical risk floor: final risk raised to at least 90")
        risk_score = overridden_score

    # Important false-positive control:
    # A verified official domain must not become high risk because of long path,
    # random service ID, dashboard URL, or AI-only uncertainty.
    if official_domain and not critical:
        overridden_score = min(risk_score, 10)
        if overridden_score != risk_score:
            applied_overrides.append("verified official-domain cap: final risk limited to at most 10")
        risk_score = overridden_score

    risk_score = max(0, min(100, risk_score))
    safety_score = 100 - risk_score

    if risk_score >= 80:
        decision = "Phishing"
        result = "High Risk"
    elif risk_score >= 45:
        decision = "Suspicious"
        result = "Suspicious"
    elif risk_score >= 20:
        decision = "Relatively Safe"
        result = "Low Risk"
    else:
        decision = "Safe"
        result = "Trusted"

    model_info = {
        "model_name": MODEL_NAME,
        "score_method": SCORE_METHOD,
        "api_version": API_VERSION,
        "model_load_error": MODEL_LOAD_ERROR,
        "ai_phishing_probability": round(effective_ai_probability, 4),
        "ai_phishing_probability_percent": round(effective_ai_probability * 100, 2),
        "effective_ai_probability": round(effective_ai_probability, 4),
        "effective_ai_probability_percent": round(effective_ai_probability * 100, 2),
        "raw_ai_phishing_probability": round(raw_ai_phishing_probability, 4),
        "raw_ai_phishing_probability_percent": round(raw_ai_phishing_probability * 100, 2),
        "feature_ai_probability": round(feature_ai_probability, 4),
        "feature_ai_probability_percent": round(feature_ai_probability * 100, 2),
        "calibrated_ai_phishing_probability": round(calibrated_ai_phishing_probability, 4),
        "calibrated_ai_phishing_probability_percent": round(calibrated_ai_phishing_probability * 100, 2),
        "effective_ai_risk_percent": ai_score,
        "adjusted_ai_risk_score": ai_score,
        "ai_weight_percent": int(AI_WEIGHT * 100),
        "ai_weighted_contribution_points": round(ai_score * AI_WEIGHT, 2),
        "ai_confidence": round(ai_confidence, 4),
        "ai_confidence_percent": round(ai_confidence * 100, 2),
        "official_domain": official_domain,
        "official_brand": official_brand,
        "official_matched_domain": official_matched,
        "domain_skeleton": normalize_confusable(domain),
        "critical_reasons": critical_reasons,
        "model_features": model_feature_audit,
        "model_feature_count": len(model_feature_audit),
        "indicator_weights": {
            name: round(weight * 100, 2)
            for name, weight in INDICATOR_WEIGHTS.items()
        },
        "indicator_weight_total_percent": round(sum(INDICATOR_WEIGHTS.values()) * 100, 2),
        "weighted_score_before_overrides": weighted_score_before_overrides,
        "rounded_weighted_score": rounded_weighted_score,
        "final_risk_score": risk_score,
        "rounding_adjustment_points": round(rounded_weighted_score - weighted_score_before_overrides, 2),
        "override_adjustment_points": risk_score - rounded_weighted_score,
        "applied_overrides": applied_overrides
    }

    return risk_score, safety_score, decision, result, critical, indicators, model_info


def build_recommendations(risk_score):
    if risk_score >= 80:
        return [
            "This URL is high risk. Do NOT enter username, password, OTP, or payment information.",
            "Verify the website by typing the official domain manually.",
            "Avoid downloading files or clicking further links from this page.",
            "Report this URL to the relevant security officer or platform."
        ]
    elif risk_score >= 45:
        return [
            "Proceed with caution.",
            "Check the domain carefully before entering sensitive information.",
            "Avoid login or payment actions unless the website is verified."
        ]
    elif risk_score >= 20:
        return [
            "The website appears relatively safe, but verify the URL carefully.",
            "Do not enter sensitive information unless necessary."
        ]
    else:
        return [
            "No obvious phishing indicators were detected.",
            "Safe to proceed with normal browsing activities."
        ]


# =========================
# API routes
# =========================
@app.route("/")
def home():
    return jsonify({
        "status": "running",
        "message": "PhishGuard API Running",
        "api_version": API_VERSION,
        "model_loaded": model is not None,
        "model_load_error": MODEL_LOAD_ERROR
    })


@app.route("/predict", methods=["POST"])
def predict():
    start_time = time.time()

    data = request.get_json(silent=True)

    if not data or "url" not in data:
        return jsonify({"error": "URL is required."}), 400

    url = normalize_url(data["url"])

    if not url:
        return jsonify({"error": "URL is required."}), 400

    risk_score, safety_score, decision, result, critical, indicators, model_info = analyse_url(url)

    explanations = [
        item["explanation"]
        for item in indicators
        if item["status"] in ["warning", "danger"]
    ]

    if not explanations:
        explanations.append("No obvious phishing indicators were detected.")

    prediction = 1 if decision in ["Phishing", "Suspicious"] else 0

    analysis_time_ms = round((time.time() - start_time) * 1000, 2)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return jsonify({
        "url": url,
        "prediction": prediction,
        "decision": decision,
        "result": result,
        "risk_score": risk_score,
        "safety_score": safety_score,
        "critical_phishing": critical,
        "critical_reasons": model_info.get("critical_reasons", []),
        "timestamp": timestamp,
        "analysis_time_ms": analysis_time_ms,
        "model_name": MODEL_NAME,
        "score_method": SCORE_METHOD,
        "api_version": API_VERSION,
        "confidence": model_info["ai_confidence_percent"],
        "ai_phishing_probability": model_info["ai_phishing_probability"],
        "ai_phishing_probability_percent": model_info["ai_phishing_probability_percent"],
        "raw_ai_phishing_probability": model_info["raw_ai_phishing_probability"],
        "raw_ai_phishing_probability_percent": model_info["raw_ai_phishing_probability_percent"],
        "feature_ai_probability": model_info["feature_ai_probability"],
        "feature_ai_probability_percent": model_info["feature_ai_probability_percent"],
        "feature_evidence_probability": model_info["feature_ai_probability"],
        "feature_evidence_probability_percent": model_info["feature_ai_probability_percent"],
        "feature_ai_risk_score": model_info["feature_ai_probability_percent"],
        "calibrated_ai_phishing_probability": model_info["calibrated_ai_phishing_probability"],
        "calibrated_ai_phishing_probability_percent": model_info["calibrated_ai_phishing_probability_percent"],
        "effective_ai_probability": model_info["effective_ai_probability"],
        "effective_ai_probability_percent": model_info["effective_ai_probability_percent"],
        "adjusted_ai_risk_score": model_info["adjusted_ai_risk_score"],
        "ai_weight_percent": model_info["ai_weight_percent"],
        "ai_weighted_contribution_points": model_info["ai_weighted_contribution_points"],
        "model_features": model_info["model_features"],
        "score_audit": {
            "indicator_weights": model_info["indicator_weights"],
            "indicator_weight_total_percent": model_info["indicator_weight_total_percent"],
            "weighted_score_before_overrides": model_info["weighted_score_before_overrides"],
            "rounded_weighted_score": model_info["rounded_weighted_score"],
            "final_risk_score": model_info["final_risk_score"],
            "rounding_adjustment_points": model_info["rounding_adjustment_points"],
            "override_adjustment_points": model_info["override_adjustment_points"],
            "applied_overrides": model_info["applied_overrides"]
        },
        "model_info": model_info,
        "explanations": explanations,
        "indicators": indicators,
        "recommendations": build_recommendations(risk_score)
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
