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

API_VERSION = "2.4"
MODEL_NAME = "Enhanced Extra Trees URL Classifier"
SCORE_METHOD = "Weighted Explainable Scoring + Calibrated AI-Assisted Probability"
AI_WEIGHT = 0.18

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
        "ukm.my"
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
}


# =========================
# Basic URL helpers
# =========================
def normalize_url(url):
    url = str(url or "").strip()

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
            if is_same_or_subdomain(domain, official):
                return True, brand, official

    return False, None, None


def domain_skeleton_matches_official(domain):
    domain = strip_www(domain)
    domain_skeleton = normalize_confusable(domain)

    for brand, domains in OFFICIAL_DOMAINS.items():
        for official in domains:
            official = strip_www(official)
            official_skeleton = normalize_confusable(official)

            if is_same_or_subdomain(domain_skeleton, official_skeleton):
                official_raw, _, _ = domain_is_official(domain)

                if not official_raw:
                    return True, brand, official

    return False, None, None


# =========================
# AI model functions
# =========================
def extract_url_features(url):
    url = normalize_url(url)
    lower = url.lower()
    parsed = urlparse(url)
    brands = list(OFFICIAL_DOMAINS.keys())

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
        sum(brand in lower for brand in brands)
    ]]


def get_phishing_probability(features):
    if model is None:
        return 0.0, 1.0

    try:
        probability = model.predict_proba(features)[0]

        if hasattr(model, "classes_") and 1 in model.classes_:
            phishing_index = list(model.classes_).index(1)
            phishing_probability = float(probability[phishing_index])
        else:
            phishing_probability = float(probability[-1])

        confidence = float(max(probability))

        return phishing_probability, confidence

    except Exception:
        return 0.0, 1.0


def estimate_feature_ai_probability(url, domain, scheme, path, query, official_domain):
    """Continuous lexical estimate used to calibrate over-confident Random Forest votes."""
    target = f"{domain} {path} {query}".lower()
    target_skeleton = normalize_confusable(target)
    tld = get_tld(domain)
    tld_skeleton = normalize_confusable(tld)
    root = get_root_domain(domain)
    sld = get_sld(root)

    score = 4 if official_domain else 12

    if scheme != "https":
        score += 12

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

    if raw_probability <= 0.02 or raw_probability >= 0.98:
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


def detect_brand_impersonation(domain):
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
            "confidence_percent": round(ai_confidence * 100, 2)
        },
        f"{int(AI_WEIGHT * 100)}%"
    ))

    brand_indicator = detect_brand_impersonation(domain)
    homograph_indicator = detect_homograph_attack(domain)
    structure_indicator = detect_url_structure(url, domain, scheme, path, query)
    keyword_indicator = detect_suspicious_keywords(domain, path, query)
    ssl_indicator = detect_ssl_indicator(scheme)
    length_indicator = detect_url_length_complexity(url, domain)

    indicators.extend([
        brand_indicator,
        homograph_indicator,
        structure_indicator,
        keyword_indicator,
        ssl_indicator,
        length_indicator
    ])

    score_by_name = {item["name"]: item["score"] for item in indicators}

    brand_score = score_by_name.get("brandVerification", 0)
    homograph_score = score_by_name.get("homographAttack", 0)
    structure_score = score_by_name.get("urlStructure", 0)
    keyword_score = score_by_name.get("suspiciousKeywords", 0)
    ssl_score = score_by_name.get("sslCertificate", 0)
    length_score = score_by_name.get("urlLengthComplexity", 0)
    official_score = score_by_name.get("officialDomain", 0)

    official_clean = (
        official_domain
        and official_score == 0
        and brand_score == 0
        and homograph_score == 0
        and structure_score == 0
        and keyword_score == 0
        and ssl_score == 0
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

    # Internal Reputation Indicator
    reputation_score = 0
    reputation_status = "safe"
    reputation_reason = "Internal reputation indicator shows no strong internal red flags."

    if official_score >= 90 or brand_score >= 90 or homograph_score >= 90 or structure_score >= 90:
        reputation_score = 75
        reputation_status = "warning"
        reputation_reason = "Internal reputation warning based on strong phishing indicators."

    indicators.append(indicator(
        "domainReputation",
        reputation_score,
        reputation_status,
        reputation_reason,
        None
    ))

    weights = {
        "officialDomain": 0.12,
        "aiModelProbability": AI_WEIGHT,
        "brandVerification": 0.20,
        "homographAttack": 0.20,
        "urlStructure": 0.10,
        "suspiciousKeywords": 0.10,
        "sslCertificate": 0.05,
        "urlLengthComplexity": 0.05
    }

    weighted_score = 0
    for item in indicators:
        name = item["name"]
        if name in weights:
            weighted_score += item["score"] * weights[name]

    risk_score = int(round(weighted_score))

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

    if brand_score >= 90 and keyword_score >= 40:
        critical_reasons.append("brand name combined with phishing keyword")

    if ssl_score >= 60 and keyword_score >= 70:
        critical_reasons.append("HTTP combined with phishing keywords")

    if "@" in url:
        critical_reasons.append("URL contains @ redirection pattern")

    if re.search(r"(\d{1,3}\.){3}\d{1,3}", domain):
        critical_reasons.append("IP address used as domain")

    critical = len(critical_reasons) > 0

    if critical:
        risk_score = max(risk_score, 90)

    # Important false-positive control:
    # A verified official domain must not become high risk because of long path,
    # random service ID, dashboard URL, or AI-only uncertainty.
    if official_domain and not critical:
        risk_score = min(risk_score, 10)

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
        "critical_reasons": critical_reasons
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
        "model_info": model_info,
        "explanations": explanations,
        "indicators": indicators,
        "recommendations": build_recommendations(risk_score)
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
