from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import re
import time
from datetime import datetime
from urllib.parse import urlparse
import Levenshtein

app = Flask(__name__)
CORS(app)

model = joblib.load("phishing_web_model.pkl")

API_VERSION = "1.2"
MODEL_NAME = "Random Forest Classifier"
SCORE_METHOD = "Weighted Explainable AI with Rule Overrides"

OFFICIAL_DOMAINS = {
    "google": ["google.com", "google.com.my"],
    "paypal": ["paypal.com", "paypal.com.my"],
    "apple": ["apple.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com"],
    "amazon": ["amazon.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "whatsapp": ["whatsapp.com"],
    "maybank": ["maybank2u.com.my", "maybank.com"],
    "cimb": ["cimb.com.my", "cimbclicks.com.my"],
    "rhb": ["rhbgroup.com"],
    "touchngo": ["touchngo.com.my", "tngdigital.com.my"],
    "tng": ["touchngo.com.my", "tngdigital.com.my"],
    "github": ["github.com"],
    "stackoverflow": ["stackoverflow.com"],
    "ukm": ["ukm.my"],
    "openai": ["openai.com", "chatgpt.com"],
    "render": ["render.com"],
    "vercel": ["vercel.com", "vercel.app"],
    "netlify": ["netlify.com", "netlify.app"],
    "railway": ["railway.app"],
    "heroku": ["herokuapp.com"],
    "cloudflare": ["cloudflare.com", "pages.dev"]
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account", "confirm",
    "payment", "password", "unlock", "suspend", "wallet", "support",
    "limited", "signin", "reset", "security", "bank", "urgent",
    "locked", "email", "emails", "credential", "credentials",
    "dashboard", "admin", "console", "panel", "portal", "billing",
    "settings", "server", "srv", "webmail", "cpanel", "auth", "session"
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
    "loan": 80
}

SENSITIVE_SERVICE_WORDS = {
    "dashboard", "admin", "console", "panel", "portal", "billing",
    "settings", "server", "srv", "webmail", "cpanel", "auth", "session"
}

CONFUSABLE_MAP = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
    "|": "l"
})

RANDOM_TOKEN_RE = re.compile(r"[a-z0-9]{10,}", re.I)


def normalize_url(url):
    url = str(url).strip()

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    return url


def get_domain(url):
    parsed = urlparse(normalize_url(url))
    domain = parsed.netloc.lower()

    if "@" in domain:
        domain = domain.split("@")[-1]

    if ":" in domain:
        domain = domain.split(":")[0]

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def get_tld(domain):
    parts = domain.split(".")
    return parts[-1] if len(parts) > 1 else ""


def normalize_confusable(text):
    text = str(text).lower().translate(CONFUSABLE_MAP)
    return text.replace("rn", "m").replace("vv", "w")


def domain_labels(domain):
    return [label for label in domain.split(".") if label]


def domain_candidates(domain):
    labels = domain_labels(domain)
    candidates = {domain}

    for index in range(len(labels) - 1):
        candidates.add(".".join(labels[index:index + 2]))

    if len(labels) >= 3:
        candidates.add(".".join(labels[-3:]))

    return candidates


def has_confusable_com_label(domain):
    labels = domain_labels(domain)

    if not labels:
        return False

    tld_label = labels[-1]
    return tld_label != "com" and normalize_confusable(tld_label) == "com"


def find_sensitive_service_words(domain, path):
    normalized_text = normalize_confusable(f"{domain} {path}")
    return [
        word
        for word in SENSITIVE_SERVICE_WORDS
        if word in normalized_text
    ]


def is_official_domain(domain):
    for domains in OFFICIAL_DOMAINS.values():
        for official in domains:
            if domain == official or domain.endswith("." + official):
                return True
    return False


def find_lookalike_domain(domain):
    if is_official_domain(domain):
        return None

    best_match = None

    for candidate in domain_candidates(domain):
        normalized_candidate = normalize_confusable(candidate)

        for brand, official_list in OFFICIAL_DOMAINS.items():
            for official in official_list:
                normalized_official = normalize_confusable(official)

                if candidate == official or domain.endswith("." + official):
                    continue

                sim_original = Levenshtein.ratio(candidate, official)
                sim_normalized = Levenshtein.ratio(
                    normalized_candidate,
                    normalized_official
                )
                sim = max(sim_original, sim_normalized)

                if normalized_candidate == normalized_official and candidate != official:
                    sim = 1.0

                if sim >= 0.88 and (best_match is None or sim > best_match["similarity"]):
                    best_match = {
                        "brand": brand,
                        "domain": domain,
                        "candidate": candidate,
                        "official": official,
                        "similarity": round(sim, 2)
                    }

    return best_match


def extract_url_features(url):
    url = normalize_url(url)
    lower = url.lower()
    parsed = urlparse(url)
    brands = list(OFFICIAL_DOMAINS.keys())

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
    probability = model.predict_proba(features)[0]

    if hasattr(model, "classes_") and 1 in model.classes_:
        phishing_index = list(model.classes_).index(1)
        phishing_probability = float(probability[phishing_index])
    else:
        phishing_probability = float(probability[-1])

    confidence = float(max(probability))

    return phishing_probability, confidence


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


def analyse_url(url):
    url = normalize_url(url)
    lower = url.lower()
    normalized_lower = normalize_confusable(lower)
    parsed = urlparse(url)
    domain = get_domain(url)
    tld = get_tld(domain)

    indicators = []
    critical = False
    official_domain = is_official_domain(domain)

    if official_domain:
        indicators.append(indicator(
            "officialDomain",
            0,
            "safe",
            "The URL matches a verified official domain. Full URL indicators are still analysed for transparency.",
            domain
        ))
    else:
        indicators.append(indicator(
            "officialDomain",
            0,
            "safe",
            "The URL is not on the verified official-domain whitelist; this is not treated as risk by itself.",
            domain
        ))

    # 1. AI Model, 20%
    features = extract_url_features(url)
    ai_phishing_probability, ai_confidence = get_phishing_probability(features)
    raw_ai_score = int(ai_phishing_probability * 100)
    ai_score = raw_ai_score

    ai_indicator = indicator(
        "aiModelProbability",
        raw_ai_score,
        "danger" if raw_ai_score >= 70 else "warning" if raw_ai_score >= 40 else "safe",
        f"The trained AI model estimates phishing probability at {ai_phishing_probability:.2f}.",
        {
            "phishing_probability": round(ai_phishing_probability, 4),
            "phishing_probability_percent": round(ai_phishing_probability * 100, 2),
            "confidence": round(ai_confidence, 4),
            "confidence_percent": round(ai_confidence * 100, 2)
        },
        "20%"
    )
    indicators.append(ai_indicator)

    # 2. Brand Verification, 25%
    brand_score = 0
    brand_reason = "No brand impersonation was detected."
    brand_value = None

    for brand, official_list in OFFICIAL_DOMAINS.items():
        if brand in lower:
            is_real = any(domain == d or domain.endswith("." + d) for d in official_list)

            if not is_real:
                brand_score = 100
                brand_reason = f"Possible brand impersonation detected: '{brand}' appears in an unofficial domain."
                brand_value = brand
                break

    indicators.append(indicator(
        "brandVerification",
        brand_score,
        "danger" if brand_score >= 70 else "safe",
        brand_reason,
        brand_value,
        "25%"
    ))

    # 3. Homograph / Look-alike Domain, 15%
    homograph_score = 0
    homograph_reason = "No strong look-alike domain pattern was detected."
    homograph_value = domain

    lookalike_match = find_lookalike_domain(domain)

    if lookalike_match:
        homograph_score = 100
        critical = True
        homograph_reason = (
            "Critical look-alike domain detected. "
            f"The domain strongly resembles '{lookalike_match['official']}'."
        )
        homograph_value = lookalike_match

    indicators.append(indicator(
        "homographAttack",
        homograph_score,
        "danger" if homograph_score >= 70 else "safe",
        homograph_reason,
        homograph_value,
        "15%"
    ))

    # 4. URL Structure, 20%
    structure_score = 0
    structure_reasons = []
    confusable_com_label = has_confusable_com_label(domain)
    service_hits = find_sensitive_service_words(domain, parsed.path)
    random_path_token = bool(RANDOM_TOKEN_RE.search(parsed.path))

    if "@" in url:
        structure_score += 100
        structure_reasons.append("URL contains '@', which may hide the real destination")

    if re.search(r"(\d{1,3}\.){3}\d{1,3}", url):
        structure_score += 100
        structure_reasons.append("URL uses an IP address instead of a normal domain")

    if confusable_com_label:
        structure_score += 90
        critical = True
        structure_reasons.append("Domain contains a look-alike '.com' label such as 'c0m' or 'corn'")

    if ".corn" in domain:
        structure_score += 90
        structure_reasons.append("'.corn' detected, a common typo of '.com'")

    if service_hits:
        structure_score += 45
        structure_reasons.append("Sensitive service/admin word(s) detected: " + ", ".join(service_hits))

    if random_path_token:
        structure_score += 35
        structure_reasons.append("URL path contains a long random-looking token")

    if "xn--" in domain:
        structure_score = 100
        critical = True
        structure_reasons.append("Punycode domain detected (possible IDN homograph attack)")

    if tld in BAD_TLDS:
        structure_score += BAD_TLDS[tld]
        structure_reasons.append(f"Suspicious TLD detected: .{tld}")

    hyphen_count = domain.count("-")

    if hyphen_count >= 3:
        structure_score += 70
        structure_reasons.append("Excessive hyphens in domain")
    elif hyphen_count > 0:
        structure_score += 45
        structure_reasons.append("Domain contains hyphens")

    if domain.count(".") >= 3:
        structure_score += 70
        structure_reasons.append("Excessive subdomain levels detected")

    structure_score = min(100, structure_score)

    indicators.append(indicator(
        "urlStructure",
        structure_score,
        "danger" if structure_score >= 70 else "warning" if structure_score >= 40 else "safe",
        "URL structure issue(s): " + ", ".join(structure_reasons) if structure_reasons else "No abnormal URL structure was detected.",
        structure_reasons,
        "20%"
    ))

    # 5. Suspicious Keywords, 10%
    found_keywords = [
        word
        for word in SUSPICIOUS_KEYWORDS
        if word in lower or word in normalized_lower
    ]

    if len(found_keywords) >= 4:
        keyword_score = 100
    elif len(found_keywords) >= 3:
        keyword_score = 100
    elif len(found_keywords) == 2:
        keyword_score = 75
    elif len(found_keywords) == 1:
        keyword_score = 45
    else:
        keyword_score = 0

    indicators.append(indicator(
        "suspiciousKeywords",
        keyword_score,
        "danger" if keyword_score >= 70 else "warning" if keyword_score >= 40 else "safe",
        "The URL contains suspicious keyword(s): " + ", ".join(found_keywords) if found_keywords else "No suspicious keyword was detected.",
        found_keywords,
        "10%"
    ))

    # 6. HTTPS / SSL, 5%
    if lower.startswith("https://"):
        ssl_score = 0
        ssl_reason = "The URL uses HTTPS."
        ssl_status = "safe"
    else:
        ssl_score = 100
        ssl_reason = "The URL does not use HTTPS."
        ssl_status = "danger"

    indicators.append(indicator(
        "sslCertificate",
        ssl_score,
        ssl_status,
        ssl_reason,
        "HTTPS" if ssl_score == 0 else "HTTP",
        "5%"
    ))

    # 7. URL Length / Complexity, 5%
    length_score = 0
    length_reasons = []

    if len(url) > 90:
        length_score += 100
        length_reasons.append("URL is extremely long")
    elif len(url) > 60:
        length_score += 70
        length_reasons.append("URL length is suspicious")
    elif len(url) > 45:
        length_score += 40
        length_reasons.append("URL is moderately long")

    special_count = len(re.findall(r"[^a-zA-Z0-9]", url))

    if special_count > 15:
        length_score += 50
        length_reasons.append("URL contains many special characters")

    length_score = min(100, length_score)

    indicators.append(indicator(
        "urlLengthComplexity",
        length_score,
        "danger" if length_score >= 70 else "warning" if length_score >= 40 else "safe",
        "URL length/complexity issue(s): " + ", ".join(length_reasons) if length_reasons else "URL length and complexity appear normal.",
        {
            "length": len(url),
            "special_characters": special_count
        },
        "5%"
    ))

    official_clean = (
        official_domain
        and not critical
        and brand_score == 0
        and homograph_score == 0
        and structure_score == 0
        and keyword_score == 0
        and ssl_score == 0
        and length_score < 70
    )

    if official_clean:
        ai_score = 0
        ai_indicator.update({
            "score": 0,
            "risk_points": 0,
            "safety_score": 100,
            "status": "safe",
            "explanation": (
                "Raw AI probability was suppressed because the hostname is a verified official domain "
                "and no URL-level risk indicators were detected."
            )
        })

        if isinstance(ai_indicator.get("value"), dict):
            ai_indicator["value"]["raw_ai_score"] = raw_ai_score

    # 8. Internal Reputation Indicator
    reputation_score = 0
    reputation_status = "safe"
    reputation_reason = "Internal reputation indicator shows no strong internal red flags."

    if brand_score >= 100 or homograph_score >= 100 or structure_score >= 90:
        reputation_score = 70
        reputation_status = "warning"
        reputation_reason = "Internal reputation warning based on strong phishing indicators."

    indicators.append(indicator(
        "domainReputation",
        reputation_score,
        reputation_status,
        reputation_reason,
        None
    ))

    weighted_score = (
        ai_score * 0.20 +
        brand_score * 0.25 +
        homograph_score * 0.15 +
        structure_score * 0.20 +
        keyword_score * 0.10 +
        ssl_score * 0.05 +
        length_score * 0.05
    )

    risk_score = int(round(weighted_score))

    if critical:
        risk_score = 100

    if "@" in url or re.search(r"(\d{1,3}\.){3}\d{1,3}", url):
        risk_score = max(risk_score, 95)

    if service_hits and random_path_token:
        risk_score = max(risk_score, 60)

    if official_domain and not critical:
        if official_clean:
            risk_score = 0
        elif brand_score == 0 and homograph_score == 0 and structure_score < 70:
            risk_score = min(risk_score, 35)

    risk_score = max(0, min(100, risk_score))
    safety_score = 100 - risk_score

    if risk_score >= 80:
        decision = "Phishing"
        result = "Critical"
    elif risk_score >= 60:
        decision = "Phishing"
        result = "High Risk"
    elif risk_score >= 35:
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
        "ai_phishing_probability": round(ai_phishing_probability, 4),
        "ai_phishing_probability_percent": round(ai_phishing_probability * 100, 2),
        "ai_confidence": round(ai_confidence, 4),
        "ai_confidence_percent": round(ai_confidence * 100, 2),
        "official_domain": official_domain
    }

    return risk_score, safety_score, decision, result, critical, indicators, model_info


def build_recommendations(risk_score):
    if risk_score >= 80:
        return [
            "This URL is critically risky. Do NOT visit this website.",
            "Do not enter username, password, OTP, or payment information.",
            "Verify the website by typing the official domain manually.",
            "Report this URL to the relevant security officer or platform."
        ]
    elif risk_score >= 60:
        return [
            "This URL is high risk.",
            "Avoid login, payment, or personal data entry.",
            "Verify the domain carefully before continuing."
        ]
    elif risk_score >= 35:
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


@app.route("/")
def home():
    return "PhishGuard API Running"


@app.route("/predict", methods=["POST"])
def predict():
    start_time = time.time()

    data = request.json

    if not data or "url" not in data:
        return jsonify({"error": "URL is required."}), 400

    url = normalize_url(data["url"])

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
        "timestamp": timestamp,
        "analysis_time_ms": analysis_time_ms,
        "model_name": MODEL_NAME,
        "score_method": SCORE_METHOD,
        "api_version": API_VERSION,
        "confidence": model_info["ai_confidence_percent"],
        "ai_phishing_probability": model_info["ai_phishing_probability"],
        "ai_phishing_probability_percent": model_info["ai_phishing_probability_percent"],
        "model_info": model_info,
        "explanations": explanations,
        "indicators": indicators,
        "recommendations": build_recommendations(risk_score)
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
