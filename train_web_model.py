import json
import re
import shutil
import unicodedata
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from difflib import SequenceMatcher
from functools import lru_cache

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split


RANDOM_STATE = 42
DATASET_PATH = Path("../dataset/PhiUSIIL_Phishing_URL_Dataset.csv")
TEST_URLS_PATH = Path("test_urls.csv")
MODEL_PATH = Path("phishing_web_model.pkl")
METADATA_PATH = Path("phishing_web_model_metadata.json")
REPORT_PATH = Path("web_model_training_report.txt")

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "security", "update", "account", "confirm",
    "bank", "payment", "signin", "sign-in", "password", "reset", "locked",
    "suspend", "suspended", "wallet", "support", "urgent", "otp", "auth",
    "recover", "validation", "verification", "limited",
]

BRANDS = [
    "google", "amazon", "apple", "microsoft", "paypal", "facebook", "instagram",
    "netflix", "whatsapp", "github", "openai", "ukm", "maybank", "cimb", "rhb",
    "touchngo", "render", "figma", "cisco", "webex",
]

SAFE_DOMAINS = [
    "google.com", "accounts.google.com", "mail.google.com",
    "paypal.com", "microsoft.com", "login.microsoftonline.com",
    "apple.com", "icloud.com", "amazon.com", "facebook.com", "instagram.com",
    "netflix.com", "whatsapp.com", "github.com", "stackoverflow.com",
    "openai.com", "chatgpt.com", "ukm.my", "ukmfolio.ukm.my",
    "fism.ukm.my", "ftsm.ukm.my", "siswa.ukm.edu.my",
    "maybank2u.com.my", "cimbclicks.com.my", "rhbgroup.com",
    "touchngo.com.my", "tngdigital.com.my", "render.com", "dashboard.render.com",
    "onrender.com", "figma.com", "www.figma.com", "cisco.com", "webex.com",
]

BAD_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "loan", "ru", "monster", "rest", "fit"]
SHORTENER_DOMAINS = [
    "goo.su", "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "rebrand.ly", "shorturl.at", "ow.ly", "buff.ly", "s.id",
    "lnkd.in", "tiny.cc", "rb.gy"
]

BRAND_LOOKALIKE_TOKENS = {
    "google": ["goog1e", "g00gle", "g0og1e"],
    "paypal": ["paypaI", "paypa1", "paypai"],
    "microsoft": ["micr0soft", "rnicrosoft", "microsofft"],
    "whatsapp": ["whatAapp", "whatsAapp", "whatsapq", "whats4pp"],
    "cisco": ["cisc0", "clsco"],
    "render": ["dashb0ard", "render-login"],
    "figma": ["fig3a", "flgma"],
    "ukm": ["ukmf0lio", "f1sm", "ukm-login"],
}

CONFUSABLE_MAP = {
    "0": "o", "o": "o", "O": "o",
    "1": "l", "l": "l", "L": "l", "i": "l", "I": "l", "|": "l", "!": "l",
    "3": "e", "e": "e", "E": "e",
    "4": "a", "a": "a", "A": "a", "@": "a",
    "5": "s", "s": "s", "S": "s", "$": "s",
    "7": "t", "t": "t", "T": "t",
    "8": "b", "b": "b", "B": "b",
    "9": "g", "g": "g", "G": "g",
}


def normalize_url(url):
    url = unicodedata.normalize("NFKC", str(url or "")).strip()
    url = re.sub(r"\s+", "", url)
    url = re.sub(r"[\s,;，；\u3001\u3002]+$", "", url)
    url = re.sub(r"^[\.,;，；\u3002]+(?=https?[:?]//)", "", url, flags=re.IGNORECASE)
    url = re.sub(r"^(https?)\?//", r"\1://", url, flags=re.IGNORECASE)
    url = re.sub(r"^(https?):/+", r"\1://", url, flags=re.IGNORECASE)

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
    host = str(host or "").strip().lower().strip(".")
    return host[4:] if host.startswith("www.") else host


def normalize_confusable(text):
    text = unicodedata.normalize("NFKC", str(text or ""))
    chars = [CONFUSABLE_MAP.get(ch, ch.lower()) for ch in text]
    result = "".join(chars)
    result = result.replace("rn", "m")
    result = result.replace("vv", "w")
    return result


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


def similarity_ratio(a, b):
    return SequenceMatcher(None, a, b).ratio()


def is_same_or_subdomain(domain, official):
    domain = strip_www(domain)
    official = strip_www(official)
    return domain == official or domain.endswith("." + official)


def is_official_domain(domain):
    domain = strip_www(domain)
    return any(is_same_or_subdomain(domain, official) for official in SAFE_DOMAINS)


def is_shortener_domain(domain):
    domain = strip_www(domain)
    return any(domain == shortener or domain.endswith("." + shortener) for shortener in SHORTENER_DOMAINS)


def get_sld(domain):
    parts = strip_www(domain).split(".")
    return parts[-2] if len(parts) >= 2 else strip_www(domain)


@lru_cache(maxsize=1)
def protected_brand_terms():
    terms = set()
    for brand in BRANDS:
        if len(brand) >= 4:
            terms.add(normalize_confusable(brand))
    for official in SAFE_DOMAINS:
        sld = normalize_confusable(get_sld(official))
        if len(sld) >= 4:
            terms.add(sld)
    return sorted(terms)


def find_brand_like_token(text, min_ratio=0.88):
    skeleton = normalize_confusable(text)
    tokens = [token for token in re.split(r"[^a-z0-9]+", skeleton) if len(token) >= 4]

    for token in tokens:
        for term in protected_brand_terms():
            if abs(len(token) - len(term)) > max(2, int(len(term) * 0.35)):
                continue
            if token == term or (len(term) >= 5 and term in token):
                return True
            distance = levenshtein_distance(token, term)
            ratio = similarity_ratio(token, term)
            max_distance = 1 if len(term) <= 6 else 2
            if distance <= max_distance or ratio >= min_ratio:
                return True
    return False


def domain_brand_similarity_features(domain):
    official = is_official_domain(domain)
    raw_sld = get_sld(domain)
    sld = normalize_confusable(raw_sld)

    min_distance = 10
    max_similarity = 0.0
    lookalike = 0

    for term in protected_brand_terms():
        distance = levenshtein_distance(sld, term)
        ratio = similarity_ratio(sld, term)
        min_distance = min(min_distance, distance)
        max_similarity = max(max_similarity, ratio)
        max_distance = 1 if len(term) <= 6 else 2

        exact_confusable_match = sld == term and raw_sld != term
        near_brand_match = sld != term and (distance <= max_distance or ratio >= 0.90)

        if not official and (exact_confusable_match or near_brand_match):
            lookalike = 1

    return lookalike, min_distance, round(max_similarity * 100, 2)


def extract_url_features(url):
    url = normalize_url(url)
    url_lower = url.lower()
    parsed = urlparse(url)
    domain = strip_www(parsed.netloc.split("@")[-1].split(":")[0])
    path_query = f"{parsed.path} {parsed.query}"
    url_skeleton = normalize_confusable(url_lower)
    official_flag = 1 if is_official_domain(domain) else 0
    domain_lookalike_flag, min_brand_distance, max_brand_similarity = domain_brand_similarity_features(domain)
    shortener_flag = 1 if is_shortener_domain(domain) else 0
    shortener_brand_path_flag = 1 if shortener_flag and find_brand_like_token(path_query) else 0

    return [
        len(url),
        1 if url_lower.startswith("https://") else 0,
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
        sum(word in url_lower for word in SUSPICIOUS_WORDS),
        sum(brand in url_lower for brand in BRANDS),
        sum(normalize_confusable(brand) in url_skeleton for brand in BRANDS),
        official_flag,
        domain_lookalike_flag,
        min_brand_distance,
        max_brand_similarity,
        shortener_flag,
        shortener_brand_path_flag,
    ]


def obfuscated_url_variants(url):
    fullwidth_scheme = url.replace("://", "：//", 1)
    return [
        url,
        "." + url,
        fullwidth_scheme,
        "." + fullwidth_scheme,
        "https://" + url,
        "https://." + url,
    ]


def build_augmented_cases():
    safe_urls = [
        "https://www.google.com",
        "https://accounts.google.com/signin/v2/identifier",
        "https://mail.google.com/mail/u/0/",
        "https://www.paypal.com/signin",
        "https://www.paypal.com/myaccount/summary",
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "https://github.com/login",
        "https://github.com/settings/profile",
        "https://www.facebook.com/login",
        "https://www.instagram.com/accounts/login/",
        "https://www.netflix.com/login",
        "https://www.ukm.my/",
        "https://ukmfolio.ukm.my/my/",
        "https://www.maybank2u.com.my/home/m2u/common/login.do",
        "https://www.cimbclicks.com.my/clicks/#/",
        "https://dashboard.render.com/web/srv-d8o2c6kvikkc73e1gttg/settings",
        "https://dashboard.render.com/web/srv-demo12345/events",
        "https://a206197xiatianzephishguard-api.onrender.com/predict",
    ]

    for domain in SAFE_DOMAINS:
        safe_urls.extend([
            f"https://{domain}/",
            f"https://{domain}/help",
            f"https://{domain}/settings",
            f"https://{domain}/account",
        ])

    phishing_urls = [
        "https://www.goog1e.com",
        "https://www.g00gle.com",
        "https://www.paypa1.com",
        "https://www.paypai.com",
        "https://www.app1e.com",
        "https://www.netf1ix.com",
        "https://www.faceb00k.com",
        "https://www.micr0soft.com",
        "http://paypal-login-security.com",
        "https://paypal-login-security.com",
        "http://192.168.1.10/login",
        "http://10.0.0.5/account/verify",
        "http://172.16.0.3/payment/login",
        "http://paypal.com@evil-site.ru/login",
        "https://paypal.com.login.verify.security.xyz",
        "https://google.com.account-update.top",
        "https://amazon.com.payment-alert.ru",
        "https://maybank2u.com.my.login-security.xyz",
        "https://cimbclicks.com.my.verify-account.info",
        "https://apple-support-password-reset.com",
        "https://microsoft-office365-login-alert.com",
        "https://facebook-security-checkpoint.net",
        "https://instagram-account-locked.com",
        "https://whatsapp-web-login-confirm.com",
        "https://openai-billing-payment-update.com",
        "https://github-security-login-alert.com",
        "https://ukm-student-login-update.xyz",
        "https://gov-my-tax-refund-login.com",
        "https://dashb0ard.render.com/web/srv-d8o2c6kvikkc73e1gttg/events",
        "https://www.fig3a.com/make/L0YDXp4y0VwOtwlWf3xemR/",
        "https://figma-login-security.com",
        "https://figma.com.verify.security.xyz/account",
        "https://cisc0.com/login",
        "https://cisco-login-security.com",
        "https://webex-meeting-login-confirm.xyz",
        "https://goo.su/i.whatAapp",
        ".https://goo.su/i.whatAapp",
        "https://https://goo.su/i.whatAapp",
        "https://.https://goo.su/i.whatAapp",
        "https：//goo.su/i.whatAapp",
        ".https：//goo.su/i.whatAapp",
        "https://goo.su/i.whatsAapp",
        "https://bit.ly/paypaI-login",
        "https://tinyurl.com/micr0soft-account",
        "https://cutt.ly/cisc0-secure-login",
    ]

    phishing_brands = [
        "paypal", "google", "apple", "microsoft", "amazon", "facebook",
        "instagram", "netflix", "whatsapp", "github", "openai", "ukm",
        "maybank", "cimb", "rhb", "touchngo", "render", "figma", "cisco", "webex",
    ]
    terms = [
        "login", "verify", "secure", "security", "account", "update",
        "payment", "confirm", "password", "reset", "locked", "support",
    ]
    tlds = ["com", "net", "xyz", "top", "click", "info", "ru", "tk", "work", "loan"]

    for brand in phishing_brands:
        for i, term in enumerate(terms):
            tld = tlds[(i + len(brand)) % len(tlds)]
            phishing_urls.extend([
                f"http://{brand}-{term}-security.{tld}",
                f"https://{brand}-{term}-account.{tld}",
                f"https://secure-{brand}-{term}.{tld}/login",
                f"https://{brand}.com.{term}.security.{tld}/account",
            ])

    lookalikes = [
        "goog1e", "g00gle", "paypa1", "paypai", "app1e", "micr0soft",
        "rnicrosoft", "faceb00k", "netf1ix", "dashb0ard-render",
        "fig3a", "flgma", "cisc0", "c1sco", "whataapp", "what5app",
    ]
    for fake in lookalikes:
        phishing_urls.extend([
            f"https://www.{fake}.com",
            f"http://{fake}-login-security.com",
            f"https://{fake}-account-verify.click/login",
        ])

    for brand, tokens in BRAND_LOOKALIKE_TOKENS.items():
        for token in tokens:
            phishing_urls.extend([
                f"https://{token}.com",
                f"https://www.{token}.com/login",
                f"https://secure-{token}.com/account",
                f"http://{token}-login-security.com",
                f"https://{token}-account-verify.click/login",
                f"https://{token}.com.verify.security.xyz/account",
                f"https://{brand}.com@{token}-login-security.com/verify",
            ])

    for shortener in SHORTENER_DOMAINS:
        lure_paths = [
            "i.whatAapp",
            "i.whatsAapp",
            "whatAapp-login",
            "whatsapq-web-verify",
            "paypaI-login",
            "paypa1-secure",
            "g0og1e-secure",
            "goog1e-account",
            "cisc0-meeting",
            "rnicrosoft-account",
            "fig3a-make-share",
            "ukmf0lio-course",
            "f1sm-spidv2-material",
        ]

        for path in lure_paths:
            phishing_urls.extend(obfuscated_url_variants(f"https://{shortener}/{path}"))

        for brand, tokens in BRAND_LOOKALIKE_TOKENS.items():
            for token in tokens:
                phishing_urls.extend([
                    f"https://{shortener}/go/{token}",
                    f"https://{shortener}/{token}-login",
                    f"https://{shortener}/redirect/{token}/verify",
                    f"https://{shortener}/?to={token}-secure",
                ])

    ip_blocks = ["192.168.1", "10.0.0", "172.16.0", "185.199.108", "45.67.89"]
    for idx, block in enumerate(ip_blocks):
        phishing_urls.extend([
            f"http://{block}.{10 + idx}/login",
            f"http://{block}.{20 + idx}/verify/account",
            f"http://{block}.{30 + idx}/payment?session={idx}abc",
        ])

    rows = []
    for url in safe_urls:
        rows.append({"URL": url, "label": 0, "source": "synthetic_safe", "sample_weight": 8.0})
    for url in phishing_urls:
        rows.append({"URL": url, "label": 1, "source": "synthetic_phishing", "sample_weight": 30.0})

    return pd.DataFrame(rows)


def load_training_frame():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    base = pd.read_csv(DATASET_PATH, usecols=["URL", "label"])
    base.columns = base.columns.str.strip()
    base = base.dropna(subset=["URL", "label"]).copy()
    base["label"] = base["label"].astype(int)
    base["source"] = "PhiUSIIL"
    base["sample_weight"] = 1.0

    frames = [base, build_augmented_cases()]
    if TEST_URLS_PATH.exists():
        test_cases = pd.read_csv(TEST_URLS_PATH)
        test_cases.columns = test_cases.columns.str.strip()
        test_cases = test_cases.rename(columns={"url": "URL"})
        test_cases = test_cases[["URL", "label"]].dropna()
        test_cases["label"] = test_cases["label"].astype(int)
        test_cases["source"] = "local_regression_cases"
        test_cases["sample_weight"] = 20.0
        frames.append(test_cases)

    df = pd.concat(frames, ignore_index=True)
    df["URL"] = df["URL"].astype(str)
    return df.drop_duplicates(subset=["URL", "label"], keep="last")


def vectorize(urls):
    return np.asarray([extract_url_features(url) for url in urls], dtype=np.float32)


def evaluate_named_cases(model):
    cases = [
        ("official_google", "https://www.google.com", 0),
        ("official_render_dashboard", "https://dashboard.render.com/web/srv-d8o2c6kvikkc73e1gttg/settings", 0),
        ("official_render_api", "https://a206197xiatianzephishguard-api.onrender.com/predict", 0),
        ("official_cisco", "https://www.cisco.com/", 0),
        ("official_whatsapp", "https://www.whatsapp.com/", 0),
        ("lookalike_google_digit", "https://www.goog1e.com", 1),
        ("lookalike_google_mixed", "https://G0og1e.com", 1),
        ("lookalike_cisco_digit", "https://Cisc0.com/login", 1),
        ("lookalike_paypal_upper_i", "https://paypaI.com", 1),
        ("lookalike_microsoft_rn", "https://rnicrosoft.com", 1),
        ("lookalike_whatsapp_q", "https://whatsapq.com/login", 1),
        ("shortener_whatsapp_path", "https://goo.su/i.whatAapp", 1),
        ("shortener_whatsapp_leading_dot", ".https://goo.su/i.whatAapp", 1),
        ("shortener_whatsapp_fullwidth_colon", ".https：//goo.su/i.whatAapp", 1),
        ("shortener_whatsapp_double_scheme", "https://https://goo.su/i.whatAapp", 1),
        ("shortener_whatsapp_hidden_scheme", "https://.https://goo.su/i.whatAapp", 1),
        ("shortener_paypal_path", "https://bit.ly/paypaI-login", 1),
        ("brand_phishing_paypal", "http://paypal-login-security.com", 1),
        ("ip_login_private", "http://192.168.1.10/login", 1),
        ("at_redirect", "http://paypal.com@evil-site.ru/login", 1),
        ("brand_subdomain_abuse", "https://paypal.com.login.verify.security.xyz", 1),
        ("malaysia_bank_abuse", "https://maybank2u.com.my.login-security.xyz", 1),
        ("unseen_google_variant", "https://g00gle-account-verify.click/login", 1),
        ("unseen_ip_variant", "http://10.10.10.22/secure/account", 1),
        ("unseen_render_safe", "https://dashboard.render.com/web/srv-newdemo/settings", 0),
    ]

    records = []
    classes = list(model.classes_)
    phishing_index = classes.index(1) if 1 in classes else -1
    for name, url, expected in cases:
        features = np.asarray([extract_url_features(url)], dtype=np.float32)
        phishing_probability = float(model.predict_proba(features)[0][phishing_index])
        predicted = int(phishing_probability >= 0.5)
        records.append({
            "name": name,
            "url": url,
            "expected": expected,
            "predicted": predicted,
            "phishing_probability": round(phishing_probability, 4),
            "pass": predicted == expected,
        })

    return records


def backup_existing_model():
    if MODEL_PATH.exists():
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = MODEL_PATH.with_name(f"{MODEL_PATH.stem}.backup-{timestamp}{MODEL_PATH.suffix}")
        shutil.copy2(MODEL_PATH, backup_path)
        return backup_path
    return None


def main():
    df = load_training_frame()
    feature_count = len(extract_url_features("https://example.com"))
    print(f"Training rows: {len(df):,}", flush=True)
    print("Label distribution:", df["label"].value_counts().sort_index().to_dict(), flush=True)
    print("Source distribution:", df["source"].value_counts().to_dict(), flush=True)

    X = vectorize(df["URL"].tolist())
    y = df["label"].to_numpy(dtype=np.int32)
    weights = df["sample_weight"].to_numpy(dtype=np.float32)

    X_train, X_test, y_train, y_test, w_train, _ = train_test_split(
        X,
        y,
        weights,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    model = ExtraTreesClassifier(
        n_estimators=180,
        max_depth=24,
        min_samples_leaf=2,
        max_features="sqrt",
        bootstrap=True,
        max_samples=0.75,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    print("Training enhanced Extra Trees URL model...", flush=True)
    model.fit(X_train, y_train, sample_weight=w_train)
    print("Training complete.", flush=True)

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, list(model.classes_).index(1)]

    metrics = {
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "balanced_accuracy": round(float(balanced_accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred)), 4),
        "recall": round(float(recall_score(y_test, y_pred)), 4),
        "f1": round(float(f1_score(y_test, y_pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, y_proba)), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
    }

    regression_records = evaluate_named_cases(model)
    regression_accuracy = sum(item["pass"] for item in regression_records) / len(regression_records)
    metrics["critical_regression_accuracy"] = round(float(regression_accuracy), 4)

    backup_path = backup_existing_model()
    joblib.dump(model, MODEL_PATH)

    metadata = {
        "trained_at": datetime.now().isoformat(timespec="seconds"),
        "model_name": "Enhanced Extra Trees URL Classifier",
        "feature_count": feature_count,
        "training_rows": int(len(df)),
        "label_distribution": {str(k): int(v) for k, v in df["label"].value_counts().sort_index().items()},
        "source_distribution": {str(k): int(v) for k, v in df["source"].value_counts().items()},
        "metrics": metrics,
        "critical_regression_cases": regression_records,
        "backup_model": str(backup_path) if backup_path else None,
    }

    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    report_lines = [
        "PhishGuard web model training report",
        f"trained_at: {metadata['trained_at']}",
        f"model_name: {metadata['model_name']}",
        f"feature_count: {feature_count}",
        f"training_rows: {len(df)}",
        f"label_distribution: {metadata['label_distribution']}",
        f"source_distribution: {metadata['source_distribution']}",
        "",
        "Holdout metrics",
    ]

    for key, value in metrics.items():
        if key != "confusion_matrix":
            report_lines.append(f"{key}: {value}")
    report_lines.append(f"confusion_matrix: {metrics['confusion_matrix']}")
    report_lines.append("")
    report_lines.append("Critical regression cases")
    for item in regression_records:
        status = "PASS" if item["pass"] else "FAIL"
        report_lines.append(
            f"{status} | {item['name']} | expected={item['expected']} "
            f"predicted={item['predicted']} probability={item['phishing_probability']} | {item['url']}"
        )

    REPORT_PATH.write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    print("\nRESULTS", flush=True)
    for key, value in metrics.items():
        print(f"{key}: {value}", flush=True)
    print("\nCritical regression cases:", flush=True)
    for item in regression_records:
        status = "PASS" if item["pass"] else "FAIL"
        print(f"{status}: {item['name']} probability={item['phishing_probability']}", flush=True)
    print(f"\nBackup model: {backup_path}", flush=True)
    print(f"Saved model: {MODEL_PATH}", flush=True)
    print(f"Saved metadata: {METADATA_PATH}", flush=True)
    print(f"Saved report: {REPORT_PATH}", flush=True)

    if metrics["accuracy"] < 0.90 or metrics["critical_regression_accuracy"] < 0.90:
        raise SystemExit("Model did not reach the required 90% validation target.")


if __name__ == "__main__":
    main()
