import re

def extract_features(url):
    url_lower = url.lower()

    features = []

    features.append(len(url))
    features.append(1 if url_lower.startswith("https://") else 0)
    features.append(url_lower.count("."))
    features.append(url_lower.count("-"))

    suspicious_words = ["login", "verify", "account", "secure", "update", "confirm"]
    keyword_count = sum(1 for word in suspicious_words if word in url_lower)
    features.append(keyword_count)

    return features