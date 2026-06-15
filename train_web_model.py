import pandas as pd
import joblib
import re
from urllib.parse import urlparse

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix


def extract_url_features(url):
    url = str(url)
    url_lower = url.lower()
    parsed = urlparse(url)

    suspicious_words = [
        "login", "verify", "secure", "update", "account",
        "confirm", "bank", "payment", "signin", "password"
    ]

    brands = [
        "google", "amazon", "apple", "microsoft",
        "paypal", "facebook", "netflix", "bank"
    ]

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
        sum(word in url_lower for word in suspicious_words),
        sum(brand in url_lower for brand in brands)
    ]


df = pd.read_csv("../dataset/PhiUSIIL_Phishing_URL_Dataset.csv")
df.columns = df.columns.str.strip()

X = df["URL"].apply(extract_url_features).tolist()
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)

print("Training web model...")
model.fit(X_train, y_train)
print("Training complete!")

y_pred = model.predict(X_test)

print("\nRESULTS")
print("Accuracy :", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(y_test, y_pred))
print("Recall   :", recall_score(y_test, y_pred))
print("F1 Score :", f1_score(y_test, y_pred))

print("\nConfusion Matrix")
print(confusion_matrix(y_test, y_pred))

joblib.dump(model, "phishing_web_model.pkl")

print("\nWeb model saved as phishing_web_model.pkl")