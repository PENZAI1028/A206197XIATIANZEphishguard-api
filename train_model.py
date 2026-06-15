import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from feature_extraction import extract_features

df = pd.read_csv("../dataset/phishing_dataset.csv")

X = df["url1"].apply(extract_features).tolist()
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42
)

model = RandomForestClassifier()
model.fit(X_train, y_train)

joblib.dump(model, "phishing_model.pkl")

print("Model trained and saved!")