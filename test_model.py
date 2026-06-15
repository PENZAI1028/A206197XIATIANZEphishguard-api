import joblib
from feature_extraction import extract_features

model = joblib.load("phishing_model.pkl")

test_url = input("Enter URL to test: ")

features = [extract_features(test_url)]

prediction = model.predict(features)[0]

if prediction == 1:
    print("Result: Phishing")
else:
    print("Result: Safe")