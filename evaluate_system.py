import pandas as pd
import requests

from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

df = pd.read_csv("test_urls.csv")

true_labels = []
pred_labels = []

for index, row in df.iterrows():
    url = row["url"]
    true_label = int(row["label"])

    response = requests.post(
        "http://127.0.0.1:5000/predict",
        json={"url": url}
    )

    result = response.json()

    predicted_label = int(result["prediction"])

    true_labels.append(true_label)
    pred_labels.append(predicted_label)

    print("==============================")
    print("URL:", url)
    print("Expected:", true_label)
    print("Predicted:", predicted_label)
    print("Decision:", result["decision"])
    print("Risk Score:", result["risk_score"])

print("\nRESULTS")
print("Accuracy :", accuracy_score(true_labels, pred_labels))
print("Precision:", precision_score(true_labels, pred_labels))
print("Recall   :", recall_score(true_labels, pred_labels))
print("F1 Score :", f1_score(true_labels, pred_labels))

print("\nConfusion Matrix")
print(confusion_matrix(true_labels, pred_labels))