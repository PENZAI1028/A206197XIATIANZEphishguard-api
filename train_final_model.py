import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

df = pd.read_csv("../dataset/PhiUSIIL_Phishing_URL_Dataset.csv")

# 清理列名空格
df.columns = df.columns.str.strip()

# 把 label 单独拿出来
y = df["label"]

# 只保留数字列作为特征
X = df.drop("label", axis=1)
X = X.select_dtypes(include=["int64", "float64", "int32", "float32"])

print("Features used:", X.shape[1])
print("Rows:", X.shape[0])

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

print("Training model...")
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

joblib.dump(model, "phishing_model_final.pkl")

print("\nModel Saved Successfully!")