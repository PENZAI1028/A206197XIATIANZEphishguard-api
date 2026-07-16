# Model evidence and reproducibility

This record identifies the model artifact used by the Flask backend and ties it
to the public training data, training code, split protocol, metrics, and runtime
versions. It is intended to make the implementation claims independently
inspectable.

## Canonical files

- Deployed artifact: `backend/phishing_web_model.pkl`
- Machine-readable evidence: `backend/phishing_web_model_metadata.json`
- Training entry point: `training/train_url_model.py`
- Custom lexical transformer: `backend/phishguard_ml_features.py`
- Exact training dependencies: `training/requirements-training.txt`
- Source dataset: `dataset/PhiUSIIL_Phishing_URL_Dataset.csv`

Artifact SHA-256:

```text
5eca55e09e1736fc4d493a555de0fc5969a80d202c62e04987b58bece9cefc6b
```

Dataset SHA-256:

```text
a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6
```

## Model and data split

The serialized bundle is `phishguard_url_pipeline_v4`. Its pipeline combines
TF-IDF character n-grams (3-5) with 21 lexical URL features and an
`SGDClassifier` using logistic loss.

After cleaning, the public source dataset contains 235,370 rows: 134,850
phishing and 100,520 safe. `GroupShuffleSplit` with `random_state=42` and a
20% test size groups URLs by registered root-like domain. The split occurs
before augmentation. The training partition contains 192,971 source rows plus
50,000 synthetic lookalikes added only to training (242,971 total). The untouched
holdout contains 42,399 URLs across 32,690 root-domain groups.

## Grouped-holdout results

| Metric | Value |
| --- | ---: |
| Accuracy | 0.9947640275 |
| Precision | 0.9916847704 |
| Recall | 1.0000000000 |
| F1 | 0.9958250273 |

The confusion matrix in `[safe, phishing]` label order is
`[[15701, 222], [0, 26476]]` (TN, FP, FN, TP).

The separate 100-URL end-to-end API regression set in `backend/test_urls.csv`
produces 96/100 correct predictions with confusion matrix
`[[49, 1], [3, 47]]`. This system-level result includes the API's rules and
score aggregation and must not be confused with the grouped model holdout.

## Recorded training environment

- Python 3.14.6
- joblib 1.5.3
- NumPy 2.5.0
- pandas 3.0.3
- SciPy 1.18.0
- scikit-learn 1.9.0

The exact library constraints are in `training/requirements-training.txt`.
An independent environment record can also be captured with:

```powershell
python --version
python -m pip freeze > pip-freeze.txt
```

## Verification

From the repository root, verify the hashes:

```powershell
Get-FileHash -Algorithm SHA256 phishguard/backend/phishing_web_model.pkl
Get-FileHash -Algorithm SHA256 phishguard/dataset/PhiUSIIL_Phishing_URL_Dataset.csv
```

Inspect the serialized model metadata:

```powershell
cd phishguard/backend
python -c "import joblib; b=joblib.load('phishing_web_model.pkl'); print(b['format']); print(b['model_name']); print(b['metadata'])"
```

Recreate the training environment and rerun training from `phishguard/`:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r training/requirements-training.txt
.\.venv\Scripts\python.exe training/train_url_model.py --data dataset/PhiUSIIL_Phishing_URL_Dataset.csv --min-rows 100000 --max-rows 1000000 --target 0.99
```

The JSON evidence file duplicates the material fields from the serialized
bundle so they can be reviewed without executing a pickle. As with any pickle,
only load the artifact from a trusted repository revision.
