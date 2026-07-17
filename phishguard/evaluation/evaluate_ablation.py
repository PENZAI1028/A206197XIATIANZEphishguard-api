"""Evaluate AI/rule/reputation component ablations on the fixed regression set."""

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

ROOT=Path(__file__).resolve().parents[1]; BACKEND=ROOT/"backend"; sys.path.insert(0,str(BACKEND)); import app  # noqa: E402


def metric(labels,predictions):
    return {"accuracy":accuracy_score(labels,predictions),"precision":precision_score(labels,predictions,zero_division=0),"recall":recall_score(labels,predictions,zero_division=0),"f1":f1_score(labels,predictions,zero_division=0),"confusion_matrix":confusion_matrix(labels,predictions,labels=[0,1]).tolist()}


def safe_reputation(url,domain):
    return app.indicator("reputationEvidence",0,"safe","Reputation disabled for ablation.",{"match":False},"rule override")


def rule_only_prediction(url, payload):
    scores={item["name"]:item["score"] for item in payload["indicators"]}; scores["aiModelProbability"]=0; scores["reputationEvidence"]=0
    weighted=round(sum(scores[name]*weight for name,weight in app.INDICATOR_WEIGHTS.items()))
    critical_names=("officialDomain","homographAttack","brandVerification","urlStructure")
    critical=any(scores.get(name,0)>=90 for name in critical_names) or "@" in url
    domain=app.get_domain(url)
    if critical:
        top=sorted(scores.values(),reverse=True)[:3]; weighted=max(weighted,round(sum(value*weight for value,weight in zip(top,(.65,.20,.15)))))
    if app.domain_is_official(domain)[0] and not critical: weighted=min(weighted,10)
    if app.is_shared_hosting_domain(domain) and not critical: weighted=max(weighted,20)
    return int(weighted>=45)


def sensitivity_prediction(url, payload, ai_weight):
    scores={item["name"]:item["score"] for item in payload["indicators"]}; scores["reputationEvidence"]=0
    other_total=sum(weight for name,weight in app.INDICATOR_WEIGHTS.items() if name not in ("aiModelProbability","reputationEvidence"))
    weights={name:(ai_weight if name=="aiModelProbability" else 0 if name=="reputationEvidence" else weight*((1-ai_weight)/other_total)) for name,weight in app.INDICATOR_WEIGHTS.items()}
    risk=round(sum(scores[name]*weights[name] for name in weights)); domain=app.get_domain(url)
    critical=any(scores.get(name,0)>=90 for name in ("officialDomain","homographAttack","brandVerification","urlStructure")) or "@" in url
    if critical:
        top=sorted(scores.values(),reverse=True)[:3]; risk=max(risk,round(sum(value*weight for value,weight in zip(top,(.65,.20,.15)))))
    if not app.domain_is_official(domain)[0] and not critical and ((scores["aiModelProbability"]>=45 and scores["suspiciousKeywords"]>=75 and scores["urlStructure"]>=25) or (scores["aiModelProbability"]>=50 and scores["suspiciousKeywords"]>=40 and scores["urlStructure"]>=60)): risk=max(risk,45)
    if app.domain_is_official(domain)[0] and not critical: risk=min(risk,10)
    if app.is_shared_hosting_domain(domain) and not critical: risk=max(risk,20)
    return int(risk>=45)


def main():
    rows=list(csv.DictReader((BACKEND/"test_urls.csv").open(encoding="utf-8"))); labels=[int(row["label"]) for row in rows]
    full=[]; no_reputation=[]; ai_only=[]; rules_only=[]; sensitivity={weight:[] for weight in (.10,.18,.25)}
    with app.app.test_client() as client:
        for row in rows:
            payload=client.post("/predict",json={"url":row["url"]}).get_json(); full.append(int(payload["prediction"])); rules_only.append(rule_only_prediction(row["url"],payload)); threshold=app.get_model_decision_threshold(); raw_probability,_=app.get_phishing_probability(None,url=row["url"]); calibrated_probability=app.calibrate_ai_probability(raw_probability); ai_only.append(int(calibrated_probability>=threshold))
            for weight in sensitivity: sensitivity[weight].append(sensitivity_prediction(row["url"],payload,weight))
    with patch.object(app,"detect_reputation_evidence",safe_reputation):
        with app.app.test_client() as client:
            for row in rows: no_reputation.append(int(client.post("/predict",json={"url":row["url"]}).get_json()["prediction"]))
    result={"generated_at_utc":datetime.now(timezone.utc).isoformat(),"dataset":"backend/test_urls.csv","rows":len(rows),"ai_only_decision_threshold":app.get_model_decision_threshold(),"ai_only_threshold_source":"model.metadata.probability_calibration.decision_threshold","weight_policy":"The production weights are expert-set design values, not fitted coefficients. Sensitivity values are exploratory only and were not used to optimise the production weights.","limitations":"Project regression cases are a controlled behavioural baseline, not an independent generalisation benchmark.","variants":{"rules_only":metric(labels,rules_only),"ai_only_formally_calibrated":metric(labels,ai_only),"ai_plus_deterministic_rules":metric(labels,no_reputation),"ai_plus_rules_plus_reputation":metric(labels,full)},"ai_weight_sensitivity":{f"ai_weight_{int(weight*100)}_percent":metric(labels,predictions) for weight,predictions in sensitivity.items()}}
    out=ROOT/"evaluation"/"results"/"ablation_results.json"; out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(result,indent=2),encoding="utf-8"); print(json.dumps(result,indent=2))


if __name__=="__main__": main()
