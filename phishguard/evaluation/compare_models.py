"""Bounded grouped benchmark of candidate classifiers on one shared feature matrix."""

import argparse, csv, json, sys, time
from datetime import datetime, timezone
from pathlib import Path
import joblib
from sklearn.base import clone
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.naive_bayes import ComplementNB
from sklearn.svm import LinearSVC

ROOT=Path(__file__).resolve().parents[1]; sys.path[:0]=[str(ROOT/"training"),str(ROOT/"backend")]
from train_url_model import read_dataset, resolve_column, to_binary_label, root_group, stratified_cap, build_pipeline, URL_CANDIDATES, LABEL_CANDIDATES  # noqa: E402
from phishguard_ml_features import normalise_for_model  # noqa: E402
import pandas as pd  # noqa: E402


def main():
    p=argparse.ArgumentParser(); p.add_argument("--rows",type=int,default=20000); p.add_argument("--max-features",type=int,default=20000); p.add_argument("--output",default=str(ROOT/"evaluation"/"results"/"model_comparison.json")); args=p.parse_args(); seed=42
    frame=read_dataset(ROOT/"dataset"/"PhiUSIIL_Phishing_URL_Dataset.csv"); u=resolve_column(frame,None,URL_CANDIDATES,"url"); l=resolve_column(frame,None,LABEL_CANDIDATES,"label"); data=pd.DataFrame({"url":frame[u].map(normalise_for_model),"raw":frame[l]}); data["label"]=data.raw.map(lambda v:to_binary_label(v,"0")); data=data.dropna(subset=["url","label"]); data=data[data.url.str.len()>=8].drop_duplicates("url"); data["label"]=data.label.astype(int); data["group"]=data.url.map(root_group); data=stratified_cap(data,args.rows,seed)
    split=GroupShuffleSplit(n_splits=1,test_size=.2,random_state=seed); tr,te=next(split.split(data.url,data.label,groups=data.group)); train,test=data.iloc[tr],data.iloc[te]
    features=build_pipeline(args.max_features,seed).named_steps["features"]; start=time.perf_counter(); x_train=features.fit_transform(train.url.tolist(),train.label.to_numpy()); x_test=features.transform(test.url.tolist()); feature_seconds=time.perf_counter()-start
    models={"Logistic Regression":LogisticRegression(max_iter=1000,class_weight="balanced",solver="liblinear",random_state=seed),"SGD log-loss":SGDClassifier(loss="log_loss",alpha=4e-6,class_weight="balanced",random_state=seed),"Linear SVM":LinearSVC(class_weight="balanced",random_state=seed),"Random Forest":RandomForestClassifier(n_estimators=60,max_depth=24,min_samples_leaf=2,class_weight="balanced",n_jobs=-1,random_state=seed),"Extra Trees":ExtraTreesClassifier(n_estimators=60,max_depth=24,min_samples_leaf=2,class_weight="balanced",n_jobs=-1,random_state=seed),"Complement Naive Bayes":ComplementNB(alpha=1.0)}
    results=[]
    for name,model in models.items():
        start=time.perf_counter(); model.fit(x_train,train.label); fit=time.perf_counter()-start; start=time.perf_counter(); pred=model.predict(x_test); predict=time.perf_counter()-start
        results.append({"model":name,"accuracy":accuracy_score(test.label,pred),"precision":precision_score(test.label,pred,zero_division=0),"recall":recall_score(test.label,pred,zero_division=0),"f1":f1_score(test.label,pred,zero_division=0),"fit_seconds":fit,"predict_seconds":predict})
    report={"generated_at_utc":datetime.now(timezone.utc).isoformat(),"scope":"bounded candidate comparison; same TF-IDF character 3-5 gram plus 21-lexical feature matrix for all models","source_rows":len(data),"train_rows":len(train),"test_rows":len(test),"group_split_random_state":seed,"max_tfidf_features":args.max_features,"feature_fit_transform_seconds":feature_seconds,"selection_note":"The production SGD choice also considers sparse scalability, probability support and deployment size; this benchmark is comparative evidence, not a universal ranking.","results":results}
    out=Path(args.output); out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(report,indent=2),encoding="utf-8"); print(json.dumps(report,indent=2))


if __name__=="__main__": main()
