from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from .feature_extractor import FEATURE_NAMES, extract_url_features


URL_COLUMNS = ("url", "link", "website", "address", "uri")
LABEL_COLUMNS = ("label", "type", "class", "status", "result", "target", "is_phishing")


def find_column(columns: list[str], candidates: tuple[str, ...]) -> str | None:
    normalized = {str(column).strip().lower(): column for column in columns}
    for candidate in candidates:
        if candidate in normalized:
            return normalized[candidate]
    for column in columns:
        lower = str(column).strip().lower()
        if any(candidate in lower for candidate in candidates):
            return column
    return None


def normalize_label(value: object) -> int | None:
    text = str(value).strip().lower()
    if text in {"1", "phishing", "phish", "malicious", "suspicious", "bad", "fraud", "true"}:
        return 1
    if text in {"0", "legitimate", "legit", "benign", "safe", "good", "valid", "false"}:
        return 0
    try:
        number = int(float(text))
        return number if number in {0, 1} else None
    except ValueError:
        return None


def load_labeled_dataset(path: Path) -> tuple[pd.DataFrame, dict[str, str | int]]:
    raw = pd.read_csv(path)
    url_column = find_column(list(raw.columns), URL_COLUMNS)
    label_column = find_column(list(raw.columns), LABEL_COLUMNS)
    if not url_column or not label_column:
        raise ValueError(f"Could not identify URL and label columns. Found columns: {list(raw.columns)}")

    clean = raw[[url_column, label_column]].rename(columns={url_column: "url", label_column: "label"}).copy()
    clean["url"] = clean["url"].astype(str).str.strip()
    clean = clean[clean["url"].ne("")].drop_duplicates(subset=["url"])
    clean["label"] = clean["label"].map(normalize_label)
    clean = clean.dropna(subset=["label"]).copy()
    valid_rows: list[dict] = []
    invalid_count = 0
    for row in clean.to_dict("records"):
        try:
            extract_url_features(row["url"])
            valid_rows.append(row)
        except ValueError:
            invalid_count += 1
    result = pd.DataFrame(valid_rows)
    if result.empty or result["label"].nunique() != 2:
        raise ValueError("Dataset must contain valid URLs and both legitimate (0) and phishing (1) classes.")
    result["label"] = result["label"].astype(int)
    return result, {"url_column": str(url_column), "label_column": str(label_column), "invalid_rows_removed": invalid_count, "rows_used": len(result)}


def evaluate_model(model, X_test, y_test) -> dict:
    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)[:, 1]
    return {
        "accuracy": round(float(accuracy_score(y_test, predictions)), 6),
        "precision": round(float(precision_score(y_test, predictions, zero_division=0)), 6),
        "recall": round(float(recall_score(y_test, predictions, zero_division=0)), 6),
        "f1": round(float(f1_score(y_test, predictions, zero_division=0)), 6),
        "roc_auc": round(float(roc_auc_score(y_test, probabilities)), 6),
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        "classification_report": classification_report(y_test, predictions, zero_division=0),
    }


def train(dataset_path: Path, output_path: Path) -> dict:
    data, dataset_metadata = load_labeled_dataset(dataset_path)
    features = pd.DataFrame([extract_url_features(url) for url in data["url"]], columns=FEATURE_NAMES)
    X_train, X_test, y_train, y_test = train_test_split(features, data["label"], test_size=0.2, random_state=42, stratify=data["label"])
    scale_pos_weight = max(1.0, (y_train == 0).sum() / max(1, (y_train == 1).sum()))
    model = XGBClassifier(
        n_estimators=500, max_depth=5, learning_rate=0.05, min_child_weight=2,
        subsample=0.85, colsample_bytree=0.85, reg_lambda=1.0,
        objective="binary:logistic", eval_metric="logloss", tree_method="hist",
        scale_pos_weight=scale_pos_weight, random_state=42, n_jobs=4,
    )
    try:
        model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False, early_stopping_rounds=40)
    except TypeError:
        model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)

    metrics = evaluate_model(model, X_test, y_test)
    baseline = RandomForestClassifier(n_estimators=250, class_weight="balanced", random_state=42, n_jobs=4)
    baseline.fit(X_train, y_train)
    baseline_metrics = evaluate_model(baseline, X_test, y_test)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "feature_names": FEATURE_NAMES, "dataset_metadata": dataset_metadata, "metrics": metrics}, output_path)
    metrics_path = output_path.with_name("evaluation.json")
    metrics_path.write_text(json.dumps({"xgboost": metrics, "random_forest_baseline": baseline_metrics, "dataset": dataset_metadata}, indent=2), encoding="utf-8")
    print(json.dumps({"xgboost": metrics, "random_forest_baseline": baseline_metrics, "dataset": dataset_metadata}, indent=2))
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Urlora's XGBoost phishing URL classifier.")
    parser.add_argument("dataset", type=Path, help="Path to a labeled CSV dataset")
    parser.add_argument("--output", type=Path, default=Path("backend/ml/model/phishing_xgboost.pkl"))
    args = parser.parse_args()
    train(args.dataset, args.output)
