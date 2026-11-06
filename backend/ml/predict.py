from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

import joblib
import pandas as pd

from .feature_extractor import FEATURE_NAMES, explain_url_features, extract_url_features, redact_url


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_PATH = ROOT / "backend" / "ml" / "model" / "phishing_xgboost.pkl"


class ModelNotReadyError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def load_artifact() -> dict:
    path = Path(os.getenv("MODEL_PATH", DEFAULT_MODEL_PATH))
    if not path.exists():
        raise ModelNotReadyError("XGBoost model is not trained yet. Provide a labeled dataset and run backend/ml/train_model.py.")
    try:
        artifact = joblib.load(path)
    except Exception as error:
        raise ModelNotReadyError("XGBoost model artifact could not be loaded; retrain the model.") from error
    if (
        not isinstance(artifact, dict)
        or "model" not in artifact
        or artifact.get("feature_names") != FEATURE_NAMES
        or not hasattr(artifact["model"], "predict_proba")
    ):
        raise ModelNotReadyError("Model artifact is invalid; retrain the XGBoost model.")
    return artifact


def predict_url(url: str) -> dict:
    artifact = load_artifact()
    features = extract_url_features(url)
    frame = pd.DataFrame([[features[name] for name in FEATURE_NAMES]], columns=FEATURE_NAMES)
    model = artifact["model"]
    probability = float(model.predict_proba(frame)[0][1])
    known_safe = bool(features.get("known_safe_domain"))
    phishing = probability >= 0.5 and not known_safe
    # The training set is lexical-only and cannot establish domain reputation. Keep
    # the public score conservative and make that limitation explicit to callers.
    if known_safe:
        calibrated_risk = 0.02
        assessment = "known_safe_domain"
        confidence = 0.75
    else:
        calibrated_risk = min(0.90, max(0.10, 0.10 + (probability * 0.80)))
        assessment = "heuristic_only"
        confidence = min(0.85, max(0.50, max(probability, 1 - probability)))
    return {
        "url": redact_url(url),
        "prediction": "Phishing" if phishing else "Safe",
        "confidence": round(confidence, 4),
        "risk_score": round(calibrated_risk * 100),
        "assessment": assessment,
        "calibration_note": "Lexical model only; domain reputation and page content were not verified.",
        "reasons": explain_url_features(features),
        "features": features,
    }
