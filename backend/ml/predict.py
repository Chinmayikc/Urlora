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


def predict_url(url: str, verification: dict | None = None) -> dict:
    artifact = load_artifact()
    features = extract_url_features(url)
    frame = pd.DataFrame([[features[name] for name in FEATURE_NAMES]], columns=FEATURE_NAMES)
    model = artifact["model"]
    probability = float(model.predict_proba(frame)[0][1])
    known_safe = bool(features.get("known_safe_domain"))
    verification = verification or {
        "status": "not_run",
        "domain_reputation": "not_run",
        "page_content": "not_run",
        "signals": ["Domain and page verification was not run."],
    }
    verification_status = str(verification.get("status", "unverified"))
    lexical_reasons = explain_url_features(features)
    high_signal = bool(
        features["contains_ip_address"]
        or features["contains_at_symbol"]
        or not features["uses_https"]
        or features["uses_url_shortener"]
        or features["suspicious_keyword_count"]
        or features["url_length"] > 75
        or features["number_of_subdomains"] >= 3
        or features["contains_suspicious_symbol"]
    )
    reputation_malicious = verification.get("domain_reputation") == "malicious" or verification_status == "malicious"
    page_suspicious = verification_status == "suspicious" or verification.get("page_content") == "suspicious"

    if reputation_malicious or page_suspicious:
        prediction = "Phishing"
        assessment = "verified_suspicious"
        calibrated_risk = max(0.80, min(0.98, 0.10 + (probability * 0.80)))
        confidence = 0.90
    elif verification_status == "verified" and not high_signal:
        # A clean, same-domain HTML page that identifies itself consistently is
        # stronger evidence than the lexical model's false positive.
        prediction = "Safe"
        assessment = "verified_page"
        calibrated_risk = 0.05
        confidence = 0.85
    elif known_safe and not reputation_malicious and not high_signal and verification_status in {"not_run", "verified"}:
        prediction = "Safe"
        assessment = "known_safe_domain"
        calibrated_risk = 0.02
        confidence = 0.75
    elif probability >= 0.5 and high_signal:
        prediction = "Phishing"
        assessment = "lexical_suspicious" if verification_status in {"unverified", "unavailable", "blocked", "not_run"} else "suspicious_signals"
        calibrated_risk = min(0.90, max(0.10, 0.10 + (probability * 0.80)))
        confidence = min(0.85, max(0.50, max(probability, 1 - probability)))
    elif verification_status in {"unverified", "unavailable", "blocked", "not_run", "inspected"}:
        # Do not turn a model-only guess into a safe verdict when verification
        # failed or the page identity was inconclusive.
        prediction = "Needs review"
        assessment = "needs_review"
        calibrated_risk = min(0.90, max(0.10, 0.10 + (probability * 0.80)))
        confidence = min(0.75, max(0.50, max(probability, 1 - probability)))
    else:
        prediction = "Safe"
        assessment = "screened_safe"
        calibrated_risk = min(0.45, max(0.05, 0.10 + (probability * 0.50)))
        confidence = min(0.80, max(0.50, max(probability, 1 - probability)))

    if assessment == "verified_page":
        calibration_note = "The public page was fetched over HTTP(S), stayed on the same domain, and its content matched the hostname."
    elif assessment == "verified_suspicious":
        calibration_note = "Page content or the configured domain reputation provider produced a phishing signal."
    elif assessment == "needs_review":
        calibration_note = "Verification was inconclusive; do not treat this result as safe or enter credentials."
    elif assessment == "known_safe_domain":
        calibration_note = "Hostname matches a small curated safe-domain list; live reputation and page content were not verified."
    else:
        calibration_note = "Lexical indicators were found; domain reputation or page content was not sufficient to override them."

    if known_safe:
        verification.setdefault("signals", []).append("Hostname is on the curated safe-domain list; this is not a reputation guarantee.")
    return {
        "url": redact_url(url),
        "prediction": prediction,
        "confidence": round(confidence, 4),
        "risk_score": round(calibrated_risk * 100),
        "assessment": assessment,
        "calibration_note": calibration_note,
        "reasons": explain_url_features(features),
        "features": features,
        "verification": verification,
    }
