import json
from pathlib import Path

from backend.ml.predict import load_artifact
from backend.ml.train_model import export_vercel_model
from backend.ml.feature_extractor import FEATURE_NAMES


def test_trained_artifact_exports_the_live_runtime_format():
    output = Path(__file__).resolve().parents[2] / "api" / "model.json"
    metadata = export_vercel_model(load_artifact()["model"], output)
    exported = json.loads(output.read_text(encoding="utf-8"))
    assert metadata["feature_count"] == len(FEATURE_NAMES)
    assert exported["learner"]["feature_names"] == FEATURE_NAMES
    assert metadata["tree_count"] == len(exported["learner"]["gradient_booster"]["model"]["trees"])
