from __future__ import annotations

import os
import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from dotenv import load_dotenv

try:
    from backend.ml.predict import ModelNotReadyError, predict_url
    from backend.supabase_service import save_scan_if_configured
except ModuleNotFoundError:  # Supports running uvicorn from inside backend/.
    from ml.predict import ModelNotReadyError, predict_url
    from supabase_service import save_scan_if_configured


ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
logger = logging.getLogger(__name__)
app = FastAPI(title="Urlora API", version="1.0.0")

origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

DIST_DIR = ROOT / "dist"
if (DIST_DIR / "assets").exists():
    app.mount("/assets", StaticFiles(directory=DIST_DIR / "assets"), name="assets")


class PredictRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)


class PredictResponse(BaseModel):
    url: str
    prediction: str
    confidence: float
    risk_score: int
    reasons: list[str]
    features: dict[str, float | int | str]
    created_at: str


@app.get("/", include_in_schema=False, response_model=None)
def root() -> FileResponse | dict[str, str | bool]:
    index_file = DIST_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {
        "service": "Urlora API",
        "status": "ok",
        "message": "Frontend build not found. Run npm run build, or open the Vite frontend on port 5173.",
    }


@app.get("/health")
def health() -> dict[str, str | bool]:
    model_path = Path(os.getenv("MODEL_PATH", ROOT / "backend/ml/model/phishing_xgboost.pkl"))
    return {"status": "ok", "model_ready": model_path.exists()}


@app.post("/predict", response_model=PredictResponse)
def predict(payload: PredictRequest) -> PredictResponse:
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=422, detail="URL cannot be empty.")
    try:
        result = predict_url(url)
    except ModelNotReadyError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    response = PredictResponse(**result, created_at=datetime.now(timezone.utc).isoformat())
    try:
        # Do not accept a caller-supplied user id. Associate rows only after
        # Supabase Auth token verification is implemented on this API.
        save_scan_if_configured(response.model_dump(), user_id=None)
    except Exception:
        # Persistence is optional; a database outage must not turn a valid model result into a 500.
        logger.exception("Optional scan persistence failed")
    return response
