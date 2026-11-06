from __future__ import annotations

import os
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from dotenv import load_dotenv

try:
    from backend.ml.predict import ModelNotReadyError, load_artifact, predict_url
    from backend.supabase_service import save_scan_if_configured
except ModuleNotFoundError:  # Supports running uvicorn from inside backend/.
    from ml.predict import ModelNotReadyError, load_artifact, predict_url
    from supabase_service import save_scan_if_configured


ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
logger = logging.getLogger(__name__)
api_app = FastAPI(title="Urlora API", version="1.0.0")

origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if origin.strip()]
api_app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

DIST_DIR = ROOT / "dist"
if (DIST_DIR / "assets").exists():
    api_app.mount("/assets", StaticFiles(directory=DIST_DIR / "assets"), name="assets")


class PredictRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)


class PredictResponse(BaseModel):
    url: str
    prediction: str
    confidence: float
    risk_score: int
    assessment: str
    calibration_note: str
    reasons: list[str]
    features: dict[str, float | int | str]
    created_at: str


@api_app.get("/", include_in_schema=False, response_model=None)
def root() -> FileResponse | dict[str, str | bool]:
    index_file = DIST_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {
        "service": "Urlora API",
        "status": "ok",
        "message": "Frontend build not found. Run npm run build, or open the Vite frontend on port 5173.",
    }


RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "30"))
_rate_limit: dict[str, tuple[float, int]] = {}


def _rate_limited(request: Request) -> bool:
    now = time.monotonic()
    client = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown").split(",")[0].strip()
    window_start, count = _rate_limit.get(client, (now, 0))
    if now - window_start >= RATE_LIMIT_WINDOW_SECONDS:
        window_start, count = now, 0
    count += 1
    _rate_limit[client] = (window_start, count)
    if len(_rate_limit) > 10_000:
        _rate_limit.clear()
    return count > RATE_LIMIT_MAX_REQUESTS


@api_app.get("/health")
def health() -> dict[str, str | bool]:
    try:
        load_artifact()
        model_ready = True
    except ModelNotReadyError:
        model_ready = False
    return {"status": "ok" if model_ready else "degraded", "model_ready": model_ready}


@api_app.post("/predict", response_model=PredictResponse)
def predict(payload: PredictRequest, request: Request) -> PredictResponse:
    if _rate_limited(request):
        raise HTTPException(status_code=429, detail="Too many scans. Please try again in a minute.", headers={"Retry-After": "60"})
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
