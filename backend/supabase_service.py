from __future__ import annotations

import os
import logging
from typing import Any

logger = logging.getLogger(__name__)


def save_scan_if_configured(result: dict[str, Any], user_id: str | None = None) -> None:
    """Persist a scan only when server-side Supabase credentials are configured."""
    supabase_url = os.getenv("SUPABASE_URL")
    service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    if not supabase_url or not service_key:
        return

    try:
        from supabase import create_client

        client = create_client(supabase_url, service_key)
        table = os.getenv("SUPABASE_TABLE", "url_scans")
        client.table(table).insert({
            "user_id": user_id,
            "url": result["url"],
            "prediction": result["prediction"],
            "confidence": result["confidence"],
            "risk_score": result["risk_score"],
            "created_at": result["created_at"],
        }).execute()
    except Exception:
        # Prediction should remain available if an optional analytics write fails.
        logger.exception("Supabase scan insert failed")
