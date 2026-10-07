"""Vercel ASGI entrypoint for Urlora's FastAPI backend."""

from backend.main import api_app

app = api_app

__all__ = ["app"]
