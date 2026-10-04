"""Thin HTTP client for the ScamLens backend. All errors become friendly APIError messages."""
from __future__ import annotations

import os
from typing import Any, Optional

import requests


class APIError(Exception):
    def __init__(self, message: str, code: str | None = None, status: int | None = None):
        super().__init__(message)
        self.message, self.code, self.status = message, code, status


def _secret(name: str, default: str = "") -> str:
    value = os.getenv(name)
    if value:
        return value
    try:
        import streamlit as st
        return str(st.secrets.get(name, default))
    except Exception:
        return default


def base_url() -> str:
    return _secret("SCAMLENS_API_URL", "http://localhost:8000").rstrip("/")


def _headers() -> dict[str, str]:
    token = _secret("SCAMLENS_API_TOKEN")
    return {"X-API-Key": token} if token else {}


def _request(method: str, path: str, *, timeout: float = 20, **kwargs: Any) -> Any:
    try:
        resp = requests.request(method, base_url() + path, headers=_headers(), timeout=timeout, **kwargs)
    except requests.exceptions.Timeout as exc:
        raise APIError("The request took too long. Please try again.", "timeout") from exc
    except requests.exceptions.RequestException as exc:
        raise APIError("We can't reach the ScamLens service right now. Check that the backend is running.",
                       "unreachable") from exc
    if resp.status_code >= 400:
        try:
            body = resp.json()
            raise APIError(body.get("detail") or "Something went wrong.", body.get("code"), resp.status_code)
        except ValueError:
            raise APIError("Something went wrong. Please try again.", None, resp.status_code)
    try:
        return resp.json()
    except ValueError as exc:
        raise APIError("The service returned an unreadable response.", None, resp.status_code) from exc


def health() -> dict:
    return _request("GET", "/health", timeout=6)


def ocr(file_bytes: bytes, filename: str, content_type: str) -> dict:
    return _request("POST", "/ocr", timeout=60, files={"file": (filename, file_bytes, content_type)})


def analyze_text(text: str, source_type: str = "message", original_text: Optional[str] = None) -> dict:
    return _request("POST", "/analyze/text", timeout=90,
                    json={"text": text, "source_type": source_type, "original_text": original_text})


def analyze_file(file_bytes: bytes, filename: str, content_type: str) -> dict:
    return _request("POST", "/analyze/file", timeout=90, files={"file": (filename, file_bytes, content_type)})


def list_analyses(limit: int = 10, offset: int = 0, risk_levels: Optional[list[str]] = None) -> dict:
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if risk_levels:
        params["risk_level"] = ",".join(risk_levels)
    return _request("GET", "/analyses", params=params)


def get_analysis(analysis_id: int) -> dict:
    return _request("GET", f"/analyses/{analysis_id}")


def stats() -> dict:
    return _request("GET", "/stats")
