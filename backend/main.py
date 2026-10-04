"""ScamLens FastAPI application."""
from __future__ import annotations

import hmac
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, File, Header, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import analyzer, database, ocr, service
from .config import get_settings
from .errors import (AuthError, InputTooLargeError, InvalidInputError, NotFoundError, RateLimitedError,
                     ScamLensError)
from .schemas import AnalysisResult, AnalyzeTextRequest, HistoryResponse, OCRResponse
from .utils import RateLimiter, client_ip, parse_text_upload, setup_logging

logger = logging.getLogger("scamlens")
VERSION = "1.0.0"
_limiter = RateLimiter()


@asynccontextmanager
async def lifespan(_: FastAPI):
    setup_logging(get_settings().log_level)
    database.init_db()
    if analyzer.build_provider() is None:
        logger.warning("No AI provider API key configured: analysis endpoints will return 503 until one is set.")
    yield


app = FastAPI(
    title="ScamLens API",
    version=VERSION,
    description="Explainable scam, phishing and impersonation analysis. AI-assisted risk assessment, not a guarantee.",
    lifespan=lifespan,
)
if get_settings().cors_origins:
    app.add_middleware(CORSMiddleware, allow_origins=get_settings().cors_origins,
                       allow_methods=["GET", "POST"], allow_headers=["*"])


# ------------------------------------------------------------------ dependencies
def get_provider() -> Optional[analyzer.AIProvider]:
    return analyzer.build_provider()


def require_auth(x_api_key: Optional[str] = Header(default=None)) -> None:
    token = get_settings().api_token
    if token and not hmac.compare_digest((x_api_key or "").encode(), token.encode()):
        raise AuthError()


def rate_limit(request: Request) -> None:
    s = get_settings()
    if not _limiter.allow(client_ip(request, s.trust_proxy), s.rate_limit_per_minute):
        raise RateLimitedError()


AUTH = [Depends(require_auth)]
GUARDED = [Depends(require_auth), Depends(rate_limit)]


# --------------------------------------------------------------- error handling
@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    s = get_settings()
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > s.max_image_bytes + 1_048_576:
        return JSONResponse(status_code=413, content={"detail": "That upload is too large.", "code": "input_too_large"})
    return await call_next(request)


@app.exception_handler(ScamLensError)
async def scamlens_error_handler(_: Request, exc: ScamLensError):
    if exc.status_code >= 500:
        logger.error("%s: %s", exc.code, exc)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.user_message, "code": exc.code})


@app.exception_handler(RequestValidationError)
async def validation_handler(_: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": "The request was not valid. Check your input and try again.",
                                                  "code": "invalid_request"})


@app.exception_handler(Exception)
async def unhandled_handler(_: Request, exc: Exception):
    logger.exception("Unhandled error: %s", type(exc).__name__)
    return JSONResponse(status_code=500, content={"detail": "Something went wrong on our side. Please try again.",
                                                  "code": "internal_error"})


# ---------------------------------------------------------------------- routes
@app.get("/health")
def health():
    provider = analyzer.build_provider()
    return {
        "status": "ok",
        "version": VERSION,
        "ai_configured": provider is not None,
        "ai_model": f"{provider.name}:{provider.model}" if provider else None,
        "ocr_available": ocr.is_available(),
    }


@app.post("/analyze/text", response_model=AnalysisResult, dependencies=GUARDED)
def analyze_text(payload: AnalyzeTextRequest, refresh: bool = Query(False),
                 provider: Optional[analyzer.AIProvider] = Depends(get_provider)):
    return service.run_analysis(payload.text, payload.source_type, provider, payload.original_text, refresh)


def _read_upload(file: UploadFile, limit: int) -> bytes:
    data = file.file.read(limit + 1)
    if len(data) > limit:
        raise InputTooLargeError(f"That file is too large. The limit is {limit // (1024 * 1024)} MB.")
    if not data:
        raise InvalidInputError("The uploaded file is empty.")
    return data


@app.post("/ocr", response_model=OCRResponse, dependencies=GUARDED)
def extract_screenshot_text(file: UploadFile = File(...)):
    data = _read_upload(file, get_settings().max_image_bytes)
    result = ocr.extract_text(data)
    return OCRResponse(text=result.text, char_count=len(result.text), warnings=result.warnings)


@app.post("/analyze/image", response_model=AnalysisResult, dependencies=GUARDED)
def analyze_image(file: UploadFile = File(...), refresh: bool = Query(False),
                  provider: Optional[analyzer.AIProvider] = Depends(get_provider)):
    data = _read_upload(file, get_settings().max_image_bytes)
    extracted = ocr.extract_text(data)
    return service.run_analysis(extracted.text, "screenshot", provider, extracted.text, refresh)


@app.post("/analyze/file", response_model=AnalysisResult, dependencies=GUARDED)
def analyze_file(file: UploadFile = File(...), refresh: bool = Query(False),
                 provider: Optional[analyzer.AIProvider] = Depends(get_provider)):
    data = _read_upload(file, get_settings().max_file_bytes)
    text = parse_text_upload(file.filename, data)
    return service.run_analysis(text, "file", provider, None, refresh)


@app.get("/analyses", response_model=HistoryResponse, dependencies=AUTH)
def list_analyses(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0),
                  risk_level: Optional[str] = Query(None, description="Comma-separated, e.g. HIGH,CRITICAL")):
    levels = None
    if risk_level:
        levels = [l.strip().upper() for l in risk_level.split(",") if l.strip()]
        if any(l not in database.RISK_LEVELS for l in levels):
            raise InvalidInputError("Unknown risk level filter.")
    total, items = database.list_analyses(limit, offset, levels)
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.get("/analyses/{analysis_id}", response_model=AnalysisResult, dependencies=AUTH)
def get_analysis(analysis_id: int):
    result = database.get_analysis(analysis_id)
    if result is None:
        raise NotFoundError()
    result["from_cache"] = False
    return result


@app.get("/stats", dependencies=AUTH)
def stats():
    return database.get_stats()
