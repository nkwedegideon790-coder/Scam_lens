"""Environment-driven settings. Read on every call so tests can override env vars."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "") or default)
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, "") or default)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    db_path: Path
    ai_provider: str
    max_text_chars: int
    min_text_chars: int
    max_image_bytes: int
    max_file_bytes: int
    max_image_pixels: int
    rate_limit_per_minute: int
    api_token: str
    trust_proxy: bool
    cors_origins: list[str] = field(default_factory=list)
    ocr_lang: str = "eng"
    ocr_timeout: int = 30
    ai_timeout: float = 45.0
    log_level: str = "INFO"


def get_settings() -> Settings:
    db = os.getenv("SCAMLENS_DB_PATH") or str(BASE_DIR / "data" / "scamlens.db")
    db_path = Path(db)
    if not db_path.is_absolute():
        db_path = BASE_DIR / db_path
    origins = [o.strip() for o in (os.getenv("SCAMLENS_CORS_ORIGINS") or "").split(",") if o.strip()]
    return Settings(
        db_path=db_path,
        ai_provider=(os.getenv("SCAMLENS_AI_PROVIDER") or "anthropic").strip().lower(),
        max_text_chars=_int("SCAMLENS_MAX_TEXT_CHARS", 8000),
        min_text_chars=3,
        max_image_bytes=_int("SCAMLENS_MAX_IMAGE_MB", 8) * 1024 * 1024,
        max_file_bytes=_int("SCAMLENS_MAX_FILE_MB", 1) * 1024 * 1024,
        max_image_pixels=_int("SCAMLENS_MAX_IMAGE_PIXELS", 40_000_000),
        rate_limit_per_minute=_int("SCAMLENS_RATE_LIMIT_PER_MIN", 20),
        api_token=os.getenv("SCAMLENS_API_TOKEN", "").strip(),
        trust_proxy=os.getenv("SCAMLENS_TRUST_PROXY", "0") == "1",
        cors_origins=origins,
        ocr_lang=os.getenv("SCAMLENS_OCR_LANG", "eng"),
        ocr_timeout=_int("SCAMLENS_OCR_TIMEOUT", 30),
        ai_timeout=_float("AI_TIMEOUT_SECONDS", 45.0),
        log_level=(os.getenv("SCAMLENS_LOG_LEVEL") or "INFO").upper(),
    )
