"""Analysis pipeline: validate -> (cache) -> AI -> risk engine -> store -> result."""
from __future__ import annotations

import logging
from typing import Optional

from . import analyzer, database, risk_engine
from .config import get_settings
from .errors import InputTooLargeError
from .utils import normalize_text, require_non_empty, text_hash

logger = logging.getLogger(__name__)


def run_analysis(text: str, source_type: str, provider: Optional[analyzer.AIProvider],
                 original_text: Optional[str] = None, refresh: bool = False) -> dict:
    settings = get_settings()
    clean = normalize_text(text)
    require_non_empty(clean, settings.min_text_chars)
    if len(clean) > settings.max_text_chars:
        raise InputTooLargeError(f"That message is too long. Please keep it under {settings.max_text_chars:,} characters.")

    digest = text_hash(clean)
    if not refresh:
        cached_id = database.find_cached(digest)
        if cached_id is not None:
            cached = database.get_analysis(cached_id)
            if cached:
                cached["from_cache"] = True
                return cached

    links = risk_engine.analyze_links(clean)
    hints = [f"{l.domain}: " + "; ".join(l.reasons) for l in links if l.suspicious]
    ai = analyzer.analyze(clean, provider, hints)

    flags = risk_engine.verify_evidence(ai.red_flags, clean)
    signals = risk_engine.detect_signals(clean, links)
    level, notes = risk_engine.classify(ai.risk_level, signals, flags)
    meta = risk_engine.RISK_META[level]

    raw = normalize_text(original_text) if original_text else clean
    payload = {
        "input_type": source_type,
        "risk_level": level,
        "risk_label": meta["label"],
        "risk_icon": meta["icon"],
        "assessment_message": meta["message"],
        "confidence": ai.confidence,
        "confidence_note": risk_engine.CONFIDENCE_NOTE,
        "scam_category": ai.scam_category,
        "summary": ai.summary,
        "red_flags": [f.model_dump() for f in flags],
        "recommended_actions": risk_engine.build_actions(level, signals, ai.recommended_actions),
        "verification_steps": risk_engine.build_verification(ai.verification_steps),
        "links": [l.model_dump() for l in links],
        "links_message": risk_engine.NO_URL_MESSAGE if not links else (
            risk_engine.LINK_SUSPICIOUS_MESSAGE if any(l.suspicious for l in links) else risk_engine.LINK_OK_MESSAGE),
        "signals": [s.model_dump() for s in signals],
        "risk_notes": notes,
        "original_text": raw,
        "extracted_text": clean if source_type != "message" else None,
        "analyzed_text": clean,
        "language": ai.language,
        "intent": ai.intent,
        "sender_claims": ai.sender_claims,
        "requests_made": ai.requests_made,
        "model": f"{provider.name}:{provider.model}" if provider else None,
        "disclaimer": risk_engine.DISCLAIMER,
    }
    analysis_id = database.save_analysis(payload, digest)
    result = database.get_analysis(analysis_id)
    assert result is not None
    result["from_cache"] = False
    return result
