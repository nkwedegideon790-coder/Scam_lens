"""Pydantic schemas: the AI output contract and the public API responses."""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SourceType = Literal["message", "screenshot", "file"]


class RedFlag(BaseModel):
    indicator: str
    evidence: str
    explanation: str
    # Computed by the backend (not the AI): was the quoted evidence found in the message?
    evidence_in_message: Optional[bool] = None


class AIAnalysis(BaseModel):
    """Validated, normalised output of the language model."""

    risk_level: RiskLevel
    confidence: int = Field(ge=0, le=100)
    scam_category: str
    summary: str
    red_flags: list[RedFlag] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)
    language: Optional[str] = None
    intent: Optional[str] = None
    sender_claims: list[str] = Field(default_factory=list)
    requests_made: list[str] = Field(default_factory=list)


class LinkFinding(BaseModel):
    url: str
    domain: str
    suspicious: bool
    reasons: list[str] = Field(default_factory=list)
    message: str


class Signal(BaseModel):
    name: str
    label: str
    strong: bool
    evidence: str


class AnalyzeTextRequest(BaseModel):
    text: str
    source_type: SourceType = "message"
    # Raw OCR / parsed text before the user edited it (optional).
    original_text: Optional[str] = None


class AnalysisResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: int
    created_at: str
    input_type: SourceType
    risk_level: RiskLevel
    risk_label: str
    risk_icon: str
    assessment_message: str
    confidence: int
    confidence_note: str
    scam_category: str
    summary: str
    red_flags: list[RedFlag]
    recommended_actions: list[str]
    verification_steps: list[str]
    links: list[LinkFinding]
    links_message: str
    signals: list[Signal]
    risk_notes: list[str]
    original_text: str
    extracted_text: Optional[str] = None
    analyzed_text: str
    language: Optional[str] = None
    intent: Optional[str] = None
    sender_claims: list[str] = Field(default_factory=list)
    requests_made: list[str] = Field(default_factory=list)
    model: Optional[str] = None
    from_cache: bool = False
    disclaimer: str


class OCRResponse(BaseModel):
    text: str
    char_count: int
    warnings: list[str] = Field(default_factory=list)


class AnalysisSummary(BaseModel):
    id: int
    created_at: str
    input_type: SourceType
    risk_level: RiskLevel
    confidence: int
    scam_category: str
    summary: str
    preview: str


class HistoryResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[AnalysisSummary]
