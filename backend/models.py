"""SQLite table definitions (plain SQL, no ORM, to keep the MVP light)."""

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS analyses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT    NOT NULL,
    input_type      TEXT    NOT NULL CHECK (input_type IN ('message', 'screenshot', 'file')),
    original_text   TEXT    NOT NULL,
    extracted_text  TEXT,
    risk_level      TEXT    NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    confidence      INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    scam_category   TEXT    NOT NULL,
    summary         TEXT    NOT NULL,
    ai_result       TEXT    NOT NULL,
    text_hash       TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS red_flags (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id  INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    indicator    TEXT    NOT NULL,
    evidence     TEXT    NOT NULL,
    explanation  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS recommended_actions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id  INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    action       TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_hash    ON analyses(text_hash);
CREATE INDEX IF NOT EXISTS idx_flags_analysis   ON red_flags(analysis_id);
CREATE INDEX IF NOT EXISTS idx_actions_analysis ON recommended_actions(analysis_id);
"""
