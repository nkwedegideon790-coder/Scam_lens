"""SQLite persistence for analyses, red flags and recommended actions."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, Optional

from .config import get_settings
from .models import SCHEMA_SQL

RISK_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
NO_CATEGORY_MARKERS = ("no scam category", "none identified", "none")


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    path = get_settings().db_path
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA_SQL)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def save_analysis(payload: dict, text_hash: str) -> int:
    """Insert an analysis (+ red flags + actions) in one transaction. Returns the new id."""
    stored = {k: v for k, v in payload.items() if k not in ("id", "created_at", "from_cache")}
    with connect() as conn:
        cur = conn.execute(
            """INSERT INTO analyses
               (created_at, input_type, original_text, extracted_text, risk_level,
                confidence, scam_category, summary, ai_result, text_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                _now(),
                payload["input_type"],
                payload["original_text"],
                payload.get("extracted_text"),
                payload["risk_level"],
                payload["confidence"],
                payload["scam_category"],
                payload["summary"],
                json.dumps(stored, ensure_ascii=False),
                text_hash,
            ),
        )
        analysis_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO red_flags (analysis_id, indicator, evidence, explanation) VALUES (?, ?, ?, ?)",
            [(analysis_id, f["indicator"], f["evidence"], f["explanation"]) for f in payload["red_flags"]],
        )
        conn.executemany(
            "INSERT INTO recommended_actions (analysis_id, action) VALUES (?, ?)",
            [(analysis_id, a) for a in payload["recommended_actions"]],
        )
        return analysis_id


def find_cached(text_hash: str) -> Optional[int]:
    with connect() as conn:
        row = conn.execute(
            "SELECT id FROM analyses WHERE text_hash = ? ORDER BY id DESC LIMIT 1", (text_hash,)
        ).fetchone()
        return row["id"] if row else None


def get_analysis(analysis_id: int) -> Optional[dict]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    if row is None:
        return None
    result = json.loads(row["ai_result"])
    result.update(
        id=row["id"],
        created_at=row["created_at"],
        input_type=row["input_type"],
        original_text=row["original_text"],
        extracted_text=row["extracted_text"],
        risk_level=row["risk_level"],
        confidence=row["confidence"],
        scam_category=row["scam_category"],
        summary=row["summary"],
    )
    return result


def list_analyses(limit: int = 20, offset: int = 0, risk_levels: Optional[list[str]] = None) -> tuple[int, list[dict]]:
    where, params = "", []
    if risk_levels:
        where = f"WHERE risk_level IN ({','.join('?' * len(risk_levels))})"
        params = list(risk_levels)
    with connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) AS n FROM analyses {where}", params).fetchone()["n"]
        rows = conn.execute(
            f"""SELECT id, created_at, input_type, risk_level, confidence, scam_category, summary,
                       substr(COALESCE(extracted_text, original_text), 1, 160) AS preview
                FROM analyses {where} ORDER BY id DESC LIMIT ? OFFSET ?""",
            [*params, limit, offset],
        ).fetchall()
    return total, [dict(r) for r in rows]


def get_stats() -> dict:
    with connect() as conn:
        total = conn.execute("SELECT COUNT(*) AS n FROM analyses").fetchone()["n"]
        dist = {lvl: 0 for lvl in RISK_LEVELS}
        for r in conn.execute("SELECT risk_level, COUNT(*) AS n FROM analyses GROUP BY risk_level"):
            dist[r["risk_level"]] = r["n"]
        cats = conn.execute(
            """SELECT scam_category, COUNT(*) AS n FROM analyses
               WHERE risk_level != 'LOW' GROUP BY scam_category ORDER BY n DESC, scam_category LIMIT 8"""
        ).fetchall()
        sources = {r["input_type"]: r["n"] for r in conn.execute(
            "SELECT input_type, COUNT(*) AS n FROM analyses GROUP BY input_type")}
        recent = conn.execute(
            """SELECT id, created_at, input_type, risk_level, confidence, scam_category, summary
               FROM analyses ORDER BY id DESC LIMIT 5"""
        ).fetchall()
    top_categories = [{"category": r["scam_category"], "count": r["n"]} for r in cats]
    return {
        "total_analyses": total,
        "high_risk": dist["HIGH"],
        "critical": dist["CRITICAL"],
        "most_common_category": top_categories[0]["category"] if top_categories else None,
        "risk_distribution": dist,
        "top_categories": top_categories,
        "by_input_type": sources,
        "recent": [dict(r) for r in recent],
    }
