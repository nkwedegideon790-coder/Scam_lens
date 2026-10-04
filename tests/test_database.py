import sqlite3

import pytest

from backend import database as db


def payload(level="HIGH", category="Phishing", text="hello"):
    return {
        "input_type": "message", "original_text": text, "extracted_text": None, "risk_level": level,
        "confidence": 80, "scam_category": category, "summary": "s",
        "red_flags": [{"indicator": "Urgency", "evidence": "now", "explanation": "e"}],
        "recommended_actions": ["a1", "a2"],
    }


def test_init_is_idempotent_and_save_get_roundtrip():
    db.init_db(); db.init_db()
    aid = db.save_analysis(payload(), "h1")
    got = db.get_analysis(aid)
    assert got["id"] == aid and got["risk_level"] == "HIGH" and got["red_flags"][0]["indicator"] == "Urgency"
    with db.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM red_flags WHERE analysis_id=?", (aid,)).fetchone()[0] == 1
        assert c.execute("SELECT COUNT(*) FROM recommended_actions WHERE analysis_id=?", (aid,)).fetchone()[0] == 2


def test_foreign_keys_enforced_and_cascade():
    db.init_db()
    with pytest.raises(sqlite3.IntegrityError):
        with db.connect() as c:
            c.execute("INSERT INTO red_flags (analysis_id, indicator, evidence, explanation) VALUES (999,'a','b','c')")
    aid = db.save_analysis(payload(), "h2")
    with db.connect() as c:
        c.execute("DELETE FROM analyses WHERE id=?", (aid,))
        assert c.execute("SELECT COUNT(*) FROM red_flags").fetchone()[0] == 0


def test_cache_lookup_missing_and_listing_filters():
    db.init_db()
    assert db.get_analysis(12345) is None and db.find_cached("nope") is None
    db.save_analysis(payload("LOW", "None"), "a"); db.save_analysis(payload("CRITICAL"), "b"); db.save_analysis(payload("HIGH"), "c")
    assert db.find_cached("b") is not None
    total, items = db.list_analyses(limit=2)
    assert total == 3 and len(items) == 2 and items[0]["id"] > items[1]["id"]
    assert db.list_analyses(risk_levels=["HIGH", "CRITICAL"])[0] == 2


def test_stats_empty_and_populated():
    db.init_db()
    s = db.get_stats()
    assert s["total_analyses"] == 0 and s["most_common_category"] is None and sum(s["risk_distribution"].values()) == 0
    db.save_analysis(payload("HIGH", "Phishing"), "1"); db.save_analysis(payload("CRITICAL", "Phishing"), "2")
    db.save_analysis(payload("LOW", "No scam category identified"), "3")
    s = db.get_stats()
    assert (s["total_analyses"], s["high_risk"], s["critical"]) == (3, 1, 1)
    assert s["most_common_category"] == "Phishing" and len(s["recent"]) == 3
