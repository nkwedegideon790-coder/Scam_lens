import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend import main  # noqa: E402
from backend.analyzer import AIProvider  # noqa: E402


class FakeProvider(AIProvider):
    """Test double: returns canned model output. Never used by the real app."""
    name, model = "fake", "fake-1"

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def complete(self, system, user):
        self.calls += 1
        return self.responses[min(self.calls - 1, len(self.responses) - 1)]


def ai_json(level="HIGH", confidence=91, category="Phishing / Impersonation", flags=None, **extra):
    data = {
        "risk_level": level, "confidence": confidence, "scam_category": category,
        "summary": "The message contains several indicators commonly associated with phishing.",
        "red_flags": flags if flags is not None else [],
        "recommended_actions": ["Do not click the link."],
        "verification_steps": ["Check the organization's official website."],
    }
    data.update(extra)
    return json.dumps(data)


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMLENS_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("SCAMLENS_RATE_LIMIT_PER_MIN", "0")
    monkeypatch.setenv("SCAMLENS_API_TOKEN", "")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    main._limiter.reset()


@pytest.fixture
def make_client():
    clients = []

    def _make(*responses):
        provider = FakeProvider(responses or [ai_json()])
        main.app.dependency_overrides[main.get_provider] = lambda: provider
        client = TestClient(main.app)
        client.__enter__()
        clients.append(client)
        return client, provider

    yield _make
    for c in clients:
        c.__exit__(None, None, None)
    main.app.dependency_overrides.clear()
