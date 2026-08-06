from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.gateway.schemas import (
    ChatRequest,
    ChatResponse,
    ChatTurn,
    HealthResponse,
    StatsResponse,
    VerdictModel,
)


def test_chat_request_minimum_fields() -> None:
    req = ChatRequest(session_id="s", message="hello")
    assert req.defended is True
    assert req.history == []


def test_chat_request_rejects_empty_message() -> None:
    with pytest.raises(ValidationError):
        ChatRequest(session_id="s", message="")


def test_chat_request_rejects_oversized_message() -> None:
    with pytest.raises(ValidationError):
        ChatRequest(session_id="s", message="x" * 8001)


def test_chat_request_rejects_empty_session_id() -> None:
    with pytest.raises(ValidationError):
        ChatRequest(session_id="", message="hi")


def test_chat_request_history_role_validation() -> None:
    ok = ChatRequest(
        session_id="s",
        message="m",
        history=[
            ChatTurn(role="user", content="prev"),
            ChatTurn(role="assistant", content="answer"),
        ],
    )
    assert len(ok.history) == 2
    with pytest.raises(ValidationError):
        ChatTurn(role="system", content="x")  # type: ignore[arg-type]


def test_verdict_action_must_be_known() -> None:
    VerdictModel(action="allow", score=0.0)
    VerdictModel(action="review", score=0.5)
    VerdictModel(action="block", score=1.0)
    with pytest.raises(ValidationError):
        VerdictModel(action="explode", score=0.5)  # type: ignore[arg-type]


def test_chat_response_serializes_round_trip() -> None:
    resp = ChatResponse(
        reply="ok",
        verdict=VerdictModel(action="allow", score=0.0, reasons=["x"]),
        latency_ms=12,
    )
    js = resp.model_dump()
    again = ChatResponse(**js)
    assert again.reply == "ok"
    assert again.verdict.action == "allow"


def test_health_and_stats_models() -> None:
    h = HealthResponse(status="ok", version="1.2.3")
    assert h.status == "ok"
    s = StatsResponse(window_seconds=None, counts={"allow": 1}, recent=[])
    assert s.window_seconds is None
    assert s.counts["allow"] == 1
