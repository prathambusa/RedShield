from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ChatTurn(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class ChatRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)
    message: str = Field(..., min_length=1, max_length=8000)
    history: list[ChatTurn] = Field(default_factory=list)
    defended: bool = Field(default=True, description="If False, bypass defenders (raw path).")


class VerdictModel(BaseModel):
    action: Literal["allow", "review", "block"]
    score: float
    reasons: list[str] = Field(default_factory=list)


class ChatResponse(BaseModel):
    reply: str
    verdict: VerdictModel
    latency_ms: int
    output_leaked_system_prompt: bool = False


class HealthResponse(BaseModel):
    status: str
    version: str


class StatsResponse(BaseModel):
    window_seconds: int | None
    counts: dict[str, int]
    recent: list[dict]
