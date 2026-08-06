from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

from app.audit import AuditLog, default_audit_log
from app.config import Settings, get_settings
from app.detectors.classifier import LLMClassifier, default_classifier
from app.detectors.output_filter import OutputFilter, default_output_filter
from app.detectors.rules import RuleMatcher, default_matcher
from app.policy.allowlist import Allowlist, load_allowlist
from app.policy.blocklist import Blocklist, load_blocklist


class ChatBackend(Protocol):
    def __call__(self, *, system: str, messages: list[dict]) -> str: ...


@dataclass
class AppDeps:
    settings: Settings
    matcher: RuleMatcher
    classifier: LLMClassifier | None
    output_filter: OutputFilter
    allowlist: Allowlist
    blocklist: Blocklist
    audit: AuditLog
    chat_backend: ChatBackend


def _openai_backend() -> ChatBackend:
    from app.llm.openai_client import default_client

    settings = get_settings()

    def backend(*, system: str, messages: list[dict]) -> str:
        full = [{"role": "system", "content": system}] + messages
        return default_client().chat(model=settings.chat_model, messages=full, temperature=0.7)

    return backend


def build_default_deps() -> AppDeps:
    settings = get_settings()
    return AppDeps(
        settings=settings,
        matcher=default_matcher(),
        classifier=default_classifier() if settings.classifier_enabled else None,
        output_filter=default_output_filter(),
        allowlist=load_allowlist(settings.allowlist_file),
        blocklist=load_blocklist(settings.blocklist_file),
        audit=default_audit_log(),
        chat_backend=_openai_backend(),
    )


_deps: AppDeps | None = None


def get_deps() -> AppDeps:
    global _deps
    if _deps is None:
        _deps = build_default_deps()
    return _deps


def set_deps(deps: AppDeps) -> None:
    global _deps
    _deps = deps


def reset_deps() -> None:
    global _deps
    _deps = None
