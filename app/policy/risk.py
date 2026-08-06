from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from app.config import get_settings
from app.detectors.classifier import ClassifierVerdict
from app.detectors.rules import Hit

HARD_BLOCK_SEVERITY = 9
HARD_BLOCK_CLASSIFIER_CONFIDENCE = 0.85


@dataclass
class Verdict:
    action: str  # "allow" | "review" | "block"
    score: float  # 0.0–1.0
    reasons: list[str] = field(default_factory=list)
    rule_hits: list[Hit] = field(default_factory=list)
    classifier: ClassifierVerdict | None = None


def aggregate(
    rule_hits: Sequence[Hit],
    classifier_verdict: ClassifierVerdict | None,
    *,
    block_threshold: float | None = None,
    review_threshold: float | None = None,
    allowlisted: bool = False,
    blocklist_match: str | None = None,
) -> Verdict:
    settings = get_settings()
    block_threshold = settings.block_threshold if block_threshold is None else block_threshold
    review_threshold = settings.review_threshold if review_threshold is None else review_threshold

    hits = list(rule_hits)
    reasons: list[str] = []

    if blocklist_match is not None:
        reasons.append(f"blocklist_match:{blocklist_match!r}")
        return Verdict(
            action="block",
            score=1.0,
            reasons=reasons,
            rule_hits=hits,
            classifier=classifier_verdict,
        )

    if allowlisted:
        reasons.append("allowlisted")
        return Verdict(
            action="allow",
            score=0.0,
            reasons=reasons,
            rule_hits=hits,
            classifier=classifier_verdict,
        )

    hard_hits = [h for h in hits if h.severity >= HARD_BLOCK_SEVERITY]
    if hard_hits:
        reasons.extend(f"rule:{h.rule_id}({h.taxonomy},sev={h.severity})" for h in hard_hits)
        return Verdict(
            action="block",
            score=1.0,
            reasons=reasons,
            rule_hits=hits,
            classifier=classifier_verdict,
        )

    if (
        classifier_verdict
        and classifier_verdict.verdict == "malicious"
        and classifier_verdict.confidence >= HARD_BLOCK_CLASSIFIER_CONFIDENCE
    ):
        reasons.append(
            f"classifier:malicious(conf={classifier_verdict.confidence:.2f}):{classifier_verdict.reason}"
        )
        return Verdict(
            action="block",
            score=classifier_verdict.confidence,
            reasons=reasons,
            rule_hits=hits,
            classifier=classifier_verdict,
        )

    # Divisor 10 → single sev-7 hit crosses the 0.7 block threshold; sev-6 lands in review.
    rule_score = min(1.0, sum(h.severity for h in hits) / 10.0) if hits else 0.0
    if classifier_verdict and classifier_verdict.verdict != "benign":
        cls_score = classifier_verdict.confidence
    else:
        cls_score = 0.0
    score = max(rule_score, cls_score)

    if hits:
        reasons.extend(f"rule:{h.rule_id}({h.taxonomy},sev={h.severity})" for h in hits)
    if classifier_verdict:
        reasons.append(
            f"classifier:{classifier_verdict.verdict}(conf={classifier_verdict.confidence:.2f})"
        )

    if score >= block_threshold:
        action = "block"
    elif score >= review_threshold:
        action = "review"
    else:
        action = "allow"

    return Verdict(
        action=action,
        score=score,
        reasons=reasons,
        rule_hits=hits,
        classifier=classifier_verdict,
    )
