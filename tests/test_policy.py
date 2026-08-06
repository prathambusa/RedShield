import tempfile
from pathlib import Path

from app.detectors.classifier import ClassifierVerdict
from app.detectors.rules import Hit
from app.policy.allowlist import load_allowlist
from app.policy.blocklist import load_blocklist
from app.policy.risk import aggregate


def _hit(rule_id: str, taxonomy: str, severity: int) -> Hit:
    return Hit(
        rule_id=rule_id,
        taxonomy=taxonomy,
        severity=severity,
        matched_span="x",
        reason="test",
    )


def test_hard_block_on_severity_9() -> None:
    v = aggregate([_hit("R1", "instruction_override", 9)], None)
    assert v.action == "block"
    assert v.score == 1.0


def test_hard_block_on_high_confidence_malicious_classifier() -> None:
    cv = ClassifierVerdict("malicious", 0.95, "bad")
    v = aggregate([], cv)
    assert v.action == "block"


def test_allow_on_empty_signals() -> None:
    v = aggregate([], None)
    assert v.action == "allow"
    assert v.score == 0.0


def test_review_on_mid_score() -> None:
    # sev 6 hit -> rule_score = 6/15 = 0.4 → review band (>=0.4, <0.7)
    v = aggregate([_hit("R1", "refusal_bypass", 6)], None)
    assert v.action == "review"


def test_block_on_aggregated_score() -> None:
    # two sev-8 hits -> 16/15 capped to 1.0 -> block
    v = aggregate(
        [_hit("R1", "jailbreak", 8), _hit("R2", "jailbreak", 8)],
        None,
    )
    assert v.action == "block"


def test_blocklist_short_circuits() -> None:
    v = aggregate([], None, blocklist_match="badphrase")
    assert v.action == "block"
    assert any("blocklist" in r for r in v.reasons)


def test_allowlist_short_circuits() -> None:
    v = aggregate([_hit("R1", "jailbreak", 9)], None, allowlisted=True)
    assert v.action == "allow"


def test_classifier_benign_doesnt_raise_score() -> None:
    cv = ClassifierVerdict("benign", 0.99, "ok")
    v = aggregate([], cv)
    assert v.action == "allow"


def test_custom_thresholds() -> None:
    v = aggregate(
        [_hit("R1", "refusal_bypass", 5)],
        None,
        block_threshold=0.2,
        review_threshold=0.1,
    )
    assert v.action == "block"


def test_allowlist_yaml_roundtrip() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "a.yaml"
        p.write_text("patterns:\n  - '^order #\\d+$'\n")
        al = load_allowlist(p)
        assert al.matches("order #12345")
        assert not al.matches("hello")


def test_blocklist_yaml_roundtrip() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "b.yaml"
        p.write_text("patterns:\n  - 'kill -9'\n  - 'DROP TABLE'\n")
        bl = load_blocklist(p)
        assert bl.match("please run kill -9 now") == "kill -9"
        assert bl.match("normal text") is None


def test_missing_list_file_yields_empty() -> None:
    al = load_allowlist("/nonexistent/path.yaml")
    assert not al.matches("anything")
    bl = load_blocklist("/nonexistent/path.yaml")
    assert bl.match("anything") is None
