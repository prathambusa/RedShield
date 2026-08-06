from __future__ import annotations

import importlib

from app import config as config_mod


def test_get_settings_is_cached_singleton() -> None:
    config_mod.reset_settings()
    a = config_mod.get_settings()
    b = config_mod.get_settings()
    assert a is b


def test_reset_settings_creates_fresh_instance() -> None:
    config_mod.reset_settings()
    a = config_mod.get_settings()
    config_mod.reset_settings()
    b = config_mod.get_settings()
    assert a is not b


def test_environment_overrides_thresholds(monkeypatch) -> None:
    monkeypatch.setenv("REDSHIELD_BLOCK_THRESHOLD", "0.55")
    monkeypatch.setenv("REDSHIELD_REVIEW_THRESHOLD", "0.25")
    monkeypatch.setenv("REDSHIELD_CLASSIFIER_ENABLED", "false")
    config_mod.reset_settings()
    s = config_mod.get_settings()
    assert s.block_threshold == 0.55
    assert s.review_threshold == 0.25
    assert s.classifier_enabled is False
    config_mod.reset_settings()


def test_default_paths_resolve_inside_repo() -> None:
    config_mod.reset_settings()
    s = config_mod.get_settings()
    assert s.patterns_file.name == "patterns.yaml"
    assert s.allowlist_file.name == "allowlist.yaml"
    assert s.blocklist_file.name == "blocklist.yaml"
    assert s.patterns_file.exists()


def test_module_reimport_keeps_singleton_isolated() -> None:
    config_mod.reset_settings()
    s_before = config_mod.get_settings()
    importlib.reload(config_mod)
    config_mod.reset_settings()
    s_after = config_mod.get_settings()
    assert s_before is not s_after
