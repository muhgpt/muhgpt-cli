"""Tests for configuration loading and Settings."""
from __future__ import annotations

import pytest

from muhgpt.config import ConfigError, Settings, load_settings


def test_missing_key_raises(monkeypatch):
    monkeypatch.delenv("MUHGPT_API_KEY", raising=False)
    with pytest.raises(ConfigError):
        load_settings(env_file=None)


def test_reads_env_overrides(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    monkeypatch.setenv("MUHGPT_MODEL", "custom-model")
    monkeypatch.setenv("MUHGPT_TEMPERATURE", "0.7")
    monkeypatch.setenv("MUHGPT_MAX_HISTORY_MESSAGES", "12")
    settings = load_settings(env_file=None)
    assert settings.api_key == "abc"
    assert settings.model == "custom-model"
    assert settings.temperature == 0.7
    assert settings.max_history_messages == 12


def test_temperature_can_be_disabled(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    monkeypatch.setenv("MUHGPT_TEMPERATURE", "none")
    assert load_settings(env_file=None).temperature is None


def test_stream_defaults_on_and_can_be_disabled(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    monkeypatch.delenv("MUHGPT_STREAM", raising=False)
    assert load_settings(env_file=None).stream is True
    for off in ("0", "false", "no", "off", "FALSE"):
        monkeypatch.setenv("MUHGPT_STREAM", off)
        assert load_settings(env_file=None).stream is False


def test_autonomous_settings_defaults_and_overrides(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    for var in ("MUHGPT_AUTO", "MUHGPT_AUTO_MAX_ROUNDS", "MUHGPT_AUTO_MAX_IDLE"):
        monkeypatch.delenv(var, raising=False)
    s = load_settings(env_file=None)
    assert s.auto is False
    assert s.auto_max_rounds == 40
    assert s.auto_max_idle == 3

    monkeypatch.setenv("MUHGPT_AUTO", "1")
    monkeypatch.setenv("MUHGPT_AUTO_MAX_ROUNDS", "12")
    monkeypatch.setenv("MUHGPT_AUTO_MAX_IDLE", "5")
    s = load_settings(env_file=None)
    assert s.auto is True
    assert s.auto_max_rounds == 12
    assert s.auto_max_idle == 5


def test_chat_completions_url_strips_trailing_slash():
    settings = Settings(api_key="k", base_url="https://host/v1/")
    assert settings.chat_completions_url == "https://host/v1/chat/completions"


def test_out_of_range_settings_are_rejected(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    monkeypatch.setenv("MUHGPT_AUTO_MAX_ROUNDS", "0")
    with pytest.raises(ConfigError):
        load_settings(env_file=None)
    monkeypatch.delenv("MUHGPT_AUTO_MAX_ROUNDS")
    monkeypatch.setenv("MUHGPT_COMMAND_TIMEOUT", "0")
    with pytest.raises(ConfigError):
        load_settings(env_file=None)


def test_direct_construction_validates():
    with pytest.raises(ConfigError):
        Settings(api_key="k", auto_max_idle=0)
    with pytest.raises(ConfigError):
        Settings(api_key="k", max_retries=-1)
    # valid edges are accepted (0 allowed where it means "unlimited"/"none")
    Settings(api_key="k", max_history_messages=0, auto_max_installs=0)


def test_malformed_numeric_env_raises_clean_config_error(monkeypatch):
    # A non-numeric value for a numeric var must surface as ConfigError (which the
    # CLI catches and prints cleanly), not an uncaught ValueError traceback.
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    for var, bad in (
        ("MUHGPT_MAX_RETRIES", "foo"),
        ("MUHGPT_REQUEST_TIMEOUT", "abc"),
        ("MUHGPT_TEMPERATURE", "warm"),
        ("MUHGPT_PRICE_PROMPT_PER_1M", "free"),
    ):
        monkeypatch.setenv(var, bad)
        with pytest.raises(ConfigError) as exc:
            load_settings(env_file=None)
        assert var in str(exc.value)  # the message names the offending variable
        monkeypatch.delenv(var)


def test_price_settings_default_zero_and_parse(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    monkeypatch.delenv("MUHGPT_PRICE_PROMPT_PER_1M", raising=False)
    assert load_settings(env_file=None).price_prompt_per_1m == 0.0
    monkeypatch.setenv("MUHGPT_PRICE_PROMPT_PER_1M", "3.5")
    monkeypatch.setenv("MUHGPT_PRICE_COMPLETION_PER_1M", "10")
    s = load_settings(env_file=None)
    assert s.price_prompt_per_1m == 3.5
    assert s.price_completion_per_1m == 10.0
