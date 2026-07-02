"""Tests for configuration loading and Settings."""
from __future__ import annotations

import pytest

from muhgpt.config import ConfigError, Settings, load_settings


def test_missing_key_raises(monkeypatch):
    monkeypatch.delenv("MUHGPT_API_KEY", raising=False)
    with pytest.raises(ConfigError):
        load_settings(env_file=None)


# --- persistent user config (first-run key setup) --------------------------
def test_user_config_path_honours_xdg(monkeypatch, tmp_path):
    from muhgpt.config import user_config_path

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert user_config_path() == tmp_path / "muhgpt" / ".env"


def test_save_user_api_key_writes_replaces_and_locks_perms(monkeypatch, tmp_path):
    import os
    import stat

    from muhgpt.config import save_user_api_key, user_config_path

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    path = save_user_api_key("mghp_abc")
    assert path == user_config_path()
    assert "MUHGPT_API_KEY=mghp_abc" in path.read_text()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600  # secret: owner-only

    save_user_api_key("mghp_xyz")  # replace in place, no duplicate line
    text = path.read_text()
    assert "mghp_xyz" in text and "mghp_abc" not in text
    assert text.count("MUHGPT_API_KEY=") == 1


def test_load_settings_reads_saved_user_config(monkeypatch, tmp_path):
    from muhgpt.config import save_user_api_key

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("MUHGPT_API_KEY", raising=False)
    save_user_api_key("mghp_fromconfig")
    # no cwd .env, no env var -> the key must come from ~/.config/muhgpt/.env
    assert load_settings(env_file=None).api_key == "mghp_fromconfig"


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


def test_mcp_settings_default_off(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    settings = load_settings(env_file=None)
    assert settings.mcp_enabled is False
    assert settings.mcp_config_path is None
    assert settings.mcp_timeout == 30.0
    assert settings.mcp_auto_tools == ()


def test_mcp_settings_from_env(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    monkeypatch.setenv("MUHGPT_MCP_ENABLED", "1")
    monkeypatch.setenv("MUHGPT_MCP_CONFIG", "~/servers.json")
    monkeypatch.setenv("MUHGPT_MCP_TIMEOUT", "12.5")
    monkeypatch.setenv("MUHGPT_MCP_AUTO_TOOLS", "mcp__a__x, mcp__b__y mcp__c__z")
    settings = load_settings(env_file=None)
    assert settings.mcp_enabled is True
    assert str(settings.mcp_config_path).endswith("servers.json")
    assert settings.mcp_timeout == 12.5
    assert settings.mcp_auto_tools == ("mcp__a__x", "mcp__b__y", "mcp__c__z")


def test_mcp_timeout_must_be_positive(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    monkeypatch.setenv("MUHGPT_MCP_TIMEOUT", "0")
    with pytest.raises(ConfigError):
        load_settings(env_file=None)


def test_yolo_defaults_off_and_reads_env(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    assert load_settings(env_file=None).yolo is False
    monkeypatch.setenv("MUHGPT_AUTO_YOLO", "1")
    assert load_settings(env_file=None).yolo is True


def test_mcp_use_defaults_on_unless_disabled(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    assert load_settings(env_file=None).mcp_use_defaults is True
    monkeypatch.setenv("MUHGPT_MCP_DEFAULTS", "0")
    assert load_settings(env_file=None).mcp_use_defaults is False


def test_scan_mode_default_and_validation(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    assert load_settings(env_file=None).scan_mode == "standard"
    monkeypatch.setenv("MUHGPT_SCAN_MODE", "DEEP")
    assert load_settings(env_file=None).scan_mode == "deep"  # normalized
    monkeypatch.setenv("MUHGPT_SCAN_MODE", "bogus")
    with pytest.raises(ConfigError):
        load_settings(env_file=None)


def test_stream_defaults_on_and_can_be_disabled(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    monkeypatch.delenv("MUHGPT_STREAM", raising=False)
    assert load_settings(env_file=None).stream is True
    for off in ("0", "false", "no", "off", "FALSE"):
        monkeypatch.setenv("MUHGPT_STREAM", off)
        assert load_settings(env_file=None).stream is False


def test_bidi_defaults_auto_and_accepts_choices(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    monkeypatch.delenv("MUHGPT_BIDI", raising=False)
    assert load_settings(env_file=None).bidi == "auto"
    for value in ("on", "OFF", "Auto"):
        monkeypatch.setenv("MUHGPT_BIDI", value)
        assert load_settings(env_file=None).bidi == value.lower()


def test_bidi_rejects_unknown_value(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    monkeypatch.setenv("MUHGPT_BIDI", "yes")
    with pytest.raises(ConfigError):
        load_settings(env_file=None)


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


def test_models_and_usage_urls_derive_from_base():
    s = Settings(api_key="k", base_url="https://api.muhgpt.com/v1")
    assert s.models_url == "https://api.muhgpt.com/v1/models"
    assert s.usage_url == "https://api.muhgpt.com/v1/usage"
    s2 = Settings(api_key="k", base_url="https://host/v1/")  # trailing slash normalized
    assert s2.models_url == "https://host/v1/models"
    assert s2.usage_url == "https://host/v1/usage"


def test_show_balance_default_and_env(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    monkeypatch.delenv("MUHGPT_SHOW_BALANCE", raising=False)
    assert load_settings(env_file=None).show_balance is True
    monkeypatch.setenv("MUHGPT_SHOW_BALANCE", "0")
    assert load_settings(env_file=None).show_balance is False


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


def test_extra_safe_recon_default_and_env(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    monkeypatch.delenv("MUHGPT_EXTRA_SAFE_RECON", raising=False)
    assert load_settings(env_file=None).extra_safe_recon == ()
    monkeypatch.setenv("MUHGPT_EXTRA_SAFE_RECON", "gobuster, ffuf  shodan-cli")
    assert load_settings(env_file=None).extra_safe_recon == ("gobuster", "ffuf", "shodan-cli")


def test_research_settings_default_off(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    s = load_settings(env_file=None)
    assert s.research_enabled is False
    assert s.research_model == ""
    assert s.research_active is False
    assert s.research_max_rounds == 12
    assert s.research_max_commands == 20
    assert s.research_wall_clock_s == 300


def test_research_active_when_model_named(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    monkeypatch.setenv("MUHGPT_RESEARCH_MODEL", "relace-search")
    s = load_settings(env_file=None)
    assert s.research_active is True  # naming a model implies enablement
    assert s.research_model == "relace-search"


def test_research_active_via_enable_flag(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    monkeypatch.setenv("MUHGPT_RESEARCH_ENABLED", "1")
    assert load_settings(env_file=None).research_active is True


def test_research_client_settings_falls_back_to_main(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "mainkey")
    monkeypatch.setenv("MUHGPT_RESEARCH_MODEL", "rsearch")
    s = load_settings(env_file=None)
    rc = s.research_client_settings()
    assert rc.model == "rsearch"
    assert rc.api_key == "mainkey"      # unset research key -> main key
    assert rc.base_url == s.base_url     # unset research base -> main base


def test_research_client_settings_separate_provider(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "mainkey")
    monkeypatch.setenv("MUHGPT_RESEARCH_MODEL", "rsearch")
    monkeypatch.setenv("MUHGPT_RESEARCH_BASE_URL", "https://openrouter.ai/api/v1")
    monkeypatch.setenv("MUHGPT_RESEARCH_API_KEY", "orkey")
    rc = load_settings(env_file=None).research_client_settings()
    assert rc.base_url == "https://openrouter.ai/api/v1"
    assert rc.api_key == "orkey"
    assert rc.chat_completions_url == "https://openrouter.ai/api/v1/chat/completions"


def test_research_bounds_validation(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    monkeypatch.setenv("MUHGPT_RESEARCH_MAX_ROUNDS", "0")
    with pytest.raises(ConfigError):
        load_settings(env_file=None)


def test_price_settings_default_zero_and_parse(monkeypatch):
    monkeypatch.setenv("MUHGPT_API_KEY", "abc")
    monkeypatch.delenv("MUHGPT_PRICE_PROMPT_PER_1M", raising=False)
    assert load_settings(env_file=None).price_prompt_per_1m == 0.0
    monkeypatch.setenv("MUHGPT_PRICE_PROMPT_PER_1M", "3.5")
    monkeypatch.setenv("MUHGPT_PRICE_COMPLETION_PER_1M", "10")
    s = load_settings(env_file=None)
    assert s.price_prompt_per_1m == 3.5
    assert s.price_completion_per_1m == 10.0
