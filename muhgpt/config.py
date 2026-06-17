"""Configuration loading and runtime settings for MuhGPT."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Settings:
    """Immutable runtime configuration for the MuhGPT agent."""

    api_key: str
    base_url: str = "https://api.muhgpt.com/v1"
    model: str = "muh-chat"
    request_timeout: float = 60.0
    connect_timeout: float = 10.0
    max_retries: int = 4
    backoff_base: float = 1.5
    temperature: float | None = 0.2
    max_tool_rounds: int = 8
    max_history_messages: int = 40
    command_timeout: int = 300
    stream: bool = True
    auto: bool = False
    auto_max_rounds: int = 40
    auto_max_commands: int = 60
    auto_max_installs: int = 8
    auto_wall_clock_s: int = 1200
    auto_max_blocks: int = 5
    auto_max_idle: int = 3
    price_prompt_per_1m: float = 0.0
    price_completion_per_1m: float = 0.0
    reports_dir: Path = Path("reports")

    def __post_init__(self) -> None:
        """Reject out-of-range numeric settings with a clear, named message."""
        minimums = {
            "MUHGPT_MAX_TOOL_ROUNDS": (self.max_tool_rounds, 1),
            "MUHGPT_MAX_RETRIES": (self.max_retries, 0),
            "MUHGPT_MAX_HISTORY_MESSAGES": (self.max_history_messages, 0),
            "MUHGPT_COMMAND_TIMEOUT": (self.command_timeout, 1),
            "MUHGPT_AUTO_MAX_ROUNDS": (self.auto_max_rounds, 1),
            "MUHGPT_AUTO_MAX_COMMANDS": (self.auto_max_commands, 1),
            "MUHGPT_AUTO_MAX_INSTALLS": (self.auto_max_installs, 0),
            "MUHGPT_AUTO_WALLCLOCK_S": (self.auto_wall_clock_s, 1),
            "MUHGPT_AUTO_MAX_BLOCKS": (self.auto_max_blocks, 1),
            "MUHGPT_AUTO_MAX_IDLE": (self.auto_max_idle, 1),
        }
        for name, (value, minimum) in minimums.items():
            if value < minimum:
                raise ConfigError(f"{name} must be >= {minimum} (got {value}).")
        if self.request_timeout <= 0 or self.connect_timeout <= 0:
            raise ConfigError("MUHGPT_REQUEST_TIMEOUT and MUHGPT_CONNECT_TIMEOUT must be positive.")
        if self.price_prompt_per_1m < 0 or self.price_completion_per_1m < 0:
            raise ConfigError("MUHGPT_PRICE_* values must be non-negative.")

    @property
    def chat_completions_url(self) -> str:
        """Full URL of the OpenAI-compatible chat completions endpoint."""
        return f"{self.base_url.rstrip('/')}/chat/completions"


def load_settings(env_file: str | os.PathLike[str] | None = ".env") -> Settings:
    """Load settings from environment variables, optionally seeded by a .env file.

    Args:
        env_file: Path to a dotenv file. Loaded if present and python-dotenv is
            installed; ignored otherwise.

    Returns:
        A fully populated, immutable :class:`Settings` instance.

    Raises:
        ConfigError: If ``MUHGPT_API_KEY`` is not set.
    """
    if load_dotenv is not None and env_file is not None and Path(env_file).exists():
        load_dotenv(env_file)

    api_key = os.getenv("MUHGPT_API_KEY", "").strip()
    if not api_key:
        raise ConfigError(
            "MUHGPT_API_KEY is not set. Copy .env.example to .env and add your key."
        )

    def _float(name: str, default: float) -> float:
        raw = os.getenv(name)
        if not raw:
            return default
        try:
            return float(raw)
        except ValueError:
            raise ConfigError(f"{name} must be a number (got {raw!r}).") from None

    def _int(name: str, default: int) -> int:
        raw = os.getenv(name)
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            raise ConfigError(f"{name} must be an integer (got {raw!r}).") from None

    def _bool(name: str, default: bool) -> bool:
        raw = os.getenv(name)
        if raw is None or raw.strip() == "":
            return default
        return raw.strip().lower() not in {"0", "false", "no", "off"}

    def _opt_float(name: str, default: float | None) -> float | None:
        """Like ``_float`` but lets an explicit empty/``none`` value omit the field."""
        raw = os.getenv(name)
        if raw is None:
            return default
        raw = raw.strip()
        if raw == "" or raw.lower() == "none":
            return None
        try:
            return float(raw)
        except ValueError:
            raise ConfigError(f"{name} must be a number or 'none' (got {raw!r}).") from None

    return Settings(
        api_key=api_key,
        base_url=os.getenv("MUHGPT_BASE_URL", "https://api.muhgpt.com/v1").strip(),
        model=os.getenv("MUHGPT_MODEL", "muh-chat").strip(),
        request_timeout=_float("MUHGPT_REQUEST_TIMEOUT", 60.0),
        connect_timeout=_float("MUHGPT_CONNECT_TIMEOUT", 10.0),
        max_retries=_int("MUHGPT_MAX_RETRIES", 4),
        temperature=_opt_float("MUHGPT_TEMPERATURE", 0.2),
        max_tool_rounds=_int("MUHGPT_MAX_TOOL_ROUNDS", 8),
        max_history_messages=_int("MUHGPT_MAX_HISTORY_MESSAGES", 40),
        command_timeout=_int("MUHGPT_COMMAND_TIMEOUT", 300),
        stream=_bool("MUHGPT_STREAM", True),
        auto=_bool("MUHGPT_AUTO", False),
        auto_max_rounds=_int("MUHGPT_AUTO_MAX_ROUNDS", 40),
        auto_max_commands=_int("MUHGPT_AUTO_MAX_COMMANDS", 60),
        auto_max_installs=_int("MUHGPT_AUTO_MAX_INSTALLS", 8),
        auto_wall_clock_s=_int("MUHGPT_AUTO_WALLCLOCK_S", 1200),
        auto_max_blocks=_int("MUHGPT_AUTO_MAX_BLOCKS", 5),
        auto_max_idle=_int("MUHGPT_AUTO_MAX_IDLE", 3),
        price_prompt_per_1m=_float("MUHGPT_PRICE_PROMPT_PER_1M", 0.0),
        price_completion_per_1m=_float("MUHGPT_PRICE_COMPLETION_PER_1M", 0.0),
        reports_dir=Path(os.getenv("MUHGPT_REPORTS_DIR", "reports")),
    )
