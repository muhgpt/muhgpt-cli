"""Configuration loading and runtime settings for MuhGPT."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


def user_config_path() -> Path:
    """Path to the persistent user config (``~/.config/muhgpt/.env``).

    Honours ``XDG_CONFIG_HOME``. This is where the first-run setup saves the API
    key so an installed ``muhgpt`` works from any directory without a local
    ``.env`` — the operator never edits a file by hand.
    """
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base).expanduser() / "muhgpt" / ".env"


def save_user_api_key(key: str) -> Path:
    """Persist ``MUHGPT_API_KEY`` to the user config, with 0600 perms. Returns the path.

    Replaces an existing ``MUHGPT_API_KEY`` line and preserves any other lines, so
    re-running setup updates the key in place rather than duplicating it.
    """
    path = user_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    kept = []
    if path.exists():
        kept = [
            ln for ln in path.read_text(encoding="utf-8").splitlines()
            if not ln.strip().startswith("MUHGPT_API_KEY=")
        ]
    kept.append(f"MUHGPT_API_KEY={key}")
    path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)  # a secret — owner read/write only
    except OSError:
        pass
    return path


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
    bidi: str = "auto"
    # Show real remaining credits (from GET /v1/usage) at session start.
    show_balance: bool = True
    auto: bool = False
    # yolo: in autonomous mode, auto-approve the CONFIRM tier too (everything
    # except the destructive denylist and secret-file reads). Opt-in, high-trust.
    yolo: bool = False
    scan_mode: str = "standard"  # quick | standard | deep — shapes the agent's depth
    auto_max_rounds: int = 40
    auto_max_commands: int = 60
    auto_max_installs: int = 8
    auto_wall_clock_s: int = 1200
    auto_max_blocks: int = 5
    auto_max_idle: int = 3
    price_prompt_per_1m: float = 0.0
    price_completion_per_1m: float = 0.0
    reports_dir: Path = Path("reports")
    # --- MCP client (off by default; opt-in, never auto-installs/launches servers) ---
    mcp_enabled: bool = False
    mcp_config_path: Path | None = None
    # When MCP is enabled, also load the bundled curated free servers (search/OSINT/
    # fetch). User config from mcp_config_path is merged on top (and wins by name).
    mcp_use_defaults: bool = True
    mcp_timeout: float = 30.0
    # Namespaced tool names (mcp__<server>__<tool>) the operator trusts to auto-run
    # in --auto mode. Empty by default: every MCP call falls to a human CONFIRM.
    mcp_auto_tools: tuple[str, ...] = ()
    # Extra read-only recon binaries the operator adds to the auto-run allowlist
    # (on top of guard.SAFE_RECON). Sanitized by guard.sanitize_extra_recon — names
    # in guard._NEVER_RECON (shells/interpreters/curl/…) are rejected. The denylist
    # and metacharacter gates still run first, so this can never auto-run a
    # destructive or chained command. Empty by default.
    extra_safe_recon: tuple[str, ...] = ()
    # --- Research sub-agent (off by default; OSINT search delegate, relace-search-style) ---
    # When active, the lead agent gains a `research` tool that delegates a question to a
    # focused search sub-agent. The sub-agent runs on research_model (falling back to the
    # main model) at research_base_url/research_api_key (falling back to the main endpoint).
    research_enabled: bool = False
    research_model: str = ""
    research_base_url: str = ""
    research_api_key: str = ""
    research_max_rounds: int = 12
    research_max_commands: int = 20
    research_wall_clock_s: int = 300

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
            "MUHGPT_RESEARCH_MAX_ROUNDS": (self.research_max_rounds, 1),
            "MUHGPT_RESEARCH_MAX_COMMANDS": (self.research_max_commands, 1),
            "MUHGPT_RESEARCH_WALLCLOCK_S": (self.research_wall_clock_s, 1),
        }
        for name, (value, minimum) in minimums.items():
            if value < minimum:
                raise ConfigError(f"{name} must be >= {minimum} (got {value}).")
        if self.request_timeout <= 0 or self.connect_timeout <= 0:
            raise ConfigError("MUHGPT_REQUEST_TIMEOUT and MUHGPT_CONNECT_TIMEOUT must be positive.")
        if self.price_prompt_per_1m < 0 or self.price_completion_per_1m < 0:
            raise ConfigError("MUHGPT_PRICE_* values must be non-negative.")
        if self.mcp_timeout <= 0:
            raise ConfigError("MUHGPT_MCP_TIMEOUT must be positive.")
        if self.bidi not in ("auto", "on", "off"):
            raise ConfigError(
                f"MUHGPT_BIDI must be one of auto/on/off (got {self.bidi!r})."
            )
        if self.scan_mode not in ("quick", "standard", "deep"):
            raise ConfigError(
                f"MUHGPT_SCAN_MODE must be one of quick/standard/deep (got {self.scan_mode!r})."
            )

    @property
    def chat_completions_url(self) -> str:
        """Full URL of the OpenAI-compatible chat completions endpoint."""
        return f"{self.base_url.rstrip('/')}/chat/completions"

    @property
    def models_url(self) -> str:
        """Full URL of the models list endpoint (GET /v1/models)."""
        return f"{self.base_url.rstrip('/')}/models"

    @property
    def usage_url(self) -> str:
        """Full URL of the usage/credit-balance endpoint (GET /v1/usage)."""
        return f"{self.base_url.rstrip('/')}/usage"

    @property
    def research_active(self) -> bool:
        """Whether the research sub-agent should be wired up.

        On when explicitly enabled, or implicitly when a dedicated research model
        is named (naming a model is intent enough to turn the feature on).
        """
        return self.research_enabled or bool(self.research_model)

    def research_client_settings(self) -> Settings:
        """A Settings clone pointed at the research model/endpoint.

        Each field falls back to the main configuration when unset, so the
        feature works out of the box on the main model and only diverges where
        the operator overrode it (e.g. a Relace Search endpoint via OpenRouter).
        """
        from dataclasses import replace

        return replace(
            self,
            model=self.research_model or self.model,
            base_url=self.research_base_url or self.base_url,
            api_key=self.research_api_key or self.api_key,
        )


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
    if load_dotenv is not None:
        # A local .env (cwd) wins; the persistent user config fills in anything it
        # didn't set. load_dotenv never overrides an already-set var, so real env
        # vars > cwd .env > ~/.config/muhgpt/.env.
        if env_file is not None and Path(env_file).exists():
            load_dotenv(env_file)
        user_cfg = user_config_path()
        if user_cfg.exists():
            load_dotenv(user_cfg)

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

    def _csv(name: str) -> tuple[str, ...]:
        """Parse a comma/whitespace-separated env var into a tuple (frozen-safe)."""
        raw = os.getenv(name, "")
        return tuple(t.strip() for t in re.split(r"[\s,]+", raw) if t.strip())

    def _opt_path(name: str) -> Path | None:
        """An optional filesystem path; ``None`` when the var is unset/empty."""
        raw = os.getenv(name)
        raw = raw.strip() if raw else ""
        return Path(raw).expanduser() if raw else None

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
        bidi=os.getenv("MUHGPT_BIDI", "auto").strip().lower() or "auto",
        show_balance=_bool("MUHGPT_SHOW_BALANCE", True),
        auto=_bool("MUHGPT_AUTO", False),
        yolo=_bool("MUHGPT_AUTO_YOLO", False),
        scan_mode=os.getenv("MUHGPT_SCAN_MODE", "standard").strip().lower() or "standard",
        auto_max_rounds=_int("MUHGPT_AUTO_MAX_ROUNDS", 40),
        auto_max_commands=_int("MUHGPT_AUTO_MAX_COMMANDS", 60),
        auto_max_installs=_int("MUHGPT_AUTO_MAX_INSTALLS", 8),
        auto_wall_clock_s=_int("MUHGPT_AUTO_WALLCLOCK_S", 1200),
        auto_max_blocks=_int("MUHGPT_AUTO_MAX_BLOCKS", 5),
        auto_max_idle=_int("MUHGPT_AUTO_MAX_IDLE", 3),
        price_prompt_per_1m=_float("MUHGPT_PRICE_PROMPT_PER_1M", 0.0),
        price_completion_per_1m=_float("MUHGPT_PRICE_COMPLETION_PER_1M", 0.0),
        reports_dir=Path(os.getenv("MUHGPT_REPORTS_DIR", "reports")),
        mcp_enabled=_bool("MUHGPT_MCP_ENABLED", False),
        mcp_config_path=_opt_path("MUHGPT_MCP_CONFIG"),
        mcp_use_defaults=_bool("MUHGPT_MCP_DEFAULTS", True),
        mcp_timeout=_float("MUHGPT_MCP_TIMEOUT", 30.0),
        mcp_auto_tools=_csv("MUHGPT_MCP_AUTO_TOOLS"),
        extra_safe_recon=_csv("MUHGPT_EXTRA_SAFE_RECON"),
        research_enabled=_bool("MUHGPT_RESEARCH_ENABLED", False),
        research_model=os.getenv("MUHGPT_RESEARCH_MODEL", "").strip(),
        research_base_url=os.getenv("MUHGPT_RESEARCH_BASE_URL", "").strip(),
        research_api_key=os.getenv("MUHGPT_RESEARCH_API_KEY", "").strip(),
        research_max_rounds=_int("MUHGPT_RESEARCH_MAX_ROUNDS", 12),
        research_max_commands=_int("MUHGPT_RESEARCH_MAX_COMMANDS", 20),
        research_wall_clock_s=_int("MUHGPT_RESEARCH_WALLCLOCK_S", 300),
    )
