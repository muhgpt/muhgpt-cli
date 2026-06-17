"""Terminal styling for MuhGPT: ANSI colors with auto TTY / NO_COLOR detection.

Pure stdlib — no extra dependency, works under Termux. Colors are emitted only
when the destination is a real terminal (so piping output or writing reports
stays clean). Honours ``NO_COLOR`` / ``MUHGPT_NO_COLOR`` (off) and ``FORCE_COLOR``
(on); ``set_enabled(...)`` lets the CLI force a choice via ``--no-color``.
"""
from __future__ import annotations

import os
import sys

# --- raw SGR codes --------------------------------------------------------
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
ITALIC = "\033[3m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"


def fg(n: int) -> str:
    """256-color foreground escape for palette index ``n``."""
    return f"\033[38;5;{n}m"


_forced: bool | None = None


def set_enabled(value: bool | None) -> None:
    """Force colors on/off, or pass ``None`` to restore auto-detection."""
    global _forced
    _forced = value


def enabled() -> bool:
    """Whether ANSI styling should be emitted right now."""
    if _forced is not None:
        return _forced
    if os.getenv("NO_COLOR") is not None or os.getenv("MUHGPT_NO_COLOR"):
        return False
    if os.getenv("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


def style(text: str, *codes: str) -> str:
    """Wrap ``text`` in the given SGR codes, or return it bare if colors are off."""
    if not codes or not enabled():
        return text
    return f"{''.join(codes)}{text}{RESET}"


# --- semantic helpers -----------------------------------------------------
def success(text: str) -> str:
    return style(text, GREEN, BOLD)


def error(text: str) -> str:
    return style(text, RED, BOLD)


def warn(text: str) -> str:
    return style(text, YELLOW, BOLD)


def info(text: str) -> str:
    return style(text, CYAN)


def dim(text: str) -> str:
    return style(text, DIM)


def accent(text: str) -> str:
    return style(text, MAGENTA, BOLD)


def reasoning(text: str) -> str:
    """Soft italic grey — the model's narrated thinking between tool calls."""
    return style(text, ITALIC, fg(244))


def command(text: str) -> str:
    """Gold + bold — a proposed shell command awaiting approval."""
    return style(text, fg(220), BOLD)


def prompt(text: str) -> str:
    """Bright-cyan bold — interactive input prompts."""
    return style(text, fg(45), BOLD)


# --- banner ---------------------------------------------------------------
_BANNER_ART = [
    r"  __  __ _   _ _   _  ____ ____ _____",
    r" |  \/  | | | | | | |/ ___|  _ \_   _|",
    r" | |\/| | | | | |_| | |  _| |_) || |",
    r" | |  | | |_| |  _  | |_| |  __/ | |",
    r" |_|  |_|\___/|_| |_|\____|_|    |_|",
]
# vertical cyan -> blue gradient across the five art rows
_BANNER_GRADIENT = [51, 45, 39, 33, 27]


def banner(version: str) -> str:
    """Render the startup banner with a gradient and a colored tagline."""
    out = [""]
    for art, color in zip(_BANNER_ART, _BANNER_GRADIENT):
        out.append(style(art, fg(color), BOLD))
    out.append("")
    out.append(
        "   "
        + accent("⚡ pentest & osint assistant")
        + dim("  ·  human-in-the-loop")
        + dim(f"  ·  v{version}")
    )
    out.append("   " + style("─" * 46, fg(238)))
    out.append("")
    return "\n".join(out)
