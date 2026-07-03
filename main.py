"""MuhGPT CLI entry point."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import shutil
import sys
from dataclasses import replace
from functools import partial

from muhgpt import __version__, arsenal, bidi, guard, knowledge, ui
from muhgpt.agent import AUTONOMOUS_SYSTEM_PROMPT, SYSTEM_PROMPT, Agent
from muhgpt.api_client import APIStatusError, MuhGPTClient, MuhGPTError
from muhgpt.config import ConfigError, load_settings, save_user_api_key, user_config_path
from muhgpt.guard import Budget
from muhgpt.mcp import (
    McpError,
    McpManager,
    default_config_path,
    load_mcp_config,
    merge_mcp_configs,
)
from muhgpt.render import render_markdown, wrapped_rows
from muhgpt.session import Session
from muhgpt.tools import ToolRegistry, console_confirm

_COMMANDS = [
    ("/help", "Show this help."),
    ("/install <pkg>...", "Install one or more CLI tools via the package manager."),
    ("/mcp", "List connected MCP servers and their tools."),
    ("/models", "List the models available on your API key."),
    ("/balance", "Show your real remaining credits + usage (or /balance <start> <end>)."),
    ("/research <q>", "Run the OSINT research sub-agent on a question (if enabled)."),
    ("/skills", "List vulnerability playbooks the agent can load (or /skills <name> to preview)."),
    ("/report", "Export the engagement report to Markdown now."),
    ("/scope", "Show the engagement scope."),
    ("/exit, /quit", "Exit (you will be offered a report export)."),
]

# A safe package-name token: starts AND ends alphanumeric, with [._+-] allowed
# inside. No spaces/shell metacharacters and no leading/trailing punctuation, so
# nothing dangerous — or malformed like "nmap." — reaches the package manager.
_PKG_TOKEN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._+-]*[A-Za-z0-9])?$")

# Words that must never be treated as a package name when inferring intent from
# free text (articles, pronouns, generic nouns, politeness). The explicit
# /install command has no such filter — there the operator named the package.
_INSTALL_STOPWORDS = (
    "the|a|o|os|as|um|uma|it|this|that|these|those|them|they|all|everything|"
    "anything|something|stuff|latest|one|some|more|me|my|us|your|you|u|up|"
    "please|pls|obrigad[oa]|favor|por|tool|tools|package|packages|pacote|"
    "pacotes|ferramenta|ferramentas"
)

# Whole-message "install X" intent (EN + PT), anchored so it only fires on a bare
# install imperative with exactly one real package token — never mid-sentence,
# never with a trailing clause, never on uninstall/reinstall (the verb must
# start), and never capturing an article/pronoun/noun as the package.
_INSTALL_INTENT = re.compile(
    r"^\s*"
    r"(?:please\s+|pls\s+|pf\s+|por\s+favor\s+)?"
    r"(?:(?:can|could|would)\s+(?:you|u)\s+|pode(?:s|ria)?\s+|consegue(?:s)?\s+)?"
    r"(?:install|instala(?:r)?|setup|set\s*up)\s+"
    r"(?:the\s+|o\s+|a\s+|os\s+|as\s+|um\s+|uma\s+)?"
    r"(?:tool\s+|package\s+|pacote\s+|ferramenta\s+)?"  # PT puts the noun before the name
    r"(?!(?:" + _INSTALL_STOPWORDS + r")\b)"
    r"(?P<pkg>[A-Za-z0-9](?:[A-Za-z0-9._+-]*[A-Za-z0-9])?)"
    r"(?:\s+(?:tool|package|pacote|ferramenta))?"
    r"(?:\s+(?:please|pls|por\s+favor|pf|obrigad[oa]))?"  # trailing politeness
    r"\s*$",
    re.IGNORECASE,
)


# Built-in recon skills: /<name> <target> expands to a playbook objective that is
# run through the agent (hands-off under --auto, step-approved otherwise). Each
# template leans on allowlisted, auto-runnable recon tools.
_SKILLS: dict[str, tuple[str, str]] = {
    "recon": (
        "Full recon of a host/domain",
        "Perform thorough reconnaissance of {target}, passive-first then active: WHOIS, DNS "
        "records, subdomain enumeration, TLS/certificate inspection, an nmap service/version "
        "scan of open ports, and HTTP fingerprinting of any web services. Save each finding to "
        "the report as you go, then write a final summary.",
    ),
    "subdomains": (
        "Enumerate subdomains of a domain",
        "Enumerate subdomains of {target} using passive sources (subfinder, amass -passive, "
        "assetfinder, certificate transparency). Resolve them, report the live ones with IPs and "
        "any detected technologies, and save the list to the report.",
    ),
    "dns": (
        "Map DNS records for a domain",
        "Enumerate DNS records for {target} (A, AAAA, MX, NS, TXT, SOA, CNAME) and attempt a zone "
        "transfer (AXFR) against its nameservers. Report the full DNS map and flag anything "
        "security-relevant (SPF/DMARC, wildcards, exposed internal names). Save to the report.",
    ),
    "tls": (
        "Inspect TLS / certificate of a host",
        "Inspect the TLS configuration and certificate of {target} with sslscan / testssl.sh: "
        "protocol versions, cipher suites, certificate chain, expiry, SANs, and weak or deprecated "
        "settings. Save the findings to the report.",
    ),
    "ports": (
        "Scan ports and services of a host",
        "Run an nmap service/version scan (-sV with default safe scripts) of {target}. Report all "
        "open ports with their services and versions, flag anything notable, and save the report.",
    ),
    "web": (
        "Fingerprint a web target",
        "Fingerprint the web service at {target} using httpx and whatweb: status, title, server, "
        "technologies, and response headers. Flag missing security headers (HSTS, CSP, "
        "X-Frame-Options, …) and exposed paths like robots.txt. Save the findings to the report.",
    ),
}

# Attack-chain playbooks (the HexStrike-style multi-tool objectives) are sourced
# from the arsenal so the chaining catalog stays in one place; they resolve
# through the same /<name> <target> path as the built-in recon skills.
_SKILLS.update(arsenal.PLAYBOOKS)

# A recon target: a single host / domain / URL / IP token, no spaces or shell chars.
_SKILL_TARGET = re.compile(r"^[A-Za-z0-9][\w.\-:/@?=&%+]{0,253}$")
_SKILL_USAGE = object()  # sentinel: matched a skill but the target was missing/invalid

# General-purpose "capability" skills: /<name> <free text> runs a one-off through
# the agent with the role below as the SYSTEM prompt (not the pentest persona),
# isolated from the engagement history — so a weak model reliably adopts the role.
# The user's free text is the user message; these descriptions are the role.
_ASSISTANT_FORMAT = (
    "Reply in clean GitHub-flavored Markdown; use fenced code blocks for any code. Be concise "
    "and correct. If the request is ambiguous, state a reasonable assumption and proceed — do "
    "not refuse or ask to use a different tool."
)
_PROMPT_SKILLS: dict[str, tuple[str, str]] = {
    "code": (
        "Perfect coding",
        "You are a senior software engineer. Write clean, correct, idiomatic, well-structured "
        "code for the user's request. Handle edge cases, keep it minimal, and add a short note "
        "on key decisions and how to test it.",
    ),
    "analyze": (
        "Deep analysis",
        "You are a sharp analyst. Analyze the user's subject deeply and rigorously: break it down, "
        "surface assumptions, trade-offs, risks, and second-order effects, and end with a clear "
        "conclusion or recommendation.",
    ),
    "debug": (
        "Bug hunter",
        "You are a meticulous debugger. Find the most likely root cause(s) of the user's problem, "
        "explain the reasoning, give a concrete fix (with code if relevant), and how to verify it. "
        "If information is missing, say what you'd check.",
    ),
    "explain": (
        "Explain simply",
        "You are a great teacher. Explain the user's topic clearly and simply for a smart "
        "non-expert. Use plain language, a concrete analogy if it helps, and tight structure. "
        "Define any jargon you must use.",
    ),
    "write": (
        "Pro writing",
        "You are a professional writer and editor. Produce polished, clear, well-structured prose "
        "for the user's request. Match an appropriate tone, stay concise, and prefer strong, "
        "direct sentences.",
    ),
    "optimize": (
        "Optimize & refactor",
        "You are a performance- and clarity-focused engineer. Review the user's code or process "
        "for correctness, performance, readability, and simplicity. Identify concrete issues, then "
        "show an improved/refactored version with a short explanation of each change and the "
        "trade-offs.",
    ),
    "security": (
        "Security review",
        "You are a security engineer. Perform a security review of what the user provides (code, "
        "config, or design). Identify concrete vulnerabilities with severity, explain the risk and "
        "how it's exploited, and give a specific remediation for each. Flag anything unverifiable.",
    ),
}


def _render_help() -> str:
    """Build the colorized in-session command help."""
    lines = [ui.accent("Commands:")]
    for cmd, desc in _COMMANDS:
        lines.append("  " + ui.info(f"{cmd:<22}") + ui.dim(desc))
    lines.append("")
    lines.append(
        ui.accent("Recon skills") + ui.dim("  — /<name> <target> (hands-off with --auto):")
    )
    for name, (desc, _template) in _SKILLS.items():
        lines.append("  " + ui.info(f"/{name} <target>".ljust(22)) + ui.dim(desc))
    lines.append("")
    lines.append(ui.accent("Assistant skills") + ui.dim("  — /<name> <your text>:"))
    for name, (desc, _template) in _PROMPT_SKILLS.items():
        lines.append("  " + ui.info(f"/{name} <text>".ljust(22)) + ui.dim(desc))
    lines.append("")
    lines.append(ui.dim("Anything else is sent to the agent."))
    return "\n".join(lines)


def _expand_skill(user_input: str):
    """Resolve a recon `/<skill> <target>` line into an agent objective.

    Returns the expanded playbook objective string, the ``_SKILL_USAGE`` sentinel
    (a usage line was printed), or ``None`` if this isn't a recon-skill command.
    """
    if not user_input.startswith("/"):
        return None
    parts = user_input[1:].split(None, 1)
    name = parts[0].lower() if parts else ""
    if name not in _SKILLS:
        return None
    target = parts[1].strip() if len(parts) > 1 else ""
    if not target or not _SKILL_TARGET.match(target):
        print(ui.warn(f"Usage: /{name} <target>   e.g. /{name} example.com"))
        return _SKILL_USAGE
    print(ui.dim(f"(skill /{name} → {target})"))
    return _SKILLS[name][1].format(target=target)


def _expand_prompt_skill(user_input: str):
    """Resolve an assistant `/<skill> <free text>` line.

    Returns ``(system_prompt, user_text)`` for a one-off `ask_once`, the
    ``_SKILL_USAGE`` sentinel (a usage line was printed), or ``None`` if this isn't
    an assistant-skill command.
    """
    if not user_input.startswith("/"):
        return None
    parts = user_input[1:].split(None, 1)
    name = parts[0].lower() if parts else ""
    if name not in _PROMPT_SKILLS:
        return None
    text = parts[1].strip() if len(parts) > 1 else ""
    if not text:
        print(ui.warn(f"Usage: /{name} <text>   e.g. /{name} <your request>"))
        return _SKILL_USAGE
    print(ui.dim(f"(skill /{name})"))
    role = _PROMPT_SKILLS[name][1] + "\n\n" + _ASSISTANT_FORMAT
    return role, text


def _parse_install_args(arg: str) -> list[str]:
    """Split and validate '/install' arguments into safe package tokens (or [])."""
    tokens = [t.strip(".,!?") for t in arg.split()]
    tokens = [t for t in tokens if t]
    return tokens if tokens and all(_PKG_TOKEN.match(t) for t in tokens) else []


def _match_install_intent(text: str) -> str | None:
    """Return the package name if `text` is a bare 'install X' request, else None."""
    match = _INSTALL_INTENT.match(text.rstrip(" .,!?"))
    return match.group("pkg") if match else None


def _do_install(tools: ToolRegistry, package: str) -> None:
    """Route an operator install request straight through the install_package tool.

    Goes through the same dispatch -> approval -> package-manager path the model
    would use, so the [y/N] confirmation (HITL) is preserved; the model is simply
    not in the loop, which makes this work regardless of its tool-calling ability.
    """
    result = tools.dispatch(
        "install_package", json.dumps({"package": package, "rationale": "operator request"})
    )
    print(ui.dim(result.content) if result.executed else ui.warn(result.content))


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="MuhGPT pentest/OSINT CLI assistant.")
    parser.add_argument("--version", action="version", version=f"muhgpt {__version__}")
    parser.add_argument("--model", help="Override the model name from .env.")
    parser.add_argument("--env-file", default=".env", help="Path to the .env file.")
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output."
    )
    parser.add_argument(
        "--operator", help="Operator handle for the report (default: your login name)."
    )
    parser.add_argument(
        "--scope", default="unrestricted", help="Engagement scope label for the report."
    )
    parser.add_argument(
        "--no-stream",
        action="store_true",
        help="Disable token streaming (buffer the full reply, then render it).",
    )
    parser.add_argument(
        "--no-balance",
        action="store_true",
        help="Don't fetch/show your real credit balance at session start.",
    )
    parser.add_argument(
        "--reset-key",
        action="store_true",
        help="Re-enter your MUHGPT API key, replacing the stored one (fixes a "
        "wrong/expired key saved by first-run setup).",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Autonomous mode: plan and run read-only recon end-to-end without "
        "approving each step (destructive commands are blocked; installs still prompt).",
    )
    parser.add_argument(
        "--objective",
        metavar="TEXT",
        help="Run a single objective (or a '/skill target') non-interactively, then "
        "exit. Pairs with --auto for scripting/cron; the report is exported automatically.",
    )
    parser.add_argument(
        "--yolo",
        action="store_true",
        help="High-trust autonomous mode: auto-approve EVERYTHING except the destructive "
        "denylist and secret-file reads (curl/wget/pipes/installs/file-reads run unattended). "
        "Implies --auto. Use only against trusted/authorized targets.",
    )
    parser.add_argument(
        "--mcp",
        action="store_true",
        help="Enable the MCP client (connect to external MCP servers and use their tools).",
    )
    parser.add_argument(
        "--mcp-config",
        metavar="PATH",
        help="Path to an mcpServers JSON config (overrides MUHGPT_MCP_CONFIG).",
    )
    parser.add_argument(
        "--scan-mode",
        choices=["quick", "standard", "deep"],
        help="Depth of autonomous testing: quick (fast/breadth), standard (balanced), "
        "deep (exhaustive + vuln chaining). Default: standard (or MUHGPT_SCAN_MODE).",
    )
    parser.add_argument(
        "--no-mcp", action="store_true", help="Disable the MCP client even if enabled in .env."
    )
    parser.add_argument(
        "--no-mcp-defaults",
        action="store_true",
        help="Don't load the bundled curated free MCP servers; use only --mcp-config.",
    )
    parser.add_argument(
        "--research",
        action="store_true",
        help="Enable the OSINT research sub-agent (a `research` tool + the /research command) "
        "on the main model.",
    )
    parser.add_argument(
        "--research-model",
        metavar="MODEL",
        help="Use a dedicated model for the research sub-agent (implies --research), e.g. a "
        "Relace Search / Perplexity endpoint. Pair with MUHGPT_RESEARCH_BASE_URL / "
        "MUHGPT_RESEARCH_API_KEY for a separate provider.",
    )
    parser.add_argument(
        "--no-research",
        action="store_true",
        help="Disable the research sub-agent even if enabled in .env.",
    )
    parser.add_argument(
        "--extra-recon",
        metavar="LIST",
        help="Comma/space list of extra read-only recon tools to add to the auto-run "
        "allowlist in --auto (merged with MUHGPT_EXTRA_SAFE_RECON). Dangerous binaries "
        "(shells, interpreters, curl/wget, …) are rejected.",
    )
    parser.add_argument(
        "--classify",
        metavar="CMD",
        help="Dry-run: print how CMD would be classified by the guard "
        "(BLOCK/ALLOW/CONFIRM + reason) and exit. Runs nothing; needs no API key.",
    )
    return parser.parse_args(argv)


def _extra_recon_tokens(flag_value, from_settings=()) -> list[str]:
    """Merge the --extra-recon flag with the .env/settings list into raw tokens."""
    tokens = list(from_settings)
    if flag_value:
        tokens += [t for t in re.split(r"[\s,]+", flag_value) if t]
    return tokens


def _validate_api_key(key: str, env_file):
    """Check a pasted key against the live API. Return ``(ok, reason)``.

    Builds Settings with the candidate key and calls ``list_models`` (a cheap,
    credit-free Bearer probe). A ``401`` — the API's answer for an invalid or
    unknown key — is a definitive reject. Every other outcome (402 no-credits but
    valid key, 403/404, 5xx, or a network/offline error, or a non-muh endpoint)
    is treated as *accept*: we don't block first-run setup on a transient or
    endpoint-specific condition — a real auth problem still surfaces on first use.
    """
    prior = os.environ.get("MUHGPT_API_KEY")
    os.environ["MUHGPT_API_KEY"] = key
    try:
        settings = load_settings(env_file)
        MuhGPTClient(settings).list_models()
        return True, ""
    except APIStatusError as exc:
        if exc.status_code == 401:
            return False, "MUHGPT rejected that key (invalid or unknown)."
        return True, ""  # valid key, unrelated HTTP error — don't block setup
    except MuhGPTError:
        return True, ""  # network/transport hiccup — accept, verify on first use
    except ConfigError:
        return False, "that key was not accepted."
    finally:
        # Restore the pre-probe value; the caller re-sets it only once a key validates.
        if prior is None:
            os.environ.pop("MUHGPT_API_KEY", None)
        else:
            os.environ["MUHGPT_API_KEY"] = prior


def _prompt_and_save_key(env_file):
    """Prompt for an API key in a loop, validate each paste against the API, and
    persist the first one that passes. Returns loaded Settings, or None if the
    operator cancels (empty line / EOF). A rejected paste is never written to disk.
    """
    while True:
        try:
            key = input(ui.prompt("  Paste your MUHGPT API key: ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if not key:
            return None  # empty line — operator declined
        if not key.startswith("mghp_"):
            print(ui.warn("  ✗ That doesn't look like a MUHGPT key (they start with 'mghp_')."))
            print(ui.dim("  Paste your MUHGPT API key, or press Enter to cancel."))
            continue
        print(ui.dim("  Checking key…"))
        ok, reason = _validate_api_key(key, env_file)
        if not ok:
            print(ui.error(f"  ✗ {reason}"))
            print(ui.dim("  Paste a valid MUHGPT API key, or press Enter to cancel."))
            continue
        path = save_user_api_key(key)
        os.environ["MUHGPT_API_KEY"] = key
        print(ui.success(f"  ✓ Saved to {path}")
              + ui.dim("  — future runs pick it up automatically."))
        print()
        try:
            return load_settings(env_file)
        except ConfigError:
            return None


def _first_run_key_setup(exc: ConfigError, env_file):
    """On a missing API key, offer a one-time interactive paste + save, then reload.

    The operator never has to edit a file: they paste the key once, it's validated
    against the API, saved to the persistent user config (``~/.config/muhgpt/.env``,
    0600), and every future run picks it up. A wrong/garbage paste is rejected with
    an error and re-prompted (no bad key is ever persisted). Returns loaded Settings
    on success, or None to fall back to the hard config error (a different config
    problem, non-interactive, or declined).
    """
    if "MUHGPT_API_KEY" not in str(exc):
        return None  # a different config error — don't hijack it
    if not sys.stdin.isatty():
        return None  # no operator to prompt (piped / cron) — keep the hard error
    print()
    print(ui.warn("  No API key set yet — quick one-time setup."))
    print(ui.dim("  Get one at https://muhgpt.com → your account → API keys (mghp_…)."))
    return _prompt_and_save_key(env_file)


def _reset_key_setup(env_file):
    """`--reset-key`: force re-entry of the API key, replacing the stored one.

    The escape hatch for a wrong/stale saved key: the normal first-run prompt never
    fires while *any* key is present (even a bad one), so this bypasses that gate and
    prompts unconditionally. Requires a TTY. Returns loaded Settings, or None.
    """
    if not sys.stdin.isatty():
        print(ui.error("[reset-key] needs an interactive terminal to read a key."),
              file=sys.stderr)
        return None
    print()
    print(ui.warn("  Reset API key — paste a new MUHGPT key to replace the stored one."))
    print(ui.dim(f"  Replacing the key at {user_config_path()} (0600)."))
    print(ui.dim("  Get one at https://muhgpt.com → your account → API keys (mghp_…)."))
    return _prompt_and_save_key(env_file)


def _run_classify(args) -> int:
    """`--classify CMD`: print the guard verdict for CMD and exit (no run, no key).

    Reads the extra-recon allowlist from MUHGPT_EXTRA_SAFE_RECON + --extra-recon so
    the operator can preview exactly how their configured allowlist classifies a
    command, without starting a session or needing credentials.
    """
    env_extra = tuple(
        t for t in re.split(r"[\s,]+", os.getenv("MUHGPT_EXTRA_SAFE_RECON", "")) if t
    )
    accepted, rejected = guard.sanitize_extra_recon(
        _extra_recon_tokens(args.extra_recon, env_extra)
    )
    verdict, reason = guard.classify(args.classify, accepted)
    tint = {"BLOCK": ui.error, "ALLOW": ui.success, "CONFIRM": ui.warn}[verdict.name]
    # Don't surface the raw denylist regex (it's audit-log-only by policy); show a
    # generic reason for BLOCK. ALLOW/CONFIRM reasons are already safe to display.
    shown = "destructive/weaponized (denylisted)" if verdict is guard.Verdict.BLOCK else reason
    print(tint(verdict.name) + ui.dim(f"  ({shown})"))
    print(ui.dim(f"  $ {args.classify}"))
    if accepted:
        print(ui.dim("  extra recon allowlisted: ") + ", ".join(sorted(accepted)))
    if rejected:
        print(ui.warn("  rejected (never-allowlist): ") + ", ".join(rejected))
    return 0


class _StreamView:
    """Prints streamed assistant tokens live, re-rendering a final reply in place.

    Deltas are echoed as they arrive (responsive, raw Markdown). When a final
    reply finishes and the terminal can take it, the streamed block is rewound
    and replaced with the formatted Markdown render — so streaming and pretty
    tables coexist. If the block would have scrolled off-screen, or output is
    not a TTY, the raw stream is left untouched.
    """

    def __init__(self, bidi_mode: str = "off") -> None:
        self._open = False
        self._buf: list[str] = []
        self._bidi = bidi_mode

    def delta(self, piece: str) -> None:
        if not self._open:
            sys.stdout.write("\n")
            self._open = True
        self._buf.append(piece)
        sys.stdout.write(piece)
        sys.stdout.flush()

    def boundary(self, final: bool) -> None:
        if not self._open:
            self._buf = []
            return
        text = "".join(self._buf)
        # Re-render to apply Markdown styling (needs colors) or to reorder RTL
        # text the terminal would otherwise mangle (needed even with --no-color).
        if final and sys.stdout.isatty() and (ui.enabled() or self._wants_bidi(text)):
            self._rerender(text)
        else:
            sys.stdout.write("\n")
        sys.stdout.flush()
        self._open = False
        self._buf = []

    def _wants_bidi(self, text: str) -> bool:
        return self._bidi == "on" or (self._bidi == "auto" and bidi.contains_rtl(text))

    def _rerender(self, text: str) -> None:
        size = shutil.get_terminal_size((80, 24))
        rows = wrapped_rows(text, size.columns)
        if rows < size.lines - 1:
            sys.stdout.write("\r")
            if rows > 1:
                sys.stdout.write(f"\033[{rows - 1}A")
            sys.stdout.write("\033[J")
            sys.stdout.write(bidi.to_display(render_markdown(text), self._bidi) + "\n")
        else:  # too tall to rewind safely — keep the raw stream as printed
            sys.stdout.write("\n")


def _cost(prompt_tokens: int, completion_tokens: int, settings) -> float:
    """Estimated USD cost from configured per-1M-token prices (0 if unpriced)."""
    return (
        prompt_tokens / 1_000_000 * settings.price_prompt_per_1m
        + completion_tokens / 1_000_000 * settings.price_completion_per_1m
    )


def _print_usage(turn: dict[str, int] | None, session: Session, settings) -> None:
    """Print a dim one-line token-usage (and, if priced, cost) summary for the turn."""
    if not turn or not turn.get("total_tokens"):
        return
    line = (
        f"  ↑{turn['prompt_tokens']} ↓{turn['completion_tokens']} tokens"
        f"  ·  session {session.usage['total_tokens']}"
    )
    if settings.price_prompt_per_1m or settings.price_completion_per_1m:
        turn_cost = _cost(turn["prompt_tokens"], turn["completion_tokens"], settings)
        sess_cost = _cost(
            session.usage["prompt_tokens"], session.usage["completion_tokens"], settings
        )
        line += f"  ·  ~${turn_cost:.4f} (session ~${sess_cost:.4f})"
    print(ui.dim(line))


def _error_hint(exc) -> str:
    """An actionable dim suffix for known typed API errors, else ''.

    Maps the muh API's error types / HTTP codes to a next step so a failure is
    self-explanatory (out of credits, wrong model, bad key).
    """
    et = getattr(exc, "error_type", None)
    code = getattr(exc, "status_code", None)
    if et == "insufficient_quota" or code == 402:
        return "  → out of credits. Check with /balance; top up at https://muhgpt.com"
    if et == "model_not_allowed" or code == 403:
        return "  → this API key can't use that model. See /models for what's allowed."
    if et == "model_not_found" or code == 404:
        return "  → unknown model. See /models for available IDs."
    if code == 401:
        return "  → invalid or missing API key. Re-enter it with:  muhgpt --reset-key"
    return ""


def _render_models(models: list, current: str) -> str:
    """Aligned list of available model IDs, marking the configured one."""
    lines = [ui.accent("Available models:")]
    for m in models:
        mid = str(m.get("id", "?"))
        owner = str(m.get("owned_by", ""))
        mark = ui.success("  ← current") if mid == current else ""
        lines.append("  " + ui.info(mid.ljust(34)) + ui.dim(owner) + mark)
    return "\n".join(lines)


def _render_usage(usage: dict) -> str:
    """Render balance + usage totals (and a short by-model breakdown)."""
    balance = usage.get("balance")
    totals = usage.get("totals") or {}
    lines = [ui.accent("Credits & usage:")]
    if balance is not None:
        lines.append("  " + ui.success(f"balance: {balance:,} credits"))
    if totals:
        lines.append("  " + ui.dim(
            f"used: {totals.get('credits', 0):,} credits · {totals.get('tokens', 0):,} tokens · "
            f"{totals.get('requests', 0):,} requests"
        ))
    period = f"{usage.get('start', '')} → {usage.get('end', '')}".strip(" →")
    if period:
        lines.append("  " + ui.dim(f"period: {period}"))
    for bm in (usage.get("by_model") or [])[:5]:
        lines.append("  " + ui.dim(
            f"  {bm.get('model', '?')}: {bm.get('credits', 0):,} credits, "
            f"{bm.get('requests', 0)} req"
        ))
    return "\n".join(lines)


def _print_startup_balance(client) -> None:
    """Best-effort: show real remaining credits at startup; silent on any error.

    Never breaks the session — a network failure, a 404 on a non-muh endpoint, or
    a missing balance field just skips the line.
    """
    try:
        usage = client.get_usage()
    except Exception:  # noqa: BLE001 - a startup nicety must never abort the session
        return
    balance = usage.get("balance") if isinstance(usage, dict) else None
    if balance is not None:
        print(ui.dim(f"  credits: {balance:,} remaining"))


def _default_operator() -> str:
    """Best-effort OS login name, used as the operator handle."""
    try:
        return getpass.getuser() or "operator"
    except Exception:
        return "operator"


def _authorize_autonomous(
    requested: bool, scope: str, settings, session: Session, interactive: bool = True,
    yolo: bool = False,
) -> bool:
    """Confirm autonomous execution before the session; return the final flag.

    Interactive sessions get a one-time ``[y/N]`` acknowledgement (a "no" falls
    back to manual HITL mode). For non-interactive one-shot runs the `--auto`
    flag itself is the consent, since there is no operator to answer a prompt.
    ``yolo`` prints a stronger warning (it auto-approves the CONFIRM tier too).
    """
    if not requested:
        return False
    print()
    if yolo:
        print(ui.error("  ⚠ YOLO AUTONOMOUS MODE"))
        print(ui.dim("  The agent auto-approves EVERYTHING except the destructive denylist and"))
        print(ui.dim("  secret-file reads — including curl/wget, pipes, installs, and file reads."))
        print(ui.dim("  No per-step prompts. Only run against targets you fully trust: scanned"))
        print(ui.dim("  output could prompt-inject the model into running CONFIRM-tier commands."))
    else:
        print(ui.warn("  ⚠ AUTONOMOUS MODE"))
        print(ui.dim("  The agent self-directs: it runs read-only recon and installs tools"))
        print(ui.dim("  without approving each step. Destructive commands are blocked; unknown"))
        print(ui.dim(
            "  commands and installs still prompt. Only run against authorized, in-scope targets."
        ))
    print(ui.dim(
        f"  Scope: {scope}    Budget: {settings.auto_max_rounds} rounds / "
        f"{settings.auto_max_commands} cmds / {settings.auto_wall_clock_s}s"
    ))
    if not interactive:
        print(ui.dim("  Non-interactive run — authorized via --auto."))
        session.log_event(
            "autonomous_authorized", {"scope": scope, "noninteractive": True, "yolo": yolo}
        )
        return True
    prompt = "  Run in YOLO mode against '{}'?" if yolo else "  Run autonomously against '{}'?"
    if not console_confirm(ui.warn(prompt.format(scope))):
        print(ui.dim("  Autonomous mode declined — continuing in manual (HITL) mode."))
        return False
    session.log_event("autonomous_authorized", {"scope": scope, "yolo": yolo})
    return True


def _drive(produce_reply, *, agent: Agent, settings, session: Session, stream_view) -> None:
    """Run a reply-producing call (run_turn or ask_once) and render reply + usage."""
    try:
        reply = produce_reply()
    except MuhGPTError as exc:
        stream_view.boundary(False)
        print(ui.error(f"[api error] {exc}") + ui.dim(_error_hint(exc)))
        return
    except KeyboardInterrupt:
        stream_view.boundary(False)
        print("\n" + ui.warn("[interrupted]"))
        return
    # In stream mode the reply was already printed live (and re-rendered) by the
    # stream view; only the buffered path renders it here.
    if not settings.stream:
        rendered = render_markdown(reply)
        if sys.stdout.isatty():  # reorder RTL for display; keep pipes logical
            rendered = bidi.to_display(rendered, settings.bidi)
        print("\n" + rendered + "\n")
    _print_usage(agent.last_turn_usage, session, settings)


def _build_mcp(settings, enabled: bool, config_path, use_defaults: bool) -> McpManager | None:
    """Connect to the MCP servers (bundled curated defaults + the operator's own).

    When enabled, loads the bundled free servers (search/OSINT/fetch) unless
    ``use_defaults`` is off, then merges the operator's ``config_path`` on top
    (same-named entries override the bundled one). Failures are non-fatal: a
    missing config or a server that won't connect prints a warning and is skipped,
    so the CLI always comes up. Returns a connected manager only when at least one
    tool was discovered (otherwise its subprocesses are closed and None returned).
    """
    if not enabled:
        return None

    config_lists = []
    if use_defaults:
        try:
            config_lists.append(load_mcp_config(default_config_path()))
        except McpError as exc:
            print(ui.warn(f"  [mcp] could not load bundled defaults: {exc}"))
    if config_path is not None:
        try:
            config_lists.append(load_mcp_config(config_path))
        except McpError as exc:
            print(ui.error(f"  [mcp] {exc}"))
            return None
    configs = merge_mcp_configs(*config_lists)
    if not configs:
        print(ui.warn(
            "  [mcp] enabled but no servers (defaults off and no --mcp-config) — skipping."
        ))
        return None

    print(ui.dim(f"  [mcp] connecting to {len(configs)} server(s)…"))
    manager = McpManager(
        configs, timeout=settings.mcp_timeout, auto_tools=settings.mcp_auto_tools
    )
    manager.connect()
    for name, err in manager.errors:
        print(ui.warn(f"  [mcp] {name}: {err}"))
    tool_count = len(manager.tools)
    if not tool_count:
        manager.close()
        print(ui.warn("  [mcp] no tools available — MCP disabled for this session."))
        return None
    print(ui.success(f"  [mcp] {tool_count} tool(s) ready") + ui.dim(f"  ({manager.describe()})"))
    return manager


def main(argv: list[str] | None = None) -> int:
    """Run the interactive MuhGPT session. Returns a process exit code."""
    args = _parse_args(argv)
    if args.no_color:
        ui.set_enabled(False)
    # Dry-run guard inspector: classify a command and exit, before anything else
    # (no banner, no session, no API key required).
    if args.classify is not None:
        return _run_classify(args)
    print(ui.banner(__version__))

    if args.reset_key:
        # Force re-entry, replacing any stored key (even a valid one). The escape
        # hatch when a wrong key was saved — the first-run prompt won't fire then.
        settings = _reset_key_setup(args.env_file)
        if settings is None:
            return 2
    else:
        try:
            settings = load_settings(args.env_file)
        except ConfigError as exc:
            settings = _first_run_key_setup(exc, args.env_file)
            if settings is None:
                print(ui.error(f"[config error] {exc}"), file=sys.stderr)
                return 2

    if args.model:
        settings = replace(settings, model=args.model)
    if args.no_stream:
        settings = replace(settings, stream=False)
    if args.scan_mode:
        settings = replace(settings, scan_mode=args.scan_mode)
    if args.research_model:
        settings = replace(
            settings, research_model=args.research_model, research_enabled=True
        )
    elif args.research:
        settings = replace(settings, research_enabled=True)
    if args.no_research:
        settings = replace(settings, research_enabled=False, research_model="")

    operator = (args.operator or _default_operator()).strip() or "operator"
    scope = args.scope.strip() or "unrestricted"

    session = Session(operator=operator, scope=scope, reports_dir=settings.reports_dir)
    client = MuhGPTClient(settings)

    yolo = args.yolo or settings.yolo
    auto = _authorize_autonomous(
        args.auto or settings.auto or yolo, scope, settings, session,
        interactive=args.objective is None, yolo=yolo,
    )
    yolo = yolo and auto  # yolo only applies if autonomous was actually authorized
    budget = (
        Budget(
            max_rounds=settings.auto_max_rounds,
            max_commands=settings.auto_max_commands,
            max_installs=settings.auto_max_installs,
            wall_clock_s=settings.auto_wall_clock_s,
            max_blocks=settings.auto_max_blocks,
            max_idle_rounds=settings.auto_max_idle,
        )
        if auto
        else None
    )

    mcp = _build_mcp(
        settings,
        enabled=(args.mcp or settings.mcp_enabled) and not args.no_mcp,
        config_path=args.mcp_config or settings.mcp_config_path,
        use_defaults=settings.mcp_use_defaults and not args.no_mcp_defaults,
    )

    # Research sub-agent: a second model client (or the main one) the lead agent
    # can delegate OSINT questions to. Built only when active and not disabled.
    research_client = None
    if settings.research_active and not args.no_research:
        rs = settings.research_client_settings()
        research_client = MuhGPTClient(rs)
        print(ui.dim(f"  [research] sub-agent on '{rs.model}'") + (
            ui.dim(f" @ {rs.base_url}") if settings.research_base_url else ""
        ))

    # Everything after the MCP servers are spawned runs inside this try/finally,
    # so their subprocesses are shut down on every exit path — including a failure
    # while building the registry or agent (not just during the REPL).
    try:
        # Operator-extended recon allowlist: sanitize (dropping never-allowlistable
        # binaries), build a classifier bound to the clean set, and surface what was
        # accepted vs rejected. The denylist/metachar gates still run first.
        accepted_recon, rejected_recon = guard.sanitize_extra_recon(
            _extra_recon_tokens(args.extra_recon, settings.extra_safe_recon)
        )
        classifier = guard.make_classifier(accepted_recon)
        if accepted_recon or rejected_recon:
            line = ui.dim("  [guard] extra recon allowlisted: ") + (
                ui.info(", ".join(sorted(accepted_recon))) if accepted_recon else ui.dim("(none)")
            )
            if rejected_recon:
                line += ui.warn("   rejected: " + ", ".join(rejected_recon))
            print(line)

        tools = ToolRegistry(
            session, command_timeout=settings.command_timeout, auto=auto, budget=budget,
            mcp=mcp, yolo=yolo, classifier=classifier,
            research_client=research_client,
            research_max_rounds=settings.research_max_rounds,
            research_max_commands=settings.research_max_commands,
            research_wall_clock_s=settings.research_wall_clock_s,
            scan_mode=settings.scan_mode,
        )
        stream_view = _StreamView(bidi_mode=settings.bidi)
        agent = Agent(
            client,
            tools,
            session,
            max_tool_rounds=settings.max_tool_rounds,
            max_history_messages=settings.max_history_messages,
            on_assistant_text=lambda text: print("\n" + ui.reasoning(text)),
            stream=settings.stream,
            on_delta=stream_view.delta,
            on_message_boundary=stream_view.boundary,
            autonomous=auto,
            budget=budget,
            scan_mode=settings.scan_mode,
            system_prompt=AUTONOMOUS_SYSTEM_PROMPT if auto else SYSTEM_PROMPT,
        )

        print(
            "\n" + ui.success("Session started.")
            + ui.dim(f"  Reports dir: {settings.reports_dir.resolve()}")
        )
        if settings.show_balance and not args.no_balance:
            _print_startup_balance(client)

        # One-shot: run a single objective (recon "/skill target", assistant
        # "/skill text", or free objective), export, and exit.
        if args.objective is not None:
            objective = args.objective.strip()
            if not objective:
                print(ui.error("Empty --objective."), file=sys.stderr)
                return 2
            recon = _expand_skill(objective)
            if recon is _SKILL_USAGE:
                return 2
            prompt_skill = None if recon is not None else _expand_prompt_skill(objective)
            if prompt_skill is _SKILL_USAGE:
                return 2
            if recon is not None:
                thunk = partial(agent.run_turn, recon)
            elif prompt_skill is not None:
                thunk = partial(agent.ask_once, prompt_skill[0], prompt_skill[1])
            else:
                thunk = partial(agent.run_turn, objective)
            _drive(thunk, agent=agent, settings=settings, session=session, stream_view=stream_view)
            if session.has_activity:
                print(ui.success("Report written to ") + ui.dim(str(session.export())))
            print(ui.dim("Done."))
            return 0

        print(ui.dim("Type /help for commands.") + "\n")

        prompt_str = ui.prompt(f"[{operator}@muhgpt] ❯ ")
        while True:
            try:
                user_input = input(prompt_str).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not user_input:
                continue
            if user_input in {"/exit", "/quit"}:
                break
            if user_input == "/help":
                print(_render_help())
                continue
            if user_input == "/scope":
                print(ui.info("Authorized scope: ") + scope)
                continue
            if user_input == "/mcp":
                print(ui.info("MCP: ") + (mcp.describe() if mcp is not None else "disabled"))
                continue
            if user_input == "/models":
                try:
                    models = client.list_models()
                except MuhGPTError as exc:
                    print(ui.error(f"[models error] {exc}") + ui.dim(_error_hint(exc)))
                else:
                    print(_render_models(models, settings.model))
                continue
            if user_input in {"/balance", "/usage"} or user_input.startswith(
                ("/balance ", "/usage ")
            ):
                parts = user_input.split()
                start = parts[1] if len(parts) > 1 else None
                end = parts[2] if len(parts) > 2 else None
                try:
                    usage = client.get_usage(start=start, end=end)
                except MuhGPTError as exc:
                    print(ui.error(f"[balance error] {exc}") + ui.dim(_error_hint(exc)))
                else:
                    print(_render_usage(usage))
                continue
            if user_input == "/research" or user_input.startswith("/research "):
                query = user_input[len("/research"):].strip()
                if research_client is None:
                    print(ui.warn(
                        "Research sub-agent not enabled. Start with --research (or set "
                        "MUHGPT_RESEARCH_MODEL / MUHGPT_RESEARCH_ENABLED)."
                    ))
                elif not query:
                    print(ui.warn(
                        "Usage: /research <question>   e.g. /research breach history of example.com"
                    ))
                else:
                    result = tools.dispatch("research", json.dumps({"query": query}))
                    rendered = render_markdown(result.content)
                    if sys.stdout.isatty():
                        rendered = bidi.to_display(rendered, settings.bidi)
                    print("\n" + rendered + "\n")
                continue
            if user_input == "/skills" or user_input.startswith("/skills "):
                arg = user_input[len("/skills"):].strip()
                if arg:
                    body = knowledge.load_skill(arg)
                    print(render_markdown(body) if body else ui.warn(f"Unknown skill: {arg}"))
                else:
                    print(ui.info("Vulnerability playbooks: ") + (
                        ", ".join(knowledge.list_skills()) or "(none)"))
                    print(ui.dim("  Preview with /skills <name>; agent loads via load_skill."))
                continue
            if user_input == "/report":
                print(ui.success("Report written to ") + ui.dim(str(session.export())))
                continue
            if user_input == "/install" or user_input.startswith("/install "):
                packages = _parse_install_args(user_input[len("/install"):].strip())
                if not packages:
                    print(ui.warn(
                        "Usage: /install <package> [<package> ...]   e.g. /install nmap"
                    ))
                else:
                    for package in packages:
                        _do_install(tools, package)
                continue

            # Recon skill: /<name> <target> -> playbook objective via the pentest agent.
            expanded = _expand_skill(user_input)
            if expanded is _SKILL_USAGE:
                continue
            if expanded is not None:
                _drive(
                    partial(agent.run_turn, expanded),
                    agent=agent, settings=settings, session=session, stream_view=stream_view,
                )
                continue

            # Assistant skill: /<name> <free text> -> isolated one-off with its own persona.
            prompt_skill = _expand_prompt_skill(user_input)
            if prompt_skill is _SKILL_USAGE:
                continue
            if prompt_skill is not None:
                _drive(
                    partial(agent.ask_once, prompt_skill[0], prompt_skill[1]),
                    agent=agent, settings=settings, session=session, stream_view=stream_view,
                )
                continue

            # Bare "install X" / "instala o X" — route straight to the installer.
            if package := _match_install_intent(user_input):
                print(ui.dim("(install intent detected — use /install to be explicit)"))
                _do_install(tools, package)
                continue

            _drive(
                partial(agent.run_turn, user_input),
                agent=agent, settings=settings, session=session, stream_view=stream_view,
            )

        if session.has_activity and console_confirm(
            ui.info("Export engagement report before exiting?")
        ):
            print(ui.success("Report written to ") + ui.dim(str(session.export())))
        print(ui.dim("Done."))
        return 0
    finally:
        if mcp is not None:
            mcp.close()


if __name__ == "__main__":
    raise SystemExit(main())
