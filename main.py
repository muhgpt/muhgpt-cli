"""MuhGPT CLI entry point."""
from __future__ import annotations

import argparse
import getpass
import json
import re
import shutil
import sys
from dataclasses import replace
from functools import partial

from muhgpt import __version__, ui
from muhgpt.agent import AUTONOMOUS_SYSTEM_PROMPT, SYSTEM_PROMPT, Agent
from muhgpt.api_client import MuhGPTClient, MuhGPTError
from muhgpt.config import ConfigError, load_settings
from muhgpt.guard import Budget
from muhgpt.render import render_markdown, wrapped_rows
from muhgpt.session import Session
from muhgpt.tools import ToolRegistry, console_confirm

_COMMANDS = [
    ("/help", "Show this help."),
    ("/install <pkg>...", "Install one or more CLI tools via the package manager."),
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
    return parser.parse_args(argv)


class _StreamView:
    """Prints streamed assistant tokens live, re-rendering a final reply in place.

    Deltas are echoed as they arrive (responsive, raw Markdown). When a final
    reply finishes and the terminal can take it, the streamed block is rewound
    and replaced with the formatted Markdown render — so streaming and pretty
    tables coexist. If the block would have scrolled off-screen, or output is
    not a TTY, the raw stream is left untouched.
    """

    def __init__(self) -> None:
        self._open = False
        self._buf: list[str] = []

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
        if final and sys.stdout.isatty() and ui.enabled():
            self._rerender(text)
        else:
            sys.stdout.write("\n")
        sys.stdout.flush()
        self._open = False
        self._buf = []

    def _rerender(self, text: str) -> None:
        size = shutil.get_terminal_size((80, 24))
        rows = wrapped_rows(text, size.columns)
        if rows < size.lines - 1:
            sys.stdout.write("\r")
            if rows > 1:
                sys.stdout.write(f"\033[{rows - 1}A")
            sys.stdout.write("\033[J")
            sys.stdout.write(render_markdown(text) + "\n")
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


def _default_operator() -> str:
    """Best-effort OS login name, used as the operator handle."""
    try:
        return getpass.getuser() or "operator"
    except Exception:
        return "operator"


def _authorize_autonomous(
    requested: bool, scope: str, settings, session: Session, interactive: bool = True
) -> bool:
    """Confirm autonomous execution before the session; return the final flag.

    Interactive sessions get a one-time ``[y/N]`` acknowledgement (a "no" falls
    back to manual HITL mode). For non-interactive one-shot runs the `--auto`
    flag itself is the consent, since there is no operator to answer a prompt.
    """
    if not requested:
        return False
    print()
    print(ui.warn("  ⚠ AUTONOMOUS MODE"))
    print(ui.dim("  The agent self-directs: it runs read-only recon and installs tools without"))
    print(ui.dim("  approving each step. Destructive/irreversible commands are blocked; unknown"))
    print(ui.dim(
        "  commands and installs still prompt. Only run against authorized, in-scope targets."
    ))
    print(ui.dim(
        f"  Scope: {scope}    Budget: {settings.auto_max_rounds} rounds / "
        f"{settings.auto_max_commands} cmds / {settings.auto_wall_clock_s}s"
    ))
    if not interactive:
        print(ui.dim("  Non-interactive run — authorized via --auto."))
        session.log_event("autonomous_authorized", {"scope": scope, "noninteractive": True})
        return True
    if not console_confirm(ui.warn(f"  Run autonomously against '{scope}'?")):
        print(ui.dim("  Autonomous mode declined — continuing in manual (HITL) mode."))
        return False
    session.log_event("autonomous_authorized", {"scope": scope})
    return True


def _drive(produce_reply, *, agent: Agent, settings, session: Session, stream_view) -> None:
    """Run a reply-producing call (run_turn or ask_once) and render reply + usage."""
    try:
        reply = produce_reply()
    except MuhGPTError as exc:
        stream_view.boundary(False)
        print(ui.error(f"[api error] {exc}"))
        return
    except KeyboardInterrupt:
        stream_view.boundary(False)
        print("\n" + ui.warn("[interrupted]"))
        return
    # In stream mode the reply was already printed live (and re-rendered) by the
    # stream view; only the buffered path renders it here.
    if not settings.stream:
        print("\n" + render_markdown(reply) + "\n")
    _print_usage(agent.last_turn_usage, session, settings)


def main(argv: list[str] | None = None) -> int:
    """Run the interactive MuhGPT session. Returns a process exit code."""
    args = _parse_args(argv)
    if args.no_color:
        ui.set_enabled(False)
    print(ui.banner(__version__))

    try:
        settings = load_settings(args.env_file)
    except ConfigError as exc:
        print(ui.error(f"[config error] {exc}"), file=sys.stderr)
        return 2

    if args.model:
        settings = replace(settings, model=args.model)
    if args.no_stream:
        settings = replace(settings, stream=False)

    operator = (args.operator or _default_operator()).strip() or "operator"
    scope = args.scope.strip() or "unrestricted"

    session = Session(operator=operator, scope=scope, reports_dir=settings.reports_dir)
    client = MuhGPTClient(settings)

    auto = _authorize_autonomous(
        args.auto or settings.auto, scope, settings, session,
        interactive=args.objective is None,
    )
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

    tools = ToolRegistry(
        session, command_timeout=settings.command_timeout, auto=auto, budget=budget
    )
    stream_view = _StreamView()
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
        system_prompt=AUTONOMOUS_SYSTEM_PROMPT if auto else SYSTEM_PROMPT,
    )

    print(
        "\n" + ui.success("Session started.")
        + ui.dim(f"  Reports dir: {settings.reports_dir.resolve()}")
    )

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
        if user_input == "/report":
            print(ui.success("Report written to ") + ui.dim(str(session.export())))
            continue
        if user_input == "/install" or user_input.startswith("/install "):
            packages = _parse_install_args(user_input[len("/install"):].strip())
            if not packages:
                print(ui.warn("Usage: /install <package> [<package> ...]   e.g. /install nmap"))
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


if __name__ == "__main__":
    raise SystemExit(main())
