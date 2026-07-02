"""Local tools the model can invoke, plus the human-in-the-loop dispatcher."""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Protocol

from . import cvss, guard, knowledge, ui
from .guard import Budget, Verdict
from .packages import PackageManager, detect_package_manager
from .session import Session

if TYPE_CHECKING:
    from .api_client import MuhGPTClient
    from .mcp import McpManager, McpTool


class Confirmer(Protocol):
    """Callable that asks the operator to approve an action."""

    def __call__(self, prompt: str) -> bool: ...


def console_confirm(prompt: str) -> bool:
    """Default confirmation: prompt on stdin, accepting only an explicit yes."""
    try:
        answer = input(f"{prompt} [y/N]: ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "execute_terminal_command",
            "description": (
                "Run a single shell command on the operator's machine and return its "
                "combined stdout and stderr. Use for reconnaissance and testing tools "
                "(e.g. nmap, curl, whois, dig) against IN-SCOPE, AUTHORIZED targets only. "
                "Every command must be approved by the human operator before it runs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The exact command line to execute.",
                    },
                    "rationale": {
                        "type": "string",
                        "description": "One sentence on why this is the next logical step.",
                    },
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a UTF-8 text file from the local filesystem and return its "
            "contents.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to the file to read."},
                    "max_bytes": {
                        "type": "integer",
                        "description": "Optional cap on bytes to read (default 100000).",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "install_package",
            "description": (
                "Install a missing CLI tool using the system package manager when a "
                "command fails because the tool is not installed (e.g. 'nmap not found'). "
                "Give the package name; the correct install command is chosen for this OS. "
                "Requires operator approval like any other command."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "package": {
                        "type": "string",
                        "description": "Package/tool name to install, e.g. 'nmap', 'whois', 'dig'.",
                    },
                    "rationale": {
                        "type": "string",
                        "description": "One sentence on why this tool is needed.",
                    },
                },
                "required": ["package"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "save_report",
            "description": (
                "Append a finding or analysis section to the engagement report, "
                "using clean Markdown suitable for a bug bounty submission."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Short heading for the section."},
                    "content": {"type": "string", "description": "Markdown body of the section."},
                },
                "required": ["title", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "load_skill",
            "description": (
                "Load a vulnerability playbook (knowledge pack) for a bug class to guide "
                "how you find, VALIDATE, and report it — techniques, payloads, and a "
                "'no PoC, no finding' validation method. Call this BEFORE hunting a specific "
                "vulnerability class. The available skill names are listed in the system prompt."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Skill slug, e.g. 'xss', 'sqli', 'ssrf', 'idor'.",
                    },
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "note",
            "description": (
                "Save a short note to the engagement scratchpad — durable memory that "
                "survives conversation trimming. Use it to record state, hypotheses, "
                "endpoints to revisit, credentials in scope, or your current plan."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "content": {"type": "string", "description": "The note text."},
                    "category": {
                        "type": "string",
                        "description": "Optional tag: general, plan, methodology, lead, question.",
                    },
                },
                "required": ["content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "recall_notes",
            "description": "Read back every note saved this engagement (your scratchpad memory).",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_vulnerability",
            "description": (
                "File a VALIDATED vulnerability into the report. 'No PoC, no finding': a "
                "concrete proof/evidence is REQUIRED — do not file unconfirmed or scanner-only "
                "results. Optionally provide CVSS 3.1 base metrics and a real CVSS score is "
                "computed for you. Duplicate titles are ignored."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Short, specific vuln title."},
                    "description": {
                        "type": "string",
                        "description": "What the issue is, where, and the impact.",
                    },
                    "poc": {
                        "type": "string",
                        "description": "The proof: exact request/payload/steps and the observed "
                        "evidence that confirms exploitability. REQUIRED.",
                    },
                    "remediation": {"type": "string", "description": "How to fix it."},
                    "affected": {
                        "type": "string",
                        "description": "Affected URL/endpoint/parameter/host.",
                    },
                    "severity": {
                        "type": "string",
                        "description": "Critical/High/Medium/Low (used if no CVSS metrics given).",
                    },
                    "cvss": {
                        "type": "object",
                        "description": "Optional CVSS 3.1 base metrics for an exact score.",
                        "properties": {
                            "AV": {"type": "string", "description": "Attack Vector: N/A/L/P"},
                            "AC": {"type": "string", "description": "Attack Complexity: L/H"},
                            "PR": {"type": "string", "description": "Privileges Required: N/L/H"},
                            "UI": {"type": "string", "description": "User Interaction: N/R"},
                            "S": {"type": "string", "description": "Scope: U/C"},
                            "C": {"type": "string", "description": "Confidentiality: H/L/N"},
                            "I": {"type": "string", "description": "Integrity: H/L/N"},
                            "A": {"type": "string", "description": "Availability: H/L/N"},
                        },
                    },
                },
                "required": ["title", "description", "poc"],
            },
        },
    },
]


# Advertised only when a research model is configured (see ToolRegistry). Lets the
# lead agent delegate a research question to a focused OSINT search sub-agent that
# returns a distilled, sourced brief — the "sub-agent -> oracle" pattern.
RESEARCH_TOOL_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "research",
        "description": (
            "Delegate ONE OSINT research question to a focused research sub-agent. It runs its "
            "own bounded search loop (web search + page fetch when available, plus WHOIS/DNS and "
            "other passive recon) and returns a concise, SOURCED Markdown brief. Use it to gather "
            "background, corroborate facts, or investigate a domain/company/person WITHOUT "
            "flooding your own context with raw search output. Ask one specific question per call."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The single research question, as specific as possible.",
                },
            },
            "required": ["query"],
        },
    },
}


@dataclass
class ToolResult:
    """Outcome of a single tool invocation returned to the model."""

    content: str
    executed: bool = True


class ToolRegistry:
    """Maps tool names to implementations and enforces human approval.

    Command execution and file reads both pass through the supplied
    :class:`Confirmer` before any side effect occurs, so the model can never
    act without explicit operator consent.
    """

    def __init__(
        self,
        session: Session,
        command_timeout: int = 300,
        confirm: Confirmer = console_confirm,
        package_manager: PackageManager | None | str = "auto",
        auto: bool = False,
        budget: Budget | None = None,
        classifier: Callable[[str], tuple[Verdict, str]] = guard.classify,
        mcp: McpManager | None = None,
        mcp_classifier: Callable[..., tuple[Verdict, str]] = guard.classify_mcp,
        yolo: bool = False,
        research_client: MuhGPTClient | None = None,
        research_max_rounds: int = 12,
        research_max_commands: int = 20,
        research_wall_clock_s: int = 300,
        scan_mode: str = "standard",
    ) -> None:
        self._session = session
        self._command_timeout = command_timeout
        self._confirm = confirm
        self._auto = auto
        # yolo only has meaning inside autonomous mode; it auto-approves the CONFIRM
        # tier too (everything except BLOCK and secret-file reads). See _auto_approves.
        self._yolo = yolo and auto
        self._budget = budget
        self._classify = classifier
        self._mcp = mcp
        self._classify_mcp = mcp_classifier
        # Research sub-agent (relace-search-style): only wired when a model client
        # is supplied. The `research` tool is advertised/handled only then.
        self._research_client = research_client
        self._research_max_rounds = research_max_rounds
        self._research_max_commands = research_max_commands
        self._research_wall_clock_s = research_wall_clock_s
        self._scan_mode = scan_mode
        self._package_manager: PackageManager | None = (
            detect_package_manager() if package_manager == "auto" else package_manager
        )
        self._handlers: dict[str, Callable[[dict[str, Any]], ToolResult]] = {
            "execute_terminal_command": self._execute_terminal_command,
            "install_package": self._install_package,
            "read_file": self._read_file,
            "save_report": self._save_report,
            "load_skill": self._load_skill,
            "note": self._note,
            "recall_notes": self._recall_notes,
            "report_vulnerability": self._report_vulnerability,
        }
        if self._research_client is not None:
            self._handlers["research"] = self._research

    @property
    def schemas(self) -> list[dict[str, Any]]:
        """OpenAI-compatible tool schemas to advertise to the model.

        The built-ins, plus the ``research`` tool when a research model is wired,
        plus — when an MCP manager is attached — every tool discovered on the
        connected MCP servers (namespaced ``mcp__server__tool``).
        """
        schemas = list(TOOL_SCHEMAS)
        if self._research_client is not None:
            schemas.append(RESEARCH_TOOL_SCHEMA)
        if self._mcp is not None and self._mcp.schemas:
            schemas += self._mcp.schemas
        return schemas

    def dispatch(self, name: str, raw_arguments: str) -> ToolResult:
        """Parse arguments and route the call to the matching handler.

        Args:
            name: The tool/function name requested by the model.
            raw_arguments: The JSON-encoded argument string from the model.

        Returns:
            A :class:`ToolResult` whose ``content`` is fed back to the model.
        """
        handler = self._handlers.get(name)
        is_mcp = handler is None and self._mcp is not None and self._mcp.has_tool(name)
        if handler is None and not is_mcp:
            return ToolResult(f"[error] Unknown tool: {name!r}", executed=False)
        try:
            arguments = json.loads(raw_arguments) if raw_arguments else {}
        except json.JSONDecodeError:
            return ToolResult(
                f"[error] Could not parse arguments for {name}: {raw_arguments!r}",
                executed=False,
            )
        if not isinstance(arguments, dict):
            return ToolResult(f"[error] Arguments for {name} must be an object.", executed=False)
        if is_mcp:
            return self._call_mcp(name, arguments)
        return handler(arguments)

    def _execute_terminal_command(self, args: dict[str, Any]) -> ToolResult:
        """Run a shell command after explicit operator approval."""
        command = str(args.get("command", "")).strip()
        rationale = str(args.get("rationale", "")).strip()
        if not command:
            return ToolResult("[error] No command provided.", executed=False)
        return self._approve_and_run(
            command, rationale, header="proposed command", recover_missing=True
        )

    def _install_package(self, args: dict[str, Any]) -> ToolResult:
        """Install a missing tool with the detected package manager, after approval."""
        package = str(args.get("package", "")).strip()
        rationale = str(args.get("rationale", "")).strip()
        if not package:
            return ToolResult("[error] No package specified.", executed=False)
        if self._package_manager is None:
            return ToolResult(
                "[error] No supported package manager found (looked for brew, apt-get, "
                "pkg, dnf, yum, pacman, apk, zypper). Install the tool manually.",
                executed=False,
            )
        command = self._package_manager.install_command(package)
        return self._approve_and_run(
            command, rationale or f"install '{package}'",
            header=f"install via {self._package_manager.name}", kind="install",
        )

    def _auto_approves(self, verdict: Verdict) -> bool:
        """Whether a classified action runs without a human prompt.

        Outside autonomous mode: never (HITL confirms everything). In autonomous
        mode: an ALLOW (read-only recon) always auto-runs; a CONFIRM auto-runs only
        under ``--yolo``. A BLOCK never auto-runs (it never reaches here).
        """
        if not self._auto:
            return False
        if verdict is Verdict.ALLOW:
            return True
        return self._yolo and verdict is Verdict.CONFIRM

    def _call_mcp(self, name: str, args: dict[str, Any]) -> ToolResult:
        """Route a namespaced MCP tool call through the MCP approval boundary."""
        tool = self._mcp.tool(name) if self._mcp is not None else None
        if tool is None:
            return ToolResult(f"[error] Unknown MCP tool: {name!r}", executed=False)
        return self._approve_and_run_mcp(tool, args)

    def _approve_and_run_mcp(self, tool: McpTool, args: dict[str, Any]) -> ToolResult:
        """Approve (or auto-classify) and invoke one MCP tool call.

        The MCP analogue of :meth:`_approve_and_run`. The verdict is computed by
        :func:`guard.classify_mcp` from the tool/server identity — never the
        model's framing — so it holds under prompt injection. In autonomous mode a
        weaponized tool is BLOCKED, an operator-allowlisted tool may auto-run (with
        a structured-argument scope check), and everything else still prompts. In
        HITL mode every MCP call prompts, exactly like a shell command.
        """
        if self._auto:
            verdict, reason = self._classify_mcp(
                tool.name, tool.server, tool.raw_name, self._mcp.auto_tools
            )
            if verdict is Verdict.BLOCK:
                self._session.log_event(
                    "guard_block", {"mcp_tool": tool.name, "rule": reason}
                )
                print()
                print(
                    ui.error("  [blocked by policy] ")
                    + ui.dim("weaponized or out-of-bounds MCP tool")
                )
                if self._budget is not None:
                    self._budget.charge("block")
                return ToolResult(
                    "[blocked by policy] This MCP tool is weaponized or out of bounds and will "
                    "not run. Do not retry or rephrase it; choose a non-destructive alternative.",
                    executed=False,
                )
            if verdict is Verdict.ALLOW and guard.mcp_targets_out_of_scope(
                args, self._session.scope
            ):
                print()
                print(ui.warn("  MCP target looks outside the declared scope — confirming"))
                self._session.log_event("scope_confirm", {"mcp_tool": tool.name})
                verdict = Verdict.CONFIRM
        else:
            verdict = None

        print()
        print(_box_rule(f"MCP tool · {tool.server}"))
        print("  " + ui.command(f"{tool.raw_name}({_summarize_args(args)})"))
        print(_box_rule())

        if self._auto_approves(verdict):
            yolo = " [yolo]" if verdict is Verdict.CONFIRM else ""
            print("  " + ui.dim("[auto] approved (autonomous mode)" + yolo))
        elif not self._confirm(ui.warn("  Run this MCP tool call?")):
            self._session.log_event(
                "mcp_call",
                {"server": tool.server, "tool": tool.raw_name, "arguments": args,
                 "approved": False},
            )
            return ToolResult("[declined] Operator declined the MCP tool call.", executed=False)

        if self._auto and self._budget is not None:
            self._budget.charge("command")  # MCP calls draw on the command budget

        try:
            output = self._mcp.invoke(tool.name, args)
        except Exception as exc:  # noqa: BLE001 - surface any transport/server failure to the model
            self._session.log_event(
                "mcp_call",
                {"server": tool.server, "tool": tool.raw_name, "arguments": args,
                 "approved": True, "error": str(exc)},
            )
            return ToolResult(f"[error] MCP tool '{tool.raw_name}' failed: {exc}")

        self._session.log_event(
            "mcp_call",
            {"server": tool.server, "tool": tool.raw_name, "arguments": args,
             "approved": True, "output": output},
        )
        return ToolResult(output)

    def _approve_and_run(
        self,
        command: str,
        rationale: str,
        header: str,
        recover_missing: bool = False,
        kind: str = "command",
    ) -> ToolResult:
        """Show a command, get approval (or auto-approve in auto mode), and run it.

        In autonomous mode a safety guard classifies the command first: destructive
        commands are BLOCKED (never run, never prompt), read-only recon is
        auto-approved, and anything else still requires the operator's ``[y/N]``.
        In HITL mode (the default) the guard is bypassed and every command prompts,
        exactly as before. When ``recover_missing`` is set and the command fails
        because its tool is missing (exit 127), the tool is installed and the
        command re-run automatically.
        """
        if self._auto:
            verdict, reason = self._classify(command)
            if verdict is Verdict.BLOCK:
                # The precise rule (regex) goes to the audit log only — the model
                # (possibly prompt-injected) sees a generic, non-actionable reason.
                self._session.log_event("guard_block", {"command": command, "rule": reason})
                print()
                print(
                    ui.error("  [blocked by policy] ")
                    + ui.dim("destructive or out-of-bounds command")
                )
                if self._budget is not None:
                    self._budget.charge("block")  # too many blocks ends the run
                return ToolResult(
                    "[blocked by policy] This command is destructive or out of bounds and will "
                    "not run. Do not retry or rephrase it; choose a non-destructive alternative.",
                    executed=False,
                )
            if verdict is Verdict.ALLOW and guard.targets_out_of_scope(
                command, self._session.scope
            ):
                # Possible scope pivot (e.g. injected "now scan 10.0.0.5") — don't
                # auto-run it; fall back to a human confirm.
                print()
                print(ui.warn("  target looks outside the declared scope — confirming"))
                self._session.log_event("scope_confirm", {"command": command})
                verdict = Verdict.CONFIRM
        else:
            verdict = None

        print()
        print(_box_rule(header))
        if rationale:
            print("  " + ui.dim("why: ") + ui.dim(rationale))
        print("  " + ui.command(f"$ {command}"))
        print(_box_rule())

        if self._auto_approves(verdict):
            yolo = " [yolo]" if verdict is Verdict.CONFIRM else ""
            print("  " + ui.dim("[auto] approved (autonomous mode)" + yolo))
        elif not self._confirm(ui.warn("  Execute this command?")):
            self._session.log_command(command, output="", approved=False)
            return ToolResult("[declined] Operator declined to run this command.", executed=False)

        if self._auto and self._budget is not None:
            self._budget.charge("install" if kind == "install" else "command")

        output, return_code, stderr = self._run_shell(command)
        self._session.log_command(command, output=output, approved=True)

        if recover_missing and return_code == 127 and self._package_manager is not None:
            recovered = self._recover_missing_tool(command, stderr)
            if recovered is not None:
                return recovered
            output += (
                "\n[hint] Exit 127 usually means a required tool is not installed. "
                "Use the install_package tool to install it, then retry."
            )
        return ToolResult(output)

    def _recover_missing_tool(self, command: str, stderr: str) -> ToolResult | None:
        """On a 'command not found', offer to install the tool and re-run the command.

        Returns a :class:`ToolResult` when the missing tool was identified (whether
        the operator approved the install or not), or ``None`` to let the caller
        fall back to a generic hint when the tool name can't be determined.
        """
        binary = _missing_command(stderr, command)
        manager = self._package_manager
        if not binary or manager is None:
            return None

        install_cmd = manager.install_command(binary)
        print()
        print(ui.warn(f"  '{binary}' is not installed."))
        print("  " + ui.command(f"$ {install_cmd}"))
        if not self._confirm(ui.warn(f"  Install '{binary}' via {manager.name} and retry?")):
            self._session.log_command(install_cmd, output="", approved=False)
            return ToolResult(
                f"[declined] '{binary}' is not installed and the operator declined to "
                "install it. Cannot run this command.",
                executed=False,
            )

        install_out, install_rc, _ = self._run_shell(install_cmd)
        self._session.log_command(install_cmd, output=install_out, approved=True)
        if install_rc != 0:
            return ToolResult(f"[error] Failed to install '{binary}'.\n{install_out}")

        retry_out, _, _ = self._run_shell(command)
        self._session.log_command(command, output=retry_out, approved=True)
        return ToolResult(f"[installed '{binary}' and re-ran the command]\n{retry_out}")

    def _auto_read_ok(self, path: Path) -> bool:
        """Whether a file may be auto-read in auto mode: under the read-root, no secret."""
        if guard.is_secret_path(str(path)):
            return False
        try:
            resolved = str(path.resolve())
            roots = [str(Path.cwd().resolve()), str(self._session.reports_dir.resolve())]
        except OSError:
            return False
        return any(resolved == root or resolved.startswith(root + os.sep) for root in roots)

    def _run_shell(self, command: str) -> tuple[str, int, str]:
        """Run a shell command; return (combined_output, return_code, raw_stderr)."""
        try:
            completed = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self._command_timeout,
            )
        except subprocess.TimeoutExpired:
            return (f"[timeout] Command exceeded {self._command_timeout}s and was killed.", -1, "")
        except OSError as exc:
            return (f"[error] Failed to launch command: {exc}", -1, "")
        output = _combine_streams(completed.stdout, completed.stderr, completed.returncode)
        return (output, completed.returncode, completed.stderr or "")

    def _read_file(self, args: dict[str, Any]) -> ToolResult:
        """Read a local text file after explicit operator approval."""
        path = Path(str(args.get("path", "")).strip()).expanduser()
        try:
            max_bytes = int(args.get("max_bytes", 100_000))
        except (TypeError, ValueError):
            max_bytes = 100_000
        if max_bytes <= 0:
            max_bytes = 100_000

        if not path.is_file():
            return ToolResult(f"[error] Not a file: {path}", executed=False)
        # Auto-read in autonomous mode under the read-root, or — in yolo — any file
        # that is NOT a secret/credential path (that gate stays absolute even in yolo).
        auto_read = self._auto and (
            self._auto_read_ok(path)
            or (self._yolo and not guard.is_secret_path(str(path)))
        )
        if auto_read:
            print("  " + ui.dim(f"[auto] read {path}"))
        elif not self._confirm(ui.warn(f"  Allow the agent to read {path}?")):
            return ToolResult("[declined] Operator declined the file read.", executed=False)
        try:
            # Read only up to max_bytes instead of slurping the whole file first,
            # so a multi-gigabyte log can't exhaust memory.
            with path.open("rb") as handle:
                data = handle.read(max_bytes)
        except OSError as exc:
            return ToolResult(f"[error] Could not read {path}: {exc}", executed=False)

        self._session.log_event("read_file", {"path": str(path), "bytes": len(data)})
        return ToolResult(data.decode("utf-8", errors="replace"))

    def _save_report(self, args: dict[str, Any]) -> ToolResult:
        """Append a Markdown section to the engagement report."""
        title = str(args.get("title", "Untitled")).strip() or "Untitled"
        content = str(args.get("content", "")).strip()
        self._session.add_finding(title, content)
        return ToolResult(f"[ok] Saved section '{title}' to the report.")

    def _load_skill(self, args: dict[str, Any]) -> ToolResult:
        """Return a vulnerability playbook from the knowledge base (read-only data)."""
        name = str(args.get("name", "")).strip()
        content = knowledge.load_skill(name)
        if content is None:
            return ToolResult(
                f"[error] Unknown skill {name!r}. Available: {knowledge.skills_index()}",
                executed=False,
            )
        print("  " + ui.dim(f"[skill] loaded '{name}'"))
        # executed=False: loading knowledge is preparation, not engagement progress,
        # so it never resets the autonomous no-progress/idle guard.
        return ToolResult(content, executed=False)

    def _note(self, args: dict[str, Any]) -> ToolResult:
        """Save a scratchpad note to engagement memory."""
        content = str(args.get("content", "")).strip()
        if not content:
            return ToolResult("[error] Empty note.", executed=False)
        category = str(args.get("category", "general")).strip() or "general"
        self._session.add_note(content, category)
        print("  " + ui.dim(f"[note] {category}: {content[:60]}"))
        return ToolResult("[ok] Note saved.", executed=False)

    def _recall_notes(self, _args: dict[str, Any]) -> ToolResult:
        """Read back all engagement notes."""
        notes = self._session.notes
        if not notes:
            return ToolResult("[no notes saved yet]", executed=False)
        body = "\n".join(
            f"- ({n.get('category', 'general')}) {n.get('content', '')}" for n in notes
        )
        return ToolResult(f"Engagement notes:\n{body}", executed=False)

    def _report_vulnerability(self, args: dict[str, Any]) -> ToolResult:
        """File a validated vulnerability (PoC required; CVSS computed; deduped)."""
        title = str(args.get("title", "")).strip()
        description = str(args.get("description", "")).strip()
        poc = str(args.get("poc", "")).strip()
        if not title or not description:
            return ToolResult("[error] title and description are required.", executed=False)
        if not poc:
            return ToolResult(
                "[error] A proof of concept / concrete evidence is REQUIRED (no PoC, no finding). "
                "Validate the issue first, then report it with the exact repro and observed proof.",
                executed=False,
            )
        if any(
            v.get("title", "").lower() == title.lower() for v in self._session.vulnerabilities
        ):
            return ToolResult(f"[duplicate] '{title}' is already in the report.", executed=False)

        vuln: dict[str, Any] = {
            "title": title,
            "description": description,
            "poc": poc,
            "remediation": str(args.get("remediation", "")).strip(),
            "affected": str(args.get("affected", "")).strip(),
            "severity": str(args.get("severity", "")).strip() or None,
        }
        metrics = args.get("cvss")
        if isinstance(metrics, dict) and metrics:
            try:
                score, severity, vector = cvss.base_score(metrics)
                vuln["cvss_score"] = score
                vuln["cvss_vector"] = vector
                vuln["severity"] = severity  # CVSS-derived severity wins
            except cvss.CvssError as exc:
                vuln["description"] += f"\n\n_(CVSS not scored: {exc})_"
        self._session.add_vulnerability(vuln)
        sev = vuln.get("severity") or "unrated"
        score_txt = f" CVSS {vuln['cvss_score']}" if vuln.get("cvss_score") is not None else ""
        print("  " + ui.success(f"[vuln] {sev}{score_txt}: {title}"))
        return ToolResult(f"[ok] Reported '{title}' ({sev}{score_txt}).")

    def _research(self, args: dict[str, Any]) -> ToolResult:
        """Delegate one question to the OSINT research sub-agent, return its brief.

        Builds a DEDICATED sub-registry that shares this engagement's session, MCP
        manager, guard classifier and package manager, and inherits ``auto`` — but
        forces ``yolo`` OFF (the sub-agent ingests untrusted web content, so its
        CONFIRM-tier primitives like curl/wget never auto-run) and exposes NO
        ``research`` tool (so it cannot recurse). The sub-run is bounded by its own
        Budget — shared with that sub-registry so round/command/wall-clock caps are
        all enforced — and each delegation also draws one unit from the engagement
        command budget, so the number of research calls stays bounded too.
        Registered only when a research client was supplied at construction.
        """
        from . import research  # lazy import: breaks the tools -> research -> agent cycle

        if self._research_client is None:  # pragma: no cover - not registered without a client
            return ToolResult("[research] No research model configured.", executed=False)
        query = str(args.get("query", "")).strip()
        if not query:
            return ToolResult("[error] No research question provided.", executed=False)
        if self._auto and self._budget is not None:
            self._budget.charge("command")  # bound how many research calls one run may make
        print("  " + ui.dim(f"[research] sub-agent investigating: {query[:70]}"))

        sub_budget = Budget(
            max_rounds=self._research_max_rounds,
            max_commands=self._research_max_commands,
            max_installs=2,
            wall_clock_s=self._research_wall_clock_s,
            max_blocks=3,
            max_idle_rounds=3,
        )
        sub_tools = ToolRegistry(
            self._session,
            command_timeout=self._command_timeout,
            confirm=self._confirm,
            package_manager=self._package_manager,
            auto=self._auto,
            budget=sub_budget,
            classifier=self._classify,
            mcp=self._mcp,
            mcp_classifier=self._classify_mcp,
            yolo=False,            # research never inherits YOLO (untrusted web in)
            research_client=None,  # no `research` tool on the sub-registry -> no recursion
            scan_mode=self._scan_mode,
        )
        try:
            brief = research.run_research(
                query,
                client=self._research_client,
                tools=sub_tools,
                session=self._session,
                budget=sub_budget,
                scan_mode=self._scan_mode,
            )
        except Exception as exc:  # noqa: BLE001 - surface any sub-agent/model failure to the lead
            return ToolResult(f"[error] Research sub-agent failed: {exc}")
        self._session.log_event("research", {"query": query})
        return ToolResult(brief)


_NOT_FOUND_PATTERNS = [
    re.compile(r"command not found:\s*([\w.+-]+)"),   # zsh
    re.compile(r"([\w.+-]+):\s*command not found"),   # bash
    re.compile(r"([\w./+-]+):\s*not found"),          # sh / dash / busybox
]


def _missing_command(stderr: str, command: str) -> str | None:
    """Best-effort name of the missing executable from a 'not found' error.

    Parses the shell's error text first (most reliable), then falls back to the
    first real token of the command (skipping ``VAR=val`` assignments and common
    wrappers like ``sudo``/``env``).
    """
    for pattern in _NOT_FOUND_PATTERNS:
        match = pattern.search(stderr or "")
        if match:
            return os.path.basename(match.group(1).strip())

    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    for token in tokens:
        if "=" in token.split("/")[0] or token in {"sudo", "command", "env", "exec", "time"}:
            continue
        return os.path.basename(token)
    return None


def _summarize_args(args: dict[str, Any], limit: int = 300) -> str:
    """Compact one-line ``k=v`` rendering of MCP arguments for the approval box."""
    if not args:
        return ""
    try:
        rendered = ", ".join(f"{k}={json.dumps(v, ensure_ascii=False)}" for k, v in args.items())
    except (TypeError, ValueError):
        rendered = str(args)
    return rendered if len(rendered) <= limit else rendered[: limit - 1] + "…"


_BOX_WIDTH = 47


def _box_rule(label: str = "") -> str:
    """A colored box rule, optionally with an inline label (e.g. 'proposed command')."""
    if label:
        prefix = f"── {label} "
        return ui.accent("  " + prefix + "─" * max(4, _BOX_WIDTH - len(prefix)))
    return ui.accent("  " + "─" * _BOX_WIDTH)


def _combine_streams(stdout: str, stderr: str, return_code: int) -> str:
    """Merge stdout, stderr and the exit code into a single readable block."""
    parts = [f"(exit code: {return_code})"]
    if stdout.strip():
        parts.append(f"--- stdout ---\n{stdout.strip()}")
    if stderr.strip():
        parts.append(f"--- stderr ---\n{stderr.strip()}")
    if len(parts) == 1:
        parts.append("(no output)")
    return "\n".join(parts)
