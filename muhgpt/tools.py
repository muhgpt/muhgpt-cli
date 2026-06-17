"""Local tools the model can invoke, plus the human-in-the-loop dispatcher."""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

from . import guard, ui
from .guard import Budget, Verdict
from .packages import PackageManager, detect_package_manager
from .session import Session


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
]


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
    ) -> None:
        self._session = session
        self._command_timeout = command_timeout
        self._confirm = confirm
        self._auto = auto
        self._budget = budget
        self._classify = classifier
        self._package_manager: PackageManager | None = (
            detect_package_manager() if package_manager == "auto" else package_manager
        )
        self._handlers: dict[str, Callable[[dict[str, Any]], ToolResult]] = {
            "execute_terminal_command": self._execute_terminal_command,
            "install_package": self._install_package,
            "read_file": self._read_file,
            "save_report": self._save_report,
        }

    @property
    def schemas(self) -> list[dict[str, Any]]:
        """OpenAI-compatible tool schemas to advertise to the model."""
        return TOOL_SCHEMAS

    def dispatch(self, name: str, raw_arguments: str) -> ToolResult:
        """Parse arguments and route the call to the matching handler.

        Args:
            name: The tool/function name requested by the model.
            raw_arguments: The JSON-encoded argument string from the model.

        Returns:
            A :class:`ToolResult` whose ``content`` is fed back to the model.
        """
        handler = self._handlers.get(name)
        if handler is None:
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

        if self._auto and verdict is Verdict.ALLOW:
            print("  " + ui.dim("[auto] approved (autonomous mode)"))
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
        if self._auto and self._auto_read_ok(path):
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
