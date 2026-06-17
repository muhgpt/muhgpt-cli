"""Engagement session: structured logging and Markdown report export."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp() -> str:
    return _utc_now().strftime("%Y-%m-%d %H:%M:%SZ")


@dataclass
class Finding:
    """A single report section authored by the agent or operator."""

    title: str
    content: str
    created_at: str = field(default_factory=_stamp)


@dataclass
class Session:
    """Records the full engagement and renders it as a report.

    Two parallel records are kept: a human-facing list of findings (for the
    final report) and an append-only JSONL audit log of every event written to
    disk as it happens (for traceability and recovery).
    """

    operator: str
    scope: str
    reports_dir: Path
    started_at: str = field(default_factory=_stamp)
    findings: list[Finding] = field(default_factory=list)
    usage: dict[str, int] = field(
        default_factory=lambda: {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    )
    _events: list[dict[str, Any]] = field(default_factory=list, repr=False)
    _log_path: Path | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        slug = _utc_now().strftime("%Y%m%d-%H%M%S")
        self._log_path = self.reports_dir / f"session-{slug}.jsonl"

    def log_event(self, kind: str, data: dict[str, Any]) -> None:
        """Append a typed event to the in-memory and on-disk audit logs."""
        event = {"ts": _stamp(), "kind": kind, **data}
        self._events.append(event)
        if self._log_path is not None:
            with self._log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")

    def log_message(self, role: str, content: str) -> None:
        """Record a conversational message exchanged with the model."""
        self.log_event("message", {"role": role, "content": content})

    def log_command(self, command: str, output: str, approved: bool) -> None:
        """Record a proposed command, whether it ran, and any output produced."""
        self.log_event("command", {"command": command, "approved": approved, "output": output})

    def add_finding(self, title: str, content: str) -> Finding:
        """Add a section to the engagement report and audit log."""
        finding = Finding(title=title, content=content)
        self.findings.append(finding)
        self.log_event("finding", {"title": title, "content": content})
        return finding

    def add_usage(self, usage: dict[str, Any]) -> None:
        """Accumulate token-usage counts reported by the API."""
        for key in self.usage:
            value = usage.get(key)
            if isinstance(value, (int, float)):
                self.usage[key] += int(value)
        self.log_event("usage", {key: usage.get(key) for key in self.usage})

    @property
    def has_activity(self) -> bool:
        """True if any findings or approved commands have been recorded."""
        if self.findings:
            return True
        return any(e["kind"] == "command" and e.get("approved") for e in self._events)

    def render_markdown(self) -> str:
        """Produce a clean Markdown report of the engagement."""
        lines = [
            "# MuhGPT Engagement Report",
            "",
            f"- **Operator:** {self.operator}",
            f"- **Authorized scope:** {self.scope}",
            f"- **Started:** {self.started_at}",
            f"- **Generated:** {_stamp()}",
            "",
            "## Findings",
            "",
        ]
        if not self.findings:
            lines.append("_No findings recorded._")
        else:
            for index, finding in enumerate(self.findings, start=1):
                lines += [
                    f"### {index}. {finding.title}",
                    f"_Recorded {finding.created_at}_",
                    "",
                    finding.content,
                    "",
                ]

        lines += ["", "## Command Log", ""]
        commands = [e for e in self._events if e["kind"] == "command" and e.get("approved")]
        if not commands:
            lines.append("_No commands were executed._")
        else:
            for event in commands:
                lines += [
                    f"**`$ {event['command']}`** _(at {event['ts']})_",
                    "",
                    "```",
                    (event["output"] or "").strip() or "(no output)",
                    "```",
                    "",
                ]

        if self.usage.get("total_tokens"):
            lines += [
                "",
                "## Token Usage",
                "",
                f"- **Prompt:** {self.usage['prompt_tokens']}",
                f"- **Completion:** {self.usage['completion_tokens']}",
                f"- **Total:** {self.usage['total_tokens']}",
            ]
        return "\n".join(lines).rstrip() + "\n"

    def export(self, filename: str | None = None) -> Path:
        """Write the Markdown report to ``reports_dir`` and return its path."""
        name = filename or f"report-{_utc_now().strftime('%Y%m%d-%H%M%S')}.md"
        path = self.reports_dir / name
        path.write_text(self.render_markdown(), encoding="utf-8")
        return path
