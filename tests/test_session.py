"""Tests for the engagement session: audit log + Markdown report."""
from __future__ import annotations

import json


def test_fresh_session_has_no_activity(session):
    assert session.has_activity is False


def test_finding_marks_activity_and_renders(session):
    session.add_finding("Open Redirect", "redirects to attacker.example")
    assert session.has_activity is True
    md = session.render_markdown()
    assert "## Findings" in md
    assert "1. Open Redirect" in md
    assert "redirects to attacker.example" in md


def test_approved_command_marks_activity_and_appears_in_report(session):
    session.log_command("nmap -sV host", output="(exit code: 0)", approved=True)
    assert session.has_activity is True
    md = session.render_markdown()
    assert "nmap -sV host" in md
    assert "## Command Log" in md


def test_declined_command_does_not_mark_activity(session):
    session.log_command("rm -rf /", output="", approved=False)
    assert session.has_activity is False


def test_export_writes_file_matching_render(session):
    session.add_finding("T", "body")
    path = session.export()
    assert path.exists()
    assert path.read_text(encoding="utf-8") == session.render_markdown()


def test_usage_accumulates_and_renders_in_report(session):
    session.add_usage({"prompt_tokens": 100, "completion_tokens": 40, "total_tokens": 140})
    session.add_usage({"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15})
    assert session.usage == {"prompt_tokens": 110, "completion_tokens": 45, "total_tokens": 155}
    md = session.render_markdown()
    assert "## Token Usage" in md
    assert "155" in md


def test_usage_ignores_missing_or_bad_fields(session):
    session.add_usage({"prompt_tokens": 7})  # no completion/total
    assert session.usage["prompt_tokens"] == 7
    assert session.usage["total_tokens"] == 0
    # no usage section when nothing was totalled
    assert "## Token Usage" not in session.render_markdown()


def test_events_are_streamed_to_jsonl(session):
    session.log_message("user", "hello")
    lines = session._log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["kind"] == "message"
    assert event["role"] == "user"
    assert event["content"] == "hello"
