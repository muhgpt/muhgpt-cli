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


def test_vulnerability_marks_activity_and_renders_sorted(session):
    session.add_vulnerability(
        {"title": "Low bug", "description": "d", "poc": "p", "severity": "Low"}
    )
    session.add_vulnerability({
        "title": "RCE", "description": "exec", "poc": "id; uid=0", "severity": "Critical",
        "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    })
    assert session.has_activity is True
    md = session.render_markdown()
    assert "## Vulnerabilities" in md
    assert md.index("[Critical] RCE") < md.index("[Low] Low bug")  # sorted by severity
    assert "CVSS 9.8" in md and "id; uid=0" in md


def test_notes_render_but_do_not_mark_activity(session):
    session.add_note("revisit /admin", "lead")
    assert session.has_activity is False  # notes alone aren't a deliverable
    md = session.render_markdown()
    assert "## Notes & Methodology" in md and "revisit /admin" in md


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
