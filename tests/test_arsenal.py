"""Tests for the recon arsenal catalog, briefing, and attack-chain playbooks."""
from __future__ import annotations

import pytest

from muhgpt import arsenal, guard


def test_tool_index_marks_auto_vs_confirm_against_the_live_guard():
    index = arsenal.tool_index()
    # An allowlisted tool appears unmarked; a non-allowlisted one is flagged with *.
    assert "nmap" in index and "nmap*" not in index
    assert "gobuster*" in index  # active fuzzer is not auto-run
    assert "masscan*" in index


def test_auto_run_tools_is_the_guard_allowlist():
    assert arsenal.auto_run_tools() == guard.SAFE_RECON


def test_briefing_phrasing_differs_by_mode():
    auto = arsenal.arsenal_briefing(autonomous=True)
    hitl = arsenal.arsenal_briefing(autonomous=False)
    assert "AUTO-RUN" in auto
    assert "operator approval" in hitl
    # Both carry the chaining methodology and the full tool index.
    for briefing in (auto, hitl):
        assert "CHAINING METHODOLOGY" in briefing
        assert "DNS & subdomains" in briefing


@pytest.mark.parametrize("name", sorted(arsenal.PLAYBOOKS))
def test_every_playbook_has_a_target_template(name):
    desc, template = arsenal.PLAYBOOKS[name]
    assert desc and "{target}" in template
    # The template must render cleanly with a concrete target.
    assert "example.com" in template.format(target="example.com")


def test_expected_playbooks_present():
    assert {"pentest", "osint", "cloud", "api", "vulns"} <= set(arsenal.PLAYBOOKS)
