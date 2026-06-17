"""Tests for the built-in recon skill commands (/recon, /tls, ...)."""
from __future__ import annotations

import pytest

import main
from main import (
    _PROMPT_SKILLS,
    _SKILL_USAGE,
    _SKILLS,
    _expand_prompt_skill,
    _expand_skill,
)


@pytest.mark.parametrize("name", list(_SKILLS))
def test_every_skill_expands_with_a_clean_target(name):
    objective = _expand_skill(f"/{name} example.com")
    assert isinstance(objective, str)
    assert "example.com" in objective
    assert "{target}" not in objective  # template was filled


def test_recon_objective_is_a_playbook():
    objective = _expand_skill("/recon scanme.example.org")
    assert "scanme.example.org" in objective
    assert "recon" in objective.lower()


def test_url_target_is_accepted():
    objective = _expand_skill("/web https://example.com/path")
    assert objective is not None and objective is not _SKILL_USAGE
    assert "https://example.com/path" in objective


def test_missing_target_prints_usage():
    assert _expand_skill("/recon") is _SKILL_USAGE


@pytest.mark.parametrize("line", [
    "/recon two targets here",   # spaces -> not a single token
    "/recon ; rm -rf /",         # shell injection attempt (space + ;)
    "/tls $(whoami)",            # command substitution
    "/ports a|b",                # pipe -> out of the target charset
    "/dns a;b",                  # semicolon -> out of charset
])
def test_unsafe_target_is_rejected(line):
    # NB: even an accepted target only reaches the agent's prompt as text — actual
    # shell commands the model forms are still vetted by the guard. This is hygiene.
    assert _expand_skill(line) is _SKILL_USAGE


@pytest.mark.parametrize("line", ["/notaskill foo", "hello there", "/help", ""])
def test_non_skill_returns_none(line):
    assert _expand_skill(line) is None


def test_help_lists_skills():
    main.ui.set_enabled(False)
    try:
        rendered = main._render_help()
    finally:
        main.ui.set_enabled(None)
    for name in _SKILLS:
        assert f"/{name} <target>" in rendered
    assert "Recon skills" in rendered
    for name in _PROMPT_SKILLS:
        assert f"/{name} <text>" in rendered
    assert "Assistant skills" in rendered


# --- capability / prompt skills (free text -> role system prompt + user text) ---
@pytest.mark.parametrize("name", list(_PROMPT_SKILLS))
def test_prompt_skill_returns_role_and_text(name):
    result = _expand_prompt_skill(f"/{name} make this thing better, please")
    assert isinstance(result, tuple)
    role, text = result
    assert isinstance(role, str) and role  # a persona / system prompt
    assert text == "make this thing better, please"
    assert "Markdown" in role  # shared format guidance is appended


def test_prompt_skill_accepts_arbitrary_text_with_spaces_and_symbols():
    # free text — NOT the single-token recon validation
    result = _expand_prompt_skill("/security review POST /login?u=a&p=b; bypass auth?")
    assert isinstance(result, tuple)
    _role, text = result
    assert text == "review POST /login?u=a&p=b; bypass auth?"


def test_prompt_skill_requires_text():
    assert _expand_prompt_skill("/code") is _SKILL_USAGE
    assert _expand_prompt_skill("/explain   ") is _SKILL_USAGE


def test_code_skill_sets_engineer_role_in_system_prompt():
    role, text = _expand_prompt_skill("/code a function that reverses a linked list")
    assert "software engineer" in role.lower()
    assert text == "a function that reverses a linked list"


def test_skill_kinds_do_not_cross_match():
    # _expand_skill is recon-only; _expand_prompt_skill is assistant-only
    assert _expand_skill("/code something") is None
    assert _expand_prompt_skill("/recon example.com") is None
    assert _expand_prompt_skill("hello there") is None
