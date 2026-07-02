"""Tests for the vulnerability knowledge base (skills) loader."""
from __future__ import annotations

from muhgpt import knowledge

CORE = {"xss", "sqli", "ssrf", "idor", "ssti", "xxe", "rce",
        "auth-jwt", "path-traversal", "csrf", "open-redirect", "nosqli"}


def test_core_skills_are_shipped():
    available = set(knowledge.list_skills())
    assert CORE <= available, f"missing: {CORE - available}"


def test_load_skill_returns_markdown():
    body = knowledge.load_skill("xss")
    assert body and body.lstrip().startswith("#")
    assert "Validation" in body  # the validation-first section


def test_load_skill_is_case_insensitive_and_trims():
    assert knowledge.load_skill("  XSS ") == knowledge.load_skill("xss")


def test_unknown_or_malicious_name_returns_none():
    assert knowledge.load_skill("does-not-exist") is None
    assert knowledge.load_skill("../config") is None      # path traversal blocked
    assert knowledge.load_skill("a/b") is None            # separators blocked
    assert knowledge.load_skill("") is None


def test_skills_index_lists_slugs():
    index = knowledge.skills_index()
    assert "xss" in index and "sqli" in index and ", " in index
