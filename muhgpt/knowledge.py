"""On-demand vulnerability knowledge base — Strix-style "skills" playbooks.

Each skill is a Markdown playbook for one vulnerability class (XSS, SQLi, …),
shipped under ``muhgpt/skills/`` and loaded into the conversation on demand via
the ``load_skill`` tool. This ports Strix's biggest capability lever — a curated
knowledge base injected into context — as pure prompt data: it teaches a weak
model how to find, VALIDATE, and report a bug class, while granting NO new
execution power (everything it suggests still passes the guard).
"""
from __future__ import annotations

import re
from pathlib import Path

SKILLS_DIR = Path(__file__).resolve().parent / "skills"
# A skill name token: lowercase, starts alnum, [a-z0-9-] inside. Blocks traversal.
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")


def _skill_files() -> dict[str, Path]:
    """Map of skill slug -> markdown path (recursive, so categories are allowed)."""
    if not SKILLS_DIR.is_dir():
        return {}
    return {p.stem: p for p in sorted(SKILLS_DIR.rglob("*.md"))}


def list_skills() -> list[str]:
    """All available skill slugs, sorted."""
    return sorted(_skill_files())


def load_skill(name: str) -> str | None:
    """Return the markdown body of a skill by slug, or ``None`` if unknown/invalid.

    The slug is validated against a strict pattern (no path separators, no
    traversal), so a poisoned tool argument can't read arbitrary files.
    """
    slug = (name or "").strip().lower()
    if not _SLUG_RE.match(slug):
        return None
    path = _skill_files().get(slug)
    if path is None:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def skills_index() -> str:
    """Comma-separated slug list for the system prompt (empty if none shipped)."""
    return ", ".join(list_skills())
