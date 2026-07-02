"""CVSS v3.1 base-score computation — pure stdlib (no `cvss` dependency).

Implements the official CVSS 3.1 base metric equations and roundup so MuhGPT can
attach a real score/severity/vector to a validated finding (Strix's reporting
mandates CVSS; here we compute it without adding a dependency).

Reference: FIRST CVSS v3.1 specification, section 7.1.
"""
from __future__ import annotations

import math

# Metric value tables. Privileges Required depends on Scope, handled in _pr().
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}

_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_ALLOWED = {
    "AV": set(_AV), "AC": set(_AC), "PR": {"N", "L", "H"}, "UI": set(_UI),
    "S": {"U", "C"}, "C": set(_IMPACT), "I": set(_IMPACT), "A": set(_IMPACT),
}


class CvssError(ValueError):
    """Raised when CVSS metrics are missing or invalid."""


def _roundup(value: float) -> float:
    """Official CVSS 3.1 roundup: ceil to one decimal with float-safety."""
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return (math.floor(int_input / 10_000) + 1) / 10.0


def severity_of(score: float) -> str:
    """Qualitative severity rating for a base score (CVSS 3.1 table)."""
    if score <= 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def normalize_metrics(metrics: dict) -> dict:
    """Uppercase + validate the 8 base metrics; raise CvssError on any problem."""
    out: dict[str, str] = {}
    for key in _METRICS:
        raw = metrics.get(key) or metrics.get(key.lower())
        if raw is None:
            raise CvssError(f"missing CVSS metric {key}")
        val = str(raw).strip().upper()
        if val not in _ALLOWED[key]:
            raise CvssError(f"invalid CVSS metric {key}={raw!r} (allowed: {sorted(_ALLOWED[key])})")
        out[key] = val
    return out


def base_score(metrics: dict) -> tuple[float, str, str]:
    """Compute (score, severity, vector) from the 8 base metrics.

    ``metrics`` keys: AV, AC, PR, UI, S, C, I, A (case-insensitive values).
    """
    m = normalize_metrics(metrics)
    scope_changed = m["S"] == "C"

    iss = 1 - (1 - _IMPACT[m["C"]]) * (1 - _IMPACT[m["I"]]) * (1 - _IMPACT[m["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]

    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        score = _roundup(min(impact + exploitability, 10.0))

    vector = "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in _METRICS)
    return score, severity_of(score), vector
