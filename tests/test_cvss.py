"""Tests for the pure-stdlib CVSS 3.1 base-score implementation."""
from __future__ import annotations

import pytest

from muhgpt.cvss import CvssError, base_score, severity_of

# Official CVSS 3.1 reference vectors (score, severity).
REFERENCE = [
    (dict(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"), 9.8, "Critical"),
    (dict(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"), 6.1, "Medium"),
    (dict(AV="N", AC="L", PR="L", UI="N", S="U", C="H", I="N", A="N"), 6.5, "Medium"),
    (dict(AV="L", AC="H", PR="H", UI="R", S="U", C="N", I="N", A="N"), 0.0, "None"),
    (dict(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="L", A="N"), 5.3, "Medium"),
    (dict(AV="P", AC="H", PR="H", UI="R", S="U", C="L", I="L", A="L"), 3.5, "Low"),
]


@pytest.mark.parametrize("metrics,score,severity", REFERENCE)
def test_reference_vectors(metrics, score, severity):
    got_score, got_sev, vector = base_score(metrics)
    assert got_score == score, f"{vector}: expected {score}, got {got_score}"
    assert got_sev == severity


def test_vector_string_and_case_insensitivity():
    lower = dict(av="n", ac="l", pr="n", ui="n", s="u", c="h", i="h", a="h")
    score, sev, vector = base_score(lower)
    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert (score, sev) == (9.8, "Critical")


def test_severity_bands():
    assert severity_of(0.0) == "None"
    assert severity_of(3.9) == "Low"
    assert severity_of(4.0) == "Medium"
    assert severity_of(6.9) == "Medium"
    assert severity_of(7.0) == "High"
    assert severity_of(8.9) == "High"
    assert severity_of(9.0) == "Critical"


def test_invalid_metrics_raise():
    with pytest.raises(CvssError):
        base_score(dict(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H"))  # missing A
    with pytest.raises(CvssError):
        base_score(dict(AV="X", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"))  # bad AV
