import pytest

from tools.risk import (
    calculate_risk,
    calculate_risk_score,
    get_risk_level,
)


def test_empty_findings():
    assert calculate_risk_score([]) == 0
    assert get_risk_level(0) == "LOW"


def test_single_high_finding():
    findings = [
        {"risk": "HIGH"},
    ]

    assert calculate_risk_score(findings) == 50
    assert get_risk_level(50) == "HIGH"


def test_multiple_findings():
    findings = [
        {"risk": "HIGH"},
        {"risk": "MEDIUM"},
        {"risk": "LOW"},
        {"risk": "INFO"},
    ]

    result = calculate_risk(findings)

    assert result["score"] == 85
    assert result["level"] == "CRITICAL"

    assert result["breakdown"] == {
        "INFO": 1,
        "LOW": 1,
        "MEDIUM": 1,
        "HIGH": 1,
        "CRITICAL": 0,
    }


def test_score_is_capped_at_100():
    findings = [
        {"risk": "CRITICAL"},
        {"risk": "CRITICAL"},
    ]

    assert calculate_risk_score(findings) == 100


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "LOW"),
        (19, "LOW"),
        (20, "MEDIUM"),
        (49, "MEDIUM"),
        (50, "HIGH"),
        (79, "HIGH"),
        (80, "CRITICAL"),
        (100, "CRITICAL"),
    ],
)
def test_risk_levels(score, expected):
    assert get_risk_level(score) == expected


@pytest.mark.parametrize(
    "score",
    [-1, 101],
)
def test_invalid_score(score):
    with pytest.raises(ValueError):
        get_risk_level(score)


def test_unknown_severity_is_ignored():
    findings = [
        {"risk": "UNKNOWN"},
        {"risk": "HIGH"},
    ]

    assert calculate_risk_score(findings) == 50