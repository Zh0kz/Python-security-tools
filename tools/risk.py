SEVERITY_WEIGHTS = {
    "INFO": 0,
    "LOW": 10,
    "MEDIUM": 25,
    "HIGH": 50,
    "CRITICAL": 100,
}

RISK_LEVELS = (
    (80, "CRITICAL"),
    (50, "HIGH"),
    (20, "MEDIUM"),
    (0, "LOW"),
)


def calculate_risk_score(findings):
    """
    Calculate an overall risk score from security findings.

    Args:
        findings: Iterable of finding dictionaries.

    Returns:
        int: Risk score between 0 and 100.
    """
    if not findings:
        return 0

    score = sum(
        SEVERITY_WEIGHTS.get(
            finding.get("risk", "INFO").upper(),
            0,
        )
        for finding in findings
    )

    return min(score, 100)


def get_risk_level(score):
    """
    Convert a numeric risk score into a risk level.

    Args:
        score: Numeric score between 0 and 100.

    Returns:
        str: LOW, MEDIUM, HIGH, or CRITICAL.
    """
    if not 0 <= score <= 100:
        raise ValueError(
            "Risk score must be between 0 and 100."
        )

    for minimum, level in RISK_LEVELS:
        if score >= minimum:
            return level

    return "LOW"


def calculate_risk(findings):
    """
    Calculate a complete risk assessment.

    Returns:
        dict: Risk score, level, and severity breakdown.
    """
    score = calculate_risk_score(findings)

    breakdown = {
        severity: 0
        for severity in SEVERITY_WEIGHTS
    }

    for finding in findings:
        severity = finding.get(
            "risk",
            "INFO",
        ).upper()

        if severity in breakdown:
            breakdown[severity] += 1

    return {
        "score": score,
        "level": get_risk_level(score),
        "breakdown": breakdown,
    }