"""
Verdict engine — derives an overall risk verdict from all findings.
"""

from threatscout.models.finding import Finding, RiskLevel, Report


def derive_verdict(findings: list[Finding]) -> tuple[RiskLevel, int]:
    """
    Derive an overall verdict and confidence score from a list of findings.

    Strategy:
      - Any MALICIOUS finding → overall MALICIOUS (confidence = max of malicious sources)
      - Any SUSPICIOUS with no MALICIOUS → SUSPICIOUS
      - All CLEAN → CLEAN
      - All UNKNOWN / errors → UNKNOWN

    Returns:
        (RiskLevel, confidence_0_to_100)
    """
    successful = [f for f in findings if f.error is None]
    if not successful:
        return RiskLevel.UNKNOWN, 0

    malicious = [f for f in successful if f.risk_level == RiskLevel.MALICIOUS]
    suspicious = [f for f in successful if f.risk_level == RiskLevel.SUSPICIOUS]
    clean = [f for f in successful if f.risk_level == RiskLevel.CLEAN]

    if malicious:
        # Confidence = percentage of queried sources that agree it's malicious
        confidence = int((len(malicious) / len(successful)) * 100)
        # Boost confidence if AbuseIPDB score is very high
        for f in malicious:
            if f.source_name == "AbuseIPDB" and f.confidence and f.confidence >= 90:
                confidence = min(100, confidence + 20)
            if f.source_name == "VirusTotal" and f.detections and f.detections >= 10:
                confidence = min(100, confidence + 15)
            if f.source_name == "CISA KEV" and f.is_known_exploited:
                confidence = min(100, confidence + 30)
        return RiskLevel.MALICIOUS, min(confidence, 99)

    if suspicious:
        confidence = int((len(suspicious) / len(successful)) * 60)
        return RiskLevel.SUSPICIOUS, confidence

    if clean:
        return RiskLevel.CLEAN, int((len(clean) / len(successful)) * 100)

    return RiskLevel.UNKNOWN, 0
