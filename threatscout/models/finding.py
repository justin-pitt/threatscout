"""Finding and Report — normalized output models."""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from threatscout.models.indicator import Indicator


class RiskLevel(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass
class Finding:
    """
    Normalized result from a single threat intelligence source.

    Each source adapter returns one of these. The report aggregates them.
    """
    source_name: str                        # e.g. "VirusTotal", "AbuseIPDB"
    indicator: Indicator
    risk_level: RiskLevel = RiskLevel.UNKNOWN

    # Common fields — populated when available
    detections: int | None = None           # e.g. 14 engines flagged it
    total_engines: int | None = None        # e.g. 92 total engines checked
    confidence: int | None = None           # 0-100 abuse/confidence score
    categories: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    country: str | None = None
    isp: str | None = None
    last_analysis: str | None = None
    pulse_count: int | None = None          # OTX pulses

    # CVE-specific fields
    cvss_score: float | None = None
    cvss_severity: str | None = None        # LOW / MEDIUM / HIGH / CRITICAL
    description: str | None = None
    published_date: str | None = None
    is_known_exploited: bool | None = None  # from CISA KEV

    # Raw source data for debugging / advanced use
    raw: dict = field(default_factory=dict, repr=False)

    # Error info if the source query failed
    error: str | None = None


@dataclass
class Report:
    """
    Aggregated report for a single indicator, combining findings from all sources.
    """
    indicator: Indicator
    findings: list[Finding] = field(default_factory=list)
    verdict: RiskLevel = RiskLevel.UNKNOWN
    verdict_confidence: int = 0             # 0-100
    query_time_seconds: float = 0.0
    sources_queried: int = 0
    sources_errored: int = 0
    resolved_ip: str | None = None          # DNS-resolved IP for domain/URL indicators

    def successful_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.error is None]

    def failed_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.error is not None]

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator": {"value": self.indicator.value, "type": self.indicator.type},
            "verdict": self.verdict,
            "verdict_confidence": self.verdict_confidence,
            "query_time_seconds": round(self.query_time_seconds, 2),
            "sources_queried": self.sources_queried,
            "sources_errored": self.sources_errored,
            "findings": [
                {
                    "source": f.source_name,
                    "risk_level": f.risk_level,
                    "detections": f.detections,
                    "total_engines": f.total_engines,
                    "confidence": f.confidence,
                    "categories": f.categories,
                    "tags": f.tags,
                    "malware_families": f.malware_families,
                    "country": f.country,
                    "isp": f.isp,
                    "cvss_score": f.cvss_score,
                    "cvss_severity": f.cvss_severity,
                    "description": f.description,
                    "is_known_exploited": f.is_known_exploited,
                    "error": f.error,
                }
                for f in self.findings
            ],
        }
