"""
NIST National Vulnerability Database (NVD) CVE API v2 source.

Supports: CVE only
Free tier: 50 req/30s with API key, 5 req/30s without
API key: https://nvd.nist.gov/developers/request-an-api-key (free, instant)
"""

from __future__ import annotations
import logging

from restlink import ApiClient, ApiKeyAuth, RetryConfig, RateLimitConfig

from threatscout.models.indicator import Indicator, IndicatorType
from threatscout.models.finding import Finding, RiskLevel
from threatscout.sources.base import ThreatSource

logger = logging.getLogger(__name__)

BASE_URL = "https://services.nvd.nist.gov/rest/json"


class NVDSource(ThreatSource):
    """
    Queries the NIST NVD for official CVE data including CVSS scores,
    descriptions, affected products, and references.

    This is the authoritative source for vulnerability severity data.
    """

    supported_types = [IndicatorType.CVE]

    def __init__(self, api_key: str | None = None) -> None:
        # NVD supports no-key access but at a much lower rate limit
        auth = ApiKeyAuth(key=api_key, header="apiKey") if api_key else _NoAuth()
        rate = RateLimitConfig(requests_per_second=1.5, burst=5) if api_key \
            else RateLimitConfig(requests_per_second=0.15, burst=2)

        self._client = ApiClient(
            base_url=BASE_URL,
            auth=auth,
            rate_limit=rate,
            retry=RetryConfig(max_attempts=3),
        )

    @property
    def name(self) -> str:
        return "NVD (NIST)"

    def query(self, indicator: Indicator) -> Finding:
        try:
            response = self._client.get("/cves/2.0", params={"cveId": indicator.value})
            vulns = response.data.get("vulnerabilities", [])
            if not vulns:
                return Finding(
                    source_name=self.name,
                    indicator=indicator,
                    risk_level=RiskLevel.UNKNOWN,
                    error="CVE not found in NVD",
                )
            return self._normalize(indicator, vulns[0])
        except Exception as e:
            logger.warning(f"NVD query failed for {indicator}: {e}")
            return Finding(source_name=self.name, indicator=indicator, error=str(e))

    def _normalize(self, indicator: Indicator, data: dict) -> Finding:
        cve = data.get("cve", {})

        # Description (prefer English)
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )

        # CVSS score — prefer v3.1, fall back to v3.0, then v2
        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_severity = None

        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity") or \
                                metric_list[0].get("baseSeverity")
                break

        risk = _cvss_to_risk(cvss_score)

        return Finding(
            source_name=self.name,
            indicator=indicator,
            risk_level=risk,
            cvss_score=cvss_score,
            cvss_severity=cvss_severity,
            description=description[:300] + "..." if len(description) > 300 else description,
            published_date=cve.get("published", "")[:10],
            raw=data,
        )


def _cvss_to_risk(score: float | None) -> RiskLevel:
    if score is None:
        return RiskLevel.UNKNOWN
    if score >= 9.0:
        return RiskLevel.MALICIOUS   # Critical
    if score >= 7.0:
        return RiskLevel.MALICIOUS   # High
    if score >= 4.0:
        return RiskLevel.SUSPICIOUS  # Medium
    return RiskLevel.CLEAN           # Low


class _NoAuth:
    """Placeholder auth for NVD when no key is provided."""
    def apply(self, session) -> None:
        pass
