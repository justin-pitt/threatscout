"""
AbuseIPDB API v2 source.

Supports: IP only
Free tier: 1,000 requests/day
API key: https://www.abuseipdb.com/register
"""

from __future__ import annotations
import logging

import httpx

from threatscout.models.indicator import Indicator, IndicatorType
from threatscout.models.finding import Finding, RiskLevel
from threatscout.sources.base import ThreatSource

logger = logging.getLogger(__name__)

BASE_URL = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBSource(ThreatSource):
    """
    Queries AbuseIPDB for IP reputation based on community-submitted abuse reports.

    AbuseIPDB is especially useful for identifying IPs associated with
    brute force attacks, spam, and botnet activity.
    """

    supported_types = [IndicatorType.IP]

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    @property
    def name(self) -> str:
        return "AbuseIPDB"

    async def query(self, indicator: Indicator) -> Finding:
        try:
            async with httpx.AsyncClient(
                base_url=BASE_URL,
                headers={"Key": self._api_key, "Accept": "application/json"},
                timeout=15,
            ) as client:
                resp = await client.get("/check", params={
                    "ipAddress": indicator.value,
                    "maxAgeInDays": 90,
                    "verbose": True,
                })
            resp.raise_for_status()
            return self._normalize(indicator, resp.json())
        except Exception as e:
            logger.warning(f"AbuseIPDB query failed for {indicator}: {e}")
            return Finding(source_name=self.name, indicator=indicator, error=str(e))

    def _normalize(self, indicator: Indicator, data: dict) -> Finding:
        d = data.get("data", {})
        score = d.get("abuseConfidenceScore", 0)

        if score >= 80:
            risk = RiskLevel.MALICIOUS
        elif score >= 25:
            risk = RiskLevel.SUSPICIOUS
        else:
            risk = RiskLevel.CLEAN

        categories = _decode_categories(d.get("reports", []))

        return Finding(
            source_name=self.name,
            indicator=indicator,
            risk_level=risk,
            confidence=score,
            detections=d.get("totalReports", 0),
            country=d.get("countryCode"),
            isp=d.get("isp"),
            categories=list(set(categories)),
            tags=["tor"] if d.get("isTor") else [],
            raw=data,
        )


# AbuseIPDB category code → human readable label
_CATEGORY_MAP = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
    12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


def _decode_categories(reports: list) -> list[str]:
    seen = set()
    for report in reports:
        for code in report.get("categories", []):
            label = _CATEGORY_MAP.get(code)
            if label:
                seen.add(label)
    return list(seen)
