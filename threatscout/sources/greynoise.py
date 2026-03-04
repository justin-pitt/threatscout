"""
GreyNoise Community source.

Supports: IP
Free community API key: https://viz.greynoise.io/signup
API docs: https://docs.greynoise.io/reference/get_v3-community-ip

Classifies IPs as internet background noise, known benign services, or targeted threats.
"""

from __future__ import annotations
import json
import logging
import urllib.request
import urllib.error

from threatscout.models.indicator import Indicator, IndicatorType
from threatscout.models.finding import Finding, RiskLevel
from threatscout.sources.base import ThreatSource

logger = logging.getLogger(__name__)

BASE_URL = "https://api.greynoise.io/v3/community"


class GreyNoiseSource(ThreatSource):
    """
    Queries GreyNoise to classify internet background noise vs targeted threats.
    RIOT IPs (Google, Cloudflare, etc.) are flagged as benign.
    Mass scanners are flagged as suspicious.
    Free community API key required.
    """

    supported_types = [IndicatorType.IP]

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    @property
    def name(self) -> str:
        return "GreyNoise"

    def query(self, indicator: Indicator) -> Finding:
        try:
            req = urllib.request.Request(
                f"{BASE_URL}/{indicator.value}",
                headers={"key": self._api_key, "User-Agent": "threatscout/1.0"},
            )
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read())
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return Finding(
                        source_name=self.name,
                        indicator=indicator,
                        risk_level=RiskLevel.UNKNOWN,
                        description="IP not observed by GreyNoise",
                    )
                raise
            return self._normalize(indicator, data)
        except Exception as e:
            logger.warning(f"GreyNoise query failed for {indicator}: {e}")
            return Finding(source_name=self.name, indicator=indicator, error=str(e))

    def _normalize(self, indicator: Indicator, data: dict) -> Finding:
        noise = data.get("noise", False)
        riot = data.get("riot", False)
        classification = data.get("classification", "unknown")
        name = data.get("name", "")
        last_seen = (data.get("last_seen") or "")[:10] or None

        tags = []
        if noise:
            tags.append("internet-scanner")
        if riot:
            tags.append("known-benign-service")
        if name:
            tags.append(name)

        if classification == "malicious":
            risk = RiskLevel.MALICIOUS
        elif riot:
            # RIOT = Reliable Intelligence on Trusted IPs (known good)
            risk = RiskLevel.CLEAN
        elif noise:
            risk = RiskLevel.SUSPICIOUS
        else:
            risk = RiskLevel.UNKNOWN

        desc_parts = []
        if noise:
            desc_parts.append("Mass internet scanner")
        if riot:
            desc_parts.append("Known benign service")
        if name:
            desc_parts.append(f"Name: {name}")
        description = " | ".join(desc_parts) if desc_parts else None

        return Finding(
            source_name=self.name,
            indicator=indicator,
            risk_level=risk,
            tags=tags,
            last_analysis=last_seen,
            description=description,
        )
