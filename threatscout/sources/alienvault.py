"""
AlienVault OTX (Open Threat Exchange) source.

Supports: IP, domain, URL, hash
Free tier: Unlimited (requires free account)
API key: https://otx.alienvault.com/accounts/register
"""

from __future__ import annotations
import logging

import httpx

from threatscout.models.indicator import Indicator, IndicatorType
from threatscout.models.finding import Finding, RiskLevel
from threatscout.sources.base import ThreatSource

logger = logging.getLogger(__name__)

BASE_URL = "https://otx.alienvault.com/api/v1"


class AlienVaultOTXSource(ThreatSource):
    """
    Queries AlienVault OTX for community threat intelligence pulses.

    OTX is a crowd-sourced platform where security researchers share
    indicators of compromise (IOCs). It's particularly good for context —
    malware family names, threat actor associations, and campaign tags.
    """

    supported_types = [IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.URL, IndicatorType.HASH]

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    @property
    def name(self) -> str:
        return "AlienVault OTX"

    async def query(self, indicator: Indicator) -> Finding:
        try:
            section = "general"
            path = f"/indicators/{self._type_path(indicator)}/{indicator.value}/{section}"
            async with httpx.AsyncClient(
                base_url=BASE_URL,
                headers={"X-OTX-API-KEY": self._api_key},
                timeout=15,
            ) as client:
                resp = await client.get(path)
            resp.raise_for_status()
            return self._normalize(indicator, resp.json())
        except Exception as e:
            logger.warning(f"OTX query failed for {indicator}: {e}")
            return Finding(source_name=self.name, indicator=indicator, error=str(e))

    def _type_path(self, indicator: Indicator) -> str:
        return {
            IndicatorType.IP: "IPv4",
            IndicatorType.DOMAIN: "domain",
            IndicatorType.URL: "url",
            IndicatorType.HASH: "file",
        }[indicator.type]

    def _normalize(self, indicator: Indicator, data: dict) -> Finding:
        pulse_info = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)

        # Collect all tags and malware families from pulses
        tags: set[str] = set()
        malware_families: set[str] = set()
        for pulse in pulse_info.get("pulses", []):
            tags.update(pulse.get("tags", []))
            for mw in pulse.get("malware_families", []):
                name = mw.get("display_name") or mw.get("id", "")
                if name:
                    malware_families.add(name)

        # Risk based on pulse count
        if pulse_count >= 5:
            risk = RiskLevel.MALICIOUS
        elif pulse_count >= 1:
            risk = RiskLevel.SUSPICIOUS
        else:
            risk = RiskLevel.UNKNOWN

        return Finding(
            source_name=self.name,
            indicator=indicator,
            risk_level=risk,
            pulse_count=pulse_count,
            tags=list(tags)[:10],                       # cap for display
            malware_families=list(malware_families),
            country=data.get("country_name"),
            raw=data,
        )
