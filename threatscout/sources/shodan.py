"""
Shodan source.

Supports: IP
API key required: https://account.shodan.io/ (paid plan for full access)
API docs: https://developer.shodan.io/api

Shows open ports, exposed services, and known CVEs for a host.
"""

from __future__ import annotations
import json
import logging
import urllib.request
import urllib.error
import urllib.parse

from threatscout.models.indicator import Indicator, IndicatorType
from threatscout.models.finding import Finding, RiskLevel
from threatscout.sources.base import ThreatSource

logger = logging.getLogger(__name__)

BASE_URL = "https://api.shodan.io/shodan/host"


class ShodanSource(ThreatSource):
    """
    Queries Shodan for open ports, banners, and vulnerabilities on a host.
    Shows what services are exposed to the internet and flags known CVEs.
    Paid API key required.
    """

    supported_types = [IndicatorType.IP]

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    @property
    def name(self) -> str:
        return "Shodan"

    def query(self, indicator: Indicator) -> Finding:
        try:
            url = f"{BASE_URL}/{indicator.value}?key={urllib.parse.quote(self._api_key)}"
            req = urllib.request.Request(url, headers={"User-Agent": "threatscout/1.0"})
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read())
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    return Finding(
                        source_name=self.name,
                        indicator=indicator,
                        error="Invalid or insufficient Shodan API key",
                    )
                if e.code == 404:
                    return Finding(
                        source_name=self.name,
                        indicator=indicator,
                        risk_level=RiskLevel.UNKNOWN,
                        description="IP not found in Shodan",
                    )
                raise
            return self._normalize(indicator, data)
        except Exception as e:
            logger.warning(f"Shodan query failed for {indicator}: {e}")
            return Finding(source_name=self.name, indicator=indicator, error=str(e))

    def _normalize(self, indicator: Indicator, data: dict) -> Finding:
        ports = sorted(data.get("ports", []))
        tags = list(data.get("tags", []))
        vulns = list(data.get("vulns", {}).keys())
        org = data.get("org", "")
        isp = data.get("isp", "")
        country = data.get("country_code", "") or None
        last_update = (data.get("last_update") or "")[:10] or None

        if ports:
            tags.append(f"ports: {', '.join(str(p) for p in ports[:10])}")
        for cve in vulns[:5]:
            tags.append(cve)

        risk = RiskLevel.SUSPICIOUS if vulns else RiskLevel.UNKNOWN

        desc_parts = []
        if org:
            desc_parts.append(f"Org: {org}")
        if ports:
            desc_parts.append(f"{len(ports)} open port(s)")
        if vulns:
            desc_parts.append(f"{len(vulns)} known CVE(s)")
        description = " | ".join(desc_parts) if desc_parts else None

        return Finding(
            source_name=self.name,
            indicator=indicator,
            risk_level=risk,
            country=country,
            isp=isp or None,
            tags=tags,
            last_analysis=last_update,
            description=description,
        )
