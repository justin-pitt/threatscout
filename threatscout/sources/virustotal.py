"""
VirusTotal API v3 source.

Supports: IP, domain, URL, file hash
Free tier: 4 requests/minute, 500/day
API key: https://www.virustotal.com/gui/join-us
"""

from __future__ import annotations
import base64
import logging

import httpx

from threatscout.models.indicator import Indicator, IndicatorType
from threatscout.models.finding import Finding, RiskLevel
from threatscout.sources.base import ThreatSource

logger = logging.getLogger(__name__)

BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalSource(ThreatSource):
    """
    Queries VirusTotal for malware scan results across 70+ AV engines.

    VirusTotal is most useful for file hashes (definitive malware verdicts)
    and IPs/domains (reputation and categorization data).
    """

    supported_types = [IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.URL, IndicatorType.HASH]

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    @property
    def name(self) -> str:
        return "VirusTotal"

    async def query(self, indicator: Indicator) -> Finding:
        try:
            path = self._get_path(indicator)
            async with httpx.AsyncClient(
                base_url=BASE_URL,
                headers={"x-apikey": self._api_key},
                timeout=15,
            ) as client:
                resp = await client.get(path)
            if resp.status_code == 404:
                return Finding(
                    source_name=self.name,
                    indicator=indicator,
                    risk_level=RiskLevel.UNKNOWN,
                    error="Indicator not found in VirusTotal database",
                )
            resp.raise_for_status()
            return self._normalize(indicator, resp.json())
        except Exception as e:
            logger.warning(f"VirusTotal query failed for {indicator}: {e}")
            return Finding(source_name=self.name, indicator=indicator, error=str(e))

    def _get_path(self, indicator: Indicator) -> str:
        if indicator.type == IndicatorType.IP:
            return f"/ip_addresses/{indicator.value}"
        elif indicator.type == IndicatorType.DOMAIN:
            return f"/domains/{indicator.value}"
        elif indicator.type == IndicatorType.HASH:
            return f"/files/{indicator.value}"
        elif indicator.type == IndicatorType.URL:
            url_id = base64.urlsafe_b64encode(indicator.value.encode()).rstrip(b"=").decode()
            return f"/urls/{url_id}"
        raise ValueError(f"Unsupported indicator type: {indicator.type}")

    def _normalize(self, indicator: Indicator, data: dict) -> Finding:
        attrs = data.get("data", {}).get("attributes", {})

        # Last analysis stats
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        # Determine risk level
        if malicious >= 5 or (malicious + suspicious) >= 10:
            risk = RiskLevel.MALICIOUS
        elif malicious > 0 or suspicious > 0:
            risk = RiskLevel.SUSPICIOUS
        elif total > 0:
            risk = RiskLevel.CLEAN
        else:
            risk = RiskLevel.UNKNOWN

        # Categories (varies by indicator type)
        categories = list(set(attrs.get("categories", {}).values()))

        # Tags
        tags = attrs.get("tags", [])

        # Last analysis date — flag results older than 6 months as stale
        last_analysis_ts = attrs.get("last_analysis_date")
        last_analysis = None
        if last_analysis_ts:
            from datetime import datetime, timezone
            last_analysis_dt = datetime.fromtimestamp(last_analysis_ts, tz=timezone.utc)
            last_analysis = last_analysis_dt.strftime("%Y-%m-%d")
            age_days = (datetime.now(timezone.utc) - last_analysis_dt).days
            if age_days > 180:
                tags = list(tags) + [f"stale-analysis ({age_days}d old)"]

        return Finding(
            source_name=self.name,
            indicator=indicator,
            risk_level=risk,
            detections=malicious + suspicious,
            total_engines=total,
            categories=categories,
            tags=tags,
            country=attrs.get("country"),
            last_analysis=last_analysis,
            raw=data,
        )
