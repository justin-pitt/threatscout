"""
URLScan.io source.

Supports: IP, domain, URL
Free tier: no API key required for search queries
API: https://urlscan.io/docs/api/
"""

from __future__ import annotations
import logging

import httpx

from threatscout.models.indicator import Indicator, IndicatorType
from threatscout.models.finding import Finding, RiskLevel
from threatscout.sources.base import ThreatSource

logger = logging.getLogger(__name__)

BASE_URL = "https://urlscan.io/api/v1/search/"


class URLScanSource(ThreatSource):
    """
    Queries URLScan.io for historical web scan results.
    Returns malicious verdicts, tags, and scan history for IPs, domains, and URLs.
    No API key required for search.
    """

    supported_types = [IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.URL]

    @property
    def name(self) -> str:
        return "URLScan.io"

    async def query(self, indicator: Indicator) -> Finding:
        try:
            q = self._build_query(indicator)
            async with httpx.AsyncClient(
                headers={"User-Agent": "threatscout/1.0"},
                timeout=15,
            ) as client:
                resp = await client.get(BASE_URL, params={"q": q, "size": 10})
            resp.raise_for_status()
            return self._normalize(indicator, resp.json())
        except Exception as e:
            logger.warning(f"URLScan query failed for {indicator}: {e}")
            return Finding(source_name=self.name, indicator=indicator, error=str(e))

    def _build_query(self, indicator: Indicator) -> str:
        if indicator.type == IndicatorType.IP:
            return f"ip:{indicator.value}"
        if indicator.type == IndicatorType.DOMAIN:
            return f"domain:{indicator.value}"
        if indicator.type == IndicatorType.URL:
            return f'page.url:"{indicator.value}"'
        return indicator.value

    def _normalize(self, indicator: Indicator, data: dict) -> Finding:
        results = data.get("results", [])
        total = data.get("total", 0)

        if not results:
            return Finding(
                source_name=self.name,
                indicator=indicator,
                risk_level=RiskLevel.UNKNOWN,
                description="No URLScan results found",
            )

        malicious_count = 0
        all_tags: set[str] = set()
        last_seen = None

        for r in results:
            verdicts = r.get("verdicts", {}).get("overall", {})
            if verdicts.get("malicious"):
                malicious_count += 1
            for tag in verdicts.get("tags", []):
                all_tags.add(tag)
            task_time = r.get("task", {}).get("time", "")
            if task_time and (last_seen is None or task_time > last_seen):
                last_seen = task_time[:10]

        risk = RiskLevel.MALICIOUS if malicious_count > 0 else RiskLevel.CLEAN

        return Finding(
            source_name=self.name,
            indicator=indicator,
            risk_level=risk,
            detections=malicious_count,
            total_engines=len(results),
            tags=list(all_tags)[:10],
            last_analysis=last_seen,
            description=f"{total} total scan(s) found",
        )
