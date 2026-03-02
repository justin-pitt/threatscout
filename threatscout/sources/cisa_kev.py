"""
CISA Known Exploited Vulnerabilities (KEV) Catalog source.

Supports: CVE only
Free tier: No API key required — public JSON feed
Data: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

The KEV catalog is maintained by CISA and lists CVEs that have confirmed,
real-world exploitation. If a CVE appears here, it's actively being exploited
in the wild — this is the highest-confidence signal for prioritizing patching.
"""

from __future__ import annotations
import json
import logging
import time
import urllib.request
from threading import Lock

from threatscout.models.indicator import Indicator, IndicatorType
from threatscout.models.finding import Finding, RiskLevel
from threatscout.sources.base import ThreatSource

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Cache the KEV catalog in memory for the lifetime of the process
# so we only download it once per run even if querying multiple CVEs
_kev_cache: dict[str, dict] | None = None
_kev_cache_lock = Lock()
_kev_cache_time: float = 0.0
_KEV_CACHE_TTL = 3600  # 1 hour


class CISAKevSource(ThreatSource):
    """
    Checks whether a CVE appears in CISA's Known Exploited Vulnerabilities catalog.

    A match here means the vulnerability has confirmed active exploitation in the wild.
    This source requires no API key and is rate-limit-free.
    """

    supported_types = [IndicatorType.CVE]

    @property
    def name(self) -> str:
        return "CISA KEV"

    def query(self, indicator: Indicator) -> Finding:
        try:
            catalog = self._get_catalog()
            entry = catalog.get(indicator.value.upper())

            if entry:
                return Finding(
                    source_name=self.name,
                    indicator=indicator,
                    risk_level=RiskLevel.MALICIOUS,
                    is_known_exploited=True,
                    description=f"Actively exploited. Required action: {entry.get('requiredAction', 'See CISA advisory')}",
                    published_date=entry.get("dateAdded"),
                    tags=["actively-exploited", "cisa-kev"],
                    categories=[entry.get("vendorProject", ""), entry.get("product", "")],
                    raw=entry,
                )
            else:
                return Finding(
                    source_name=self.name,
                    indicator=indicator,
                    risk_level=RiskLevel.UNKNOWN,
                    is_known_exploited=False,
                    description="Not found in CISA Known Exploited Vulnerabilities catalog",
                )

        except Exception as e:
            logger.warning(f"CISA KEV query failed: {e}")
            return Finding(source_name=self.name, indicator=indicator, error=str(e))

    def _get_catalog(self) -> dict[str, dict]:
        """Download and cache the KEV catalog, indexed by CVE ID."""
        global _kev_cache, _kev_cache_time

        with _kev_cache_lock:
            if _kev_cache is not None and (time.time() - _kev_cache_time) < _KEV_CACHE_TTL:
                return _kev_cache

            logger.info("Downloading CISA KEV catalog...")
            with urllib.request.urlopen(KEV_URL, timeout=15) as resp:
                data = json.loads(resp.read().decode())

            _kev_cache = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
            _kev_cache_time = time.time()
            logger.info(f"CISA KEV: loaded {len(_kev_cache)} entries")
            return _kev_cache
