"""
WHOIS source.

Supports: domain
Free: no API key required (uses WHOIS protocol directly)
Requires: pip install python-whois
"""

from __future__ import annotations
import logging
from datetime import datetime, timezone

from threatscout.models.indicator import Indicator, IndicatorType
from threatscout.models.finding import Finding, RiskLevel
from threatscout.sources.base import ThreatSource

logger = logging.getLogger(__name__)

# Flag domains registered within this many days as suspicious
_NEW_DOMAIN_THRESHOLD_DAYS = 30


class WHOISSource(ThreatSource):
    """
    Queries WHOIS records for domain registration information.
    Flags recently registered domains (< 30 days) as suspicious.
    No API key required.
    """

    supported_types = [IndicatorType.DOMAIN]

    @property
    def name(self) -> str:
        return "WHOIS"

    def query(self, indicator: Indicator) -> Finding:
        try:
            import whois
        except ImportError:
            return Finding(
                source_name=self.name,
                indicator=indicator,
                error="python-whois not installed. Run: pip install python-whois",
            )
        try:
            w = whois.whois(indicator.value)
            return self._normalize(indicator, w)
        except Exception as e:
            logger.warning(f"WHOIS query failed for {indicator}: {e}")
            return Finding(source_name=self.name, indicator=indicator, error=str(e))

    def _normalize(self, indicator: Indicator, w) -> Finding:
        if not w or not w.domain_name:
            return Finding(
                source_name=self.name,
                indicator=indicator,
                risk_level=RiskLevel.UNKNOWN,
                description="No WHOIS record found",
            )

        registrar = w.registrar or "Unknown"
        country = w.country or None

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        creation_str = creation.strftime("%Y-%m-%d") if creation else "Unknown"

        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        expiry_str = expiry.strftime("%Y-%m-%d") if expiry else "Unknown"

        ns = w.name_servers or []
        if isinstance(ns, str):
            ns = [ns]
        ns_str = ", ".join(sorted({n.lower() for n in ns})[:4]) if ns else "Unknown"

        tags = []
        risk = RiskLevel.UNKNOWN

        if creation:
            try:
                now = datetime.now(timezone.utc)
                if hasattr(creation, "tzinfo") and creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                age_days = (now - creation).days
                if age_days < _NEW_DOMAIN_THRESHOLD_DAYS:
                    risk = RiskLevel.SUSPICIOUS
                    tags.append(f"newly-registered ({age_days}d old)")
                else:
                    risk = RiskLevel.CLEAN
            except Exception:
                pass

        description = (
            f"Registrar: {registrar} | "
            f"Created: {creation_str} | "
            f"Expires: {expiry_str} | "
            f"NS: {ns_str}"
        )

        return Finding(
            source_name=self.name,
            indicator=indicator,
            risk_level=risk,
            country=country,
            tags=tags,
            description=description,
        )
