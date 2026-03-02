"""
Scanner — orchestrates parallel queries across all configured sources.
"""

from __future__ import annotations
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from threatscout.models.indicator import Indicator
from threatscout.models.finding import Report
from threatscout.sources.base import ThreatSource
from threatscout.enrichment.verdict import derive_verdict

logger = logging.getLogger(__name__)


class Scanner:
    """
    Queries all applicable sources in parallel for a given indicator.

    Sources that don't support the indicator type are silently skipped.
    Individual source failures are caught and recorded — a single bad
    source never prevents results from the others.

    Usage:
        scanner = Scanner(sources=[VirusTotalSource(...), AbuseIPDBSource(...)])
        report = scanner.scan(Indicator.detect("1.2.3.4"))
    """

    def __init__(self, sources: list[ThreatSource], max_workers: int = 5) -> None:
        self._sources = sources
        self._max_workers = max_workers

    def scan(self, indicator: Indicator) -> Report:
        """Query all applicable sources and return a unified Report."""
        applicable = [s for s in self._sources if s.supports(indicator)]

        if not applicable:
            logger.warning(f"No sources support indicator type: {indicator.type}")
            return Report(indicator=indicator)

        logger.info(f"Querying {len(applicable)} source(s) for {indicator.type} {indicator.value}")
        start = time.monotonic()
        findings = []

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = {executor.submit(source.query, indicator): source for source in applicable}
            for future in as_completed(futures):
                source = futures[future]
                try:
                    finding = future.result(timeout=30)
                    findings.append(finding)
                    logger.debug(f"  {source.name}: {finding.risk_level}")
                except Exception as e:
                    from threatscout.models.finding import Finding
                    logger.warning(f"  {source.name}: unhandled error — {e}")
                    findings.append(Finding(
                        source_name=source.name,
                        indicator=indicator,
                        error=f"Unhandled error: {e}",
                    ))

        elapsed = time.monotonic() - start
        verdict, confidence = derive_verdict(findings)

        return Report(
            indicator=indicator,
            findings=findings,
            verdict=verdict,
            verdict_confidence=confidence,
            query_time_seconds=elapsed,
            sources_queried=len(applicable),
            sources_errored=len([f for f in findings if f.error]),
        )
