"""
Scanner — orchestrates parallel queries across all configured sources.
"""

from __future__ import annotations
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from threatscout.models.indicator import Indicator, IndicatorType
from threatscout.models.finding import Finding, Report
from threatscout.sources.base import ThreatSource
from threatscout.enrichment.verdict import derive_verdict
from threatscout.enrichment.dns_resolver import resolve_to_ip, resolve_to_hostname

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
        start = time.monotonic()
        findings = []
        resolved_ip = None
        resolved_hostname = None

        if applicable:
            logger.info(f"Querying {len(applicable)} source(s) for {indicator.type} {indicator.value}")
            findings.extend(self._run_sources(applicable, indicator))

        # Forward DNS enrichment: for domains and URLs, resolve to IP and query IP sources
        if indicator.type in (IndicatorType.DOMAIN, IndicatorType.URL):
            resolved_ip = resolve_to_ip(indicator)
            if resolved_ip:
                logger.info(f"DNS resolved {indicator.value} -> {resolved_ip}, querying IP sources")
                ip_indicator = Indicator(resolved_ip, IndicatorType.IP)
                ip_applicable = [s for s in self._sources if s.supports(ip_indicator)]
                if ip_applicable:
                    findings.extend(self._run_sources(ip_applicable, ip_indicator))
            else:
                logger.warning(f"DNS enrichment skipped — could not resolve {indicator.value} to an IP address")

        # Reverse DNS enrichment: for IPs, resolve to hostname and query domain sources
        if indicator.type == IndicatorType.IP:
            resolved_hostname = resolve_to_hostname(indicator)
            if resolved_hostname:
                logger.info(f"Reverse DNS resolved {indicator.value} -> {resolved_hostname}, querying domain sources")
                domain_indicator = Indicator(resolved_hostname, IndicatorType.DOMAIN)
                domain_applicable = [s for s in self._sources if s.supports(domain_indicator)]
                if domain_applicable:
                    findings.extend(self._run_sources(domain_applicable, domain_indicator))
            else:
                logger.warning(f"Reverse DNS enrichment skipped — no PTR record for {indicator.value}")

        if not findings:
            logger.warning(f"No sources support indicator type: {indicator.type}")
            return Report(indicator=indicator, resolved_ip=resolved_ip, resolved_hostname=resolved_hostname)

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
            resolved_ip=resolved_ip,
            resolved_hostname=resolved_hostname,
        )

    def _run_sources(self, sources: list[ThreatSource], indicator: Indicator) -> list[Finding]:
        """Run a list of sources against an indicator in parallel."""
        findings = []
        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = {executor.submit(source.query, indicator): source for source in sources}
            for future in as_completed(futures):
                source = futures[future]
                try:
                    finding = future.result(timeout=30)
                    findings.append(finding)
                    logger.debug(f"  {source.name}: {finding.risk_level}")
                except Exception as e:
                    logger.warning(f"  {source.name}: unhandled error — {e}")
                    findings.append(Finding(
                        source_name=source.name,
                        indicator=indicator,
                        error=f"Unhandled error: {e}",
                    ))
        return findings
