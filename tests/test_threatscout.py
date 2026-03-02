"""Tests for ThreatScout core logic."""

from __future__ import annotations
import pytest
import responses as rsps_lib
from unittest.mock import MagicMock, patch

from threatscout.models.indicator import Indicator, IndicatorType
from threatscout.models.finding import Finding, RiskLevel, Report
from threatscout.enrichment.verdict import derive_verdict
from threatscout.scanner import Scanner


# ── Indicator Detection ───────────────────────────────────────────────────────

class TestIndicatorDetect:
    def test_detects_ipv4(self):
        i = Indicator.detect("1.2.3.4")
        assert i.type == IndicatorType.IP

    def test_detects_cve(self):
        i = Indicator.detect("CVE-2021-44228")
        assert i.type == IndicatorType.CVE
        assert i.value == "CVE-2021-44228"

    def test_detects_cve_case_insensitive(self):
        i = Indicator.detect("cve-2021-44228")
        assert i.type == IndicatorType.CVE
        assert i.value == "CVE-2021-44228"

    def test_detects_md5_hash(self):
        i = Indicator.detect("d41d8cd98f00b204e9800998ecf8427e")
        assert i.type == IndicatorType.HASH

    def test_detects_sha256_hash(self):
        i = Indicator.detect("a" * 64)
        assert i.type == IndicatorType.HASH

    def test_detects_domain(self):
        i = Indicator.detect("evil.example.com")
        assert i.type == IndicatorType.DOMAIN


# ── Verdict Engine ────────────────────────────────────────────────────────────

class TestVerdictEngine:
    def _finding(self, source: str, risk: RiskLevel, **kwargs) -> Finding:
        return Finding(
            source_name=source,
            indicator=Indicator("1.2.3.4", IndicatorType.IP),
            risk_level=risk,
            **kwargs,
        )

    def test_malicious_finding_returns_malicious(self):
        findings = [self._finding("VirusTotal", RiskLevel.MALICIOUS)]
        verdict, confidence = derive_verdict(findings)
        assert verdict == RiskLevel.MALICIOUS
        assert confidence > 0

    def test_all_clean_returns_clean(self):
        findings = [
            self._finding("VirusTotal", RiskLevel.CLEAN),
            self._finding("AbuseIPDB", RiskLevel.CLEAN),
        ]
        verdict, _ = derive_verdict(findings)
        assert verdict == RiskLevel.CLEAN

    def test_suspicious_with_no_malicious_returns_suspicious(self):
        findings = [self._finding("AbuseIPDB", RiskLevel.SUSPICIOUS)]
        verdict, _ = derive_verdict(findings)
        assert verdict == RiskLevel.SUSPICIOUS

    def test_empty_findings_returns_unknown(self):
        verdict, confidence = derive_verdict([])
        assert verdict == RiskLevel.UNKNOWN
        assert confidence == 0

    def test_all_errors_returns_unknown(self):
        findings = [
            Finding(
                source_name="VirusTotal",
                indicator=Indicator("1.2.3.4", IndicatorType.IP),
                error="Connection timeout",
            )
        ]
        verdict, _ = derive_verdict(findings)
        assert verdict == RiskLevel.UNKNOWN

    def test_cisa_kev_boosts_confidence(self):
        findings = [
            self._finding("CISA KEV", RiskLevel.MALICIOUS, is_known_exploited=True),
            self._finding("NVD (NIST)", RiskLevel.MALICIOUS, cvss_score=9.8),
        ]
        verdict, confidence = derive_verdict(findings)
        assert verdict == RiskLevel.MALICIOUS
        assert confidence >= 80


# ── Scanner ───────────────────────────────────────────────────────────────────

class TestScanner:
    def _make_mock_source(self, name: str, supported_types, risk: RiskLevel):
        source = MagicMock()
        source.name = name
        source.supports = lambda i: i.type in supported_types
        source.query.return_value = Finding(
            source_name=name,
            indicator=MagicMock(),
            risk_level=risk,
        )
        return source

    def test_scanner_queries_applicable_sources_only(self):
        ip_source = self._make_mock_source("IPSource", [IndicatorType.IP], RiskLevel.CLEAN)
        cve_source = self._make_mock_source("CVESource", [IndicatorType.CVE], RiskLevel.UNKNOWN)

        scanner = Scanner(sources=[ip_source, cve_source])
        indicator = Indicator("1.2.3.4", IndicatorType.IP)
        report = scanner.scan(indicator)

        ip_source.query.assert_called_once()
        cve_source.query.assert_not_called()
        assert report.sources_queried == 1

    def test_scanner_handles_source_error_gracefully(self):
        bad_source = MagicMock()
        bad_source.name = "BadSource"
        bad_source.supports = lambda i: True
        bad_source.query.side_effect = RuntimeError("Network down")

        scanner = Scanner(sources=[bad_source])
        indicator = Indicator("1.2.3.4", IndicatorType.IP)
        report = scanner.scan(indicator)

        # Should not raise — should record the error in the finding
        assert report.sources_errored == 1

    def test_report_no_sources_returns_empty(self):
        scanner = Scanner(sources=[])
        report = scanner.scan(Indicator("1.2.3.4", IndicatorType.IP))
        assert report.sources_queried == 0
        assert report.verdict == RiskLevel.UNKNOWN
