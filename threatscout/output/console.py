"""
Console output — renders a Report to the terminal using Rich.
"""

from __future__ import annotations
import csv
import io
import logging
import os
import sys

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text

from threatscout.models.finding import Report, Finding, RiskLevel

_RISK_ORDER = {
    RiskLevel.CLEAN: 0,
    RiskLevel.UNKNOWN: 1,
    RiskLevel.SUSPICIOUS: 2,
    RiskLevel.MALICIOUS: 3,
    RiskLevel.ERROR: -1,
}

_MIN_RISK_THRESHOLD = {
    "clean": _RISK_ORDER[RiskLevel.CLEAN],
    "suspicious": _RISK_ORDER[RiskLevel.SUSPICIOUS],
    "malicious": _RISK_ORDER[RiskLevel.MALICIOUS],
}

console = Console(legacy_windows=False)

_RISK_COLOR = {
    RiskLevel.MALICIOUS: "bold red",
    RiskLevel.SUSPICIOUS: "bold yellow",
    RiskLevel.CLEAN: "bold green",
    RiskLevel.UNKNOWN: "dim white",
    RiskLevel.ERROR: "dim red",
}

_RISK_ICON = {
    RiskLevel.MALICIOUS: "🔴",
    RiskLevel.SUSPICIOUS: "🟡",
    RiskLevel.CLEAN: "🟢",
    RiskLevel.UNKNOWN: "⚪",
    RiskLevel.ERROR: "❌",
}


def _filter_findings(findings: list[Finding], min_risk: str | None) -> list[Finding]:
    """Filter findings to those at or above the minimum risk threshold."""
    if not min_risk:
        return findings
    threshold = _MIN_RISK_THRESHOLD.get(min_risk.lower(), 0)
    return [f for f in findings if _RISK_ORDER.get(f.risk_level, -1) >= threshold]


def render_report(report: Report, min_risk: str | None = None) -> None:
    """Render a full report to the terminal."""

    # ── Header panel ──────────────────────────────────────────────────────────
    verdict_icon = _RISK_ICON.get(report.verdict, "⚪")
    verdict_color = _RISK_COLOR.get(report.verdict, "white")
    verdict_text = f"{verdict_icon}  {report.verdict.upper()}"
    if report.verdict_confidence > 0:
        verdict_text += f"  (confidence: {report.verdict_confidence}%)"

    resolved_line = ""
    if report.resolved_ip:
        resolved_line += f"\n[bold]Resolved IP:      [/bold] {report.resolved_ip}"
    if report.resolved_hostname:
        resolved_line += f"\n[bold]Resolved Hostname:[/bold] {report.resolved_hostname}"
    header = (
        f"[bold]Indicator:[/bold]  {report.indicator.value}  "
        f"[dim]({report.indicator.type})[/dim]"
        f"{resolved_line}\n"
        f"[bold]Verdict:  [/bold]  [{verdict_color}]{verdict_text}[/{verdict_color}]"
    )
    console.print(Panel(header, title="[bold cyan]ThreatScout Report[/bold cyan]", expand=False))
    console.print()

    # ── Per-source findings, grouped by indicator ─────────────────────────────
    # Group findings by indicator value so enriched indicators get their own section
    visible_findings = _filter_findings(report.findings, min_risk)
    seen: dict[str, list] = {}
    for f in visible_findings:
        seen.setdefault(f.indicator.value, []).append(f)

    # Original indicator first, then any enriched indicators in insertion order
    ordered_keys = [report.indicator.value] + [
        k for k in seen if k != report.indicator.value
    ]

    for key in ordered_keys:
        group = seen.get(key, [])
        if not group:
            continue
        ind = group[0].indicator
        if ind.value != report.indicator.value:
            console.print(
                f"[bold dim]── Enriched: {ind.type.upper()} {ind.value} ──[/bold dim]"
            )
            console.print()
        for finding in sorted(group, key=lambda f: f.source_name):
            _render_finding(finding)

    # ── Footer ────────────────────────────────────────────────────────────────
    console.print(
        f"[dim]Sources queried: {report.sources_queried}  |  "
        f"Errors: {report.sources_errored}  |  "
        f"Query time: {report.query_time_seconds:.1f}s[/dim]"
    )


def _render_finding(f: Finding) -> None:
    risk_color = _RISK_COLOR.get(f.risk_level, "white")
    risk_icon = _RISK_ICON.get(f.risk_level, "⚪")

    title = f"[bold]{f.source_name}[/bold]  {risk_icon} [{risk_color}]{f.risk_level.upper()}[/{risk_color}]"
    console.print(f"  {title}")

    if f.error:
        console.print(f"    [red]Error: {f.error}[/red]")
        console.print()
        return

    rows = []

    if f.detections is not None and f.total_engines:
        rows.append(("Detections", f"{f.detections} / {f.total_engines} engines"))
    if f.confidence is not None:
        rows.append(("Abuse Score", f"{f.confidence} / 100"))
    if f.pulse_count is not None:
        rows.append(("OTX Pulses", str(f.pulse_count)))
    if f.cvss_score is not None:
        severity = f" ({f.cvss_severity})" if f.cvss_severity else ""
        rows.append(("CVSS Score", f"{f.cvss_score}{severity}"))
    if f.is_known_exploited is not None:
        val = "[bold red]YES — actively exploited[/bold red]" if f.is_known_exploited else "No"
        rows.append(("Known Exploited", val))
    if f.description:
        rows.append(("Description", f.description))
    if f.country:
        rows.append(("Country", f.country))
    if f.isp:
        rows.append(("ISP", f.isp))
    if f.categories:
        rows.append(("Categories", ", ".join(f.categories[:5])))
    if f.malware_families:
        rows.append(("Malware", ", ".join(f.malware_families[:5])))
    if f.tags:
        rows.append(("Tags", ", ".join(f.tags[:8])))
    if f.last_analysis:
        rows.append(("Last Analysis", f.last_analysis))
    if f.published_date:
        rows.append(("Published", f.published_date))

    for label, value in rows:
        console.print(f"    [dim]{label:<18}[/dim] {value}")

    console.print()


def render_csv(report: Report, min_risk: str | None = None) -> str:
    """Render a report as a CSV string."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "indicator", "indicator_type", "source", "risk_level",
        "detections", "total_engines", "confidence", "pulse_count",
        "cvss_score", "cvss_severity", "is_known_exploited",
        "country", "isp", "categories", "malware_families", "tags",
        "last_analysis", "description", "error",
        "resolved_ip", "resolved_hostname",
    ])
    visible = _filter_findings(report.findings, min_risk)
    for f in visible:
        writer.writerow([
            report.indicator.value,
            report.indicator.type,
            f.source_name,
            f.risk_level,
            f.detections,
            f.total_engines,
            f.confidence,
            f.pulse_count,
            f.cvss_score,
            f.cvss_severity,
            f.is_known_exploited,
            f.country,
            f.isp,
            "|".join(f.categories or []),
            "|".join(f.malware_families or []),
            "|".join(f.tags or []),
            f.last_analysis,
            f.description,
            f.error,
            report.resolved_ip or "",
            report.resolved_hostname or "",
        ])
    return buf.getvalue()


def main(indicator_str: str | None = None) -> Report:
    """Scan an indicator and render the report to the console."""
    import asyncio

    sys.stdout.reconfigure(encoding="utf-8")
    if indicator_str is None:
        if len(sys.argv) < 2:
            print("Usage: python -m threatscout.output.console <ip|domain|hash|cve>")
            sys.exit(1)
        indicator_str = sys.argv[1]
    load_dotenv()
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    from threatscout.models.indicator import Indicator
    from threatscout.scanner import Scanner
    from threatscout.sources.virustotal import VirusTotalSource
    from threatscout.sources.abuseipdb import AbuseIPDBSource
    from threatscout.sources.alienvault import AlienVaultOTXSource
    from threatscout.sources.nvd import NVDSource
    from threatscout.sources.cisa_kev import CISAKevSource
    from threatscout.sources.malwarebazaar import MalwareBazaarSource
    from threatscout.sources.urlscan import URLScanSource
    from threatscout.sources.whois_source import WHOISSource
    from threatscout.sources.greynoise import GreyNoiseSource
    from threatscout.sources.shodan import ShodanSource

    sources = []

    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if vt_key:
        sources.append(VirusTotalSource(api_key=vt_key))
    else:
        console.print("[yellow]WARN: VIRUSTOTAL_API_KEY not set — VirusTotal skipped[/yellow]")

    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    if abuse_key:
        sources.append(AbuseIPDBSource(api_key=abuse_key))
    else:
        console.print("[yellow]WARN: ABUSEIPDB_API_KEY not set — AbuseIPDB skipped[/yellow]")

    otx_key = os.getenv("OTX_API_KEY")
    if otx_key:
        sources.append(AlienVaultOTXSource(api_key=otx_key))
    else:
        console.print("[yellow]WARN: OTX_API_KEY not set — AlienVault OTX skipped[/yellow]")

    nvd_key = os.getenv("NVD_API_KEY")
    if nvd_key:
        sources.append(NVDSource(api_key=nvd_key))
    else:
        console.print("[yellow]WARN: NVD_API_KEY not set — NVD running at reduced rate (5 req/30s)[/yellow]")
        sources.append(NVDSource(api_key=None))

    sources.append(CISAKevSource())
    sources.append(MalwareBazaarSource())
    sources.append(URLScanSource())
    sources.append(WHOISSource())

    gn_key = os.getenv("GREYNOISE_API_KEY")
    if gn_key:
        sources.append(GreyNoiseSource(api_key=gn_key))

    shodan_key = os.getenv("SHODAN_API_KEY")
    if shodan_key:
        sources.append(ShodanSource(api_key=shodan_key))

    indicator = Indicator.detect(indicator_str)
    scanner = Scanner(sources=sources)
    report = asyncio.run(scanner.scan(indicator))
    render_report(report)
    return report


if __name__ == "__main__":
    main()
