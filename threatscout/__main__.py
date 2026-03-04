"""
ThreatScout CLI entrypoint.
"""

from __future__ import annotations
import json
import logging
import os
import sys

import click
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")


def _build_scanner(include: tuple[str, ...] = (), exclude: tuple[str, ...] = ()):
    """Build a Scanner with all configured sources, optionally filtered by name."""
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
    warnings = []

    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if vt_key:
        sources.append(VirusTotalSource(api_key=vt_key))
    else:
        warnings.append("VIRUSTOTAL_API_KEY not set — VirusTotal skipped")

    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    if abuse_key:
        sources.append(AbuseIPDBSource(api_key=abuse_key))
    else:
        warnings.append("ABUSEIPDB_API_KEY not set — AbuseIPDB skipped")

    otx_key = os.getenv("OTX_API_KEY")
    if otx_key:
        sources.append(AlienVaultOTXSource(api_key=otx_key))
    else:
        warnings.append("OTX_API_KEY not set — AlienVault OTX skipped")

    # NVD works without a key but at a lower rate
    nvd_key = os.getenv("NVD_API_KEY")
    sources.append(NVDSource(api_key=nvd_key))

    # Always-on free sources (no key required)
    sources.append(CISAKevSource())
    sources.append(MalwareBazaarSource())
    sources.append(URLScanSource())
    sources.append(WHOISSource())

    # Optional paid/community sources
    gn_key = os.getenv("GREYNOISE_API_KEY")
    if gn_key:
        sources.append(GreyNoiseSource(api_key=gn_key))
    else:
        warnings.append("GREYNOISE_API_KEY not set — GreyNoise skipped (free community key at viz.greynoise.io)")

    shodan_key = os.getenv("SHODAN_API_KEY")
    if shodan_key:
        sources.append(ShodanSource(api_key=shodan_key))
    else:
        warnings.append("SHODAN_API_KEY not set — Shodan skipped (paid key at account.shodan.io)")

    # Apply source selection filters
    include_lower = {s.lower() for s in include}
    exclude_lower = {s.lower() for s in exclude}
    if include_lower:
        sources = [s for s in sources if s.name.lower() in include_lower]
    if exclude_lower:
        sources = [s for s in sources if s.name.lower() not in exclude_lower]

    for w in warnings:
        click.echo(click.style(f"⚠  {w}", fg="yellow"), err=True)

    if not sources:
        click.echo("No API keys configured. Copy .env.example to .env and add your keys.", err=True)
        sys.exit(1)

    return Scanner(sources=sources)


def _run_query(
    value: str,
    output: str | None,
    fmt: str,
    include: tuple[str, ...] = (),
    exclude: tuple[str, ...] = (),
    min_risk: str | None = None,
) -> None:
    from threatscout.models.indicator import Indicator
    from threatscout.output.console import render_report, render_csv

    indicator = Indicator.detect(value)
    scanner = _build_scanner(include=include, exclude=exclude)
    report = scanner.scan(indicator)

    if fmt == "json":
        data = json.dumps(report.to_dict(), indent=2)
        if output:
            with open(output, "w") as f:
                f.write(data)
            click.echo(f"Report saved to {output}")
        else:
            click.echo(data)
    elif fmt == "csv":
        csv_data = render_csv(report, min_risk=min_risk)
        if output:
            with open(output, "w", encoding="utf-8", newline="") as f:
                f.write(csv_data)
            click.echo(f"Report saved to {output}")
        else:
            click.echo(csv_data, nl=False)
    else:
        render_report(report, min_risk=min_risk)
        if output:
            with open(output, "w") as f:
                json.dump(report.to_dict(), f, indent=2)
            click.echo(f"Report also saved to {output}")


# ── CLI ───────────────────────────────────────────────────────────────────────

@click.group()
def cli():
    """ThreatScout — query multiple threat intelligence APIs at once."""
    pass


_COMMON_OPTIONS = [
    click.option("--format", "fmt", default="table", type=click.Choice(["table", "json", "csv"])),
    click.option("--output", default=None, help="Save report to file"),
    click.option("--sources", default=None, help="Comma-separated list of sources to use (e.g. virustotal,shodan)"),
    click.option("--exclude", default=None, help="Comma-separated list of sources to skip"),
    click.option("--min-risk", default=None, type=click.Choice(["clean", "suspicious", "malicious"]),
                 help="Only show findings at or above this risk level"),
]


def _add_common_options(func):
    for option in reversed(_COMMON_OPTIONS):
        func = option(func)
    return func


def _parse_csv_arg(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(v.strip() for v in value.split(",") if v.strip())


@cli.command()
@click.argument("ip_address")
@_add_common_options
def ip(ip_address: str, fmt: str, output: str | None, sources: str | None, exclude: str | None, min_risk: str | None):
    """Look up an IP address across all configured sources."""
    _run_query(ip_address, output, fmt, _parse_csv_arg(sources), _parse_csv_arg(exclude), min_risk)


@cli.command()
@click.argument("domain_name")
@_add_common_options
def domain(domain_name: str, fmt: str, output: str | None, sources: str | None, exclude: str | None, min_risk: str | None):
    """Look up a domain across all configured sources."""
    _run_query(domain_name, output, fmt, _parse_csv_arg(sources), _parse_csv_arg(exclude), min_risk)


@cli.command()
@click.argument("file_hash")
@_add_common_options
def hash(file_hash: str, fmt: str, output: str | None, sources: str | None, exclude: str | None, min_risk: str | None):
    """Look up a file hash (MD5, SHA1, or SHA256) across all configured sources."""
    _run_query(file_hash, output, fmt, _parse_csv_arg(sources), _parse_csv_arg(exclude), min_risk)


@cli.command()
@click.argument("cve_id")
@_add_common_options
def cve(cve_id: str, fmt: str, output: str | None, sources: str | None, exclude: str | None, min_risk: str | None):
    """Look up a CVE ID for CVSS scores, description, and exploitation status."""
    _run_query(cve_id, output, fmt, _parse_csv_arg(sources), _parse_csv_arg(exclude), min_risk)


@cli.command()
@click.argument("url")
@_add_common_options
def url(url: str, fmt: str, output: str | None, sources: str | None, exclude: str | None, min_risk: str | None):
    """Look up a URL across all configured sources."""
    _run_query(url, output, fmt, _parse_csv_arg(sources), _parse_csv_arg(exclude), min_risk)


@cli.command()
@click.argument("indicator")
@_add_common_options
def scan(indicator: str, fmt: str, output: str | None, sources: str | None, exclude: str | None, min_risk: str | None):
    """
    Auto-detect the indicator type and query all applicable sources.

    Works with IPs, domains, URLs, file hashes, and CVE IDs.
    """
    _run_query(indicator, output, fmt, _parse_csv_arg(sources), _parse_csv_arg(exclude), min_risk)


if __name__ == "__main__":
    cli()
