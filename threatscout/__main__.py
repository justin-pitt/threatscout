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


def _build_scanner():
    """Build a Scanner with all configured sources."""
    from threatscout.scanner import Scanner
    from threatscout.sources.virustotal import VirusTotalSource
    from threatscout.sources.abuseipdb import AbuseIPDBSource
    from threatscout.sources.alienvault import AlienVaultOTXSource
    from threatscout.sources.nvd import NVDSource
    from threatscout.sources.cisa_kev import CISAKevSource

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

    # CISA KEV needs no key
    sources.append(CISAKevSource())

    for w in warnings:
        click.echo(click.style(f"⚠  {w}", fg="yellow"), err=True)

    if not sources:
        click.echo("No API keys configured. Copy .env.example to .env and add your keys.", err=True)
        sys.exit(1)

    return Scanner(sources=sources)


def _run_query(value: str, output: str | None, fmt: str) -> None:
    from threatscout.models.indicator import Indicator
    from threatscout.output.console import render_report

    indicator = Indicator.detect(value)
    scanner = _build_scanner()
    report = scanner.scan(indicator)

    if fmt == "json":
        data = json.dumps(report.to_dict(), indent=2)
        if output:
            with open(output, "w") as f:
                f.write(data)
            click.echo(f"Report saved to {output}")
        else:
            click.echo(data)
    else:
        render_report(report)
        if output:
            with open(output, "w") as f:
                json.dump(report.to_dict(), f, indent=2)
            click.echo(f"Report also saved to {output}")


# ── CLI ───────────────────────────────────────────────────────────────────────

@click.group()
def cli():
    """ThreatScout — query multiple threat intelligence APIs at once."""
    pass


@cli.command()
@click.argument("ip_address")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json"]))
@click.option("--output", default=None, help="Save report to file")
def ip(ip_address: str, fmt: str, output: str | None):
    """Look up an IP address across all configured sources."""
    _run_query(ip_address, output, fmt)


@cli.command()
@click.argument("domain_name")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json"]))
@click.option("--output", default=None, help="Save report to file")
def domain(domain_name: str, fmt: str, output: str | None):
    """Look up a domain across all configured sources."""
    _run_query(domain_name, output, fmt)


@cli.command()
@click.argument("file_hash")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json"]))
@click.option("--output", default=None, help="Save report to file")
def hash(file_hash: str, fmt: str, output: str | None):
    """Look up a file hash (MD5, SHA1, or SHA256) across all configured sources."""
    _run_query(file_hash, output, fmt)


@cli.command()
@click.argument("cve_id")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json"]))
@click.option("--output", default=None, help="Save report to file")
def cve(cve_id: str, fmt: str, output: str | None):
    """Look up a CVE ID for CVSS scores, description, and exploitation status."""
    _run_query(cve_id, output, fmt)


@cli.command()
@click.argument("url")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json"]))
@click.option("--output", default=None, help="Save report to file")
def url(url: str, fmt: str, output: str | None):
    """Look up a URL across all configured sources."""
    _run_query(url, output, fmt)


@cli.command()
@click.argument("indicator")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json"]))
@click.option("--output", default=None, help="Save report to file")
def scan(indicator: str, fmt: str, output: str | None):
    """
    Auto-detect the indicator type and query all applicable sources.

    Works with IPs, domains, URLs, file hashes, and CVE IDs.
    """
    _run_query(indicator, output, fmt)


if __name__ == "__main__":
    cli()
