"""
Shared scanner factory — builds a Scanner with all configured sources.

Reused by the Django views (and could be reused by the CLI / API if desired).
"""

from __future__ import annotations
import os

from threatscout.scanner import Scanner


def build_scanner() -> Scanner:
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

    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    if abuse_key:
        sources.append(AbuseIPDBSource(api_key=abuse_key))

    otx_key = os.getenv("OTX_API_KEY")
    if otx_key:
        sources.append(AlienVaultOTXSource(api_key=otx_key))

    nvd_key = os.getenv("NVD_API_KEY")
    sources.append(NVDSource(api_key=nvd_key))

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

    return Scanner(sources=sources)
