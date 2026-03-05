"""
ThreatScout REST API — FastAPI application.

Start with:
    uvicorn threatscout.api:app --reload
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from enum import Enum

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from threatscout.models.indicator import Indicator
from threatscout.scanner import Scanner

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scanner singleton — built once at startup
# ---------------------------------------------------------------------------

_scanner: Scanner | None = None


def _build_scanner() -> Scanner:
    """Build a Scanner with all configured sources (mirrors CLI logic)."""
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _scanner
    _scanner = _build_scanner()
    logger.info("ThreatScout scanner initialized with %d sources", len(_scanner._sources))
    yield


# ---------------------------------------------------------------------------
# App & models
# ---------------------------------------------------------------------------

app = FastAPI(
    title="ThreatScout API",
    version="0.1.0",
    description="Query multiple threat intelligence sources with a single request.",
    lifespan=lifespan,
)


class IndicatorTypeParam(str, Enum):
    """Optional explicit indicator type. Omit to auto-detect."""
    ip = "ip"
    domain = "domain"
    url = "url"
    hash = "hash"
    cve = "cve"


class ScanRequest(BaseModel):
    indicator: str = Field(..., description="The indicator value to scan (IP, domain, URL, hash, or CVE ID)")
    indicator_type: IndicatorTypeParam | None = Field(
        None, description="Explicit indicator type. If omitted, ThreatScout auto-detects it."
    )
    sources: list[str] | None = Field(
        None, description="Only query these sources (by name). Omit to use all configured sources."
    )
    exclude: list[str] | None = Field(
        None, description="Skip these sources (by name)."
    )

    model_config = {"json_schema_extra": {"examples": [
        {"indicator": "8.8.8.8"},
        {"indicator": "CVE-2021-44228"},
        {"indicator": "evil.com", "indicator_type": "domain", "exclude": ["WHOIS"]},
    ]}}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/scan")
def scan(req: ScanRequest):
    """
    Scan an indicator across all applicable threat intelligence sources.

    Returns a unified report with per-source findings and an overall verdict.
    """
    if _scanner is None:
        raise HTTPException(status_code=503, detail="Scanner not initialized")

    if not req.indicator.strip():
        raise HTTPException(status_code=422, detail="Indicator value must not be empty")

    # Build indicator (auto-detect or explicit type)
    if req.indicator_type:
        from threatscout.models.indicator import IndicatorType
        type_map = {
            "ip": IndicatorType.IP,
            "domain": IndicatorType.DOMAIN,
            "url": IndicatorType.URL,
            "hash": IndicatorType.HASH,
            "cve": IndicatorType.CVE,
        }
        indicator = Indicator(value=req.indicator.strip(), type=type_map[req.indicator_type.value])
    else:
        indicator = Indicator.detect(req.indicator)

    # Apply source filters if requested
    scanner = _scanner
    if req.sources or req.exclude:
        include_lower = {s.lower() for s in (req.sources or [])}
        exclude_lower = {s.lower() for s in (req.exclude or [])}
        filtered = _scanner._sources[:]
        if include_lower:
            filtered = [s for s in filtered if s.name.lower() in include_lower]
        if exclude_lower:
            filtered = [s for s in filtered if s.name.lower() not in exclude_lower]
        if not filtered:
            raise HTTPException(status_code=400, detail="No sources remain after filtering")
        scanner = Scanner(sources=filtered)

    report = scanner.scan(indicator)
    return report.to_dict()


@app.get("/health")
def health():
    """Health check endpoint."""
    source_count = len(_scanner._sources) if _scanner else 0
    return {"status": "ok", "sources_loaded": source_count}
