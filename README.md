# threatscout

A Python CLI tool that queries multiple free threat intelligence and vulnerability APIs simultaneously and returns a unified, enriched report on any indicator — IP address (IPv4 or IPv6), domain, URL, file hash, or CVE. DNS enrichment runs automatically in both directions: domain/URL indicators resolve to their IP and query IP-based sources, and IP indicators perform a reverse DNS lookup to find the associated hostname and query domain-based sources.

```bash
# Look up an IP across all sources (IPv4 or IPv6)
threatscout ip 198.51.100.42
threatscout ip 2001:db8::1

# Look up a domain (also checks the resolved IP automatically)
threatscout domain malicious-example.com

# Look up a URL (also checks the resolved IP automatically)
threatscout url "https://malicious-example.com/payload"

# Look up a file hash (MD5, SHA1, or SHA256)
threatscout hash d41d8cd98f00b204e9800998ecf8427e

# Look up a CVE
threatscout cve CVE-2021-44228

# Auto-detect indicator type
threatscout scan 198.51.100.42

# Output as JSON or CSV (for piping into other tools)
threatscout ip 198.51.100.42 --format json
threatscout ip 198.51.100.42 --format csv

# Save report to file
threatscout ip 198.51.100.42 --output report.json

# Only query specific sources
threatscout ip 198.51.100.42 --sources virustotal,abuseipdb

# Skip specific sources
threatscout ip 198.51.100.42 --exclude shodan,greynoise

# Only show findings at or above a risk level
threatscout ip 198.51.100.42 --min-risk suspicious
```

You can also run the console output directly as a Python module, passing any indicator as an argument:

```bash
python -m threatscout.output.console 198.51.100.42
python -m threatscout.output.console malicious-example.com
python -m threatscout.output.console "https://malicious-example.com/payload"
python -m threatscout.output.console CVE-2021-44228
```

---

## Why This Exists

When investigating a suspicious indicator, analysts typically open 4–6 browser tabs to check VirusTotal, AbuseIPDB, AlienVault OTX, and NVD separately, then manually piece together the results. This tool automates that process — querying all configured sources in parallel and returning a single normalized report in seconds.

It is built on top of [restlink](https://github.com/justin-pitt/restlink), which handles authentication, retries, and rate limiting for each source API.

---

## Supported Sources

| Source | What It Provides | Indicator Types | Key Required |
|---|---|---|---|
| [VirusTotal](https://virustotal.com) | Malware scan results from 70+ AV engines | IP, domain, URL, hash | Free (4 req/min) |
| [AbuseIPDB](https://abuseipdb.com) | IP abuse reports and confidence score | IP | Free (1,000 req/day) |
| [AlienVault OTX](https://otx.alienvault.com) | Community threat pulses and IOC context | IP, domain, URL, hash | Free (no stated limit) |
| [NVD / NIST](https://nvd.nist.gov) | Official CVE database with CVSS scores | CVE | Optional (higher rate with key) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known Exploited Vulnerabilities catalog | CVE | No key required |
| [MalwareBazaar](https://bazaar.abuse.ch) | Malware hash lookup with family and file type | Hash | No key required |
| [URLScan.io](https://urlscan.io) | URL/domain/IP scan history and malicious flags | IP, domain, URL | No key required |
| [WHOIS](https://pypi.org/project/python-whois/) | Domain registration age, registrar, nameservers | Domain | No key required |
| [GreyNoise](https://greynoise.io) | Internet background noise classification (scanners vs. targeted threats) | IP | Free community key |
| [Shodan](https://shodan.io) | Open ports, exposed services, and known CVEs on a host | IP | Paid key |

Sources without a key (MalwareBazaar, URLScan.io, WHOIS, CISA KEV, NVD) run automatically. GreyNoise and Shodan are optional — add their keys to `.env` to enable them.

---

## Architecture

```
threatscout/
├── __main__.py          # CLI entrypoint (click)
├── api.py               # FastAPI REST API
├── scanner.py           # Orchestrates parallel queries + DNS enrichment
├── sources/
│   ├── base.py          # ThreatSource abstract base class
│   ├── virustotal.py    # VirusTotal API v3
│   ├── abuseipdb.py     # AbuseIPDB API v2
│   ├── alienvault.py    # AlienVault OTX API
│   ├── nvd.py           # NIST NVD CVE API v2
│   ├── cisa_kev.py      # CISA Known Exploited Vulnerabilities (no key needed)
│   ├── malwarebazaar.py # MalwareBazaar hash lookup (no key needed)
│   ├── urlscan.py       # URLScan.io scan history (no key needed)
│   ├── whois_source.py  # WHOIS domain registration info (no key needed)
│   ├── greynoise.py     # GreyNoise internet noise classification (free community key)
│   └── shodan.py        # Shodan open ports and CVEs (paid key)
├── models/
│   ├── indicator.py     # Indicator dataclass (IPv4/IPv6, domain, URL, hash, CVE)
│   └── finding.py       # Finding and Report dataclasses + RiskLevel enum
├── enrichment/
│   ├── verdict.py       # Derives an overall verdict from all findings
│   └── dns_resolver.py  # Forward DNS (domain/URL → IP/IPv6) and reverse DNS (IP → hostname)
└── output/
    └── console.py       # Rich terminal output + CSV export
```

**Query flow:**

```
CLI or API input (ip / domain / url / hash / cve)
   │
   ▼
Scanner — determines which sources support this indicator type
   │
   ├──► VirusTotal     ──┐
   ├──► AbuseIPDB      ──┤
   ├──► AlienVault OTX ──┤  (parallel, using ThreadPoolExecutor)
   ├──► NVD / CISA KEV ──┤
   ├──► MalwareBazaar  ──┤
   ├──► URLScan.io     ──┤
   ├──► WHOIS          ──┤
   ├──► GreyNoise      ──┤
   └──► Shodan         ──┘
                      │
                      ▼
                  Normalize → Finding objects
                      │
                      ▼
           [domain / URL] Forward DNS → resolved IP
           Scanner queries IP sources against resolved IP
           (AbuseIPDB, VirusTotal, AlienVault for the IP)
                      │
           [IP] Reverse DNS (PTR) → resolved hostname
           Scanner queries domain sources against hostname
           (VirusTotal, AlienVault for the domain)
                      │
                      ▼
                  Verdict engine → overall risk level
                      │
                      ▼
                  Console report, JSON, or CSV output
                  (resolved IP / hostname shown in report header,
                   enriched findings in a separate labelled section)
```

---

## REST API

ThreatScout also ships a FastAPI-based REST API for programmatic access.

### Start the server

```bash
uvicorn threatscout.api:app --reload
```

### `POST /scan`

Submit an indicator for scanning. The request body is JSON:

```json
{
  "indicator": "8.8.8.8",
  "indicator_type": null,
  "sources": null,
  "exclude": null
}
```

| Field | Type | Description |
|---|---|---|
| `indicator` | string (required) | The value to scan (IP, domain, URL, hash, or CVE ID) |
| `indicator_type` | string or null | Explicit type: `ip`, `domain`, `url`, `hash`, `cve`. Omit to auto-detect. |
| `sources` | list or null | Only query these sources (by name). Omit to use all. |
| `exclude` | list or null | Skip these sources (by name). |

**Example with curl:**

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"indicator": "CVE-2021-44228"}'
```

Returns the same JSON report structure as `threatscout scan --format json`.

### `GET /health`

Returns API status and the number of loaded sources.

### Interactive docs

FastAPI auto-generates interactive API docs at `http://localhost:8000/docs`.

### Example script

See [`examples/api_example.py`](examples/api_example.py) for a complete Python example using `requests`.

---

## Installation

**Prerequisites:** Python 3.10+

```bash
git clone https://github.com/justin-pitt/threatscout.git
cd threatscout
pip install -e .
```

`pip install -e .` automatically installs all dependencies including [restlink](https://github.com/justin-pitt/restlink) directly from GitHub.

Copy `.env.example` to `.env` and add your API keys:

```bash
cp .env.example .env
```

```env
# Required for full coverage
VIRUSTOTAL_API_KEY=your-key-here
ABUSEIPDB_API_KEY=your-key-here
OTX_API_KEY=your-key-here

# Optional — higher rate limit with key; works without one
NVD_API_KEY=your-key-here

# Optional — free community key
GREYNOISE_API_KEY=your-key-here

# Optional — paid plan
SHODAN_API_KEY=your-key-here
```

MalwareBazaar, URLScan.io, WHOIS, and CISA KEV require no key and are always active. See [Getting API Keys](#getting-api-keys) below.

---

## Example Output

```
threatscout ip 198.51.100.42

  ╭──────────────── ThreatScout Report ─────────────────╮
  │ Indicator:         198.51.100.42  (ip)               │
  │ Resolved Hostname: malicious-host.example.com        │
  │ Verdict:           🔴 MALICIOUS  (confidence: 87%)   │
  ╰──────────────────────────────────────────────────────╯

  AbuseIPDB  🔴 MALICIOUS
    Abuse Score        94 / 100
    Country            RU
    ISP                Example Hosting Ltd

  VirusTotal  🔴 MALICIOUS
    Detections         14 / 92 engines
    Categories         malware, phishing
    Last Analysis      2025-02-28

  AlienVault OTX  🔴 MALICIOUS
    OTX Pulses         7
    Malware            Emotet, TrickBot
    Tags               botnet, c2, ransomware

── Enriched: DOMAIN malicious-host.example.com ──

  AlienVault OTX  🟡 SUSPICIOUS
    OTX Pulses         3
    Tags               c2, malware

  VirusTotal  🟡 SUSPICIOUS
    Detections         2 / 92 engines

  Sources queried: 3  |  Errors: 0  |  Query time: 1.4s
```

---

## Getting API Keys

- **VirusTotal** — [virustotal.com](https://www.virustotal.com/gui/join-us) → free: 4 req/min, 500/day
- **AbuseIPDB** — [abuseipdb.com](https://www.abuseipdb.com/register) → free: 1,000 req/day
- **AlienVault OTX** — [otx.alienvault.com](https://otx.alienvault.com/accounts/register) → free, no stated limit
- **NVD** — [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) → free: 50 req/30s with key, 5 req/30s without
- **GreyNoise** — [viz.greynoise.io](https://viz.greynoise.io/signup) → free community key
- **Shodan** — [account.shodan.io](https://account.shodan.io) → paid plan required for host lookups
- **CISA KEV, MalwareBazaar, URLScan.io, WHOIS** — no key required

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```