# threatscout

A Python CLI tool that queries multiple free threat intelligence and vulnerability APIs simultaneously and returns a unified, enriched report on any indicator — IP address, domain, URL, file hash, or CVE. DNS enrichment runs automatically in both directions: domain/URL indicators resolve to their IP and query IP-based sources, and IP indicators perform a reverse DNS lookup to find the associated hostname and query domain-based sources.

```bash
# Look up an IP across all sources
threatscout ip 198.51.100.42

# Look up a domain (also checks the resolved IP automatically)
threatscout domain malicious-example.com

# Look up a URL (also checks the resolved IP automatically)
threatscout url "https://malicious-example.com/payload"

# Look up a file hash
threatscout hash d41d8cd98f00b204e9800998ecf8427e

# Look up a CVE
threatscout cve CVE-2021-44228

# Auto-detect indicator type
threatscout scan 198.51.100.42

# Output as JSON (for piping into other tools)
threatscout ip 198.51.100.42 --format json

# Save report to file
threatscout ip 198.51.100.42 --output report.json
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

| Source | What It Provides | Indicator Types | Free Tier |
|---|---|---|---|
| [VirusTotal](https://virustotal.com) | Malware scan results from 70+ AV engines | IP, domain, URL, hash | 4 requests/min |
| [AbuseIPDB](https://abuseipdb.com) | IP abuse reports and confidence score | IP | 1,000 req/day |
| [AlienVault OTX](https://otx.alienvault.com) | Community threat pulses and IOC context | IP, domain, URL, hash | Unlimited (free account) |
| [NVD / NIST](https://nvd.nist.gov) | Official CVE database with CVSS scores | CVE | 50 req/30s (with API key) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known Exploited Vulnerabilities catalog | CVE | No key required |

---

## Architecture

```
threatscout/
├── __main__.py          # CLI entrypoint (click)
├── scanner.py           # Orchestrates parallel queries + DNS enrichment
├── sources/
│   ├── base.py          # ThreatSource abstract base class
│   ├── virustotal.py    # VirusTotal API v3
│   ├── abuseipdb.py     # AbuseIPDB API v2
│   ├── alienvault.py    # AlienVault OTX API
│   ├── nvd.py           # NIST NVD CVE API v2
│   └── cisa_kev.py      # CISA Known Exploited Vulnerabilities (no key needed)
├── models/
│   ├── indicator.py     # Indicator dataclass (IP, domain, URL, hash, CVE)
│   └── finding.py       # Finding and Report dataclasses + RiskLevel enum
├── enrichment/
│   ├── verdict.py       # Derives an overall verdict from all findings
│   └── dns_resolver.py  # Forward DNS (domain/URL → IP) and reverse DNS (IP → hostname)
└── output/
    └── console.py       # Rich terminal output with color-coded verdict
```

**Query flow:**

```
CLI input (ip / domain / url / hash / cve)
   │
   ▼
Scanner — determines which sources support this indicator type
   │
   ├──► VirusTotal  ──┐
   ├──► AbuseIPDB   ──┤  (parallel, using ThreadPoolExecutor)
   ├──► AlienVault  ──┤
   └──► NVD / CISA  ──┘
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
                  Console report or JSON output
                  (resolved IP / hostname shown in report header,
                   enriched findings in a separate labelled section)
```

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
VIRUSTOTAL_API_KEY=your-key-here
ABUSEIPDB_API_KEY=your-key-here
OTX_API_KEY=your-key-here
NVD_API_KEY=your-key-here        # optional but recommended
```

All keys are free. See [Getting API Keys](#getting-api-keys) below.

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

All keys are free with a basic account registration:

- **VirusTotal** — [virustotal.com](https://www.virustotal.com/gui/join-us) → free: 4 req/min, 500/day
- **AbuseIPDB** — [abuseipdb.com](https://www.abuseipdb.com/register) → free: 1,000 req/day
- **AlienVault OTX** — [otx.alienvault.com](https://otx.alienvault.com/accounts/register) → free, no stated limit
- **NVD** — [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) → free: 50 req/30s with key, 5 req/30s without
- **CISA KEV** — no key required, public JSON feed

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```