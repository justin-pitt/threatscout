# threatscout

A Python CLI tool that queries multiple free threat intelligence and vulnerability APIs simultaneously and returns a unified, enriched report on any indicator — IP address, domain, file hash, or CVE.

```bash
# Look up an IP across all sources
threatscout ip 198.51.100.42

# Look up a file hash
threatscout hash d41d8cd98f00b204e9800998ecf8427e

# Look up a domain
threatscout domain malicious-example.com

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
python -m threatscout.output.console CVE-2021-44228
```

---

## Why This Exists

When investigating a suspicious indicator, analysts typically open 4–6 browser tabs to check VirusTotal, AbuseIPDB, AlienVault OTX, and NVD separately, then manually piece together the results. This tool automates that process — querying all configured sources in parallel and returning a single normalized report in seconds.

It is built on top of [restlink](https://github.com/youruser/restlink), which handles authentication, retries, and rate limiting for each source API.

---

## Supported Sources

| Source | What It Provides | Indicator Types | Free Tier |
|---|---|---|---|
| [VirusTotal](https://virustotal.com) | Malware scan results from 70+ AV engines | IP, domain, hash, URL | 4 requests/min |
| [AbuseIPDB](https://abuseipdb.com) | IP abuse reports and confidence score | IP | 1,000 req/day |
| [AlienVault OTX](https://otx.alienvault.com) | Community threat pulses and IOC context | IP, domain, hash | Unlimited (free account) |
| [NVD / NIST](https://nvd.nist.gov) | Official CVE database with CVSS scores | CVE | 50 req/30s (with API key) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known Exploited Vulnerabilities catalog | CVE | No key required |

---

## Architecture

```
threatscout/
├── __main__.py          # CLI entrypoint (click)
├── scanner.py           # Orchestrates parallel queries across all sources
├── sources/
│   ├── base.py          # ThreatSource abstract base class
│   ├── virustotal.py    # VirusTotal API v3
│   ├── abuseipdb.py     # AbuseIPDB API v2
│   ├── alienvault.py    # AlienVault OTX API
│   ├── nvd.py           # NIST NVD CVE API v2
│   └── cisa_kev.py      # CISA Known Exploited Vulnerabilities (no key needed)
├── models/
│   ├── indicator.py     # Indicator dataclass (IP, domain, hash, CVE)
│   └── finding.py       # Finding and Report dataclasses + RiskLevel enum
├── enrichment/
│   └── verdict.py       # Derives an overall verdict from all findings
└── output/
    └── console.py       # Rich terminal output with color-coded verdict
```

**Query flow:**

```
CLI input (ip / domain / hash / cve)
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
                  Verdict engine → overall risk level
                      │
                      ▼
                  Console report or JSON output
```

---

## Installation

**Prerequisites:** Python 3.10+ and `setuptools` are required.

```bash
pip install setuptools
git clone https://github.com/youruser/threatscout.git
cd threatscout
pip install -e .
```

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

  ┌─────────────────────────────────────────────┐
  │  ThreatScout Report                         │
  │  Indicator: 198.51.100.42  (ip)             │
  │  Verdict:   🔴 MALICIOUS  (confidence: 87%) │
  └─────────────────────────────────────────────┘

  VirusTotal
    Detections:    14 / 92 engines
    Categories:    malware, phishing
    Last analysis: 2025-02-28

  AbuseIPDB
    Abuse score:   94 / 100
    Reports:       312 reports from 87 users
    Country:       RU
    ISP:           Example Hosting Ltd

  AlienVault OTX
    Pulses:        7 threat intelligence pulses
    Malware:       Emotet, TrickBot
    Tags:          botnet, c2, ransomware

  ─────────────────────────────────────────────
  Sources queried: 3  |  Query time: 1.4s
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

---

## License

MIT
