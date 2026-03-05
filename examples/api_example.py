"""
Example script showing how to use the ThreatScout API.

Prerequisites:
    1. Start the API server:
       uvicorn threatscout.api:app --reload

    2. Run this script:
       python examples/api_example.py
"""

import requests

BASE_URL = "http://localhost:8000"


def scan_indicator(indicator: str, **kwargs) -> dict:
    """Send a scan request and return the report."""
    payload = {"indicator": indicator, **kwargs}
    resp = requests.post(f"{BASE_URL}/scan", json=payload)
    resp.raise_for_status()
    return resp.json()


def print_report(report: dict) -> None:
    """Pretty-print a scan report."""
    ind = report["indicator"]
    print(f"\n{'='*60}")
    print(f"  Indicator : {ind['value']} ({ind['type']})")
    print(f"  Verdict   : {report['verdict']}  (confidence: {report['verdict_confidence']}%)")
    print(f"  Sources   : {report['sources_queried']} queried, {report['sources_errored']} errored")
    print(f"  Time      : {report['query_time_seconds']}s")
    print(f"{'='*60}")

    for f in report["findings"]:
        status = f"[{f['risk_level']}]" if not f["error"] else f"[ERROR: {f['error']}]"
        print(f"  {f['source']:20s} {status}")
        if f.get("detections") is not None:
            print(f"  {'':20s}   detections: {f['detections']}/{f['total_engines']}")
        if f.get("confidence") is not None:
            print(f"  {'':20s}   confidence: {f['confidence']}%")
        if f.get("categories"):
            print(f"  {'':20s}   categories: {', '.join(f['categories'])}")
        if f.get("tags"):
            print(f"  {'':20s}   tags: {', '.join(f['tags'])}")
        if f.get("description"):
            print(f"  {'':20s}   {f['description']}")
    print()


if __name__ == "__main__":
    # 1. Health check
    health = requests.get(f"{BASE_URL}/health").json()
    print(f"API status: {health['status']} ({health['sources_loaded']} sources loaded)")

    # 2. Scan an IP (auto-detected)
    print("\n--- Scanning an IP address ---")
    report = scan_indicator("8.8.8.8")
    print_report(report)

    # 3. Scan a CVE
    print("--- Scanning a CVE ---")
    report = scan_indicator("CVE-2021-44228")
    print_report(report)

    # 4. Scan a domain with explicit type and source filtering
    print("--- Scanning a domain (exclude WHOIS) ---")
    report = scan_indicator("example.com", indicator_type="domain", exclude=["WHOIS"])
    print_report(report)
