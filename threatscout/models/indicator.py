"""
Indicator — represents the thing being looked up.
Supports IP addresses, domains, URLs, file hashes, and CVE IDs.
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
import re


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    CVE = "cve"


@dataclass
class Indicator:
    value: str
    type: IndicatorType

    @classmethod
    def detect(cls, value: str) -> Indicator:
        """
        Auto-detect the indicator type from its value.

        Examples:
            Indicator.detect("1.2.3.4")              → IndicatorType.IP
            Indicator.detect("evil.com")             → IndicatorType.DOMAIN
            Indicator.detect("CVE-2021-44228")       → IndicatorType.CVE
            Indicator.detect("d41d8cd98f00b204...") → IndicatorType.HASH
        """
        value = value.strip()

        if re.match(r"^CVE-\d{4}-\d+$", value, re.IGNORECASE):
            return cls(value.upper(), IndicatorType.CVE)

        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
            return cls(value, IndicatorType.IP)

        if re.match(r"^[a-fA-F0-9]{32}$", value) or \
           re.match(r"^[a-fA-F0-9]{40}$", value) or \
           re.match(r"^[a-fA-F0-9]{64}$", value):
            return cls(value.lower(), IndicatorType.HASH)

        if re.match(r"^https?://", value, re.IGNORECASE):
            return cls(value, IndicatorType.URL)

        # Default to domain for anything else that looks like a hostname
        return cls(value.lower(), IndicatorType.DOMAIN)

    def __str__(self) -> str:
        return self.value
