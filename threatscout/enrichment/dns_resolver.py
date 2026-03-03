"""
DNS resolution utility — resolves a domain or URL hostname to an IPv4 address.
"""

from __future__ import annotations
import logging
import socket
from urllib.parse import urlparse

from threatscout.models.indicator import Indicator, IndicatorType

logger = logging.getLogger(__name__)


def resolve_to_ip(indicator: Indicator) -> str | None:
    """
    Resolve a DOMAIN or URL indicator to its IPv4 address.

    Returns the resolved IP string, or None if resolution fails or the
    indicator type doesn't support DNS resolution.
    """
    if indicator.type == IndicatorType.URL:
        hostname = urlparse(indicator.value).hostname
    elif indicator.type == IndicatorType.DOMAIN:
        hostname = indicator.value
    else:
        return None

    if not hostname:
        return None

    try:
        ip = socket.gethostbyname(hostname)
        logger.debug(f"DNS resolved {hostname} -> {ip}")
        return ip
    except socket.gaierror as e:
        logger.debug(f"DNS resolution failed for {hostname}: {e}")
        return None
