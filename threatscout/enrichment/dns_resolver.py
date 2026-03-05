"""
DNS resolution utility — async forward and reverse DNS lookups for indicator enrichment.
"""

from __future__ import annotations
import asyncio
import logging
import socket
from urllib.parse import urlparse

from threatscout.models.indicator import Indicator, IndicatorType

logger = logging.getLogger(__name__)


async def resolve_to_hostname(indicator: Indicator) -> str | None:
    """
    Reverse DNS: resolve an IP indicator to its PTR hostname.

    Returns the hostname string, or None if no PTR record exists or
    the indicator is not an IP.
    """
    if indicator.type != IndicatorType.IP:
        return None

    try:
        hostname, _, _ = await asyncio.to_thread(socket.gethostbyaddr, indicator.value)
        logger.debug(f"Reverse DNS resolved {indicator.value} -> {hostname}")
        return hostname
    except (socket.herror, socket.gaierror) as e:
        logger.debug(f"Reverse DNS failed for {indicator.value}: {e}")
        return None


async def resolve_to_ip(indicator: Indicator) -> str | None:
    """
    Resolve a DOMAIN or URL indicator to its IP address (IPv4 preferred, IPv6 fallback).

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
        loop = asyncio.get_running_loop()
        results = await loop.getaddrinfo(hostname, None)
        ipv4 = [r[4][0] for r in results if r[0] == socket.AF_INET]
        ipv6 = [r[4][0] for r in results if r[0] == socket.AF_INET6]
        ip = (ipv4 or ipv6 or [None])[0]
        if ip:
            logger.debug(f"DNS resolved {hostname} -> {ip}")
        return ip
    except socket.gaierror as e:
        logger.debug(f"DNS resolution failed for {hostname}: {e}")
        return None
