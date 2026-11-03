# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""SSRF policy shared by the browser request guard and the WHOIS tool.

One policy judges the submitted URL, every browser subresource and every RDAP
redirect, so an attacker cannot reach an internal address through a hop the
first check never saw.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import threading
import time
from urllib.parse import urlparse, urlsplit

from phish_contracts.ip_literal import AmbiguousIpLiteral, parse_ip_literal

logger = logging.getLogger(__name__)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Explicit ranges that the ipaddress properties do not flag on every Python version.
_DENIED_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "100.64.0.0/10",
        "192.0.0.0/24",
        "198.18.0.0/15",
        "169.254.169.254/32",
        "fd00:ec2::254/128",
        "64:ff9b::/96",
        "::/128",
    )
)
_DENIED_DOMAIN_SUFFIXES = (".internal", ".local", ".localhost", ".corp", ".lan", ".intranet")
_ALLOWED_PORTS = {80, 443}
BROWSER_INTERNAL_SCHEMES = frozenset(
    {"chrome-extension", "chrome", "devtools", "about", "data", "blob"}
)


def _ip_blocked_reason(ip: IPAddress) -> str | None:
    # Unwrap ::ffff:a.b.c.d so a mapped metadata address is judged as IPv4.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        inner = _ip_blocked_reason(ip.ipv4_mapped)
        if inner:
            return f"IPv4-mapped ({inner})"
    if not ip.is_global:
        return "not a globally-routable address"
    for attr in (
        "is_private",
        "is_loopback",
        "is_link_local",
        "is_multicast",
        "is_reserved",
        "is_unspecified",
        "is_site_local",
    ):
        if getattr(ip, attr, False):
            return attr
    for network in _DENIED_NETWORKS:
        if ip in network:
            return f"blocked range {network}"
    return None


def validate_url(url: str) -> str | None:
    """Static checks. Returns a refusal reason, or None when the URL may be fetched."""
    if not url or not isinstance(url, str):
        return "'url' is required and must be a string"
    if len(url) > 2048:
        return "'url' must be under 2048 characters"
    if not url.startswith(("http://", "https://")):
        return "'url' must start with http:// or https://"
    try:
        parsed = urlparse(url)
    except ValueError:
        return "'url' is malformed and cannot be parsed"
    if parsed.username or parsed.password:
        return "'url' must not contain embedded credentials (user:pass@host)"
    hostname = parsed.hostname
    if not hostname:
        return "'url' must contain a valid hostname"
    try:
        port = parsed.port
    except ValueError:
        return "'url' has an invalid port"
    if port is not None and port not in _ALLOWED_PORTS:
        return f"'url' port {port} is not allowed - only ports 80 and 443 are permitted"
    lower = hostname.lower()
    for suffix in _DENIED_DOMAIN_SUFFIXES:
        if lower.endswith(suffix) or lower == suffix.lstrip("."):
            return f"'url' hostname '{hostname}' resolves to a blocked internal domain"
    # Integer, octal, hex and short-dotted IPv4 hosts are read as the address they spell,
    # the way Chromium and getaddrinfo read them, before the address check.
    try:
        ip = parse_ip_literal(hostname)
    except AmbiguousIpLiteral:
        return f"'url' hostname '{hostname}' is not a valid address"
    if ip is not None:
        reason = _ip_blocked_reason(ip)
        if reason:
            return f"'url' targets a blocked IP address {hostname} ({reason})"
    return None


# Outcome kinds of a host check. NXDOMAIN is kept apart from other refusals because a
# scan host that does not resolve is a finding about the site (taken down, never set up),
# not an error of ours.
HOST_OK = "ok"
HOST_NXDOMAIN = "nxdomain"
HOST_UNRESOLVED = "unresolved"
HOST_BLOCKED = "blocked"


def resolve_and_validate(url: str) -> str | None:
    """Resolve the host and refuse if ANY address is internal (DNS rebinding defence)."""
    return _resolve(url)[0]


def _resolve(url: str) -> tuple[str | None, bool]:
    """(refusal reason or None, whether the decision is definitive enough to cache)."""
    reason, cacheable, _kind = _resolve_kind(url)
    return reason, cacheable


def _resolve_kind(url: str, *, retry: bool = False) -> tuple[str | None, bool, str]:
    """(refusal reason or None, cacheable, one of the HOST_* kinds)."""
    reason, cacheable, kind, _addresses = _resolve_addresses(url, retry=retry)
    return reason, cacheable, kind


# A resolver failure that is not NXDOMAIN (EAI_AGAIN, or OSError errno 16 EBUSY seen 200 times
# under 16-way concurrency in the 2026-10-31 evaluation) says nothing about the domain. One retry
# after a short backoff separates resolver contention from a host that really does not resolve.
DNS_TRANSIENT_ERROR = "dns_transient_error"
DNS_RETRY_BACKOFF_S = 0.25


CAPTURE_RECOVERY_ENV = "CAPTURE_RECOVERY"


def capture_recovery_enabled() -> bool:
    """-c captureRecovery sets CAPTURE_RECOVERY=1: the S3-website http fetch, the certificate-
    tolerant retry, download fingerprinting and the transient DNS retry. Off keeps the earlier
    capture behaviour; page_state and verdict_detail are recorded either way."""
    return os.environ.get(CAPTURE_RECOVERY_ENV, "").strip() == "1"


def _definitive_dns_failure(exc: socket.gaierror) -> bool:
    return exc.errno in (getattr(socket, "EAI_NONAME", None), getattr(socket, "EAI_NODATA", None))


def _getaddrinfo(hostname: str, *, retry: bool) -> list:
    """socket.getaddrinfo, retried once after DNS_RETRY_BACKOFF_S on a transient failure.

    Always called off the event loop (asyncio.to_thread or a worker thread), so the sleep
    blocks only that thread.
    """
    try:
        return socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except UnicodeError:
        raise
    except OSError as exc:
        if (
            not retry
            or not capture_recovery_enabled()
            or (isinstance(exc, socket.gaierror) and _definitive_dns_failure(exc))
        ):
            raise
        logger.info(
            "%s class=%s errno=%s; retrying once",
            DNS_TRANSIENT_ERROR,
            type(exc).__name__,
            getattr(exc, "errno", None),
        )
    time.sleep(DNS_RETRY_BACKOFF_S)
    return socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)


def _resolve_addresses(url: str, *, retry: bool = False) -> tuple[str | None, bool, str, list[str]]:
    """_resolve_kind plus every resolved address, all of which passed (empty on refusal)."""
    try:
        hostname = urlparse(url).hostname
    except ValueError:
        return "'url' is malformed", True, HOST_BLOCKED, []
    if not hostname:
        return "'url' has no hostname", True, HOST_BLOCKED, []
    try:
        infos = _getaddrinfo(hostname, retry=retry)
    except socket.gaierror as e:
        definitive = _definitive_dns_failure(e)
        logger.info("dns %s errno=%s", "NXDOMAIN" if definitive else "resolver failure", e.errno)
        if definitive:
            return (
                (
                    f"The domain '{hostname}' does not resolve. It may never have been registered, "
                    "may have expired, or may already have been taken down."
                ),
                True,
                HOST_NXDOMAIN,
                [],
            )
        return (
            f"The domain '{hostname}' could not be resolved right now "
            f"({DNS_TRANSIENT_ERROR}). Please retry.",
            False,
            HOST_UNRESOLVED,
            [],
        )
    except UnicodeError:
        # getaddrinfo raises UnicodeError (a ValueError) for DNS labels over 63 chars.
        return (
            (
                f"The hostname '{hostname}' is not a valid DNS name: a single label may "
                "not exceed 63 characters."
            ),
            True,
            HOST_NXDOMAIN,
            [],
        )
    except OSError as e:
        logger.info("dns error class=%s errno=%s", type(e).__name__, getattr(e, "errno", None))
        return (
            f"The domain '{hostname}' could not be resolved right now ({DNS_TRANSIENT_ERROR}).",
            False,
            HOST_UNRESOLVED,
            [],
        )
    if not infos:
        return f"'url' hostname '{hostname}' resolved to no addresses", False, HOST_UNRESOLVED, []
    addresses: list[str] = []
    for info in infos:
        raw = info[4][0]
        try:
            resolved = ipaddress.ip_address(raw.split("%", 1)[0])
        except ValueError:
            continue
        reason = _ip_blocked_reason(resolved)
        if reason:
            return (
                (
                    f"'url' hostname '{hostname}' resolves to {raw} which is blocked "
                    f"({reason}) (possible DNS rebinding)"
                ),
                True,
                HOST_BLOCKED,
                [],
            )
        if str(resolved) not in addresses:
            addresses.append(str(resolved))
    return None, True, HOST_OK, addresses


def origin_of(url: str) -> str | None:
    """scheme://netloc/ of a URL. The SSRF decision depends only on the origin."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}/"


# Decisions are cached per origin so a page with 150 subresources does not resolve the
# same CDN 150 times. Only definitive decisions are cached, and only for a minute, so a
# resolver hiccup does not refuse an origin for the life of the process and a DNS change
# (including a rebinding attempt) is seen again soon.
DECISION_TTL_S = 60.0
_CACHE_MAX = 512
_cache: dict[str, tuple[float, str | None, str]] = {}
_cache_lock = threading.Lock()


def _now() -> float:
    return time.monotonic()


def _cache_clear() -> None:
    with _cache_lock:
        _cache.clear()


def _origin_allowed(origin: str) -> str | None:
    return _origin_decision(origin)[0]


def _origin_decision(origin: str, *, retry: bool = False) -> tuple[str | None, str]:
    now = _now()
    with _cache_lock:
        hit = _cache.get(origin)
        if hit and now - hit[0] < DECISION_TTL_S:
            return hit[1], hit[2]
    reason = validate_url(origin)
    cacheable, kind = True, HOST_BLOCKED
    if reason is None:
        reason, cacheable, kind = _resolve_kind(origin, retry=retry)
    if cacheable:
        with _cache_lock:
            if len(_cache) >= _CACHE_MAX:
                _cache.pop(next(iter(_cache)))
            _cache[origin] = (now, reason, kind)
    return reason, kind


def host_check(url: str) -> tuple[str | None, str]:
    """(refusal reason or None, HOST_* kind) for a page URL, sharing the guard's cache."""
    origin = origin_of(url)
    if origin is None:
        return "request URL could not be parsed", HOST_BLOCKED
    return _origin_decision(origin, retry=True)


def checked_addresses(url: str) -> tuple[str | None, str, list[str]]:
    """host_check without the cache, plus the addresses that passed it.

    The HTTP probe connects only to these addresses, so a DNS answer that changes between the
    check and the connect (rebinding, or a 60 s cached decision outliving the record) is never
    dialled. Uncached because the addresses, not only the decision, must be fresh.
    """
    origin = origin_of(url)
    if origin is None:
        return "request URL could not be parsed", HOST_BLOCKED, []
    reason = validate_url(origin)
    if reason:
        return reason, HOST_BLOCKED, []
    reason, _cacheable, kind, addresses = _resolve_addresses(origin, retry=True)
    return reason, kind, addresses


def request_allowed(url: str) -> str | None:
    """Guard for every browser request, judged by origin so long CDN URLs are not refused."""
    scheme = url.split(":", 1)[0].lower() if ":" in url else ""
    if scheme in BROWSER_INTERNAL_SCHEMES:
        return None
    origin = origin_of(url)
    if origin is None:
        return "request URL could not be parsed"
    return _origin_allowed(origin)


request_allowed.cache_clear = _cache_clear  # type: ignore[attr-defined]
