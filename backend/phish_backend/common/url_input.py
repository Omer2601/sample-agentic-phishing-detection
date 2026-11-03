# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Syntax checks on URLs submitted for scanning.

This rejects what can never be scanned or would aim the browser at internal
addresses by literal. DNS-based SSRF checks happen in the agents
(agents/phish_agents/common/url_safety.py) right before the browser navigates,
because DNS can change between submission and scan.
"""

from urllib.parse import urlsplit

from phish_contracts.ip_literal import AmbiguousIpLiteral, parse_ip_literal, unwrap_mapped

MAX_URL_LENGTH = 2048
_LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}


class InvalidUrl(ValueError):
    pass


def validate_submitted_url(raw: object) -> str:
    if raw is None or raw == "":
        raise InvalidUrl("url is required")
    if not isinstance(raw, str):
        raise InvalidUrl("url must be a string")
    url = raw.strip()
    if not url:
        raise InvalidUrl("url is required")
    if len(url) > MAX_URL_LENGTH:
        raise InvalidUrl(f"url is longer than {MAX_URL_LENGTH} characters")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise InvalidUrl("url contains whitespace or control characters")
    lowered = url.lower()
    if not lowered.startswith(("http://", "https://")):
        raise InvalidUrl("url must start with http:// or https://")
    try:
        host = urlsplit(url).hostname
    except ValueError as exc:
        raise InvalidUrl("url could not be parsed") from exc
    if not host:
        raise InvalidUrl("url has no host")
    if host.lower().rstrip(".") in _LOCAL_NAMES or host.lower().endswith(".localhost"):
        raise InvalidUrl("url targets a private or reserved address")
    # Integer, octal, hex and short-dotted IPv4 hosts are read as the address they spell,
    # as the browser and the OS resolver read them, before the private-address check.
    try:
        address = parse_ip_literal(host)
    except AmbiguousIpLiteral as exc:
        raise InvalidUrl("url host is not a valid address") from exc
    if address is None:
        return url
    if not address.is_global or not unwrap_mapped(address).is_global:
        raise InvalidUrl("url targets a private or reserved address")
    return url


def error_or_none(raw: str) -> str | None:
    """Adapter for feed.py, which takes a validator returning an error string or None."""
    try:
        validate_submitted_url(raw)
    except InvalidUrl as exc:
        return str(exc)
    return None
