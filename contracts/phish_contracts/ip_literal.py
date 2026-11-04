# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Parse a URL host the way browsers and the OS resolver read numeric IP literals.

`ipaddress.ip_address` accepts only canonical dotted-quad IPv4, but Chromium (WHATWG URL
host parsing) and glibc's inet_aton, which getaddrinfo uses for numeric hosts, also accept
integer (`2130706433`), octal (`0177.0.0.1`), hex (`0x7f.1`) and short-dotted (`127.1`)
forms. A check that only recognises the canonical form lets those through as "hostnames"
while the client still connects to the address they spell. `parse_ip_literal` normalises
every such form to the address the client would dial, so the private-address check is
applied to that address.
"""

from __future__ import annotations

import ipaddress
import re

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_HEX = re.compile(r"0[xX][0-9a-fA-F]*")
_OCTAL = re.compile(r"0[0-7]+")
_DECIMAL = re.compile(r"0|[1-9][0-9]*")
_NUMERIC_LABEL = re.compile(r"[0-9]+|0[xX][0-9a-fA-F]*")


class AmbiguousIpLiteral(ValueError):
    """The host ends in a number but is not a valid IP literal.

    Browsers refuse such hosts and resolvers may read them as addresses, so they are
    neither a safe hostname nor a known address; callers must reject them.
    """


def _part_value(part: str) -> int:
    if _HEX.fullmatch(part):
        return int(part[2:] or "0", 16)
    if _OCTAL.fullmatch(part):
        return int(part, 8)
    if _DECIMAL.fullmatch(part):
        return int(part, 10)
    raise AmbiguousIpLiteral(f"invalid IPv4 component {part!r}")


def _parse_ipv4(host: str) -> ipaddress.IPv4Address | None:
    labels = host[:-1].split(".") if host.endswith(".") else host.split(".")
    if not _NUMERIC_LABEL.fullmatch(labels[-1]):
        return None
    if len(labels) > 4 or any(label == "" for label in labels):
        raise AmbiguousIpLiteral(f"invalid IPv4 literal {host!r}")
    values = [_part_value(label) for label in labels]
    *head, last = values
    if any(v > 255 for v in head) or last >= 256 ** (5 - len(values)):
        raise AmbiguousIpLiteral(f"IPv4 literal {host!r} is out of range")
    number = last
    for index, value in enumerate(head):
        number += value << (8 * (3 - index))
    return ipaddress.IPv4Address(number)


def parse_ip_literal(host: str) -> IPAddress | None:
    """The address a numeric URL host denotes, or None when the host is a domain name.

    Accepts the host as `urllib.parse.urlsplit(url).hostname` returns it (no brackets).
    Raises AmbiguousIpLiteral for a host that ends in a number but is not a valid literal.
    """
    if ":" in host:
        try:
            return ipaddress.IPv6Address(host.split("%", 1)[0])
        except ValueError as exc:
            raise AmbiguousIpLiteral(f"invalid IPv6 literal {host!r}") from exc
    return _parse_ipv4(host)


def unwrap_mapped(address: IPAddress) -> IPAddress:
    """The IPv4 address inside an IPv4-mapped IPv6 address (::ffff:a.b.c.d), else itself."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address
