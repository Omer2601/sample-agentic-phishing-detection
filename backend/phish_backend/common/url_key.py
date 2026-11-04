# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Canonical URL form and the per-owner dedup key stored on every scan row.

The normalisation is deliberately conservative: a false match hands one page's phishing
verdict to a different page, while a missed match only costs one extra scan. It folds
only what is case-insensitive or redundant by definition: scheme case, host case, the
Unicode/punycode spelling of a host and an explicit default port. Everything else is
kept verbatim:

- a non-ASCII host is folded to its lowercase A-label with IDNA 2008 / UTS-46
  non-transitional processing (`idna` package), as browsers do, so `café.example` and
  `xn--caf-dma.example` share a key while `faß`/`fass` and final/medial sigma stay
  distinct; a host `idna` rejects falls back to plain lowercasing;
- a trailing dot on the host is kept (it can change the origin and Host routing);
- bracketed IP literals (IPv6, IPvFuture) keep their brackets;
- userinfo, path, query and fragment are kept, since servers and single-page apps can
  serve a different page for any difference in them (including `#/route` fragments).
"""

import hashlib
from urllib.parse import urlsplit, urlunsplit

import idna

DEDUP_KEY_VERSION = "v1"
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _split_authority(netloc: str) -> tuple[str, str, str]:
    """(userinfo, host, port text) from a netloc, keeping IP-literal brackets."""
    userinfo, at, hostport = netloc.rpartition("@")
    if hostport.startswith("["):
        end = hostport.find("]")
        if end == -1:
            return userinfo if at else "", hostport, ""
        host, rest = hostport[: end + 1], hostport[end + 1 :]
        return userinfo if at else "", host, rest[1:] if rest.startswith(":") else ""
    host, _, port = hostport.partition(":")
    return userinfo if at else "", host, port


def _fold_host(host: str) -> str:
    """Lowercase ASCII hosts; fold non-ASCII ones to their UTS-46 non-transitional A-label."""
    if host.isascii():
        return host.lower()
    try:
        return idna.encode(host, uts46=True, transitional=False).decode("ascii").lower()
    except (UnicodeError, ValueError):
        return host.lower()


def normalize_url(url: str) -> str:
    """Return the canonical form of an already validated http(s) URL.

    A URL the parser cannot split (for example an out-of-range port) is returned
    stripped but otherwise unchanged, so the key stays deterministic.
    """
    raw = url.strip()
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        return raw
    userinfo, host, _ = _split_authority(parts.netloc)
    if not host:
        return raw
    scheme = parts.scheme.lower()
    host = _fold_host(host)
    netloc = host if port in (None, _DEFAULT_PORTS.get(scheme)) else f"{host}:{port}"
    if userinfo or "@" in parts.netloc:
        netloc = f"{userinfo}@{netloc}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, parts.fragment))


def dedup_key(owner: str, url: str) -> str:
    """SHA-256 hex of the owner and normalised URL; never shared across owners."""
    material = f"{DEDUP_KEY_VERSION}\n{owner}\n{normalize_url(url)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
