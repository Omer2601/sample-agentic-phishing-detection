# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Canonical URL form and the per-owner dedup key stored on every scan row.

The normalisation is deliberately conservative: a false match hands one page's phishing
verdict to a different page, while a missed match only costs one extra scan. It folds only
what is case-insensitive or redundant by definition: scheme case, host case and an explicit
default port. Everything else is kept verbatim: a trailing dot on the host, IP-literal
brackets, userinfo, path, query and fragment (single-page apps route on `#/...`).
"""

import hashlib
from urllib.parse import urlsplit, urlunsplit

DEDUP_KEY_VERSION = "v1"
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _split_authority(netloc: str) -> tuple[str, str]:
    """(userinfo, host) from a netloc, keeping IP-literal brackets."""
    userinfo, at, hostport = netloc.rpartition("@")
    if hostport.startswith("["):
        end = hostport.find("]")
        host = hostport if end == -1 else hostport[: end + 1]
    else:
        host = hostport.partition(":")[0]
    return (userinfo if at else ""), host


def normalize_url(url: str) -> str:
    """The canonical form of an already validated http(s) URL.

    A URL the parser cannot split (for example an out-of-range port) is returned stripped
    but otherwise unchanged, so the key stays deterministic.
    """
    raw = url.strip()
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        return raw
    userinfo, host = _split_authority(parts.netloc)
    if not host:
        return raw
    scheme = parts.scheme.lower()
    # ponytail: a non-ASCII host is only lowercased, so its Unicode and punycode spellings get
    # different keys (a missed match, one extra scan). Fold with UTS-46 if that ever matters.
    host = host.lower()
    netloc = host if port in (None, _DEFAULT_PORTS.get(scheme)) else f"{host}:{port}"
    if userinfo or "@" in parts.netloc:
        netloc = f"{userinfo}@{netloc}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, parts.fragment))


def dedup_key(owner: str, url: str) -> str:
    """SHA-256 hex of the owner and the normalised URL; never shared across owners."""
    material = f"{DEDUP_KEY_VERSION}\n{owner}\n{normalize_url(url)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
