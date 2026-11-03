# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""RDAP (the JSON successor to WHOIS) lookup for the scan's registered domain."""

from __future__ import annotations

import logging
from datetime import date

import httpx

from phish_agents.common import cache
from phish_agents.common.url_safety import resolve_and_validate, validate_url

logger = logging.getLogger(__name__)

RDAP_BOOTSTRAP = "https://rdap.org/domain/"
# Second-level labels that sit under a country TLD (bbc.co.uk). A small list keeps the
# image free of a public-suffix dependency; a miss only makes WHOIS look up a parent.
_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "or", "ne", "go"}


def registered_domain(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _guard_request(request: httpx.Request) -> None:
    # rdap.org redirects to the registry's server; every hop gets the same SSRF check.
    url = str(request.url)
    reason = validate_url(url) or resolve_and_validate(url)
    if reason:
        raise httpx.RequestError(f"refused RDAP hop: {reason}", request=request)


def _event(data: dict, action: str) -> str | None:
    for event in data.get("events", []):
        if event.get("eventAction") == action and event.get("eventDate"):
            return event["eventDate"][:10]
    return None


def _registrar(data: dict) -> str | None:
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            for entry in (entity.get("vcardArray") or [None, []])[1]:
                if entry and entry[0] == "fn":
                    return str(entry[3])
    return None


def _age_days(registered: str | None, today: str | None) -> int | None:
    if not registered:
        return None
    return (
        date.fromisoformat(today or date.today().isoformat()) - date.fromisoformat(registered)
    ).days


def _shape(domain: str, fields: dict, today: str | None) -> dict:
    # Age is derived here, at read time, from the stored creation date: a cached row never
    # freezes the age at the day it was fetched.
    registered = fields.get("registered")
    return {
        "domain": domain,
        "registered": registered,
        "expires": fields.get("expires"),
        "last_changed": fields.get("last_changed"),
        "age_days": _age_days(registered, today),
        "registrar": fields.get("registrar"),
        "status": list(fields.get("status") or [])[:6],
        "nameservers": list(fields.get("nameservers") or [])[:6],
    }


def _cached_fields(domain: str, today: str | None) -> dict | None:
    """The cached RDAP fields as a result, or None (miss, damaged row, caching off)."""
    stored = cache.get(cache.rdap_key(registered_domain(domain)))
    if stored is None:
        return None
    try:
        return _shape(domain, stored, today)
    except (TypeError, ValueError) as exc:
        logger.warning("cache row ignored type=rdap error=%s", type(exc).__name__)
        return None


def rdap_lookup(
    domain: str, *, client: httpx.Client | None = None, today: str | None = None
) -> dict:
    # Cached per registered domain, so a.example.com and b.example.com share one row. Only a
    # successful, non-empty answer is stored; errors, 404s and rate limits always go live.
    hit = _cached_fields(domain, today)
    if hit is not None:
        return hit
    owns_client = client is None
    client = client or httpx.Client(
        timeout=6.0, follow_redirects=True, event_hooks={"request": [_guard_request]}
    )
    try:
        response = client.get(RDAP_BOOTSTRAP + domain, headers={"Accept": "application/rdap+json"})
    except httpx.HTTPError as exc:
        logger.info("rdap lookup failed domain=%s error=%s", domain, type(exc).__name__)
        return {"domain": domain, "error": "lookup_failed"}
    finally:
        if owns_client:
            client.close()
    if response.status_code == 404:
        return {"domain": domain, "error": "not_found"}
    if response.status_code != 200:
        return {"domain": domain, "error": f"http_{response.status_code}"}
    try:
        data = response.json()
        fields = {
            "registered": _event(data, "registration"),
            "expires": _event(data, "expiration"),
            "last_changed": _event(data, "last changed"),
            "registrar": _registrar(data),
            "status": data.get("status", [])[:6],
            "nameservers": [ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])][
                :6
            ],
        }
        shaped = _shape(domain, fields, today)
    except (ValueError, TypeError, AttributeError, IndexError, KeyError) as exc:
        # A 200 with an HTML error page, a truncated body, an unexpected JSON shape, a short
        # vCard entry or an eventDate that is not a date. Shaped before caching, so a body
        # that cannot be read is never stored.
        logger.info("rdap parse failed domain=%s error=%s", domain, type(exc).__name__)
        return {"domain": domain, "error": "lookup_failed"}
    # An answer with neither a creation date nor a registrar is empty for our purposes; do not
    # let it displace a real lookup for the next TTL. A subdomain answer is not stored under
    # the registered domain's key either.
    if (fields["registered"] or fields["registrar"]) and domain.lower().strip(
        "."
    ) == registered_domain(domain):
        cache.put(cache.rdap_key(domain), fields, cache.rdap_ttl_s())
    return shaped
