# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Redirect chains as evidence: which hops change site, land on free hosting or a shortener.

A chain is a list of hops, oldest first: {"url", "via", "status"?, "error"?}. `via` is start,
http (a 3xx), client (a script or meta refresh navigation) or warning_bypass (the one click
past a provider warning). annotate() adds the flags the Finding and the UI show; facts() sums
them up for a model. Both are pure: the URLs are only parsed, never fetched.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from phish_agents.url_analyst.whois import registered_domain
from phish_contracts.models import REDIRECT_HOPS_MAX, REDIRECT_URL_MAX, RedirectHop

START, HTTP, CLIENT, WARNING_BYPASS = "start", "http", "client", "warning_bypass"

# Registered domains where anyone can publish a site in minutes; a new subdomain of one is a
# new site. ponytail: a short hand-kept list, swap for the Public Suffix List's private section
# if misses show up in the evaluation.
FREE_HOSTING = frozenset(
    {
        "pages.dev",
        "workers.dev",
        "github.io",
        "gitlab.io",
        "netlify.app",
        "vercel.app",
        "web.app",
        "firebaseapp.com",
        "weebly.com",
        "wixsite.com",
        "godaddysites.com",
        "square.site",
        "blogspot.com",
        "glitch.me",
        "onrender.com",
        "herokuapp.com",
        "webflow.io",
        "framer.app",
        "000webhostapp.com",
        "r2.dev",
    }
)
SHORTENERS = frozenset(
    {
        "bit.ly",
        "t.co",
        "tinyurl.com",
        "is.gd",
        "goo.gl",
        "ow.ly",
        "rebrand.ly",
        "cutt.ly",
        "t.ly",
        "rb.gy",
        "shorturl.at",
        "tiny.cc",
        "lnkd.in",
        "s.id",
    }
)


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _site(host: str) -> str:
    """What counts as one site: the registered domain, or the full host on free hosting."""
    domain = registered_domain(host) if host else ""
    return host if domain in FREE_HOSTING else domain


def annotate(hops: list[dict]) -> list[RedirectHop]:
    """The chain as RedirectHop models, flagged, at most REDIRECT_HOPS_MAX hops."""
    out: list[RedirectHop] = []
    previous = ""
    for hop in hops[:REDIRECT_HOPS_MAX]:
        url = str(hop.get("url") or "")[:REDIRECT_URL_MAX]
        host = _host(url)
        site = _site(host)
        status = hop.get("status")
        out.append(
            RedirectHop(
                url=url,
                via=str(hop.get("via") or START),
                status=status if isinstance(status, int) and not isinstance(status, bool) else None,
                error=(str(hop["error"])[:120] if hop.get("error") else None),
                cross_domain=bool(previous and site and site != previous),
                free_hosting=registered_domain(host) in FREE_HOSTING if host else False,
                shortener=host in SHORTENERS or registered_domain(host) in SHORTENERS,
            )
        )
        previous = site or previous
    return out


def facts(start_url: str, chain: list[RedirectHop]) -> dict:
    """A compact summary of a chain for a model prompt."""
    final = chain[-1].url if chain else start_url
    return {
        "hops": [h.model_dump(exclude_defaults=True) for h in chain],
        "cross_domain_hops": sum(h.cross_domain for h in chain),
        "via_free_hosting_or_shortener": any((h.free_hosting or h.shortener) for h in chain[:-1]),
        "lands_on_free_hosting_or_shortener": any(
            (h.free_hosting or h.shortener) and h.cross_domain for h in chain
        ),
        "final_host_differs": bool(chain) and _site(_host(final)) != _site(_host(start_url)),
    }
