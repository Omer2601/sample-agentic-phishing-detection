# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Deterministic page-state recognition: takedown, parked and S3 AccessDenied pages.

Every rule is an exact response pattern seen in the 2026-10-31 capture-failure analysis
(31 taken-down, 29 parked and 7 S3 AccessDenied rows). The S3 and Vercel rules need the
provider's status and error markers. The page text is attacker-controlled, so the suspended,
for-sale text and /lander rules never match a page that asks for input (a form or a credential
field), and those rules (except an error-status "Site suspended" title) also need the captured
DOM to check that: a lure page that says "suspended" or "for sale", or sits at /lander, cannot
earn a benign page state.
The result is a fact about the page, not a verdict. It goes on Finding.page_state, a code-only
field that is never shown to the model (so it cannot sway the verdict), and
phish_contracts.page_state turns it into Verdict.verdict_detail. It describes what the site
served to the sandbox; a page that imitates a provider's error document can still earn it,
which is why it never changes the verdict.
"""

from __future__ import annotations

import html
import re
from urllib.parse import urlparse

from phish_contracts.models import PageState, PageStateObservation
from phish_contracts.page_state import (
    FOR_SALE_LANDER,
    GODADDY_LANDER,
    PROVIDER_SUSPENDED_PAGE,
    S3_ACCESS_DENIED,
    S3_ALL_ACCESS_DISABLED,
    VERCEL_451_DEPLOYMENT_UNAVAILABLE,
)

# The S3 error document always carries RequestId and HostId next to the code; matching both
# keeps a page that merely mentions the word from counting.
_S3_ERROR_IDS = re.compile(r"<RequestId>.*</RequestId>.*<HostId>", re.IGNORECASE | re.DOTALL)
_S3_ALL_ACCESS_DISABLED = re.compile(r"<Code>\s*AllAccessDisabled\s*</Code>")
_S3_ACCESS_DENIED = re.compile(r"<Code>\s*AccessDenied\s*</Code>")
_VERCEL_UNAVAILABLE = re.compile(r"deployment\s+unavailable", re.IGNORECASE)
_SUSPENDED_TITLE = re.compile(r"^\s*site suspended\b", re.IGNORECASE)
_SUSPENDED_BODY = re.compile(
    r"has been suspended because it links to content that was flagged as unsafe|"
    r"provider has suspended it for abuse",
    re.IGNORECASE,
)
_LANDER_REDIRECT = re.compile(
    r"""location(?:\.href)?\s*=\s*["']/lander["']|location\.replace\(\s*["']/lander["']""",
    re.IGNORECASE,
)
_FOR_SALE_HOSTS = ("forsale.godaddy.com", "hugedomains.com", "dynadot.com", "sedo.com")
_FOR_SALE_TEXT = re.compile(
    r"\b(?:this|the) domain(?: name)?(?: \S+)? (?:is|may be) for sale\b", re.IGNORECASE
)
_INPUT_PAGE = re.compile(r"<form\b|<input\b|<textarea\b", re.IGNORECASE)
_BODY_LIMIT = 20_000


def _body(nav: dict) -> str:
    parts = [nav.get(key) for key in ("dom_html", "visible_text", "body_text")]
    # html.unescape: an XML error document can come back escaped inside a viewer's markup.
    return html.unescape("\n".join(p for p in parts if isinstance(p, str))[: _BODY_LIMIT * 2])


def _urls(nav: dict) -> list[str]:
    urls = [nav.get("final_url")]
    for hop in nav.get("redirect_chain") or []:
        urls.append(hop.get("url") if isinstance(hop, dict) else None)
    return [u for u in urls if isinstance(u, str)]


def _host_path(url: str) -> tuple[str, str]:
    try:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower(), parsed.path or ""
    except ValueError:
        return "", ""


def _for_sale_host(host: str) -> bool:
    return any(host == h or host.endswith("." + h) for h in _FOR_SALE_HOSTS)


def classify(nav: dict) -> tuple[PageState, str] | None:
    """(page state, reason) for a recognised page, else None."""
    status = nav.get("status")
    title = (nav.get("title") or "").strip()
    body = _body(nav)
    if status == 403 and _S3_ERROR_IDS.search(body):
        if _S3_ALL_ACCESS_DISABLED.search(body):
            return PageState.TAKEN_DOWN, S3_ALL_ACCESS_DISABLED
        if _S3_ACCESS_DENIED.search(body):
            return PageState.S3_ACCESS_DENIED, S3_ACCESS_DENIED
    if status == 451 and (_VERCEL_UNAVAILABLE.search(title) or _VERCEL_UNAVAILABLE.search(body)):
        return PageState.TAKEN_DOWN, VERCEL_451_DEPLOYMENT_UNAVAILABLE
    hosts_paths = [_host_path(u) for u in _urls(nav)]
    # A page served by a for-sale marketplace's own host is not attacker-controlled, so it needs
    # no gate. Only the final URL counts: an earlier hop there proves nothing about the page.
    if _for_sale_host(_host_path(nav.get("final_url") or "")[0]):
        return PageState.PARKED, FOR_SALE_LANDER
    dom = nav.get("dom_html") if isinstance(nav.get("dom_html"), str) else None
    if dom is not None and _INPUT_PAGE.search(html.unescape(dom)):
        return None
    # Text-only rules need the DOM: without it a form on the page could not be ruled out.
    text_rules = dom is not None
    if (isinstance(status, int) and status >= 400 and _SUSPENDED_TITLE.search(title)) or (
        text_rules and _SUSPENDED_BODY.search(body)
    ):
        return PageState.TAKEN_DOWN, PROVIDER_SUSPENDED_PAGE
    if text_rules and _FOR_SALE_TEXT.search(f"{title}\n{body}"):
        return PageState.PARKED, FOR_SALE_LANDER
    if text_rules and (
        any(path.rstrip("/") == "/lander" for _, path in hosts_paths)
        or _LANDER_REDIRECT.search(body)
    ):
        return PageState.PARKED, GODADDY_LANDER
    return None


def observation(nav: dict | None) -> PageStateObservation | None:
    """classify() as the code-only Finding.page_state, or None."""
    match = classify(nav) if nav else None
    if match is None:
        return None
    state, reason = match
    return PageStateObservation(page_state=state, reason=reason)
