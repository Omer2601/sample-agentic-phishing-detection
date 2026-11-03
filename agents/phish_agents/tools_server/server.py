# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The shared tools MCP server: capture_page, capture_page_code, whois_lookup and precheck_url.

One AgentCore Runtime behind one Gateway target. The specialists call these tools through the
Gateway instead of running a browser or an RDAP client in their own process, so the browser and
outbound-network permissions live on this Runtime's role only.

Every tool checks its input itself (url_safety for the URL, validate_scan_id for the S3 key):
the Gateway authenticates the caller but cannot tell which specialist asked, so the server
treats every caller as untrusted. The capture tools upload their artifact to S3 from here
(screenshot.png, capture.json) and return a JSON payload; the image never passes through a model
or the Gateway.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from urllib.parse import urlparse

import boto3
from mcp.server import MCPServer

from phish_agents.brand_visual.capture import BrandCapture
from phish_agents.code_analyst.capture import CodeCapture
from phish_agents.common import latency
from phish_agents.common import server as common_server
from phish_agents.common.browser import (
    BLOCKED_BY_BROWSER,
    BLOCKED_BY_GUARD,
    NAVIGATION_TIMEOUT,
    NOT_FOUND_STATUS,
    SITE_UNREACHABLE,
    CaptureFailure,
    classify_failure,
    open_page,
    precheck_navigation,
    preflight,
)
from phish_agents.common.capture_recovery import s3_website_http_url
from phish_agents.common.finding import validate_scan_id
from phish_agents.common.http_probe import TOTAL_S as HTTP_PROBE_S
from phish_agents.common.http_probe import http_probe
from phish_agents.common.remote_tools import capture_payload
from phish_agents.common.timing import CallRecorder
from phish_agents.common.url_safety import validate_url
from phish_agents.url_analyst.whois import rdap_lookup, registered_domain

logger = logging.getLogger(__name__)

# A backstop above the capture's own budget (code_analyst/capture.py CAPTURE_BUDGET_S, 20 s,
# browser and raw HTML fallback included), so a stuck capture still returns a failed one
# before the client gives up (remote_tools.CODE_CAPTURE_TIMEOUT_S).
CODE_CAPTURE_DEADLINE_S = 20 if latency.TIGHT_BUDGETS else 22
WHOIS_DEADLINE_S = 8
# precheck_url is a fast path for dead links, so it must be cheap: a hard cap on the whole call,
# session start included: 8 s navigation (browser.PRECHECK_NAV_TIMEOUT_MS) plus start-up, then
# up to 8 s for the HTTP probe when the browser timed out. The backend client waits 22 s.
PRECHECK_DEADLINE_S = 19


def _s3():
    return boto3.client("s3", region_name=os.environ["AWS_REGION"])


def _refused(reason: str) -> str:
    """The payload for a URL our guard refuses, in the shape a failed capture has."""
    failure = CaptureFailure(BLOCKED_BY_GUARD, "url_safety", reason)
    return json.dumps(
        {
            "data": {
                "error": "capture_failed",
                "category": failure.category,
                "reason": failure.code,
            },
            "artifacts": [],
            "failure": {"category": failure.category, "code": failure.code, "detail": reason},
            "site_block": None,
        }
    )


async def run_capture_page(url: str, scan_id: str, *, s3=None, open_page_fn=open_page) -> str:
    validate_scan_id(scan_id)
    reason = validate_url(url)
    if reason:
        return _refused(reason)
    cap = BrandCapture(
        url, scan_id, CallRecorder(), s3 or _s3(), os.environ["ARTIFACTS_BUCKET"], open_page_fn
    )
    await cap.capture()
    return json.dumps(capture_payload(cap))


async def run_capture_page_code(url: str, scan_id: str, *, s3=None, open_page_fn=open_page) -> str:
    validate_scan_id(scan_id)
    reason = validate_url(url)
    if reason:
        return _refused(reason)
    cap = CodeCapture(
        url, scan_id, CallRecorder(), s3 or _s3(), os.environ["ARTIFACTS_BUCKET"], open_page_fn
    )
    try:
        await asyncio.wait_for(cap.capture(), CODE_CAPTURE_DEADLINE_S)
    except TimeoutError:
        logger.warning("capture_page_code deadline after %ss", CODE_CAPTURE_DEADLINE_S)
        return json.dumps(
            {
                "data": {
                    "error": "capture_failed",
                    "category": "navigation_timeout",
                    "reason": "timeout",
                },
                "artifacts": [],
                "failure": {"category": "navigation_timeout", "code": "timeout", "detail": ""},
                "site_block": None,
            }
        )
    return json.dumps(capture_payload(cap))


async def run_whois_lookup(url: str, *, lookup=rdap_lookup) -> str:
    """RDAP for the URL's registered domain. The caller passes a URL, not a domain, so this
    tool cannot be used to query arbitrary names."""
    reason = validate_url(url)
    if reason:
        return json.dumps({"domain": "", "error": "url_refused"})
    domain = registered_domain(urlparse(url).hostname or "")
    try:
        result = await asyncio.wait_for(asyncio.to_thread(lookup, domain), WHOIS_DEADLINE_S)
    except TimeoutError:
        result = {"domain": domain, "error": "lookup_failed"}
    return json.dumps(result)


def _precheck_result(
    outcome: str,
    status: int | None = None,
    final_url: str = "",
    *,
    hops: list[str] | None = None,
    reason: str = "",
    probe: str = "browser",
    browser_refused: bool = False,
) -> str:
    return json.dumps(
        {
            "outcome": outcome,
            "final_status": status,
            "final_url": final_url,
            "hops": hops or [],
            "reason": reason,
            "probe": probe,
            "browser_refused": browser_refused,
        }
    )


# Browser failures the plain HTTP probe can still answer: a refusal before any request,
# a dead host, or a page too slow to commit. tls_error is left out on purpose: the host
# answered, so the outcome is `unreachable` (a full scan), never `site_down`, and a plain
# GET would only meet the same certificate.
_HTTP_FALLBACK = frozenset({BLOCKED_BY_BROWSER, SITE_UNREACHABLE, NAVIGATION_TIMEOUT})
# Below this the HTTP probe cannot finish a TLS handshake and one GET; it is skipped.
_MIN_HTTP_PROBE_S = 1.5


async def run_precheck_url(
    url: str,
    scan_id: str,
    *,
    open_page_fn=open_page,
    preflight_fn=preflight,
    http_probe_fn=http_probe,
) -> str:
    """Navigate only and report how the site answers.

    Outcomes: `error_404` when the FINAL response after redirects is exactly HTTP 404;
    `site_down` when the plain HTTP probe finds the site gone (410, DNS failure, refused or
    reset connection, a redirect to a host that does not resolve); `ok`; `blocked` (our
    guard); `unreachable` (inconclusive). Callers treat `ok`, `unreachable` and `blocked`
    alike: only `error_404` and `site_down` end the scan early. The HTTP probe runs only when
    the browser was refused, found no host, or timed out, inside the same PRECHECK_DEADLINE_S
    cap. A certificate or TLS error is always `unreachable`: the site answered, so it is not
    down. The tool writes nothing to S3.
    """
    validate_scan_id(scan_id)
    reason = validate_url(url)
    if reason:
        return _precheck_result("blocked", reason=reason)
    # An S3 website endpoint has no TLS listener: over https it resets or times out and the
    # HTTP probe would call the site down (2 rows wrongly dead in the 2026-10-31 evaluation).
    url = s3_website_http_url(url)
    started = time.monotonic()

    async def browse() -> dict:
        # No browser session for a host that does not resolve.
        await preflight_fn(url)
        async with open_page_fn(CallRecorder(), "precheck_url") as page:
            return await precheck_navigation(page, url)

    try:
        nav = await asyncio.wait_for(browse(), PRECHECK_DEADLINE_S)
    except Exception as exc:  # noqa: BLE001 - the worker must always get an outcome back
        failure = classify_failure(exc)
        logger.info("precheck_url failed category=%s code=%s", failure.category, failure.code)
        if failure.category == BLOCKED_BY_GUARD:
            return _precheck_result("blocked", reason=failure.detail or failure.code)
        left_s = min(HTTP_PROBE_S, PRECHECK_DEADLINE_S - (time.monotonic() - started))
        if failure.category not in _HTTP_FALLBACK or left_s < _MIN_HTTP_PROBE_S:
            return _precheck_result("unreachable", reason=f"{failure.category}: {failure.code}")
        http = await http_probe_fn(url, total_s=left_s)
        logger.info("precheck_url http probe outcome=%s", http["outcome"])
        return _precheck_result(
            http["outcome"],
            http["final_status"],
            http["final_url"],
            hops=http["hops"],
            reason=http["reason"],
            probe="http",
            browser_refused=failure.category == BLOCKED_BY_BROWSER,
        )
    status = nav["status"]
    outcome = "error_404" if status == NOT_FOUND_STATUS else "ok"
    return _precheck_result(
        outcome, status, nav["final_url"], hops=nav["hops"], reason=f"HTTP {status}"
    )


def build_server(*, s3=None, open_page_fn=open_page, lookup=rdap_lookup) -> MCPServer:
    mcp = MCPServer("phish-tools")

    @mcp.tool(
        name="capture_page",
        description=(
            "Open the URL in an isolated AgentCore Browser, save a viewport screenshot to the "
            "scan's artifacts and return the title, final URL and visible text as JSON "
            "(data, artifacts, failure, site_block). The screenshot is stored, not returned."
        ),
    )
    async def capture_page(url: str, scan_id: str) -> str:
        return await run_capture_page(url, scan_id, s3=s3, open_page_fn=open_page_fn)

    @mcp.tool(
        name="capture_page_code",
        description=(
            "Open the URL in an instrumented AgentCore Browser and return its forms, scripts, "
            "network requests, listeners and data sinks as JSON; also saved as capture.json."
        ),
    )
    async def capture_page_code(url: str, scan_id: str) -> str:
        return await run_capture_page_code(url, scan_id, s3=s3, open_page_fn=open_page_fn)

    @mcp.tool(
        name="whois_lookup",
        description=(
            "RDAP registration data (age, registrar, status, nameservers) for the registered "
            "domain of the given URL, as JSON."
        ),
    )
    async def whois_lookup(url: str) -> str:
        return await run_whois_lookup(url, lookup=lookup)

    @mcp.tool(
        name="precheck_url",
        description=(
            "Fast check of how the site answers, with no screenshot or analysis: navigate in an "
            "AgentCore Browser (plain guarded HTTP GET when the browser cannot answer), follow "
            "redirects and return {outcome, final_status, final_url, hops, reason, probe, "
            "browser_refused}. outcome is error_404 only when the final response is HTTP 404 "
            "and site_down only when the site is gone; ok, unreachable and blocked all mean "
            "the URL still needs a full scan."
        ),
    )
    async def precheck_url(url: str, scan_id: str) -> str:
        return await run_precheck_url(url, scan_id, open_page_fn=open_page_fn)

    return mcp


def main() -> None:
    common_server.serve(build_server())


if __name__ == "__main__":
    main()
