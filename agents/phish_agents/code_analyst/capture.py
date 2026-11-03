# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Capture what the page's code does, inside an instrumented AgentCore Browser session."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import time
from contextlib import AsyncExitStack
from importlib import resources
from urllib.parse import urlparse

from phish_agents.code_analyst import compact_view
from phish_agents.code_analyst.heuristics import code_insights, derive_signals
from phish_agents.code_analyst.static_html import read_static_html
from phish_agents.common import browser, capture_recovery, latency
from phish_agents.common.browser import (
    BLOCKED_BY_BROWSER,
    BROWSER_ERROR,
    NAVIGATION_TIMEOUT,
    CaptureFailure,
    capture_note,
    capture_signals,
    log_capture_failure,
    navigate,
    open_page,
    page_not_found_signal,
    preflight,
    site_block_signal,
)
from phish_agents.common.http_probe import http_probe
from phish_agents.common.timing import CallRecorder
from phish_agents.common.untrusted import sanitize_for_retry, sanitize_values, wrap_untrusted
from phish_contracts.models import CodeInsights, PageStateObservation, Severity, Signal

logger = logging.getLogger(__name__)

INSTRUMENT_JS = (
    resources.files("phish_agents.code_analyst")
    .joinpath("instrument.js")
    .read_text(encoding="utf-8")
)
# -c codeTextBudget=half: the final code_analyst turn is on the scan's critical path, and its
# prompt was 40-49k tokens in the source fork's evaluation, most of it script text. Halved: kit
# logic and exfil endpoints sit in small first-party scripts; large libraries were already cut
# at the per-script limit.
PER_SCRIPT_LIMIT = 10_000 if latency.HALF_CODE_TEXT else 15_000
TOTAL_SCRIPT_LIMIT = 30_000 if latency.HALF_CODE_TEXT else 60_000
SANITIZED_SCRIPT_LIMIT = 20_000
MAX_REQUESTS = 150
# The whole capture, session start, browser and raw HTML fallback included. code_analyst has
# 35 s (common/server.py) for a model turn to call the tool, this capture and the answer
# turn. Before 2026-10-26 the capture could run to the tools server's 25 s ceiling (28 s on
# the client) and nothing after navigation had a bound, so a page that never loaded plus
# both model turns ran past the deadline: 11 www.roblox.rw scans ended as `timeout` errors.
# -c latencyBudgets=true: 18 s, with 3 s kept for the fallback.
CAPTURE_BUDGET_S = 18.0 if latency.TIGHT_BUDGETS else 20.0
# Kept back from the browser for the raw HTML read when the browser cannot load the page.
HTML_FALLBACK_S = 3.0 if latency.TIGHT_BUDGETS else 4.0
# Kept back from navigation (goto, settle, the click past a warning) for the DOM probe, the
# rendered DOM and the script bodies.
AFTER_NAV_S = 2.0
# Script bodies get this long after the DOM read, not the rest of the browser budget. In the
# 2026-10-31 evaluation run, 31 of 160 captures waited to the budget for a body that never
# arrived (a streamed or long-polled script), ending every one of them at ~14.9 s with the page
# already read; bodies that do arrive come back in well under a second.
SCRIPT_BODIES_S = 2.0
# networkidle settle after load. -c latencyBudgets=true: 1.5 s; the source fork measured the
# 2.5 s browser default always reached (pages keep polling), and 1 s missed one backend-driven
# redirect.
SETTLE_MS = 1_500 if latency.TIGHT_BUDGETS else browser.SETTLE_TIMEOUT_MS
_MIN_NAV_MS = 1_000
# Below this a TLS handshake and one GET cannot finish; the fallback is skipped.
_MIN_FALLBACK_S = 1.0
# Browser failures where the site may still answer a plain GET. Not tls_error (the GET meets
# the same certificate), site_unreachable (no host), blocked_by_guard (our policy) or
# blocked_by_site (the site refused us).
_HTML_FALLBACK = frozenset({NAVIGATION_TIMEOUT, BLOCKED_BY_BROWSER, BROWSER_ERROR})
STATIC_HTML_ONLY = "static_html_only"
# Rendered DOM, after scripts ran: hidden inputs, script-built forms and input names.
DOM_HTML_LIMIT = 12_000 if latency.HALF_CODE_TEXT else 20_000
# Large, well-known libraries add tokens and no signal. Matched on the exact hostname
# (and a path prefix where the host is shared), never as a substring of the URL, or an
# attacker could hide a keylogger at https://googletagmanager.com.evil.example/k.js.
_SKIP_SCRIPT_HOSTS = frozenset(
    {
        "googletagmanager.com",
        "www.googletagmanager.com",
        "google-analytics.com",
        "www.google-analytics.com",
        "code.jquery.com",
        "www.gstatic.com",
        "static.cloudflareinsights.com",
    }
)
_SKIP_SCRIPT_PREFIXES = {"cdnjs.cloudflare.com": ("/ajax/libs/jquery/",)}


def skip_script(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    # The managed browser's own recording extension (rrweb) injects chrome-extension://
    # scripts into every page; they are the browser's, not the site's.
    if parsed.scheme == "chrome-extension":
        return True
    if parsed.scheme != "https":
        return False
    host = (parsed.hostname or "").lower()
    if host in _SKIP_SCRIPT_HOSTS:
        return True
    return any(parsed.path.startswith(p) for p in _SKIP_SCRIPT_PREFIXES.get(host, ()))


DOM_PROBE = """() => (window.__phishCollect && window.__phishCollect(), {
  forms: [...document.forms].slice(0, 20).map(f => {
    const inputs = [...f.querySelectorAll('input')].slice(0, 30);
    return {
      action: f.getAttribute('action') || '', method: (f.method || 'get').toLowerCase(),
      inputs: inputs.map(i => (i.type || 'text').toLowerCase()),
      names: inputs.map(i => (i.getAttribute('name') || '').slice(0, 80))
    };
  }),
  inline_scripts: [...document.scripts].filter(s => !s.src).slice(0, 40)
    .map(s => s.textContent || ''),
  script_srcs: [...document.scripts].filter(s => s.src).slice(0, 60).map(s => s.src),
  iframes: [...document.querySelectorAll('iframe')].slice(0, 20).map(f => f.src || ''),
  meta_refresh: (document.querySelector('meta[http-equiv="refresh" i]') || {}).content || null,
  log: window.__phishLog || {listeners: [], sinks: []}
})"""


async def _script_bodies(responses: list, deadline: float) -> dict[str, str]:
    """The script bodies, read concurrently (each is one CDP round trip) until deadline.

    In URL order of the responses; a body that is unreadable or not back by the deadline is
    left out, as the sequential reads before 2026-10-31 left out everything after the cut.
    """

    async def one(resp) -> tuple[str, str] | None:
        try:
            return resp.url, (await resp.text())[:PER_SCRIPT_LIMIT]
        except Exception as exc:  # noqa: BLE001 - one unreadable script must not sink the capture
            logger.info("script body unavailable error=%s", type(exc).__name__)
            return None

    if not responses:
        return {}
    tasks = [asyncio.ensure_future(one(r)) for r in responses]
    done, pending = await asyncio.wait(tasks, timeout=max(deadline - time.monotonic(), 0.0))
    for task in pending:
        task.cancel()
    if pending:
        # Reap the cancelled reads so none is left pending; bounded, a CDP read can be stuck.
        await asyncio.wait(pending, timeout=0.5)
        logger.info("script bodies cut short by the capture budget missing=%d", len(pending))
    bodies: dict[str, str] = {}
    for task in tasks:
        if task in done and task.result() is not None:
            url, text = task.result()
            bodies.setdefault(url, text)
    return bodies


class CodeCapture:
    def __init__(
        self,
        url: str,
        scan_id: str,
        recorder: CallRecorder,
        s3,
        bucket: str,
        open_page_fn=open_page,
        http_probe_fn=None,
    ) -> None:
        self.url = capture_recovery.s3_website_http_url(url)
        self.scan_id, self.recorder = scan_id, recorder
        self.s3, self.bucket, self.open_page_fn = s3, bucket, open_page_fn
        self.http_probe_fn = http_probe_fn
        self.data: dict | None = None
        self.artifacts: list[str] = []
        self.failure: CaptureFailure | None = None
        self.site_block: Signal | None = None

    async def capture(self) -> dict:
        if self.data is not None:
            return self.data
        requests: list[dict] = []
        pending_bodies: list = []

        def on_request(req) -> None:
            if len(requests) < MAX_REQUESTS:
                requests.append(
                    {
                        "url": req.url[:300],
                        "method": req.method,
                        "resource_type": req.resource_type,
                        # post_data decodes the body as UTF-8 and raised on gzip or binary
                        # beacons inside the event listener, which broke every later route
                        # call and failed the capture (D8). The raw buffer never decodes.
                        "has_body": bool(req.post_data_buffer),
                    }
                )

        def on_response(resp) -> None:
            if resp.request.resource_type == "script" and not skip_script(resp.url):
                pending_bodies.append(resp)

        started = time.monotonic()
        end = started + CAPTURE_BUDGET_S
        browser_end = end - HTML_FALLBACK_S
        nav_end = browser_end - AFTER_NAV_S
        # Every step after navigation (the DOM probe, page.content, script bodies) runs in the
        # page and has no timeout of its own, so the browser part has one hard bound.
        budget = asyncio.timeout(browser_end - time.monotonic())
        try:
            async with budget:
                await preflight(self.url)
                async with (
                    self.open_page_fn(
                        self.recorder, "code_analyst", init_script=INSTRUMENT_JS
                    ) as page,
                    AsyncExitStack() as stack,
                ):

                    def listen(target) -> None:
                        # A retry in a certificate-tolerant page describes that page alone.
                        requests.clear()
                        pending_bodies.clear()
                        target.on("request", on_request)
                        target.on("response", on_response)

                    listen(page)

                    # Session start-up comes out of the budget; navigation gets what is left
                    # before nav_end, and the click past a provider warning at most
                    # BYPASS_BUDGET_MS of it.
                    def nav_left_ms() -> int:
                        return int((nav_end - time.monotonic()) * 1000)

                    async def open_url(page, url: str) -> dict:
                        if url != self.url:
                            # The www. sibling: the capture describes its page alone.
                            requests.clear()
                            pending_bodies.clear()
                        return await navigate(
                            page,
                            url,
                            nav_timeout_ms=max(
                                _MIN_NAV_MS, min(browser.NAV_TIMEOUT_MS, nav_left_ms())
                            ),
                            settle_ms=SETTLE_MS,
                            settle_deadline=nav_end,
                            bypass_deadline=min(
                                time.monotonic() + browser.BYPASS_BUDGET_MS / 1000, nav_end
                            ),
                        )

                    # A www. name the certificate does not cover: one try at the bare host; any
                    # other certificate error: one try with certificate checks ignored; a
                    # download: its fingerprint. All inside navigation's share of the budget.
                    nav, page = await capture_recovery.open_capture(
                        stack,
                        page,
                        self.url,
                        open_url,
                        nav_left_ms,
                        _MIN_NAV_MS,
                        init_script=INSTRUMENT_JS,
                        prepare=listen,
                    )
                    self.site_block = page_not_found_signal(nav) or site_block_signal(nav)
                    dom, dom_html = {}, ""
                    if "download" not in nav:
                        # A file, not a page: there is no DOM to probe.
                        dom = await page.evaluate(DOM_PROBE)
                        dom_html = (await page.content())[:DOM_HTML_LIMIT]
                    bodies = await _script_bodies(
                        pending_bodies[:20],
                        min(browser_end - 0.5, time.monotonic() + SCRIPT_BODIES_S),
                    )
                    # The in-page work is done: closing the CDP connection and stopping the
                    # session (bounded in open_page) must not turn this capture into a
                    # capture_budget failure.
                    budget.reschedule(None)
        except Exception as exc:  # noqa: BLE001 - a failed capture is evidence, not a crash
            self.failure = log_capture_failure("code_analyst", exc)
            if budget.expired():
                self.failure = dataclasses.replace(self.failure, code="capture_budget")
            self.data = {
                "error": "capture_failed",
                "category": self.failure.category,
                "reason": self.failure.code,
            }
            await self._static_fallback(end)
            return self.data

        scripts, budget = [], TOTAL_SCRIPT_LIMIT
        for text in dom.get("inline_scripts", []):
            chunk = text[: min(PER_SCRIPT_LIMIT, budget)]
            if chunk:
                scripts.append({"src": None, "text": chunk})
                budget -= len(chunk)
        in_dom = dom.get("script_srcs", [])
        # Scripts that were fetched and then removed from the DOM are a classic loader
        # trick, so every fetched body is kept, not only those still in document.scripts.
        removed = [u for u in bodies if u not in set(in_dom)]
        for src, present in [*((u, True) for u in in_dom), *((u, False) for u in removed)]:
            chunk = bodies.get(src, "")[: max(min(PER_SCRIPT_LIMIT, budget), 0)]
            scripts.append({"src": src[:300], "text": chunk, "in_dom": present})
            budget -= len(chunk)
        log = dom.get("log") or {}
        data = {
            **nav,
            "forms": dom.get("forms", []),
            "dom_html": dom_html,
            "iframes": dom.get("iframes", []),
            "meta_refresh": dom.get("meta_refresh"),
            "scripts": scripts,
            "requests": requests,
            "listeners": log.get("listeners", []),
            "sinks": log.get("sinks", []),
        }
        for signal in capture_signals(data):
            data[signal.name] = signal.evidence
        data["derived_signals"] = derive_signals(data, urlparse(nav["final_url"]).hostname or "")
        self._store(data)
        self.data = data
        return data

    def _store(self, data: dict) -> None:
        key = f"scans/{self.scan_id}/capture.json"
        self.s3.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=json.dumps(data).encode(),
            ContentType="application/json",
        )
        self.artifacts.append(key)

    async def _static_fallback(self, end: float) -> None:
        """After a browser failure the site may still answer a plain GET: read its raw HTML
        with the guarded HTTP probe, never executing it, inside what is left of the budget."""
        left = end - time.monotonic()
        if self.failure is None or self.failure.category not in _HTML_FALLBACK:
            return
        if left < _MIN_FALLBACK_S:
            logger.info("raw HTML fallback skipped: %.1f s left", left)
            return
        static = await read_static_html(self.url, left, self.http_probe_fn or http_probe)
        logger.info("raw HTML fallback %s", "read" if static else "had no usable page")
        if static is None:
            return
        self.data["static_html"] = static
        try:
            # boto3 blocks; off the event loop, and a failed upload keeps the result.
            await asyncio.to_thread(self._store, self.data)
        except Exception as exc:  # noqa: BLE001 - capture.json is an artifact, not the result
            logger.warning("capture.json upload failed error=%s", type(exc).__name__)

    def _static(self) -> dict | None:
        static = (self.data or {}).get("static_html")
        return static if isinstance(static, dict) else None

    def static_only(self) -> bool:
        """The browser failed and the page was judged from its raw HTML excerpt alone."""
        return bool(self.failure and self._static())

    def signals(self) -> list[Signal]:
        if self.failure:
            signal = self.failure.signal()
            out = [signal] if signal else []
            if self._static():
                out.append(
                    Signal(
                        name=STATIC_HTML_ONLY,
                        severity=Severity.LOW,
                        evidence=(
                            f"The browser could not load the page ({self.failure.category}); "
                            "its raw HTML was read with a plain HTTP GET instead: not rendered, "
                            "scripts not run, so the rendered page was not observed."
                        ),
                    )
                )
            return out
        data = self.data or {}
        return [] if "error" in data else capture_signals(data)

    def note(self) -> str | None:
        if self.failure and self._static():
            return (
                "The page did not load in the browser, so its raw HTML was read instead "
                "(not rendered, scripts not run); the rendered page was not observed."
            )
        data = self.data or {}
        return capture_note(
            self.failure,
            self.site_block,
            data.get("provider_warning"),
            browser.sibling_capture(data),
        )

    def page_observed(self) -> bool:
        return browser.page_observed(self.failure, self.data)

    def page_state(self) -> PageStateObservation | None:
        return browser.recognised_page_state(self.failure, self.data)

    def chain(self) -> list[dict]:
        return list((self.data or {}).get("redirect_chain") or [])

    def insights(self) -> CodeInsights | None:
        data = self.data
        if not data or "error" in data:
            return None
        host = urlparse(data.get("final_url") or self.url).hostname or ""
        return CodeInsights(**code_insights(data, host))

    def model_view(self, sanitize: bool) -> str:
        data = self.data or {"error": "capture_failed", "reason": "not captured"}
        static = self._static()
        if "error" in data and self.failure and static:
            if sanitize:
                static = sanitize_values(static, 2_000)
            return (
                f"{self.failure.category} ({self.failure.code}): the browser could not load "
                f"the page. A plain HTTP GET read its raw HTML instead. Signal "
                f"`{STATIC_HTML_ONLY}`: this excerpt is {static['source']}, so script-built "
                "forms, listeners and network calls are missing and the rendered page was not "
                "observed.\n"
                + wrap_untrusted(
                    "raw HTML excerpt, not rendered, scripts not run",
                    json.dumps(static, separators=(",", ":")),
                    30_000,
                )
            )
        if "error" in data:
            return self.failure.tool_text() if self.failure else f"capture_failed: {data['reason']}"
        sibling = browser.sibling_capture(data)
        if sanitize:
            data = self._sanitized(data)
        notes = []
        # The guardrail retry gets the full sanitized view: the denser compact view of a kit
        # config drew repeated model refusals that the full view never did.
        if compact_view.enabled() and not sanitize:
            try:
                data = compact_view.compact_capture(data, compact_view.budget_tokens())
                notes.append(compact_view.NOTE)
            except Exception:  # noqa: BLE001 - the full view is always a valid answer
                logger.exception("compact model view failed, sending the full view")
        view = wrap_untrusted("page code capture", json.dumps(data, separators=(",", ":")), 70_000)
        # Our words, outside the fence, so the model reads them as fact, not page content.
        if sibling:
            notes.insert(0, browser.WWW_SIBLING_TOOL_TEXT)
        return "\n".join([*notes, view])

    @staticmethod
    def _sanitized(data: dict) -> dict:
        # Only script bodies carry free text worth emptying; URLs, form actions and listener
        # targets are the evidence and stay intact. Scripts share a smaller retry budget.
        scripts, budget = [], SANITIZED_SCRIPT_LIMIT
        for script in data.get("scripts", []):
            text = sanitize_for_retry(script.get("text") or "", max(budget, 0))
            budget -= len(text)
            scripts.append({**script, "text": text})
        dom_html = sanitize_for_retry(data.get("dom_html") or "", DOM_HTML_LIMIT)
        return {**data, "scripts": scripts, "dom_html": dom_html}
