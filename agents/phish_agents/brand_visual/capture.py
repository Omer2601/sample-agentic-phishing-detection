# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Capture the page once: screenshot bytes to S3, visible text and title to the model."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import time
from contextlib import AsyncExitStack

from botocore.exceptions import BotoCoreError, ClientError
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeout

from phish_agents.common import browser, capture_recovery, latency
from phish_agents.common.browser import (
    CaptureFailure,
    capture_note,
    capture_signals,
    log_capture_failure,
    navigate,
    open_page,
    page_not_found_signal,
    preflight,
    rendered_after_timeout,
    site_block_signal,
    viewport_png,
)
from phish_agents.common.timing import CallRecorder
from phish_agents.common.untrusted import sanitize_for_retry, wrap_untrusted
from phish_contracts.models import PageStateObservation, Signal

logger = logging.getLogger(__name__)

TEXT_LIMIT = 6000
# Findings from 2026-09-30: the browser step errored at about 29 s (Playwright's 30 s
# default on a screenshot or text read) and the 30 s analysis deadline fired before the
# model ran. The whole capture, session start included, now gets 14 s, which leaves the
# model about 14 s inside common/server.py deadline_s().
CAPTURE_BUDGET_S = 14.0
# Navigation runs to the navigation deadline (budget minus _AFTER_NAV_MS), not a fixed
# cap: on 2026-10-01 sopport-service.app had not committed when a fixed 8 s goto timeout
# fired with 3.7 s of the budget unused. Kept only as an upper bound.
NAV_TIMEOUT_MS = 12_000
# A screenshot needs the page painted, not quiet: after domcontentloaded, settle on load
# for at most 1 s, and only out of navigation's share of the budget.
SETTLE_MS = 1_000
# The CDP capture plus S3 upload took 0.47 to 0.72 s on the 2026-10-01 rescan; the rest
# of this is the page.screenshot fallback's (browser.viewport_png).
SCREENSHOT_TIMEOUT_MS = 2_000
# -c latencyBudgets=true: what the screenshot may use when navigation ended early. In the source
# fork's evaluation 28 of 160 screenshots timed out at the 2 s share with 3.5 to 7.4 s of the
# budget unused.
SCREENSHOT_MAX_MS = 5_000
# S3 put of a viewport PNG, so the artifact is saved before the budget can expire.
UPLOAD_RESERVE_MS = 500
TEXT_TIMEOUT_MS = 1_000
# Kept back from navigation for the screenshot and its upload. Navigation (goto plus
# settle) ends at deadline minus this, then the screenshot is taken of whatever rendered.
# On 2026-10-01 session start and CDP connect took 2 to 5.3 s, which leaves navigation
# 6 to 9.5 s. The text read only gets what is left: it is not the evidence that matters.
_AFTER_NAV_MS = SCREENSHOT_TIMEOUT_MS + UPLOAD_RESERVE_MS
_MIN_NAV_MS = 1_000
# -c latencyBudgets=true: never less for the screenshot; 296 to 798 ms shares timed out on pages
# that had loaded in the source fork's capture-failure analysis.
_MIN_SCREENSHOT_MS = 1_500 if latency.TIGHT_BUDGETS else 500
_MIN_TEXT_MS = 200
# The capture's own clock, so tests can model a slow session start.
_clock = time.monotonic


def _ms_until(deadline: float) -> int:
    return int((deadline - _clock()) * 1000)


class BrandCapture:
    def __init__(
        self,
        url: str,
        scan_id: str,
        recorder: CallRecorder,
        s3,
        bucket: str,
        open_page_fn=open_page,
    ) -> None:
        self.url = capture_recovery.s3_website_http_url(url)
        self.scan_id, self.recorder = scan_id, recorder
        self.s3, self.bucket, self.open_page_fn = s3, bucket, open_page_fn
        self.data: dict | None = None
        self.png: bytes | None = None
        self.artifacts: list[str] = []
        self.failure: CaptureFailure | None = None
        self.site_block: Signal | None = None
        self._nav: dict | None = None
        self._ended_early = False

    async def capture(self) -> dict:
        if self.data is not None:
            return self.data
        budget = asyncio.timeout(CAPTURE_BUDGET_S)
        try:
            async with budget:
                nav, text = await self._capture(_clock() + CAPTURE_BUDGET_S)
        except Exception as exc:  # noqa: BLE001 - a failed capture is evidence, not a crash
            if self.artifacts and self._nav is not None:
                # The screenshot is already in S3; losing the text or a clean session close
                # must not turn a saved capture into a failed one.
                logger.warning(
                    "capture ended after the screenshot was saved error=%s", type(exc).__name__
                )
                self.data = {**self._nav, "visible_text": ""}
                self._ended_early = True
                return self.data
            self.failure = log_capture_failure("brand_visual", exc)
            if budget.expired():
                self.failure = dataclasses.replace(self.failure, code="capture_budget")
            self.data = {
                "error": "capture_failed",
                "category": self.failure.category,
                "reason": self.failure.code,
            }
            return self.data
        self.data = {**nav, "visible_text": text[:TEXT_LIMIT]}
        return self.data

    async def _capture(self, deadline: float) -> tuple[dict, str]:
        await preflight(self.url)
        async with (
            self.open_page_fn(self.recorder, "brand_visual") as page,
            AsyncExitStack() as stack,
        ):
            # Session start-up comes out of the same budget; navigation gets what is left
            # after the screenshot's share, and can never spend that share.
            nav_deadline = deadline - _AFTER_NAV_MS / 1000

            async def open_url(page, url: str) -> dict:
                nav_timeout_ms = max(_MIN_NAV_MS, min(NAV_TIMEOUT_MS, _ms_until(nav_deadline)))
                try:
                    return await navigate(
                        page,
                        url,
                        nav_timeout_ms=nav_timeout_ms,
                        settle_state="load",
                        settle_ms=SETTLE_MS,
                        settle_deadline=time.monotonic() + max(_ms_until(nav_deadline), 0) / 1000,
                        # The click past a provider warning comes out of navigation's share too.
                        bypass_deadline=time.monotonic() + max(_ms_until(nav_deadline), 0) / 1000,
                    )
                except (PlaywrightTimeout, TimeoutError):
                    # Keep whatever rendered: a half-loaded phishing page is still evidence.
                    partial = await rendered_after_timeout(page)
                    if partial is None:
                        raise
                    logger.info(
                        "navigation timed out after %d ms; capturing what rendered", nav_timeout_ms
                    )
                    return {**partial, "navigation_timed_out": True}

            # A www. name the certificate does not cover: one try at the bare host; any other
            # certificate error: one try with certificate checks ignored; a download: its
            # fingerprint. All inside navigation's share of the same budget.
            nav, page = await capture_recovery.open_capture(
                stack, page, self.url, open_url, lambda: _ms_until(nav_deadline), _MIN_NAV_MS
            )
            self._nav = nav
            if "download" in nav:
                # A file, not a page: nothing to screenshot or read.
                return nav, ""
            self.site_block = page_not_found_signal(nav) or site_block_signal(nav)
            remaining_ms = _ms_until(deadline) - UPLOAD_RESERVE_MS
            if latency.TIGHT_BUDGETS:
                # The 1.5 s floor never outlasts the budget itself: a nearly spent budget gets a
                # shorter shot instead of a capture lost to the budget timeout.
                shot_ms = max(
                    min(_MIN_SCREENSHOT_MS, max(remaining_ms, 1)),
                    min(SCREENSHOT_MAX_MS, remaining_ms),
                )
            else:
                shot_ms = max(_MIN_SCREENSHOT_MS, min(SCREENSHOT_TIMEOUT_MS, remaining_ms))
            shot_started = _clock()
            try:
                self.png = await viewport_png(page, shot_ms)
            except (PlaywrightError, TimeoutError) as exc:
                if not latency.TIGHT_BUDGETS:
                    raise
                # The page loaded: its navigation facts and text are still the capture. Only
                # the image is missing, as when the upload below fails.
                logger.warning(
                    "screenshot failed after the page loaded error=%s", type(exc).__name__
                )
                self.png = None
                nav = {**nav, "screenshot_failed": True}
                self._nav = nav
            # Saved before anything else can fail or time out, so the artifact survives.
            if self.png:
                await self._upload_screenshot()
            logger.info(
                "screenshot saved=%s shot_ms=%d shot_took_ms=%d left_ms=%d",
                bool(self.artifacts),
                shot_ms,
                int((_clock() - shot_started) * 1000),
                _ms_until(deadline),
            )
            text_ms = max(_MIN_TEXT_MS, min(TEXT_TIMEOUT_MS, _ms_until(deadline)))
            text = await self._visible_text(page, text_ms)
        return nav, text

    async def _upload_screenshot(self) -> None:
        key = f"scans/{self.scan_id}/screenshot.png"
        try:
            await asyncio.to_thread(
                self.s3.put_object,
                Bucket=self.bucket,
                Key=key,
                Body=self.png,
                ContentType="image/png",
            )
        except (BotoCoreError, ClientError) as exc:
            # The model still sees the image; only the stored artifact is missing.
            logger.warning("screenshot upload failed error=%s", type(exc).__name__)
            return
        self.artifacts.append(key)

    @staticmethod
    async def _visible_text(page, timeout_ms: int = TEXT_TIMEOUT_MS) -> str:
        try:
            return await page.inner_text("body", timeout=timeout_ms)
        except PlaywrightError as exc:
            # The screenshot is the evidence that matters; missing text is not a failed capture.
            logger.info("visible text unavailable error=%s", type(exc).__name__)
            return ""

    def capture_status(self) -> str:
        """One word (or a failure category) for logs and error Findings, never a bare timeout."""
        if self.failure:
            return f"failed ({self.failure.category}: {self.failure.code})"
        if self.data is None:
            return "not_captured"
        if "download" in self.data:
            return "download"
        if not self.artifacts:
            return "screenshot_not_saved"
        # A capture that errored after the screenshot was saved kept its evidence but did not
        # finish cleanly, so it is partial, never complete.
        if self._ended_early or self.data.get("navigation_timed_out"):
            return "partial"
        return "complete"

    def signals(self) -> list[Signal]:
        if self.failure:
            signal = self.failure.signal()
            return [signal] if signal else []
        data = self.data or {}
        return [] if "error" in data else capture_signals(data)

    def note(self) -> str | None:
        data = self.data or {}
        return capture_note(
            self.failure,
            self.site_block,
            data.get("provider_warning"),
            browser.sibling_capture(data),
            data.get("block_retry"),
        )

    def page_observed(self) -> bool:
        return browser.page_observed(self.failure, self.data)

    def page_state(self) -> PageStateObservation | None:
        return browser.recognised_page_state(self.failure, self.data)

    def chain(self) -> list[dict]:
        return list((self.data or {}).get("redirect_chain") or [])

    def tool_result(self, sanitize: bool) -> dict:
        data = self.data or {"error": "capture_failed", "reason": "not captured"}
        if "error" in data:
            text = self.failure.tool_text() if self.failure else f"capture_failed: {data['reason']}"
            return {"status": "success", "content": [{"text": text}]}
        text = data["visible_text"]
        meta_fields = {k: data[k] for k in ("final_url", "status", "title")}
        if data.get("navigation_timed_out"):
            meta_fields["load_status"] = (
                "the page did not finish loading in time; this is what had rendered"
            )
        if data.get("screenshot_failed"):
            # Only with -c latencyBudgets=true, which keeps a loaded page whose screenshot failed.
            meta_fields["screenshot"] = (
                "not available: the screenshot failed after the page loaded; there is no image "
                "to judge, so the page's appearance is unknown, not benign"
            )
        for signal in self.signals():
            meta_fields[signal.name] = signal.evidence
        if self.chain():
            meta_fields["redirect_chain"] = [
                {k: h[k] for k in ("url", "via", "status", "error") if h.get(k) is not None}
                for h in self.chain()
            ]
        if browser.sibling_capture(data):
            meta_fields["sibling_capture"] = data["sibling_capture"]
        for key in ("download", "tls_certificate"):
            if isinstance(data.get(key), dict):
                meta_fields[key] = data[key]
        meta = json.dumps(meta_fields)
        body = f"{meta}\n{sanitize_for_retry(text, TEXT_LIMIT) if sanitize else text}"
        wrapped = wrap_untrusted("page capture", body, TEXT_LIMIT + 500)
        if browser.sibling_capture(data):
            # Our words, outside the fence, so the model reads them as fact, not page content.
            wrapped = f"{browser.WWW_SIBLING_TOOL_TEXT}\n{wrapped}"
        content = [{"text": wrapped}]
        if not sanitize and self.png:
            # The retry drops the screenshot too: an image can be what tripped the filter.
            content.append({"image": {"format": "png", "source": {"bytes": self.png}}})
        return {"status": "success", "content": content}
