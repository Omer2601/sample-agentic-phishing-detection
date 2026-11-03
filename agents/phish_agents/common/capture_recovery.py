# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Capture recovery for three failure modes found in the 2026-10-31 capture-failure analysis.

- S3 website endpoints have no TLS listener, so https:// on one never loads (9 rows, 2 of them
  wrongly judged dead): s3_website_http_url sends them over http://.
- A certificate error (self-signed, wrong name, expired, unknown CA) was fatal to the capture
  (14 rows): open_capture retries once in a fresh browser context that ignores certificate
  errors, scoped to that context only, behind the same route guard, and records
  `tls_certificate` so the page is never treated as trusted.
- A URL that answers with a file made `goto` fail with "Download is starting" (3 rows):
  open_capture cancels the browser download and fingerprints the file with one guarded,
  size-capped GET (http_probe.download_fingerprint). The file is never opened or executed.

With CAPTURE_BLOCK_RETRY=1 (browser.block_retry_enabled), two more, both from the 2026-11-01
fake-shop eval:
- A certificate that does not match the host, reached over http://, failed as
  net::ERR_BLOCKED_BY_CLIENT (the managed browser upgrades to https and refuses), not as a
  certificate error, so the tolerant retry never ran. A browser refusal now gets the same one
  retry; its `tls_certificate` type says the certificate error was not confirmed.
- A bot wall (browser.bot_block_reason) gets one retry in a fresh context with a desktop
  Chrome profile (user agent without the AgentCore token, en-US locale and Accept-Language,
  New York time zone, 1366x768). Same route guard and init script. The first capture keeps its
  whole navigation budget; the retry gets at most BLOCK_RETRY_MS of what is left, and a retry
  that runs out or only half-renders keeps the first capture. `block_retry` records the outcome.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from urllib.parse import urlparse, urlunparse

from playwright.async_api import Error as PlaywrightError

from phish_agents.common import browser, http_probe
from phish_agents.common.url_safety import capture_recovery_enabled
from phish_contracts.models import REDIRECT_URL_MAX

logger = logging.getLogger(__name__)

# <bucket>.s3-website-<region>.amazonaws.com and <bucket>.s3-website.<region>.amazonaws.com
# (and the .com.cn partition). S3 website endpoints serve HTTP only.
_S3_WEBSITE_HOST = re.compile(
    r"\.s3-website[-.][a-z]{2}(?:-gov|-iso[a-z]?)?-[a-z]+-\d+\.amazonaws\.com(?:\.cn)?$"
)
TLS_CHECKS_IGNORED = "ignored_for_this_capture"
DOWNLOAD_FETCH_S = 8.0
_MIN_DOWNLOAD_FETCH_S = 1.0
# "Download is starting" can reach goto before the download event does.
_DOWNLOAD_EVENT_WAIT_S = 1.0
_FILENAME_LIMIT = 120
_UNSAFE_FILENAME = re.compile(r"[\x00-\x1f\x7f/\\]+")
_DISPOSITION_FILENAME = re.compile(r"""filename\*?=(?:UTF-8'')?["']?([^"';]+)""", re.IGNORECASE)


def s3_website_http_url(url: str) -> str:
    """http:// for an https:// S3 website endpoint on the default port; any other URL as is."""
    if not capture_recovery_enabled():
        return url
    try:
        parsed = urlparse(url)
        host, port = (parsed.hostname or "").lower(), parsed.port
    except ValueError:
        return url
    if parsed.scheme != "https" or port not in (None, 443) or not _S3_WEBSITE_HOST.search(host):
        return url
    logger.info("s3 website endpoint opened over http (no TLS listener)")
    return urlunparse(("http", host, parsed.path, parsed.params, parsed.query, parsed.fragment))


BLOCK_RETRY_PROFILE = "desktop_chrome_en_us"
# Measured 2026-11-02: real recoveries finished in 2.1-6.7 s and still-blocked answers in
# 0.5-4.5 s; the retries that ran on to the ~9 s navigation budget only timed out.
BLOCK_RETRY_MS = 7_000
UPGRADE_REFUSAL_CODE = "net::ERR_BLOCKED_BY_CLIENT"
_DESKTOP_VIEWPORT = {"width": 1366, "height": 768}
_DESKTOP_LOCALE = "en-US"
_DESKTOP_TIMEZONE = "America/New_York"
_DESKTOP_HEADERS = {"Accept-Language": "en-US,en;q=0.9"}
_CHROME_MAJOR = re.compile(r"^(\d+)\.")


def desktop_user_agent(browser_version: str) -> str:
    """A Windows desktop Chrome user agent for the remote browser's own major version."""
    match = _CHROME_MAJOR.match(browser_version or "")
    major = match.group(1) if match else "130"
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{major}.0.0.0 Safari/537.36"
    )


@asynccontextmanager
async def alternate_page(
    page,
    *,
    init_script: str | None = None,
    ignore_https_errors: bool = False,
    desktop_profile: bool = False,
) -> AsyncIterator:
    """A new page in a new browser context in the same browser session as `page`, with the
    route guard and init script installed exactly as in browser.open_page. Only this context
    is lenient about certificates (ignore_https_errors) or wears the desktop profile."""
    remote = page.context.browser
    if remote is None:
        raise PlaywrightError("no browser to open another context in")
    # Service workers can answer requests that context.route never sees, so the guard_route
    # SSRF check would not apply to them; every alternate context blocks them.
    options: dict = {"service_workers": "block"}
    if ignore_https_errors:
        options["ignore_https_errors"] = True
    if desktop_profile:
        options.update(
            user_agent=desktop_user_agent(remote.version),
            locale=_DESKTOP_LOCALE,
            timezone_id=_DESKTOP_TIMEZONE,
            extra_http_headers=dict(_DESKTOP_HEADERS),
            viewport=dict(_DESKTOP_VIEWPORT),
        )
    elif page.viewport_size:
        options["viewport"] = page.viewport_size
    context = await remote.new_context(**options)
    try:
        await context.route("**/*", browser.guard_route)
        if init_script:
            await context.add_init_script(init_script)
        yield await context.new_page()
    finally:
        await browser._bounded("alternate context close", context.close())


def tls_tolerant_page(page, *, init_script: str | None = None):
    """A new page in a new browser context that ignores certificate errors (alternate_page)."""
    return alternate_page(page, init_script=init_script, ignore_https_errors=True)


class DownloadWatch:
    """Remembers the first download a page starts, so a failed goto can tell it was one."""

    def __init__(self, page) -> None:
        self.download = None
        self._page = page
        on = getattr(page, "on", None)
        self._listening = callable(on)
        if self._listening:
            on("download", self._on_download)

    def _on_download(self, download) -> None:
        if self.download is None:
            self.download = download

    async def wait(self, timeout_s: float) -> None:
        """Wait up to timeout_s for the download event: goto can fail before it arrives."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_s
        while self.download is None and self._listening and loop.time() < deadline:
            await asyncio.sleep(0.05)

    def started(self, exc: BaseException) -> bool:
        return self.download is not None or browser._DOWNLOAD_STARTING in str(exc)

    def close(self) -> None:
        remove = getattr(self._page, "remove_listener", None)
        if not self._listening or not callable(remove):
            return
        self._listening = False
        try:
            remove("download", self._on_download)
        except (PlaywrightError, KeyError, ValueError):
            logger.debug("download listener already gone")


def safe_filename(name: str | None) -> str:
    """The file's base name with control characters and separators removed, capped."""
    base = re.split(r"[/\\]", (name or "").strip())[-1]
    return _UNSAFE_FILENAME.sub("_", base).strip(" .")[:_FILENAME_LIMIT]


def _disposition_filename(disposition: str) -> str:
    match = _DISPOSITION_FILENAME.search(disposition or "")
    return match.group(1) if match else ""


async def download_nav(watch: DownloadWatch, url: str, left_ms, fingerprint) -> dict:
    """A capture record for a navigation that answered with a file instead of a page."""
    if watch.download is None:
        await watch.wait(_DOWNLOAD_EVENT_WAIT_S)
    download = watch.download
    file_url, suggested = url, ""
    if download is not None:
        file_url = getattr(download, "url", "") or url
        suggested = getattr(download, "suggested_filename", "") or ""
        try:
            await asyncio.wait_for(download.cancel(), browser.CLOSE_TIMEOUT_S)
        except (PlaywrightError, TimeoutError):
            logger.debug("download cancel did not complete")
    total_s = max(_MIN_DOWNLOAD_FETCH_S, min(DOWNLOAD_FETCH_S, left_ms() / 1000))
    found = await fingerprint(file_url, total_s=total_s)
    logger.info(
        "download response fingerprinted outcome=%s kind=%s bytes=%s truncated=%s",
        found["outcome"],
        found["kind"],
        found["bytes_read"],
        found["truncated"],
    )
    filename = safe_filename(suggested or _disposition_filename(found["content_disposition"]))
    if not filename:
        filename = safe_filename(urlparse(found["final_url"] or file_url).path)
    return {
        "final_url": (found["final_url"] or file_url)[:REDIRECT_URL_MAX],
        "status": found["status"],
        "title": "",
        "redirect_chain": [],
        "download": {
            "filename": filename,
            "sha256": found["sha256"],
            "size": found["size"],
            "bytes_read": found["bytes_read"],
            "size_cap": found["size_cap"],
            "truncated": found["truncated"],
            "content_type": found["content_type"],
            "sniffed_type": found["sniffed_type"],
            "kind": found["kind"] or "other",
            "fetch_outcome": found["outcome"],
            "fetched": "guarded_refetch",
        },
    }


async def _open_or_download(page, url, open_url, left_ms, fingerprint) -> dict:
    watch = DownloadWatch(page)
    try:
        return await open_url(page, url)
    except PlaywrightError as exc:
        if not watch.started(exc):
            raise
        return await download_nav(watch, url, left_ms, fingerprint)
    finally:
        watch.close()


async def open_capture(
    stack: AsyncExitStack,
    page,
    url: str,
    open_url,
    left_ms,
    min_ms: int,
    *,
    init_script: str | None = None,
    prepare=None,
    fingerprint=http_probe.download_fingerprint,
) -> tuple[dict, object]:
    """(nav, page): open_url(page, url) through browser.open_with_www_sibling, recovering
    from a download (fingerprinted, never opened) and from a certificate error (one retry in a
    certificate-tolerant context entered on `stack`, whose page is returned). With
    CAPTURE_BLOCK_RETRY on, a browser refusal also gets the tolerant retry and a bot wall one
    retry with the desktop profile (block_retry).

    prepare(page) runs on a retry page before it navigates (request listeners). If the
    tolerant retry fails, or less than min_ms is left, the original failure is raised.
    """
    nav, page = await _open_recovering(
        stack, page, url, open_url, left_ms, min_ms, init_script, prepare, fingerprint
    )
    if not browser.block_retry_enabled():
        return nav, page
    return await _retry_bot_block(
        stack, page, url, nav, open_url, left_ms, min_ms, init_script, prepare, fingerprint
    )


def _tolerant_retry_type(failure: browser.CaptureFailure) -> str | None:
    cert_type = browser.certificate_error_type(failure)
    if cert_type is None and browser.block_retry_enabled():
        # Chrome's http->https upgrade reports a certificate it refuses as BLOCKED_BY_CLIENT.
        if failure.code == UPGRADE_REFUSAL_CODE:
            return browser.TLS_UNCONFIRMED
    return cert_type


async def _open_recovering(
    stack, page, url, open_url, left_ms, min_ms, init_script, prepare, fingerprint
) -> tuple[dict, object]:
    if not capture_recovery_enabled():
        # Earlier behaviour: a download or a certificate error fails the capture as it is.
        nav = await browser.open_with_www_sibling(
            url, lambda target: open_url(page, target), left_ms, min_ms
        )
        return nav, page
    watch = DownloadWatch(page)
    try:
        nav = await browser.open_with_www_sibling(
            url, lambda target: open_url(page, target), left_ms, min_ms
        )
        return nav, page
    except PlaywrightError as exc:
        if watch.started(exc):
            return await download_nav(watch, url, left_ms, fingerprint), page
        failure = browser.classify_failure(exc)
        cert_type = _tolerant_retry_type(failure)
        if cert_type is None:
            raise
        if left_ms() < min_ms:
            logger.info("certificate-tolerant retry skipped: %d ms left", left_ms())
            raise
        logger.info(
            "certificate error code=%s; retrying with certificate checks ignored", failure.code
        )
        try:
            tolerant = await stack.enter_async_context(
                tls_tolerant_page(page, init_script=init_script)
            )
            if prepare is not None:
                prepare(tolerant)
            if left_ms() < min_ms:
                raise PlaywrightError(f"no time left after context setup: {left_ms()} ms")
            nav = await _open_or_download(tolerant, url, open_url, left_ms, fingerprint)
        except Exception as retry_exc:  # noqa: BLE001 - the original failure is the one reported
            retry = browser.classify_failure(retry_exc)
            logger.info(
                "certificate-tolerant retry failed category=%s code=%s",
                retry.category,
                retry.code,
            )
            raise exc from None
        cert = {"type": cert_type, "code": failure.code, "certificate_checks": TLS_CHECKS_IGNORED}
        return {**nav, "tls_certificate": cert}, tolerant
    finally:
        watch.close()


async def _retry_bot_block(
    stack, page, url, nav, open_url, left_ms, min_ms, init_script, prepare, fingerprint
) -> tuple[dict, object]:
    """One retry with the desktop profile when the page is a bot wall. The retry's page is
    kept when it navigated (recovered or still blocked); a failed retry keeps the first."""
    reason = browser.bot_block_reason(nav)
    if reason is None or browser.sibling_capture(nav):
        return nav, page
    record = {
        "reason": reason,
        "first_status": nav.get("status"),
        "profile": BLOCK_RETRY_PROFILE,
    }
    if left_ms() < min_ms:
        logger.info("bot-wall retry skipped: %d ms left", left_ms())
        return {**nav, "block_retry": {**record, "outcome": "skipped_no_time"}}, page
    tolerant = isinstance(nav.get("tls_certificate"), dict)
    logger.info(
        "bot wall reason=%s status=%s; retrying with the desktop profile",
        reason,
        nav.get("status"),
    )
    restore = None
    retry_s = min(BLOCK_RETRY_MS, left_ms()) / 1000
    try:
        async with asyncio.timeout(retry_s):
            alt = await stack.enter_async_context(
                alternate_page(
                    page,
                    init_script=init_script,
                    ignore_https_errors=tolerant,
                    desktop_profile=True,
                )
            )
            if prepare is not None:
                restore = prepare(alt)
            if left_ms() < min_ms:
                raise PlaywrightError(f"no time left after context setup: {left_ms()} ms")
            retried = await _open_or_download(alt, url, open_url, left_ms, fingerprint)
        if retried.get("navigation_timed_out"):
            raise TimeoutError("the retry only half-rendered before its navigation timed out")
    except Exception as exc:  # noqa: BLE001 - the first, blocked capture is still the capture
        if callable(restore):
            restore()
        timed_out = isinstance(exc, TimeoutError)
        failure = browser.classify_failure(exc)
        logger.info(
            "bot-wall retry failed category=%s code=%s budget_ms=%d",
            failure.category,
            failure.code,
            int(retry_s * 1000),
        )
        outcome = "retry_timed_out" if timed_out else "retry_failed"
        return {**nav, "block_retry": {**record, "outcome": outcome}}, page
    if tolerant:
        retried = {**retried, "tls_certificate": nav["tls_certificate"]}
    outcome = "still_blocked" if browser.bot_block_reason(retried) else "recovered"
    logger.info("bot-wall retry outcome=%s status=%s", outcome, retried.get("status"))
    return {**retried, "block_retry": {**record, "outcome": outcome}}, alt
