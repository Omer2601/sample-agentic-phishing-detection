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


@asynccontextmanager
async def tls_tolerant_page(page, *, init_script: str | None = None) -> AsyncIterator:
    """A new page in a new browser context that ignores certificate errors, in the same
    browser session as `page`. Only this context is lenient; the route guard and init script
    are installed exactly as in browser.open_page."""
    remote = page.context.browser
    if remote is None:
        raise PlaywrightError("no browser to open a certificate-tolerant context in")
    # Service workers can answer requests that context.route never sees, so the guard_route
    # SSRF check would not apply to them; this lenient context blocks them.
    options: dict = {"ignore_https_errors": True, "service_workers": "block"}
    if page.viewport_size:
        options["viewport"] = page.viewport_size
    context = await remote.new_context(**options)
    try:
        await context.route("**/*", browser.guard_route)
        if init_script:
            await context.add_init_script(init_script)
        yield await context.new_page()
    finally:
        await browser._bounded("tolerant context close", context.close())


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
    certificate-tolerant context entered on `stack`, whose page is returned).

    prepare(page) runs on the tolerant page before it navigates (request listeners). If the
    tolerant retry fails, or less than min_ms is left, the original failure is raised.
    """
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
        cert_type = browser.certificate_error_type(failure)
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
