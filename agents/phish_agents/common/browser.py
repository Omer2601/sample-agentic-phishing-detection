# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""One AgentCore Browser session per call, driven over CDP with Playwright.

The screenshot and page data come back as bytes and text in this process, so they
never sit in a sandbox path that a later call cannot read (the v1 failure).
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

from bedrock_agentcore.tools.browser_client import BrowserClient
from botocore.exceptions import ClientError
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeout
from playwright.async_api import async_playwright

from phish_agents.common import page_state, redirects, url_safety
from phish_agents.common.timing import CallRecorder
from phish_agents.common.url_safety import request_allowed
from phish_contracts.models import (
    REDIRECT_URL_MAX,
    CallKind,
    PageState,
    PageStateObservation,
    Severity,
    Signal,
)
from phish_contracts.page_state import BLOCK_PAGE, BOT_CHALLENGE_PAGE, BOT_FILTER_PAGE

logger = logging.getLogger(__name__)

BROWSER_ID = os.environ.get("BROWSER_ID", "aws.browser.v1")
# Perf analysis 2026-09-29 (842 browser captures): p50 4.2 s, 5% over 15 s, 3% over 20 s.
# One slow page stalls the whole scan (the next specialist waits for it), so
# navigation gets 15 s and the networkidle settle 2.5 s: a page still loading after that
# is reported as a failed capture, which the orchestrator already treats as a gap.
NAV_TIMEOUT_MS = 15_000
SETTLE_TIMEOUT_MS = 2_500
SESSION_TIMEOUT_SECONDS = 180
TITLE_TIMEOUT_S = 1.0


class BlockedNavigation(Exception):  # noqa: N818 - reads as the refusal it reports
    """Our url_safety guard refused the scan URL, a redirect hop or the final URL."""


class BrowserRefused(Exception):  # noqa: N818 - reads as the refusal it reports
    """The browser, or the AgentCore Browser service, refused the navigation (error page)."""


class DnsTransientError(Exception):  # noqa: N818 - reads as the finding it reports
    """The resolver failed on the scan host, even after one retry, without saying NXDOMAIN."""


class SiteUnreachable(Exception):  # noqa: N818 - reads as the finding it reports
    """The scan host does not resolve, so there is no page to open."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# Capture failure categories. site_unreachable, tls_error and the three blocked_by_*
# categories become signals (tls_error and blocked_by_browser only as low capture gaps); the
# others are gaps in our capture. Kept small so logs and the model see the same vocabulary.
SITE_UNREACHABLE = "site_unreachable"
# The host answered, but its certificate or TLS handshake was rejected (net::ERR_CERT_*,
# net::ERR_SSL_*). One rule for every such code, in the capture, the precheck and the HTTP
# probe: the site is NOT down (something answered on the port, so a `site_down` verdict
# would be false) and a bad certificate is NOT phishing evidence on its own (expired,
# self-signed and wrong-name certificates are common on neglected legitimate sites, while
# most phishing kits sit behind valid free certificates). It is a capture gap: the page was
# not seen, so it lowers confidence and the verdict rests on the URL and the other findings.
# Before 2026-10-18 these codes were site_unreachable, which the specialists read as
# "unreachable is evidence" (suspicious) and the orchestrator as "could not be reached"
# (site_down), so the same certificate error gave either verdict.
TLS_ERROR = "tls_error"
NAVIGATION_TIMEOUT = "navigation_timeout"
# The resolver failed without answering NXDOMAIN (EAI_AGAIN, OSError errno 16), even after
# url_safety's one retry. Not a dead site and not evidence: a capture gap. Before 2026-10-31
# the browser was sent anyway and the route guard's own failed lookup labelled it
# blocked_by_guard (net::ERR_ACCESS_DENIED), 47 rows in the 2026-10-31 evaluation.
DNS_TRANSIENT_ERROR = url_safety.DNS_TRANSIENT_ERROR
# A certificate check failed and the page was captured with certificate errors ignored for that
# one browser context (capture_recovery.open_capture). Infrastructure evidence, never trust.
TLS_CERTIFICATE_ERROR = "tls_certificate_error"
# The navigation answered with a file download instead of a page (capture_recovery).
DOWNLOAD_RESPONSE = "download_response"
DOWNLOAD_STARTED = "download_started"
_DOWNLOAD_STARTING = "Download is starting"
BLOCKED_BY_GUARD = "blocked_by_guard"
BLOCKED_BY_BROWSER = "blocked_by_browser"
BLOCKED_BY_SITE = "blocked_by_site"
# The final navigated response was HTTP 404: the page is gone, which is a fact about the
# site and not evidence of phishing. Other 4xx/5xx statuses behave as before.
PAGE_NOT_FOUND = "page_not_found"
NOT_FOUND_STATUS = 404
BROWSER_ERROR = "browser_error"
INTERNAL_ERROR = "internal_error"

# Our route guard aborts with accessdenied (net::ERR_ACCESS_DENIED). In the 2026-09-30
# release run the managed browser refused 11 phishing hosts with ERR_BLOCKED_BY_CLIENT
# and no guard refusal logged, so that code is left to mean "the browser said no".
GUARD_ABORT = "accessdenied"
_GUARD_NET = frozenset({"ACCESS_DENIED"})
_BROWSER_BLOCK_NET = frozenset({"BLOCKED_BY_CLIENT", "BLOCKED_BY_ADMINISTRATOR"})
_SITE_BLOCK_NET = frozenset({"BLOCKED_BY_RESPONSE"})
# A block page or bot wall still loads, so it is captured and flagged, not failed.
_SITE_BLOCK_STATUS = frozenset({401, 403, 406, 429, 451})
_BOT_WALL_TITLE = re.compile(
    r"just a moment|attention required|verify you are (a )?human|are you a robot|"
    r"access denied|ddos-guard|captcha|request blocked|security check",
    re.IGNORECASE,
)

CLOUDFLARE_PHISHING_WARNING = "cloudflare_phishing_warning"
CLOUDFLARE_MALWARE_WARNING = "cloudflare_malware_warning"
CLOAKING_BOT_FILTER = "cloaking_bot_filter"
BOT_CHALLENGE = "bot_challenge"
# Cloudflare's interstitials, by page title: (title pattern, signal, kind as Cloudflare names
# it). "Suspected Malware" fronted most of a pages.dev phishing campaign on 2026-10-16 and,
# read as a plain 403 block, left those scans at suspicious. "Suspected Misleading Website"
# ("reported for potentially misrepresenting itself as a particular brand or service") is a
# brand impersonation report, so it maps to the phishing signal; it uses the same Turnstile-gated
# /cdn-cgi/phish-bypass form (2 of 91 pages.dev hosts screened on 2026-10-21).
_CLOUDFLARE_WARNINGS = (
    (
        re.compile(r"suspected phishing", re.IGNORECASE),
        CLOUDFLARE_PHISHING_WARNING,
        "Suspected Phishing",
    ),
    (
        re.compile(r"suspected misleading website", re.IGNORECASE),
        CLOUDFLARE_PHISHING_WARNING,
        "Suspected Misleading Website",
    ),
    (
        re.compile(r"suspected malware", re.IGNORECASE),
        CLOUDFLARE_MALWARE_WARNING,
        "Suspected Malware",
    ),
)
_CLOAKING_TITLE = re.compile(r"eggy-?wall", re.IGNORECASE)
# Interactive challenges that may clear for a real browser; plain "access denied" pages are blocks.
_CHALLENGE_TITLE = re.compile(
    r"just a moment|attention required|verify you are (a )?human|are you a robot|ddos-guard|"
    r"captcha|security check|unusual traffic",
    re.IGNORECASE,
)

_NET_ERROR = re.compile(r"net::ERR_[A-Z0-9_]+")
# Chromium network errors that mean the site itself did not answer (dead DNS, refused or
# reset connection). A phishing host that is gone is common and telling. Certificate and
# TLS errors are not here: the host answered (see TLS_ERROR).
_TLS_NET_PREFIXES = ("CERT_", "SSL_")
_UNREACHABLE_NET = frozenset(
    {
        "NAME_NOT_RESOLVED",
        "NAME_RESOLUTION_FAILED",
        "ADDRESS_UNREACHABLE",
        "CONNECTION_REFUSED",
        "CONNECTION_RESET",
        "CONNECTION_CLOSED",
        "CONNECTION_FAILED",
        "CONNECTION_TIMED_OUT",
        "TIMED_OUT",
        "EMPTY_RESPONSE",
        "TOO_MANY_REDIRECTS",
        "HTTP2_PROTOCOL_ERROR",
    }
)
_THROTTLE_CODES = frozenset({"ThrottlingException", "TooManyRequestsException"})


@dataclass(frozen=True)
class CaptureFailure:
    category: str
    code: str
    detail: str = ""

    def tool_text(self) -> str:
        head = f"{self.category} ({self.code}): "
        if self.category == SITE_UNREACHABLE:
            return head + (
                "the page could not be loaded, so there is "
                "no screenshot, text or code. An unreachable site is evidence in itself: "
                "phishing hosts are often taken down or never fully set up. Judge from the "
                "URL alone and say that the site did not load."
            )
        if self.category == TLS_ERROR:
            return head + (
                "the site answered, but its HTTPS certificate or TLS setup was rejected, so "
                "the page was not opened. The site is up, so this is not site_down. An invalid "
                "certificate alone is not evidence of phishing: it is a capture gap. Judge from "
                "the URL alone, lower your confidence, and say the page could not be captured."
            )
        if self.category == DNS_TRANSIENT_ERROR:
            return head + (
                "the DNS resolver failed on this host twice without saying the name does not "
                "exist, so the page was not opened. This is a transient resolver error, not "
                "evidence that the site is down or phishing: a capture gap. Judge from the URL "
                "alone, lower your confidence, and say the page could not be captured."
            )
        if self.category == BLOCKED_BY_BROWSER:
            return head + (
                "the managed browser refused to open this URL before sending any request. "
                "Its blocklists include ad and extension lists, so this is a capture gap and "
                "not evidence of phishing. There is no page; judge from the URL alone, lower "
                "your confidence, and say the page could not be captured."
            )
        if self.category == BLOCKED_BY_GUARD:
            reason = self.detail or "internal or non-web origin"
            return head + (
                f"our URL safety guard refused the capture ({reason}). "
                "This is our policy, not evidence; judge from the URL alone."
            )
        if self.category == BLOCKED_BY_SITE:
            return head + (
                "the site refused our browser. There is no page; judge from the URL alone."
            )
        return f"capture_failed ({self.category}: {self.code}): judge from the URL alone."

    def signal(self) -> Signal | None:
        """A deterministic signal for the Finding, so the fact never depends on the model."""
        if self.category == SITE_UNREACHABLE:
            return Signal(
                name=SITE_UNREACHABLE,
                severity=Severity.MEDIUM,
                evidence=f"The site did not load ({self.code}); no page could be captured.",
            )
        if self.category == TLS_ERROR:
            # LOW: a capture gap, never site_down and never evidence alone (see TLS_ERROR).
            return Signal(
                name=TLS_ERROR,
                severity=Severity.LOW,
                evidence=(
                    f"The site answered but its certificate or TLS setup was rejected "
                    f"({self.code}), so the page was not captured; the site is not down."
                ),
            )
        if self.category == DNS_TRANSIENT_ERROR:
            return Signal(
                name=DNS_TRANSIENT_ERROR,
                severity=Severity.LOW,
                evidence=(
                    "The DNS resolver failed on the host twice without an NXDOMAIN answer; "
                    "this is a transient resolver error, not a dead site."
                ),
            )
        if self.category == BLOCKED_BY_BROWSER:
            # LOW: a capture gap. The refusal happens before any request is sent, and the
            # blocklists behind it are not phishing verdicts (dead S3 sites hit it too).
            return Signal(
                name=BLOCKED_BY_BROWSER,
                severity=Severity.LOW,
                evidence=(
                    f"The managed browser refused to open the URL ({self.code}) before sending "
                    "a request; this is a capture gap, not evidence of phishing."
                ),
            )
        if self.category == BLOCKED_BY_GUARD:
            return Signal(
                name=BLOCKED_BY_GUARD,
                severity=Severity.LOW,
                evidence=f"Our URL safety guard refused the capture: {self.detail or self.code}.",
            )
        if self.category == BLOCKED_BY_SITE:
            return Signal(
                name=BLOCKED_BY_SITE,
                severity=Severity.LOW,
                evidence=f"The site refused the browser during navigation ({self.code}).",
            )
        return None


# The one click past a provider warning (proceed_past_warning) either reached the real page or
# was stopped; a stopped click is a capture gap, reported as warning_bypass_blocked.
WARNING_BYPASS_BLOCKED = "warning_bypass_blocked"
BYPASS_PROCEEDED = "proceeded"
BYPASS_BLOCKED = "blocked"
_BYPASS_REASONS = {
    "turnstile": (
        "its proceed button stays disabled behind a Cloudflare Turnstile check, which is never "
        "solved"
    ),
    "proceed_disabled": "its proceed button was disabled",
    "no_proceed_control": "the warning offers no way to proceed",
    "no_navigation": "proceeding did not open a page in time",
    "still_on_warning": "proceeding led back to the warning",
    "no_time": "no time was left in the capture budget",
}
_WARNING_KINDS = {
    CLOUDFLARE_PHISHING_WARNING: "Suspected Phishing",
    CLOUDFLARE_MALWARE_WARNING: "Suspected Malware",
}


def _cloudflare_warning(nav: dict) -> tuple[str, str] | None:
    """(signal, kind) for a loaded page that is a Cloudflare warning, by its title, or None."""
    title = (nav.get("title") or "").strip()
    for pattern, name, kind in _CLOUDFLARE_WARNINGS:
        if pattern.search(title):
            return name, kind
    return None


def warning_name(nav: dict) -> str | None:
    """The provider warning signal a loaded page is, by its title, or None."""
    found = _cloudflare_warning(nav)
    return found[0] if found else None


def _bypass_reason(warning: dict) -> str:
    return _BYPASS_REASONS.get(str(warning.get("reason")), "it could not be passed")


def warning_signal(nav: dict) -> Signal | None:
    """The provider warning, saying whether the real page behind it was observed."""
    warning = nav.get("provider_warning")
    if not isinstance(warning, dict) or warning.get("signal") not in _WARNING_KINDS:
        return None
    if warning.get("outcome") == BYPASS_PROCEEDED:
        tail = "the isolated browser proceeded past it once and captured the real page behind it."
    else:
        tail = (
            f"the browser could not proceed past it ({_bypass_reason(warning)}), so the real "
            "page was not observed."
        )
    return Signal(
        name=warning["signal"],
        severity=Severity.HIGH,
        evidence=(
            f"Cloudflare served its own '{_kind(warning)}' warning for this "
            f"URL (HTTP {warning.get('status')}); {tail}"
        ),
    )


def _kind(warning: dict) -> str:
    return str(warning.get("kind") or _WARNING_KINDS[warning["signal"]])


def bypass_blocked_signal(nav: dict) -> Signal | None:
    """LOW, a capture gap: the warning was shown and the browser could not get past it."""
    warning = nav.get("provider_warning")
    if not isinstance(warning, dict) or warning.get("outcome") != BYPASS_BLOCKED:
        return None
    return Signal(
        name=WARNING_BYPASS_BLOCKED,
        severity=Severity.LOW,
        evidence=(
            f"The browser did not get past Cloudflare's warning: {_bypass_reason(warning)}. "
            "The real page was not observed; this is a capture gap."
        ),
    )


def capture_signals(nav: dict) -> list[Signal]:
    """Every deterministic signal a loaded capture carries: www. sibling, warning, bypass gap,
    block page."""
    signals = sibling_signals(nav)
    signals += [s for s in (warning_signal(nav), bypass_blocked_signal(nav)) if s]
    signals += [s for s in (tls_certificate_signal(nav), download_signal(nav)) if s]
    block = page_not_found_signal(nav) or site_block_signal(nav)
    if block and block.name not in {s.name for s in signals}:
        signals.append(block)
    return signals


# www. sibling capture. Four phishing URLs missed in the 2026-10-26 accuracy rerun failed with
# ERR_CERT_COMMON_NAME_INVALID on a www. name the certificate does not cover (a free host's
# wildcard covers *.vercel.app, not www.*.vercel.app), so no page was seen. The same name
# without www. belongs to the same tenant or registrant, so its page is evidence about the
# same site operator; but the submitted page itself was not observed (a visitor gets a
# certificate warning), so page_observed stays False and the verdict cap applies.
WWW_SIBLING_CAPTURE = "www_sibling_capture"
WWW_SIBLING_CODE = "net::ERR_CERT_COMMON_NAME_INVALID"
WWW_SIBLING_REASON = "the certificate does not cover the www. name"
WWW_SIBLING_TOOL_TEXT = (
    "Note: the submitted URL failed with a certificate error because its certificate does not "
    "cover the www. name, so the page below is the same site without www., captured instead. "
    "The submitted URL itself shows a certificate warning to visitors, so the submitted page "
    "was not observed."
)
WWW_SIBLING_NOTE = (
    "The certificate does not cover the www. name, so the same site without www. was captured "
    "instead. Visitors to this link see a certificate warning."
)


def www_sibling_url(url: str, failure: CaptureFailure | None) -> str | None:
    """https://<host without www.> with the same port, path and query, when the capture failed
    because the certificate does not cover the www. name; else None."""
    if failure is None or (failure.category, failure.code) != (TLS_ERROR, WWW_SIBLING_CODE):
        return None
    try:
        parsed = urlparse(url)
        host, port = (parsed.hostname or ""), parsed.port
    except ValueError:
        return None
    rest = host.removeprefix("www.")
    labels = rest.split(".")
    # A cert error on an http:// URL means it was sent on to https, so the sibling is https.
    if parsed.scheme not in {"http", "https"} or rest == host or len(labels) < 2:
        return None
    if not all(labels):
        return None
    netloc = f"{rest}:{port}" if port else rest
    return urlunparse(("https", netloc, parsed.path, parsed.params, parsed.query, ""))


def sibling_record(submitted_url: str, captured_url: str) -> dict:
    return {
        "submitted_url": submitted_url[:REDIRECT_URL_MAX],
        "captured_url": captured_url[:REDIRECT_URL_MAX],
        "reason": WWW_SIBLING_REASON,
    }


def sibling_capture(data: dict | None) -> dict | None:
    found = (data or {}).get("sibling_capture")
    return found if isinstance(found, dict) else None


def sibling_signals(data: dict | None) -> list[Signal]:
    """The submitted URL's tls_error (kept visible) and www_sibling_capture, both LOW."""
    sibling = sibling_capture(data)
    if sibling is None:
        return []
    tls = CaptureFailure(TLS_ERROR, WWW_SIBLING_CODE).signal()
    return [
        tls,
        Signal(
            name=WWW_SIBLING_CAPTURE,
            severity=Severity.LOW,
            evidence=(
                f"The certificate does not cover the www. name, so {sibling['submitted_url']} "
                f"shows visitors a certificate warning; the same site without www. "
                f"({sibling['captured_url']}) was captured instead. The submitted page was not "
                "observed."
            ),
        ),
    ]


async def open_with_www_sibling(url, open_url, left_ms, min_ms: int) -> dict:
    """open_url(url); if that fails because the certificate does not cover the www. name,
    open_url once on the www. sibling (preflight first, so the same guard applies).

    left_ms() is the time left before the caller's navigation deadline; below min_ms the
    sibling is skipped. If the sibling fails too, the original failure is raised.
    """
    try:
        return await open_url(url)
    except PlaywrightError as exc:
        sibling = www_sibling_url(url, classify_failure(exc))
        if sibling is None:
            raise
        if left_ms() < min_ms:
            logger.info("www sibling capture skipped: %d ms left", left_ms())
            raise
        try:
            await preflight(sibling)
            try:
                nav = await open_url(sibling)
            except PlaywrightError as first:
                # The failed www. navigation commits Chromium's error page a moment after goto
                # raised, and that commit interrupts the sibling goto (seen live 2026-10-27).
                if "interrupted by another navigation" not in str(first) or left_ms() < min_ms:
                    raise
                nav = await open_url(sibling)
        except Exception as sibling_exc:  # noqa: BLE001 - the original failure is the one reported
            failure = classify_failure(sibling_exc)
            logger.info(
                "www sibling capture failed error=%s category=%s code=%s message=%s",
                type(sibling_exc).__name__,
                failure.category,
                failure.code,
                _first_line(sibling_exc),
            )
            raise exc from None
        logger.info("captured the www sibling after a certificate name error")
        return {**nav, "sibling_capture": sibling_record(url, sibling)}


# tls_certificate type for a page that loaded only after a browser refusal and a retry with
# certificate checks ignored (CAPTURE_BLOCK_RETRY): the certificate error itself was not seen.
TLS_UNCONFIRMED = "unconfirmed_after_browser_refusal"
_CERT_ERROR_TYPES = {
    "net::ERR_CERT_AUTHORITY_INVALID": "self_signed_or_unknown_ca",
    "net::ERR_CERT_COMMON_NAME_INVALID": "hostname_mismatch",
    "net::ERR_CERT_DATE_INVALID": "expired_or_not_yet_valid",
}


def certificate_error_type(failure: CaptureFailure | None) -> str | None:
    """The kind of certificate error behind a TLS_ERROR failure, or None when the failure is not
    a certificate error (handshake, protocol and cipher errors are not recoverable this way)."""
    if failure is None or failure.category != TLS_ERROR:
        return None
    if not failure.code.startswith("net::ERR_CERT_"):
        return None
    return _CERT_ERROR_TYPES.get(failure.code, "invalid_certificate")


def tls_certificate_signal(nav: dict) -> Signal | None:
    """LOW infrastructure evidence: the page was only seen with certificate checks ignored."""
    cert = nav.get("tls_certificate")
    if not isinstance(cert, dict):
        return None
    if cert.get("type") == TLS_UNCONFIRMED:
        return Signal(
            name=TLS_CERTIFICATE_ERROR,
            severity=Severity.LOW,
            evidence=(
                f"The managed browser refused the page ({cert.get('code')}) until certificate "
                "checks were ignored for this capture only, which points to a certificate that "
                "does not validate; the page's content is not authenticated."
            ),
        )
    return Signal(
        name=TLS_CERTIFICATE_ERROR,
        severity=Severity.LOW,
        evidence=(
            f"The site's HTTPS certificate failed validation ({cert.get('type')}, "
            f"{cert.get('code')}); the page was captured with certificate checks ignored for "
            "this capture only, so its content is not authenticated."
        ),
    )


_RISKY_DOWNLOAD_KINDS = frozenset({"executable", "archive", "html"})


def download_signal(nav: dict) -> Signal | None:
    """The navigation answered with a file. MEDIUM for an unsolicited executable, archive or HTML
    attachment (common malware and credential-harvest delivery), LOW otherwise."""
    download = nav.get("download")
    if not isinstance(download, dict):
        return None
    kind = download.get("kind") or "other"
    size = download.get("size")
    what = f"{kind} file {download.get('filename')!r}"
    if download.get("sha256"):
        what += f", sha256 {download['sha256']}"
    if size is not None:
        what += f", {size} bytes" + (" (size cap reached)" if download.get("truncated") else "")
    return Signal(
        name=DOWNLOAD_RESPONSE,
        severity=Severity.MEDIUM if kind in _RISKY_DOWNLOAD_KINDS else Severity.LOW,
        evidence=(
            f"Opening the URL started a download instead of a page: {what}, type "
            f"{download.get('content_type') or 'unknown'}. The file was hashed, never opened."
        ),
    )


# A page behind one of these was not the site's real content.
_UNOBSERVED_BLOCKS = frozenset(
    {
        CLOUDFLARE_PHISHING_WARNING,
        CLOUDFLARE_MALWARE_WARNING,
        CLOAKING_BOT_FILTER,
        BOT_CHALLENGE,
        BLOCKED_BY_SITE,
    }
)


# CAPTURE_BLOCK_RETRY=1: a bot wall gets one retry with another browser profile, a browser
# refusal (ERR_BLOCKED_BY_CLIENT) the certificate-tolerant retry, and a page still behind a
# bot wall the page state bot_blocked. Off by default.
BLOCK_RETRY_ENV = "CAPTURE_BLOCK_RETRY"
_TRUE = frozenset({"1", "true", "on", "yes"})
# A plain block page counts as a bot wall only on these statuses; 401 asks for a login and
# 451 is a legal block, so neither is retried or reported as bot_blocked.
_BOT_BLOCK_STATUS = frozenset({403, 429})
_BOT_BLOCK_UNAVAILABLE = 503


def block_retry_enabled() -> bool:
    return os.environ.get(BLOCK_RETRY_ENV, "").strip().lower() in _TRUE


def bot_block_reason(nav: dict | None) -> str | None:
    """bot_challenge_page, bot_filter_page or block_page when the loaded page is a bot wall
    standing in front of the site, else None. Provider phishing/malware warnings, 404s and
    recognised provider pages (S3 AccessDenied, takedowns, parking) are not bot walls."""
    if not nav or "error" in nav or "download" in nav or _cloudflare_warning(nav):
        return None
    status, title = nav.get("status"), (nav.get("title") or "").strip()
    if status == NOT_FOUND_STATUS or page_state.classify(nav) is not None:
        return None
    if _CLOAKING_TITLE.search(title):
        return BOT_FILTER_PAGE
    if _CHALLENGE_TITLE.search(title):
        return BOT_CHALLENGE_PAGE
    if status in _BOT_BLOCK_STATUS or (
        status == _BOT_BLOCK_UNAVAILABLE and _BOT_WALL_TITLE.search(title)
    ):
        return BLOCK_PAGE
    return None


def recognised_page_state(
    failure: CaptureFailure | None, data: dict | None
) -> PageStateObservation | None:
    """The page state code recognised on a loaded capture (code-only Finding.page_state)."""
    if failure is not None or not data or "error" in data or "download" in data:
        return None
    observed = page_state.observation(data)
    if observed is not None or not block_retry_enabled() or sibling_capture(data):
        return observed
    reason = bot_block_reason(data)
    if reason is None:
        return None
    return PageStateObservation(page_state=PageState.BOT_BLOCKED, reason=reason)


def page_observed(failure: CaptureFailure | None, data: dict | None) -> bool:
    """True when the capture saw the site's real page (an HTTP 404 page counts: it is real)."""
    if failure is not None or not data or "error" in data:
        return False
    if isinstance(data.get("download"), dict):
        # A file, not a page: there is no page content to have observed.
        return False
    if sibling_capture(data):
        # The www. sibling was seen, not the submitted page (visitors get a certificate warning).
        return False
    warning = data.get("provider_warning")
    if isinstance(warning, dict) and warning.get("outcome") != BYPASS_PROCEEDED:
        return False
    block = page_not_found_signal(data) or site_block_signal(data)
    return not (block and block.name in _UNOBSERVED_BLOCKS)


def page_not_found_signal(nav: dict) -> Signal | None:
    """The final navigated response was HTTP 404: reported explicitly, never as phishing."""
    if nav.get("status") != NOT_FOUND_STATUS:
        return None
    return Signal(
        name=PAGE_NOT_FOUND,
        severity=Severity.LOW,
        evidence=(
            f"The site returned HTTP {NOT_FOUND_STATUS} (Not Found) for the submitted URL; "
            "the page does not exist."
        ),
    )


def site_block_signal(nav: dict) -> Signal | None:
    """A loaded page that is a block page or bot wall: flagged, and the capture is kept.

    Low severity: legitimate sites use bot walls too, but the page is not the site's real
    content, and phishing kits often cloak from cloud browsers this way.
    """
    status, title = nav.get("status"), (nav.get("title") or "").strip()
    warned = _cloudflare_warning(nav)
    if warned:
        return Signal(
            name=warned[0],
            severity=Severity.HIGH,
            evidence=(
                f"Cloudflare served its own '{warned[1]}' warning for this URL "
                f"(HTTP {status}); the page behind it was not opened."
            ),
        )
    if _CLOAKING_TITLE.search(title):
        return Signal(
            name=CLOAKING_BOT_FILTER,
            severity=Severity.MEDIUM,
            evidence=f"A bot filter page ({title[:60]!r}) hid the site's real content.",
        )
    if _CHALLENGE_TITLE.search(title):
        return Signal(
            name=BOT_CHALLENGE,
            severity=Severity.LOW,
            evidence=f"A bot check ({title[:60]!r}) was shown instead of the page.",
        )
    if status in _SITE_BLOCK_STATUS:
        what = f"HTTP {status}" + (f", title {title[:60]!r}" if title else "")
    elif _BOT_WALL_TITLE.search(title):
        what = f"block page, title {title[:60]!r}"
    else:
        return None
    return Signal(
        name=BLOCKED_BY_SITE,
        severity=Severity.LOW,
        evidence=f"The site served a block page to our browser ({what}), not its real content.",
    )


_FAILURE_NOTES = {
    BLOCKED_BY_BROWSER: (
        "The managed browser refused to open this URL before sending a request; "
        "this is not evidence of phishing."
    ),
    SITE_UNREACHABLE: "The site did not load (its host is gone or refused the connection).",
    TLS_ERROR: (
        "The site answered but its certificate or TLS setup was rejected, so the page was "
        "not captured; this is not evidence of phishing."
    ),
    DNS_TRANSIENT_ERROR: (
        "The DNS resolver failed on this host (a transient error, not a missing domain), so "
        "the page was not captured."
    ),
    NAVIGATION_TIMEOUT: "The page did not finish loading in time, so it was not captured.",
    BLOCKED_BY_GUARD: "Our URL safety guard did not allow this address to be opened.",
    BLOCKED_BY_SITE: "The site refused our browser, so its real content was not captured.",
}
_BLOCK_NOTES = {
    CLOUDFLARE_PHISHING_WARNING: (
        "Cloudflare showed its own phishing warning for this site; "
        "the page behind it was not opened."
    ),
    CLOUDFLARE_MALWARE_WARNING: (
        "Cloudflare showed its own malware warning for this site; "
        "the page behind it was not opened."
    ),
    CLOAKING_BOT_FILTER: "A bot filter hid the site's real content from our browser.",
    BOT_CHALLENGE: "A bot check was shown instead of the page, so its content was not captured.",
    BLOCKED_BY_SITE: "The site served a block page instead of its real content.",
    PAGE_NOT_FOUND: "The page answered HTTP 404 (Not Found); there was nothing to capture.",
}


def _warning_note(warning: dict) -> str:
    kind = _kind(warning).removeprefix("Suspected ").lower()
    if warning.get("outcome") == BYPASS_PROCEEDED:
        return (
            f"Cloudflare showed its own {kind} warning for this site; the browser proceeded past "
            "it once and captured the real page."
        )
    return (
        f"Cloudflare showed its own {kind} warning for this site and the browser could not get "
        f"past it ({_bypass_reason(warning)}), so the real page was not observed."
    )


def capture_note(
    failure: CaptureFailure | None,
    block: Signal | None,
    warning: dict | None = None,
    sibling: dict | None = None,
    block_retry: dict | None = None,
) -> str | None:
    """One plain-English sentence on how the capture went, or None when it was complete."""
    note = _capture_note(failure, block, warning, sibling)
    retry = _BLOCK_RETRY_NOTES.get(block_retry.get("outcome")) if block_retry else None
    if failure is not None or not retry:
        return note
    return f"{note} {retry}" if note else retry


def _capture_note(
    failure: CaptureFailure | None,
    block: Signal | None,
    warning: dict | None,
    sibling: dict | None,
) -> str | None:
    if failure is not None:
        return _FAILURE_NOTES.get(
            failure.category, "The page could not be captured, so it was judged from its URL."
        )
    if sibling:
        block_note = _BLOCK_NOTES.get(block.name, "") if block else ""
        return f"{WWW_SIBLING_NOTE} {block_note}".strip()
    if isinstance(warning, dict) and warning.get("signal") in _WARNING_KINDS:
        note = _warning_note(warning)
        if warning.get("outcome") == BYPASS_PROCEEDED and block is not None:
            note = f"{note} {_BLOCK_NOTES.get(block.name, '')}".strip()
        return note
    if block is not None:
        return _BLOCK_NOTES.get(block.name)
    return None


_BLOCK_RETRY_NOTES = {
    "recovered": (
        "The site first served a bot wall to our browser; a second try with a different "
        "browser profile got past it and captured the real page."
    ),
    "still_blocked": "A second try with a different browser profile was blocked too.",
}


def _first_line(exc: BaseException, limit: int = 200) -> str:
    text = str(exc).strip().splitlines()
    return (text[0] if text else "")[:limit]


def classify_failure(exc: BaseException) -> CaptureFailure:
    if isinstance(exc, SiteUnreachable):
        return CaptureFailure(SITE_UNREACHABLE, exc.code)
    if isinstance(exc, BlockedNavigation):
        return CaptureFailure(BLOCKED_BY_GUARD, "url_safety", _first_line(exc))
    if isinstance(exc, BrowserRefused):
        return CaptureFailure(BLOCKED_BY_BROWSER, "chrome_error_page")
    if isinstance(exc, PlaywrightTimeout | TimeoutError):
        return CaptureFailure(NAVIGATION_TIMEOUT, "timeout")
    if isinstance(exc, DnsTransientError):
        return CaptureFailure(DNS_TRANSIENT_ERROR, DNS_TRANSIENT_ERROR, _first_line(exc))
    if isinstance(exc, ClientError):
        code = str(exc.response.get("Error", {}).get("Code", "ClientError"))
        return CaptureFailure(
            BROWSER_ERROR, "session_throttled" if code in _THROTTLE_CODES else code
        )
    if isinstance(exc, PlaywrightError):
        match = _NET_ERROR.search(str(exc))
        if match:
            net = match.group(0).removeprefix("net::ERR_")
            if net.startswith(_TLS_NET_PREFIXES):
                return CaptureFailure(TLS_ERROR, match.group(0))
            if net in _UNREACHABLE_NET:
                return CaptureFailure(SITE_UNREACHABLE, match.group(0))
            if net in _GUARD_NET:
                return CaptureFailure(BLOCKED_BY_GUARD, match.group(0))
            if net in _BROWSER_BLOCK_NET:
                return CaptureFailure(BLOCKED_BY_BROWSER, match.group(0))
            if net in _SITE_BLOCK_NET:
                return CaptureFailure(BLOCKED_BY_SITE, match.group(0))
            return CaptureFailure(BROWSER_ERROR, match.group(0))
        if _DOWNLOAD_STARTING in str(exc):
            return CaptureFailure(BROWSER_ERROR, DOWNLOAD_STARTED)
        return CaptureFailure(BROWSER_ERROR, type(exc).__name__)
    return CaptureFailure(INTERNAL_ERROR, type(exc).__name__)


def log_capture_failure(agent: str, exc: BaseException) -> CaptureFailure:
    """Log class, category and the first line of the message; never page content."""
    failure = classify_failure(exc)
    log = logger.info if failure.signal() else logger.warning
    log(
        "capture failed agent=%s category=%s code=%s error=%s message=%s",
        agent,
        failure.category,
        failure.code,
        type(exc).__name__,
        _first_line(exc),
    )
    return failure


async def preflight(url: str) -> None:
    """Resolve the scan host before paying for a browser session.

    A host that does not resolve (a third of failed captures in the 2026-09-29 run) cannot
    load, so it is reported as unreachable at once. A resolver failure that persists through
    url_safety's one retry is reported as DNS_TRANSIENT_ERROR: the browser's own guard lookup
    would fail the same way and be mislabelled blocked_by_guard.
    """
    reason, kind = await asyncio.to_thread(url_safety.host_check, url)
    if kind == url_safety.HOST_NXDOMAIN:
        raise SiteUnreachable("dns_nxdomain")
    if kind == url_safety.HOST_UNRESOLVED:
        raise DnsTransientError(reason or DNS_TRANSIENT_ERROR)
    if kind == url_safety.HOST_BLOCKED and reason:
        raise BlockedNavigation(reason)


async def guard_route(route) -> None:
    """Refuse any routed request (documents and subresources) to an internal origin.

    Playwright does not route the hops of a server redirect, so this guard never sees
    them. navigate() checks every hop after the fact and refuses the capture instead.
    """
    reason = await asyncio.to_thread(request_allowed, route.request.url)
    try:
        if reason:
            logger.info("browser request refused: %s", reason)
            await route.abort(GUARD_ABORT)
        else:
            await route.continue_()
    except PlaywrightError as exc:
        # The page closed while this request was in flight (capture already finished).
        # Raising here only adds a traceback to the log; the request is gone either way.
        logger.debug("route settled after close error=%s", type(exc).__name__)


@asynccontextmanager
async def open_page(
    recorder: CallRecorder,
    name: str,
    *,
    init_script: str | None = None,
    client_factory=BrowserClient,
    playwright_factory=async_playwright,
) -> AsyncIterator:
    client = client_factory(os.environ["AWS_REGION"])
    phases: dict[str, int] = {}
    t0 = time.monotonic()
    with recorder.record(CallKind.BROWSER, name):
        await _start_session(client)
        phases["start_ms"] = _ms_since(t0)
        try:
            ws_url, headers = client.generate_ws_headers()
            async with playwright_factory() as pw:
                t1 = time.monotonic()
                remote = await pw.chromium.connect_over_cdp(ws_url, headers=headers)
                try:
                    context = remote.contexts[0]
                    await context.route("**/*", guard_route)
                    if init_script:
                        await context.add_init_script(init_script)
                    page = context.pages[0] if context.pages else await context.new_page()
                    phases["connect_ms"] = _ms_since(t1)
                    t2 = time.monotonic()
                    yield page
                    phases["page_ms"] = _ms_since(t2)
                finally:
                    t3 = time.monotonic()
                    await _bounded("cdp close", remote.close())
                    phases["cdp_close_ms"] = _ms_since(t3)
        finally:
            # Always release the session: an orphaned one keeps billing until its timeout. A
            # stop that outlives the bound still finishes in its thread, and logs a failure.
            t4 = time.monotonic()
            await _bounded("session stop", asyncio.to_thread(_stop_session, client))
            phases["stop_ms"] = _ms_since(t4)
            logger.info(
                "browser phases name=%s total_ms=%d %s",
                name,
                _ms_since(t0),
                " ".join(f"{k}={v}" for k, v in phases.items()),
            )


def _ms_since(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


async def _start_session(client) -> None:
    """client.start in a thread; a session that comes up after the caller was cancelled is
    stopped, since the thread cannot be interrupted and nobody else would release it."""
    start = asyncio.ensure_future(
        asyncio.to_thread(
            client.start, identifier=BROWSER_ID, session_timeout_seconds=SESSION_TIMEOUT_SECONDS
        )
    )
    try:
        await asyncio.shield(start)
    except asyncio.CancelledError:
        start.add_done_callback(lambda task: _stop_if_started(task, client))
        raise


def _stop_if_started(task: asyncio.Future, client) -> None:
    if task.cancelled() or task.exception() is not None:
        return
    logger.warning("session started after its caller was cancelled; stopping it")
    asyncio.get_running_loop().run_in_executor(None, _stop_session, client)


def _stop_session(client) -> None:
    """client.stop with its failure logged here: past the bound, or after a cancelled start,
    nobody awaits the thread. A failed stop does not fail the capture it follows."""
    try:
        client.stop()
    except Exception as exc:  # noqa: BLE001 - logged; the session times out on its own
        logger.warning("session stop failed error=%s", _first_line(exc, 120))


# Closing the CDP connection and stopping the session run after a capture's own budget
# (a cancelled capture still runs them), so each gets a bound and cannot hold the caller.
CLOSE_TIMEOUT_S = 2.0


async def _bounded(what: str, awaitable) -> None:
    try:
        await asyncio.wait_for(awaitable, CLOSE_TIMEOUT_S)
    except TimeoutError:
        logger.warning("%s took over %.0f s; not waiting for it", what, CLOSE_TIMEOUT_S)


def _navigation_hops(response, final_url: str) -> list[str]:
    """page.url, the response URL, then every earlier redirect hop back to the first."""
    hops = [final_url]
    if response is not None:
        hops.append(response.url)
        request = response.request.redirected_from
        while request is not None:
            hops.append(request.url)
            request = request.redirected_from
    return hops


class NavigationLog:
    """Main-frame navigation requests in order: the start URL, every 3xx hop, every script or
    meta refresh navigation, and the one click past a provider warning.

    Playwright emits a `request` event for each redirect hop (with redirected_from set), which
    the route guard never sees, so this is also the list every hop is checked against.
    """

    def __init__(self, page) -> None:
        self.hops: list[dict] = []
        # How the next navigation that is not a redirect was started (warning_bypass).
        self.next_via: str | None = None
        self._by_request: dict[int, dict] = {}
        page.on("request", self._on_request)
        page.on("response", self._on_response)
        page.on("requestfailed", self._on_failed)

    @staticmethod
    def _main_navigation(request) -> bool:
        try:
            return bool(request.is_navigation_request()) and request.frame.parent_frame is None
        except (PlaywrightError, AttributeError):
            # A request whose frame is gone (or a test double without frames): not a hop.
            return False

    def _on_request(self, request) -> None:
        if len(self.hops) >= MAX_LOGGED_HOPS or not self._main_navigation(request):
            return
        if request.redirected_from is not None:
            via = redirects.HTTP
        elif not self.hops:
            via = redirects.START
        else:
            via, self.next_via = self.next_via or redirects.CLIENT, None
        hop = {"url": request.url[:REDIRECT_URL_MAX], "via": via}
        self.hops.append(hop)
        self._by_request[id(request)] = hop

    def _on_response(self, response) -> None:
        hop = self._by_request.get(id(response.request))
        if hop is not None:
            hop["status"] = response.status

    def _on_failed(self, request) -> None:
        hop = self._by_request.get(id(request))
        if hop is not None:
            hop["error"] = (request.failure or "failed")[:120]

    def last_status(self, fallback: int | None) -> int | None:
        status = self.hops[-1].get("status") if self.hops else None
        return status if isinstance(status, int) else fallback


# A chain longer than this is not followed further in the log (the Finding keeps 10).
MAX_LOGGED_HOPS = 20


def redirect_chain(log: NavigationLog, response, url: str, final_url: str) -> list[dict]:
    """The hops from the submitted URL to final_url, oldest first.

    From the navigation log; when it saw nothing (a browser that emits no request events),
    from the response's redirect chain, which only holds the first navigation's 3xx hops.
    """
    if log.hops:
        return [dict(h) for h in log.hops]
    urls = list(dict.fromkeys([url, *ordered_hops(_navigation_hops(response, final_url))]))
    return [
        {"url": u[:REDIRECT_URL_MAX], "via": redirects.START if i == 0 else redirects.HTTP}
        for i, u in enumerate(urls)
    ]


async def _guard_hops(urls: list[str]) -> None:
    for hop in urls:
        reason = await asyncio.to_thread(request_allowed, hop)
        if reason:
            logger.info("navigation refused at a redirect hop: %s", reason)
            raise BlockedNavigation(reason)


def _raise_for_error_page(page, log: NavigationLog) -> None:
    """Raise when the page ended on chrome-error:// (first load, script redirect or click).

    The failed hop's net::ERR_* code goes through classify_failure like a failed goto, so a
    redirect to a host that does not resolve is site_unreachable, not a browser refusal.
    """
    if not (page.url or "").startswith("chrome-error://"):
        return
    logger.info("navigation ended on a browser error page")
    error = next((h["error"] for h in reversed(log.hops) if h.get("error")), "")
    if _NET_ERROR.search(error):
        raise PlaywrightError(error)
    raise BrowserRefused(page.url)


async def navigate(
    page,
    url: str,
    *,
    nav_timeout_ms: int = NAV_TIMEOUT_MS,
    settle_state: str = "networkidle",
    settle_ms: int = SETTLE_TIMEOUT_MS,
    settle_deadline: float | None = None,
    bypass_deadline: float | None = None,
) -> dict:
    """Open url and check every hop, settle for at most settle_ms, and proceed once past a
    provider warning (proceed_past_warning) before bypass_deadline.

    code_analyst keeps the networkidle settle so late scripts are fetched; brand_visual
    settles on a bounded load event, because a screenshot only needs the page painted.
    settle_deadline (time.monotonic()) cuts the settle short so it never eats time the
    caller kept back for the screenshot; with nothing left the settle is skipped.
    """
    log = NavigationLog(page)
    t0 = time.monotonic()
    response = await page.goto(url, wait_until="domcontentloaded", timeout=nav_timeout_ms)
    goto_ms = _ms_since(t0)
    # A browser interstitial or error page commits as chrome-error://; checked before the
    # hops, or the guard would refuse that non-web URL and hide the browser's refusal.
    _raise_for_error_page(page, log)
    await _guard_hops(_navigation_hops(response, page.url))
    if settle_deadline is not None:
        settle_ms = min(settle_ms, int((settle_deadline - time.monotonic()) * 1000))
    # Playwright reads timeout=0 as no timeout at all, so no time left means no wait.
    t1 = time.monotonic()
    if settle_ms > 0:
        try:
            await page.wait_for_load_state(settle_state, timeout=settle_ms)
        except PlaywrightTimeout:
            logger.info("page did not reach %s within %d ms; continuing", settle_state, settle_ms)
    settled_ms = _ms_since(t1)
    # A script or meta refresh may have moved the page during the settle: its hops (and their
    # 3xx hops, which no route sees) get the same guard, and an error page is classified.
    _raise_for_error_page(page, log)
    await _guard_hops([h["url"] for h in log.hops] + [page.url])
    nav = {
        "final_url": page.url,
        "status": log.last_status(response.status if response else None),
        "title": await _title(page),
    }
    nav = await proceed_past_warning(
        page, nav, log, deadline=bypass_deadline, settle_state=settle_state
    )
    nav["redirect_chain"] = redirect_chain(log, response, url, nav["final_url"])
    logger.info(
        "navigate phases goto_ms=%d settle_ms=%d settle_state=%s total_ms=%d",
        goto_ms,
        settled_ms,
        settle_state,
        _ms_since(t0),
    )
    return nav


# proceed_past_warning: Cloudflare's warning page carries a GET form to /cdn-cgi/phish-bypass
# whose "Ignore & Proceed" button (#bypass-button) Cloudflare keeps disabled until its Turnstile
# widget calls back. Every saved interstitial (eval captures, 2026-10-16 and 2026-10-21) had
# either that gated button or no button at all. Only that one same-origin control is clicked;
# the Turnstile widget is never touched.
BYPASS_FORM = 'form[action="/cdn-cgi/phish-bypass"]'
BYPASS_CONTROL = (
    f'{BYPASS_FORM} #bypass-button, {BYPASS_FORM} button[type="submit"], '
    f'{BYPASS_FORM} input[type="submit"]'
)
_BYPASS_STATE_JS = """(sel) => {
  const c = document.querySelector(sel);
  return {control: !!c, enabled: !!c && !c.disabled,
    turnstile: !!document.querySelector(
      '.cf-turnstile, [name="cf-turnstile-response"], iframe[src*="challenges.cloudflare.com"]')};
}"""
_BYPASS_ENABLED_JS = "(s) => { const c = document.querySelector(s); return !!c && !c.disabled; }"
# The whole click-through (wait, click, navigation, settle) when the caller gives no deadline.
BYPASS_BUDGET_MS = 8_000
# How long a disabled button may take to enable on its own (a Turnstile check that clears
# without interaction). Nothing is clicked or typed while waiting.
BYPASS_ENABLE_WAIT_MS = 3_000
BYPASS_CLICK_TIMEOUT_MS = 1_000
BYPASS_SETTLE_MS = 1_000
# Below this there is no time to click, navigate and paint the real page.
_MIN_BYPASS_MS = 1_500


def _ms_left(deadline: float) -> int:
    return int((deadline - time.monotonic()) * 1000)


async def proceed_past_warning(
    page,
    nav: dict,
    log: NavigationLog,
    *,
    deadline: float | None = None,
    settle_state: str = "load",
) -> dict:
    """nav unchanged unless it is a Cloudflare warning; then one click past it, bounded.

    Returns the real page's nav with provider_warning {signal, url, status, outcome
    "proceeded"}, or the warning's nav with outcome "blocked" and a reason (turnstile,
    proceed_disabled, no_proceed_control, no_navigation, still_on_warning, no_time). The
    click is the only interaction: no captcha or bot check is solved, nothing is typed, and
    no form on the real page is touched. Every hop of the click's navigation and the final URL
    go through the same guard as navigate().
    """
    found = _cloudflare_warning(nav)
    if found is None:
        return nav
    if deadline is None:
        deadline = time.monotonic() + BYPASS_BUDGET_MS / 1000
    warning = {
        "signal": found[0],
        "kind": found[1],
        "url": str(nav.get("final_url") or "")[:REDIRECT_URL_MAX],
        "status": nav.get("status"),
    }

    def blocked(reason: str, at: dict = nav) -> dict:
        logger.info("provider warning not passed reason=%s", reason)
        return {**at, "provider_warning": {**warning, "outcome": BYPASS_BLOCKED, "reason": reason}}

    if _ms_left(deadline) < _MIN_BYPASS_MS:
        return blocked("no_time")
    state = await page.evaluate(_BYPASS_STATE_JS, BYPASS_CONTROL)
    if not isinstance(state, dict) or not state.get("control"):
        return blocked("no_proceed_control")
    if not state.get("enabled"):
        wait_ms = min(BYPASS_ENABLE_WAIT_MS, _ms_left(deadline) - _MIN_BYPASS_MS)
        if wait_ms <= 0:
            return blocked("no_time")
        try:
            await page.wait_for_function(_BYPASS_ENABLED_JS, arg=BYPASS_CONTROL, timeout=wait_ms)
        except PlaywrightTimeout:
            return blocked("turnstile" if state.get("turnstile") else "proceed_disabled")
    log.next_via = redirects.WARNING_BYPASS
    try:
        async with page.expect_navigation(
            wait_until="commit", timeout=max(_ms_left(deadline), 1)
        ) as info:
            await page.click(BYPASS_CONTROL, timeout=BYPASS_CLICK_TIMEOUT_MS)
        response = await info.value
    except PlaywrightError as exc:
        log.next_via = None
        logger.info("click past the warning failed error=%s", type(exc).__name__)
        return blocked("no_navigation")
    logger.info("proceeded past the provider warning")
    left_ms = _ms_left(deadline)
    if left_ms > 0:
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=left_ms)
        except PlaywrightTimeout:
            logger.info("real page did not reach domcontentloaded in %d ms", left_ms)
    _raise_for_error_page(page, log)
    await _guard_hops([h["url"] for h in log.hops] + [page.url])
    settle_ms = min(BYPASS_SETTLE_MS, _ms_left(deadline))
    if settle_ms > 0:
        try:
            await page.wait_for_load_state(settle_state, timeout=settle_ms)
        except PlaywrightTimeout:
            logger.info("real page did not reach %s within %d ms", settle_state, settle_ms)
    real = {
        "final_url": page.url,
        "status": log.last_status(response.status if response else None),
        "title": await _title(page),
    }
    if warning_name(real):
        return blocked("still_on_warning", real)
    return {**real, "provider_warning": {**warning, "outcome": BYPASS_PROCEEDED}}


# precheck_url: navigate only, to learn the final HTTP status before any model runs.
PRECHECK_NAV_TIMEOUT_MS = 8_000


async def precheck_navigation(
    page, url: str, *, nav_timeout_ms: int = PRECHECK_NAV_TIMEOUT_MS
) -> dict:
    """Open url (domcontentloaded only, no settle, title or screenshot) and return the final
    URL and the status of the final response after redirects. Every hop goes through the same
    guard as navigate(), so a redirect to an internal origin is refused here too."""
    response = await page.goto(url, wait_until="domcontentloaded", timeout=nav_timeout_ms)
    if page.url.startswith("chrome-error://"):
        raise BrowserRefused(page.url)
    hops = _navigation_hops(response, page.url)
    for hop in hops:
        reason = await asyncio.to_thread(request_allowed, hop)
        if reason:
            raise BlockedNavigation(reason)
    return {
        "final_url": page.url,
        "status": response.status if response else None,
        "hops": ordered_hops(hops),
    }


def ordered_hops(hops: list[str]) -> list[str]:
    """_navigation_hops (newest first, with repeats) as first-to-final, each URL once."""
    return list(dict.fromkeys(reversed(hops)))


async def _title(page) -> str:
    # page.title() runs in the page and has no timeout of its own: on a page whose main
    # thread is busy (square.site, 2026-10-01) it held the capture until the 14 s cap.
    try:
        return await asyncio.wait_for(page.title(), TITLE_TIMEOUT_S)
    except (PlaywrightError, TimeoutError) as exc:
        logger.info("title unavailable error=%s", type(exc).__name__)
        return ""


async def rendered_after_timeout(page) -> dict | None:
    """What a navigation that timed out left on screen, or None when nothing committed.

    A slow page often has painted its login form long before the load event. There is
    no response here, so the redirect hops cannot be walked; the route guard has already
    judged every routed request, and the URL on screen is checked again below.
    """
    url = page.url or ""
    if url.startswith("chrome-error://"):
        raise BrowserRefused(url)
    # Anything but a web page means the navigation never committed: about:blank, or
    # Chromium's own chrome://new-tab-page/ titled "Loading <url>" (seen live 2026-10-01).
    # A screenshot of it would be evidence about the browser, not the site.
    if not url.startswith(("http://", "https://")):
        return None
    reason = await asyncio.to_thread(request_allowed, url)
    if reason:
        logger.info("timed-out navigation ended on a refused URL: %s", reason)
        raise BlockedNavigation(reason)
    return {"final_url": url, "status": None, "title": await _title(page)}


# A viewport PNG of what the compositor holds now: no scroll-to-fit, no re-layout.
CDP_SCREENSHOT_PARAMS = {"format": "png", "captureBeyondViewport": False, "fromSurface": True}
# Share of the screenshot budget the CDP path gets; the rest is the fallback's.
CDP_SHARE = 0.6
# Playwright reads timeout=0 as no timeout, so the fallback always gets a real bound.
_MIN_FALLBACK_MS = 250
_DETACH_TIMEOUT_S = 0.5


async def _cdp_png(page) -> bytes:
    session = await page.context.new_cdp_session(page)
    try:
        try:
            await session.send("Page.stopLoading")
        except PlaywrightError as exc:
            # Nothing loading, or the frame is gone: the capture below still decides.
            logger.info("stopLoading failed error=%s", _first_line(exc, 120))
        result = await session.send("Page.captureScreenshot", CDP_SCREENSHOT_PARAMS)
        return base64.b64decode(result["data"], validate=True)
    finally:
        # Bounded, because a cancelled capture still runs this and must not hang on it.
        try:
            await asyncio.wait_for(session.detach(), _DETACH_TIMEOUT_S)
        except (PlaywrightError, TimeoutError) as exc:
            logger.debug("CDP detach after capture error=%s", type(exc).__name__)


async def viewport_png(page, timeout_ms: int) -> bytes:
    """PNG of what is painted now, inside timeout_ms in total.

    Goes straight to CDP Page.captureScreenshot. Playwright's page.screenshot first waits
    for web fonts and running animations; over the remote AgentCore Browser connection it
    timed out on pages still loading (square.site, pages.dev, 2026-10-01) while the CDP
    capture returned in 0.2 to 0.6 s. Only if CDP fails or overruns its share of the
    budget does page.screenshot get the rest, with animations and the caret frozen.
    """
    deadline = time.monotonic() + timeout_ms / 1000
    try:
        return await asyncio.wait_for(_cdp_png(page), timeout_ms * CDP_SHARE / 1000)
    except (PlaywrightError, TimeoutError, KeyError, ValueError) as exc:
        logger.info(
            "CDP screenshot failed, using page.screenshot error=%s %s",
            type(exc).__name__,
            _first_line(exc, 120),
        )
    left_ms = max(_MIN_FALLBACK_MS, int((deadline - time.monotonic()) * 1000))
    return await page.screenshot(
        type="png",
        full_page=False,
        animations="disabled",
        caret="hide",
        timeout=left_ms,
    )
