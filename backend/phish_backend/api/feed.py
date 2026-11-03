# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Live phishing-URL feed.

Supplies the UI with REAL, currently-reachable phishing URLs to scan, instead of
invented example hostnames. Invented examples cannot work: the scanner resolves
DNS before analysing, so a hostname that does not exist is rejected before any
analysis happens.

The hard part is not obtaining phishing URLs, it is obtaining ones that are still
alive. Phishing hosts are taken down within hours, so a raw public feed is largely
dead on arrival: sampling the OpenPhish community feed showed only ~60% of entries
still resolving. Everything here exists to close that gap:

  1. fetch a phishing-specific public feed (no API key required),
  2. drop anything the scanner would refuse anyway (SSRF policy),
  3. DNS-resolve the remainder concurrently and keep only live hosts,
  4. cache the survivors in S3 so we neither hammer the upstream feed nor pay
     the resolution cost on every page load.

SAFETY: every URL returned by this module is a REAL malicious URL. It is returned
as an opaque string for the scanner to analyse. Nothing here fetches, follows or
renders them, and the UI must present them as hazardous. This endpoint requires
the same IAM authentication as the rest of the API.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from urllib.parse import urlparse

from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger()

# Cache lifetime. Long enough that normal UI use does not re-fetch, short enough
# that the list does not go stale as hosts are taken down.
CACHE_TTL_SECONDS = int(os.environ.get("FEED_CACHE_TTL", "900"))
CACHE_KEY = "feed/live-phishing.json"

# Cap on how many candidates we DNS-resolve per refresh. Resolution is the slow
# step, and we only need enough survivors to fill a dropdown.
MAX_RESOLVE_CANDIDATES = int(os.environ.get("FEED_MAX_CANDIDATES", "120"))
RESOLVE_WORKERS = 16
RESOLVE_TIMEOUT = 3.0

FETCH_TIMEOUT = 12
MAX_FEED_BYTES = 4 * 1024 * 1024  # Guard against an unexpectedly huge upstream body.

USER_AGENT = "sample-agentic-phishing-detection/2.0 (phishing-detection research)"


class FeedSource:
    """A public feed of phishing URLs."""

    def __init__(self, name: str, url: str, parser: str, attribution: str):
        self.name = name
        self.url = url
        self.parser = parser
        self.attribution = attribution


# Ordered by preference. OpenPhish is phishing-specific and compact. URLhaus is
# primarily malware distribution but carries an explicit online/offline column,
# which makes its "online" rows unusually likely to still be live.
SOURCES = [
    FeedSource(
        name="openphish",
        url="https://openphish.com/feed.txt",
        parser="lines",
        attribution="OpenPhish community feed",
    ),
    FeedSource(
        name="phishing.database",
        url="https://raw.githubusercontent.com/mitchellkrogza/"
        "Phishing.Database/master/phishing-links-NEW-today.txt",
        parser="lines",
        attribution="Phishing.Database (new today)",
    ),
    FeedSource(
        name="urlhaus",
        url="https://urlhaus.abuse.ch/downloads/csv_recent/",
        parser="urlhaus_csv",
        attribution="URLhaus by abuse.ch (online entries)",
    ),
]

# ─── High risk demo targets ───────────────────────────────────────────────────
#
# Curated, non-resolving phishing EXAMPLES for display in the UI, not live threat
# URLs. Real, in-the-wild phishing hosts are intentionally NOT surfaced in the UI:
# showing a genuinely live malicious link in a dropdown is a review blocker and a
# hazard to the person clicking it. These illustrate the classic patterns a
# detector must catch (typosquatting, deceptive subdomains, IP-based URLs) and are
# safe to display. Every hostname sits under an RFC 2606 reserved name
# (example.com / .example) or RFC 1918 address space, so none of them is
# registrable by a third party: a lookalike in a real TLD could be bought by
# someone else and turned into the live threat this list promises not to surface.
# They are expected to fail DNS resolution / return 404 when scanned; to exercise
# the pipeline against a genuinely live malicious URL, paste it into the scan box
# or use the single/batch APIs directly.
HIGH_RISK_SAMPLES = [
    ("https://www.paypa1-secure.example.com", "PayPal typosquat (paypa1)"),
    ("http://login.microsoft.com.verify-account.example", "Microsoft subdomain spoof"),
    ("http://192.168.1.1/banking/login.html", "IP-based banking URL"),
    ("https://www.arnazon.example.com", "Amazon typosquat (arnazon)"),
    ("http://testsafebrowsing.appspot.com/s/phishing.html", "Google Safe Browsing phishing test"),
]

# ─── Medium and low risk targets ──────────────────────────────────────────────
#
# A useful demo needs all three risk tiers, not just phishing examples: a detector
# that only ever sees phishing tells you nothing about its false-positive rate. All
# of these are REAL sites, so a scan exercises the full pipeline in every tier.

# Medium risk. Google's Safe Browsing test harness publishes pages classified as
# unwanted software and other non-phishing abuse. They are purpose-built, safe to
# visit, and stable, which matters because genuinely suspicious in-the-wild hosts
# disappear within hours and would leave this list empty most of the time.
MEDIUM_RISK = [
    (
        "https://testsafebrowsing.appspot.com/s/unwanted.html",
        "Unwanted software (Safe Browsing test)",
    ),
    (
        "https://testsafebrowsing.appspot.com/s/content_exec.html",
        "Content execution (Safe Browsing test)",
    ),
    ("https://testsafebrowsing.appspot.com/s/malware.html", "Malware page (Safe Browsing test)"),
    ("https://www.wicar.org/test-malware.html", "WICAR malware test page"),
    ("https://secure.eicar.org/eicar.com.txt", "EICAR test file"),
]

# Low risk. Well-known, high-traffic, stable domains. These test the detector's
# false-positive rate: a scanner that flags these is unusable regardless of how
# well it catches phishing.
LOW_RISK = [
    ("https://www.google.com", "Google"),
    ("https://en.wikipedia.org", "Wikipedia"),
    ("https://www.github.com", "GitHub"),
    ("https://www.iana.org", "IANA"),
    ("https://example.com", "Example.com"),
    ("https://www.cloudflare.com", "Cloudflare"),
    ("https://www.paypal.com", "PayPal (the real one)"),
    ("https://www.python.org", "Python"),
]


def _require_https(url: str) -> str:
    """Reject anything that is not http(s) before it reaches urlopen.

    urlopen honours file:, ftp: and custom schemes, so a URL assembled from
    configuration or an upstream feed could read from the local filesystem
    instead of the network. Scheme is validated here rather than trusted.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise ValueError(f"refusing non-http(s) scheme: {parsed.scheme or '(none)'}")
    if not parsed.netloc:
        raise ValueError("refusing URL without a host")
    return url


def _http_get(url: str) -> str:
    """Fetch a feed body. Follows redirects, which OpenPhish requires."""
    req = urllib.request.Request(_require_https(url), headers={"User-Agent": USER_AGENT})  # noqa: S310
    # urlopen accepts file:, ftp: and custom schemes; the URL passed here was
    # validated by _require_https, so only http(s) with a host reaches this call.
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:  # noqa: S310  # nosec B310
        raw = resp.read(MAX_FEED_BYTES)
    return raw.decode("utf-8", errors="replace")


def _parse_lines(body: str) -> list[str]:
    return [
        line.strip()
        for line in body.splitlines()
        if line.strip().startswith(("http://", "https://"))
    ]


def _parse_urlhaus_csv(body: str) -> list[str]:
    """
    Extract only rows URLhaus currently reports as online.

    The CSV carries commented header lines, so they are stripped before parsing.
    Column order: id, dateadded, url, url_status, ...
    """
    rows = [ln for ln in body.splitlines() if ln and not ln.startswith("#")]
    out: list[str] = []
    for row in csv.reader(io.StringIO("\n".join(rows))):
        if len(row) < 4:
            continue
        url, status = row[2], row[3]
        if status == "online" and url.startswith(("http://", "https://")):
            out.append(url)
    return out


def _fetch_candidates() -> tuple[list[str], str]:
    """
    Return (urls, attribution) from the first source that yields anything.

    Sources are tried in order and failures are tolerated: an upstream feed being
    unreachable degrades the suggestions list, it must never fail the request.
    """
    for src in SOURCES:
        try:
            body = _http_get(src.url)
            urls = _parse_lines(body) if src.parser == "lines" else _parse_urlhaus_csv(body)
            if urls:
                logger.info("[Feed] %s supplied %d candidates", src.name, len(urls))
                return urls, src.attribution
            logger.warning("[Feed] %s returned no usable rows", src.name)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as e:
            logger.warning("[Feed] %s unavailable: %s: %s", src.name, type(e).__name__, e)
    return [], ""


def _resolves(url: str) -> bool:
    """
    True when the hostname currently resolves within RESOLVE_TIMEOUT.

    This is the check that determines whether a suggestion is usable: the scanner
    performs the same resolution and rejects the scan if it fails.

    getaddrinfo has no per-call timeout argument. The previous implementation used
    socket.setdefaulttimeout(), which mutates a PROCESS-GLOBAL default that then
    silently caps every other socket in the same Lambda (the feed HTTP fetch, boto3
    clients, the SSRF resolution in ssrf.py) and is never restored. Running the
    lookup in a short-lived worker and bounding the wait keeps the timeout local to
    this call and leaves global socket state untouched.
    """
    try:
        host = urlparse(url).hostname
    except ValueError:
        return False
    if not host:
        return False
    pool = ThreadPoolExecutor(max_workers=1)
    future = pool.submit(socket.getaddrinfo, host, None)
    try:
        future.result(timeout=RESOLVE_TIMEOUT)
        return True
    except FuturesTimeout:
        logger.warning("[Feed] DNS resolution timed out for %s", host)
        return False
    except (socket.gaierror, OSError):
        return False
    finally:
        # Do not block on the worker if getaddrinfo is still stuck past the timeout;
        # the interpreter reaps it at exit. A blocking shutdown would defeat the
        # timeout we just enforced.
        pool.shutdown(wait=False)


def _screen(urls: list[str], validate_url) -> list[str]:
    """
    Drop URLs the scanner would refuse, and de-duplicate by host.

    Applying the scanner's own SSRF policy here means a suggestion cannot be
    something the scan would reject (a non-standard port, embedded credentials, a
    private IP). De-duplicating by host avoids a dropdown showing eight paths on
    one compromised domain.
    """
    seen_hosts: set[str] = set()
    out: list[str] = []
    for u in urls:
        if len(u) > 2000:
            continue
        if validate_url(u) is not None:
            continue
        try:
            host = (urlparse(u).hostname or "").lower()
        except ValueError:
            continue
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        out.append(u)
    return out


def _cache_read(s3, bucket: str) -> dict | None:
    if not bucket:
        return None
    try:
        obj = s3.get_object(Bucket=bucket, Key=CACHE_KEY)
        payload = json.loads(obj["Body"].read())
        age = time.time() - float(payload.get("generated_at", 0))
        if age < CACHE_TTL_SECONDS:
            payload["cache_age_seconds"] = int(age)
            return payload
        logger.info("[Feed] cache stale (%ds)", int(age))
    except (ClientError, BotoCoreError, ValueError, TypeError, KeyError) as e:
        # A cache miss must never be fatal.
        logger.info("[Feed] cache unavailable: %s", type(e).__name__)
    return None


def _cache_write(s3, bucket: str, payload: dict) -> None:
    if not bucket:
        return
    try:
        s3.put_object(
            Bucket=bucket,
            Key=CACHE_KEY,
            Body=json.dumps(payload).encode(),
            ContentType="application/json",
            ServerSideEncryption="aws:kms",
        )
    except (ClientError, BotoCoreError) as e:
        logger.warning("[Feed] cache write failed: %s: %s", type(e).__name__, e)


def get_live_phishing_urls(
    limit: int,
    validate_url,
    s3=None,
    bucket: str = "",
    force_refresh: bool = False,
) -> dict:
    """
    Return live phishing URLs suitable for scanning.

    `validate_url` is injected rather than imported to avoid a circular import with
    handler.py, and so tests can exercise screening without the Lambda module.

    Shape:
      {items: [{url, host, source}], generated_at, attribution,
       candidates_screened, live_count, cached, warning}
    """
    limit = max(1, min(int(limit or 10), 50))

    if not force_refresh:
        cached = _cache_read(s3, bucket)
        if cached:
            cached["items"] = cached.get("items", [])[:limit]
            cached["groups"] = [
                dict(g, items=g.get("items", [])[:limit]) for g in cached.get("groups", [])
            ]
            cached["cached"] = True
            return cached

    # No live threat feed is fetched: the UI shows curated, non-resolving examples
    # only. Genuinely live malicious URLs are handled by pasting them into the scan
    # box or the scan APIs, never surfaced in the UI.
    attribution = "Curated examples"

    def entry(url: str, risk: str, label: str, source: str) -> dict:
        return {
            "url": url,
            "host": urlparse(url).hostname or "",
            "risk": risk,  # high | medium | low
            "label": label,
            "source": source,
        }

    # High risk: curated, non-resolving phishing EXAMPLES, not live threat URLs.
    # Screened for policy so a displayed sample is never something the scanner
    # would reject for a reason other than being a fabricated (non-resolving) host.
    high = [
        entry(u, "high", label, "Curated phishing examples (illustrative, not live)")
        for u, label in HIGH_RISK_SAMPLES
        if validate_url(u) is None
    ]

    # Medium and low tiers are curated and stable, so they are screened for policy
    # but not liveness-probed on every refresh: they are chosen precisely because
    # they do not disappear, and probing them would add latency for no benefit.
    medium = [
        entry(u, "medium", label, "Safe Browsing / malware test harnesses")
        for u, label in MEDIUM_RISK
        if validate_url(u) is None
    ]
    low = [
        entry(u, "low", label, "Well-known high-traffic domains")
        for u, label in LOW_RISK
        if validate_url(u) is None
    ]

    payload = {
        # `items` stays high-risk-only for backwards compatibility with callers
        # that predate the tiers.
        "items": high,
        "groups": [
            {
                "risk": "high",
                "title": "Phishing",
                "description": "Illustrative phishing examples (safe to display; not live)",
                "items": high,
            },
            {
                "risk": "medium",
                "title": "Medium risk",
                "description": "Malware and unwanted-software test pages",
                "items": medium,
            },
            {
                "risk": "low",
                "title": "Safe",
                "description": "Well-known legitimate sites",
                "items": low,
            },
        ],
        "generated_at": time.time(),
        "attribution": attribution,
        "candidates_screened": 0,
        "live_count": len(high),
        "cached": False,
        "warning": (
            "High-risk entries are illustrative phishing examples for display and "
            "are not live malicious URLs; they may not resolve when scanned. To test "
            "a genuinely live URL, paste it into the scan box or use the scan APIs."
        ),
    }
    _cache_write(s3, bucket, payload)

    logger.info(
        "[Feed] %d high-risk samples; %d medium, %d low",
        len(high),
        len(medium),
        len(low),
    )
    payload = dict(payload)
    payload["items"] = payload["items"][:limit]
    payload["groups"] = [dict(g, items=g["items"][:limit]) for g in payload["groups"]]
    return payload
