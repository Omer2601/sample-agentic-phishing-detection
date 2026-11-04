# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""One plain HTTP GET walk of a URL's redirects, for when the browser cannot tell us.

The managed browser refuses some URLs before sending a request (blocked_by_browser), and a
dead host or a slow page leaves it with no answer. This probe asks the site directly: GET,
redirects followed by hand (at most MAX_REDIRECTS), every hop through the same url_safety
guard as the browser and connected to the exact address that guard approved (the hostname
still goes in SNI and Host), MAX_BODY_BYTES of the bytes on the wire read at most (no content
decoding, so a compressed body cannot inflate past the cap), nothing parsed or executed. With
keep_body the final page's bytes (at most MAX_BODY_BYTES, still unparsed, only when the page
is served uncompressed) go back to the caller: code_analyst's raw HTML fallback when the
browser cannot load the page.

Outcomes: ok (the site answers), error_404, site_down (410, a refused or reset connection,
or a hop whose host does not resolve), blocked (our guard refused a hop) and unreachable
(inconclusive: timeout, TLS failure, too many redirects), which callers treat like ok.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import ssl
from urllib.parse import urljoin

import httpcore
import httpx

from phish_agents.common import url_safety

logger = logging.getLogger(__name__)

TOTAL_S = 8.0
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 64 * 1024
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
# Kits cloak from non-browser clients (a 404 to a script would end the scan as error_404),
# so the probe presents itself as a desktop browser.
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    # The body is read raw and capped on the wire; a compressed one is not kept (keep_body).
    "Accept-Encoding": "identity",
}


class _PinnedBackend(httpcore.AsyncNetworkBackend):
    """Dials only the addresses url_safety approved for a host, never a fresh DNS answer.

    httpcore still passes the hostname for TLS (SNI and certificate checks), and httpx sends
    it in Host, so only the TCP connect changes.
    """

    def __init__(self, pins: dict[str, list[str]], inner=None) -> None:
        self._pins, self._inner = pins, inner or httpcore.AnyIOBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        addresses = self._pins.get(host)
        if not addresses:
            raise httpcore.ConnectError(f"{host} has no address approved by the guard")
        refused: httpcore.ConnectError | None = None
        timed_out: httpcore.ConnectTimeout | None = None
        for address in addresses:
            try:
                return await self._inner.connect_tcp(
                    address, port, timeout, local_address, socket_options
                )
            except httpcore.ConnectError as exc:
                refused = exc
            except httpcore.ConnectTimeout as exc:
                timed_out = exc
        # One slow address makes the host inconclusive (unreachable), not refused (site_down).
        raise timed_out or refused

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class _PinnedTransport(httpx.AsyncHTTPTransport):
    def __init__(self, pins: dict[str, list[str]], network_backend=None) -> None:
        super().__init__(trust_env=False)
        # httpx has no network_backend option, so its connection pool is replaced by the same
        # default pool dialling through _PinnedBackend.
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(trust_env=False),
            network_backend=_PinnedBackend(pins, network_backend),
        )


def _pin_key(url: str) -> str:
    # The host as httpcore sees it: IDNA-encoded, IPv6 without brackets.
    return httpx.URL(url).raw_host.decode("ascii")


def _is_tls_failure(exc: BaseException) -> bool:
    """True when the connect failed in the TLS handshake (the host answered).

    Checks the exception chain for ssl.SSLError first, so the outcome does not depend on how
    a library words its message, and falls back to the message for wrapped errors.
    """
    seen: BaseException | None = exc
    for _ in range(10):  # chains are short; the cap only guards against a cycle
        if seen is None:
            break
        if isinstance(seen, ssl.SSLError):
            return True
        seen = seen.__cause__ or seen.__context__
    text = str(exc)
    return "SSL" in text or "certificate" in text.lower()


def _result(outcome: str, hops: list[str], status=None, reason: str = "", body: int = 0) -> dict:
    return {
        "outcome": outcome,
        "final_status": status,
        "final_url": hops[-1] if hops else "",
        "hops": hops,
        "reason": reason,
        "body_bytes": body,
    }


async def _walk(
    url: str, client: httpx.AsyncClient, pins: dict[str, list[str]], keep_body: bool = False
) -> dict:
    hops: list[str] = []
    while True:
        hops.append(url)
        reason, kind, addresses = await asyncio.to_thread(url_safety.checked_addresses, url)
        if kind == url_safety.HOST_NXDOMAIN:
            return _result("site_down", hops, reason=reason or "the host does not resolve")
        if kind == url_safety.HOST_UNRESOLVED:
            return _result("unreachable", hops, reason=reason or "DNS lookup failed")
        if reason:
            return _result("blocked", hops, reason=reason)
        try:
            pins[_pin_key(url)] = addresses
            async with client.stream("GET", url, headers=_HEADERS) as response:
                headers = response.headers
                encoding = headers.get("content-encoding", "").strip().lower()
                keep = keep_body and encoding in ("", "identity")
                body, kept = 0, bytearray()
                # Raw bytes: httpx would inflate gzip or brotli per chunk, past any cap.
                async for chunk in response.aiter_raw():
                    body += len(chunk)
                    if keep:
                        kept += chunk[: MAX_BODY_BYTES - len(kept)]
                    if body >= MAX_BODY_BYTES:
                        break
                status, location = response.status_code, headers.get("location")
        except httpx.ConnectError as exc:
            text = str(exc)
            # A bad certificate or TLS setup means the server answered: inconclusive, never
            # site_down (the same rule as browser.TLS_ERROR).
            if _is_tls_failure(exc):
                return _result("unreachable", hops, reason=f"TLS handshake failed: {text[:120]}")
            return _result("site_down", hops, reason=f"could not connect: {text[:120]}")
        except (httpx.ReadError, httpx.RemoteProtocolError) as exc:
            return _result("site_down", hops, reason=f"connection reset: {type(exc).__name__}")
        except httpx.TimeoutException:
            return _result("unreachable", hops, reason="the site did not answer in time")
        except httpx.HTTPError as exc:
            return _result("unreachable", hops, reason=f"HTTP error: {type(exc).__name__}")
        body = min(body, MAX_BODY_BYTES)
        if status in _REDIRECTS and location:
            if len(hops) > MAX_REDIRECTS:
                return _result("unreachable", hops, status, f"more than {MAX_REDIRECTS} redirects")
            url = urljoin(url, location)
            continue
        if status == 404:
            return _result("error_404", hops, status, "HTTP 404 Not Found", body)
        if status == 410:
            return _result("site_down", hops, status, "HTTP 410 Gone", body)
        result = _result("ok", hops, status, f"HTTP {status}", body)
        if keep_body:
            result["body"] = bytes(kept)
            result["content_encoding"] = encoding
            result["content_type"] = headers.get("content-type", "")
            # Cloudflare marks its challenge pages with cf-mitigated: challenge.
            result["cf_mitigated"] = headers.get("cf-mitigated", "")
        return result


async def http_probe(
    url: str,
    *,
    total_s: float = TOTAL_S,
    transport=None,
    keep_body: bool = False,
    network_backend=None,
) -> dict:
    """Walk url's redirects within total_s seconds. Never raises.

    transport replaces the pinned one (tests); network_backend is what the pinned transport
    dials through (tests: a fake socket layer).
    """
    pins: dict[str, list[str]] = {}
    try:
        async with (
            asyncio.timeout(total_s),
            httpx.AsyncClient(
                follow_redirects=False,
                timeout=total_s,
                transport=transport or _PinnedTransport(pins, network_backend),
                trust_env=False,
            ) as client,
        ):
            return await _walk(url, client, pins, keep_body)
    except TimeoutError:
        return _result("unreachable", [url], reason="the probe ran out of time")


# A navigation that answers with a file (Content-Disposition attachment, or a type the browser
# will not render) is fingerprinted here, never in the browser: one guarded GET, the same pinned
# addresses and redirect walk as http_probe, bytes hashed in memory as they arrive and dropped,
# nothing written to disk, parsed or executed. The read stops at DOWNLOAD_MAX_BYTES.
DOWNLOAD_MAX_BYTES = 10 * 1024 * 1024
_SNIFF_BYTES = 512
_MAGIC = (
    (b"MZ", "application/x-msdownload", "executable"),
    (b"\x7fELF", "application/x-elf", "executable"),
    (b"\xcf\xfa\xed\xfe", "application/x-mach-binary", "executable"),
    (b"PK\x03\x04", "application/zip", "archive"),
    (b"Rar!", "application/vnd.rar", "archive"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "archive"),
    (b"\x1f\x8b", "application/gzip", "archive"),
    (b"%PDF-", "application/pdf", "document"),
)
_HTML_START = (b"<!doctype html", b"<html", b"<head", b"<script", b"<body")


def sniff_file_type(head: bytes) -> tuple[str, str]:
    """(MIME type, kind) from a file's first bytes: kind is executable, archive, document,
    html or other. Never trusts the server's Content-Type."""
    for magic, mime, kind in _MAGIC:
        if head.startswith(magic):
            return mime, kind
    text = head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if text.startswith(_HTML_START):
        return "text/html", "html"
    return "application/octet-stream", "other"


def _fingerprint_result(outcome: str, hops: list[str], status=None, reason: str = "") -> dict:
    return {
        "outcome": outcome,
        "final_url": hops[-1] if hops else "",
        "status": status,
        "reason": reason,
        "sha256": None,
        "bytes_read": 0,
        "size": None,
        "size_cap": DOWNLOAD_MAX_BYTES,
        "truncated": False,
        "content_type": "",
        "content_disposition": "",
        "sniffed_type": "",
        "kind": "",
    }


async def _fingerprint_walk(
    url: str, client: httpx.AsyncClient, pins: dict[str, list[str]], max_bytes: int
) -> dict:
    hops: list[str] = []
    while True:
        hops.append(url)
        reason, kind, addresses = await asyncio.to_thread(url_safety.checked_addresses, url)
        if kind == url_safety.HOST_NXDOMAIN:
            return _fingerprint_result("site_down", hops, reason=reason or "no such host")
        if kind == url_safety.HOST_UNRESOLVED:
            return _fingerprint_result("unreachable", hops, reason=reason or "DNS lookup failed")
        if reason:
            return _fingerprint_result("blocked", hops, reason=reason)
        pins[_pin_key(url)] = addresses
        try:
            async with client.stream("GET", url, headers=_HEADERS) as response:
                status, headers = response.status_code, response.headers
                location = headers.get("location")
                if status in _REDIRECTS and location:
                    if len(hops) > MAX_REDIRECTS:
                        return _fingerprint_result(
                            "unreachable", hops, status, f"more than {MAX_REDIRECTS} redirects"
                        )
                    url = urljoin(url, location)
                    continue
                encoding = headers.get("content-encoding", "").strip().lower()
                if encoding not in ("", "identity"):
                    # Raw bytes are the compressed stream: their hash and magic bytes would not
                    # describe the file, so none are reported.
                    return _fingerprint_result(
                        "unreachable", hops, status, f"non-identity content-encoding: {encoding}"
                    )
                digest, head, read, truncated = hashlib.sha256(), bytearray(), 0, False
                async for chunk in response.aiter_raw():
                    if read + len(chunk) > max_bytes:
                        truncated = True
                        chunk = chunk[: max_bytes - read]
                    digest.update(chunk)
                    if len(head) < _SNIFF_BYTES:
                        head += chunk[: _SNIFF_BYTES - len(head)]
                    read += len(chunk)
                    if truncated:
                        break
        except httpx.HTTPError as exc:
            return _fingerprint_result("unreachable", hops, reason=type(exc).__name__)
        declared = headers.get("content-length", "")
        mime, file_kind = sniff_file_type(bytes(head))
        result = _fingerprint_result("ok", hops, status, f"HTTP {status}")
        result.update(
            # Over the cap the hash would describe a prefix only, so it is not reported.
            sha256=None if truncated else digest.hexdigest(),
            bytes_read=read,
            size_cap=max_bytes,
            size=int(declared) if declared.isdigit() else (None if truncated else read),
            truncated=truncated,
            content_type=headers.get("content-type", "")[:120],
            content_disposition=headers.get("content-disposition", "")[:200],
            sniffed_type=mime,
            kind=file_kind,
        )
        return result


async def download_fingerprint(
    url: str,
    *,
    total_s: float = TOTAL_S,
    max_bytes: int = DOWNLOAD_MAX_BYTES,
    transport=None,
    network_backend=None,
) -> dict:
    """sha256, size and type of the file url serves, within total_s seconds. Never raises."""
    pins: dict[str, list[str]] = {}
    try:
        async with (
            asyncio.timeout(total_s),
            httpx.AsyncClient(
                follow_redirects=False,
                timeout=total_s,
                transport=transport or _PinnedTransport(pins, network_backend),
                trust_env=False,
            ) as client,
        ):
            return await _fingerprint_walk(url, client, pins, max_bytes)
    except TimeoutError:
        return _fingerprint_result("unreachable", [url], reason="the fetch ran out of time")
    except (ValueError, httpx.InvalidURL) as exc:
        # A malformed Location or an absurd Content-Length from the server.
        return _fingerprint_result("unreachable", [url], reason=type(exc).__name__)
