# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Local SigV4 signing proxy for the development server.

Stands in for the production signing tier: the browser calls same-origin /api/*,
this signs with the developer's AWS credentials and forwards to API Gateway. The
browser therefore never holds an AWS credential, which is the same property the
production web Lambda provides via its execution role.

NOT FOR PRODUCTION. It performs no authentication of its own, so anyone who can
reach it can spend Bedrock on your account. It binds to loopback only.

Usage:
    AWS_PROFILE=... API_BASE_URL=https://<id>.execute-api.<region>.amazonaws.com/<stage> \
        python3 devproxy/sign_proxy.py [--port 8787]
"""

from __future__ import annotations

import argparse
import logging
import os
import posixpath
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("signproxy")

API_BASE_URL = os.environ.get("API_BASE_URL", "").rstrip("/")
SERVICE = "execute-api"


def normalize_request_path(raw: str) -> str:
    """Reject path traversal, then return the normalized path (+ query) to forward.

    The proxy re-signs whatever path the browser sends and forwards it to API
    Gateway. SigV4 signs the canonical request, so a smuggled "../" would be
    signed and forwarded verbatim; a crafted path such as /api/../admin could
    reach an endpoint the caller was never meant to touch. The path is therefore
    normalized and validated here instead of being trusted.

    Rejects, before anything is forwarded:
      - backslashes, which are never valid in a URL path and are a classic
        traversal-smuggling vector against mixed-OS backends;
      - percent-encoded dot/slash/backslash (%2e, %2f, %5c, any case), so an
        encoded "../" cannot slip past the decoded-segment check below;
      - any literal ".." path segment.
    The query string is preserved untouched; only the path is normalized.
    """
    if "\\" in raw:
        raise ValueError("backslash in request path")

    path, sep, query = raw.partition("?")

    lowered = path.lower()
    if "%2e" in lowered or "%2f" in lowered or "%5c" in lowered:
        raise ValueError("percent-encoded traversal in request path")
    if ".." in path.split("/"):
        raise ValueError("'..' segment in request path")

    # posixpath.normpath collapses "." and "//" and resolves any residual "..";
    # a result that still starts with ".." means the path tried to escape root.
    normalized = posixpath.normpath(path)
    if normalized == "." or normalized.startswith(".."):
        raise ValueError("path escapes root after normalization")

    return normalized + (sep + query if sep else "")


def response_headers(upstream_headers, length: int) -> list[tuple[str, str]]:
    """Headers to relay for an upstream response, mirroring web/server/wsgi.py.

    JSON and CSV keep their type (so GET /stats/export downloads as a file); any
    other type is labelled JSON so it can never render as HTML on this origin.
    """
    raw = (upstream_headers.get("Content-Type") or "") if upstream_headers else ""
    upstream_type = raw.split(";")[0].strip().lower() or "application/json"
    ctype = (
        upstream_type if upstream_type in ("application/json", "text/csv") else "application/json"
    )
    headers = [("Content-Type", ctype)]
    disposition = (upstream_headers.get("Content-Disposition") or "") if upstream_headers else ""
    if ctype == "text/csv" and disposition.startswith("attachment; filename="):
        headers.append(("Content-Disposition", disposition))
    headers.append(("Content-Length", str(length)))
    return headers


def _require_https(url: str) -> str:
    """Reject anything that is not https before it reaches the network.

    A URL assembled from configuration or an upstream feed is validated here
    rather than trusted; _HTTPS_OPENER enforces the same rule a second time.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"refusing non-https scheme: {parsed.scheme or '(none)'}")
    if not parsed.netloc:
        raise ValueError("refusing URL without a host")
    return url


def _https_opener() -> urllib.request.OpenerDirector:
    """Build an opener that can only speak HTTPS.

    urlopen's default opener also serves file:, ftp:, data: and plain http: URLs.
    This one installs no handler for those schemes, so they fail with "unknown url
    type" even if a caller skips _require_https, and a redirect to one fails too.
    """
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.UnknownHandler(),
        urllib.request.HTTPSHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPRedirectHandler(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    return opener


_HTTPS_OPENER = _https_opener()


def _region() -> str:
    if API_BASE_URL:
        host = urlsplit(API_BASE_URL).netloc
        parts = host.split(".")
        if len(parts) > 2 and parts[1] == SERVICE:
            return parts[2]
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"


REGION = _region()
_session = boto3.Session()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:  # quieter default logging
        log.debug(fmt, *args)

    def _proxy(self, method: str) -> None:
        try:
            safe_path = normalize_request_path(self.path)
        except ValueError as exc:
            # Do not echo the raw path back to the client; log it for the operator.
            log.warning("rejected request path %r: %s", self.path, exc)
            self.send_error(400, "bad request path")
            return
        if not safe_path.startswith("/api/"):
            self.send_error(404, "only /api/* is proxied")
            return
        if not API_BASE_URL:
            self.send_error(500, "API_BASE_URL is not set")
            return

        upstream = f"{API_BASE_URL}{safe_path[len('/api') :]}"
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""

        creds = _session.get_credentials()
        if creds is None:
            self.send_error(500, "no AWS credentials available to sign with")
            return

        headers = {"Content-Type": "application/json"} if body else {}
        aws_req = AWSRequest(method=method, url=upstream, data=body, headers=headers)
        SigV4Auth(creds.get_frozen_credentials(), SERVICE, REGION).add_auth(aws_req)

        req = urllib.request.Request(  # noqa: S310 (scheme checked by _require_https)
            _require_https(upstream),
            data=body or None,
            method=method,
            headers=dict(aws_req.headers),
        )
        try:
            with _HTTPS_OPENER.open(req, timeout=60) as resp:
                payload, status, resp_headers = resp.read(), resp.status, resp.headers
        except urllib.error.HTTPError as e:
            # 4xx/5xx from the API are meaningful to the client (400 validation,
            # 403 auth), so forward them verbatim instead of masking as a 502.
            payload, status, resp_headers = e.read(), e.code, e.headers
        except urllib.error.URLError as e:
            log.error("upstream unreachable: %s", e.reason)
            self.send_error(502, "upstream unreachable")
            return

        log.info("%s %s -> %s (%d bytes)", method, self.path, status, len(payload))
        self.send_response(status)
        for name, value in response_headers(resp_headers, len(payload)):
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        self._proxy("GET")

    def do_POST(self) -> None:
        self._proxy("POST")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    if not API_BASE_URL:
        log.error("API_BASE_URL must be set")
        return 2
    log.info("signing for %s in %s", API_BASE_URL, REGION)
    log.info("listening on http://127.0.0.1:%d/api/*  (loopback only)", args.port)
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
