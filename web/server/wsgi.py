# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Production UI server: static SPA plus a SigV4 signing proxy.

Replaces the Streamlit app. Two responsibilities, deliberately kept small:

  1. serve the built single-page app from dist/, with history fallback so client
     side routes resolve on a hard refresh;
  2. proxy /api/* to API Gateway, signing each request with SigV4 using the web
     Lambda's execution role.

The proxy is what makes the browser safe to ship: the role credentials stay in
this function, so no AWS credential and no signing logic ever reaches the
client, and the browser talks only to its own origin. That is the same trust
model the Streamlit app used, moved behind an HTTP boundary instead of a Python
one.

Written against WSGI with no web framework: the routing surface is three cases,
and a framework would add dependencies and attack surface without removing any
real work.

AUTHENTICATION: this tier authenticates its callers with an Amazon Cognito OIDC
session (see auth.py). The unauthenticated surface is a short allowlist and
nothing else: /healthz and /health (the load balancer cannot present a session
cookie), POST /auth/register and GET /auth/config plus the /register and
/welcome pages and the hashed bundles they load (a new user has no account
yet, so a registration page behind the session check could never be reached),
and that is all. See _is_public_path.
Every other browser navigation without a session is redirected to the identity
provider, including "/"; /api/* calls without one get 401 so the SPA can decide
to start the login flow itself.

The check fails closed. If the authentication configuration cannot be read, the
request is refused with 503 rather than served, because serving it would turn a
misconfigured deploy into an open proxy for Bedrock.
"""

from __future__ import annotations

import json
import logging
import mimetypes
import os
import posixpath
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

# Relative: gunicorn loads this module as server.wsgi, so a bare "import auth"
# searches sys.path (which holds /app, not /app/server) and fails.
from . import auth

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ui")

DIST = Path(os.environ.get("DIST_DIR", "/app/dist"))
API_BASE_URL = os.environ.get("API_BASE_URL", "").rstrip("/")
SERVICE = "execute-api"
UPSTREAM_TIMEOUT = int(os.environ.get("UPSTREAM_TIMEOUT", "240"))

# Cap on the request body we will read and forward. Without a ceiling, a client
# could stream an unbounded body and force this process to buffer it entirely
# in memory before signing, which is a trivial denial-of-service. 1 MiB is far
# larger than any real payload here (a URL, or a JSON array of at most 50 URLs;
# larger lists go straight to S3) yet small enough to be harmless to hold.
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(1024 * 1024)))

# Header carrying the verified Cognito subject to the backend. It is added to the
# request BEFORE SigV4 signing (see _proxy), so it is covered by the signature and
# cannot be added or altered downstream without invalidating the request. The
# backend trusts it only when the SigV4 caller is this proxy's role (PROXY_ROLE_ARN).
CONSOLE_USER_HEADER = "X-Console-User-Sub"

# Explicit allowlist of the backend routes the SPA actually calls (derived from
# web/src/lib/api.ts and web/src/pages/ApiConsolePage.tsx). The proxy
# is a signing gateway, not an open tunnel: without an allowlist it would sign and
# forward any path under /api, lending the proxy role's authority to routes the UI
# never uses. Anything not matched here is refused with 404 so an unlisted route is
# indistinguishable from one that does not exist. Patterns are anchored full-path
# matches against the sub-path after the /api prefix; the query string is excluded.
# The complete v2 surface the SPA may reach. Anything else is a 404 here, before
# signing, so this tier can never be used to sign arbitrary API calls.
_ID = r"[A-Za-z0-9-]{1,64}"
_API_ALLOWLIST: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("GET", re.compile(r"/health")),
    ("POST", re.compile(r"/scan")),
    ("GET", re.compile(rf"/scans/{_ID}")),
    ("GET", re.compile(rf"/scans/{_ID}/report")),
    ("POST", re.compile(rf"/scans/{_ID}/retry")),
    ("POST", re.compile(r"/batches")),
    ("GET", re.compile(r"/batches")),
    ("GET", re.compile(rf"/batches/{_ID}")),
    ("GET", re.compile(rf"/batches/{_ID}/report")),
    ("POST", re.compile(rf"/batches/{_ID}/retry-failed")),
    ("GET", re.compile(r"/history")),
    ("GET", re.compile(r"/stats")),
    ("GET", re.compile(r"/stats/export")),
    ("GET", re.compile(r"/feed/phishing")),
)


def _api_route_allowed(method: str, path: str) -> bool:
    """True when method+path is an allowlisted backend route.

    path is the sub-path after the /api prefix, with the query string already
    stripped by the caller.
    """
    return any(m == method and pattern.fullmatch(path) is not None for m, pattern in _API_ALLOWLIST)


# --------------------------------------------------------------------------- #
# The unauthenticated surface
# --------------------------------------------------------------------------- #
#
# Everything else on this tier requires a session. These are the exceptions, and
# they are an allowlist rather than a prefix rule so the set can be read in one
# place and cannot grow by accident.
#
# WHY THESE TWO PAGES ARE PUBLIC
# A caller who has not registered yet cannot have a session, so a registration
# page behind the session check can never be reached: the browser would be sent
# to Cognito, where it has no account to sign in with. /register renders the
# registration form that POSTs to /auth/register, and /welcome is where that form
# lands afterwards.
#
# WHY THE ROOT IS STILL NOT PUBLIC
# "/" continues to 302 to Cognito managed login for an anonymous caller. That is
# deliberate and it is the property the whole design protects: external scanning
# evaluates the root, and a 200 with HTML there is the posture to avoid. Serving
# the app shell at two named paths is a much narrower exposure than the SPA
# history fallback would be, which is why the fallback is explicitly NOT applied
# to anonymous requests below.
_PUBLIC_PAGES = ("/register", "/welcome")

# Content-hashed bundles emitted by the Vite build into dist/assets. One path
# segment only, so nothing nested and nothing outside that directory matches.
# These are JavaScript and CSS, no HTML and no data, which is the same reasoning
# that puts them on a public CloudFront behaviour in the target architecture.
#
# The first character must be alphanumeric or an underscore, which is what
# excludes "/assets/.." and "/assets/.". Those are the dangerous cases: they are a
# single path segment, so a looser pattern matches them, and _safe_asset
# normalises both back inside dist/ where "assets/.." becomes "." and is then
# resolved to index.html. That would hand an anonymous caller a 200 with the app
# shell at an invented URL. Vite's hashed names always start alphanumeric.
_PUBLIC_ASSET_RE = re.compile(r"/assets/[A-Za-z0-9_][A-Za-z0-9._-]*")

# Root-level files a browser fetches on its own or that index.html references.
# shield.svg is the favicon (see web/index.html). The other two do not exist in
# dist today and are listed so a browser's automatic request gets an honest 404
# rather than a redirect to the identity provider.
_PUBLIC_FILES = ("/shield.svg", "/favicon.ico", "/robots.txt")


def _is_public_path(path: str) -> bool:
    """True when a path must be served without a session.

    This predicate governs the read-only GET surface only. POST /auth/register and
    GET /auth/config are also unauthenticated but are deliberately NOT listed here,
    because callers of this function are answered GET/HEAD only; both have their
    own branch above the
    session lookup in application(). Adding it here would break the POST.
    """
    # Belt and braces alongside the character class in _PUBLIC_ASSET_RE: no
    # relative segment can appear anywhere in an anonymous request, whatever a
    # future edit does to the pattern.
    if ".." in path:
        return False
    return (
        path in _PUBLIC_PAGES
        or path in _PUBLIC_FILES
        or _PUBLIC_ASSET_RE.fullmatch(path) is not None
    )


# --------------------------------------------------------------------------- #
# Invite route: limits and abuse controls
# --------------------------------------------------------------------------- #

# Body cap for POST /auth/register. Three short strings; anything larger is a mistake or
# an attempt to make this process buffer something.
REGISTER_MAX_BODY_BYTES = int(os.environ.get("REGISTER_MAX_BODY_BYTES", "4096"))

# Rate limit window and ceilings.
#
# WHAT ACTUALLY STOPS A BRUTE FORCE, honestly stated: not this. When invites are
# on (-c inviteCode=true) the code is a 32-character alphanumeric value generated
# by Secrets Manager, which is roughly 190 bits of entropy.
# No request rate makes guessing it feasible, and no rate limit would save a code
# that was chosen by a human instead. The limiter exists to keep the cost of
# pointless traffic off Cognito and out of the logs, and to make a scripted attempt
# obvious rather than invisible.
#
# Two honest limitations. First, this state is per worker process: gunicorn runs
# several workers per task and the service scales to several tasks, so the
# effective ceiling is the value below multiplied by the number of live workers.
# Second, the per-IP key is only as good as the forwarded-for derivation in
# _client_ip.
#
# What sits above this: the CLOUDFRONT-scoped edge web ACL has a RegisterRateLimit
# rule (POST /auth/register, 10 per 5 minutes per IP, blocked with a JSON 429) ahead
# of the general 3,000 per 5 minutes rule. That edge rule is the authoritative
# ceiling: this limiter is per Lambda execution environment, so concurrency
# multiplies its allowance.
REGISTER_WINDOW_SECONDS = int(os.environ.get("REGISTER_WINDOW_SECONDS", "900"))
REGISTER_MAX_PER_CLIENT = int(os.environ.get("REGISTER_MAX_PER_CLIENT", "5"))
REGISTER_MAX_PER_WINDOW = int(os.environ.get("REGISTER_MAX_PER_WINDOW", "60"))
# Ceiling on tracked client keys, so the bookkeeping cannot itself be turned into
# a memory exhaustion vector by a caller that varies its forwarded-for value.
REGISTER_MAX_TRACKED_CLIENTS = 4096

_register_lock = threading.Lock()
# client key -> attempt timestamps within the window
_register_attempts: dict[str, list[float]] = {}
# every attempt within the window, regardless of client
_register_window: list[float] = []


def _register_status(outcome: str) -> str:
    """Map an auth.INVITE_* outcome to an HTTP status line.

    A table rather than logic, so a new outcome cannot silently inherit 200, and
    built per call rather than at import so this module does not depend on the
    order in which auth.py's constants become available.

    The status codes are part of the contract with the SPA, which classifies on
    the "code" field in the body first and falls back to the status: 429 rate
    limited, 403 invite code invalid or missing, 5xx generic. There is no
    "already registered" status: an existing address gets the same 200 as a new
    one, so the route cannot be used to enumerate accounts. Every outcome below
    therefore has to agree with its own code value, which is why rate limiting
    has an outcome of its own rather than borrowing invalid_request.
    """
    return {
        auth.REGISTER_OK: "200 OK",
        auth.REGISTER_BAD_REQUEST: "400 Bad Request",
        auth.REGISTER_BAD_CODE: "403 Forbidden",
        auth.REGISTER_EMAIL_NOT_ALLOWED: "403 Forbidden",
        auth.REGISTER_RATE_LIMITED: "429 Too Many Requests",
        auth.REGISTER_UNAVAILABLE: "503 Service Unavailable",
    }.get(outcome, "500 Internal Server Error")


def _register_reply(start, outcome: str, message: str, extra_headers=None):
    """One place that builds every /auth/register response.

    "code" is the field the SPA classifies on, and it is always the same symbol
    that chose the status line, so the two can never disagree. "message" is human
    text. Nothing else goes in the body: no invite code, no token,
    and no echo of the submitted request.
    """
    body = {"code": outcome, "message": message}
    if outcome == auth.REGISTER_OK:
        # Where the SPA should send the user next. Sign-in stays on Cognito
        # managed login, which also means Cognito handles any MFA challenge
        # (optional TOTP by default, required with -c mfa=required) rather
        # than this application.
        body["next"] = "/auth/login"
    headers = [("Cache-Control", "no-store")]
    headers.extend(extra_headers or [])
    return _json(start, _register_status(outcome), body, headers)


def _client_ip(environ: dict) -> str:
    """Best available client identifier for rate limiting.

    The header this tier receives is built by two proxies that both APPEND, so
    the chain reads:

        <anything the viewer sent>, <viewer IP added by CloudFront>, <CloudFront
        edge IP added by the next hop in front of this tier>

    CloudFront appends to whatever the viewer supplied, which makes the leftmost
    entry attacker controlled: keying a rate limit on it would let one client
    present a fresh identity per request. The viewer's real address is therefore
    the second entry from the right. With a single entry the request did not come
    through both proxies (local runs, direct probes) and that entry is used as
    is; with none, the socket peer is.
    """
    forwarded = [
        part.strip() for part in environ.get("HTTP_X_FORWARDED_FOR", "").split(",") if part.strip()
    ]
    if len(forwarded) >= 2:
        return forwarded[-2]
    if forwarded:
        return forwarded[0]
    return environ.get("REMOTE_ADDR", "-")


def _register_rate_limited(client: str, now: float | None = None) -> bool:
    """Record an attempt and report whether it should be refused.

    Sliding window, two ceilings: one per client so a single source cannot
    grind, and one across all clients so a distributed attempt is bounded too.
    Over-cap tracking evicts the least recently seen client rather than refusing
    new ones, because refusing them would let a flood of throwaway identities lock
    every genuine invitee out of registering.
    """
    now = time.monotonic() if now is None else now
    cutoff = now - REGISTER_WINDOW_SECONDS
    with _register_lock:
        _register_window[:] = [t for t in _register_window if t > cutoff]
        if len(_register_window) >= REGISTER_MAX_PER_WINDOW:
            return True

        recent = [t for t in _register_attempts.get(client, []) if t > cutoff]
        if len(recent) >= REGISTER_MAX_PER_CLIENT:
            _register_attempts[client] = recent
            return True

        recent.append(now)
        _register_attempts[client] = recent
        _register_window.append(now)

        # Prune expired keys first, then evict by least recent activity.
        for key in [k for k, v in _register_attempts.items() if not v or max(v) <= cutoff]:
            del _register_attempts[key]
        while len(_register_attempts) > REGISTER_MAX_TRACKED_CLIENTS:
            oldest = min(_register_attempts, key=lambda k: max(_register_attempts[k]))
            del _register_attempts[oldest]
        return False


# Content Security Policy for every response, including the SPA shell and the
# JSON proxy responses. script-src is 'self' with no 'unsafe-inline': the Vite
# build (see web/index.html and web/vite.config.ts) emits only an external module
# script and hashed asset bundles, so inline scripts are neither present nor
# needed, and forbidding them removes the primary XSS execution path. style-src
# allows 'unsafe-inline' because the charting library and utility CSS set inline
# style attributes at runtime; that is a much weaker exposure than inline script.
# img-src permits https: because screenshot evidence is rendered from short-lived
# presigned S3 URLs on a different host, plus data:/blob: for inline previews.
# connect-src is 'self' because all API and auth traffic is same-origin through
# this proxy, plus the upload bucket origin (see build_csp). frame-ancestors
# 'none' (mirrored by X-Frame-Options for older browsers) forbids framing,
# which blocks clickjacking.
# The one extra origin the SPA talks to: the S3 upload bucket for presigned POSTs.
# Only a bare https S3 origin is accepted, so a bad value cannot widen the policy.
# It joins connect-src (the fetch that uploads) and form-action (interfaces.md).
_S3_ORIGIN_RE = re.compile(r"https://[a-z0-9][a-z0-9.-]{1,62}\.s3(\.[a-z0-9-]+)?\.amazonaws\.com")


def build_csp(upload_origin: str) -> str:
    extra = ""
    if upload_origin and _S3_ORIGIN_RE.fullmatch(upload_origin):
        extra = f" {upload_origin}"
    elif upload_origin:
        log.warning("ignoring UPLOAD_ORIGIN that is not an S3 https origin: %r", upload_origin)
    return (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob: https:; "
        "font-src 'self' data:; "
        f"connect-src 'self'{extra}; "
        "object-src 'none'; "
        "base-uri 'self'; "
        f"form-action 'self'{extra}; "
        "frame-ancestors 'none'"
    )


_CSP = build_csp(os.environ.get("UPLOAD_ORIGIN", ""))

# Applied to every response. HSTS is safe because the app is only reached over
# TLS (CloudFront terminates HTTPS in front of this tier); a two-year max-age with
# includeSubDomains is the value the preload list expects.
_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("Content-Security-Policy", _CSP),
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
)


def _with_security_headers(start_response: Callable) -> Callable:
    """Wrap start_response so every response carries the security headers.

    Adding them in one place guarantees the SPA shell, static assets, redirects,
    and the /api proxy responses are all covered; the previous code set a partial
    set on the static path only. A header already present on a response is left
    as set rather than duplicated.
    """

    def _start(status: str, headers: list, exc_info=None):
        present = {k.lower() for k, _ in headers}
        merged = list(headers)
        merged.extend((k, v) for k, v in _SECURITY_HEADERS if k.lower() not in present)
        return start_response(status, merged, exc_info)

    return _start


# Reused across requests: resolving role credentials on every call would add
# latency, and boto3 refreshes them internally before expiry.
_session = boto3.Session()


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
        parts = urlsplit(API_BASE_URL).netloc.split(".")
        if len(parts) > 2 and parts[1] == SERVICE:
            return parts[2]
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-west-2"


REGION = _region()
log.info("UI server: dist=%s api=%s region=%s", DIST, API_BASE_URL or "<unset>", REGION)


def _json(start, status: str, payload: dict, extra_headers=None):
    body = json.dumps(payload).encode()
    headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
    headers.extend(extra_headers or [])
    start(status, headers)
    return [body]


def _safe_asset(url_path: str) -> Path | None:
    """
    Resolve a request path to a file inside dist/, or None.

    Normalising and then confirming the result is still under dist/ blocks path
    traversal (`/../../etc/passwd`), which is the obvious risk in any static
    handler.
    """
    rel = posixpath.normpath(url_path.lstrip("/"))
    if rel in ("", "."):
        rel = "index.html"
    candidate = (DIST / rel).resolve()
    try:
        candidate.relative_to(DIST.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def _serve_static(url_path: str, start):
    asset = _safe_asset(url_path)
    if asset is None:
        # SPA history fallback: unknown paths are client-side routes, so hand back
        # index.html and let the router decide, rather than 404ing a valid route.
        asset = DIST / "index.html"
        if not asset.is_file():
            return _json(start, "500 Internal Server Error", {"error": "UI assets missing"})

    ctype = mimetypes.guess_type(str(asset))[0] or "application/octet-stream"
    data = asset.read_bytes()
    # Hashed bundles are immutable and safe to cache hard; index.html must not be,
    # or a deploy would keep serving the previous app shell.
    cache = "no-cache" if asset.name == "index.html" else "public, max-age=31536000, immutable"
    start(
        "200 OK",
        [
            ("Content-Type", ctype),
            ("Content-Length", str(len(data))),
            ("Cache-Control", cache),
            # Security headers (CSP, HSTS, nosniff, frame options, referrer) are
            # applied to every response by _with_security_headers, so they are not
            # repeated here.
        ],
    )
    return [data]


_PASSTHROUGH_TYPES = {"application/json", "text/csv"}
_DISPOSITION_RE = re.compile(r'attachment; filename="[A-Za-z0-9._-]{1,100}"')


def _forward(start, status: int, payload: bytes, upstream_headers) -> list[bytes]:
    """Relay an upstream response, keeping only headers this tier vouches for.

    JSON and CSV keep their type; anything else is labelled JSON, as in v1, so an
    unexpected upstream type can never render as HTML on this origin. A download
    filename survives only in its exact attachment form.
    """
    raw_type = (upstream_headers.get("Content-Type") or "") if upstream_headers else ""
    ctype = raw_type.split(";")[0].strip().lower()
    headers = [
        ("Content-Type", ctype if ctype in _PASSTHROUGH_TYPES else "application/json"),
        ("Content-Length", str(len(payload))),
        ("Cache-Control", "no-store"),
    ]
    disposition = (upstream_headers.get("Content-Disposition") or "") if upstream_headers else ""
    if ctype == "text/csv" and _DISPOSITION_RE.fullmatch(disposition):
        headers.append(("Content-Disposition", disposition))
    start(f"{status} ", headers)
    return [payload]


def _proxy(environ, start, user_sub: str | None):
    """Sign and forward one allowlisted /api/* request to API Gateway.

    user_sub is the verified Cognito subject of the authenticated caller. It is
    forwarded in a SigV4-signed header so the backend can attribute the request
    to a specific user rather than to the shared proxy role.
    """
    if not API_BASE_URL:
        return _json(
            start, "500 Internal Server Error", {"error": "API_BASE_URL is not configured"}
        )

    path = environ.get("PATH_INFO", "")[len("/api") :] or "/"
    if ".." in path:
        return _json(start, "400 Bad Request", {"error": "invalid path"})

    method = environ.get("REQUEST_METHOD", "GET")
    # Route allowlist: refuse anything the SPA does not actually call, so the
    # proxy cannot be used to reach arbitrary backend routes with the proxy role's
    # authority. Unlisted routes return 404 rather than 403 to avoid confirming
    # which paths exist.
    if not _api_route_allowed(method, path):
        log.warning("proxy rejected non-allowlisted route: %s %s", method, path)
        return _json(start, "404 Not Found", {"error": "not found"})

    query = environ.get("QUERY_STRING", "")
    upstream = f"{API_BASE_URL}{path}" + (f"?{query}" if query else "")

    # Bounded read: never buffer more than MAX_BODY_BYTES. Reading one byte past
    # the cap lets us distinguish "exactly at the limit" from "over it" and reject
    # oversized bodies with 413 before signing or forwarding them.
    body = (
        environ["wsgi.input"].read(MAX_BODY_BYTES + 1)
        if method in ("POST", "PUT", "PATCH")
        else b""
    )
    if len(body) > MAX_BODY_BYTES:
        log.warning("proxy rejected oversized body on %s %s", method, path)
        return _json(start, "413 Payload Too Large", {"error": "request body too large"})

    creds = _session.get_credentials()
    if creds is None:
        log.error("no credentials available to sign with")
        return _json(start, "500 Internal Server Error", {"error": "signing unavailable"})

    headers = {"Content-Type": "application/json"} if body else {}
    # Carry the verified Cognito subject to the backend. Adding it before add_auth
    # means SigV4 signs it, so it becomes part of SignedHeaders and any downstream
    # attempt to inject or change it invalidates the signature. The value is a
    # Cognito sub (an opaque UUID), never a token, so no credential is forwarded.
    if user_sub:
        headers[CONSOLE_USER_HEADER] = user_sub
    aws_req = AWSRequest(method=method, url=upstream, data=body, headers=headers)
    SigV4Auth(creds.get_frozen_credentials(), SERVICE, REGION).add_auth(aws_req)

    req = urllib.request.Request(  # noqa: S310 (scheme checked by _require_https)
        _require_https(upstream), data=body or None, method=method, headers=dict(aws_req.headers)
    )
    try:
        with _HTTPS_OPENER.open(req, timeout=UPSTREAM_TIMEOUT) as resp:
            payload, status, upstream_headers = resp.read(), resp.status, resp.headers
    except urllib.error.HTTPError as e:
        # Forward 4xx/5xx verbatim: a 400 validation message or a 403 ownership
        # denial is meaningful to the client and must not be flattened to a 502.
        payload, status, upstream_headers = e.read(), e.code, e.headers
    except urllib.error.URLError as e:
        log.error("upstream unreachable: %s", e.reason)
        return _json(start, "502 Bad Gateway", {"error": "upstream unreachable"})

    # Attributable access log: the Cognito sub identifies the user, never the
    # session token.
    log.info("%s %s -> %s sub=%s", method, environ.get("PATH_INFO"), status, user_sub or "-")
    return _forward(start, status, payload, upstream_headers)


def _register(environ, start):
    """POST /auth/register: create a Cognito user who is emailed a temporary password.

    Unauthenticated by necessity, which makes it the most exposed route in this
    tier, so everything cheap happens before anything expensive: method, content
    type, rate limit, body size, then JSON parse, and only then a call that
    reaches Secrets Manager or Cognito.

    The response never contains the submitted invite code, and it is not logged.
    No password is accepted: Cognito emails a temporary one (see
    auth.register_user). The only free text from Cognito that reaches the caller
    is its InvalidParameterException message.
    """
    if environ.get("REQUEST_METHOD") != "POST":
        # 405 rather than an outcome status, because the method is wrong before
        # any registration attempt has been made.
        return _json(
            start,
            "405 Method Not Allowed",
            {"code": auth.REGISTER_BAD_REQUEST, "message": "Use POST."},
            [("Cache-Control", "no-store"), ("Allow", "POST")],
        )

    # A JSON content type cannot be produced by a plain cross-site HTML form
    # (forms can only send urlencoded, multipart or text/plain), so requiring it
    # means a page on another origin cannot silently submit this endpoint on a
    # visitor's behalf. There is no ambient credential to steal here, but a
    # drive-by submission would still consume rate-limit budget and create
    # accounts, so the check is worth its two lines.
    ctype = environ.get("CONTENT_TYPE", "").split(";")[0].strip().lower()
    if ctype != "application/json":
        return _json(
            start,
            "415 Unsupported Media Type",
            {"code": auth.REGISTER_BAD_REQUEST, "message": "Send application/json."},
            [("Cache-Control", "no-store")],
        )

    client = _client_ip(environ)
    if _register_rate_limited(client):
        # The client identifier is not logged: it is an IP address, and the
        # outcome plus the route is enough to see the pattern in a log.
        log.warning("invite rate limited")
        return _register_reply(
            start,
            auth.REGISTER_RATE_LIMITED,
            "Too many attempts. Try again later.",
            [("Retry-After", str(REGISTER_WINDOW_SECONDS))],
        )

    raw = environ["wsgi.input"].read(REGISTER_MAX_BODY_BYTES + 1)
    if len(raw) > REGISTER_MAX_BODY_BYTES:
        return _json(
            start,
            "413 Payload Too Large",
            {"code": auth.REGISTER_BAD_REQUEST, "message": "Request body too large."},
            [("Cache-Control", "no-store")],
        )

    try:
        payload = json.loads(raw or b"{}")
    except ValueError:
        # The body is never echoed back or logged: it can hold an invite code.
        payload = None
    if not isinstance(payload, dict):
        return _register_reply(start, auth.REGISTER_BAD_REQUEST, "Send a JSON object.")

    outcome, message = auth.register_user(payload.get("email"), payload.get("inviteCode"))
    return _register_reply(start, outcome, message)


def _redirect(start_response, location: str, extra_headers=None):
    headers = [("Location", location), ("Content-Length", "0"), ("Cache-Control", "no-store")]
    headers.extend(extra_headers or [])
    start_response("302 Found", headers)
    return [b""]


def application(environ, start_response):
    # Every response, without exception, carries the security headers. Wrapping
    # here rather than in each branch means redirects, errors, the SPA shell and
    # the /api proxy responses are all covered.
    start_response = _with_security_headers(start_response)
    path = environ.get("PATH_INFO", "/")

    # Health probe. Deliberately does not call the API: the UI being up is a
    # separate concern from the API being up. Unauthenticated because a probe
    # cannot present a session cookie. See _is_public_path for the rest of the
    # unauthenticated surface.
    if path in ("/healthz", "/health"):
        return _json(start_response, "200 OK", {"status": "ok"})

    # Authentication configuration is mandatory. Serving the app when it cannot
    # be loaded would turn a misconfigured deploy into an open proxy for Bedrock,
    # so this fails closed instead.
    try:
        auth.config()
    except Exception as exc:  # noqa: BLE001
        # Deliberately broad. Any failure to establish who the caller is must deny
        # the request, and a narrower clause let NoRegionError escape as a 500 with
        # a stack trace page. The reason is logged, never returned.
        log.error("auth unavailable: %s: %s", type(exc).__name__, exc)
        return _json(
            start_response, "503 Service Unavailable", {"error": "authentication is not configured"}
        )

    # Registration. Unauthenticated on purpose: the caller is asking to be
    # given an account, so there is nothing to authenticate them with yet. This
    # sits above the session lookup rather than inside it, and it is the only
    # unauthenticated route that changes state. Registration deliberately does NOT
    # go through Cognito self-registration; see the module docstring in auth.py.
    if path == "/auth/register":
        # In cognito mode Cognito owns sign-up, so the app route does not exist.
        if auth.sign_up_mode(auth.config()) == "cognito":
            return _json(start_response, "404 Not Found", {"error": "not found"})
        return _register(environ, start_response)

    if path == "/auth/signup":
        if auth.sign_up_mode(auth.config()) != "cognito":
            return _json(start_response, "404 Not Found", {"error": "not found"})
        location, headers = auth.signup_redirect(environ)
        return _redirect(start_response, location, headers)

    # Public, read-only: tells the register page whether to ask for an invite code.
    if path == "/auth/config":
        if environ.get("REQUEST_METHOD") not in ("GET", "HEAD"):
            return _json(start_response, "405 Method Not Allowed", {"error": "method not allowed"})
        cfg = auth.config()
        return _json(
            start_response,
            "200 OK",
            {"invite_required": auth.invite_required(cfg), "sign_up_mode": auth.sign_up_mode(cfg)},
            [("Cache-Control", "no-store")],
        )

    if path == "/auth/login":
        location, headers = auth.login_redirect(environ)
        return _redirect(start_response, location, headers)

    if path == "/auth/callback":
        result = auth.handle_callback(environ)
        if result is None:
            # A failed exchange restarts the flow rather than reporting detail:
            # the usual causes are a stale state cookie or a replayed code, and
            # neither is actionable by the user.
            return _redirect(start_response, "/auth/login")
        target, headers = result
        return _redirect(start_response, target, headers)

    if path == "/auth/logout":
        location, headers = auth.logout_redirect()
        return _redirect(start_response, location, headers)

    # The registration pages and the bundles they load, served without a session.
    # Placed above the session lookup so an anonymous caller reaches them, and
    # read-only so nothing here can change state.
    #
    # A missing asset 404s rather than falling through to the SPA history
    # fallback. That difference matters: the fallback returns index.html for any
    # unknown path, so applying it here would hand a 200 with HTML to an
    # anonymous caller at any URL they invented, which is exactly the posture the
    # root redirect exists to prevent.
    if _is_public_path(path):
        if environ.get("REQUEST_METHOD") not in ("GET", "HEAD"):
            return _json(start_response, "405 Method Not Allowed", {"error": "method not allowed"})
        if path in _PUBLIC_PAGES:
            # The app shell. The SPA's own router renders the registration or
            # welcome view from the URL.
            return _serve_static("/index.html", start_response)
        if _safe_asset(path) is None:
            return _json(start_response, "404 Not Found", {"error": "not found"})
        return _serve_static(path, start_response)

    user = auth.current_user(environ)

    if path.startswith("/api/") or path == "/api":
        # The SPA fetches these, so a redirect would be opaque to it. A 401 lets
        # the client decide to send the user through the login flow.
        if user is None:
            return _json(start_response, "401 Unauthorized", {"error": "authentication required"})
        return _proxy(environ, start_response, user.get("sub"))

    if environ.get("REQUEST_METHOD") not in ("GET", "HEAD"):
        return _json(start_response, "405 Method Not Allowed", {"error": "method not allowed"})

    if path == "/auth/whoami":
        return (
            _json(start_response, "200 OK", {"email": user.get("email"), "sub": user.get("sub")})
            if user
            else _json(start_response, "401 Unauthorized", {"error": "authentication required"})
        )

    if user is None:
        # Browser navigation, so send the user to the identity provider and
        # remember where they were heading.
        environ["HTTP_X_ORIGINAL_PATH"] = path
        location, headers = auth.login_redirect(environ)
        return _redirect(start_response, location, headers)

    return _serve_static(path, start_response)


app = application
