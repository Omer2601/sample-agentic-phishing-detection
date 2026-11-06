# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Tests for the UI signing proxy: route allowlist, security headers, request
body cap, verified-subject header propagation, and the invite route.

These exercise the parts of wsgi.py that are cheap to test without AWS and
dangerous to get wrong. boto3 and the SigV4 machinery are stubbed so the tests
stay offline while still running the real routing and header logic. auth.py
itself is loaded for real, so the invite outcome constants and the HTTP status
mapping cannot drift apart without a failure here.
"""

from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import re
import secrets
import sys
import types
import urllib.error
import urllib.parse
import urllib.request
from unittest import mock

import pytest

# Secrets Manager ARNs (where an invite code would live), never secret values. An empty
# ARN means sign-up needs no invite code.
INVITE_ARN = "arn:aws:secretsmanager:us-west-2:123456789012:secret:invite-code"
NO_INVITE_ARN = ""

# Every sys.modules key _load_wsgi() replaces. They are restored as soon as wsgi.py
# has imported: the loaded module keeps its own references to the stubs, and the
# rest of the pytest session (moto, backend, eval) must see the real packages.
_STUBBED_MODULES = (
    "boto3",
    "botocore",
    "botocore.auth",
    "botocore.awsrequest",
    "jwt",
    "server",
    "server.auth",
    "server.wsgi",
)


def _load_wsgi():
    """Import wsgi.py with boto3 and botocore stubbed, then restore sys.modules."""
    saved = {name: sys.modules.get(name) for name in _STUBBED_MODULES}
    try:
        return _import_wsgi_with_stubs()
    finally:
        for name, original in saved.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


def _import_wsgi_with_stubs():
    # boto3.Session().get_credentials().get_frozen_credentials()
    frozen = mock.MagicMock()
    creds = mock.MagicMock()
    creds.get_frozen_credentials.return_value = frozen
    session = mock.MagicMock()
    session.get_credentials.return_value = creds
    boto3_stub = types.ModuleType("boto3")
    boto3_stub.Session = mock.MagicMock(return_value=session)
    sys.modules["boto3"] = boto3_stub

    # botocore.auth.SigV4Auth and botocore.awsrequest.AWSRequest
    botocore = types.ModuleType("botocore")
    auth_mod = types.ModuleType("botocore.auth")

    class _SigV4Auth:
        def __init__(self, *a, **k):
            pass

        def add_auth(self, req):
            # Emulate signing: record the signed header names.
            req.headers["Authorization"] = "AWS4-HMAC-SHA256 ..."

    auth_mod.SigV4Auth = _SigV4Auth
    awsrequest_mod = types.ModuleType("botocore.awsrequest")

    class _AWSRequest:
        def __init__(self, method=None, url=None, data=None, headers=None):
            self.method = method
            self.url = url
            self.data = data
            self.headers = dict(headers or {})

    awsrequest_mod.AWSRequest = _AWSRequest
    botocore.auth = auth_mod
    botocore.awsrequest = awsrequest_mod
    sys.modules["botocore"] = botocore
    sys.modules["botocore.auth"] = auth_mod
    sys.modules["botocore.awsrequest"] = awsrequest_mod

    # jwt is only touched at request time, so a stub is enough for import.
    if "jwt" not in sys.modules:
        jwt_stub = types.ModuleType("jwt")
        jwt_stub.decode = mock.MagicMock()
        jwt_stub.PyJWKClient = mock.MagicMock()
        sys.modules["jwt"] = jwt_stub
    elif not hasattr(sys.modules["jwt"], "PyJWKClient"):
        sys.modules["jwt"].PyJWKClient = mock.MagicMock()

    # The `from . import auth` in wsgi.py. The real module is loaded rather than
    # stubbed: the invite route maps auth.INVITE_* outcomes onto HTTP status
    # codes, and a stub would let those two drift apart silently. Individual
    # tests replace the one function they care about.
    server_pkg = types.ModuleType("server")
    server_pkg.__path__ = []  # mark as package
    here = pathlib.Path(__file__).parent
    real_auth_spec = importlib.util.spec_from_file_location("server.auth", here / "auth.py")
    real_auth = importlib.util.module_from_spec(real_auth_spec)
    sys.modules["server"] = server_pkg
    sys.modules["server.auth"] = real_auth
    real_auth_spec.loader.exec_module(real_auth)
    server_pkg.auth = real_auth

    spec = importlib.util.spec_from_file_location("server.wsgi", here / "wsgi.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["server.wsgi"] = module
    spec.loader.exec_module(module)
    module._auth_stub = real_auth
    return module


wsgi = _load_wsgi()


def test_loading_wsgi_leaves_no_stubs_in_sys_modules():
    """The boto3, botocore, jwt and server stubs exist only while wsgi.py imports.

    Leaving them in sys.modules broke every later test in the same session that
    imports the real boto3 (moto raised on boto3.DEFAULT_SESSION).
    """
    assert sys.modules.get("boto3") is not wsgi.boto3
    assert getattr(sys.modules.get("botocore.auth"), "SigV4Auth", None) is not wsgi.SigV4Auth
    assert (
        getattr(sys.modules.get("botocore.awsrequest"), "AWSRequest", None) is not wsgi.AWSRequest
    )
    jwt_now = sys.modules.get("jwt")
    assert jwt_now is None or getattr(jwt_now, "__file__", None), "jwt stub left in sys.modules"
    assert sys.modules.get("server.auth") is not wsgi.auth
    assert sys.modules.get("server.wsgi") is not wsgi
    assert "server" not in sys.modules or getattr(sys.modules["server"], "__file__", None)


def _capture():
    """A start_response capturing status and headers."""
    captured: dict = {}

    def start(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = headers

    return start, captured


# --------------------------------------------------------------------------- #
# Route allowlist
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/health"),
        ("POST", "/scan"),
        ("GET", "/scans/5f0c-11"),
        ("POST", "/batches"),
        ("GET", "/batches"),
        ("GET", "/batches/9d9baee7-16f2"),
        ("GET", "/history"),
        ("GET", "/stats"),
        ("GET", "/stats/export"),
        ("GET", "/feed/phishing"),
    ],
)
def test_allowlisted_routes_are_permitted(method, path):
    assert wsgi._api_route_allowed(method, path) is True


@pytest.mark.parametrize(
    "method,path",
    [
        ("DELETE", "/scan"),
        ("GET", "/scan"),
        ("POST", "/health"),
        ("GET", "/admin"),
        ("GET", "/scans/a/b"),
        ("POST", "/scan/batch"),  # v1 route, gone
        ("GET", "/result/abc"),  # v1 route, gone
        ("GET", "/history/sess-1"),  # v1 route, gone: owner comes from the session
        ("DELETE", "/batches/x"),
    ],
)
def test_non_allowlisted_routes_are_rejected(method, path):
    assert wsgi._api_route_allowed(method, path) is False


def _api_ts_routes() -> list[tuple[str, str]]:
    """Every (method, path) the SPA client in web/src/lib/api.ts can call.

    Derived from the source rather than listed by hand, so a new client call
    that is not allowlisted fails here instead of 404ing in production. Each
    request(...) call contributes its first path literal (template placeholders
    become a sample id, the query string is dropped) with POST when the call
    passes postJson(...) or method "POST". Plain links built from API_PREFIX,
    such as the CSV export, are browser GETs.
    """
    src = (pathlib.Path(__file__).parent.parent / "src" / "lib" / "api.ts").read_text()

    def literal_path(text: str) -> str | None:
        m = re.search(r"[\"`](/[^\"`]*)[\"`]", text)
        if m is None:
            return None
        path = re.sub(r"\$\{[^}]*\}", "abc-123", m.group(1))
        return path.split("?", 1)[0]

    routes: set[tuple[str, str]] = set()
    for m in re.finditer(r"\brequest<", src):
        # Walk to the opening paren of the call, skipping the generic argument.
        i = src.index("(", m.end())
        depth, j = 0, i
        while True:
            ch = src[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        args = src[i + 1 : j]
        path = literal_path(args)
        if path is None:
            continue  # the generic request() definition itself
        method = "POST" if ("postJson(" in args or 'method: "POST"' in args) else "GET"
        routes.add((method, path))
    for m in re.finditer(r"\$\{API_PREFIX\}(/[^`?]*)", src):
        routes.add(("GET", m.group(1)))
    return sorted(routes)


_SPA_ROUTES = _api_ts_routes()


def test_the_api_ts_route_scan_found_the_client_surface():
    # Guards the parser: if it silently found nothing, the test below would pass
    # vacuously. These are routes api.ts is known to call.
    assert ("POST", "/scans/abc-123/retry") in _SPA_ROUTES
    assert ("POST", "/batches/abc-123/retry-failed") in _SPA_ROUTES
    assert ("GET", "/stats/export") in _SPA_ROUTES
    assert len(_SPA_ROUTES) >= 12


def test_report_routes_are_allowlisted_for_get_only():
    assert wsgi._api_route_allowed("GET", "/scans/abc-123/report") is True
    assert wsgi._api_route_allowed("GET", "/batches/abc-123/report") is True
    assert wsgi._api_route_allowed("POST", "/scans/abc-123/report") is False
    assert wsgi._api_route_allowed("GET", "/scans/a/b/report") is False
    assert wsgi._api_route_allowed("GET", "/scans/../report") is False


@pytest.mark.parametrize("method,path", _SPA_ROUTES)
def test_every_route_the_spa_calls_is_allowlisted(method, path):
    assert wsgi._api_route_allowed(method, path) is True


def test_proxy_rejects_unlisted_route_with_404(monkeypatch):
    monkeypatch.setattr(wsgi, "API_BASE_URL", "https://api.example.com/prod")
    start, cap = _capture()
    environ = {
        "PATH_INFO": "/api/admin",
        "REQUEST_METHOD": "GET",
        "wsgi.input": io.BytesIO(b""),
    }
    wsgi._proxy(environ, start, "sub-1")
    assert cap["status"].startswith("404")


# --------------------------------------------------------------------------- #
# Security headers
# --------------------------------------------------------------------------- #


def test_security_headers_added_to_every_response():
    start, cap = _capture()
    wrapped = wsgi._with_security_headers(start)
    wrapped("200 OK", [("Content-Type", "text/html")])
    keys = {k for k, _ in cap["headers"]}
    assert "Content-Security-Policy" in keys
    assert "Strict-Transport-Security" in keys
    assert "X-Content-Type-Options" in keys
    assert "Referrer-Policy" in keys
    assert "X-Frame-Options" in keys


def _parse_csp(header: str) -> dict[str, set[str]]:
    """Parse a CSP header into {directive: {source expression, ...}}.

    Directives are separated by ";" and each one is a name followed by
    whitespace-separated sources. Parsing lets the test below assert on exact
    source sets rather than substrings, which also catches sources it never
    thought to name.
    """
    policy: dict[str, set[str]] = {}
    for part in header.split(";"):
        tokens = part.split()
        if not tokens:
            continue  # trailing or doubled ";"
        policy[tokens[0].lower()] = set(tokens[1:])
    return policy


# The only source expressions allowed on any directive other than style-src.
# Inline and eval keywords and wildcard hosts are deliberately absent, so a
# subset check rejects them.
_SAFE_SOURCES = {"'self'", "'none'", "data:", "blob:", "https:"}

# style-src is the documented exception (see the _CSP comment in wsgi.py): the
# charting library sets style attributes at runtime.
_KEYWORD_EXEMPT = "style-src"


def test_csp_forbids_inline_script():
    policy = _parse_csp(dict(wsgi._SECURITY_HEADERS)["Content-Security-Policy"])
    # The directive set is fixed, so dropping one of them fails here first.
    assert set(policy) == {
        "default-src",
        "script-src",
        "style-src",
        "img-src",
        "font-src",
        "connect-src",
        "object-src",
        "base-uri",
        "form-action",
        "frame-ancestors",
    }
    # Exact sets, not substrings: any extra source on these directives fails,
    # whether it is an inline or eval keyword, a wildcard, or a foreign host.
    assert policy["script-src"] == {"'self'"}
    assert policy["default-src"] == {"'self'"}
    assert policy["connect-src"] == {"'self'"}
    assert policy["base-uri"] == {"'self'"}
    assert policy["form-action"] == {"'self'"}
    assert policy["object-src"] == {"'none'"}
    assert policy["frame-ancestors"] == {"'none'"}
    # Everything except the exempt directive may only draw on the safe sources,
    # so a keyword smuggled onto img-src or font-src fails too.
    for directive, sources in policy.items():
        if directive == _KEYWORD_EXEMPT:
            continue
        assert sources <= _SAFE_SOURCES, directive
    assert "'self'" in policy[_KEYWORD_EXEMPT]  # still same-origin based


def test_security_wrapper_does_not_duplicate_existing_header():
    start, cap = _capture()
    wrapped = wsgi._with_security_headers(start)
    wrapped("200 OK", [("X-Frame-Options", "SAMEORIGIN")])
    xfo = [v for k, v in cap["headers"] if k == "X-Frame-Options"]
    assert xfo == ["SAMEORIGIN"]


# --------------------------------------------------------------------------- #
# Body size cap
# --------------------------------------------------------------------------- #


def test_oversized_body_is_rejected_with_413(monkeypatch):
    monkeypatch.setattr(wsgi, "MAX_BODY_BYTES", 16)
    monkeypatch.setattr(wsgi, "API_BASE_URL", "https://api.example.com/prod")
    start, cap = _capture()
    environ = {
        "PATH_INFO": "/api/scan",
        "REQUEST_METHOD": "POST",
        "wsgi.input": io.BytesIO(b"x" * 100),
    }
    wsgi._proxy(environ, start, "sub-1")
    assert cap["status"].startswith("413")


# --------------------------------------------------------------------------- #
# Verified-subject header propagation
# --------------------------------------------------------------------------- #


def test_verified_sub_is_signed_into_request(monkeypatch):
    monkeypatch.setattr(wsgi, "API_BASE_URL", "https://api.example.com/prod")
    sent = {}

    class _Resp:
        status = 200
        headers = {"Content-Type": "application/json"}

        def read(self):
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _fake_urlopen(req, timeout=None):
        sent["headers"] = req.headers
        return _Resp()

    monkeypatch.setattr(wsgi._HTTPS_OPENER, "open", _fake_urlopen)
    start, cap = _capture()
    environ = {
        "PATH_INFO": "/api/scan",
        "REQUEST_METHOD": "POST",
        "QUERY_STRING": "",
        "wsgi.input": io.BytesIO(b'{"url":"https://x.com"}'),
    }
    wsgi._proxy(environ, start, "the-sub")
    # The header must be present and carry the verified subject. Because it was
    # added before add_auth, it is part of the signed request.
    header_keys = {k.lower() for k in sent["headers"]}
    assert wsgi.CONSOLE_USER_HEADER.lower() in header_keys
    value = next(
        v for k, v in sent["headers"].items() if k.lower() == wsgi.CONSOLE_USER_HEADER.lower()
    )
    assert value == "the-sub"
    assert "Authorization" in sent["headers"]  # signing ran


# --------------------------------------------------------------------------- #
# Invite route
# --------------------------------------------------------------------------- #

auth = wsgi.auth


def _reset_rate_limiter():
    wsgi._register_attempts.clear()
    wsgi._register_window.clear()


@pytest.fixture(autouse=True)
def _clean_rate_limiter():
    """Rate-limit state is process wide, so it is cleared around every test."""
    _reset_rate_limiter()
    yield
    _reset_rate_limiter()


def _invite_env(body: bytes, ctype: str = "application/json", method: str = "POST", **extra):
    environ = {
        "PATH_INFO": "/auth/register",
        "REQUEST_METHOD": method,
        "CONTENT_TYPE": ctype,
        "QUERY_STRING": "",
        "wsgi.input": io.BytesIO(body),
        "REMOTE_ADDR": "10.0.0.1",
    }
    environ.update(extra)
    return environ


def _post_invite(monkeypatch, payload, outcome=None, message="", **env_extra):
    """Drive wsgi._invite with auth.register_user replaced, and return the response."""
    seen = {}

    def _fake_redeem(email, invite_code):
        seen["args"] = (email, invite_code)
        return outcome, message

    if outcome is not None:
        monkeypatch.setattr(auth, "register_user", _fake_redeem)
    start, cap = _capture()
    body = wsgi._register(_invite_env(json.dumps(payload).encode(), **env_extra), start)
    return cap, json.loads(b"".join(body).decode()), seen


def _fresh_code() -> str:
    """Generated, not a literal: a literal here is what Bandit B105 flags."""
    return secrets.token_hex(16)


def _fresh_password() -> str:
    return secrets.token_urlsafe(12) + "aA1!"


def test_invite_rejects_anything_but_post():
    start, cap = _capture()
    wsgi._register(_invite_env(b"{}", method="GET"), start)
    assert cap["status"].startswith("405")


def test_invite_requires_a_json_content_type():
    """A cross-site HTML form can only send urlencoded, multipart or text/plain."""
    start, cap = _capture()
    wsgi._register(_invite_env(b"email=a", ctype="application/x-www-form-urlencoded"), start)
    assert cap["status"].startswith("415")


def test_invite_rejects_an_oversized_body(monkeypatch):
    monkeypatch.setattr(wsgi, "REGISTER_MAX_BODY_BYTES", 16)
    start, cap = _capture()
    wsgi._register(_invite_env(b"x" * 200), start)
    assert cap["status"].startswith("413")


def test_invite_rejects_a_non_object_body():
    for raw in (b"not json", b"[1,2,3]", b'"a string"'):
        _reset_rate_limiter()
        start, cap = _capture()
        wsgi._register(_invite_env(raw), start)
        assert cap["status"].startswith("400"), raw


def test_invite_responses_are_never_cached():
    start, cap = _capture()
    wsgi._register(_invite_env(b"{}", method="GET"), start)
    assert ("Cache-Control", "no-store") in cap["headers"]


def test_bad_code_is_rejected_with_403_and_never_echoed(monkeypatch):
    code = _fresh_code()
    cap, body, seen = _post_invite(
        monkeypatch,
        {"email": "a@example.com", "inviteCode": code},
        outcome=auth.REGISTER_BAD_CODE,
        message="That invite code is not valid.",
    )
    assert cap["status"].startswith("403")
    # "code" is the field the SPA classifies on, so it is asserted by name.
    assert body["code"] == auth.REGISTER_BAD_CODE
    # The whole serialized response is checked, not just the message field.
    serialized = json.dumps(body)
    assert code not in serialized
    # The route passed the submitted values straight through without altering them.
    assert seen["args"] == ("a@example.com", code)


def test_success_returns_the_next_step_for_the_spa(monkeypatch):
    code = _fresh_code()
    cap, body, _ = _post_invite(
        monkeypatch,
        {"email": "a@example.com", "inviteCode": code},
        outcome=auth.REGISTER_OK,
        message=auth.REGISTER_OK_MESSAGE,
    )
    assert cap["status"].startswith("200")
    assert body["code"] == auth.REGISTER_OK
    # Sign-in stays on Cognito managed login, so the SPA is sent to the redirect
    # route rather than being handed any token.
    assert body["next"] == "/auth/login"
    serialized = json.dumps(body)
    assert code not in serialized


# The wire contract with the SPA, which classifies on the body's "code" field
# first and falls back to the HTTP status: 429 rate limited, 403 invite code
# invalid or missing, 5xx generic. There is deliberately no "already registered"
# outcome: an existing address gets the same 200 as a new one.
@pytest.mark.parametrize(
    "outcome,status",
    [
        ("created", "200"),
        ("invalid_request", "400"),
        ("invalid_invite", "403"),
        ("email_not_allowed", "403"),
        ("rate_limited", "429"),
        ("unavailable", "503"),
    ],
)
def test_every_outcome_maps_to_a_distinct_deliberate_status(outcome, status):
    assert wsgi._register_status(outcome).startswith(status)


def test_an_unknown_outcome_does_not_default_to_success():
    assert wsgi._register_status("something-new").startswith("500")


# INVITE_* string constants in auth.py that are configuration, not outcomes.
_NOT_AN_OUTCOME = {"INVITE_CODE_JSON_KEY", "INVITE_ANY_DOMAIN", "REGISTER_OK_MESSAGE"}


def test_the_outcome_constants_and_the_status_table_agree():
    """Every outcome auth.py can produce has a status chosen for it.

    Without this, adding an outcome in auth.py would fall through to the 500
    default and the SPA would render "unexpected error" for a case that has a real
    state to show.
    """
    outcomes = {
        value
        for name, value in vars(auth).items()
        if name.startswith("REGISTER_") and isinstance(value, str) and name not in _NOT_AN_OUTCOME
    }
    assert len(outcomes) >= 6  # not a vacuous pass if the constants are renamed
    default = wsgi._register_status("definitely-not-an-outcome")
    unmapped = sorted(o for o in outcomes if wsgi._register_status(o) == default)
    assert unmapped == []


def test_every_reply_carries_the_code_field_and_no_result_field():
    """The SPA reads "code". A stray "result" alias would invite drift."""
    for outcome in ("created", "invalid_invite", "rate_limited"):
        start, _ = _capture()
        body = json.loads(b"".join(wsgi._register_reply(start, outcome, "m")).decode())
        assert body["code"] == outcome
        assert "result" not in body
        assert set(body) <= {"code", "message", "next"}


# --------------------------------------------------------------------------- #
# Invite brute-force controls
# --------------------------------------------------------------------------- #


def test_attempts_from_one_client_are_capped(monkeypatch):
    monkeypatch.setattr(wsgi, "REGISTER_MAX_PER_CLIENT", 3)
    monkeypatch.setattr(wsgi, "REGISTER_MAX_PER_WINDOW", 100)
    assert [wsgi._register_rate_limited("1.2.3.4") for _ in range(5)] == [
        False,
        False,
        False,
        True,
        True,
    ]
    # A different client is unaffected by the first one's budget.
    assert wsgi._register_rate_limited("5.6.7.8") is False


def test_the_window_slides(monkeypatch):
    monkeypatch.setattr(wsgi, "REGISTER_MAX_PER_CLIENT", 2)
    monkeypatch.setattr(wsgi, "REGISTER_WINDOW_SECONDS", 100)
    assert wsgi._register_rate_limited("1.2.3.4", now=0.0) is False
    assert wsgi._register_rate_limited("1.2.3.4", now=1.0) is False
    assert wsgi._register_rate_limited("1.2.3.4", now=2.0) is True
    # Past the window, the budget is back.
    assert wsgi._register_rate_limited("1.2.3.4", now=200.0) is False


def test_a_distributed_attempt_is_bounded_too(monkeypatch):
    """The per-client cap alone would be defeated by rotating the source."""
    monkeypatch.setattr(wsgi, "REGISTER_MAX_PER_CLIENT", 100)
    monkeypatch.setattr(wsgi, "REGISTER_MAX_PER_WINDOW", 4)
    results = [wsgi._register_rate_limited(f"10.0.0.{i}") for i in range(6)]
    assert results == [False, False, False, False, True, True]


def test_tracked_clients_are_bounded_by_eviction_not_by_refusal(monkeypatch):
    """Unbounded bookkeeping would be a memory exhaustion vector of its own.

    Eviction is by least recent activity rather than by refusing new clients,
    because refusing them would let a flood of throwaway identities lock every
    genuine invitee out of registering.
    """
    monkeypatch.setattr(wsgi, "REGISTER_MAX_TRACKED_CLIENTS", 4)
    monkeypatch.setattr(wsgi, "REGISTER_MAX_PER_WINDOW", 10_000)
    for i in range(40):
        assert wsgi._register_rate_limited(f"10.0.{i // 256}.{i % 256}", now=float(i)) is False
    assert len(wsgi._register_attempts) <= 4


def test_the_route_returns_429_with_retry_after_when_limited(monkeypatch):
    monkeypatch.setattr(wsgi, "REGISTER_MAX_PER_CLIENT", 1)
    monkeypatch.setattr(auth, "register_user", lambda *a: (auth.REGISTER_BAD_CODE, "no"))
    payload = json.dumps({"email": "a@example.com", "inviteCode": _fresh_code()}).encode()
    first, cap1 = _capture()
    wsgi._register(_invite_env(payload), first)
    assert cap1["status"].startswith("403")
    second, cap2 = _capture()
    wsgi._register(_invite_env(payload), second)
    assert cap2["status"].startswith("429")
    assert ("Retry-After", str(wsgi.REGISTER_WINDOW_SECONDS)) in cap2["headers"]


@pytest.mark.parametrize(
    "xff,remote,expected",
    [
        # CloudFront appends the viewer IP, then the ALB appends the CloudFront
        # edge IP, so the viewer is second from the right.
        ("203.0.113.7, 130.176.1.1", "10.0.0.5", "203.0.113.7"),
        # A viewer that supplies its own header only pushes its forgery further
        # left; the entry CloudFront added is still second from the right.
        ("9.9.9.9, 203.0.113.7, 130.176.1.1", "10.0.0.5", "203.0.113.7"),
        # Not behind both proxies: use what is there.
        ("203.0.113.7", "10.0.0.5", "203.0.113.7"),
        ("", "10.0.0.5", "10.0.0.5"),
    ],
)
def test_client_ip_ignores_the_spoofable_left_of_the_chain(xff, remote, expected):
    environ = {"HTTP_X_FORWARDED_FOR": xff, "REMOTE_ADDR": remote}
    assert wsgi._client_ip(environ) == expected


# --------------------------------------------------------------------------- #
# Invite routing inside application()
# --------------------------------------------------------------------------- #


def test_invite_is_reachable_without_a_session(monkeypatch):
    """The caller has no account yet, so this route cannot require one.

    It must also not fall through to the browser login redirect, which is what
    would happen if it were placed after the session lookup.
    """
    monkeypatch.setattr(auth, "config", lambda: {})
    monkeypatch.setattr(auth, "current_user", lambda environ: pytest.fail("session was consulted"))
    monkeypatch.setattr(auth, "register_user", lambda *a: (auth.REGISTER_OK, "Account created."))
    start, cap = _capture()
    body = wsgi.application(
        _invite_env(
            json.dumps(
                {
                    "email": "a@example.com",
                    "inviteCode": _fresh_code(),
                }
            ).encode()
        ),
        start,
    )
    assert cap["status"].startswith("200")
    assert json.loads(b"".join(body).decode())["code"] == auth.REGISTER_OK
    # The shared security headers still apply to this route.
    assert "Content-Security-Policy" in {k for k, _ in cap["headers"]}


# --------------------------------------------------------------------------- #
# The unauthenticated surface
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "path",
    [
        "/register",
        "/welcome",
        "/assets/index-a1b2c3d4.js",
        "/assets/index-a1b2c3d4.css",
        "/shield.svg",
        "/favicon.ico",
        "/robots.txt",
    ],
)
def test_public_paths_are_public(path):
    assert wsgi._is_public_path(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "/",  # the root must keep redirecting to Cognito
        "/index.html",
        "/scan",
        "/history",
        "/api/scan",
        "/auth/whoami",
        "/register/",  # trailing slash is a different path
        "/registers",
        "/welcome/secret",
        "/assets",  # the directory itself
        "/assets/",
        "/assets/nested/app.js",  # one segment only
        "/assets/../index.html",  # traversal shape
        "/assets/../../etc/passwd",
        # These two are the ones a looser pattern lets through: both are a single
        # path segment, and _safe_asset normalises them back to index.html, which
        # would serve the app shell to an anonymous caller at an invented URL.
        "/assets/..",
        "/assets/.",
        "/assets/.hidden",
        "/assets/-dash",
    ],
)
def test_everything_else_stays_private(path):
    assert wsgi._is_public_path(path) is False


def test_a_relative_asset_segment_does_not_serve_the_shell(monkeypatch, tmp_path):
    """Regression guard for the case above, driven end to end.

    /assets/.. is one path segment, so a permissive pattern matches it, and
    posixpath.normpath turns "assets/.." into "." which _safe_asset then resolves
    to index.html. An anonymous caller must be redirected, not handed the shell.
    """
    (tmp_path / "index.html").write_text("<!doctype html><div id=root></div>")
    monkeypatch.setattr(wsgi, "DIST", tmp_path)
    _configure_anonymous(monkeypatch)
    monkeypatch.setattr(
        auth,
        "login_redirect",
        lambda environ: ("https://x.auth.us-west-2.amazoncognito.com/oauth2/authorize", []),
    )
    for path in ("/assets/..", "/assets/.", "/assets/../index.html"):
        start, cap = _capture()
        body = wsgi.application(_anonymous(path), start)
        assert cap["status"].startswith("302"), path
        assert b"id=root" not in b"".join(body), path


def _anonymous(path, method="GET"):
    return {
        "PATH_INFO": path,
        "REQUEST_METHOD": method,
        "QUERY_STRING": "",
        "wsgi.input": io.BytesIO(b""),
    }


def _configure_anonymous(monkeypatch):
    """A working auth config with no session, which is the invitee's state."""
    monkeypatch.setattr(auth, "config", lambda: {})
    monkeypatch.setattr(auth, "current_user", lambda environ: None)


@pytest.mark.parametrize("path", ["/register", "/welcome"])
def test_the_registration_pages_render_for_an_anonymous_caller(monkeypatch, path, tmp_path):
    """The blocker: without this the registration page can never be seen.

    An invitee has no account, so the session check would bounce them to Cognito,
    where they have nothing to sign in with.
    """
    (tmp_path / "index.html").write_text("<!doctype html><div id=root></div>")
    monkeypatch.setattr(wsgi, "DIST", tmp_path)
    _configure_anonymous(monkeypatch)
    monkeypatch.setattr(
        auth, "login_redirect", lambda environ: pytest.fail("was redirected to Cognito")
    )
    start, cap = _capture()
    body = wsgi.application(_anonymous(path), start)
    assert cap["status"].startswith("200")
    assert b"id=root" in b"".join(body)
    assert dict(cap["headers"])["Content-Type"] == "text/html"
    # The shell must never be cached, or a deploy keeps serving the old app.
    assert dict(cap["headers"])["Cache-Control"] == "no-cache"


def test_hashed_bundles_are_served_to_an_anonymous_caller(monkeypatch, tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "index-abc123.js").write_text("console.log(1)")
    monkeypatch.setattr(wsgi, "DIST", tmp_path)
    _configure_anonymous(monkeypatch)
    start, cap = _capture()
    body = wsgi.application(_anonymous("/assets/index-abc123.js"), start)
    assert cap["status"].startswith("200")
    assert b"console.log" in b"".join(body)


def test_a_missing_public_asset_404s_rather_than_serving_the_shell(monkeypatch, tmp_path):
    """The SPA history fallback must not apply to the anonymous surface.

    If it did, any invented URL matching the asset pattern would hand an
    anonymous caller a 200 with HTML, which is the posture the root redirect
    exists to prevent.
    """
    (tmp_path / "index.html").write_text("<!doctype html><div id=root></div>")
    monkeypatch.setattr(wsgi, "DIST", tmp_path)
    _configure_anonymous(monkeypatch)
    start, cap = _capture()
    body = wsgi.application(_anonymous("/assets/does-not-exist.js"), start)
    assert cap["status"].startswith("404")
    assert b"id=root" not in b"".join(body)


def test_the_root_still_redirects_an_anonymous_caller_to_cognito(monkeypatch):
    """The property the whole design protects: never a 200 with content at "/"."""
    _configure_anonymous(monkeypatch)
    monkeypatch.setattr(
        auth,
        "login_redirect",
        lambda environ: ("https://x.auth.us-west-2.amazoncognito.com/oauth2/authorize", []),
    )
    start, cap = _capture()
    wsgi.application(_anonymous("/"), start)
    assert cap["status"].startswith("302")
    assert (
        dict(cap["headers"])["Location"]
        == "https://x.auth.us-west-2.amazoncognito.com/oauth2/authorize"
    )


def test_an_authenticated_spa_route_is_still_gated(monkeypatch):
    """A page that is not on the allowlist keeps the session requirement."""
    _configure_anonymous(monkeypatch)
    monkeypatch.setattr(
        auth,
        "login_redirect",
        lambda environ: ("https://x.auth.us-west-2.amazoncognito.com/oauth2/authorize", []),
    )
    start, cap = _capture()
    wsgi.application(_anonymous("/history"), start)
    assert cap["status"].startswith("302")


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_the_public_pages_are_read_only(monkeypatch, method):
    _configure_anonymous(monkeypatch)
    start, cap = _capture()
    wsgi.application(_anonymous("/register", method=method), start)
    assert cap["status"].startswith("405")


def test_invite_still_fails_closed_when_auth_config_is_broken(monkeypatch):
    def _boom():
        raise RuntimeError("no ssm")

    monkeypatch.setattr(auth, "config", _boom)
    start, cap = _capture()
    wsgi.application(_invite_env(b"{}"), start)
    assert cap["status"].startswith("503")


def test_no_sub_means_no_identity_header(monkeypatch):
    monkeypatch.setattr(wsgi, "API_BASE_URL", "https://api.example.com/prod")
    sent = {}

    class _Resp:
        status = 200
        headers = {"Content-Type": "application/json"}

        def read(self):
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(
        wsgi._HTTPS_OPENER,
        "open",
        lambda req, timeout=None: sent.update(headers=req.headers) or _Resp(),
    )
    start, cap = _capture()
    environ = {
        "PATH_INFO": "/api/health",
        "REQUEST_METHOD": "GET",
        "QUERY_STRING": "",
        "wsgi.input": io.BytesIO(b""),
    }
    wsgi._proxy(environ, start, None)
    header_keys = {k.lower() for k in sent["headers"]}
    assert wsgi.CONSOLE_USER_HEADER.lower() not in header_keys


# --------------------------------------------------------------------------- #
# v2: optional invite, config route, CSV pass-through, upload CSP
# --------------------------------------------------------------------------- #


def test_invite_is_required_only_when_a_secret_is_configured():
    assert auth.invite_required({"invite_secret_arn": INVITE_ARN}) is True
    assert auth.invite_required({"invite_secret_arn": NO_INVITE_ARN}) is False
    assert auth.invite_required({}) is False


class _FakeIdp:
    """Records admin_create_user kwargs; raises UsernameExistsException for known users."""

    def __init__(self, existing=()):
        self.calls: list[dict] = []
        self.existing = set(existing)

    def admin_create_user(self, **kw):
        self.calls.append(kw)
        if kw["Username"] in self.existing:
            raise type("UsernameExistsException", (Exception,), {})("exists")
        self.existing.add(kw["Username"])
        return {}

    def admin_set_user_password(self, **kw):  # pragma: no cover - must never run
        pytest.fail("admin_set_user_password must not be called")


def _use_fake_idp(monkeypatch, idp, invite_secret_arn=NO_INVITE_ARN):
    monkeypatch.setattr(
        auth,
        "config",
        lambda: {
            "invite_secret_arn": invite_secret_arn,
            "invite_allowed_email_domains": "*",
            "user_pool_id": "pool-1",
            "region": "us-west-2",
        },
    )
    # boto3 is a stub module here (see _load_wsgi), so "client" may not exist yet.
    monkeypatch.setattr(auth.boto3, "client", lambda *a, **k: idp, raising=False)


def test_register_without_invite_skips_the_code_check(monkeypatch):
    idp = _FakeIdp()
    _use_fake_idp(monkeypatch, idp)
    monkeypatch.setattr(auth, "_invite_code", lambda cfg: pytest.fail("invite code was consulted"))
    outcome, _ = auth.register_user("new@example.com", None)
    assert outcome == auth.REGISTER_OK
    assert idp.calls[0]["Username"] == "new@example.com"


def test_register_has_cognito_email_a_temporary_password(monkeypatch):
    """Cognito generates and emails the temporary password: first sign-in proves
    the inbox is the caller's, and managed login then forces a new password."""
    idp = _FakeIdp()
    _use_fake_idp(monkeypatch, idp)
    auth.register_user("New@Example.com ", None)
    assert idp.calls == [
        {
            "UserPoolId": "pool-1",
            "Username": "new@example.com",
            "UserAttributes": [
                {"Name": "email", "Value": "new@example.com"},
                {"Name": "email_verified", "Value": "true"},
            ],
            "DesiredDeliveryMediums": ["EMAIL"],
        }
    ]


def _register_over_http(email, invite_code=None):
    payload = {"email": email}
    if invite_code is not None:
        payload["inviteCode"] = invite_code
    start, cap = _capture()
    body = wsgi._register(_invite_env(json.dumps(payload).encode()), start)
    return cap["status"], dict(cap["headers"]), json.loads(b"".join(body))


@pytest.mark.parametrize("invite", [False, True])
def test_new_and_existing_addresses_get_the_identical_response(monkeypatch, invite):
    """No user-existence oracle: an existing address is indistinguishable from a new one."""
    code = _fresh_code()
    idp = _FakeIdp(existing={"taken@example.com"})
    _use_fake_idp(monkeypatch, idp, invite_secret_arn=INVITE_ARN if invite else NO_INVITE_ARN)
    monkeypatch.setattr(auth, "_invite_code", lambda cfg: code)
    submitted = code if invite else None
    new = _register_over_http("fresh@example.com", submitted)
    existing = _register_over_http("taken@example.com", submitted)
    assert new == existing
    assert new[0].startswith("200")
    assert new[2]["code"] == auth.REGISTER_OK
    assert "temporary password" in new[2]["message"]
    assert len(idp.calls) == 2
    assert all("TemporaryPassword" not in c and "MessageAction" not in c for c in idp.calls)


def test_a_submitted_password_is_ignored(monkeypatch):
    idp = _FakeIdp()
    _use_fake_idp(monkeypatch, idp)
    start, cap = _capture()
    wsgi._register(
        _invite_env(json.dumps({"email": "a@example.com", "password": _fresh_password()}).encode()),
        start,
    )
    assert cap["status"].startswith("200")
    assert "TemporaryPassword" not in idp.calls[0]


def test_register_with_invite_still_rejects_a_bad_code(monkeypatch):
    monkeypatch.setattr(
        auth,
        "config",
        lambda: {
            "invite_secret_arn": INVITE_ARN,
            "invite_allowed_email_domains": "*",
            "user_pool_id": "p",
            "region": "us-west-2",
        },
    )
    monkeypatch.setattr(auth, "_invite_code", lambda cfg: "the-real-code")
    outcome, _ = auth.register_user("a@example.com", "wrong")
    assert outcome == auth.REGISTER_BAD_CODE


def test_auth_config_is_public_and_reports_the_invite_mode(monkeypatch):
    monkeypatch.setattr(auth, "config", lambda: {"invite_secret_arn": NO_INVITE_ARN})
    monkeypatch.setattr(auth, "current_user", lambda environ: pytest.fail("session was consulted"))
    start, cap = _capture()
    body = wsgi.application({"PATH_INFO": "/auth/config", "REQUEST_METHOD": "GET"}, start)
    assert cap["status"].startswith("200")
    assert json.loads(b"".join(body)) == {"invite_required": False, "sign_up_mode": "app"}
    assert ("Cache-Control", "no-store") in cap["headers"]


def test_auth_config_fails_closed(monkeypatch):
    def _broken():
        raise RuntimeError("no ssm")

    monkeypatch.setattr(auth, "config", _broken)
    start, cap = _capture()
    wsgi.application({"PATH_INFO": "/auth/config", "REQUEST_METHOD": "GET"}, start)
    assert cap["status"].startswith("503")


def test_csv_export_keeps_its_content_type_and_filename(monkeypatch):
    monkeypatch.setattr(wsgi, "API_BASE_URL", "https://api.example.com/prod")

    class _Resp:
        status = 200
        headers = {
            "Content-Type": "text/csv",
            "Content-Disposition": 'attachment; filename="phish-stats-7d.csv"',
        }

        def read(self):
            return b"scan_id\n"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(wsgi._HTTPS_OPENER, "open", lambda req, timeout=None: _Resp())
    start, cap = _capture()
    wsgi._proxy(
        {
            "PATH_INFO": "/api/stats/export",
            "REQUEST_METHOD": "GET",
            "QUERY_STRING": "range=7d",
            "wsgi.input": io.BytesIO(b""),
        },
        start,
        "sub-1",
    )
    headers = dict(cap["headers"])
    assert headers["Content-Type"] == "text/csv"
    assert headers["Content-Disposition"] == 'attachment; filename="phish-stats-7d.csv"'


def test_unexpected_upstream_content_type_is_forced_to_json(monkeypatch):
    monkeypatch.setattr(wsgi, "API_BASE_URL", "https://api.example.com/prod")

    class _Resp:
        status = 200
        headers = {"Content-Type": "text/html", "Content-Disposition": "inline; filename=x.html"}

        def read(self):
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(wsgi._HTTPS_OPENER, "open", lambda req, timeout=None: _Resp())
    start, cap = _capture()
    wsgi._proxy(
        {
            "PATH_INFO": "/api/history",
            "REQUEST_METHOD": "GET",
            "QUERY_STRING": "",
            "wsgi.input": io.BytesIO(b""),
        },
        start,
        "s",
    )
    headers = dict(cap["headers"])
    assert headers["Content-Type"] == "application/json"
    assert "Content-Disposition" not in headers


def test_csp_allows_the_upload_bucket_origin_only():
    csp = wsgi.build_csp("https://phish-uploads-123456789012-us-west-2.s3.us-west-2.amazonaws.com")
    assert (
        "connect-src 'self' https://phish-uploads-123456789012-us-west-2.s3.us-west-2.amazonaws.com;"
        in csp
    )
    # interfaces.md: the upload origin is added to form-action as well.
    assert (
        "form-action 'self' https://phish-uploads-123456789012-us-west-2.s3.us-west-2.amazonaws.com;"
        in csp
    )
    assert "form-action 'self';" in wsgi.build_csp("")
    assert "connect-src 'self';" in wsgi.build_csp("")
    # Anything that is not an S3 https origin is ignored rather than trusted.
    assert "evil" not in wsgi.build_csp("https://evil.example.com")
    assert "connect-src 'self';" in wsgi.build_csp("https://x.s3.amazonaws.com/path")


# v2: sign-up mode


def test_auth_config_reports_cognito_sign_up_mode(monkeypatch):
    monkeypatch.setattr(
        auth, "config", lambda: {"invite_secret_arn": NO_INVITE_ARN, "sign_up_mode": "cognito"}
    )
    start, cap = _capture()
    body = wsgi.application({"PATH_INFO": "/auth/config", "REQUEST_METHOD": "GET"}, start)
    assert json.loads(b"".join(body)) == {"invite_required": False, "sign_up_mode": "cognito"}


def test_register_route_is_closed_in_cognito_mode(monkeypatch):
    monkeypatch.setattr(
        auth, "config", lambda: {"invite_secret_arn": NO_INVITE_ARN, "sign_up_mode": "cognito"}
    )
    start, cap = _capture()
    wsgi.application(
        {
            "PATH_INFO": "/auth/register",
            "REQUEST_METHOD": "POST",
            "CONTENT_LENGTH": "2",
            "wsgi.input": io.BytesIO(b"{}"),
        },
        start,
    )
    assert cap["status"].startswith("404")


def test_sign_up_mode_defaults_to_app():
    assert auth.sign_up_mode({}) == "app"
    assert auth.sign_up_mode({"sign_up_mode": "bogus"}) == "app"
    assert auth.sign_up_mode({"sign_up_mode": "cognito"}) == "cognito"


def _signup_cfg(mode: str) -> dict:
    return {
        "invite_secret_arn": NO_INVITE_ARN,
        "sign_up_mode": mode,
        "client_id": "client-1",
        "domain": "https://auth.example.com",
        "base_url": "https://app.example.com",
        "cookie_key": b"k" * 32,
    }


def test_signup_redirects_to_cognito_signup_with_state_and_pkce(monkeypatch):
    monkeypatch.setattr(auth, "config", lambda: _signup_cfg("cognito"))
    start, cap = _capture()
    wsgi.application(
        {"PATH_INFO": "/auth/signup", "REQUEST_METHOD": "GET", "QUERY_STRING": ""}, start
    )
    assert cap["status"].startswith("302")
    headers = cap["headers"]
    location = dict(headers)["Location"]
    assert location.startswith("https://auth.example.com/signup?")
    query = wsgi.urllib.parse.parse_qs(wsgi.urllib.parse.urlsplit(location).query)
    assert query["client_id"] == ["client-1"]
    assert query["response_type"] == ["code"]
    assert query["redirect_uri"] == ["https://app.example.com/auth/callback"]
    # The callback only accepts a code that round-trips the signed state cookie.
    assert query["state"] and query["code_challenge"]
    assert any(k == "Set-Cookie" and v.startswith(auth.STATE_COOKIE) for k, v in headers)


def test_signup_is_not_offered_in_app_mode(monkeypatch):
    monkeypatch.setattr(auth, "config", lambda: _signup_cfg("app"))
    start, cap = _capture()
    wsgi.application(
        {"PATH_INFO": "/auth/signup", "REQUEST_METHOD": "GET", "QUERY_STRING": ""}, start
    )
    assert cap["status"].startswith("404")


def test_config_loader_reads_sign_up_mode_from_ssm(monkeypatch):
    names_seen = []

    class _Client:
        def get_parameters(self, Names):
            names_seen.extend(Names)
            values = {
                "user_pool_id": "pool",
                "client_id": "c",
                "cognito_domain": "https://d",
                "public_base_url": "https://b",
                "sign_up_mode": "cognito",
            }
            return {
                "Parameters": [
                    {"Name": n, "Value": values[n.rsplit("/", 1)[-1]]}
                    for n in Names
                    if n.rsplit("/", 1)[-1] in values
                ]
            }

        def describe_user_pool_client(self, **kw):
            return {"UserPoolClient": {"ClientSecret": "s3cr3t"}}

    monkeypatch.setattr(auth, "AUTH_SSM_PREFIX", "/phish/dev/auth")
    monkeypatch.setattr(auth, "_config", None)
    monkeypatch.setattr(auth, "PyJWKClient", lambda *a, **k: object())
    monkeypatch.setattr(auth.boto3, "client", lambda *a, **k: _Client(), raising=False)
    cfg = auth.config()
    assert "/phish/dev/auth/sign_up_mode" in names_seen
    assert auth.sign_up_mode(cfg) == "cognito"


# --------------------------------------------------------------------------- #
# Sign out
# --------------------------------------------------------------------------- #

_LOGOUT_CFG = {
    "client_id": "client-123",
    "domain": "https://pg.auth.us-west-2.amazoncognito.com",
    "base_url": "https://d111.cloudfront.net",
}


def _logout(monkeypatch, cookie=""):
    monkeypatch.setattr(auth, "config", lambda: dict(_LOGOUT_CFG))
    # Sign out must work for a caller whose session has already expired, so the
    # route is not allowed to depend on one.
    monkeypatch.setattr(auth, "current_user", lambda environ: pytest.fail("session was consulted"))
    env = _anonymous("/auth/logout")
    if cookie:
        env["HTTP_COOKIE"] = cookie
    start, cap = _capture()
    wsgi.application(env, start)
    return cap


def test_logout_redirects_to_cognito_hosted_logout(monkeypatch):
    cap = _logout(monkeypatch, cookie=f"{auth.SESSION_COOKIE}=tok")
    assert cap["status"].startswith("302")
    location = dict(cap["headers"])["Location"]
    parsed = urllib.parse.urlparse(location)
    assert f"{parsed.scheme}://{parsed.netloc}" == _LOGOUT_CFG["domain"]
    assert parsed.path == "/logout"
    query = urllib.parse.parse_qs(parsed.query)
    assert query["client_id"] == ["client-123"]
    # Must match the LogoutURLs entry on the app client exactly, or Cognito
    # refuses the redirect (see infra/tests/test_auth.py).
    assert query["logout_uri"] == ["https://d111.cloudfront.net/"]


def test_logout_expires_the_session_and_state_cookies(monkeypatch):
    cap = _logout(monkeypatch, cookie=f"{auth.SESSION_COOKIE}=tok")
    cookies = [v for k, v in cap["headers"] if k == "Set-Cookie"]
    for name in (auth.SESSION_COOKIE, auth.STATE_COOKIE):
        (cleared,) = [c for c in cookies if c.startswith(f"{name}=")]
        assert cleared.startswith(f"{name}=;")
        assert "Max-Age=0" in cleared
        # The __Host- prefix is only honoured with these attributes, so a
        # clearing cookie without them would be dropped and the session kept.
        assert "Path=/" in cleared and "Secure" in cleared
        assert "Domain=" not in cleared


def test_logout_is_never_cached(monkeypatch):
    cap = _logout(monkeypatch)
    assert "no-store" in dict(cap["headers"]).get("Cache-Control", "")


def test_config_loader_treats_invalid_optional_parameters_as_absent(monkeypatch):
    # inviteCode=false: invite_secret_arn does not exist, and SSM reports it in
    # InvalidParameters. The console must still load, with the invite route off.
    class _Client:
        def get_parameters(self, Names):
            values = {
                "user_pool_id": "pool",
                "client_id": "c",
                "cognito_domain": "https://d",
                "public_base_url": "https://b",
            }
            return {
                "Parameters": [
                    {"Name": n, "Value": values[n.rsplit("/", 1)[-1]]}
                    for n in Names
                    if n.rsplit("/", 1)[-1] in values
                ],
                "InvalidParameters": [n for n in Names if n.rsplit("/", 1)[-1] not in values],
            }

        def describe_user_pool_client(self, **kw):
            return {"UserPoolClient": {"ClientSecret": "s3cr3t"}}

    monkeypatch.setattr(auth, "AUTH_SSM_PREFIX", "/phish/dev/auth")
    monkeypatch.setattr(auth, "_config", None)
    monkeypatch.setattr(auth, "PyJWKClient", lambda *a, **k: object())
    monkeypatch.setattr(auth.boto3, "client", lambda *a, **k: _Client(), raising=False)
    cfg = auth.config()
    assert cfg["invite_secret_arn"] == ""
    assert auth.sign_up_mode(cfg) == "app"


NON_HTTPS_URLS = [
    "file:///etc/passwd",
    "ftp://example.com/prod",
    "http://example.com/prod",
]


@pytest.mark.parametrize("module", [wsgi, auth], ids=["wsgi", "auth"])
@pytest.mark.parametrize("url", NON_HTTPS_URLS)
def test_outbound_calls_refuse_non_https_urls(module, url):
    """Both outbound call sites (API proxy and token exchange) are https-only, twice:
    _require_https refuses the URL, and the opener has no handler that could open it."""
    with pytest.raises(ValueError, match="refusing non-https scheme"):
        module._require_https(url)
    with pytest.raises(urllib.error.URLError, match="unknown url type"):
        module._HTTPS_OPENER.open(urllib.request.Request(url), timeout=1)  # noqa: S310


def test_proxy_refuses_a_non_https_upstream(monkeypatch):
    monkeypatch.setattr(wsgi, "API_BASE_URL", "http://api.example.com/prod")
    start, _cap = _capture()
    environ = {
        "PATH_INFO": "/api/health",
        "REQUEST_METHOD": "GET",
        "QUERY_STRING": "",
        "wsgi.input": io.BytesIO(b""),
    }
    with pytest.raises(ValueError, match="refusing non-https scheme"):
        wsgi._proxy(environ, start, "sub-1")
