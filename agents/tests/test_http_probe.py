# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The plain HTTP probe precheck_url falls back to when the browser cannot answer."""

import socket

import httpcore
import httpx
import pytest

from phish_agents.common import http_probe, url_safety

pytestmark = pytest.mark.usefixtures("public_dns")


def transport(routes: dict, seen: list | None = None):
    """routes: url -> (status, headers) or an exception to raise."""

    # stream=, as from a socket: the probe reads raw bytes, and content= is pre-read.
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(str(request.url))
        outcome = routes[str(request.url)]
        if isinstance(outcome, Exception):
            raise outcome
        status, headers = outcome
        return httpx.Response(status, headers=headers, stream=httpx.ByteStream(b"x" * 200_000))

    return httpx.MockTransport(handler)


async def probe(url, routes, seen=None, **kw):
    return await http_probe.http_probe(url, transport=transport(routes, seen), **kw)


async def test_reachable_page_is_ok_with_hops():
    out = await probe(
        "http://a.example/",
        {
            "http://a.example/": (301, {"location": "https://b.example/login"}),
            "https://b.example/login": (200, {}),
        },
    )
    assert out["outcome"] == "ok" and out["final_status"] == 200
    assert out["final_url"] == "https://b.example/login"
    assert out["hops"] == ["http://a.example/", "https://b.example/login"]


async def test_final_404_is_error_404():
    out = await probe("https://a.example/x", {"https://a.example/x": (404, {})})
    assert out["outcome"] == "error_404" and out["final_status"] == 404


async def test_410_is_site_down():
    out = await probe("https://a.example/x", {"https://a.example/x": (410, {})})
    assert out["outcome"] == "site_down" and "410" in out["reason"]


@pytest.mark.parametrize("status", [403, 429, 500])
async def test_other_statuses_are_reachable(status):
    out = await probe("https://a.example/", {"https://a.example/": (status, {})})
    assert out["outcome"] == "ok" and out["final_status"] == status


async def test_connection_refused_is_site_down():
    req = httpx.Request("GET", "https://a.example/")
    out = await probe(
        "https://a.example/", {"https://a.example/": httpx.ConnectError("refused", request=req)}
    )
    assert out["outcome"] == "site_down" and "connect" in out["reason"].lower()


async def test_tls_failure_is_inconclusive_not_site_down():
    req = httpx.Request("GET", "https://a.example/")
    err = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate expired", request=req)
    out = await probe("https://a.example/", {"https://a.example/": err})
    assert out["outcome"] == "unreachable"


async def test_tls_failure_is_inconclusive_whatever_the_message_says():
    # The ssl error in the chain decides, not the wording of the wrapper's message.
    import ssl

    req = httpx.Request("GET", "https://a.example/")
    err = httpx.ConnectError("handshake did not complete", request=req)
    err.__cause__ = ssl.SSLCertVerificationError("hostname mismatch")
    out = await probe("https://a.example/", {"https://a.example/": err})
    assert out["outcome"] == "unreachable" and "TLS" in out["reason"]


async def test_redirect_to_a_host_that_does_not_resolve_is_site_down(monkeypatch):
    real = url_safety.socket.getaddrinfo

    def dns(host, *a, **k):
        if host == "dead.example":
            raise socket.gaierror(socket.EAI_NONAME, "nodename nor servname provided")
        return real(host, *a, **k)

    monkeypatch.setattr(url_safety.socket, "getaddrinfo", dns)
    seen: list = []
    out = await probe(
        "https://a.example/",
        {"https://a.example/": (302, {"location": "https://dead.example/p"})},
        seen,
    )
    assert out["outcome"] == "site_down" and "dead.example" in out["reason"]
    assert out["hops"] == ["https://a.example/", "https://dead.example/p"]
    assert seen == ["https://a.example/"]


async def test_every_hop_is_guarded():
    seen: list = []
    out = await probe(
        "https://a.example/",
        {"https://a.example/": (302, {"location": "http://169.254.169.254/latest"})},
        seen,
    )
    assert out["outcome"] == "blocked"
    assert seen == ["https://a.example/"]


async def test_redirects_are_capped_at_five():
    routes = {f"https://a.example/{i}": (302, {"location": f"/{i + 1}"}) for i in range(10)}
    seen: list = []
    out = await probe("https://a.example/0", routes, seen)
    assert out["outcome"] == "unreachable" and "redirect" in out["reason"]
    assert len(seen) == 6


async def test_total_time_is_bounded():
    import asyncio

    async def slow(_request):
        await asyncio.sleep(5)
        return httpx.Response(200)

    out = await http_probe.http_probe(
        "https://a.example/", total_s=0.2, transport=httpx.MockTransport(slow)
    )
    assert out["outcome"] == "unreachable" and "time" in out["reason"]


async def test_body_read_is_capped():
    assert http_probe.MAX_BODY_BYTES == 64 * 1024
    out = await probe("https://a.example/", {"https://a.example/": (200, {})})
    assert out["body_bytes"] <= http_probe.MAX_BODY_BYTES


async def test_keep_body_returns_the_final_page_bytes_capped_and_only_when_asked():
    routes = {
        "http://a.example/": (301, {"location": "https://a.example/login"}),
        "https://a.example/login": (
            200,
            {"content-type": "text/html", "cf-mitigated": "challenge"},
        ),
    }
    out = await probe("http://a.example/", routes, keep_body=True)
    assert out["outcome"] == "ok" and len(out["body"]) == http_probe.MAX_BODY_BYTES
    assert out["content_type"] == "text/html" and out["cf_mitigated"] == "challenge"
    plain = await probe("http://a.example/", routes)
    assert "body" not in plain and "content_type" not in plain


class FakeStream(httpcore.AsyncNetworkStream):
    """One canned HTTP/1.1 response on a fake socket; records what the client sent."""

    def __init__(self, response: bytes) -> None:
        self.response, self.sent, self.sni = response, b"", None

    async def read(self, max_bytes, timeout=None):
        out, self.response = self.response[:max_bytes], self.response[max_bytes:]
        return out

    async def write(self, buffer, timeout=None):
        self.sent += buffer

    async def aclose(self):
        pass

    async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self.sni = server_hostname
        return self

    def get_extra_info(self, info):
        return None


class FakeBackend(httpcore.AsyncNetworkBackend):
    """The socket layer under the pinned transport: records every address dialled."""

    def __init__(self, response: bytes) -> None:
        self.dialled: list[tuple[str, int]] = []
        self.stream = FakeStream(response)

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.dialled.append((host, port))
        return self.stream

    async def sleep(self, seconds):
        pass


async def test_the_probe_connects_to_the_address_the_guard_approved_not_a_later_dns_answer(
    monkeypatch,
):
    # DNS rebinding: the guard's lookup sees a public address, any later lookup a private one.
    answers = iter(["93.184.216.34"])

    def rebinding_dns(host, *_a, **_k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (next(answers, "127.0.0.1"), 0))]

    monkeypatch.setattr(url_safety.socket, "getaddrinfo", rebinding_dns)
    page = b"<html><form action=/p><input type=password></form></html>"
    backend = FakeBackend(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        + f"Content-Length: {len(page)}\r\n\r\n".encode()
        + page
    )
    out = await http_probe.http_probe(
        "https://rebind.example/login", keep_body=True, network_backend=backend
    )
    assert out["outcome"] == "ok" and out["body"] == page
    # Dialled the checked address; the hostname still went in SNI and Host.
    assert backend.dialled == [("93.184.216.34", 443)]
    assert backend.stream.sni == "rebind.example"
    assert b"Host: rebind.example\r\n" in backend.stream.sent
    assert b"Accept-Encoding: identity\r\n" in backend.stream.sent


async def test_a_hop_that_resolves_private_is_never_dialled(monkeypatch):
    def private_dns(host, *_a, **_k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]

    monkeypatch.setattr(url_safety.socket, "getaddrinfo", private_dns)
    backend = FakeBackend(b"")
    out = await http_probe.http_probe("https://inside.example/", network_backend=backend)
    assert out["outcome"] == "blocked" and backend.dialled == []


async def test_a_compressed_body_is_not_inflated_or_kept():
    import gzip

    bomb = gzip.compress(b"<html>" + b"A" * 20_000_000)
    seen: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("accept-encoding"))
        return httpx.Response(
            200,
            headers={"content-type": "text/html", "content-encoding": "gzip"},
            stream=httpx.ByteStream(bomb),
        )

    out = await http_probe.http_probe(
        "https://a.example/", transport=httpx.MockTransport(handler), keep_body=True
    )
    assert seen == ["identity"]
    assert out["outcome"] == "ok" and out["body"] == b"" and out["content_encoding"] == "gzip"
    assert out["body_bytes"] <= min(len(bomb), http_probe.MAX_BODY_BYTES)
    from phish_agents.code_analyst import static_html

    assert static_html.excerpt(out) is None


class ScriptedBackend(httpcore.AsyncNetworkBackend):
    """Inner backend whose connect to each address raises, or returns a marker stream."""

    def __init__(self, outcomes: dict):
        self.outcomes, self.dialled = outcomes, []

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.dialled.append(host)
        outcome = self.outcomes[host]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    async def sleep(self, seconds):
        pass


async def test_a_connect_timeout_on_one_approved_address_fails_over_to_the_next():
    inner = ScriptedBackend({"192.0.2.1": httpcore.ConnectTimeout("slow"), "192.0.2.2": "stream-2"})
    backend = http_probe._PinnedBackend({"multi.example": ["192.0.2.1", "192.0.2.2"]}, inner)
    assert await backend.connect_tcp("multi.example", 443, timeout=1.0) == "stream-2"
    assert inner.dialled == ["192.0.2.1", "192.0.2.2"]


async def test_a_refused_address_still_fails_over_to_the_next():
    inner = ScriptedBackend({"192.0.2.1": httpcore.ConnectError("refused"), "192.0.2.2": "s2"})
    backend = http_probe._PinnedBackend({"multi.example": ["192.0.2.1", "192.0.2.2"]}, inner)
    assert await backend.connect_tcp("multi.example", 443) == "s2"


async def test_every_address_refused_raises_connect_error():
    inner = ScriptedBackend(
        {"192.0.2.1": httpcore.ConnectError("refused 1"), "192.0.2.2": httpcore.ConnectError("2")}
    )
    backend = http_probe._PinnedBackend({"multi.example": ["192.0.2.1", "192.0.2.2"]}, inner)
    with pytest.raises(httpcore.ConnectError, match="2"):
        await backend.connect_tcp("multi.example", 443)


async def test_any_timed_out_address_makes_the_failure_a_timeout_not_a_refusal():
    # A timeout is inconclusive (unreachable); only an all-refused host is site_down.
    inner = ScriptedBackend(
        {"192.0.2.1": httpcore.ConnectTimeout("slow"), "192.0.2.2": httpcore.ConnectError("no")}
    )
    backend = http_probe._PinnedBackend({"multi.example": ["192.0.2.1", "192.0.2.2"]}, inner)
    with pytest.raises(httpcore.ConnectTimeout):
        await backend.connect_tcp("multi.example", 443)
    assert inner.dialled == ["192.0.2.1", "192.0.2.2"]


async def test_a_host_with_no_approved_address_is_never_dialled():
    inner = ScriptedBackend({})
    backend = http_probe._PinnedBackend({}, inner)
    with pytest.raises(httpcore.ConnectError, match="no address approved"):
        await backend.connect_tcp("unpinned.example", 443)
    assert inner.dialled == []
