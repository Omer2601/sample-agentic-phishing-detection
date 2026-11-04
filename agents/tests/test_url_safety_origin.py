# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from phish_agents.common import url_safety


def test_origin_strips_path_and_query():
    assert url_safety.origin_of("https://a.example.com/x?y=1") == "https://a.example.com/"


def test_origin_none_for_garbage():
    assert url_safety.origin_of("not a url") is None


def test_request_allowed_skips_browser_internal_schemes():
    assert url_safety.request_allowed("data:image/png;base64,AAAA") is None
    assert url_safety.request_allowed("blob:https://x/1") is None


def test_request_allowed_refuses_metadata_ip():
    assert url_safety.request_allowed("http://169.254.169.254/latest/meta-data") is not None


def test_request_allowed_long_url_judged_by_origin(monkeypatch):
    monkeypatch.setattr(
        url_safety, "_resolve_kind", lambda _u, **_k: (None, True, url_safety.HOST_OK)
    )
    url_safety.request_allowed.cache_clear()
    assert url_safety.request_allowed("https://cdn.example.com/" + "a" * 5000) is None


def _addr(ip):
    import socket

    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]


def test_transient_dns_failure_is_not_cached(monkeypatch):
    import socket

    answers = [socket.gaierror(socket.EAI_AGAIN, "try again"), _addr("93.184.216.34")]

    def fake(*_a, **_k):
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(url_safety.socket, "getaddrinfo", fake)
    url_safety.request_allowed.cache_clear()
    assert url_safety.request_allowed("https://flaky.example.com/a") is not None
    assert url_safety.request_allowed("https://flaky.example.com/b") is None


def test_cached_decision_expires_after_ttl(monkeypatch):
    lookups = []

    def fake(*_a, **_k):
        lookups.append(1)
        return _addr("93.184.216.34")

    clock = [1000.0]
    monkeypatch.setattr(url_safety.socket, "getaddrinfo", fake)
    monkeypatch.setattr(url_safety, "_now", lambda: clock[0])
    url_safety.request_allowed.cache_clear()
    url_safety.request_allowed("https://ttl.example.com/")
    url_safety.request_allowed("https://ttl.example.com/x")
    assert len(lookups) == 1
    clock[0] += url_safety.DECISION_TTL_S + 1
    url_safety.request_allowed("https://ttl.example.com/")
    assert len(lookups) == 2
    assert 30 <= url_safety.DECISION_TTL_S <= 120
