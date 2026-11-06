# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json
import logging
import time

import httpx
import pytest
from botocore.exceptions import ClientError, ConnectTimeoutError
from test_web_search import FakeMcp, make_search, search_payload

from phish_agents.common import cache
from phish_agents.url_analyst.whois import rdap_lookup

RDAP = {
    "events": [
        {"eventAction": "registration", "eventDate": "2026-09-20T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-09-20T00:00:00Z"},
    ],
    "entities": [
        {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "NameCheap, Inc."]]]}
    ],
    "status": ["client transfer prohibited"],
    "nameservers": [{"ldhName": "NS1.EXAMPLE.NET"}],
}


class FakeDynamo:
    """Just get_item and put_item, with the DynamoDB wire shapes."""

    def __init__(self, error: Exception | None = None) -> None:
        self.items: dict[str, dict] = {}
        self.error = error
        self.gets = self.puts = 0

    def get_item(self, *, TableName, Key):  # noqa: N803 - boto3 parameter names
        self.gets += 1
        if self.error:
            raise self.error
        item = self.items.get(Key["pk"]["S"])
        return {"Item": item} if item else {}

    def put_item(self, *, TableName, Item):  # noqa: N803
        self.puts += 1
        if self.error:
            raise self.error
        self.items[Item["pk"]["S"]] = Item


@pytest.fixture
def table(monkeypatch):
    monkeypatch.setenv("PHISH_CACHE_TABLE", "phish-cache-test")
    monkeypatch.delenv("PHISH_RDAP_CACHE_TTL_S", raising=False)
    monkeypatch.delenv("PHISH_WEBSEARCH_CACHE_TTL_S", raising=False)
    fake = FakeDynamo()
    monkeypatch.setattr(cache, "_default_client", lambda: fake)
    return fake


@pytest.fixture
def off(monkeypatch):
    monkeypatch.delenv("PHISH_CACHE_TABLE", raising=False)
    fake = FakeDynamo()
    monkeypatch.setattr(cache, "_default_client", lambda: fake)
    return fake


@pytest.fixture(autouse=True)
def no_ssrf_dns(monkeypatch):
    monkeypatch.setattr("phish_agents.url_analyst.whois.resolve_and_validate", lambda _u: None)


def rdap_client(status=200, body=None, counter=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if counter is not None:
            counter.append(str(request.url))
        return httpx.Response(status, json=RDAP if body is None else body)

    return httpx.Client(transport=httpx.MockTransport(handler))


# ── The helper ───────────────────────────────────────────────────────────────


def test_put_then_get_round_trips(table):
    assert cache.put("rdap#a.xyz", {"registrar": "R"}, 60) is True
    assert cache.get("rdap#a.xyz") == {"registrar": "R"}
    row = table.items["rdap#a.xyz"]
    assert set(row) == {"pk", "value", "fetched_at", "ttl"}
    assert json.loads(row["value"]["S"]) == {"registrar": "R"}
    assert int(row["ttl"]["N"]) > time.time()


def test_miss_returns_none(table):
    assert cache.get("rdap#nope.xyz") is None


def test_expired_entry_is_ignored_even_if_dynamodb_has_not_deleted_it(table):
    cache.put("rdap#a.xyz", {"registrar": "R"}, 60, now=time.time() - 3600)
    assert "rdap#a.xyz" in table.items
    assert cache.get("rdap#a.xyz") is None


@pytest.mark.parametrize(
    "error",
    [
        ClientError({"Error": {"Code": "ProvisionedThroughputExceededException"}}, "GetItem"),
        ClientError({"Error": {"Code": "AccessDeniedException"}}, "GetItem"),
        ConnectTimeoutError(endpoint_url="https://dynamodb"),
        RuntimeError("boom"),
    ],
)
def test_dynamodb_errors_fail_open(table, error, caplog):
    table.error = error
    with caplog.at_level(logging.WARNING, logger=cache.logger.name):
        assert cache.get("rdap#a.xyz") is None
        assert cache.put("rdap#a.xyz", {"x": 1}, 60) is False
    assert "cache get failed type=rdap" in caplog.text
    assert "cache put failed type=rdap" in caplog.text


def test_damaged_row_is_a_miss(table):
    table.items["rdap#a.xyz"] = {
        "pk": {"S": "rdap#a.xyz"},
        "value": {"S": "not json"},
        "ttl": {"N": str(int(time.time()) + 100)},
    }
    assert cache.get("rdap#a.xyz") is None


def test_unset_table_disables_everything(off):
    assert cache.enabled() is False
    assert cache.put("rdap#a.xyz", {"x": 1}, 60) is False
    assert cache.get("rdap#a.xyz") is None
    assert off.gets == off.puts == 0


def test_empty_table_name_disables(monkeypatch):
    monkeypatch.setenv("PHISH_CACHE_TABLE", "  ")
    assert cache.enabled() is False


def test_injected_client_is_used(monkeypatch):
    monkeypatch.setenv("PHISH_CACHE_TABLE", "t")
    fake = FakeDynamo()
    assert cache.put("rdap#a.xyz", {"x": 1}, 60, client=fake) is True
    assert cache.get("rdap#a.xyz", client=fake) == {"x": 1}


def test_logs_hit_and_miss_with_key_type_only(table, caplog):
    cache.put("websearch#paypal", {"payload": "value-should-not-be-logged"}, 60)
    with caplog.at_level(logging.INFO, logger=cache.logger.name):
        cache.get("websearch#paypal")
        cache.get("websearch#other")
    assert "cache hit type=websearch" in caplog.text
    assert "cache miss type=websearch" in caplog.text
    assert "paypal" not in caplog.text and "value-should-not" not in caplog.text


def test_ttl_env_defaults_and_overrides(monkeypatch):
    monkeypatch.delenv("PHISH_RDAP_CACHE_TTL_S", raising=False)
    monkeypatch.delenv("PHISH_WEBSEARCH_CACHE_TTL_S", raising=False)
    assert cache.rdap_ttl_s() == 604800
    assert cache.websearch_ttl_s() == 86400
    monkeypatch.setenv("PHISH_RDAP_CACHE_TTL_S", "120")
    monkeypatch.setenv("PHISH_WEBSEARCH_CACHE_TTL_S", "garbage")
    assert cache.rdap_ttl_s() == 120
    assert cache.websearch_ttl_s() == 86400


def test_brand_key_normalization():
    assert cache.websearch_key("  PayPal   Holdings ") == "websearch#paypal holdings"
    assert cache.websearch_key("PAYPAL HOLDINGS") == cache.websearch_key("paypal  holdings")
    assert cache.rdap_key("Example.COM.") == "rdap#example.com"


def test_client_has_short_timeouts_and_one_retry():
    cfg = cache._CLIENT_CONFIG
    assert cfg.connect_timeout == 1 and cfg.read_timeout == 1
    assert cfg.retries["total_max_attempts"] == 2


# ── RDAP ─────────────────────────────────────────────────────────────────────


def test_rdap_second_lookup_is_served_from_cache(table):
    seen: list[str] = []
    first = rdap_lookup("verify.xyz", client=rdap_client(counter=seen), today="2026-09-29")
    second = rdap_lookup("verify.xyz", client=rdap_client(counter=seen), today="2026-09-29")
    assert len(seen) == 1
    assert first == second
    assert second["registrar"] == "NameCheap, Inc." and second["nameservers"] == ["ns1.example.net"]


def test_rdap_age_is_recomputed_from_the_stored_creation_date(table):
    rdap_lookup("verify.xyz", client=rdap_client(), today="2026-09-29")
    stored = json.loads(table.items["rdap#verify.xyz"]["value"]["S"])
    assert stored["registered"] == "2026-09-20"
    assert "age_days" not in stored
    later = rdap_lookup("verify.xyz", client=rdap_client(500), today="2026-10-20")
    assert later["age_days"] == 30


def test_rdap_subdomains_share_one_registered_domain_key(table):
    seen: list[str] = []
    rdap_lookup("verify.xyz", client=rdap_client(counter=seen))
    out = rdap_lookup("login.secure.verify.xyz", client=rdap_client(counter=seen))
    assert len(seen) == 1
    assert out["domain"] == "login.secure.verify.xyz" and out["registered"] == "2026-09-20"
    assert list(table.items) == ["rdap#verify.xyz"]


def test_rdap_subdomain_answer_is_not_stored_under_the_registered_key(table):
    rdap_lookup("a.verify.xyz", client=rdap_client())
    assert table.items == {}


@pytest.mark.parametrize("status", [404, 429, 500, 503])
def test_rdap_failures_are_never_cached(table, status):
    out = rdap_lookup("verify.xyz", client=rdap_client(status))
    assert "error" in out
    assert table.puts == 0


def test_rdap_transport_error_is_never_cached(table):
    def boom(request):
        raise httpx.ConnectTimeout("slow", request=request)

    client = httpx.Client(transport=httpx.MockTransport(boom))
    assert rdap_lookup("verify.xyz", client=client)["error"] == "lookup_failed"
    assert table.puts == 0


def test_rdap_empty_answer_is_never_cached(table):
    out = rdap_lookup("verify.xyz", client=rdap_client(body={"status": ["active"]}))
    assert out["registered"] is None and out["registrar"] is None
    assert table.puts == 0


def test_rdap_expired_entry_goes_live_and_refreshes(table):
    cache.put("rdap#verify.xyz", {"registered": "2020-01-01"}, 60, now=time.time() - 3600)
    seen: list[str] = []
    out = rdap_lookup("verify.xyz", client=rdap_client(counter=seen), today="2026-09-29")
    assert len(seen) == 1 and out["registered"] == "2026-09-20"


def test_rdap_dynamodb_error_fails_open_to_a_live_lookup(table):
    table.error = RuntimeError("down")
    seen: list[str] = []
    out = rdap_lookup("verify.xyz", client=rdap_client(counter=seen), today="2026-09-29")
    assert len(seen) == 1 and out["age_days"] == 9


def test_rdap_unchanged_when_cache_is_off(off):
    seen: list[str] = []
    out = rdap_lookup("verify.xyz", client=rdap_client(counter=seen), today="2026-09-29")
    rdap_lookup("verify.xyz", client=rdap_client(counter=seen), today="2026-09-29")
    assert len(seen) == 2 and off.gets == off.puts == 0
    assert set(out) == {
        "domain",
        "registered",
        "expires",
        "last_changed",
        "age_days",
        "registrar",
        "status",
        "nameservers",
    }


def test_rdap_live_lookup_still_checks_every_redirect_hop(table, monkeypatch):
    monkeypatch.undo()  # drop the permissive resolver stub; use the real guard
    from phish_agents.url_analyst import whois

    refused: list[str] = []

    def guard(url):
        refused.append(url)
        return "private address" if "internal" in url else None

    monkeypatch.setenv("PHISH_CACHE_TABLE", "t")
    monkeypatch.setattr(cache, "_default_client", lambda: table)
    monkeypatch.setattr(whois, "validate_url", lambda _u: None)
    monkeypatch.setattr(whois, "resolve_and_validate", guard)

    def handler(request):
        if request.url.host == "rdap.org":
            return httpx.Response(302, headers={"location": "https://internal.registry/domain/x"})
        return httpx.Response(200, json=RDAP)

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
        event_hooks={"request": [whois._guard_request]},
    )
    assert rdap_lookup("verify.xyz", client=client)["error"] == "lookup_failed"
    assert any("internal.registry" in u for u in refused)
    assert table.puts == 0


# ── Web search ───────────────────────────────────────────────────────────────

HIT = {"url": "https://www.paypal.com/", "title": "PayPal", "text": "Pay online"}
HIT_LINE = "1. paypal.com | PayPal | https://www.paypal.com/ | Pay online"


async def test_web_search_hit_skips_the_gateway(table):
    fake = FakeMcp(result=search_payload(HIT))
    first = await make_search(fake).lookup("PayPal")
    second_fake = FakeMcp(result=search_payload())
    second = await make_search(second_fake).lookup("PayPal")
    assert len(fake.calls) == 1 and second_fake.calls == [] and not second_fake.started
    assert first == second and HIT_LINE in second.splitlines()
    assert "websearch#paypal" in table.items


async def test_web_search_key_is_the_normalized_brand(table):
    await make_search(FakeMcp(result=search_payload(HIT))).lookup("  PayPal  ")
    other = FakeMcp(result=search_payload(HIT))
    await make_search(other).lookup("PAYPAL")
    assert other.calls == [] and list(table.items) == ["websearch#paypal"]


async def test_web_search_hit_marks_the_scanned_site_per_scan(table):
    await make_search(FakeMcp(result=search_payload(HIT))).lookup("PayPal")
    out = await make_search(FakeMcp(), scan_url="https://www.paypal.com/login").lookup("PayPal")
    assert "[scanned site]" in out


async def test_web_search_hit_does_not_use_lookup_budget_or_record_a_call(table):
    await make_search(FakeMcp(result=search_payload(HIT))).lookup("PayPal")
    search = make_search(FakeMcp(), max_lookups=1)
    for _ in range(3):
        assert HIT_LINE in (await search.lookup("PayPal")).splitlines()
    assert search.recorder.calls == []


async def test_web_search_expired_entry_goes_live(table):
    cache.put(
        "websearch#paypal",
        {"results": [{"url": "https://old.example/"}]},
        60,
        now=time.time() - 3600,
    )
    fake = FakeMcp(result=search_payload(HIT))
    out = await make_search(fake).lookup("PayPal")
    assert len(fake.calls) == 1 and "old.example" not in out


@pytest.mark.parametrize(
    "fake",
    [
        FakeMcp(result={"status": "error", "isError": True, "content": []}),
        FakeMcp(error=TimeoutError("slow")),
        FakeMcp(error=ConnectionError("down")),
        FakeMcp(result=search_payload()),
        FakeMcp(result=search_payload({"title": "no url"})),
    ],
)
async def test_web_search_errors_and_empty_results_are_never_cached(table, fake):
    await make_search(fake).lookup("PayPal")
    assert table.puts == 0


async def test_web_search_dynamodb_error_fails_open(table):
    table.error = RuntimeError("down")
    fake = FakeMcp(result=search_payload(HIT))
    out = await make_search(fake).lookup("PayPal")
    assert len(fake.calls) == 1 and HIT_LINE in out.splitlines()


async def test_web_search_unchanged_when_cache_is_off(off):
    fake = FakeMcp(result=search_payload(HIT))
    await make_search(fake).lookup("PayPal")
    await make_search(fake).lookup("PayPal")
    assert len(fake.calls) == 2 and off.gets == off.puts == 0


async def test_web_search_stores_only_capped_render_fields(table):
    big = {**HIT, "text": "x" * 5000, "raw_html": "<script>" * 1000}
    await make_search(FakeMcp(result=search_payload(big))).lookup("PayPal")
    stored = json.loads(table.items["websearch#paypal"]["value"]["S"])
    assert set(stored["results"][0]) == {"url", "title", "text"}
    assert len(stored["results"][0]["text"]) <= 200
    assert table.items["websearch#paypal"]["ttl"]["N"]
