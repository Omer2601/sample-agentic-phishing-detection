# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Offline tests: every HTTP call is answered by a fake urlopen, nothing leaves the host."""

import importlib.util
import io
import json
import logging
from email.message import Message
from pathlib import Path
from urllib.error import HTTPError
from urllib.response import addinfourl

import pytest

spec = importlib.util.spec_from_file_location(
    "benchmark_vendors", Path(__file__).with_name("benchmark_vendors.py")
)
bv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bv)

KEY = "test-key-not-real"


class FakeHttp:
    """Queued responses: a dict is a 200 JSON body, (status, dict[, headers]) is an error."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append(request)
        assert timeout == bv.HTTP_TIMEOUT_S
        item = self.responses.pop(0)
        if isinstance(item, dict):
            return addinfourl(io.BytesIO(json.dumps(item).encode()), Message(), "", 200)
        status, body, *rest = item
        headers = Message()
        for k, v in (rest[0] if rest else {}).items():
            headers[k] = v
        raise HTTPError(
            request.full_url, status, "err", headers, io.BytesIO(json.dumps(body).encode())
        )


@pytest.fixture
def http(monkeypatch):
    def install(*responses):
        fake = FakeHttp(*responses)
        monkeypatch.setattr(bv, "urlopen", fake)
        return fake

    return install


def sleeps():
    calls = []
    return calls, calls.append


def vt_analysis(status, malicious=0, suspicious=0):
    stats = {"malicious": malicious, "suspicious": suspicious, "harmless": 60}
    return {"data": {"id": "u-abc-1", "attributes": {"status": status, "stats": stats}}}


def test_vt_submit_then_polls_until_completed(http):
    fake = http({"data": {"id": "u-abc-1"}}, vt_analysis("queued"), vt_analysis("completed", 3))
    slept, sleep = sleeps()
    raw = bv.VirusTotalClient(KEY, sleep=sleep).scan("https://bad.example/login")
    post, poll1, poll2 = fake.requests
    assert post.get_method() == "POST" and post.full_url == f"{bv.VT_BASE}/urls"
    assert post.data == b"url=https%3A%2F%2Fbad.example%2Flogin"
    assert post.get_header("X-apikey") == KEY
    assert poll2.full_url == f"{bv.VT_BASE}/analyses/u-abc-1" and poll2.get_method() == "GET"
    assert raw["data"]["attributes"]["status"] == "completed"


def test_vt_keeps_15_seconds_between_calls(http):
    http({"data": {"id": "u-abc-1"}}, vt_analysis("completed"))
    now = [100.0]
    slept = []

    def sleep(s):
        slept.append(s)
        now[0] += s

    bv.VirusTotalClient(KEY, sleep=sleep, clock=lambda: now[0]).scan("https://a.example")
    assert slept == [15.0]


@pytest.mark.parametrize(
    "malicious,suspicious,threshold,count_susp,expected",
    [
        (0, 0, 1, False, "legitimate"),
        (1, 0, 1, False, "phishing"),
        (0, 2, 1, False, "legitimate"),
        (0, 2, 1, True, "phishing"),
        (2, 0, 3, False, "legitimate"),
        (2, 1, 3, True, "phishing"),
    ],
)
def test_vt_verdict_mapping(malicious, suspicious, threshold, count_susp, expected):
    client = bv.VirusTotalClient(KEY, min_detections=threshold, count_suspicious=count_susp)
    prediction, detail = client.predict(vt_analysis("completed", malicious, suspicious))
    assert prediction == expected
    assert detail == f"malicious={malicious} suspicious={suspicious}"
    assert client.predict({}) == (None, "no stats")


def test_urlscan_submits_unlisted_and_polls_past_404(http):
    assert bv.URLSCAN_VISIBILITY == "unlisted"
    result = {"verdicts": {"overall": {"malicious": True}}}
    fake = http({"uuid": "11-22"}, (404, {"message": "not found"}), result)
    slept, sleep = sleeps()
    raw = bv.UrlscanClient(KEY, sleep=sleep).scan("https://bad.example")
    post, pending, done = fake.requests
    assert json.loads(post.data) == {"url": "https://bad.example", "visibility": "unlisted"}
    assert post.full_url == f"{bv.URLSCAN_BASE}/scan/" and post.get_header("Api-key") == KEY
    assert done.full_url == f"{bv.URLSCAN_BASE}/result/11-22/"
    assert raw == result
    assert bv.UrlscanClient.first_poll_s in slept and bv.UrlscanClient.poll_s in slept


@pytest.mark.parametrize(
    "raw,expected",
    [
        ({"verdicts": {"overall": {"malicious": True}}}, "phishing"),
        ({"verdicts": {"overall": {"malicious": False}}}, "legitimate"),
        ({"verdicts": {}}, None),
    ],
)
def test_urlscan_verdict_mapping(raw, expected):
    assert bv.UrlscanClient(KEY).predict(raw)[0] == expected


def test_backoff_on_429_then_success(http):
    fake = http((429, {}, {"Retry-After": "7"}), (429, {}), {"uuid": "u1"}, {"verdicts": {}})
    slept, sleep = sleeps()
    bv.UrlscanClient(KEY, sleep=sleep).scan("https://a.example")
    assert len(fake.requests) == 4
    # Retry-After wins when given, then exponential backoff (throttle waits are interleaved).
    assert 7.0 in slept and bv.BACKOFF_S * 2 in slept


def test_429_after_every_retry_stops_the_scanner(http, tmp_path):
    http(*[(429, {"error": {"code": "QuotaExceededError"}})] * (bv.RETRIES_ON_429 + 1))
    client = bv.VirusTotalClient(KEY, sleep=lambda s: None)
    dataset = [("https://a.example", "phishing"), ("https://b.example", "legitimate")]
    rows = bv.run_scanner(client, dataset, tmp_path)
    assert [r["prediction"] for r in rows] == [None, None]
    assert all("QuotaExceededError" in r["detail"] for r in rows)
    assert not list(tmp_path.rglob("*.json")), "a rate-limited URL must not be cached"


def test_rerun_uses_cache_and_skips_done_urls(http, tmp_path):
    http({"uuid": "u1"}, {"verdicts": {"overall": {"malicious": True}}})
    dataset = [("https://a.example", "phishing")]
    first = bv.run_scanner(bv.UrlscanClient(KEY, sleep=lambda s: None), dataset, tmp_path)
    fake = http()  # any HTTP call now fails the test (empty queue)
    second = bv.run_scanner(bv.UrlscanClient(KEY, sleep=lambda s: None), dataset, tmp_path)
    assert first[0]["prediction"] == second[0]["prediction"] == "phishing"
    assert fake.requests == []
    cached = next(tmp_path.rglob("*.json")).read_text()
    assert KEY not in cached


def test_terminal_4xx_is_cached_as_unscored(http, tmp_path):
    http((400, {"message": "DNS Error"}))
    rows = bv.run_scanner(
        bv.UrlscanClient(KEY, sleep=lambda s: None), [("https://x.invalid", "phishing")], tmp_path
    )
    assert rows[0]["prediction"] is None and "HTTP 400 DNS Error" in rows[0]["detail"]
    assert len(list(tmp_path.rglob("*.json"))) == 1


def test_summary_math():
    rows = [
        {"label": "phishing", "prediction": "phishing", "latency_ms": 1},
        {"label": "phishing", "prediction": "phishing", "latency_ms": 1},
        {"label": "phishing", "prediction": "legitimate", "latency_ms": 1},
        {"label": "phishing", "prediction": None, "latency_ms": 1},
        {"label": "legitimate", "prediction": "legitimate", "latency_ms": 1},
        {"label": "legitimate", "prediction": "legitimate", "latency_ms": 1},
        {"label": "legitimate", "prediction": "legitimate", "latency_ms": 1},
        {"label": "legitimate", "prediction": "phishing", "latency_ms": 1},
    ]
    md = bv.summarize({"Vendor 1": rows}, run_date="2026-11-11", notes=["threshold 1"])
    assert "Run 2026-11-11, 8 URLs (4 phishing, 4 legitimate)." in md
    assert "threshold 1" in md
    assert "| Vendor 1 | 0.667 (2 of 3) | 0.25 (1 of 4) | 1 |" in md


def test_missing_keys_skip_vendors_and_ours_still_scores(http, tmp_path, monkeypatch, caplog):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    fake = http()
    data = tmp_path / "d.csv"
    data.write_text("url,label\nhttps://a.example,phishing\nhttps://b.example,legitimate\n")
    ours = tmp_path / "20261111T000000Z.json"
    rows = [
        {
            "url": "https://a.example",
            "label": "phishing",
            "verdict": "phishing",
            "prediction": "phishing",
            "latency_ms": 9,
        },
        {
            "url": "https://other.example",
            "label": "phishing",
            "verdict": "phishing",
            "prediction": "phishing",
            "latency_ms": 9,
        },
    ]
    ours.write_text(json.dumps({"scores": {}, "rows": {"orchestrator": rows}}))
    out = tmp_path / "out"
    with caplog.at_level(logging.INFO, logger="benchmark_vendors"):
        code = bv.main(["--dataset", str(data), "--ours", str(ours), "--out-dir", str(out)])
    assert code == 0 and fake.requests == []
    assert "VT_API_KEY not set: skipping Vendor 1" in caplog.text
    assert "URLSCAN_API_KEY not set: skipping Vendor 2" in caplog.text
    md = next(out.glob("*.md")).read_text()
    assert "| This sample (orchestrator) | 1.0 (1 of 1) | n/a | 1 |" in md
    assert "virustotal" not in md.lower() and "urlscan" not in md.lower()
    csv_text = next(out.glob("*.csv")).read_text()
    assert "not in results file" in csv_text


def test_nothing_to_run_returns_error(monkeypatch, tmp_path):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    assert bv.main(["--out-dir", str(tmp_path)]) == 1


def test_key_is_never_logged(http, tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("URLSCAN_API_KEY", KEY)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setattr(bv.UrlscanClient, "first_poll_s", 0.0)
    monkeypatch.setattr(bv.UrlscanClient, "min_interval_s", 0.0)
    http({"uuid": "u1"}, (500, {"message": "boom"}), {"uuid": "u2"}, {"verdicts": {}})
    data = tmp_path / "d.csv"
    data.write_text("url,label\nhttps://a.example,phishing\nhttps://b.example,legitimate\n")
    out = tmp_path / "out"
    with caplog.at_level(logging.DEBUG):
        assert bv.main(["--dataset", str(data), "--out-dir", str(out)]) == 0
    assert KEY not in caplog.text
    for path in out.rglob("*"):
        if path.is_file():
            assert KEY not in path.read_text()


@pytest.mark.parametrize(
    "url",
    ["file:///etc/passwd", "http://urlscan.io/api/v1/scan/", "https://evil.example/api/v3/urls"],
)
def test_urlopen_refuses_other_schemes_and_hosts(url, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("must not open a connection")

    monkeypatch.setattr(bv._HTTP, "request", no_network)
    with pytest.raises(ValueError, match="refusing"):
        bv.urlopen(bv.Request(url), timeout=bv.HTTP_TIMEOUT_S)
