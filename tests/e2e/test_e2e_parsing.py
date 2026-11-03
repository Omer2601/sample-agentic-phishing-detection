# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Offline checks for the e2e helpers: CSV parsing, URL expansion and the report.

These never call AWS. The live runs in test_e2e.py are marked e2e and deselected by default.
"""

import io
import json
import urllib.error
import urllib.request

import pytest

from tests.e2e import client, datasets, report

BOOK = b"url\r\nhttps://a.example/\r\nhttps://b.example/?q=1\r\nhttps://a.example/\r\nftp://x\r\n"


def test_count_urls_dedupes_and_skips_header_and_invalid():
    assert datasets.count_urls(BOOK) == 2


def test_data_dir_honours_env(monkeypatch, tmp_path):
    monkeypatch.setenv("PHISH_E2E_DATA_DIR", str(tmp_path))
    (tmp_path / "Book1-clean-nohdr.csv").write_bytes(BOOK)
    assert datasets.data_dir() == tmp_path
    assert datasets.load("Book1-clean-nohdr.csv") == BOOK


def test_unique_urls_survive_server_side_dedupe(monkeypatch, tmp_path):
    monkeypatch.setenv("PHISH_E2E_DATA_DIR", str(tmp_path))
    (tmp_path / "Book1-clean-nohdr.csv").write_bytes(BOOK)
    urls = datasets.unique_urls(5)
    assert len(urls) == len(set(urls)) == 5
    assert urls[:2] == ["https://a.example/", "https://b.example/?q=1"]
    assert urls[2] == "https://a.example/?e2e=2"
    assert urls[3] == "https://b.example/?q=1&e2e=3"
    assert datasets.count_urls(("\n".join(urls) + "\n").encode()) == 5


SCANS = [
    {
        "status": "COMPLETE",
        "total_ms": 30000,
        "cost_usd": "0.10",
        "verdict": {"verdict": "phishing"},
        "calls": [{"kind": "harness", "name": "orchestrator", "duration_ms": 28000}],
    },
    {
        "status": "COMPLETE",
        "total_ms": 40000,
        "cost_usd": "0.20",
        "verdict": {"verdict": "legitimate"},
        "calls": [{"kind": "harness", "name": "orchestrator", "duration_ms": 38000}],
    },
    {
        "status": "FAILED",
        "total_ms": None,
        "cost_usd": "0",
        "error": "The orchestrator returned no verdict.",
    },
]


def test_summarize_counts_latency_cost_and_failures():
    summary = report.summarize("t", SCANS, 50000)
    assert summary["submitted"] == 3
    assert summary["status"] == {"COMPLETE": 2, "FAILED": 1}
    assert summary["verdicts"] == {"phishing": 1, "legitimate": 1, "none": 1}
    assert summary["p50_ms"] in (30000, 40000) and summary["p95_ms"] == 40000
    assert summary["cost_usd"] == "0.30"
    assert summary["calls"]["harness:orchestrator"]["count"] == 2
    assert list(summary["failures"]) == ["The orchestrator returned no verdict."]


def test_write_emits_json_and_markdown(monkeypatch, tmp_path):
    monkeypatch.setattr(report, "REPORTS", tmp_path)
    md = report.write(report.summarize("t", SCANS, None))
    assert md.suffix == ".md" and "| submitted | 3 |" in md.read_text()
    assert json.loads(md.with_suffix(".json").read_text())["label"] == "t"


@pytest.mark.parametrize(
    "url",
    ["file:///etc/passwd", "http://api.example.com/", "ftp://x.example/", "data:,x", "https://"],
)
def test_client_refuses_non_https_urls(url):
    with pytest.raises(ValueError, match="non-https"):
        client.require_https(url)
    with pytest.raises(ValueError, match="non-https"):
        client.open_https(urllib.request.Request(url))  # noqa: S310 - proves it is refused


def test_client_accepts_https_and_rejects_an_http_base_url():
    assert client.require_https("https://api.example.com/v1") == "https://api.example.com/v1"
    with pytest.raises(ValueError):
        client.ApiClient("http://api.example.com", "us-west-2", session=object())


def test_https_opener_has_no_file_or_redirect_handlers():
    kinds = {type(h) for h in client._OPENER.handlers}
    assert urllib.request.FileHandler not in kinds
    assert urllib.request.HTTPRedirectHandler not in kinds
    assert urllib.request.HTTPSHandler in kinds


class _Resp:
    def __init__(self, status, body):
        self.status, self._body = status, body
        self.headers = {"Content-Type": "application/json"}

    def read(self):
        return json.dumps(self._body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _throttled(times, final=None):
    calls = []

    def fake_open(req, timeout=60):
        calls.append(req.full_url)
        if len(calls) <= times:
            raise urllib.error.HTTPError(
                req.full_url, 429, "Too Many Requests", {"Content-Type": "application/json"},
                io.BytesIO(b'{"message": "Too Many Requests"}'),
            )  # fmt: skip
        return _Resp(200, final or {"ok": True})

    return calls, fake_open


def test_client_backs_off_and_retries_on_throttling(monkeypatch):
    # Fetching 1,000 scans with 8 threads crossed the 50 rps stage limit and the run died
    # on the first 429 (release run 2026-09-30); throttling must be retried, not fatal.
    calls, fake_open = _throttled(3)
    sleeps = []
    monkeypatch.setattr(client, "open_https", fake_open)
    monkeypatch.setattr(client, "_sleep", sleeps.append)
    api = client.ApiClient("https://api.example/prod", "us-west-2", session=object())
    assert api.request("GET", "/scans/x", signed=False) == (200, {"ok": True})
    assert len(calls) == 4
    assert len(sleeps) == 3 and sleeps[0] < sleeps[1] < sleeps[2]


def test_client_gives_up_after_bounded_retries(monkeypatch):
    calls, fake_open = _throttled(100)
    monkeypatch.setattr(client, "open_https", fake_open)
    monkeypatch.setattr(client, "_sleep", lambda s: None)
    api = client.ApiClient("https://api.example/prod", "us-west-2", session=object())
    status, _ = api.request("GET", "/scans/x", signed=False)
    assert status == 429
    assert len(calls) == client.MAX_ATTEMPTS
