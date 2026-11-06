# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Tests for the live phishing feed.

Network and DNS are stubbed throughout: these assert the screening, parsing and
caching logic, which is where the correctness risk lives. Whether a given public
feed is reachable is not something a unit test can or should pin down.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from phish_backend.api import feed


def permissive(_url: str):
    """Stand-in for handler.validate_url that accepts everything."""
    return None


def reject_high_ports(url: str):
    """Stand-in that mimics the real SSRF port rule."""
    if ":8080" in url or ":22" in url:
        return "port not allowed"
    return None


class TestParsers:
    def test_lines_parser_keeps_only_http_urls(self):
        body = "\n".join(
            [
                "https://evil.example/login",
                "# a comment",
                "",
                "ftp://not-http.example/x",
                "http://other.example/verify",
            ]
        )
        assert feed._parse_lines(body) == [
            "https://evil.example/login",
            "http://other.example/verify",
        ]

    def test_urlhaus_parser_keeps_only_online_rows(self):
        body = "\n".join(
            [
                "# comment line that must be ignored",
                '"1","2026-01-01","https://live.example/a","online","x","malware_download"',
                '"2","2026-01-01","https://dead.example/b","offline","x","malware_download"',
            ]
        )
        assert feed._parse_urlhaus_csv(body) == ["https://live.example/a"]

    def test_urlhaus_parser_tolerates_short_rows(self):
        assert feed._parse_urlhaus_csv('"1","2026-01-01"') == []


class TestScreening:
    def test_deduplicates_by_host(self):
        urls = [
            "https://evil.example/one",
            "https://evil.example/two",
            "https://other.example/three",
        ]
        out = feed._screen(urls, permissive)
        assert out == ["https://evil.example/one", "https://other.example/three"]

    def test_applies_injected_ssrf_policy(self):
        urls = ["https://ok.example/a", "https://bad.example:8080/b"]
        assert feed._screen(urls, reject_high_ports) == ["https://ok.example/a"]

    def test_drops_absurdly_long_urls(self):
        assert feed._screen(["https://e.example/" + "a" * 2100], permissive) == []

    def test_drops_unparseable_hosts(self):
        assert feed._screen(["https:///nohost"], permissive) == []


class TestCuratedSamples:
    def test_high_tier_is_the_curated_samples(self):
        out = feed.get_live_phishing_urls(limit=10, validate_url=permissive)
        urls = [i["url"] for i in out["items"]]
        assert urls == [u for u, _ in feed.HIGH_RISK_SAMPLES]
        assert out["live_count"] == len(feed.HIGH_RISK_SAMPLES)

    def test_no_live_feed_is_fetched(self):
        # The endpoint must be fully offline: no upstream threat-feed call.
        with patch.object(feed, "_fetch_candidates", side_effect=AssertionError("must not fetch")):
            out = feed.get_live_phishing_urls(limit=10, validate_url=permissive)
        assert len(out["items"]) == len(feed.HIGH_RISK_SAMPLES)

    def test_policy_screening_still_applies_to_samples(self):
        # A sample the scanner would refuse (mock: reject a specific host) is dropped.
        def reject_arnazon(url: str):
            return "blocked" if "arnazon" in url else None

        out = feed.get_live_phishing_urls(limit=10, validate_url=reject_arnazon)
        assert all("arnazon" not in i["url"] for i in out["items"])

    def test_limit_is_clamped_and_applied(self):
        assert len(feed.get_live_phishing_urls(limit=2, validate_url=permissive)["items"]) == 2
        # Over-large requests are capped rather than rejected (high tier has few).
        assert len(feed.get_live_phishing_urls(limit=999, validate_url=permissive)["items"]) == len(
            feed.HIGH_RISK_SAMPLES
        )

    def test_all_three_tiers_present(self):
        groups = {g["risk"]: g for g in feed.get_live_phishing_urls(10, permissive)["groups"]}
        assert set(groups) == {"high", "medium", "low"}
        assert groups["high"]["items"]

    def test_warning_is_not_alarming(self):
        out = feed.get_live_phishing_urls(limit=5, validate_url=permissive)
        w = out["warning"].lower()
        # Must NOT claim these are live/real malicious URLs.
        assert "not live" in w or "illustrative" in w
        assert "do not open" not in w


class TestSourceFailover:
    def test_falls_through_to_the_next_source_on_error(self):
        calls: list[str] = []

        def fake_get(url: str) -> str:
            calls.append(url)
            if len(calls) == 1:
                raise OSError("upstream down")
            return "https://second.example/x"

        with patch.object(feed, "_http_get", side_effect=fake_get):
            urls, attribution = feed._fetch_candidates()
        assert urls == ["https://second.example/x"]
        assert attribution == feed.SOURCES[1].attribution
        assert len(calls) == 2

    def test_all_sources_failing_is_not_fatal(self):
        with patch.object(feed, "_http_get", side_effect=OSError("no network")):
            urls, attribution = feed._fetch_candidates()
        assert urls == []
        assert attribution == ""


class TestCaching:
    def _s3_returning(self, payload: dict) -> MagicMock:
        s3 = MagicMock()
        s3.get_object.return_value = {"Body": io_bytes(json.dumps(payload))}
        return s3

    def test_fresh_cache_short_circuits_the_fetch(self):
        cached = {
            "items": [{"url": "https://cached.example/x", "host": "cached.example", "source": "T"}],
            "generated_at": time.time(),
            "live_count": 1,
        }
        s3 = self._s3_returning(cached)
        with patch.object(feed, "_fetch_candidates") as fetch:
            out = feed.get_live_phishing_urls(10, permissive, s3=s3, bucket="b")
        fetch.assert_not_called()
        assert out["cached"] is True
        assert out["items"][0]["url"] == "https://cached.example/x"

    def test_stale_cache_triggers_a_refresh(self):
        stale = {"items": [], "generated_at": time.time() - (feed.CACHE_TTL_SECONDS + 60)}
        s3 = self._s3_returning(stale)
        out = feed.get_live_phishing_urls(10, permissive, s3=s3, bucket="b")
        assert out["cached"] is False
        assert [i["url"] for i in out["items"]] == [u for u, _ in feed.HIGH_RISK_SAMPLES]

    def test_force_refresh_bypasses_a_fresh_cache(self):
        s3 = self._s3_returning({"items": [], "generated_at": time.time()})
        out = feed.get_live_phishing_urls(10, permissive, s3=s3, bucket="b", force_refresh=True)
        assert out["cached"] is False

    def test_cache_read_failure_degrades_to_a_rebuild(self):
        s3 = MagicMock()
        s3.get_object.side_effect = _s3_error("AccessDenied")
        out = feed.get_live_phishing_urls(10, permissive, s3=s3, bucket="b")
        assert [i["url"] for i in out["items"]] == [u for u, _ in feed.HIGH_RISK_SAMPLES]

    def test_cache_write_failure_does_not_fail_the_request(self):
        s3 = MagicMock()
        s3.get_object.side_effect = _s3_error("NoSuchKey")
        s3.put_object.side_effect = _s3_error("AccessDenied")
        out = feed.get_live_phishing_urls(10, permissive, s3=s3, bucket="b")
        assert out["live_count"] == len(feed.HIGH_RISK_SAMPLES)


def _s3_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "S3")


def io_bytes(text: str):
    """Minimal stand-in for the streaming Body object S3 returns."""
    import io as _io

    return _io.BytesIO(text.encode())


class TestResolveTimeout:
    """Low finding: _resolves must bound its DNS lookup per-call, without mutating
    the process-global socket default timeout."""

    def test_resolves_true_on_success(self):
        with patch.object(feed.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("1.2.3.4", 0))]):
            assert feed._resolves("https://ok.example/") is True

    def test_resolves_false_on_gaierror(self):
        import socket as _s

        with patch.object(feed.socket, "getaddrinfo", side_effect=_s.gaierror("nope")):
            assert feed._resolves("https://dead.example/") is False

    def test_resolves_does_not_touch_global_default_timeout(self):
        import socket as _s

        before = _s.getdefaulttimeout()
        with patch.object(feed.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("1.2.3.4", 0))]):
            feed._resolves("https://ok.example/")
        assert _s.getdefaulttimeout() == before

    def test_resolves_false_when_lookup_exceeds_timeout(self):
        import time as _t

        def slow(*_a, **_k):
            _t.sleep(0.3)
            return [(2, 1, 6, "", ("1.2.3.4", 0))]

        with (
            patch.object(feed, "RESOLVE_TIMEOUT", 0.05),
            patch.object(feed.socket, "getaddrinfo", side_effect=slow),
        ):
            assert feed._resolves("https://slow.example/") is False


NON_HTTPS_URLS = [
    "file:///etc/passwd",
    "ftp://example.com/feed.txt",
    "http://example.com/feed.txt",
]


class TestHttpsOnly:
    @pytest.mark.parametrize("url", NON_HTTPS_URLS)
    def test_fetch_refuses_non_https_url(self, url):
        with pytest.raises(ValueError, match="refusing non-https scheme"):
            feed._http_get(url)

    @pytest.mark.parametrize("url", NON_HTTPS_URLS)
    def test_opener_has_no_handler_for_non_https_schemes(self, url):
        with pytest.raises(urllib.error.URLError, match="unknown url type"):
            feed._HTTPS_OPENER.open(urllib.request.Request(url), timeout=1)  # noqa: S310
