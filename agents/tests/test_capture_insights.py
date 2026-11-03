# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import pytest

from phish_agents.code_analyst.heuristics import code_insights
from phish_agents.common import browser
from phish_agents.tools_server import server as tools_server


@pytest.mark.parametrize(
    ("status", "title", "name", "severity"),
    [
        (403, "Suspected Phishing | Cloudflare", "cloudflare_phishing_warning", "high"),
        (403, "Suspected Malware | Cloudflare", "cloudflare_malware_warning", "high"),
        (
            403,
            "Suspected Misleading Website | Cloudflare",
            "cloudflare_phishing_warning",
            "high",
        ),
        (403, "Blocked by Eggy-Wall", "cloaking_bot_filter", "medium"),
        (429, "Just a moment...", "bot_challenge", "low"),
        (200, "Attention Required! | Cloudflare", "bot_challenge", "low"),
        (403, "", "blocked_by_site", "low"),
    ],
)
def test_site_block_signal_names_the_kind_of_block(status, title, name, severity):
    signal = browser.site_block_signal({"status": status, "title": title, "final_url": "x"})
    assert (signal.name, signal.severity) == (name, severity)


@pytest.mark.parametrize(
    ("failure", "block", "expected"),
    [
        (
            browser.CaptureFailure("blocked_by_browser", "net::ERR_BLOCKED_BY_CLIENT"),
            None,
            "not evidence of phishing",
        ),
        (browser.CaptureFailure("site_unreachable", "dns_nxdomain"), None, "did not load"),
        (browser.CaptureFailure("navigation_timeout", "timeout"), None, "did not finish loading"),
        (
            None,
            browser.site_block_signal({"status": 403, "title": "Suspected Phishing"}),
            "Cloudflare showed its own phishing warning",
        ),
        (
            None,
            browser.site_block_signal({"status": 403, "title": "Suspected Malware"}),
            "Cloudflare showed its own malware warning",
        ),
        (
            None,
            browser.site_block_signal({"status": 429, "title": "Just a moment..."}),
            "bot check",
        ),
        (None, browser.page_not_found_signal({"status": 404}), "HTTP 404"),
    ],
)
def test_capture_note_is_plain_english(failure, block, expected):
    note = browser.capture_note(failure, block)
    assert expected in note
    assert "_" not in note


def test_capture_note_is_none_for_a_clean_capture():
    assert browser.capture_note(None, None) is None


KIT = {
    "forms": [{"action": "javascript:void(0);", "inputs": ["email", "password"], "names": []}],
    "scripts": [
        {"src": "https://cdn.kitcdn.example/a.js", "text": "x" * 3000},
        {"src": None, "text": "form.submit()"},
    ],
    "requests": [
        {"url": "https://api.ipify.org/?format=json", "resource_type": "fetch"},
        {"url": "https://victim-kit.example/logo.png", "resource_type": "image"},
        {"url": "https://www.google-analytics.com/g/collect", "resource_type": "xhr"},
    ],
    "sinks": [{"kind": "fetch", "url": "/api/telegram/sendMessage"}],
    "listeners": [],
}


def test_code_insights_lists_endpoints_forms_and_scripts():
    out = code_insights(KIT, "victim-kit.example")
    urls = [e["url"] for e in out["endpoints"]]
    assert urls[0] == "hxxps://api[.]ipify[.]org/?format=json"
    assert out["endpoints"][0]["off_domain"] is True
    assert any("telegram" in u for u in urls)
    assert not any("google-analytics" in u for u in urls)
    assert not any("logo.png" in u for u in urls)
    assert out["forms"] == [
        {"action": "javascript:void(0);", "fields": ["email", "password"], "submits_via_js": True}
    ]
    assert out["script_count"] == 2
    assert out["external_script_hosts"] == ["kitcdn.example"]


def test_code_insights_ignores_browser_extension_scripts():
    capture = {
        "scripts": [
            {"src": "chrome-extension://pnbccbamcffpphfpnkpooldgbkoehjlb/content.js"},
            {"src": "//cdn.kitcdn.example/b.js"},
            {"src": "/local.js"},
        ]
    }
    out = code_insights(capture, "victim-kit.example")
    assert out["external_script_hosts"] == ["kitcdn.example"]


def test_code_insights_of_an_empty_capture_is_empty():
    out = code_insights({}, "example.com")
    assert out["endpoints"] == [] and out["forms"] == [] and out["script_count"] == 0


def test_precheck_deadline_leaves_room_for_the_http_probe():
    assert tools_server.PRECHECK_DEADLINE_S >= 18


async def test_code_analyst_finding_carries_note_and_insights(monkeypatch):
    from phish_agents.code_analyst.capture import CodeCapture
    from phish_agents.common.timing import CallRecorder

    cap = CodeCapture("https://victim-kit.example/", "scan-12345678", CallRecorder(), None, "b")
    cap.data = {**KIT, "final_url": "https://victim-kit.example/"}
    assert cap.note() is None
    insights = cap.insights()
    assert insights is not None and insights.script_count == 2
    cap.data = {"error": "capture_failed"}
    cap.failure = browser.CaptureFailure("site_unreachable", "dns_nxdomain")
    assert cap.insights() is None and "did not load" in cap.note()
