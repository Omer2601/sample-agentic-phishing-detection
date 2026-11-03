# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""CAPTURE_BLOCK_RETRY: bot-wall recognition, the bot_blocked page state and capture notes."""

import pytest

from phish_agents.common import browser, capture_recovery
from phish_contracts.models import PageState, PageStateObservation, Severity
from phish_contracts.page_state import BLOCK_PAGE, BOT_CHALLENGE_PAGE, BOT_FILTER_PAGE

ACCESS_DENIED = {"status": 403, "title": "Access denied", "final_url": "https://shop.example/"}
S3_DENIED = {
    "status": 403,
    "title": "",
    "final_url": "https://bucket.s3.amazonaws.com/",
    "visible_text": "<Code>AccessDenied</Code><RequestId>R</RequestId><HostId>H</HostId>",
}


@pytest.fixture
def retry_on(monkeypatch):
    monkeypatch.setenv(browser.BLOCK_RETRY_ENV, "1")


@pytest.mark.parametrize(
    ("nav", "reason"),
    [
        (ACCESS_DENIED, BLOCK_PAGE),
        ({"status": 429, "title": ""}, BLOCK_PAGE),
        ({"status": 503, "title": "Access Denied"}, BLOCK_PAGE),
        ({"status": 403, "title": "Just a moment..."}, BOT_CHALLENGE_PAGE),
        ({"status": 200, "title": "Attention Required! | Cloudflare"}, BOT_CHALLENGE_PAGE),
        ({"status": 200, "title": "eggywall"}, BOT_FILTER_PAGE),
        ({"status": 200, "title": "Shop"}, None),
        # Amazon's sign-in error page: a 503 with no bot-wall marker is an outage, not a wall.
        ({"status": 503, "title": "Sorry! Something went wrong!"}, None),
        ({"status": 401, "title": "Unauthorized"}, None),
        ({"status": 451, "title": "Unavailable"}, None),
        ({"status": 404, "title": "Access denied"}, None),
        ({"status": 403, "title": "Suspected Phishing | Cloudflare"}, None),
        (S3_DENIED, None),
        ({"error": "capture_failed"}, None),
        ({"status": 403, "title": "", "download": {"kind": "other"}}, None),
        (None, None),
    ],
)
def test_bot_block_reason(nav, reason):
    assert browser.bot_block_reason(nav) == reason


def test_bot_blocked_is_recorded_only_with_the_flag(monkeypatch):
    monkeypatch.delenv(browser.BLOCK_RETRY_ENV, raising=False)
    assert browser.recognised_page_state(None, ACCESS_DENIED) is None
    monkeypatch.setenv(browser.BLOCK_RETRY_ENV, "true")
    assert browser.recognised_page_state(None, ACCESS_DENIED) == PageStateObservation(
        page_state=PageState.BOT_BLOCKED, reason=BLOCK_PAGE
    )


def test_a_recognised_provider_page_keeps_its_own_state(retry_on):
    state = browser.recognised_page_state(None, S3_DENIED)
    assert state.page_state == PageState.S3_ACCESS_DENIED


def test_no_bot_blocked_state_for_failures_or_real_pages(retry_on):
    failure = browser.CaptureFailure(browser.SITE_UNREACHABLE, "net::ERR_NAME_NOT_RESOLVED")
    assert browser.recognised_page_state(failure, None) is None
    assert browser.recognised_page_state(None, {"status": 200, "title": "Shop"}) is None


def test_a_bot_blocked_page_is_not_observed(retry_on):
    assert browser.page_observed(None, ACCESS_DENIED) is False


def test_capture_note_reports_the_retry_outcome():
    block = browser.site_block_signal(ACCESS_DENIED)
    still = browser.capture_note(None, block, block_retry={"outcome": "still_blocked"})
    assert still.startswith("The site served a block page")
    assert still.endswith("A second try with a different browser profile was blocked too.")
    recovered = browser.capture_note(None, None, block_retry={"outcome": "recovered"})
    assert "got past it and captured the real page" in recovered
    assert browser.capture_note(None, block) == browser.capture_note(None, block, block_retry=None)
    failure = browser.CaptureFailure(browser.SITE_UNREACHABLE, "x")
    assert browser.capture_note(
        failure, None, block_retry={"outcome": "still_blocked"}
    ) == browser.capture_note(failure, None)


@pytest.mark.parametrize(
    ("version", "major"), [("133.0.6943.141", "133"), ("", "130"), ("HeadlessChrome", "130")]
)
def test_desktop_user_agent_has_no_automation_token(version, major):
    ua = capture_recovery.desktop_user_agent(version)
    assert f"Chrome/{major}.0.0.0" in ua
    assert "Windows NT 10.0" in ua
    assert "Headless" not in ua and "AgentCore" not in ua


def test_an_unconfirmed_certificate_error_is_low_and_says_so():
    nav = {
        "tls_certificate": {
            "type": browser.TLS_UNCONFIRMED,
            "code": "net::ERR_BLOCKED_BY_CLIENT",
            "certificate_checks": capture_recovery.TLS_CHECKS_IGNORED,
        }
    }
    signal = browser.tls_certificate_signal(nav)
    assert signal.name == browser.TLS_CERTIFICATE_ERROR
    assert signal.severity == Severity.LOW
    assert "net::ERR_BLOCKED_BY_CLIENT" in signal.evidence
    assert "not authenticated" in signal.evidence


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (browser.CaptureFailure(browser.BLOCKED_BY_BROWSER, "net::ERR_BLOCKED_BY_CLIENT"), True),
        (
            browser.CaptureFailure(browser.BLOCKED_BY_BROWSER, "net::ERR_BLOCKED_BY_ADMINISTRATOR"),
            False,
        ),
        (browser.CaptureFailure(browser.BLOCKED_BY_BROWSER, "chrome_error_page"), False),
    ],
)
def test_only_the_upgrade_refusal_gets_the_unconfirmed_tolerant_retry(retry_on, failure, expected):
    retry_type = capture_recovery._tolerant_retry_type(failure)
    assert (retry_type == browser.TLS_UNCONFIRMED) is expected
    if not expected:
        assert retry_type is None
