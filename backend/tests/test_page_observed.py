# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The worker holds a scan at suspicious when a provider warning hid the real page."""

import json
import os

import boto3
import pytest
import test_run_scan
from backend_testkit import api_event
from test_run_scan import finding, seed
from test_verdict_first import COMPACT, TwoTurnHarness

from phish_backend.api import app
from phish_backend.common import store
from phish_backend.reports import html as reports
from phish_backend.worker import run_scan

WARNING = {
    "name": "cloudflare_malware_warning",
    "severity": "high",
    "evidence": "Cloudflare served its own 'Suspected Malware' warning for this URL (HTTP 403).",
}
GAP = {"name": "warning_bypass_blocked", "severity": "low", "evidence": "Turnstile."}


def browser_finding(agent, observed, signals):
    return {**finding(agent), "page_observed": observed, "signals": signals}


@pytest.fixture
def findings(monkeypatch):
    """The findings the fake specialists write: set .value before the scan runs."""
    holder = type("H", (), {"value": {}})()

    def write(scan_id):
        s3 = boto3.client("s3", region_name="us-west-2")
        for agent in ("url_analyst", "brand_visual", "code_analyst"):
            body = holder.value.get(agent, finding(agent))
            s3.put_object(
                Bucket=os.environ["ARTIFACTS_BUCKET"],
                Key=f"scans/{scan_id}/findings/{agent}.json",
                Body=json.dumps(body),
            )

    monkeypatch.setattr(test_run_scan, "write_findings", write)
    return holder


def test_phishing_from_an_unpassed_warning_is_stored_as_suspicious(aws, findings):
    findings.value = {
        "brand_visual": browser_finding("brand_visual", False, [WARNING, GAP]),
        "code_analyst": browser_finding("code_analyst", False, [WARNING, GAP]),
    }
    turn1 = dict(COMPACT, risk_score=80, summary="Cloudflare flags this throwaway host.")
    turn2 = {"report_markdown": "## Verdict\nPhishing, risk score 80."}
    run_scan.process_message(
        seed(), agentcore=TwoTurnHarness(turn1=json.dumps(turn1), turn2=json.dumps(turn2))
    )
    done = store.get_scan("s1")
    verdict = done.verdict
    assert (verdict.verdict, verdict.risk_score, verdict.action) == ("suspicious", 69, "warn")
    assert verdict.page_observed is False
    assert verdict.summary.startswith("Page not observed:")
    assert "Cloudflare flags this throwaway host." in verdict.summary
    assert "**Page not observed.**" in verdict.report_markdown
    assert "held at Suspicious with risk 69/100" in verdict.report_markdown
    stored = {f.agent: f for f in done.findings}
    assert stored["brand_visual"].page_observed is False


def test_a_warning_with_the_real_page_captured_keeps_the_model_verdict(aws, findings):
    findings.value = {
        "brand_visual": browser_finding("brand_visual", True, [WARNING]),
        "code_analyst": browser_finding("code_analyst", False, [WARNING, GAP]),
    }
    run_scan.process_message(seed(), agentcore=TwoTurnHarness())
    verdict = store.get_scan("s1").verdict
    assert (verdict.verdict, verdict.risk_score, verdict.action) == ("phishing", 95, "block")
    assert verdict.page_observed is True
    assert "Page not observed" not in verdict.summary + verdict.report_markdown


def test_no_warning_no_cap_even_when_the_page_was_not_observed(aws, findings):
    blocked = {"name": "blocked_by_browser", "severity": "low", "evidence": "refused"}
    findings.value = {
        "brand_visual": browser_finding("brand_visual", False, [blocked]),
        "code_analyst": browser_finding("code_analyst", False, [blocked]),
    }
    run_scan.process_message(seed(), agentcore=TwoTurnHarness())
    verdict = store.get_scan("s1").verdict
    assert verdict.verdict == "phishing" and verdict.risk_score == 95
    assert verdict.page_observed is False


def test_single_turn_report_also_gets_the_note(aws, findings):
    findings.value = {"brand_visual": browser_finding("brand_visual", False, [WARNING, GAP])}
    one_turn = dict(COMPACT, report_markdown="# Report\nPhishing.")
    fake = TwoTurnHarness(turn1=json.dumps(one_turn))
    run_scan.process_message(seed(), agentcore=fake)
    verdict = store.get_scan("s1").verdict
    assert verdict.verdict == "suspicious" and fake.invocations == 1
    assert "**Page not observed.**" in verdict.report_markdown


def test_the_pre_cap_answer_is_logged_stored_served_and_reported(aws, findings, caplog):
    findings.value = {
        "brand_visual": browser_finding("brand_visual", False, [WARNING, GAP]),
        "code_analyst": browser_finding("code_analyst", False, [WARNING, GAP]),
    }
    caplog.set_level("INFO", logger=run_scan.__name__)
    run_scan.process_message(seed(), agentcore=TwoTurnHarness())
    record = store.get_scan("s1")
    model = record.verdict.capped_from
    assert (model.verdict, model.risk_score, model.action) == ("phishing", 95, "block")
    [line] = [
        r for r in caplog.records if r.getMessage() == "page-not-observed cap changed the verdict"
    ]
    assert line.levelname == "INFO"
    assert (line.model_verdict, line.model_risk_score, line.model_action) == (
        "phishing",
        95,
        "block",
    )
    assert (line.verdict, line.risk_score) == ("suspicious", 69)
    response = app.handler(api_event("GET", "/scans/{id}", path={"id": "s1"}), None)
    served = json.loads(response["body"])["verdict"]["capped_from"]
    assert served == {"verdict": "phishing", "risk_score": 95, "action": "block"}
    page = reports.render_scan_report(record)
    assert "Before the page-not-observed cap the model answered Phishing, risk 95/100" in page


def test_no_pre_cap_answer_when_the_cap_changed_nothing(aws, findings):
    findings.value = {
        "brand_visual": browser_finding("brand_visual", True, [WARNING]),
    }
    run_scan.process_message(seed(), agentcore=TwoTurnHarness())
    record = store.get_scan("s1")
    assert record.verdict.capped_from is None
    assert "Before the page-not-observed cap" not in reports.render_scan_report(record)


def test_a_www_sibling_capture_is_stored_as_suspicious(aws, findings):
    # The certificate does not cover the www. name: only the bare host was seen.
    tls = {"name": "tls_error", "severity": "low", "evidence": "Certificate name error."}
    sibling = {"name": "www_sibling_capture", "severity": "low", "evidence": "Bare host."}
    findings.value = {
        "brand_visual": browser_finding("brand_visual", False, [tls, sibling]),
        "code_analyst": browser_finding("code_analyst", False, [tls, sibling]),
    }
    run_scan.process_message(seed(), agentcore=TwoTurnHarness())
    verdict = store.get_scan("s1").verdict
    assert (verdict.verdict, verdict.risk_score, verdict.action) == ("suspicious", 69, "warn")
    assert verdict.page_observed is False
    assert verdict.summary.startswith("Page not observed:")
    assert "same site without www. was captured instead" in verdict.report_markdown
