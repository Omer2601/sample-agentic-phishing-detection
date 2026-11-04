# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json
import os

import boto3
import pytest

from phish_backend.worker.findings import MAX_SIGNALS, load_findings
from phish_backend.worker.verdict import VerdictMissing, parse_verdict

VERDICT = {
    "verdict": "phishing",
    "risk_score": 95,
    "confidence": "high",
    "action": "block",
    "summary": "Credential harvest",
    "disagreements": [],
    "missed_by_specialists": [],
    "report_markdown": "# Report",
}


def test_last_verdict_block_wins():
    text = f'<verdict>{{"x": 1}}</verdict> thinking <verdict>{json.dumps(VERDICT)}</verdict>'
    assert parse_verdict(text).risk_score == 95


def test_fenced_json_inside_block():
    assert (
        parse_verdict(f"<verdict>\n```json\n{json.dumps(VERDICT)}\n```\n</verdict>").action
        == "block"
    )


@pytest.mark.parametrize(
    "text", ["", "no block", "<verdict>{bad json}</verdict>", '<verdict>{"verdict": "x"}</verdict>']
)
def test_missing_or_invalid_raises(text):
    with pytest.raises(VerdictMissing):
        parse_verdict(text)


def finding(agent, signals=1):
    return {
        "agent": agent,
        "status": "ok",
        "verdict": "phishing",
        "confidence": 80,
        "signals": [{"name": f"s{i}", "severity": "high", "evidence": "e"} for i in range(signals)],
        "artifacts": [],
        "usage": {"input_tokens": 10, "output_tokens": 5, "model_id": "m"},
        "latency_ms": 900,
        "calls": [],
    }


def test_load_findings_fills_gaps_and_caps_signals(aws):
    s3 = boto3.client("s3", region_name="us-west-2")
    s3.put_object(
        Bucket=os.environ["ARTIFACTS_BUCKET"],
        Key="scans/s1/findings/url_analyst.json",
        Body=json.dumps(finding("url_analyst", signals=30)),
    )
    s3.put_object(
        Bucket=os.environ["ARTIFACTS_BUCKET"],
        Key="scans/s1/findings/code_analyst.json",
        Body=b"{not json",
    )
    found = load_findings("s1", "global.anthropic.claude-sonnet-5-5")
    assert [f.agent for f in found] == ["url_analyst", "brand_visual", "code_analyst"]
    assert len(found[0].signals) == MAX_SIGNALS
    assert found[1].status == "error" and "no finding" in found[1].signals[0].evidence
    assert found[2].status == "error" and "validation" in found[2].signals[0].evidence


def test_access_denied_counts_as_missing_and_logs_once(monkeypatch, caplog):
    from botocore.exceptions import ClientError

    from phish_backend.worker import findings as findings_mod

    class DeniedS3:
        def get_object(self, **kwargs):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, "GetObject")

    def fake_s3():
        return DeniedS3()

    fake_s3.cache_clear = lambda: None  # clients.reset() clears every cached client
    monkeypatch.setattr(findings_mod.clients, "s3", fake_s3)
    monkeypatch.setattr(findings_mod, "_denied_logged", False)
    with caplog.at_level("WARNING"):
        first = load_findings("s1", "m")
        second = load_findings("s2", "m")
    assert [f.status for f in first + second] == ["error"] * 6
    assert "no finding" in first[0].signals[0].evidence
    assert sum("AccessDenied" in r.getMessage() for r in caplog.records) == 1


def test_error_404_verdict_parses():
    text = f"<verdict>{json.dumps({**VERDICT, 'verdict': 'error_404', 'risk_score': 10})}</verdict>"
    parsed = parse_verdict(text)
    assert parsed.verdict == "error_404" and parsed.risk_score == 10
