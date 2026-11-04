# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Verdict-first contract: report_status, compact verdict, report turn, 404 fast path."""

import json
from datetime import UTC, datetime

import pytest

from phish_contracts.disclaimer import DISCLAIMER_MARKDOWN, with_disclaimer_markdown
from phish_contracts.models import (
    REPORT_FOLLOWUP_MESSAGE,
    ReportMissing,
    ReportStatus,
    ScanRecord,
    ScanStatus,
    Verdict,
    VerdictLabel,
    VerdictMissing,
    build_report_recovery_message,
    error_404_report_markdown,
    error_404_verdict,
    extract_report,
    extract_verdict,
)

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)
COMPACT = {
    "verdict": "phishing",
    "risk_score": 91,
    "confidence": "high",
    "action": "block",
    "summary": "Looks like a bank login clone.",
}


def record(**over):
    base = {
        "scan_id": "s1",
        "owner": "o",
        "url": "https://a.example/",
        "status": ScanStatus.COMPLETE,
        "queued_at": NOW,
    }
    return ScanRecord(**{**base, **over})


def test_legacy_record_parses_as_ready():
    rec = ScanRecord.model_validate(
        {
            "scan_id": "s1",
            "owner": "o",
            "url": "u",
            "status": "COMPLETE",
            "queued_at": "2026-10-05T12:00:00Z",
        }
    )
    assert rec.report_status is ReportStatus.READY
    assert rec.report_started_at is None and rec.report_error is None


def test_report_fields_serialize_as_iso_strings():
    rec = record(
        report_status=ReportStatus.FAILED,
        report_started_at=NOW,
        report_ready_at=NOW,
        report_error="not enough time",
    )
    dumped = rec.model_dump(mode="json")
    assert dumped["report_status"] == "FAILED"
    assert dumped["report_started_at"] == "2026-10-05T12:00:00Z"
    assert dumped["report_ready_at"] == "2026-10-05T12:00:00Z"
    assert dumped["report_error"] == "not enough time"
    assert ScanRecord.model_validate(dumped) == rec


@pytest.mark.parametrize("wrap", ["bare", "fenced", "tagged", "prose"])
def test_compact_verdict_parses_in_every_shape(wrap):
    body = json.dumps(COMPACT)
    text = {
        "bare": body,
        "fenced": f"```json\n{body}\n```",
        "tagged": f"<verdict>{body}</verdict>",
        "prose": f"Here is the result: {body} done.",
    }[wrap]
    verdict = extract_verdict(text)
    assert verdict.verdict is VerdictLabel.PHISHING and verdict.report_markdown == ""


def test_verdict_with_report_still_parses_for_older_orchestrators():
    text = "<verdict>" + json.dumps({**COMPACT, "report_markdown": "# r"}) + "</verdict>"
    assert extract_verdict(text).report_markdown == "# r"


def test_last_bare_verdict_wins_and_garbage_raises():
    first = json.dumps({**COMPACT, "risk_score": 1})
    assert extract_verdict(first + "\n" + json.dumps(COMPACT)).risk_score == 91
    for text in ("", "no json here", '{"verdict": "nope"}', '{"other": 1}'):
        with pytest.raises(VerdictMissing):
            extract_verdict(text)


@pytest.mark.parametrize("wrap", ["bare", "fenced", "tagged"])
def test_report_parses(wrap):
    body = json.dumps({"report_markdown": "# Report\n\nbody {braces}"})
    text = {"bare": body, "fenced": f"```json\n{body}\n```", "tagged": f"<report>{body}</report>"}[
        wrap
    ]
    assert extract_report(text) == "# Report\n\nbody {braces}"


@pytest.mark.parametrize(
    "text", ["", "plain text", '{"report_markdown": ""}', '{"report_markdown": 3}', '{"x": 1}']
)
def test_bad_report_raises(text):
    with pytest.raises(ReportMissing):
        extract_report(text)


def test_error_404_verdict_and_report():
    verdict = error_404_verdict()
    assert (verdict.verdict, verdict.risk_score) == (VerdictLabel.ERROR_404, 10)
    assert verdict.confidence.value == "high" and verdict.action.value == "allow"
    assert verdict.summary.count(".") == 1
    report = error_404_report_markdown("https://gone.example/x", "https://gone.example/y")
    assert "HTTP 404" in report and "hxxps://gone[.]example/x" in report
    assert "https://gone.example" not in report
    wrapped = with_disclaimer_markdown(report)
    assert wrapped.startswith(DISCLAIMER_MARKDOWN) and wrapped.endswith(DISCLAIMER_MARKDOWN)


def test_recovery_message_ends_with_the_followup_and_drops_any_report():
    verdict = Verdict.model_validate({**COMPACT, "report_markdown": "SECRET-DRAFT"})
    message = build_report_recovery_message("https://a.example/", "s1", verdict, [])
    assert message.endswith(REPORT_FOLLOWUP_MESSAGE)
    assert "SECRET-DRAFT" not in message and "scan_id: s1" in message
