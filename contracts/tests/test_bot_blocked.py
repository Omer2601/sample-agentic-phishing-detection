# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""verdict_detail and the report note for the bot_blocked page state."""

from phish_backend.worker.verdict import judge, report_with_note
from phish_contracts.models import Finding, PageState, PageStateObservation, Usage, Verdict
from phish_contracts.page_state import BLOCK_PAGE, bot_blocked_report_note, verdict_detail


def finding(agent, observed, state=None, reason=None):
    return Finding(
        agent=agent,
        status="ok",
        verdict="unknown",
        confidence=40,
        usage=Usage(model_id="m"),
        latency_ms=1,
        page_observed=observed,
        page_state=PageStateObservation(page_state=state, reason=reason) if state else None,
    )


def blocked(agent="brand_visual"):
    return finding(agent, False, PageState.BOT_BLOCKED, BLOCK_PAGE)


def verdict():
    return Verdict(
        verdict="unknown", risk_score=40, confidence="low", action="warn", summary="Blocked."
    )


def test_both_captures_blocked_is_bot_blocked():
    detail = verdict_detail([blocked("brand_visual"), blocked("code_analyst")])
    assert detail.page_state == PageState.BOT_BLOCKED
    assert detail.reason == BLOCK_PAGE
    assert detail.agents == ["brand_visual", "code_analyst"]


def test_a_bot_wall_is_not_reported_once_another_capture_saw_the_page():
    assert verdict_detail([blocked("brand_visual"), finding("code_analyst", True)]) is None


def test_a_takedown_outranks_a_bot_wall():
    taken = finding("code_analyst", False, PageState.TAKEN_DOWN, "provider_suspended_page")
    assert verdict_detail([blocked(), taken]).page_state == PageState.TAKEN_DOWN


def test_judge_keeps_the_label_and_records_bot_blocked():
    judged = judge(verdict(), [blocked(), blocked("code_analyst")])
    assert (judged.verdict.value, judged.risk_score, judged.action.value) == ("unknown", 40, "warn")
    assert judged.verdict_detail.page_state == PageState.BOT_BLOCKED


def test_the_report_leads_with_the_bot_wall_note():
    findings = [blocked(), blocked("code_analyst")]
    report = report_with_note("## Report\n", verdict(), findings)
    assert report.startswith("> **Bot wall.**")
    assert "(block_page)" in report
    assert report.endswith("## Report\n")


def test_no_note_without_a_bot_wall():
    assert bot_blocked_report_note([finding("brand_visual", True)]) == ""
    assert bot_blocked_report_note([blocked(), finding("code_analyst", True)]) == ""
