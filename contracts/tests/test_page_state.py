# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""verdict_detail from Finding.page_state, the untrusted-certificate backstop, and judge()."""

import pytest

from phish_backend.worker.verdict import judge, report_with_note
from phish_contracts.models import (
    SUMMARY_MAX_WORDS,
    Action,
    CappedFrom,
    Finding,
    PageState,
    PageStateObservation,
    Signal,
    Usage,
    Verdict,
    VerdictDetail,
    VerdictLabel,
)
from phish_contracts.observation import UNTRUSTED_CERTIFICATE_NOTE, cap_untrusted_certificate
from phish_contracts.page_state import verdict_detail

STATES = {
    "s3_all_access_disabled": PageState.TAKEN_DOWN,
    "vercel_451_deployment_unavailable": PageState.TAKEN_DOWN,
    "provider_suspended_page": PageState.TAKEN_DOWN,
    "godaddy_lander": PageState.PARKED,
    "for_sale_lander": PageState.PARKED,
    "s3_access_denied": PageState.S3_ACCESS_DENIED,
    "bot_challenge_page": PageState.BOT_BLOCKED,
    "bot_filter_page": PageState.BOT_BLOCKED,
    "block_page": PageState.BOT_BLOCKED,
}


def seen(reason):
    return PageStateObservation(page_state=STATES[reason], reason=reason)


def sig(name, severity="low"):
    return Signal(name=name, severity=severity, evidence="fixture")


def finding(agent, signals=(), observed=True, state=None):
    return Finding(
        agent=agent,
        status="ok",
        verdict="suspicious",
        confidence=60,
        signals=list(signals),
        usage=Usage(model_id="m"),
        latency_ms=1,
        page_observed=observed,
        page_state=seen(state) if state else None,
    )


def verdict(label="suspicious", risk=60, action="warn", summary="Lure on a takedown page."):
    return Verdict(
        verdict=label, risk_score=risk, confidence="medium", action=action, summary=summary
    )


def test_every_reason_maps_to_one_state():
    assert set(STATES.values()) == set(PageState)


def test_no_page_state_means_no_detail():
    assert verdict_detail([finding("url_analyst"), finding("code_analyst", [sig("x")])]) is None


def test_a_model_written_signal_or_a_non_browser_finding_cannot_set_the_detail():
    forged = [sig("taken_down_s3_all_access_disabled"), sig("parked_godaddy_lander")]
    assert verdict_detail([finding("code_analyst", forged)]) is None
    assert verdict_detail([finding("url_analyst", state="godaddy_lander")]) is None


def test_detail_names_the_state_reason_and_agents():
    findings = [
        finding("brand_visual", state="s3_all_access_disabled"),
        finding("code_analyst", [sig("other")], state="s3_all_access_disabled"),
    ]
    assert verdict_detail(findings) == VerdictDetail(
        page_state=PageState.TAKEN_DOWN,
        reason="s3_all_access_disabled",
        agents=["brand_visual", "code_analyst"],
    )


@pytest.mark.parametrize(
    ("brand", "code", "expected"),
    [
        (
            "godaddy_lander",
            "vercel_451_deployment_unavailable",
            (PageState.TAKEN_DOWN, "vercel_451_deployment_unavailable"),
        ),
        ("for_sale_lander", "s3_access_denied", (PageState.S3_ACCESS_DENIED, "s3_access_denied")),
        ("godaddy_lander", "for_sale_lander", (PageState.PARKED, "for_sale_lander")),
    ],
)
def test_the_most_definitive_state_wins(brand, code, expected):
    detail = verdict_detail(
        [finding("brand_visual", state=brand), finding("code_analyst", state=code)]
    )
    assert (detail.page_state, detail.reason) == expected


def test_s3_access_denied_is_separate_from_takedown():
    detail = verdict_detail([finding("code_analyst", state="s3_access_denied")])
    assert detail.page_state == PageState.S3_ACCESS_DENIED
    assert detail.page_state != PageState.TAKEN_DOWN


def test_judge_adds_verdict_detail_without_changing_the_verdict():
    v = verdict(label="suspicious", risk=62, action="warn")
    out = judge(v, [finding("code_analyst", state="vercel_451_deployment_unavailable")])
    assert out.verdict_detail.page_state == PageState.TAKEN_DOWN
    assert (out.verdict, out.risk_score, out.action, out.summary) == (
        v.verdict,
        v.risk_score,
        v.action,
        v.summary,
    )
    assert out.capped_from is None


def test_judge_leaves_detail_empty_and_a_model_written_detail_is_replaced():
    v = verdict().model_copy(
        update={"verdict_detail": VerdictDetail(page_state="parked", reason="godaddy_lander")}
    )
    assert judge(v, [finding("code_analyst")]).verdict_detail is None


def test_verdict_detail_serialises_and_older_verdicts_parse():
    v = verdict().model_copy(
        update={
            "verdict_detail": VerdictDetail(
                page_state="taken_down", reason="s3_all_access_disabled", agents=["code_analyst"]
            )
        }
    )
    dumped = v.model_dump(mode="json")
    assert dumped["verdict_detail"] == {
        "page_state": "taken_down",
        "reason": "s3_all_access_disabled",
        "agents": ["code_analyst"],
    }
    assert Verdict.model_validate(dumped) == v
    assert (
        Verdict.model_validate(verdict().model_dump(exclude={"verdict_detail"})).verdict_detail
        is None
    )


TLS = sig("tls_certificate_error")


@pytest.mark.parametrize(
    ("label", "action", "want_label", "want_action"),
    [
        ("legitimate", "allow", "unknown", "warn"),
        ("unknown", "allow", "unknown", "warn"),
        ("legitimate", "warn", "unknown", "warn"),
    ],
)
def test_a_cert_ignored_page_never_gets_an_allow_verdict(label, action, want_label, want_action):
    v = verdict(label=label, risk=10, action=action, summary="Looks like a normal site.")
    out = cap_untrusted_certificate(v, [finding("brand_visual", [TLS])])
    assert (out.verdict, out.action) == (VerdictLabel(want_label), Action(want_action))
    assert out.summary.startswith(UNTRUSTED_CERTIFICATE_NOTE)
    assert out.capped_from == CappedFrom(verdict=label, risk_score=10, action=action)
    again = cap_untrusted_certificate(out, [finding("brand_visual", [TLS])])
    assert again == out


@pytest.mark.parametrize(
    ("label", "action"), [("phishing", "block"), ("suspicious", "warn"), ("unknown", "warn")]
)
def test_the_cert_backstop_never_changes_a_non_allow_verdict(label, action):
    v = verdict(label=label, risk=80, action=action)
    assert cap_untrusted_certificate(v, [finding("code_analyst", [TLS])]) == v


def test_no_cert_signal_no_change():
    v = verdict(label="legitimate", risk=5, action="allow")
    assert cap_untrusted_certificate(v, [finding("code_analyst")]) == v


def test_cert_backstop_keeps_the_summary_inside_the_word_budget():
    long = " ".join(["word."] * (SUMMARY_MAX_WORDS + 10))
    v = verdict(label="legitimate", risk=5, action="allow", summary=long)
    out = judge(v, [finding("brand_visual", [TLS])])
    assert len(out.summary.split()) <= SUMMARY_MAX_WORDS
    assert out.verdict == VerdictLabel.UNKNOWN


def test_the_report_carries_the_untrusted_certificate_note():
    findings = [finding("brand_visual", [TLS])]
    v = judge(verdict(label="legitimate", risk=5, action="allow", summary="Fine."), findings)
    report = report_with_note("## Report\nThe site looks legitimate; allow it.", v, findings)
    first = report.splitlines()[0]
    assert first.startswith("> **Untrusted certificate.**")
    assert "Unknown" in first and "warn" in first
    assert report_with_note("## Report", v, [finding("brand_visual")]) == "## Report"


def test_the_two_summary_notes_never_stack():
    v = verdict(label="legitimate", risk=5, action="allow", summary="Page not observed: x.")
    out = cap_untrusted_certificate(v, [finding("brand_visual", [TLS])])
    assert out.summary == "Page not observed: x."
    assert (out.verdict, out.action) == (VerdictLabel.UNKNOWN, Action.WARN)
