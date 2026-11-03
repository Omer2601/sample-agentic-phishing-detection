# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The page-not-observed cap: a provider warning alone never makes a scan phishing."""

import pytest

from phish_contracts.models import (
    SUMMARY_MAX_WORDS,
    CappedFrom,
    Finding,
    RedirectHop,
    Signal,
    Usage,
    Verdict,
    extract_verdict,
)
from phish_contracts.observation import (
    PAGE_NOT_OBSERVED_NOTE,
    UNOBSERVED_RISK_CAP,
    cap_unobserved_warning,
    page_not_observed_report_note,
    page_observed,
)

WARNING = Signal(name="cloudflare_phishing_warning", severity="high", evidence="Cloudflare.")


def finding(agent, observed=None, signals=()):
    return Finding(
        agent=agent,
        status="ok",
        verdict="suspicious",
        confidence=60,
        signals=list(signals),
        usage=Usage(model_id="m"),
        latency_ms=1,
        page_observed=observed,
    )


def verdict(label="phishing", risk=85, action="block", summary="Throwaway host."):
    return Verdict(
        verdict=label, risk_score=risk, confidence="medium", action=action, summary=summary
    )


UNSEEN = [
    finding("url_analyst"),
    finding("brand_visual", False, [WARNING]),
    finding("code_analyst", False, [WARNING]),
]


def test_warning_with_no_real_page_is_capped_and_noted():
    out = cap_unobserved_warning(verdict(), UNSEEN)
    assert (out.verdict, out.risk_score, out.action) == ("suspicious", UNOBSERVED_RISK_CAP, "warn")
    assert out.page_observed is False
    assert out.summary == f"{PAGE_NOT_OBSERVED_NOTE} Throwaway host."
    assert out.confidence == "medium"


def test_cap_is_idempotent_and_keeps_lower_risk():
    once = cap_unobserved_warning(verdict("suspicious", 55, "warn"), UNSEEN)
    twice = cap_unobserved_warning(once, UNSEEN)
    assert twice == once and once.risk_score == 55 and once.summary.count("Page not") == 1


@pytest.mark.parametrize(
    "findings",
    [
        [finding("brand_visual", True, [WARNING]), finding("code_analyst", False, [WARNING])],
        [finding("brand_visual", False), finding("code_analyst", False)],
        [finding("url_analyst", None, [WARNING])],
        [],
    ],
)
def test_no_cap_when_the_page_was_seen_or_no_warning_or_unknown(findings):
    out = cap_unobserved_warning(verdict(), findings)
    assert (out.verdict, out.risk_score, out.action) == ("phishing", 85, "block")
    assert PAGE_NOT_OBSERVED_NOTE not in out.summary


def test_page_observed_reads_only_browser_findings():
    assert page_observed([finding("url_analyst", True)]) is None
    assert page_observed([finding("brand_visual", False), finding("code_analyst", True)]) is True
    assert page_observed([finding("brand_visual", False)]) is False


def test_report_note_names_the_stored_verdict():
    capped = cap_unobserved_warning(verdict(), UNSEEN)
    note = page_not_observed_report_note(capped, UNSEEN)
    assert "**Page not observed.**" in note and "Suspicious with risk 69/100" in note
    assert page_not_observed_report_note(capped, []) == ""


def test_long_summaries_stay_inside_the_word_budget():
    out = cap_unobserved_warning(verdict(summary="word " * 60), UNSEEN)
    assert len(out.summary.split()) == 50 and out.summary.startswith(PAGE_NOT_OBSERVED_NOTE)


def test_redirect_chain_is_bounded_and_older_findings_parse():
    hops = [RedirectHop(url="https://a.example/" + "x" * 3000)] * 15
    f = finding("brand_visual").model_copy(update={})
    f = Finding.model_validate({**f.model_dump(), "redirect_chain": [h.model_dump() for h in hops]})
    assert len(f.redirect_chain) == 10 and len(f.redirect_chain[0].url) == 1024
    legacy = Finding.model_validate(
        {k: v for k, v in finding("code_analyst").model_dump().items() if k != "page_observed"}
    )
    assert legacy.redirect_chain == [] and legacy.page_observed is None


def test_model_lead_in_is_kept_unchanged():
    # Repro d304c03e: the model already led with the note, so nothing is prepended or cut.
    text = (
        "Page not observed: Cloudflare shows its 'Suspected Malware' warning in front of this "
        "random-named throwaway pages[.]dev subdomain, and the browser could not get past it. "
        "That is strong outside evidence of abuse, but the real page was never seen."
    )
    for summary in (text, text.replace("Page not observed", "page NOT observed", 1)):
        out = cap_unobserved_warning(verdict(summary=summary), UNSEEN)
        assert out.summary == summary
        assert out.summary.lower().count("page not observed") == 1


def test_prepended_note_is_short_and_the_cut_keeps_whole_sentences():
    first = "Cloudflare warns about this throwaway pages[.]dev host. "
    summary = first * 6 + "The browser could not get past the warning to the real page."
    assert len(summary.split()) > SUMMARY_MAX_WORDS - len(PAGE_NOT_OBSERVED_NOTE.split())
    out = cap_unobserved_warning(verdict(summary=summary), UNSEEN)
    assert out.summary == f"{PAGE_NOT_OBSERVED_NOTE} {(first * 6).strip()}"
    assert len(out.summary.split()) <= SUMMARY_MAX_WORDS
    assert len(PAGE_NOT_OBSERVED_NOTE.split()) <= 4


def test_cap_records_what_the_model_answered_and_only_when_it_changed_something():
    out = cap_unobserved_warning(verdict(), UNSEEN)
    assert out.capped_from == CappedFrom(verdict="phishing", risk_score=85, action="block")
    assert cap_unobserved_warning(out, UNSEEN).capped_from == out.capped_from
    unchanged = cap_unobserved_warning(verdict("suspicious", 55, "warn"), UNSEEN)
    assert unchanged.capped_from is None
    assert cap_unobserved_warning(verdict(), []).capped_from is None


def test_a_model_written_capped_from_is_ignored():
    text = (
        '{"verdict":"legitimate","risk_score":5,"confidence":"high","action":"allow",'
        '"summary":"ok","capped_from":{"verdict":"phishing","risk_score":99,"action":"block"}}'
    )
    assert extract_verdict(text).capped_from is None


SIBLING = Signal(name="www_sibling_capture", severity="low", evidence="Bare host captured.")
TLS = Signal(name="tls_error", severity="low", evidence="Certificate name error.")
SIBLING_ONLY = [
    finding("url_analyst"),
    finding("brand_visual", False, [TLS, SIBLING]),
    finding("code_analyst", False, [TLS, SIBLING]),
]


def test_www_sibling_capture_gets_the_same_cap_and_its_own_report_note():
    # 2026-10-26 rerun: the certificate does not cover www., so only the bare host was seen.
    out = cap_unobserved_warning(verdict(), SIBLING_ONLY)
    assert (out.verdict, out.risk_score, out.action) == ("suspicious", UNOBSERVED_RISK_CAP, "warn")
    assert out.page_observed is False and out.summary.startswith(PAGE_NOT_OBSERVED_NOTE)
    assert out.capped_from == CappedFrom(verdict="phishing", risk_score=85, action="block")
    note = page_not_observed_report_note(out, SIBLING_ONLY)
    assert "same site without www. was captured instead" in note
    assert "certificate warning" in note and "provider warning" not in note


def test_no_sibling_cap_when_a_browser_capture_saw_the_submitted_page():
    seen = [finding("brand_visual", False, [SIBLING]), finding("code_analyst", True)]
    out = cap_unobserved_warning(verdict(), seen)
    assert (out.verdict, out.risk_score, out.action) == ("phishing", 85, "block")
