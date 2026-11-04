# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The page-not-observed rule, applied by code after the orchestrator's verdict.

A provider warning (Cloudflare's "Suspected Phishing", "Suspected Misleading Website" or
"Suspected Malware" page) is strong supporting evidence, but it is a third party's opinion, not
the page. The browser tries once to proceed past it
(phish_agents.common.browser.proceed_past_warning). When no browser capture saw the real page,
the scan is held at `suspicious` with risk at most UNOBSERVED_RISK_CAP and a "Page not observed"
note, whatever the model answered. The same hold applies when a browser capture saw only the
www. sibling (`www_sibling_capture`: the certificate does not cover the submitted www. name, so
visitors get a certificate warning and the submitted page was not observed). The orchestrator
prompt asks for the same; this is the deterministic backstop, shared by the worker and the eval
script.
"""

from collections.abc import Sequence

from phish_contracts.models import (
    SUMMARY_MAX_WORDS,
    Action,
    CappedFrom,
    Finding,
    Verdict,
    VerdictLabel,
    cap_words,
)

PROVIDER_WARNING_SIGNALS = frozenset({"cloudflare_phishing_warning", "cloudflare_malware_warning"})
WWW_SIBLING_SIGNAL = "www_sibling_capture"
BROWSER_AGENTS = frozenset({"brand_visual", "code_analyst"})
# Below the 70 that the pre-publish gate example and `action: block` treat as phishing.
UNOBSERVED_RISK_CAP = 69
# Short on purpose: it shares the summary's word budget with the model's text, and the report
# note and the web notice already explain the rule. The prompt asks the model for this lead-in.
PAGE_NOT_OBSERVED_NOTE = "Page not observed:"
_SENTENCE_END = (".", "!", "?")


def page_observed(findings: Sequence[Finding]) -> bool | None:
    """True when a browser capture saw the real page, False when none did, None when unknown."""
    seen = [
        f.page_observed
        for f in findings
        if f.agent in BROWSER_AGENTS and f.page_observed is not None
    ]
    return any(seen) if seen else None


def provider_warned(findings: Sequence[Finding]) -> bool:
    return any(s.name in PROVIDER_WARNING_SIGNALS for f in findings for s in f.signals)


def warning_hid_page(findings: Sequence[Finding]) -> bool:
    """A provider warning was shown and no browser capture got past it to the real page."""
    return provider_warned(findings) and page_observed(findings) is False


def sibling_only(findings: Sequence[Finding]) -> bool:
    """Only the www. sibling was captured: no browser capture saw the submitted page."""
    seen = any(s.name == WWW_SIBLING_SIGNAL for f in findings for s in f.signals)
    return seen and page_observed(findings) is False


def unobserved_capped(findings: Sequence[Finding]) -> bool:
    """The page-not-observed cap applies: a warning hid the page, or only the sibling was seen."""
    return warning_hid_page(findings) or sibling_only(findings)


def cap_unobserved_warning(verdict: Verdict, findings: Sequence[Finding]) -> Verdict:
    """Record page_observed and, when a warning hid the page, hold the verdict at suspicious."""
    update: dict = {"page_observed": page_observed(findings)}
    if unobserved_capped(findings):
        if verdict.verdict == VerdictLabel.PHISHING:
            update["verdict"] = VerdictLabel.SUSPICIOUS
        update["risk_score"] = min(verdict.risk_score, UNOBSERVED_RISK_CAP)
        if verdict.action == Action.BLOCK:
            update["action"] = Action.WARN
        before = CappedFrom(
            verdict=verdict.verdict, risk_score=verdict.risk_score, action=verdict.action
        )
        after = before.model_copy(
            update={k: v for k, v in update.items() if k in CappedFrom.model_fields}
        )
        if after != before and verdict.capped_from is None:
            update["capped_from"] = before
        if not verdict.summary.lstrip().lower().startswith("page not observed"):
            budget = SUMMARY_MAX_WORDS - len(PAGE_NOT_OBSERVED_NOTE.split())
            rest = _fit(verdict.summary.strip(), budget)
            update["summary"] = f"{PAGE_NOT_OBSERVED_NOTE} {rest}".strip()
    return verdict.model_copy(update=update)


# A page captured with certificate checks ignored (phish_agents.common.capture_recovery) is not
# authenticated: a man in the middle or a look-alike host could have served it. Its content is
# evidence of what the host served, never grounds to clear the site.
TLS_CERTIFICATE_SIGNAL = "tls_certificate_error"
UNTRUSTED_CERTIFICATE_NOTE = "Untrusted certificate:"


def untrusted_certificate(findings: Sequence[Finding]) -> bool:
    return any(s.name == TLS_CERTIFICATE_SIGNAL for f in findings for s in f.signals)


def cap_untrusted_certificate(verdict: Verdict, findings: Sequence[Finding]) -> Verdict:
    """No allow verdict rests on a page seen through an invalid certificate: `legitimate`
    becomes `unknown` and `allow` becomes `warn`. Every other verdict is kept as is."""
    if not untrusted_certificate(findings):
        return verdict
    if verdict.verdict != VerdictLabel.LEGITIMATE and verdict.action != Action.ALLOW:
        return verdict
    update: dict = {}
    if verdict.verdict == VerdictLabel.LEGITIMATE:
        update["verdict"] = VerdictLabel.UNKNOWN
    if verdict.action == Action.ALLOW:
        update["action"] = Action.WARN
    if verdict.capped_from is None:
        update["capped_from"] = CappedFrom(
            verdict=verdict.verdict, risk_score=verdict.risk_score, action=verdict.action
        )
    # One lead-in only: a summary already led by either note keeps it.
    lead = verdict.summary.lstrip().lower()
    if not lead.startswith((UNTRUSTED_CERTIFICATE_NOTE.lower(), "page not observed")):
        budget = SUMMARY_MAX_WORDS - len(UNTRUSTED_CERTIFICATE_NOTE.split())
        rest = _fit(verdict.summary.strip(), budget)
        update["summary"] = f"{UNTRUSTED_CERTIFICATE_NOTE} {rest}".strip()
    return verdict.model_copy(update=update)


def _fit(text: str, limit: int) -> str:
    """text when it has at most `limit` words, else cut at its last whole sentence that fits,
    or at a word boundary when not even the first sentence fits."""
    words = text.split()
    if len(words) <= limit:
        return text
    ends = [i for i, w in enumerate(words[:limit]) if w.endswith(_SENTENCE_END)]
    if ends:
        return " ".join(words[: ends[-1] + 1])
    return cap_words(text, limit)


def page_not_observed_report_note(verdict: Verdict, findings: Sequence[Finding]) -> str:
    """A markdown line put above the report when the cap applies, else ""."""
    if not unobserved_capped(findings):
        return ""
    why = (
        "A provider warning stood in front of the site and the browser could not get past it, "
        "so the real page was never seen."
        if warning_hid_page(findings)
        else "The certificate does not cover the www. name, so the same site without www. was "
        "captured instead; visitors to this link see a certificate warning."
    )
    return (
        f"> **Page not observed.** {why} The verdict is held at "
        f"{verdict.verdict.value.capitalize()} with risk {verdict.risk_score}/100 (at most "
        f"{UNOBSERVED_RISK_CAP}), whatever the text below says.\n\n"
    )


def untrusted_certificate_report_note(verdict: Verdict, findings: Sequence[Finding]) -> str:
    """A markdown line put above the report when a page was seen only with certificate checks
    ignored, else "". The report text may have been written before the cap and still read as
    legitimate or allow; the note states what holds."""
    if not untrusted_certificate(findings):
        return ""
    return (
        "> **Untrusted certificate.** The page was captured with certificate checks ignored, "
        "so its content is not authenticated and cannot clear the site. The verdict is "
        f"{verdict.verdict.value.capitalize()} with action {verdict.action.value}, whatever "
        "the text below says.\n\n"
    )
