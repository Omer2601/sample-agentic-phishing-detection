# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Read the orchestrator's final answer.

The parsers live in phish_contracts so the eval script shares them. The worker's wrappers
also make the model's prose safe to show and store: every URL in it is defanged (an analyst
must not be able to click a phishing link in a report), and the summary is held to the
prompt's word budget. The scan's own `url` field is never touched.

judge() then applies the page-not-observed rule (phish_contracts.observation): a provider
warning that hid the real page holds the verdict at suspicious, whatever the model answered.
It also keeps a page seen only with certificate checks ignored out of an allow verdict
(cap_untrusted_certificate) and records the deterministic page state as verdict_detail
(phish_contracts.page_state). Neither changes how the label or risk is otherwise reached.
"""

import json
from collections.abc import Sequence

from phish_contracts.models import (
    SUMMARY_MAX_WORDS,
    Finding,
    ReportMissing,
    Verdict,
    VerdictMissing,
    _repair_enum_quotes,
    cap_words,
    defang_text,
    extract_report,
    extract_verdict,
)
from phish_contracts.observation import (
    cap_unobserved_warning,
    cap_untrusted_certificate,
    page_not_observed_report_note,
    untrusted_certificate_report_note,
)
from phish_contracts.page_state import bot_blocked_report_note, verdict_detail

__all__ = [
    "ReportMissing",
    "VerdictMissing",
    "judge",
    "no_verdict_shape",
    "parse_report",
    "parse_verdict",
    "readable",
    "report_with_note",
]


def readable(verdict: Verdict) -> Verdict:
    """The verdict with defanged prose and a summary of at most SUMMARY_MAX_WORDS words."""
    return verdict.model_copy(
        update={
            "summary": cap_words(defang_text(verdict.summary), SUMMARY_MAX_WORDS),
            "disagreements": [defang_text(x) for x in verdict.disagreements],
            "missed_by_specialists": [defang_text(x) for x in verdict.missed_by_specialists],
            "report_markdown": defang_text(verdict.report_markdown),
        }
    )


def parse_verdict(text: str) -> Verdict:
    return readable(extract_verdict(text))


def parse_report(text: str) -> str:
    return defang_text(extract_report(text))


def judge(verdict: Verdict, findings: Sequence[Finding]) -> Verdict:
    """The verdict to store: the page-not-observed cap and the untrusted-certificate cap
    applied to the model's verdict, and the recognised page state as verdict_detail."""
    verdict = cap_untrusted_certificate(cap_unobserved_warning(verdict, findings), findings)
    return verdict.model_copy(update={"verdict_detail": verdict_detail(findings)})


def report_with_note(report: str, verdict: Verdict, findings: Sequence[Finding]) -> str:
    """The report, led by the page-not-observed, untrusted-certificate and bot-wall notes when
    they apply (no-op otherwise)."""
    return (
        page_not_observed_report_note(verdict, findings)
        + untrusted_certificate_report_note(verdict, findings)
        + bot_blocked_report_note(findings)
        + report
    )


def no_verdict_shape(text: str) -> dict[str, object]:
    """Log-safe metadata about an answer that had no verdict: never any of its text.

    The answer can echo the submitted URL or attacker page text, so only lengths, counts,
    the decoder's own error message and offset, and a fixed classification leave here.
    """
    stripped = text.strip()
    start, end = text.find("{"), text.rfind("}")
    json_error, json_error_pos = None, None
    if start != -1:
        try:
            json.loads(text[start : end + 1] if end > start else text[start:])
        except json.JSONDecodeError as exc:  # msg and pos never include the input text
            json_error, json_error_pos = exc.msg, start + exc.pos
    opens, closes = text.count("{"), text.count("}")
    if start == -1:
        shape = "no_json_object"
    elif opens > closes:
        shape = "truncated"
    elif _repair_enum_quotes(text) != text:
        shape = "unquoted_enum_value"
    elif json_error is not None:
        shape = "invalid_json"
    else:
        shape = "schema_invalid"
    return {
        "text_chars": len(text),
        "starts_with_brace": stripped.startswith("{"),
        "ends_with_brace": stripped.endswith("}"),
        "json_error": json_error,
        "json_error_pos": json_error_pos,
        "open_braces": opens,
        "close_braces": closes,
        "quotes": text.count('"'),
        "shape": shape,
    }
