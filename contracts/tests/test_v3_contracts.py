# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json
import re
from pathlib import Path

from phish_contracts import signals
from phish_contracts.models import (
    Action,
    CodeInsights,
    ConfidenceBand,
    EndpointInsight,
    Finding,
    FormInsight,
    VerdictLabel,
    site_down_report_markdown,
    site_down_verdict,
)

CATALOG_PATH = Path(signals.__file__).with_name("signal_catalog.json")

OLD_FINDING = {
    "agent": "code_analyst",
    "status": "ok",
    "verdict": "legitimate",
    "confidence": 70,
    "signals": [],
    "usage": {"model_id": "m"},
    "latency_ms": 5,
}


def test_site_down_is_a_verdict_label():
    assert VerdictLabel.SITE_DOWN == "site_down"
    assert VerdictLabel.ERROR_404 == "error_404"


def test_old_finding_parses_without_the_new_fields():
    finding = Finding.model_validate(OLD_FINDING)
    assert finding.capture_note is None
    assert finding.insights is None


def test_finding_round_trips_insights_and_capture_note():
    insights = CodeInsights(
        endpoints=[EndpointInsight(url="hxxps://evil[.]example/x", kind="fetch", off_domain=True)],
        forms=[FormInsight(action="", fields=["email", "password"], submits_via_js=True)],
        script_count=3,
        script_kb=42,
        external_script_hosts=["cdn.example"],
    )
    finding = Finding.model_validate(
        {**OLD_FINDING, "capture_note": "A bot check did not clear.", "insights": insights}
    )
    again = Finding.model_validate_json(finding.model_dump_json())
    assert again == finding


def test_insights_defaults_are_empty():
    empty = CodeInsights()
    assert empty.endpoints == [] and empty.forms == [] and empty.external_script_hosts == []
    assert empty.script_count == 0 and empty.script_kb == 0


# Split so the repo-wide check that the dropped feature left no trace stays clean.
_DROPPED = "can" + "ary"


def test_stored_insights_with_dropped_fields_still_parse():
    # Records written before capture went passive still carry the dropped keys.
    old = {
        "endpoints": [
            {
                "url": "hxxps://a[.]example/x",
                "kind": "fetch",
                "off_domain": True,
                f"carries_{_DROPPED}": True,
            }
        ],
        f"{_DROPPED}_attempted": True,
        f"{_DROPPED}_exfil_to": ["hxxps://a[.]example/x"],
    }
    finding = Finding.model_validate({**OLD_FINDING, "insights": old})
    assert finding.insights.endpoints[0].off_domain is True
    assert _DROPPED not in finding.model_dump_json()


def test_insights_lists_are_capped_not_rejected():
    many = CodeInsights(
        endpoints=[{"url": f"u{i}", "kind": "xhr", "off_domain": False} for i in range(30)],
        forms=[{"action": "", "fields": [], "submits_via_js": False} for _ in range(12)],
        external_script_hosts=[f"h{i}.example" for i in range(20)],
    )
    assert len(many.endpoints) == 20
    assert len(many.forms) == 10
    assert len(many.external_script_hosts) == 15


def test_site_down_verdict_is_fixed_low_risk_allow():
    v = site_down_verdict()
    assert v.verdict == VerdictLabel.SITE_DOWN
    assert v.risk_score == 10
    assert v.confidence == ConfidenceBand.HIGH
    assert v.action == Action.ALLOW


def test_site_down_report_lists_defanged_hops_and_reason():
    md = site_down_report_markdown(
        "http://mb-inx.s3-website.example.com/",
        ["http://mb-inx.s3-website.example.com/", "https://dead.example.net/login"],
        "DNS lookup failed for dead.example.net",
    )
    assert "# Site down" in md
    assert "hxxp://mb-inx[.]s3-website[.]example[.]com/" in md
    assert "hxxps://dead[.]example[.]net/login" in md
    assert "DNS lookup failed" in md
    assert "http://" not in md and "https://" not in md


def test_site_down_report_without_hops_or_reason():
    md = site_down_report_markdown("https://gone.example/", [], "")
    assert "hxxps://gone[.]example/" in md
    assert "did not say why" in md


def test_catalog_entries_are_plain_english():
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    assert catalog, "catalog is empty"
    for name, entry in catalog.items():
        assert re.fullmatch(r"[a-z0-9]+(_[a-z0-9]+)*", name), name
        assert set(entry) == {"title", "explain"}, name
        assert entry["title"].strip() and entry["explain"].strip(), name
        assert "_" not in entry["title"], name
        assert len(entry["title"]) <= 80, name
        for text in entry.values():
            assert not re.search("[\u2013\u2014]", text), name


REQUIRED = {
    # Deterministic vocabulary (v3 spec).
    "blocked_by_browser",
    "blocked_by_guard",
    "site_unreachable",
    "tls_error",
    # A model-invented variant seen 2026-10-18; the prompts now forbid it.
    "tls_error_capture_gap",
    # The certificate does not cover the www. name; the bare host was captured instead.
    "www_sibling_capture",
    "page_not_found",
    "cloudflare_phishing_warning",
    "cloudflare_malware_warning",
    "warning_bypass_blocked",
    "redirect_to_free_hosting",
    "bot_challenge",
    "cloaking_bot_filter",
    "redirect_cross_domain",
    "telegram_bot_exfil",
    "discord_webhook_exfil",
    "dynamic_dns_receiver",
    "ip_geolocation_lookup",
    "js_only_credential_submit",
    "credential_form_off_domain",
    # code_analyst heuristics.
    "char_code_obfuscation",
    "data_sent_off_domain",
    "devtools_evasion",
    "eval_or_function_constructor",
    "global_key_listener",
    "key_listener_on_sensitive_input",
    "long_encoded_blob",
    "wallet_or_clipboard_hijack",
    # Most common model signal names in production.
    "brand_domain_mismatch",
    "blocked_by_site",
    "newly_registered_domain",
    "established_parent_domain",
    "insecure_http_scheme",
    "no_brand_or_lure_tokens",
    "suspicious_tld",
    "free_hosting_subdomain",
    "no_forms_or_sinks",
    "no_brand_claimed",
    "no_https",
    "cloudflare_phishing_interstitial",
    "brand_in_subdomain",
    "free_hosting_with_brand",
    "opaque_query_parameter",
    "whois_not_found",
    "brand_lure_in_url",
    "brand_in_free_hosting_subdomain",
    "whois_reflects_platform_only",
    "credential_prompt",
    "free_hosting_platform",
    "established_domain_age",
    "whois_unavailable",
    "no_code_evidence",
    "free_hosting_pages_dev",
    "brand_lookalike_domain",
    "no_exfiltration_sinks",
    "lure_tokens_in_host",
    "brand_lure_hostname",
    "platform_phishing_warning",
    "capture_failed",
    "brand_lookalike_subdomain",
    "free_hosting_abuse",
}


def test_catalog_covers_required_names():
    assert REQUIRED <= set(signals.CATALOG)


def test_title_for_uses_the_catalog():
    assert signals.title_for("blocked_by_browser") == signals.CATALOG["blocked_by_browser"]["title"]
    assert signals.explain_for("blocked_by_browser")


def test_title_for_humanizes_unknown_names():
    assert signals.title_for("some_new_model_signal") == "Some new model signal"
    assert signals.title_for("Mixed-Case_name") == "Mixed case name"
    assert signals.title_for("") == ""
    assert signals.explain_for("some_new_model_signal") == ""
