# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""HTML reports: escaping, content, owner isolation and the two report routes."""

import json
import re
from datetime import timedelta
from decimal import Decimal
from urllib.parse import parse_qs, urlparse

import boto3
from backend_testkit import OWNER_A, OWNER_B, api_event, put_batch_for_tests, utcnow

from phish_backend.api import app
from phish_backend.common import store
from phish_backend.reports import html as reports
from phish_contracts.disclaimer import DISCLAIMER_TEXT, DISCLAIMER_TITLE
from phish_contracts.models import (
    BatchRecord,
    Call,
    CallKind,
    Finding,
    ScanRecord,
    ScanStatus,
    Signal,
    Usage,
    Verdict,
)

EVIL = '<script>alert("x")</script>'
BUCKET = "phish-artifacts-123456789012-us-west-2"


def finding(agent, verdict="phishing", confidence=90, **over):
    base = {
        "agent": agent,
        "status": "ok",
        "verdict": verdict,
        "confidence": confidence,
        "signals": [Signal(name=f"sig {EVIL}", severity="high", evidence=f"ev {EVIL}")],
        "usage": Usage(input_tokens=100, output_tokens=20, model_id="global.m"),
        "latency_ms": 4321,
    }
    return Finding(**{**base, **over})


def completed(scan_id="s-1", owner=OWNER_A, url=f"https://evil.example/?q={EVIL}", **over):
    now = utcnow()
    base = {
        "scan_id": scan_id,
        "owner": owner,
        "url": url,
        "status": ScanStatus.COMPLETE,
        "queued_at": now - timedelta(seconds=40),
        "started_at": now - timedelta(seconds=35),
        "completed_at": now,
        "queue_wait_ms": 5000,
        "total_ms": 35000,
        "verdict": Verdict(
            verdict="phishing",
            risk_score=93,
            confidence="high",
            action="block",
            summary=f"Summary {EVIL}",
            disagreements=[f"disagree {EVIL}"],
            missed_by_specialists=[f"missed {EVIL}"],
            report_markdown=f"## Report\n{EVIL}",
        ),
        "findings": [
            finding("url_analyst"),
            finding("brand_visual", verdict="legitimate", confidence=61),
            finding("code_analyst", status="blocked_by_guardrail", verdict="unknown", confidence=0),
        ],
        "calls": [
            Call(
                kind=CallKind.HARNESS,
                name="orchestrator",
                started_at=now,
                duration_ms=30100,
                status="ok",
                usage=Usage(input_tokens=5000, output_tokens=900, model_id="us.orch"),
            )
        ],
        "cost_usd": Decimal("0.1432"),
    }
    return ScanRecord(**{**base, **over})


def call(event):
    response = app.handler(event, None)
    return response["statusCode"], json.loads(response["body"])


def s3_body(key):
    obj = boto3.client("s3", region_name="us-west-2").get_object(Bucket=BUCKET, Key=key)
    return obj, obj["Body"].read().decode()


# --- rendering -------------------------------------------------------------------------


def test_scan_report_escapes_every_untrusted_field():
    page = reports.render_scan_report(completed())
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
    # Only the report's own markup: no script, iframe, object, event handler or external load.
    assert not re.search(r"<(script|iframe|object|embed|link|img)\b", page)
    assert not re.search(r"\son[a-z]+\s*=", page)


def test_scan_report_is_self_contained_with_a_locking_csp():
    page = reports.render_scan_report(completed())
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page).group(1)
    assert "default-src 'none'" in csp
    assert "script-src" not in csp
    style_hash = re.search(r"style-src '(sha256-[^']+)'", csp).group(1)
    assert style_hash == reports.REPORT_CSS_HASH
    assert not re.search(r'(src|href)="https?://', page)


def test_scan_report_has_verdict_a_section_per_specialist_timings_and_cost():
    page = reports.render_scan_report(completed())
    assert "PHISHING" in page and "93" in page and "Block" in page
    for label in ("URL analyst", "Brand and visual", "Code analyst"):
        assert f"<h3>{label}</h3>" in page
    assert "61%" in page and "Blocked by guardrail" in page
    assert "4.3 s" in page  # specialist latency
    assert "35.0 s" in page and "5.0 s" in page and "30.1 s" in page  # total, queue, harness
    assert "$0.1432" in page
    assert "hxxps://evil[.]example" in page  # the URL is defanged, never a live link
    assert "## Report" in page  # the orchestrator report, verbatim and escaped


def test_scan_report_lists_a_specialist_that_did_not_report():
    record = completed(findings=[finding("url_analyst")])
    page = reports.render_scan_report(record)
    assert page.count("No report") == 2


def test_batch_report_is_a_defanged_table_linking_each_scan():
    batch = BatchRecord(
        batch_id="b-1",
        owner=OWNER_A,
        source="api",
        total=2,
        created_at=utcnow(),
        cost_usd=Decimal("0.3"),
    )
    pending = completed(scan_id="s-2", url="https://ok.example/", status=ScanStatus.PENDING)
    pending = pending.model_copy(update={"verdict": None, "cost_usd": Decimal("0")})
    page = reports.render_batch_report(
        batch, [completed(), pending], console_url="https://console.example"
    )
    assert "<script>" not in page
    assert "hxxps://evil[.]example" in page and "hxxps://ok[.]example" in page
    assert 'href="https://console.example/results/s-1"' in page
    assert 'href="https://console.example/results/s-2"' in page
    assert page.count("<tr") == 3  # header plus one row per scan
    assert "Phishing" in page and "PENDING" in page and "$0.1432" in page and "93" in page
    assert "high" in page  # orchestrator confidence band


def test_batch_report_without_a_console_url_shows_scan_ids_without_links():
    batch = BatchRecord(batch_id="b-1", owner=OWNER_A, source="api", total=1, created_at=utcnow())
    page = reports.render_batch_report(batch, [completed()], console_url="")
    assert "s-1" in page and "/results/" not in page


def test_console_url_must_be_https():
    batch = BatchRecord(batch_id="b-1", owner=OWNER_A, source="api", total=1, created_at=utcnow())
    page = reports.render_batch_report(batch, [completed()], console_url="javascript:alert(1)")
    assert "javascript:" not in page


# --- routes ----------------------------------------------------------------------------


def test_report_routes_are_registered():
    assert ("GET", "/scans/{id}/report") in app.ROUTES
    assert ("GET", "/batches/{id}/report") in app.ROUTES


def test_scan_report_route_stores_the_report_and_returns_a_download_link(aws):
    store.put_scan_if_absent(completed())
    status, body = call(api_event("GET", "/scans/{id}/report", path={"id": "s-1"}))
    assert status == 200 and body["expires_in"] == 900
    link = urlparse(body["url"])
    assert link.scheme == "https" and link.path.endswith("/scans/s-1/report.html")
    query = parse_qs(link.query)
    assert query["response-content-disposition"][0].startswith("attachment;")
    obj, page = s3_body("scans/s-1/report.html")
    assert obj["ContentType"] == "text/html; charset=utf-8"
    assert "&lt;script&gt;" in page and "<script>" not in page


def test_scan_report_is_owner_scoped(aws):
    store.put_scan_if_absent(completed())
    status, _ = call(api_event("GET", "/scans/{id}/report", path={"id": "s-1"}, sub="user-b"))
    assert status == 404
    listed = boto3.client("s3", region_name="us-west-2").list_objects_v2(Bucket=BUCKET)
    assert listed.get("KeyCount", 0) == 0


def test_scan_report_needs_a_completed_scan(aws):
    record = completed(status=ScanStatus.RUNNING).model_copy(update={"verdict": None})
    store.put_scan_if_absent(record)
    status, body = call(api_event("GET", "/scans/{id}/report", path={"id": "s-1"}))
    assert status == 409 and "COMPLETE" in body["error"]


def test_scan_report_unknown_or_malformed_id_is_404(aws):
    assert call(api_event("GET", "/scans/{id}/report", path={"id": "nope"}))[0] == 404
    assert call(api_event("GET", "/scans/{id}/report", path={"id": "../x"}))[0] == 404


def test_batch_report_route_includes_only_this_owners_batch_scans(aws, monkeypatch):
    monkeypatch.setenv("CONSOLE_URL", "https://console.example")
    from phish_backend.common import clients

    clients.reset()
    put_batch_for_tests("b-1", OWNER_A, total=2)
    store.put_scan_if_absent(completed(scan_id="s-1", batch_id="b-1"))
    store.put_scan_if_absent(completed(scan_id="s-2", batch_id="b-1", url="https://two.example/"))
    # Another batch, and a row that claims this batch but belongs to someone else.
    store.put_scan_if_absent(completed(scan_id="s-3", batch_id="b-2", url="https://other.example/"))
    store.put_scan_if_absent(
        completed(scan_id="s-4", batch_id="b-1", owner=OWNER_B, url="https://intruder.example/")
    )
    status, body = call(api_event("GET", "/batches/{id}/report", path={"id": "b-1"}))
    assert status == 200 and body["expires_in"] == 900
    assert urlparse(body["url"]).path.endswith("/batches/b-1/report.html")
    _, page = s3_body("batches/b-1/report.html")
    assert "hxxps://two[.]example" in page and "hxxps://evil[.]example" in page
    assert "other[.]example" not in page and "intruder" not in page
    assert 'href="https://console.example/results/s-2"' in page


def test_batch_report_is_owner_scoped(aws):
    put_batch_for_tests("b-1", OWNER_A, total=1)
    status, _ = call(api_event("GET", "/batches/{id}/report", path={"id": "b-1"}, sub="user-b"))
    assert status == 404
    assert call(api_event("GET", "/batches/{id}/report", path={"id": "b-9"}))[0] == 404


def test_reports_print_cleanly():
    # Analysts print these for incident tickets: a print sheet must drop the dark
    # header and shadows, keep the verdict colours and not split a section.
    css = reports.REPORT_CSS
    assert "@media print" in css
    printed = css[css.index("@media print") :]
    assert "print-color-adjust: exact" in printed
    assert "break-inside: avoid" in printed
    assert "box-shadow: none" in printed
    assert "@page" in css


def test_batch_report_marks_each_verdict_with_the_verdict_palette():
    batch = BatchRecord(batch_id="b-1", owner=OWNER_A, source="api", total=1, created_at=utcnow())
    page = reports.render_batch_report(batch, [completed()], console_url="")
    assert '<span class="pill v-phishing">Phishing</span>' in page


def _notice_count(page):
    return page.count(DISCLAIMER_TEXT)


def test_scan_report_shows_the_disclaimer_at_top_beside_the_verdict_and_in_the_footer():
    page = reports.render_scan_report(completed())
    first = page.index(DISCLAIMER_TEXT)
    assert first < page.index("Phishing analysis report</h1>")
    assert page.index('<div class="disclaimer" role="note">') < page.index('class="header"')
    assert 'class="disclaimer-note"' in page[page.index("verdict-box") :]
    assert page.rindex(DISCLAIMER_TEXT) > page.index("Orchestrator report")
    assert 'class="disclaimer footer-notice"' in page
    assert _notice_count(page) == 3
    assert DISCLAIMER_TITLE in page


def test_batch_report_shows_the_disclaimer_at_top_in_the_table_header_and_in_the_footer():
    batch = BatchRecord(batch_id="b-1", owner=OWNER_A, source="api", total=1, created_at=utcnow())
    page = reports.render_batch_report(batch, [completed()], console_url="")
    assert page.index(DISCLAIMER_TEXT) < page.index("Batch phishing report</h1>")
    assert '<table><caption class="disclaimer-note">' in page
    assert 'class="disclaimer footer-notice"' in page
    assert _notice_count(page) == 3


def test_disclaimer_is_bold_bordered_and_printable():
    css = reports.REPORT_CSS
    banner = css[css.index(".disclaimer {") :].split("}")[0]
    assert "font-weight: 800" in css and "font-weight: 700" in banner and "3px solid" in banner
    print_css = css[css.index("@media print") :]
    assert "break-inside: avoid" in print_css and ".disclaimer" in print_css


def test_error_404_verdict_has_a_label_and_a_neutral_style():
    assert reports.verdict_label("error_404") == "Error 404"
    assert reports.verdict_label("phishing") == "Phishing"
    assert ".v-error_404" in reports.REPORT_CSS


def test_scan_report_drops_the_markdown_leading_disclaimer_but_keeps_its_footer():
    from phish_contracts.disclaimer import with_disclaimer_markdown

    record = completed()
    record.verdict.report_markdown = with_disclaimer_markdown("## Report\nbody")
    page = reports.render_scan_report(record)
    pre = page[page.index("<pre>") : page.index("</pre>")]
    assert not pre.removeprefix("<pre>").lstrip().startswith("**")
    assert pre.count(DISCLAIMER_TEXT) == 1 and pre.rstrip().endswith(DISCLAIMER_TEXT)
    assert "## Report" in pre


def test_scan_report_defangs_urls_in_prose_of_records_stored_before_the_worker_did():
    sig = Signal(name="credential_form_off_domain", severity="high", evidence="posts to a.evil.top")
    record = completed(findings=[finding("code_analyst", signals=[sig])])
    record.verdict.summary = "Clone of https://bank.example/login."
    record.verdict.missed_by_specialists = ["the form host b.evil.top"]
    record.verdict.report_markdown = "## Evidence\n- see http://c.evil.top/x"
    page = reports.render_scan_report(record)
    for live in ("https://bank", "http://c", "a.evil.top", "b.evil.top", "c.evil.top"):
        assert live not in page, live
    for safe in ("hxxps://bank[.]example/login", "a[.]evil[.]top", "b[.]evil[.]top"):
        assert safe in page, safe
    assert "hxxp://c[.]evil[.]top/x" in page


# --- v3: site_down, catalog titles, capture notes and code insights ---------------------


def test_site_down_verdict_has_a_label_and_a_style():
    assert reports.verdict_label("site_down") == "Site down"
    assert ".v-site_down" in reports.REPORT_CSS and ".pill.v-site_down" in reports.REPORT_CSS


def test_signals_show_the_catalog_title_and_explanation():
    from phish_contracts.signals import CATALOG

    sig = Signal(name="blocked_by_browser", severity="low", evidence="net::ERR_BLOCKED")
    page = reports.render_scan_report(completed(findings=[finding("url_analyst", signals=[sig])]))
    assert reports._e(CATALOG["blocked_by_browser"]["title"]) in page
    assert reports._e(CATALOG["blocked_by_browser"]["explain"]) in page
    assert ">blocked_by_browser<" not in page  # the raw name is not the heading


def test_unknown_signal_names_are_humanized_and_escaped():
    sig = Signal(name=f"odd_new_name {EVIL}", severity="medium", evidence="e")
    page = reports.render_scan_report(completed(findings=[finding("url_analyst", signals=[sig])]))
    assert "Odd new name &lt;script&gt;" in page and "<script>" not in page


def test_capture_note_is_shown_escaped():
    f = finding("brand_visual", capture_note=f"A bot check did not clear {EVIL}")
    page = reports.render_scan_report(completed(findings=[f]))
    assert "A bot check did not clear &lt;script&gt;" in page


def test_code_insights_render_as_a_compact_defanged_table():
    insights = {
        "endpoints": [
            {
                "url": "hxxps://api[.]telegram[.]org/bot1/sendMessage",
                "kind": "fetch",
                "off_domain": True,
            },
            {"url": f"https://cdn.example/{EVIL}", "kind": "image", "off_domain": False},
        ],
        "forms": [{"action": "", "fields": ["email", "password"], "submits_via_js": True}],
        "script_count": 4,
        "script_kb": 120,
        "external_script_hosts": ["cdn.example"],
    }
    f = finding("code_analyst", insights=insights)
    page = reports.render_scan_report(completed(findings=[f]))
    assert "What the page&#x27;s code does" in page
    assert "hxxps://api[.]telegram[.]org/bot1/sendMessage" in page
    assert "[[.]]" not in page  # already-defanged URLs are not defanged twice
    assert "hxxps://cdn[.]example/" in page and "https://cdn.example" not in page
    assert "&lt;script&gt;" in page and "<script>" not in page
    assert "email, password" in page and "4 scripts" in page and "120 KB" in page


def test_no_insights_section_without_insights():
    page = reports.render_scan_report(completed())
    assert "What the page" not in page


def test_report_turn_is_its_own_timing_row_and_never_added_to_the_orchestrator():
    # A 2026-10-08 report showed orchestrator 76.4 s above total 69.4 s: the report turn,
    # which runs after the verdict (and so after total_ms), was summed into the orchestrator.
    record = completed()
    report = record.calls[0].model_copy(update={"name": "report", "duration_ms": 12000})
    page = reports.render_scan_report(record.model_copy(update={"calls": [*record.calls, report]}))
    assert '<td>Orchestrator (harness)</td><td class="num">30.1 s</td>' in page
    assert '<td>Total, to the verdict</td><td class="num">35.0 s</td>' in page
    assert 'Report writing (harness, after the verdict)</td><td class="num">12.0 s' in page
    assert "42.1 s" not in page


def test_scan_cost_with_an_unpriced_model_is_unknown_not_a_price():
    record = completed(unpriced_models=["au.anthropic.claude-future-9"], cost_usd=Decimal("0.06"))
    page = reports.render_scan_report(record)
    assert "Total token cost: <strong>unknown</strong>" in page
    assert "No price is known for au.anthropic.claude-future-9" in page
    assert "The priced models cost $0.0600." in page
    assert "Total token cost: <strong>$0.0600" not in page


def test_batch_report_marks_an_unpriced_scan_and_the_total_as_a_lower_bound():
    batch = BatchRecord(
        batch_id="b-1",
        owner=OWNER_A,
        source="api",
        total=2,
        created_at=utcnow(),
        cost_usd=Decimal("0.2"),
    )
    scans = [completed("s-1"), completed("s-2", unpriced_models=["xx.m"])]
    page = reports.render_batch_report(batch, scans, console_url="")
    assert "at least $0.2000" in page
    assert '<td class="num">unknown</td>' in page and '<td class="num">$0.1432</td>' in page


def test_redirect_chain_renders_defanged_with_its_marks():
    chain = [
        {"url": "https://bit.ly/x", "via": "start", "status": 301, "shortener": True},
        {"url": f"https://kit.pages.dev/{EVIL}", "via": "http", "status": 403},
        {
            "url": "https://kit.pages.dev/cdn-cgi/phish-bypass?atok=t",
            "via": "warning_bypass",
            "cross_domain": True,
            "free_hosting": True,
        },
        {"url": "https://dead.example/", "via": "client", "error": "net::ERR_NAME_NOT_RESOLVED"},
    ]
    f = finding("brand_visual", redirect_chain=chain)
    page = reports.render_scan_report(completed(findings=[f]))
    assert "Redirect chain" in page and "Proceeded past the warning" in page
    assert "hxxps://bit[.]ly/x" in page and "https://bit.ly" not in page
    assert "hxxps://kit[.]pages[.]dev/" in page and "<script>" not in page
    assert "new site, free hosting" in page and "shortener" in page
    assert "failed: net::ERR_NAME_NOT_RESOLVED" in page and "Script or meta refresh" in page


def test_a_single_hop_chain_is_not_shown():
    f = finding("url_analyst", redirect_chain=[{"url": "https://a.example/"}])
    assert "Redirect chain" not in reports.render_scan_report(completed(findings=[f]))


def test_page_not_observed_is_stated_beside_the_verdict():
    record = completed()
    unseen = record.verdict.model_copy(update={"page_observed": False})
    page = reports.render_scan_report(record.model_copy(update={"verdict": unseen}))
    assert "Page not observed: the browser never saw the site&#x27;s real page" in page
    assert "Page not observed" not in reports.render_scan_report(completed())
