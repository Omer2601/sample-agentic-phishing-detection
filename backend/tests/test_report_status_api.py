# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""report_status on GET /scans/{id}, /history, /batches/{id} and in the HTML scan report."""

import json

from backend_testkit import OWNER_A, api_event, put_batch_for_tests
from test_reports import completed

from phish_backend.api import app
from phish_backend.common import store
from phish_backend.reports import html as reports
from phish_contracts.disclaimer import DISCLAIMER_TEXT
from phish_contracts.models import ReportStatus


def call(event):
    response = app.handler(event, None)
    return response["statusCode"], json.loads(response["body"])


def pending(scan_id="p-1", **over):
    record = completed(scan_id=scan_id, url="https://a.example/", **over)
    record.verdict.report_markdown = ""
    record.report_status = ReportStatus.PENDING
    record.report_started_at = record.completed_at
    return record


def test_get_scan_history_and_batch_serialize_the_report_fields(aws):
    put_batch_for_tests("b-1", OWNER_A, total=1)
    record = pending(batch_id="b-1")
    store.put_scan_if_absent(record)
    status, got = call(api_event("GET", "/scans/{id}", path={"id": "p-1"}))
    assert status == 200 and got["status"] == "COMPLETE"
    assert got["report_status"] == "PENDING" and got["report_started_at"]
    assert got["report_ready_at"] is None and got["verdict"]["report_markdown"] == ""
    assert "owner" not in got
    _, history = call(api_event("GET", "/history"))
    assert history["items"][0]["report_status"] == "PENDING"
    _, detail = call(api_event("GET", "/batches/{id}", path={"id": "b-1"}))
    assert detail["items"][0]["report_status"] == "PENDING"


def test_legacy_scan_reads_as_ready(aws):
    store.put_scan_if_absent(completed(scan_id="old-1"))
    _, got = call(api_event("GET", "/scans/{id}", path={"id": "old-1"}))
    assert got["report_status"] == "READY"


def test_failed_report_fields_round_trip(aws):
    record = pending(scan_id="f-1")
    record.report_status = ReportStatus.FAILED
    record.report_error = "not enough time"
    record.report_ready_at = record.completed_at
    store.put_scan_if_absent(record)
    _, got = call(api_event("GET", "/scans/{id}", path={"id": "f-1"}))
    assert got["report_status"] == "FAILED" and got["report_error"] == "not enough time"
    assert got["report_ready_at"]


def test_html_shows_a_pending_notice_with_verdict_findings_and_disclaimer():
    page = reports.render_scan_report(pending())
    assert reports.PENDING_NOTICE in page and "<pre>" not in page
    assert "PHISHING" in page and "Summary" in page
    assert "Sig " in page  # the specialist signals are still shown (catalog-style title)
    assert DISCLAIMER_TEXT in page


def test_html_shows_a_failure_notice_and_escapes_the_reason():
    record = pending()
    record.report_status = ReportStatus.FAILED
    record.report_error = "<b>oops</b>"
    page = reports.render_scan_report(record)
    assert reports.FAILED_NOTICE in page and "&lt;b&gt;oops&lt;/b&gt;" in page
    assert "<b>oops</b>" not in page and DISCLAIMER_TEXT in page


def test_html_ready_report_is_unchanged():
    page = reports.render_scan_report(completed())
    assert "<pre>" in page and reports.PENDING_NOTICE not in page
