# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import os

from botocore.exceptions import ClientError

from phish_backend.common import guardrails
from phish_contracts.disclaimer import DISCLAIMER_MARKDOWN
from phish_contracts.models import Verdict

VERDICT = Verdict(
    verdict="phishing",
    risk_score=90,
    confidence="high",
    action="block",
    summary="s",
    report_markdown="# Report with a quoted lure",
)


class FakeRuntime:
    def __init__(self, action="NONE", outputs=None, error=None):
        self.action, self.outputs, self.error, self.calls = action, outputs or [], error, []

    def apply_guardrail(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return {"action": self.action, "outputs": self.outputs}


def use(monkeypatch, fake, **env):
    for key, value in {
        "GUARDRAIL_INPUT_ID": "gin",
        "GUARDRAIL_INPUT_VERSION": "1",
        "GUARDRAIL_OUTPUT_ID": "gout",
        "GUARDRAIL_OUTPUT_VERSION": "1",
        **env,
    }.items():
        monkeypatch.setenv(key, value)
    from phish_backend.common.config import settings

    settings.cache_clear()
    monkeypatch.setattr(guardrails, "_client", lambda: fake)


def test_disabled_when_no_guardrail_configured(monkeypatch):
    fake = FakeRuntime(action="GUARDRAIL_INTERVENED")
    use(monkeypatch, fake, GUARDRAIL_INPUT_ID="", GUARDRAIL_OUTPUT_ID="")
    assert guardrails.screen_url("https://a.example/") == []
    assert guardrails.screen_report(VERDICT) == (VERDICT, [])
    assert fake.calls == []


def test_input_intervention_is_an_event_not_a_rejection(monkeypatch):
    fake = FakeRuntime(action="GUARDRAIL_INTERVENED")
    use(monkeypatch, fake)
    assert guardrails.screen_url("https://a.example/") == [guardrails.INPUT_EVENT]
    assert fake.calls[0]["source"] == "INPUT"
    assert fake.calls[0]["content"] == [{"text": {"text": "https://a.example/"}}]


def test_output_intervention_replaces_report_and_keeps_verdict(monkeypatch):
    use(
        monkeypatch,
        FakeRuntime(action="GUARDRAIL_INTERVENED", outputs=[{"text": "Report withheld."}]),
    )
    screened, events = guardrails.screen_report(VERDICT)
    assert events == [guardrails.OUTPUT_EVENT]
    assert screened.report_markdown.startswith("Report withheld.")
    assert (screened.verdict, screened.risk_score, screened.action) == (
        VERDICT.verdict,
        90,
        VERDICT.action,
    )


def test_guardrail_outage_records_an_event_and_continues(monkeypatch):
    err = ClientError(
        {"Error": {"Code": "ServiceUnavailableException", "Message": "x"}}, "ApplyGuardrail"
    )
    use(monkeypatch, FakeRuntime(error=err))
    assert guardrails.screen_url("https://a.example/") == [guardrails.UNAVAILABLE_EVENT]
    assert guardrails.screen_report(VERDICT) == (VERDICT, [guardrails.UNAVAILABLE_EVENT])


def test_screen_urls_keeps_order(monkeypatch):
    use(monkeypatch, FakeRuntime(action="GUARDRAIL_INTERVENED"))
    assert guardrails.screen_urls(["https://a.example/", "https://b.example/"]) == [
        [guardrails.INPUT_EVENT],
        [guardrails.INPUT_EVENT],
    ]


def test_flagged_url_is_still_queued_by_every_entry_point(aws, monkeypatch):
    import json

    import boto3
    from backend_testkit import api_event

    from phish_backend.api import app
    from phish_backend.batch import split_csv
    from phish_backend.common import store

    use(monkeypatch, FakeRuntime(action="GUARDRAIL_INTERVENED"))
    response = app.handler(api_event("POST", "/scan", body={"url": "https://a.example/"}), None)
    assert response["statusCode"] == 202
    scan_id = json.loads(response["body"])["scan_id"]
    assert store.get_scan(scan_id).guardrail_events == [guardrails.INPUT_EVENT]

    response = app.handler(
        api_event("POST", "/batches", body={"urls": ["https://b.example/"]}), None
    )
    batch_id = json.loads(response["body"])["batch_id"]
    items, _ = store.scans_for_batch(batch_id, 10, None)
    assert [s.guardrail_events for s in items] == [[guardrails.INPUT_EVENT]]

    response = app.handler(
        api_event("POST", "/batches", body={"upload": True, "count": 1, "source": "ui"}), None
    )
    upload = json.loads(response["body"])
    fields = upload["upload_fields"]
    boto3.client("s3", region_name="us-west-2").put_object(
        Bucket=os.environ["UPLOAD_BUCKET"],
        Key=fields["key"],
        Body=b"https://c.example/\n",
        Metadata={
            "batch-id": upload["batch_id"],
            "owner": fields["x-amz-meta-owner"],
            "source": "ui",
        },
    )
    split_csv.process_object(os.environ["UPLOAD_BUCKET"], fields["key"])
    items, _ = store.scans_for_batch(upload["batch_id"], 10, None)
    assert [s.guardrail_events for s in items] == [[guardrails.INPUT_EVENT]]


def test_worker_withholds_report_but_keeps_verdict(aws, monkeypatch):
    from test_run_scan import FakeAgentCore, seed

    from phish_backend.common import store
    from phish_backend.worker import run_scan

    use(
        monkeypatch,
        FakeRuntime(action="GUARDRAIL_INTERVENED", outputs=[{"text": "Withheld."}]),
        GUARDRAIL_INPUT_ID="",
    )
    run_scan.process_message(seed(), agentcore=FakeAgentCore())
    done = store.get_scan("s1")
    assert done.status == "COMPLETE" and done.verdict.verdict == "phishing"
    assert "Withheld." in done.verdict.report_markdown
    assert done.verdict.report_markdown.startswith(DISCLAIMER_MARKDOWN)
    assert done.guardrail_events == [guardrails.OUTPUT_EVENT]
