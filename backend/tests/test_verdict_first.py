# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Verdict-first worker: two harness turns, the 404 fast path and their failure modes."""

import json
import threading
import time

import boto3
import pytest
from backend_testkit import OWNER_A
from botocore.exceptions import ClientError
from test_aggregate import COMPLETE, record, scan_item, seed_batch, stats
from test_run_scan import FakeAgentCore, seed

from phish_backend.common import aws_retry, clients, precheck, store
from phish_backend.stats import aggregate
from phish_backend.worker import run_scan
from phish_contracts.disclaimer import DISCLAIMER_MARKDOWN
from phish_contracts.models import REPORT_FOLLOWUP_MESSAGE, ReportStatus

COMPACT = {
    "verdict": "phishing",
    "risk_score": 95,
    "confidence": "high",
    "action": "block",
    "summary": "A bank login clone.",
}
REPORT = {"report_markdown": "# Full report\n\nDetails."}


class TwoTurnHarness(FakeAgentCore):
    """Turn 1 on a new session returns the compact verdict; the follow-up returns the report."""

    def __init__(
        self,
        turn1=None,
        turn2=None,
        turn2_error=None,
        turn2_delay=0.0,
        on_turn2=None,
        turn2_block=None,
    ):
        super().__init__(text=json.dumps(COMPACT) if turn1 is None else turn1)
        self.turn2 = json.dumps(REPORT) if turn2 is None else turn2
        self.turn2_error, self.turn2_delay, self.on_turn2 = turn2_error, turn2_delay, on_turn2
        # A threading.Event: turn 2 blocks until the test sets it, so a cut-off is proven by
        # order of events rather than by a wall-clock bound.
        self.turn2_block, self.turn2_finished = turn2_block, False
        self.texts = []

    def invoke_harness(self, **kwargs):
        text = kwargs["messages"][0]["content"][0]["text"]
        self.texts.append(text)
        if not text.endswith(REPORT_FOLLOWUP_MESSAGE):
            return super().invoke_harness(**kwargs)
        self.invocations += 1
        self.actors.append(kwargs.get("actorId"))
        self.sessions.append(kwargs["runtimeSessionId"])
        if self.on_turn2:
            self.on_turn2()
        if self.turn2_delay:
            time.sleep(self.turn2_delay)
        if self.turn2_block is not None:
            self.turn2_block.wait(60)
            self.turn2_finished = True
        if self.turn2_error:
            raise self.turn2_error
        events = [
            {"messageStart": {}},
            {"contentBlockDelta": {"delta": {"text": self.turn2}}},
            {"metadata": {"usage": {"inputTokens": 3000, "outputTokens": 1500}}},
        ]
        return {"stream": iter(events)}


class StubTools:
    def __init__(self, outcome="error_404", error=None, extra=None):
        self.outcome, self.error, self.calls = outcome, error, 0
        self.extra = extra or {}

    def invoke_agent_runtime(self, **kwargs):
        import io

        self.calls += 1
        if self.error:
            raise self.error
        payload = {"outcome": self.outcome, "final_status": 404, "final_url": "https://gone.ex/"}
        payload.update(self.extra)
        body = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"text": json.dumps(payload)}]}}
        return {"response": io.BytesIO(json.dumps(body).encode())}


@pytest.fixture
def tools_env(monkeypatch):
    monkeypatch.setenv("TOOLS_RUNTIME_ARN", "arn:aws:bedrock-agentcore:us-west-2:1:runtime/tools")
    clients.reset()


def test_two_turns_same_session_report_ready(aws):
    fake = TwoTurnHarness()
    run_scan.process_message(seed(), agentcore=fake)
    done = store.get_scan("s1")
    assert done.status == "COMPLETE" and done.report_status is ReportStatus.READY
    assert done.verdict.verdict == "phishing" and done.verdict.summary == "A bank login clone."
    assert done.verdict.report_markdown.startswith(DISCLAIMER_MARKDOWN)
    assert "# Full report" in done.verdict.report_markdown
    assert done.report_started_at is not None and done.report_ready_at is not None
    assert fake.invocations == 2 and len(set(fake.sessions)) == 1
    assert fake.texts[1] == "Write the full report now."
    # Stopped once, after turn 2.
    assert fake.stopped == fake.sessions[:1]
    names = [c.name for c in done.calls if c.kind == "harness"]
    assert names == ["orchestrator", "report"]
    turn_1_usages = [c.usage for c in done.calls if c.name == "orchestrator"]
    turn_1_only = run_scan.cost.price_scan(turn_1_usages + [f.usage for f in done.findings]).cost
    assert done.cost_usd > turn_1_only


def test_report_turn_keeps_the_unpriced_flag_of_an_unpriced_model(aws, monkeypatch):
    monkeypatch.setenv("ORCHESTRATOR_MODEL_ID", "xx.anthropic.claude-future-9")
    clients.reset()
    run_scan.process_message(seed(), agentcore=TwoTurnHarness())
    done = store.get_scan("s1")
    assert done.report_status is ReportStatus.READY
    assert [c.name for c in done.calls if c.kind == "harness"] == ["orchestrator", "report"]
    assert done.unpriced_models == ["xx.anthropic.claude-future-9"]


def test_stored_prose_is_defanged_and_the_summary_capped_but_the_url_is_not(aws):
    # The analyst must never get a clickable phishing link from the model's prose; the
    # scan's url stays exact because API and gate consumers parse it.
    long = "Phishing at https://evil.example/login, a clone of paypal.com. " + "x " * 60
    turn1 = dict(COMPACT, summary=long, disagreements=["url_analyst saw evil.example"])
    turn2 = {"report_markdown": "## Evidence\n- code_analyst: posts to https://drop.evil.top/c"}
    fake = TwoTurnHarness(turn1=json.dumps(turn1), turn2=json.dumps(turn2))
    run_scan.process_message(seed(), agentcore=fake)
    done = store.get_scan("s1")
    assert done.url == "https://evil.example/"
    summary = done.verdict.summary
    assert summary.startswith("Phishing at hxxps://evil[.]example/login, a clone of paypal[.]com.")
    assert len(summary.split()) == 50 and summary.endswith("...")
    assert done.verdict.disagreements == ["url_analyst saw evil[.]example"]
    assert "posts to hxxps://drop[.]evil[.]top/c" in done.verdict.report_markdown
    assert "https://" not in done.verdict.report_markdown


def test_verdict_is_stored_before_turn_2_starts(aws):
    seen = {}

    def peek():
        rec = store.get_scan("s1")
        seen.update(
            status=rec.status.value,
            report_status=rec.report_status,
            report=rec.verdict.report_markdown,
            started=rec.report_started_at,
        )

    fake = TwoTurnHarness(on_turn2=peek)
    run_scan.process_message(seed(), agentcore=fake)
    assert seen["status"] == "COMPLETE" and seen["report_status"] is ReportStatus.PENDING
    assert seen["report"] == "" and seen["started"] is not None
    assert fake.stopped == [] or fake.stopped  # session stopped only after the peek


def test_turn_2_failure_keeps_the_verdict(aws):
    err = ClientError({"Error": {"Code": "InternalServerException", "Message": "boom"}}, "Invoke")
    fake = TwoTurnHarness(turn2_error=err)
    run_scan.process_message(seed(), agentcore=fake)
    done = store.get_scan("s1")
    assert done.status == "COMPLETE" and done.verdict.verdict == "phishing"
    assert done.report_status is ReportStatus.FAILED and done.verdict.report_markdown == ""
    assert "Correlation ID" in done.report_error and "boom" not in done.report_error
    assert len(fake.stopped) == 1


def test_unparsable_report_fails_the_report_but_counts_its_tokens(aws):
    fake = TwoTurnHarness(turn2="I could not do that.")
    run_scan.process_message(seed(), agentcore=fake)
    done = store.get_scan("s1")
    assert done.status == "COMPLETE" and done.report_status is ReportStatus.FAILED
    report_call = next(c for c in done.calls if c.name == "report")
    assert report_call.status == "error" and report_call.usage.output_tokens == 1500


def test_not_enough_time_never_calls_turn_2(aws, monkeypatch):
    monkeypatch.setattr(aws_retry, "remaining_seconds", lambda default=300.0: 20.0)
    fake = TwoTurnHarness()
    run_scan.process_message(seed(), agentcore=fake)
    done = store.get_scan("s1")
    assert done.report_status is ReportStatus.FAILED and done.report_error == "not enough time"
    assert fake.invocations == 1 and done.status == "COMPLETE"


def test_turn_2_that_overruns_is_cut_off(aws, monkeypatch):
    monkeypatch.setattr(aws_retry, "remaining_seconds", lambda default=300.0: 15.4)
    monkeypatch.setattr(run_scan, "REPORT_MIN_SECONDS", 0)
    # Turn 2 never returns until released: if the worker waited for it, process_message
    # would only come back after the 60 s backstop, with turn2_finished already True.
    release = threading.Event()
    fake = TwoTurnHarness(turn2_block=release)
    try:
        run_scan.process_message(seed(), agentcore=fake)
        assert fake.turn2_finished is False
    finally:
        release.set()
    done = store.get_scan("s1")
    assert done.report_status is ReportStatus.FAILED and done.report_error == "not enough time"
    assert len(fake.stopped) == 1


def test_older_orchestrator_with_a_full_verdict_needs_no_turn_2(aws):
    full = "<verdict>" + json.dumps({**COMPACT, "report_markdown": "# one turn"}) + "</verdict>"
    fake = TwoTurnHarness(turn1=full)
    run_scan.process_message(seed(), agentcore=fake)
    done = store.get_scan("s1")
    assert fake.invocations == 1 and done.report_status is ReportStatus.READY
    assert "# one turn" in done.verdict.report_markdown and len(fake.stopped) == 1


def test_no_verdict_still_retries_and_stops_the_session(aws):
    fake = TwoTurnHarness(turn1="nothing useful")
    with pytest.raises(run_scan.RetryableScanError):
        run_scan.process_message(seed(), agentcore=fake)
    assert len(fake.stopped) == 1 and fake.invocations == 1
    assert store.get_scan("s1").status == "PENDING"


def _expire_lease(scan_id="s1"):
    boto3.resource("dynamodb", region_name="us-west-2").Table("phish-scans").update_item(
        Key={"scan_id": scan_id},
        UpdateExpression="SET report_claimed_at = :z",
        ExpressionAttributeValues={":z": 0},
    )


def test_redelivery_never_reruns_the_analysis_and_resumes_only_the_report(aws, monkeypatch):
    msg = seed()
    fake = TwoTurnHarness()
    # The first worker dies right after storing the verdict.
    monkeypatch.setattr(run_scan, "_write_report", lambda **kw: None)
    run_scan.process_message(msg, agentcore=fake)
    assert store.get_scan("s1").report_status is ReportStatus.PENDING
    monkeypatch.undo()
    # A redelivery while the first worker still holds its lease does nothing.
    run_scan.process_message(msg, agentcore=fake)
    assert fake.invocations == 1
    # After the lease expires the report is written on a fresh session; turn 1 is not re-run.
    _expire_lease()
    run_scan.process_message(msg, agentcore=fake)
    done = store.get_scan("s1")
    assert (
        done.report_status is ReportStatus.READY and "# Full report" in done.verdict.report_markdown
    )
    assert fake.invocations == 2
    assert fake.texts[1].endswith(REPORT_FOLLOWUP_MESSAGE) and "verdict:" in fake.texts[1]
    assert not any(t.startswith("Analyse this URL") for t in fake.texts[1:])
    assert fake.sessions[1] != fake.sessions[0] and len(fake.stopped) == 1
    # And once READY, further duplicates do nothing.
    run_scan.process_message(msg, agentcore=fake)
    assert fake.invocations == 2
    # The resumed report runs as the same per-scan actor as turn 1.
    assert fake.actors == ["s1", "s1"]


def test_every_harness_turn_runs_as_the_scan_actor(aws):
    # Harness memory is keyed by actorId; with none, every user's scans shared the actor
    # "default". Both turns of a scan use the scan id, and no two scans share one.
    fake = TwoTurnHarness()
    run_scan.process_message(seed("s1"), agentcore=fake)
    run_scan.process_message(seed("s2"), agentcore=fake)
    assert fake.invocations == 4
    assert fake.actors == ["s1", "s1", "s2", "s2"]


def test_failed_report_is_not_retried_by_redelivery(aws):
    msg = seed()
    fake = TwoTurnHarness(turn2="garbage")
    run_scan.process_message(msg, agentcore=fake)
    run_scan.process_message(msg, agentcore=fake)
    assert fake.invocations == 2


def test_legacy_item_without_report_fields_reads_as_ready(aws):
    run_scan.process_message(seed(), agentcore=TwoTurnHarness())
    boto3.resource("dynamodb", region_name="us-west-2").Table("phish-scans").update_item(
        Key={"scan_id": "s1"},
        UpdateExpression="REMOVE report_status, report_started_at, report_ready_at",
    )
    assert store.get_scan("s1").report_status is ReportStatus.READY


# ---- 404 fast path ----------------------------------------------------------------


def test_404_fast_path_answers_without_a_model_call(aws, tools_env):
    fake, tools = TwoTurnHarness(), StubTools()
    run_scan.process_message(seed(), agentcore=fake, tools_client=tools)
    done = store.get_scan("s1")
    assert fake.invocations == 0 and tools.calls == 1
    assert done.status == "COMPLETE" and done.report_status is ReportStatus.READY
    v = done.verdict
    assert (v.verdict.value, v.risk_score, v.confidence.value, v.action.value) == (
        "error_404",
        10,
        "high",
        "allow",
    )
    assert v.report_markdown.startswith(DISCLAIMER_MARKDOWN) and "HTTP 404" in v.report_markdown
    assert "hxxps://evil[.]example/" in v.report_markdown
    assert [(c.kind.value, c.name) for c in done.calls] == [("browser", "precheck")]
    assert done.cost_usd == 0 and done.total_ms is not None and done.findings == []


def test_404_fast_path_counts_in_stats_like_a_normal_completion(aws, tools_env):
    seed_batch()
    msg = seed()
    # Attach the scan to the batch the aggregator test seeded.
    boto3.resource("dynamodb", region_name="us-west-2").Table("phish-scans").update_item(
        Key={"scan_id": "s1"},
        UpdateExpression="SET batch_id = :b",
        ExpressionAttributeValues={":b": "b1"},
    )
    run_scan.process_message(msg, agentcore=TwoTurnHarness(), tools_client=StubTools())
    item = (
        boto3.resource("dynamodb", region_name="us-west-2")
        .Table("phish-scans")
        .get_item(Key={"scan_id": "s1"})["Item"]
    )
    aggregate.apply_record(
        record(
            scan_item("RUNNING", started_at=item["started_at"]),
            {**{k: v for k, v in item.items()}, "owner": OWNER_A},
        )
    )
    assert stats("all")["scanned"] == 1 and stats("all")["verdict#error_404"] == 1
    assert store.get_batch("b1").verdict_counts["error_404"] == 1


# ---- site_down fast path ----------------------------------------------------------

SITE_DOWN = {
    "final_status": None,
    "final_url": "https://dead.example.net/login",
    "hops": ["https://evil.example/", "https://dead.example.net/login"],
    "reason": "DNS lookup failed for dead.example.net",
    "probe": "http",
    "browser_refused": True,
}


def test_site_down_fast_path_answers_without_a_model_call(aws, tools_env):
    fake, tools = TwoTurnHarness(), StubTools("site_down", extra=SITE_DOWN)
    run_scan.process_message(seed(), agentcore=fake, tools_client=tools)
    done = store.get_scan("s1")
    assert fake.invocations == 0 and tools.calls == 1
    assert done.status == "COMPLETE" and done.report_status is ReportStatus.READY
    v = done.verdict
    assert (v.verdict.value, v.risk_score, v.confidence.value, v.action.value) == (
        "site_down",
        10,
        "high",
        "allow",
    )
    md = v.report_markdown
    assert md.startswith(DISCLAIMER_MARKDOWN) and md.endswith(DISCLAIMER_MARKDOWN)
    assert "# Site down" in md and "DNS lookup failed" in md
    assert "hxxps://evil[.]example/" in md and "hxxps://dead[.]example[.]net/login" in md
    assert [(c.kind.value, c.name) for c in done.calls] == [("browser", "precheck")]
    assert done.cost_usd == 0 and done.total_ms is not None and done.findings == []


def test_site_down_without_hops_lists_the_submitted_url(aws, tools_env):
    tools = StubTools("site_down", extra={"final_url": "", "reason": "connection refused"})
    run_scan.process_message(seed(), agentcore=TwoTurnHarness(), tools_client=tools)
    md = store.get_scan("s1").verdict.report_markdown
    assert "hxxps://evil[.]example/" in md and "connection refused" in md


def test_site_down_counts_in_stats_and_batch(aws, tools_env):
    seed_batch()
    msg = seed()
    boto3.resource("dynamodb", region_name="us-west-2").Table("phish-scans").update_item(
        Key={"scan_id": "s1"},
        UpdateExpression="SET batch_id = :b",
        ExpressionAttributeValues={":b": "b1"},
    )
    tools = StubTools("site_down", extra=SITE_DOWN)
    run_scan.process_message(msg, agentcore=TwoTurnHarness(), tools_client=tools)
    item = (
        boto3.resource("dynamodb", region_name="us-west-2")
        .Table("phish-scans")
        .get_item(Key={"scan_id": "s1"})["Item"]
    )
    aggregate.apply_record(
        record(scan_item("RUNNING", started_at=item["started_at"]), {**item, "owner": OWNER_A})
    )
    assert stats("all")["scanned"] == 1 and stats("all")["verdict#site_down"] == 1
    assert store.get_batch("b1").verdict_counts["site_down"] == 1


@pytest.mark.parametrize("outcome", ["ok", "unreachable", "blocked"])
def test_other_precheck_outcomes_run_the_normal_scan(aws, tools_env, outcome):
    fake = TwoTurnHarness()
    run_scan.process_message(seed(), agentcore=fake, tools_client=StubTools(outcome))
    assert fake.invocations == 2 and store.get_scan("s1").verdict.verdict == "phishing"


def test_precheck_failure_falls_through(aws, tools_env):
    err = ClientError({"Error": {"Code": "ThrottlingException"}}, "InvokeAgentRuntime")
    fake = TwoTurnHarness()
    run_scan.process_message(seed(), agentcore=fake, tools_client=StubTools(error=err))
    assert fake.invocations == 2 and store.get_scan("s1").report_status is ReportStatus.READY


def test_precheck_timeout_falls_through(aws, tools_env, monkeypatch):
    def too_slow(*a, **k):
        raise precheck.PrecheckError("precheck exceeded 13s")

    monkeypatch.setattr(precheck, "precheck_url", too_slow)
    fake = TwoTurnHarness()
    run_scan.process_message(seed(), agentcore=fake, tools_client=StubTools())
    assert fake.invocations == 2


def test_without_a_tools_runtime_the_precheck_is_skipped(aws):
    tools = StubTools()
    fake = TwoTurnHarness()
    run_scan.process_message(seed(), agentcore=fake, tools_client=tools)
    assert tools.calls == 0 and fake.invocations == 2


# ---- stats and batch counters -----------------------------------------------------


def _pending(**extra):
    return {**COMPLETE, "report_status": "PENDING", **extra}


def test_report_turn_adds_only_its_own_cost_and_tokens(aws):
    seed_batch()
    aggregate.apply_record(
        record(scan_item("RUNNING", started_at="2026-09-29T12:00:00Z"), _pending())
    )
    ready = {
        **_pending(),
        "report_status": "READY",
        "cost_usd": "0.350000",
        "calls": [
            *COMPLETE["calls"],
            {
                "kind": "harness",
                "name": "report",
                "started_at": "2026-09-29T12:00:35Z",
                "duration_ms": 20000,
                "status": "ok",
                "usage": {
                    "input_tokens": 3000,
                    "output_tokens": 1500,
                    "model_id": "us.anthropic.claude-opus-5-5",
                },
            },
        ],
    }
    event = record(_pending(), ready, seq="2")
    aggregate.apply_record(event)
    aggregate.apply_record(event)  # stream retry
    item = stats("all")
    assert item["scanned"] == 1 and item["verdict#phishing"] == 1
    assert item["input_tokens"] == 4100 and item["output_tokens"] == 1710
    assert item["call#harness#report#count"] == 1
    assert float(item["cost_usd"]) == pytest.approx(0.35)
    batch = store.get_batch("b1")
    assert batch.status_counts["COMPLETE"] == 1 and float(batch.cost_usd) == pytest.approx(0.35)
    assert batch.verdict_counts["phishing"] == 1


def test_verdict_is_counted_at_the_pending_write_not_at_ready(aws):
    seed_batch()
    aggregate.apply_record(
        record(scan_item("RUNNING", started_at="2026-09-29T12:00:00Z"), _pending())
    )
    assert stats("all")["scanned"] == 1
    assert store.get_batch("b1").verdict_counts["phishing"] == 1
