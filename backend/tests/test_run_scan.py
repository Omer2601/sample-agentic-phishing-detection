# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json
import os

import boto3
import pytest
from backend_testkit import OWNER_A
from botocore.exceptions import ClientError

from phish_backend.common import scans, store
from phish_backend.worker import run_scan, verdict
from phish_contracts.disclaimer import DISCLAIMER_MARKDOWN, DISCLAIMER_TEXT
from phish_contracts.models import PAST_SCANS_LABEL

VERDICT = {
    "verdict": "phishing",
    "risk_score": 95,
    "confidence": "high",
    "action": "block",
    "summary": "s",
    "report_markdown": "# r",
}


def finding(agent):
    return {
        "agent": agent,
        "status": "ok",
        "verdict": "phishing",
        "confidence": 80,
        "signals": [],
        "artifacts": [],
        "usage": {
            "input_tokens": 1000,
            "output_tokens": 100,
            "model_id": "global.anthropic.claude-sonnet-5-5",
        },
        "latency_ms": 15000,
        "calls": [
            {
                "kind": "browser",
                "name": agent,
                "started_at": "2026-09-29T12:00:00Z",
                "duration_ms": 9000,
                "status": "ok",
            }
        ],
    }


class FakeAgentCore:
    def __init__(
        self,
        text=None,
        error=None,
        tools=("url-analyst", "brand-visual", "code-analyst"),
        write_findings=True,
    ):
        self.text = text if text is not None else f"<verdict>{json.dumps(VERDICT)}</verdict>"
        self.error = error
        self.tools = tools
        self.write_findings = write_findings
        self.invocations = 0
        self.sessions = []
        self.stopped = []
        self.messages = []
        self.actors = []

    def invoke_harness(self, **kwargs):
        self.invocations += 1
        self.actors.append(kwargs.get("actorId"))
        self.messages.append(kwargs["messages"][0]["content"][0]["text"])
        self.sessions.append(kwargs["runtimeSessionId"])
        if self.error:
            raise self.error
        if self.write_findings:
            # The specialists persist their Findings while the harness runs.
            text = kwargs["messages"][0]["content"][0]["text"]
            write_findings(text.split("scan_id: ", 1)[1].split("\n", 1)[0].strip())
        events = [{"messageStart": {}}]
        events += [
            {"contentBlockStart": {"start": {"toolUse": {"name": f"{t}___analyze"}}}}
            for t in self.tools
        ]
        events += [
            {"metadata": {"usage": {"inputTokens": 2000, "outputTokens": 100}}},
            {"messageStart": {}},
            {"contentBlockDelta": {"delta": {"text": self.text}}},
            {"metadata": {"usage": {"inputTokens": 6000, "outputTokens": 900}}},
        ]
        return {"stream": iter(events)}

    def stop_runtime_session(self, **kwargs):
        self.stopped.append(kwargs["runtimeSessionId"])


def write_findings(scan_id):
    s3 = boto3.client("s3", region_name="us-west-2")
    for agent in ("url_analyst", "brand_visual", "code_analyst"):
        s3.put_object(
            Bucket=os.environ["ARTIFACTS_BUCKET"],
            Key=f"scans/{scan_id}/findings/{agent}.json",
            Body=json.dumps(finding(agent)),
        )


def seed(scan_id="s1"):
    scans.create_and_enqueue([scans.new_scan(OWNER_A, "https://evil.example/", scan_id=scan_id)])
    return {"scan_id": scan_id, "owner": OWNER_A, "url": "https://evil.example/", "batch_id": None}


def test_happy_path_completes_with_calls_and_cost(aws):
    fake = FakeAgentCore()
    run_scan.process_message(seed(), agentcore=fake)
    done = store.get_scan("s1")
    assert done.status == "COMPLETE"
    assert done.verdict.verdict == "phishing"
    assert done.verdict.report_markdown.startswith(DISCLAIMER_MARKDOWN)
    assert done.verdict.report_markdown.endswith(DISCLAIMER_MARKDOWN)
    assert done.verdict.report_markdown.count(DISCLAIMER_TEXT) == 2
    kinds = [c.kind for c in done.calls]
    assert (
        kinds.count("harness") == 1
        and kinds.count("specialist") == 3
        and kinds.count("browser") == 3
    )
    harness = next(c for c in done.calls if c.kind == "harness")
    assert harness.usage.input_tokens == 8000
    assert done.cost_usd > 0
    assert done.total_ms is not None and done.queue_wait_ms is not None
    assert fake.invocations == 1 and len(fake.stopped) == 1


def test_duplicate_message_does_not_invoke_twice(aws):
    fake = FakeAgentCore()
    msg = seed()
    run_scan.process_message(msg, agentcore=fake)
    run_scan.process_message(msg, agentcore=fake)
    assert fake.invocations == 1


def _three_attempts(msg, fake):
    for _ in range(run_scan.MAX_SCAN_ATTEMPTS - 1):
        try:
            run_scan.process_message(msg, agentcore=fake)
        except run_scan.RetryableScanError:
            pass
    run_scan.process_message(msg, agentcore=fake)


def test_missing_verdict_fails_scan_without_leaking_detail(aws):
    _three_attempts(seed(), FakeAgentCore(text="I refuse"))
    failed = store.get_scan("s1")
    assert failed.status == "FAILED"
    assert "no verdict" in failed.error and "Correlation ID" in failed.error
    assert len(failed.findings) == 3


def _no_verdict_warning(caplog, text):
    with caplog.at_level("WARNING", logger="phish_backend.worker.run_scan"):
        try:
            run_scan.process_message(seed(), agentcore=FakeAgentCore(text=text))
        except run_scan.RetryableScanError:
            pass
    return next(r for r in caplog.records if r.getMessage() == "no verdict")


def test_missing_verdict_logs_shape_not_text(aws, caplog):
    text = "I refuse to visit https://evil.example/login?u=victim\n to answer"
    warn = _no_verdict_warning(caplog, text)
    assert warn.scan_id == "s1"
    assert warn.text_chars == len(text)
    assert warn.shape == "no_json_object"
    assert warn.json_error is None and warn.json_error_pos is None
    assert not hasattr(warn, "text_head") and not hasattr(warn, "text_tail")
    assert all("evil" not in str(v) and "refuse" not in str(v) for v in vars(warn).values())


def test_missing_verdict_logs_the_json_error_position(aws, caplog):
    text = '{"verdict":"phishing","risk_score":88,"confidence":' + "x" * 500 + "}"
    warn = _no_verdict_warning(caplog, text)
    assert warn.shape == "invalid_json"
    assert warn.json_error == "Expecting value"
    assert warn.json_error_pos == text.index("x")
    assert warn.starts_with_brace and warn.ends_with_brace
    assert (warn.open_braces, warn.close_braces, warn.quotes) == (1, 1, 8)


@pytest.mark.parametrize(
    ("text", "shape"),
    [
        ("", "no_json_object"),
        ('{"verdict":"phishing","risk_score":', "truncated"),
        ('{"verdict":"phishing","confidence":high,"risk_score":', "truncated"),
        ('{"verdict":"phishing","confidence":high}', "unquoted_enum_value"),
        ('{"verdict":"phishing","risk_score":"lots"}', "schema_invalid"),
    ],
)
def test_no_verdict_shape_classifies_without_text(text, shape):
    meta = verdict.no_verdict_shape(text)
    assert meta["shape"] == shape
    assert all(not isinstance(v, str) or v in {shape, meta["json_error"]} for v in meta.values())


def test_harness_error_is_caller_safe(aws):
    err = ClientError(
        {
            "Error": {
                "Code": "ValidationException",
                "Message": "arn:aws:bedrock-agentcore:us-west-2:123456789012:harness/x bad",
            }
        },
        "InvokeHarness",
    )
    _three_attempts(seed(), FakeAgentCore(error=err))
    failed = store.get_scan("s1")
    assert failed.status == "FAILED"
    assert "arn:" not in failed.error


class RegistryFirstHarness(FakeAgentCore):
    """Step 0 searches the registry in its own message, then round 1 calls the three tools."""

    def invoke_harness(self, **kwargs):
        response = super().invoke_harness(**kwargs)
        lookup = [
            {"messageStart": {"role": "assistant"}},
            {
                "contentBlockStart": {
                    "start": {
                        "toolUse": {"name": "registry___search_discoverable_registry_records"}
                    }
                }
            },
            {"messageStop": {"stopReason": "tool_use"}},
            {"messageStart": {"role": "user"}},
        ]
        return {"stream": iter([*lookup, *response["stream"]])}


def test_registry_lookup_is_its_own_call_and_specialists_start_after_it(aws):
    run_scan.process_message(seed(), agentcore=RegistryFirstHarness())
    done = store.get_scan("s1")
    assert done.status == "COMPLETE" and done.verdict.verdict == "phishing"
    (lookup,) = [c for c in done.calls if c.kind == "registry"]
    assert lookup.name == "registry" and lookup.status == "ok" and lookup.usage is None
    specialists = [c for c in done.calls if c.kind == "specialist"]
    assert [c.name for c in specialists] == ["url_analyst", "brand_visual", "code_analyst"]
    # The lookup is not a specialist row, and the specialists start at the first tool call.
    assert all(c.started_at >= lookup.started_at for c in specialists)
    # Priced usage is unchanged: the lookup has no model usage of its own.
    assert [c.kind for c in done.calls].count("harness") == 1


def test_collect_calls_starts_specialists_at_the_first_non_registry_tool():
    from datetime import UTC, datetime

    from phish_backend.worker.harness_stream import HarnessOutcome
    from phish_contracts.models import Call, CallKind, Usage

    t0, t1, t2 = (datetime(2026, 10, 16, 12, 0, s, tzinfo=UTC) for s in (0, 3, 5))
    harness = Call(
        kind=CallKind.HARNESS, name="orchestrator", started_at=t0, duration_ms=1, status="ok"
    )
    outcome = HarnessOutcome(
        usage=Usage(model_id="m"),
        tool_calls=[
            Call(
                kind=CallKind.SPECIALIST,
                name="registry",
                started_at=t1,
                duration_ms=900,
                status="ok",
            ),
            Call(
                kind=CallKind.SPECIALIST,
                name="url_analyst",
                started_at=t2,
                duration_ms=20_000,
                status="ok",
            ),
        ],
    )
    from phish_contracts.models import Finding

    f = Finding.model_validate(finding("url_analyst"))
    calls = run_scan._collect_calls(harness, outcome, [f])
    assert [(c.kind.value, c.name) for c in calls[:3]] == [
        ("harness", "orchestrator"),
        ("registry", "registry"),
        ("specialist", "url_analyst"),
    ]
    assert calls[1].duration_ms == 900 and calls[2].started_at == t2


def test_one_dispatcher_call_times_all_three_specialists_from_its_start():
    from datetime import UTC, datetime

    from phish_backend.worker.harness_stream import HarnessOutcome
    from phish_contracts.models import Call, CallKind, Finding, Usage, tool_agent

    t0, t1 = (datetime(2026, 10, 21, 12, 0, s, tzinfo=UTC) for s in (0, 2))
    harness = Call(
        kind=CallKind.HARNESS, name="orchestrator", started_at=t0, duration_ms=1, status="ok"
    )
    dispatch = Call(
        kind=CallKind.SPECIALIST,
        name=tool_agent("dispatcher___analyze_all"),
        started_at=t1,
        duration_ms=21_000,
        status="ok",
    )
    outcome = HarnessOutcome(usage=Usage(model_id="m"), tool_calls=[dispatch])
    findings = [Finding.model_validate(finding(n)) for n in ("url_analyst", "brand_visual")]
    calls = run_scan._collect_calls(harness, outcome, findings)
    specialists = [c for c in calls if c.kind == CallKind.SPECIALIST]
    # Concurrent runs share the dispatcher's start; the dispatcher itself is not a row.
    assert [c.name for c in specialists] == ["url_analyst", "brand_visual"]
    assert {c.started_at for c in specialists} == {t1}
    assert "dispatcher" not in {c.name for c in calls}


def test_handler_reports_only_retryable_failures(aws, monkeypatch):
    def boom(message, agentcore=None):
        raise run_scan.RetryableScanError("claim unavailable")

    monkeypatch.setattr(run_scan, "process_message", boom)
    out = run_scan.handler({"Records": [{"messageId": "m1", "body": '{"scan_id": "x"}'}]}, None)
    assert out == {"batchItemFailures": [{"itemIdentifier": "m1"}]}


def test_render_request_does_not_format_braces():
    text = run_scan.render_request("https://x.example/{a}", "s1")
    assert "https://x.example/{a}" in text and "scan_id: s1" in text


def test_specialist_calls_come_from_findings_not_the_stream(aws):
    # The harness runs same-turn tools serially and reports one result message for all three,
    # so the stream's tool timing is not per-specialist truth; the persisted Findings are.
    for tools in (("url-analyst", "brand-visual", "code-analyst"), ("url-analyst",), ()):
        store_id = f"s-{len(tools)}"
        run_scan.process_message(seed(store_id), agentcore=FakeAgentCore(tools=tools))
        done = store.get_scan(store_id)
        specialist = [c for c in done.calls if c.kind == "specialist"]
        assert [c.name for c in specialist] == ["url_analyst", "brand_visual", "code_analyst"]
        assert all(c.duration_ms == 15000 and c.usage.input_tokens == 1000 for c in specialist)
        assert [c.kind for c in done.calls].count("harness") == 1


def test_findings_from_an_earlier_attempt_are_not_reused(aws):
    msg = seed()
    write_findings("s1")  # left behind by an earlier attempt
    _three_attempts(msg, FakeAgentCore(text="", write_findings=False))
    failed = store.get_scan("s1")
    assert failed.status == "FAILED"
    assert all(f.status == "error" for f in failed.findings)


def test_each_attempt_gets_a_fresh_harness_session(aws):
    msg = seed()
    fake = FakeAgentCore(text="")
    _three_attempts(msg, fake)
    assert len(set(fake.sessions)) == 3
    assert all(sid.endswith(f"-a{n}") for n, sid in enumerate(fake.sessions, start=1))
    store.reopen_failed_scan("s1", OWNER_A)
    good = FakeAgentCore()
    run_scan.process_message(msg, agentcore=good)
    # A user retry resets attempts, but never reuses an earlier session.
    retried = store.get_scan("s1")
    assert retried.status == "COMPLETE" and retried.attempts == 1
    assert good.sessions[0].endswith("-a4") and good.sessions[0] not in fake.sessions


def test_scan_complete_log_carries_token_usage(aws, caplog):
    with caplog.at_level("INFO", logger="phish_backend.worker.run_scan"):
        run_scan.process_message(seed(), agentcore=FakeAgentCore())
    done = next(r for r in caplog.records if r.getMessage() == "scan complete")
    # Orchestrator 2000 + 6000 in, 100 + 900 out; three specialists 1000 in, 100 out each.
    assert (done.input_tokens, done.output_tokens) == (11000, 1300)


def test_unknown_orchestrator_model_completes_with_an_unpriced_flag(aws, caplog, monkeypatch):
    from phish_backend.common import clients

    monkeypatch.setenv("ORCHESTRATOR_MODEL_ID", "eu.anthropic.claude-future-9")
    clients.reset()
    with caplog.at_level("INFO", logger="phish_backend.worker.run_scan"):
        run_scan.process_message(seed(), agentcore=FakeAgentCore())
    stored = store.get_scan("s1")
    assert stored.status == "COMPLETE"
    done = next(r for r in caplog.records if r.getMessage() == "scan complete")
    assert done.unpriced_models == ["eu.anthropic.claude-future-9"]
    # The record says the cost is unknown, not that it is $0.
    assert stored.unpriced_models == ["eu.anthropic.claude-future-9"]


def test_a_fully_priced_scan_has_no_unpriced_models(aws):
    run_scan.process_message(seed(), agentcore=FakeAgentCore())
    stored = store.get_scan("s1")
    assert stored.unpriced_models == [] and stored.cost_usd > 0


def test_scan_complete_log_carries_the_harness_breakdown(aws, caplog, monkeypatch):
    from phish_backend.common import aws_retry

    ticks = iter(range(0, 10_000, 1))
    monkeypatch.setattr(run_scan.time, "monotonic", lambda: float(next(ticks)))
    stopped = []

    def slow_stop(client, session_id, arn):
        # A slow StopRuntimeSession must not be billed to the orchestrator.
        for _ in range(50):
            next(ticks)
        stopped.append(session_id)
        return True

    monkeypatch.setattr(aws_retry, "stop_harness_session", slow_stop)
    with caplog.at_level("INFO", logger="phish_backend.worker.run_scan"):
        run_scan.process_message(seed(), agentcore=FakeAgentCore())
    done = next(r for r in caplog.records if r.getMessage() == "scan complete")
    assert stopped
    assert done.harness_ms < 50_000
    assert done.harness_model_ms == done.harness_ms - done.harness_tool_wait_ms
    for key in ("harness_invoke_ms", "harness_first_event_ms", "harness_ttft_ms"):
        assert hasattr(done, key), key


def test_orchestrator_call_starts_at_the_harness_and_fits_inside_the_total(aws, monkeypatch):
    from datetime import timedelta

    base = run_scan.utcnow()
    ticks = iter(range(10_000))
    # Every utcnow() is one second later: the claim, the precheck and the memory read all
    # happen before the harness call, so its start must be after the scan's start.
    monkeypatch.setattr(run_scan, "utcnow", lambda: base + timedelta(seconds=next(ticks)))
    run_scan.process_message(seed(), agentcore=FakeAgentCore())
    done = store.get_scan("s1")
    orchestrator = next(c for c in done.calls if c.name == "orchestrator")
    assert orchestrator.started_at > done.started_at
    end = orchestrator.started_at + timedelta(milliseconds=orchestrator.duration_ms)
    assert end <= done.completed_at
    assert orchestrator.duration_ms <= done.total_ms


def _spy_calls(monkeypatch, **env):
    from phish_backend.common import clients

    for key, value in env.items():
        monkeypatch.setenv(key, value)
    clients.reset()
    fake = FakeAgentCore()
    calls = []
    original = fake.invoke_harness

    def spy(**kwargs):
        calls.append(kwargs)
        return original(**kwargs)

    fake.invoke_harness = spy
    run_scan.process_message(seed(), agentcore=fake)
    return calls


def _fields(call):
    return call["model"]["bedrockModelConfig"]["additionalParams"]["additionalModelRequestFields"]


def test_prompt_cache_is_sent_on_every_turn_by_default(aws, monkeypatch):
    monkeypatch.delenv("ORCHESTRATOR_PROMPT_CACHE", raising=False)
    calls = _spy_calls(monkeypatch)
    # Every turn carries the cache hint; the report turn goes through the same _turn.
    assert calls
    assert all(_fields(c) == {"cache_control": {"type": "ephemeral"}} for c in calls)
    model = calls[0]["model"]["bedrockModelConfig"]
    assert model["maxTokens"] == 8192 and model["modelId"] == "us.anthropic.claude-opus-5-5"


@pytest.mark.parametrize("value", ["0", "false", "OFF", "no"])
def test_no_model_override_when_cache_and_effort_are_off(aws, monkeypatch, value):
    calls = _spy_calls(monkeypatch, ORCHESTRATOR_PROMPT_CACHE=value)
    assert all("model" not in c for c in calls)


def test_orchestrator_effort_is_sent_as_a_model_override(aws, monkeypatch):
    calls = _spy_calls(monkeypatch, ORCHESTRATOR_EFFORT="low", HARNESS_MAX_TOKENS="3000")
    model = calls[0]["model"]["bedrockModelConfig"]
    assert _fields(calls[0]) == {
        "output_config": {"effort": "low"},
        "cache_control": {"type": "ephemeral"},
    }
    # A top-level output_config or cache_control is rejected by the harness's Converse call.
    assert set(model["additionalParams"]) == {"additionalModelRequestFields"}
    assert model["maxTokens"] == 3000 and model["modelId"] == "us.anthropic.claude-opus-5-5"


def test_harness_max_tokens_default_matches_infra(monkeypatch):
    # Same default as infra's DEFAULT_HARNESS_MAX_TOKENS: room for thinking plus the fuller report.
    from phish_backend.common import clients
    from phish_backend.common.config import settings

    monkeypatch.delenv("HARNESS_MAX_TOKENS", raising=False)
    clients.reset()
    settings.cache_clear()
    assert settings().harness_max_tokens == 8192
    settings.cache_clear()


MEMORY_ID = "phish_scan_memory_dev-abcdef1234"


class FakeMemory:
    def __init__(self, records=(), read_error=None, write_error=None):
        self.records = list(records)
        self.read_error = read_error
        self.write_error = write_error
        self.retrieved = []
        self.created = []

    def retrieve_memory_records(self, **kwargs):
        self.retrieved.append(kwargs)
        if self.read_error:
            raise self.read_error
        return {
            "memoryRecordSummaries": [
                {"content": {"text": t}, "metadata": {"scan_id": {"stringValue": f"past-{i}"}}}
                for i, t in enumerate(self.records)
            ]
        }

    def batch_create_memory_records(self, **kwargs):
        self.created.append(kwargs)
        if self.write_error:
            raise self.write_error
        return {"successfulRecords": [], "failedRecords": []}


def _with_memory(monkeypatch):
    from phish_backend.common import clients

    monkeypatch.setenv("MEMORY_ID", MEMORY_ID)
    clients.reset()


PAST = "hxxps://evil2[.]example/ | verdict=phishing | risk=90 | reason: fake bank login"


def test_past_scans_reach_the_orchestrator_as_labelled_context(aws, monkeypatch):
    _with_memory(monkeypatch)
    fake, memory = FakeAgentCore(), FakeMemory(records=[PAST])
    run_scan.process_message(seed(), agentcore=fake, memory=memory)
    (message,) = fake.messages
    assert message.startswith("Analyse this URL.\nurl: https://evil.example/\nscan_id: s1")
    assert PAST_SCANS_LABEL in message and "- " + PAST in message
    assert memory.retrieved[0]["searchCriteria"]["topK"] == 3
    done = store.get_scan("s1")
    assert done.status == "COMPLETE"
    # Deployment-wide matches are kept internally; the record itself never carries them.
    assert done.similar_scans == []
    assert store.memory_matches("s1") == [{"scan_id": "past-0", "summary": PAST}]


def test_completed_scan_is_stored_in_memory(aws, monkeypatch):
    _with_memory(monkeypatch)
    memory = FakeMemory()
    run_scan.process_message(seed(), agentcore=FakeAgentCore(), memory=memory)
    (call,) = memory.created
    text = call["records"][0]["content"]["text"]
    assert text == "hxxps://evil[.]example/ | verdict=phishing | risk=95 | reason: s"
    assert call["clientToken"] == "s1"
    assert store.memory_matches("s1") == []


def test_memory_failures_never_fail_a_scan(aws, monkeypatch):
    _with_memory(monkeypatch)
    err = ClientError({"Error": {"Code": "ThrottledException", "Message": "slow"}}, "X")
    fake = FakeAgentCore()
    memory = FakeMemory(read_error=err, write_error=err)
    run_scan.process_message(seed(), agentcore=fake, memory=memory)
    assert store.get_scan("s1").status == "COMPLETE"
    assert PAST_SCANS_LABEL not in fake.messages[0]
    assert len(memory.created) == 1


def test_unexpected_memory_error_never_fails_a_scan(aws, monkeypatch):
    _with_memory(monkeypatch)

    class Broken(FakeMemory):
        def retrieve_memory_records(self, **kwargs):
            raise RuntimeError("boom")

        def batch_create_memory_records(self, **kwargs):
            raise RuntimeError("boom")

    run_scan.process_message(seed(), agentcore=FakeAgentCore(), memory=Broken())
    assert store.get_scan("s1").status == "COMPLETE"


def test_memory_off_without_memory_id(aws):
    memory = FakeMemory(records=[PAST])
    fake = FakeAgentCore()
    run_scan.process_message(seed(), agentcore=fake, memory=memory)
    assert memory.retrieved == [] and memory.created == []
    assert fake.messages[0] == "Analyse this URL.\nurl: https://evil.example/\nscan_id: s1"


def test_failed_scan_is_not_stored_in_memory(aws, monkeypatch):
    _with_memory(monkeypatch)
    memory = FakeMemory()
    _three_attempts_with_memory(seed(), FakeAgentCore(text="I refuse"), memory)
    assert store.get_scan("s1").status == "FAILED"
    assert memory.created == []


def _three_attempts_with_memory(msg, fake, memory):
    for _ in range(run_scan.MAX_SCAN_ATTEMPTS):
        try:
            run_scan.process_message(msg, agentcore=fake, memory=memory)
        except run_scan.RetryableScanError:
            pass


def test_a_harness_scan_another_worker_stored_is_not_remembered_or_counted_twice(aws, monkeypatch):
    remembered, emitted = [], []
    monkeypatch.setattr(run_scan.store, "complete_scan", lambda *a, **k: False)
    monkeypatch.setattr(run_scan.scan_memory, "remember", lambda *a, **k: remembered.append(a))
    monkeypatch.setattr(run_scan, "_emit", lambda *a, **k: emitted.append(a))
    run_scan.process_message(seed(), agentcore=FakeAgentCore())
    assert remembered == [] and emitted == []
