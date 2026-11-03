# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Direct orchestration: dispatcher alongside the precheck, then one Converse verdict turn and
one Converse report turn. Protocol-level fakes for the two AgentCore runtimes and Bedrock, moto
for DynamoDB and S3 (the same pattern as test_verdict_first.py)."""

import io
import json
import threading
from pathlib import Path

import pytest
from botocore.exceptions import ClientError
from test_run_scan import seed, write_findings
from test_verdict_first import COMPACT, REPORT, StubTools

from phish_backend.common import clients, store
from phish_backend.common.config import settings
from phish_backend.worker import direct, run_scan
from phish_contracts.disclaimer import DISCLAIMER_MARKDOWN
from phish_contracts.models import REPORT_FOLLOWUP_MESSAGE, ReportStatus

DISPATCHER_ARN = "arn:aws:bedrock-agentcore:us-west-2:1:runtime/dispatcher"
REPO = Path(__file__).resolve().parents[2]


class FakeDispatcher:
    """The dispatcher runtime: writes the three Findings to S3, as the specialists do."""

    def __init__(self, error=None, write=True, started=None, release=None):
        self.error, self.write, self.calls = error, write, []
        self.started, self.release = started, release

    def invoke_agent_runtime(self, **kwargs):
        self.calls.append(kwargs)
        if self.started is not None:
            self.started.set()
        if self.release is not None:
            self.release.wait(10)
        if self.error:
            raise self.error
        args = json.loads(kwargs["payload"])["params"]["arguments"]
        if self.write:
            write_findings(args["scan_id"])
        text = json.dumps({"findings": [{}, {}, {}]})
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": text}]},
        }
        return {"response": io.BytesIO(json.dumps(body).encode())}


class FakeBedrock:
    """bedrock-runtime Converse: the verdict turn, then the report turn."""

    def __init__(self, verdict=None, report=None, error=None, report_error=None):
        self.verdict = json.dumps(COMPACT) if verdict is None else verdict
        self.report = json.dumps(REPORT) if report is None else report
        self.error, self.report_error = error, report_error
        self.requests = []

    def converse(self, **kwargs):
        self.requests.append(kwargs)
        last = kwargs["messages"][-1]["content"][0]["text"]
        is_report = last == REPORT_FOLLOWUP_MESSAGE or last.endswith(REPORT_FOLLOWUP_MESSAGE)
        if is_report and self.report_error:
            raise self.report_error
        if not is_report and self.error:
            raise self.error
        text = self.report if is_report else self.verdict
        return {
            "output": {"message": {"role": "assistant", "content": [{"text": text}]}},
            "usage": {
                "inputTokens": 500,
                "outputTokens": 120,
                "cacheReadInputTokens": 4000 if is_report else 0,
                "cacheWriteInputTokens": 0 if is_report else 4000,
            },
        }


@pytest.fixture
def direct_env(monkeypatch):
    monkeypatch.setenv("ORCHESTRATION_MODE", "direct")
    monkeypatch.setenv("DISPATCHER_RUNTIME_ARN", DISPATCHER_ARN)
    monkeypatch.setenv("TOOLS_RUNTIME_ARN", "arn:aws:bedrock-agentcore:us-west-2:1:runtime/tools")
    monkeypatch.setenv("ORCHESTRATOR_EFFORT", "low")
    clients.reset()


class NoHarness:
    def invoke_harness(self, **kwargs):
        raise AssertionError("direct orchestration must not invoke the harness")


def test_off_by_default_without_mode_or_arn(monkeypatch):
    monkeypatch.delenv("ORCHESTRATION_MODE", raising=False)
    monkeypatch.setenv("DISPATCHER_RUNTIME_ARN", DISPATCHER_ARN)
    clients.reset()
    assert settings().direct_orchestration is False
    monkeypatch.setenv("ORCHESTRATION_MODE", "direct")
    monkeypatch.delenv("DISPATCHER_RUNTIME_ARN")
    clients.reset()
    assert settings().direct_orchestration is False


def test_direct_scan_stores_verdict_then_report(aws, direct_env):
    dispatcher, bedrock = FakeDispatcher(), FakeBedrock()
    tools = StubTools(outcome="ok", extra={"final_status": 200})
    run_scan.process_message(
        seed(),
        agentcore=NoHarness(),
        tools_client=tools,
        dispatcher=dispatcher,
        bedrock=bedrock,
    )
    done = store.get_scan("s1")
    assert done.status == "COMPLETE" and done.report_status is ReportStatus.READY
    assert done.verdict.verdict == "phishing" and done.verdict.summary == "A bank login clone."
    assert done.verdict.report_markdown.startswith(DISCLAIMER_MARKDOWN)
    assert "# Full report" in done.verdict.report_markdown
    assert tools.calls == 1 and len(dispatcher.calls) == 1
    call = dispatcher.calls[0]
    assert call["agentRuntimeArn"] == DISPATCHER_ARN
    params = json.loads(call["payload"])["params"]
    assert params == {
        "name": "analyze_all",
        "arguments": {"url": "https://evil.example/", "scan_id": "s1"},
    }
    verdict_req, report_req = bedrock.requests
    assert verdict_req["system"][0]["text"] == direct.system_prompt()
    assert verdict_req["system"][1] == {"cachePoint": {"type": "default"}}
    assert verdict_req["additionalModelRequestFields"] == {"output_config": {"effort": "low"}}
    message = verdict_req["messages"][0]["content"][0]["text"]
    assert message.startswith("Analyse this URL.\nurl: https://evil.example/\nscan_id: s1")
    findings = json.loads(message.split(direct.FINDINGS_LABEL + "\n", 1)[1])
    assert [f["agent"] for f in findings] == [
        "url_analyst",
        "brand_visual",
        "code_analyst",
    ]
    assert all("usage" not in f and "calls" not in f for f in findings)
    # The report turn continues the same conversation.
    assert [m["role"] for m in report_req["messages"]] == ["user", "assistant", "user"]
    assert report_req["messages"][1]["content"][0]["text"] == json.dumps(COMPACT)
    names = [c.name for c in done.calls if c.kind == "harness"]
    assert names == ["orchestrator", "report"]
    specialists = [c.name for c in done.calls if c.kind == "specialist"]
    assert specialists == ["url_analyst", "brand_visual", "code_analyst"]
    orch = next(c for c in done.calls if c.name == "orchestrator")
    assert orch.usage.input_tokens == 4500 and orch.usage.cache_write_tokens == 4000


def test_dispatch_and_precheck_run_concurrently(aws, direct_env):
    started, release = threading.Event(), threading.Event()
    dispatcher = FakeDispatcher(started=started, release=release)

    class GatedTools(StubTools):
        def invoke_agent_runtime(self, **kwargs):
            # The precheck only answers once the dispatcher call is in flight.
            assert started.wait(10), "dispatch did not start while the precheck ran"
            release.set()
            return super().invoke_agent_runtime(**kwargs)

    run_scan.process_message(
        seed(),
        tools_client=GatedTools(outcome="ok", extra={"final_status": 200}),
        dispatcher=dispatcher,
        bedrock=FakeBedrock(),
    )
    assert store.get_scan("s1").status == "COMPLETE"


def test_precheck_404_takes_the_fast_path_without_a_model_call(aws, direct_env):
    bedrock = FakeBedrock()
    run_scan.process_message(
        seed(), tools_client=StubTools(), dispatcher=FakeDispatcher(), bedrock=bedrock
    )
    done = store.get_scan("s1")
    assert done.verdict.verdict == "error_404" and done.report_status is ReportStatus.READY
    assert bedrock.requests == []


def test_failed_dispatch_still_gives_a_verdict_from_error_findings(aws, direct_env):
    bedrock = FakeBedrock()
    run_scan.process_message(
        seed(),
        tools_client=StubTools(outcome="ok", extra={"final_status": 200}),
        dispatcher=FakeDispatcher(error=TimeoutError("read timeout"), write=False),
        bedrock=bedrock,
    )
    done = store.get_scan("s1")
    assert done.status == "COMPLETE"
    assert {f.status.value for f in done.findings} == {"error"}
    message = bedrock.requests[0]["messages"][0]["content"][0]["text"]
    assert "missing_finding" in message


def test_converse_failure_is_retried_then_failed(aws, direct_env):
    error = ClientError({"Error": {"Code": "ValidationException", "Message": "x"}}, "Converse")
    with pytest.raises(run_scan.RetryableScanError):
        run_scan.process_message(
            seed(),
            tools_client=StubTools(outcome="ok", extra={"final_status": 200}),
            dispatcher=FakeDispatcher(),
            bedrock=FakeBedrock(error=error),
        )
    assert store.get_scan("s1").status == "PENDING"


def test_no_verdict_json_is_retried(aws, direct_env):
    with pytest.raises(run_scan.RetryableScanError):
        run_scan.process_message(
            seed(),
            tools_client=StubTools(outcome="ok", extra={"final_status": 200}),
            dispatcher=FakeDispatcher(),
            bedrock=FakeBedrock(verdict="I cannot decide."),
        )


def test_report_failure_keeps_the_verdict(aws, direct_env):
    error = ClientError({"Error": {"Code": "ModelErrorException", "Message": "x"}}, "Converse")
    run_scan.process_message(
        seed(),
        tools_client=StubTools(outcome="ok", extra={"final_status": 200}),
        dispatcher=FakeDispatcher(),
        bedrock=FakeBedrock(report_error=error),
    )
    done = store.get_scan("s1")
    assert done.status == "COMPLETE" and done.verdict.verdict == "phishing"
    assert done.report_status is ReportStatus.FAILED


def test_page_not_observed_cap_still_applies(aws, direct_env, monkeypatch):
    # The cap is code, applied to the model's answer whatever the orchestration path.
    import test_run_scan
    from test_page_observed import GAP, WARNING

    original = test_run_scan.finding

    def unobserved(agent):
        f = original(agent)
        if agent != "url_analyst":
            f.update(page_observed=False, signals=[WARNING, GAP])
        return f

    monkeypatch.setattr(test_run_scan, "finding", unobserved)
    run_scan.process_message(
        seed(),
        tools_client=StubTools(outcome="ok", extra={"final_status": 200}),
        dispatcher=FakeDispatcher(),
        bedrock=FakeBedrock(verdict=json.dumps(dict(COMPACT, risk_score=80))),
    )
    done = store.get_scan("s1")
    assert done.verdict.verdict == "suspicious" and done.verdict.capped_from is not None
    assert done.verdict.risk_score <= 69


def test_direct_prompt_shares_the_judging_rules_with_the_harness_prompt():
    harness = (REPO / "agents/orchestrator/prompt.md").read_text(encoding="utf-8")
    shared = harness[harness.index("## Untrusted content") : harness.index("## Step 4")]
    assert shared in direct.system_prompt()
    assert "dispatcher___analyze_all" not in direct.system_prompt()


def test_findings_block_is_bounded():
    from phish_contracts.models import Finding

    f = Finding.model_validate(
        {
            "agent": "url_analyst",
            "status": "ok",
            "verdict": "phishing",
            "confidence": 80,
            "signals": [{"name": "x", "severity": "high", "evidence": "{" * 4000}] * 20,
            "usage": {"model_id": "m"},
            "latency_ms": 1,
        }
    )
    assert len(direct.findings_block([f, f, f])) <= direct.FINDINGS_CHARS_MAX


def _legit(agent, **over):
    from test_run_scan import finding

    data = {**finding(agent), "verdict": "legitimate", "confidence": 90}
    if agent != "url_analyst":
        data["page_observed"] = True
    return {**data, **over}


def _findings(**per_agent):
    from phish_contracts.models import Finding

    return [
        Finding.model_validate(_legit(a, **per_agent.get(a, {})))
        for a in ("url_analyst", "brand_visual", "code_analyst")
    ]


def test_unanimous_legitimate_needs_three_confident_observed_clean_findings():
    verdict = direct.unanimous_legitimate(_findings())
    assert verdict is not None and verdict.verdict == "legitimate"
    assert verdict.action == "allow" and verdict.confidence == "high" and verdict.risk_score == 5
    serious = [{"name": "brand_domain_mismatch", "severity": "high", "evidence": "x"}]
    for change in (
        {"brand_visual": {"verdict": "suspicious"}},
        {"code_analyst": {"status": "error"}},
        {"url_analyst": {"confidence": 79}},
        {"brand_visual": {"page_observed": False}},
        {"brand_visual": {"page_observed": None}, "code_analyst": {"page_observed": None}},
        {"code_analyst": {"signals": serious}},
    ):
        assert direct.unanimous_legitimate(_findings(**change)) is None, change
    assert direct.unanimous_legitimate(_findings()[:2]) is None


def _write_legit(scan_id, **per_agent):
    import os

    import boto3

    s3 = boto3.client("s3", region_name="us-west-2")
    for agent in ("url_analyst", "brand_visual", "code_analyst"):
        s3.put_object(
            Bucket=os.environ["ARTIFACTS_BUCKET"],
            Key=f"scans/{scan_id}/findings/{agent}.json",
            Body=json.dumps(_legit(agent, **per_agent.get(agent, {}))),
        )


class LegitDispatcher(FakeDispatcher):
    def __init__(self, per_agent=None, **kwargs):
        super().__init__(write=False, **kwargs)
        self.per_agent = per_agent or {}

    def invoke_agent_runtime(self, **kwargs):
        response = super().invoke_agent_runtime(**kwargs)
        scan_id = json.loads(kwargs["payload"])["params"]["arguments"]["scan_id"]
        _write_legit(scan_id, **self.per_agent)
        return response


LEGIT_VERDICT = json.dumps({**COMPACT, "verdict": "legitimate", "action": "allow", "risk_score": 5})


@pytest.mark.parametrize("enabled", [True, False])
def test_unanimous_fast_path_skips_only_the_verdict_turn(aws, direct_env, monkeypatch, enabled):
    if enabled:
        monkeypatch.setenv("UNANIMOUS_FAST_PATH", "1")
    clients.reset()
    bedrock = FakeBedrock(verdict=LEGIT_VERDICT)
    run_scan.process_message(
        seed(),
        agentcore=NoHarness(),
        tools_client=StubTools(outcome="ok", extra={"final_status": 200}),
        dispatcher=LegitDispatcher(),
        bedrock=bedrock,
    )
    done = store.get_scan("s1")
    assert done.status == "COMPLETE" and done.report_status is ReportStatus.READY
    assert done.verdict.verdict == "legitimate" and done.verdict.action == "allow"
    assert DISCLAIMER_MARKDOWN in done.verdict.report_markdown
    names = [c.name for c in done.calls if c.kind == "harness"]
    if enabled:
        (report_req,) = bedrock.requests
        assert done.verdict.summary == direct.UNANIMOUS_SUMMARY
        # The report turn restates the stored verdict and findings in one fresh message.
        assert [m["role"] for m in report_req["messages"]] == ["user"]
        assert names == ["report"]
    else:
        assert len(bedrock.requests) == 2 and names == ["orchestrator", "report"]


def test_unanimous_fast_path_never_allows_an_unobserved_page(aws, direct_env, monkeypatch):
    monkeypatch.setenv("UNANIMOUS_FAST_PATH", "1")
    clients.reset()
    bedrock = FakeBedrock(verdict=LEGIT_VERDICT)
    run_scan.process_message(
        seed(),
        agentcore=NoHarness(),
        tools_client=StubTools(outcome="ok", extra={"final_status": 200}),
        dispatcher=LegitDispatcher({"brand_visual": {"page_observed": False}}),
        bedrock=bedrock,
    )
    done = store.get_scan("s1")
    # The model was asked, and the page-not-observed cap still held the stored verdict.
    assert [c.name for c in done.calls if c.kind == "harness"] == ["orchestrator", "report"]
    assert done.verdict.summary != direct.UNANIMOUS_SUMMARY


SPECIALIST_ARNS = {
    a: f"arn:aws:bedrock-agentcore:us-west-2:1:runtime/{a}"
    for a in ("url_analyst", "brand_visual", "code_analyst")
}


class FakeSpecialists:
    """The three specialist Runtimes: each `analyze` writes that specialist's Finding to S3."""

    def __init__(self, fail=()):
        self.fail, self.calls = set(fail), []
        self.lock = threading.Lock()

    def invoke_agent_runtime(self, **kwargs):
        import os

        import boto3
        from test_run_scan import finding

        with self.lock:
            self.calls.append(kwargs)
        agent = next(a for a, arn in SPECIALIST_ARNS.items() if arn == kwargs["agentRuntimeArn"])
        if agent in self.fail:
            raise ClientError({"Error": {"Code": "ThrottlingException"}}, "InvokeAgentRuntime")
        params = json.loads(kwargs["payload"])["params"]
        assert params["name"] == "analyze"
        scan_id = params["arguments"]["scan_id"]
        boto3.client("s3", region_name="us-west-2").put_object(
            Bucket=os.environ["ARTIFACTS_BUCKET"],
            Key=f"scans/{scan_id}/findings/{agent}.json",
            Body=json.dumps(finding(agent)),
        )
        text = json.dumps(finding(agent))
        body = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": text}]}}
        return {"response": io.BytesIO(json.dumps(body).encode())}


@pytest.fixture
def specialists_env(monkeypatch, direct_env):
    monkeypatch.setenv("DIRECT_SPECIALISTS", "1")
    for agent, arn in SPECIALIST_ARNS.items():
        monkeypatch.setenv(f"{agent.upper()}_RUNTIME_ARN", arn)
    clients.reset()


def test_direct_specialists_need_the_flag_and_all_three_arns(monkeypatch, direct_env):
    assert settings().direct_specialists is False
    monkeypatch.setenv("DIRECT_SPECIALISTS", "1")
    for agent, arn in list(SPECIALIST_ARNS.items())[:2]:
        monkeypatch.setenv(f"{agent.upper()}_RUNTIME_ARN", arn)
    clients.reset()
    assert settings().direct_specialists is False
    monkeypatch.setenv("CODE_ANALYST_RUNTIME_ARN", SPECIALIST_ARNS["code_analyst"])
    clients.reset()
    assert settings().direct_specialists is True


def test_the_worker_calls_the_three_specialists_without_the_dispatcher(aws, specialists_env):
    runtimes, bedrock = FakeSpecialists(), FakeBedrock()
    run_scan.process_message(
        seed(),
        agentcore=NoHarness(),
        tools_client=StubTools(outcome="ok", extra={"final_status": 200}),
        dispatcher=runtimes,
        bedrock=bedrock,
    )
    done = store.get_scan("s1")
    assert done.status == "COMPLETE" and done.verdict.verdict == "phishing"
    assert sorted(c["agentRuntimeArn"] for c in runtimes.calls) == sorted(SPECIALIST_ARNS.values())
    assert len({c["runtimeSessionId"] for c in runtimes.calls}) == 3
    assert [f.status for f in done.findings] == ["ok", "ok", "ok"]


def test_a_failed_specialist_becomes_an_error_finding(aws, specialists_env):
    runtimes = FakeSpecialists(fail={"brand_visual"})
    run_scan.process_message(
        seed(),
        agentcore=NoHarness(),
        tools_client=StubTools(outcome="ok", extra={"final_status": 200}),
        dispatcher=runtimes,
        bedrock=FakeBedrock(),
    )
    done = store.get_scan("s1")
    assert done.status == "COMPLETE"
    by_agent = {f.agent: f.status for f in done.findings}
    assert by_agent == {"url_analyst": "ok", "brand_visual": "error", "code_analyst": "ok"}


@pytest.mark.parametrize("unanimous", [False, True])
def test_a_scan_another_worker_stored_is_not_remembered_or_counted_twice(
    aws, direct_env, monkeypatch, unanimous
):
    if unanimous:
        monkeypatch.setenv("UNANIMOUS_FAST_PATH", "1")
        clients.reset()
    remembered, emitted = [], []
    monkeypatch.setattr(run_scan.store, "complete_scan", lambda *a, **k: False)
    monkeypatch.setattr(run_scan.scan_memory, "remember", lambda *a, **k: remembered.append(a))
    monkeypatch.setattr(run_scan, "_emit", lambda *a, **k: emitted.append(a))
    bedrock = FakeBedrock()
    run_scan.process_message(
        seed(),
        agentcore=NoHarness(),
        tools_client=StubTools(outcome="ok", extra={"final_status": 200}),
        dispatcher=LegitDispatcher() if unanimous else FakeDispatcher(),
        bedrock=bedrock,
    )
    assert remembered == [] and emitted == []
    # No report turn either: the other worker owns this scan's report.
    assert len(bedrock.requests) == (0 if unanimous else 1)
