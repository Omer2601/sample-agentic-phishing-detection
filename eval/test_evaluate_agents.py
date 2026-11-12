# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "evaluate_agents", Path(__file__).with_name("evaluate_agents.py")
)
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)


def test_load_dataset_skips_comments(tmp_path):
    p = tmp_path / "d.csv"
    p.write_text("url,label\n# comment\nhttps://a.com,legitimate\nhttps://b.xyz,phishing\n\n")
    assert ev.load_dataset(p) == [("https://a.com", "legitimate"), ("https://b.xyz", "phishing")]


@pytest.mark.parametrize(
    "verdict,mode,expected",
    [
        ("phishing", "phishing", "phishing"),
        ("suspicious", "phishing", "phishing"),
        ("suspicious", "legitimate", "legitimate"),
        ("unknown", "phishing", None),
        ("legitimate", "phishing", "legitimate"),
    ],
)
def test_to_prediction(verdict, mode, expected):
    assert ev.to_prediction(verdict, mode) == expected


def test_score_counts_confusion_and_errors():
    rows = [
        {"label": "phishing", "prediction": "phishing", "latency_ms": 10},
        {"label": "phishing", "prediction": "legitimate", "latency_ms": 20},
        {"label": "legitimate", "prediction": "legitimate", "latency_ms": 30},
        {"label": "legitimate", "prediction": "phishing", "latency_ms": 40},
        {"label": "legitimate", "prediction": None, "latency_ms": 50},
    ]
    s = ev.score(rows)
    assert (s["tp"], s["fn"], s["tn"], s["fp"], s["errors"]) == (1, 1, 1, 1, 1)
    assert s["precision"] == 0.5 and s["recall"] == 0.5 and s["p50_ms"] == 30
    assert s["fpr"] == 0.5


def test_extract_verdict():
    text = (
        'noise <verdict>{"verdict":"phishing","risk_score":90,"confidence":"high","action":"block",'
        '"summary":"s","disagreements":[],"missed_by_specialists":[],"report_markdown":"r"}</verdict>'
    )
    assert ev.extract_verdict(text).risk_score == 90


def test_agentcore_client_makes_one_attempt_with_long_read_timeout():
    import boto3

    # Static placeholder keys stop boto3 from running a credential_process; nothing is sent.
    fake = "testing"
    session = boto3.Session(aws_access_key_id=fake, aws_secret_access_key=fake)
    cfg = ev.agentcore_client(session, "us-west-2").meta.config
    assert cfg.retries["total_max_attempts"] == 1
    assert cfg.read_timeout >= 180


def fake_api(*answers):
    calls = []
    queue = list(answers)

    def call(method, path, body=None):
        calls.append((method, path, body))
        return queue.pop(0)

    return call, calls


def test_run_scan_via_api_posts_with_force_and_polls_to_complete():
    u = "https://a.example/"
    call, calls = fake_api(
        {"scan_id": "s1", "status": "PENDING"},
        {"status": "RUNNING"},
        {"status": "COMPLETE", "verdict": {"verdict": "phishing"}},
    )
    assert ev.run_scan_via_api(call, u, sleep=lambda s: None) == "phishing"
    assert calls[0] == ("POST", "/scan", {"url": u, "force": True})
    assert calls[1:] == [("GET", "/scans/s1", None)] * 2


def test_run_scan_via_api_failed_scan_raises():
    call, _ = fake_api({"scan_id": "s1"}, {"status": "FAILED"})
    with pytest.raises(RuntimeError):
        ev.run_scan_via_api(call, "https://a.example/", sleep=lambda s: None)


def test_run_scan_via_api_times_out():
    now = [0.0]

    def sleep(s):
        now[0] += s

    call, _ = fake_api({"scan_id": "s1"}, *[{"status": "RUNNING"}] * 10)
    with pytest.raises(TimeoutError):
        ev.run_scan_via_api(
            call, "https://a.example/", timeout_s=5, poll_s=2, sleep=sleep, clock=lambda: now[0]
        )


class FakeHttp:
    def __init__(self, status=202, data=b'{"scan_id": "s1"}'):
        self.status, self.data, self.sent = status, data, []

    def request(self, method, url, **kwargs):
        self.sent.append((method, url, kwargs))
        return self


def static_session():
    import boto3

    # Static placeholder keys stop boto3 from running a credential_process; nothing is sent.
    fake = "testing"
    return boto3.Session(aws_access_key_id=fake, aws_secret_access_key=fake)


def test_api_caller_signs_with_sigv4_and_refuses_http():
    http = FakeHttp()
    call = ev.api_caller(static_session(), "us-west-2", "https://api.example/prod/", http=http)
    assert call("POST", "/scan", {"url": "https://a.example/", "force": True}) == {"scan_id": "s1"}
    method, url, kwargs = http.sent[0]
    assert (method, url) == ("POST", "https://api.example/prod/scan")
    auth = kwargs["headers"]["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256") and "/execute-api/" in auth
    assert kwargs["retries"] is False and kwargs["redirect"] is False
    with pytest.raises(ValueError):
        ev.api_caller(static_session(), "us-west-2", "http://x.example")


def test_api_caller_raises_on_non_2xx():
    http = FakeHttp(status=403, data=b"{}")
    call = ev.api_caller(static_session(), "us-west-2", "https://api.example/prod/", http=http)
    with pytest.raises(RuntimeError, match="HTTP 403"):
        call("GET", "/scans/s1")


def run_main_orchestrator(monkeypatch, tmp_path, *extra):
    import json

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    (tmp_path / "results").mkdir()
    dataset = tmp_path / "d.csv"
    dataset.write_text("url,label\nhttps://a.example/,phishing\n")
    outputs = {"ApiUrl": "https://api.example/prod/", "OrchestratorHarnessArn": "arn:h"}
    sentinel, seen = object(), []
    monkeypatch.setattr(ev, "HERE", tmp_path)
    monkeypatch.setattr(ev, "stack_outputs", lambda *a: outputs)
    monkeypatch.setattr(ev, "agentcore_client", lambda *a: object())
    monkeypatch.setattr(ev, "api_caller", lambda s, r, api_url: (seen.append(api_url), sentinel)[1])

    def via_api(call, url):
        seen.append(("api", call is sentinel, url))
        return "phishing"

    def via_harness(client, arn, url, scan_id):
        seen.append(("harness", arn, url))
        return "phishing"

    monkeypatch.setattr(ev, "run_scan_via_api", via_api)
    monkeypatch.setattr(ev, "run_orchestrator", via_harness)
    args = ["--agent", "orchestrator", "--region", "us-west-2", "--dataset", str(dataset)]
    assert ev.main([*args, *extra]) == 0
    (out,) = (tmp_path / "results").glob("*.json")
    return seen, json.loads(out.read_text())


def test_main_scores_orchestrator_through_api_by_default(monkeypatch, tmp_path):
    seen, result = run_main_orchestrator(monkeypatch, tmp_path)
    assert seen == ["https://api.example/prod/", ("api", True, "https://a.example/")]
    assert result["orchestrator_path"] == "api"
    assert result["rows"]["orchestrator"][0]["prediction"] == "phishing"


def test_main_harness_flag_uses_invoke_harness(monkeypatch, tmp_path):
    seen, result = run_main_orchestrator(monkeypatch, tmp_path, "--orchestrator-path", "harness")
    assert seen == [("harness", "arn:h", "https://a.example/")]
    assert result["orchestrator_path"] == "harness"
