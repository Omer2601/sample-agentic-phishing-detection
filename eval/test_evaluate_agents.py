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
