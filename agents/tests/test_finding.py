# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json
import time

import pytest
from agent_fakes import FakeS3

from phish_agents.common.finding import (
    FindingDraft,
    SignalDraft,
    build_finding,
    error_finding,
    persist_finding,
    validate_scan_id,
)
from phish_contracts.models import Usage

USAGE = Usage(input_tokens=10, output_tokens=5, model_id="global.anthropic.claude-sonnet-5-5")


def test_build_from_draft():
    draft = FindingDraft(
        verdict="phishing",
        confidence=88,
        signals=[SignalDraft(name="typosquat", severity="high", evidence="g00gle")],
    )
    f = build_finding(
        "url_analyst",
        draft,
        blocked=False,
        usage=USAGE,
        started=time.monotonic(),
        calls=[],
        artifacts=[],
    )
    assert f.status == "ok" and f.verdict == "phishing" and f.signals[0].name == "typosquat"


def test_build_blocked_has_unknown_verdict_and_signal():
    f = build_finding(
        "brand_visual",
        None,
        blocked=True,
        usage=USAGE,
        started=time.monotonic(),
        calls=[],
        artifacts=[],
    )
    assert f.status == "blocked_by_guardrail" and f.verdict == "unknown" and f.confidence == 0
    assert f.signals[0].name == "model_guardrail_block"


def test_no_usable_answer_without_a_block_is_an_error_not_a_refusal():
    f = build_finding(
        "brand_visual",
        None,
        blocked=False,
        usage=USAGE,
        started=time.monotonic(),
        calls=[],
        artifacts=["a.png"],
    )
    assert f.status == "error" and f.verdict == "unknown" and f.confidence == 0
    assert f.signals[0].name == "analysis_error"
    assert "model_guardrail_block" not in [s.name for s in f.signals]
    assert f.artifacts == ["a.png"]


def test_error_finding():
    f = error_finding(
        "code_analyst", "navigation failed", usage=USAGE, started=time.monotonic(), calls=[]
    )
    assert f.status == "error" and "navigation failed" in f.signals[0].evidence


@pytest.mark.parametrize("bad", ["../x", "a/b", "", "x" * 65, "sp ace"])
def test_scan_id_rejects_path_tricks(bad):
    with pytest.raises(ValueError):
        validate_scan_id(bad)


def test_persist_writes_json_under_scan_prefix():
    s3 = FakeS3()
    f = error_finding("url_analyst", "r", usage=USAGE, started=time.monotonic(), calls=[])
    key = persist_finding(s3, "bucket", "scan-1234abcd", f)
    assert key == "scans/scan-1234abcd/findings/url_analyst.json"
    body = s3.objects[key]
    assert (
        body["ContentType"] == "application/json"
        and json.loads(body["Body"])["agent"] == "url_analyst"
    )
