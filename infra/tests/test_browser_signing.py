# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""-c browserSigning: one signed (Web Bot Auth) custom browser, or the AWS-managed one."""

import json

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from phish_infra.config import load_config
from phish_infra.constructs.agents import AgentsLayer
from phish_infra.constructs.data import DataLayer

MANAGED = "aws.browser.v1"
# Only the tools Runtime drives the browser; the specialists call it through the tools Gateway.
BROWSER_RUNTIMES = ["tools_server"]


def synth(app_context, test_env, **extra):
    app = cdk.App(context={**app_context, **extra})
    stack = cdk.Stack(app, "S", env=test_env)
    cfg = load_config(app.node)
    data = DataLayer(stack, "Data", cfg=cfg)
    AgentsLayer(stack, "Agents", cfg=cfg, key=data.key, artifacts_bucket=data.artifacts_bucket)
    return Template.from_stack(stack)


def runtime_env(template, name):
    (runtime,) = [
        r
        for r in template.find_resources("AWS::BedrockAgentCore::Runtime").values()
        if r["Properties"]["AgentRuntimeName"] == f"phish_{name}"
    ]
    return runtime["Properties"]["EnvironmentVariables"]


def browser_statements(template):
    return [
        st
        for p in template.find_resources("AWS::IAM::Policy").values()
        for st in p["Properties"]["PolicyDocument"]["Statement"]
        if "bedrock-agentcore:StartBrowserSession" in json.dumps(st["Action"])
    ]


@pytest.fixture(scope="module", params=[False, True], ids=["default", "agentRegistry"])
def signed(request, harness_context, test_env):
    return request.param, synth(
        harness_context, test_env, agentRegistry=request.param, browserSigning=True
    )


@pytest.fixture(scope="module", params=[False, True], ids=["default", "agentRegistry"])
def unsigned(request, harness_context, test_env):
    t = synth(harness_context, test_env, agentRegistry=request.param, browserSigning=False)
    return request.param, t


def test_signing_is_off_by_default(app_context):
    # Opt-in: Web Bot Auth is in preview and added 1 to 4 s per page load in a 2026-10-11 test.
    app = cdk.App(context={**app_context})
    assert load_config(app.node).browser_signing is False
    app = cdk.App(context={**app_context, "browserSigning": "true"})
    assert load_config(app.node).browser_signing is True


def test_one_signed_public_custom_browser(signed):
    _, t = signed
    (browser,) = t.find_resources("AWS::BedrockAgentCore::BrowserCustom").values()
    props = browser["Properties"]
    assert props["BrowserSigning"] == {"Enabled": True}
    assert props["NetworkConfiguration"]["NetworkMode"] == "PUBLIC"


def test_browser_runtimes_get_the_custom_browser_id(signed):
    mode, t = signed
    (logical_id,) = t.find_resources("AWS::BedrockAgentCore::BrowserCustom")
    for name in BROWSER_RUNTIMES:
        assert runtime_env(t, name)["BROWSER_ID"] == {"Fn::GetAtt": [logical_id, "BrowserId"]}


def test_browser_iam_is_scoped_to_the_custom_browser(signed):
    mode, t = signed
    (logical_id,) = t.find_resources("AWS::BedrockAgentCore::BrowserCustom")
    statements = browser_statements(t)
    assert len(statements) == len(BROWSER_RUNTIMES)
    for st in statements:
        text = json.dumps(st["Resource"])
        assert MANAGED not in text
        assert json.dumps({"Fn::GetAtt": [logical_id, "BrowserArn"]}) in text


def test_unsigned_keeps_the_managed_browser(unsigned):
    mode, t = unsigned
    assert not t.find_resources("AWS::BedrockAgentCore::BrowserCustom")
    for name in BROWSER_RUNTIMES:
        assert runtime_env(t, name)["BROWSER_ID"] == MANAGED
    for st in browser_statements(t):
        assert f"browser/{MANAGED}" in json.dumps(st["Resource"])
