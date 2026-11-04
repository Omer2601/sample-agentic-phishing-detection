# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from phish_infra.config import load_config
from phish_infra.stacks.edge_waf import EdgeWafStack
from phish_infra.stacks.main import PhishTriageStack

ACCOUNT = "123456789012"


def synth(app_context, **extra):
    app = cdk.App(context={**app_context, **extra})
    cfg = load_config(app.node)
    edge = EdgeWafStack(
        app,
        "Edge",
        cfg=cfg,
        env=cdk.Environment(account=ACCOUNT, region="us-east-1"),
        cross_region_references=True,
    )
    main = PhishTriageStack(
        app,
        "Main",
        cfg=cfg,
        web_acl_arn=edge.web_acl_arn,
        web_search=edge.web_search,
        env=cdk.Environment(account=ACCOUNT, region="us-west-2"),
        cross_region_references=True,
    )
    return cfg, Template.from_stack(edge), Template.from_stack(main)


@pytest.fixture(scope="module")
def on(app_context):
    return synth(app_context)


@pytest.fixture(scope="module")
def off(app_context):
    return synth(app_context, webSearch="false")


def runtime_env(main: Template, name: str) -> dict:
    [runtime] = [
        r
        for r in main.find_resources("AWS::BedrockAgentCore::Runtime").values()
        if r["Properties"]["AgentRuntimeName"] == f"phish_{name}"
    ]
    return runtime["Properties"]["EnvironmentVariables"]


def statements(template: Template) -> list[dict]:
    return [
        s
        for p in template.find_resources("AWS::IAM::Policy").values()
        for s in p["Properties"]["PolicyDocument"]["Statement"]
    ]


def test_flag_defaults_on_and_parses_false(on, off):
    assert on[0].web_search is True
    assert off[0].web_search is False


def test_edge_stack_has_an_iam_gateway_with_the_web_search_connector(on):
    _, edge, _ = on
    [gateway] = edge.find_resources("AWS::BedrockAgentCore::Gateway").values()
    props = gateway["Properties"]
    assert props["AuthorizerType"] == "AWS_IAM"
    assert props["ProtocolType"] == "MCP"
    [target] = edge.find_resources("AWS::BedrockAgentCore::GatewayTarget").values()
    tprops = target["Properties"]
    assert tprops["Name"] == "web-search"
    connector = tprops["TargetConfiguration"]["Mcp"]["Connector"]
    assert connector["Source"] == {"ConnectorId": "web-search"}
    assert connector["Configurations"] == [{"Name": "WebSearch", "ParameterValues": {}}]
    assert tprops["CredentialProviderConfigurations"] == [
        {"CredentialProviderType": "GATEWAY_IAM_ROLE"}
    ]


def test_gateway_role_may_invoke_only_the_aws_owned_web_search_tool(on):
    _, edge, _ = on
    [statement] = [
        s for s in statements(edge) if s["Action"] == "bedrock-agentcore:InvokeWebSearch"
    ]
    resource = json.dumps(statement["Resource"])
    assert '"AWS::Partition"' in resource
    assert ":bedrock-agentcore:us-east-1:aws:tool/web-search.v1" in resource


def test_gateway_role_trust_is_scoped_to_this_account_and_gateway(on):
    _, edge, _ = on
    roles = [
        r
        for r in edge.find_resources("AWS::IAM::Role").values()
        if "bedrock-agentcore.amazonaws.com" in json.dumps(r)
    ]
    [role] = roles
    [trust] = role["Properties"]["AssumeRolePolicyDocument"]["Statement"]
    assert "aws:SourceAccount" in trust["Condition"]["StringEquals"]
    assert "gateway/phish-web-search" in json.dumps(trust["Condition"]["ArnLike"])


def test_edge_outputs_the_gateway_url_and_arn(on):
    _, edge, _ = on
    assert {"WebSearchGatewayUrl", "WebSearchGatewayArn"} <= set(edge.find_outputs("*"))


def test_brand_visual_gets_the_gateway_url_and_region(on):
    _, _, main = on
    env = runtime_env(main, "brand_visual")
    assert env["WEB_SEARCH_REGION"] == "us-east-1"
    assert env["WEB_SEARCH_TOOL_NAME"] == "web-search___WebSearch"
    # A cross-region reference: read from SSM in the main region, never a literal URL.
    assert "WEB_SEARCH_GATEWAY_URL" in env and isinstance(env["WEB_SEARCH_GATEWAY_URL"], dict)
    for other in ("url_analyst", "code_analyst"):
        assert not any(k.startswith("WEB_SEARCH") for k in runtime_env(main, other))


def test_only_brand_visual_may_invoke_the_web_search_gateway(on):
    _, _, main = on
    invokers = [
        (logical_id, p)
        for logical_id, p in main.find_resources("AWS::IAM::Policy").items()
        if any(
            s["Action"] == "bedrock-agentcore:InvokeGateway"
            and "WebSearch" in json.dumps(s["Resource"])
            for s in p["Properties"]["PolicyDocument"]["Statement"]
        )
    ]
    assert len(invokers) == 1
    assert "BrandVisual" in json.dumps(invokers[0][1]["Properties"]["Roles"])


def test_flag_off_removes_the_gateway_and_the_wiring(off):
    _, edge, main = off
    assert not edge.find_resources("AWS::BedrockAgentCore::Gateway")
    assert not edge.find_resources("AWS::BedrockAgentCore::GatewayTarget")
    assert not any(k.startswith("WEB_SEARCH") for k in runtime_env(main, "brand_visual"))
    assert "WebSearch" not in json.dumps(main.to_json())


def test_main_stack_alone_has_no_web_search(app_context, test_env):
    app = cdk.App(context=app_context)
    main = PhishTriageStack(app, "Solo", cfg=load_config(app.node), web_acl_arn=None, env=test_env)
    assert not any(
        k.startswith("WEB_SEARCH") for k in runtime_env(Template.from_stack(main), "brand_visual")
    )


def test_edge_gateway_and_target_are_tagged_and_destroyed_in_dev(on):
    _, edge, _ = on
    for kind in ("AWS::BedrockAgentCore::Gateway", "AWS::BedrockAgentCore::GatewayTarget"):
        for res in edge.find_resources(kind).values():
            assert res.get("DeletionPolicy") == "Delete", kind
    [gateway] = edge.find_resources("AWS::BedrockAgentCore::Gateway").values()
    tags = gateway["Properties"]["Tags"]
    assert {"Project", "Owner", "Environment"} <= set(tags)
