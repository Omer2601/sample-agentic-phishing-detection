# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import aws_cdk as cdk
import pytest
from aws_cdk import aws_lambda as lambda_
from aws_cdk.assertions import Match, Template

from phish_infra.config import load_config
from phish_infra.constructs.agents import AgentsLayer
from phish_infra.constructs.api import ROUTES, ScanApi
from phish_infra.constructs.data import DataLayer
from phish_infra.constructs.guardrails import Guardrails
from phish_infra.constructs.pipeline import ScanPipeline


@pytest.fixture(scope="module")
def t(app_context, test_env, tmp_path_factory):
    app = cdk.App(context=app_context)
    stack = cdk.Stack(app, "S", env=test_env)
    cfg = load_config(app.node)
    data = DataLayer(stack, "Data", cfg=cfg)
    g = Guardrails(stack, "G", cfg=cfg)
    agents = AgentsLayer(
        stack, "Agents", cfg=cfg, key=data.key, artifacts_bucket=data.artifacts_bucket
    )
    code = lambda_.Code.from_asset(str(tmp_path_factory.mktemp("code")))
    pipeline = ScanPipeline(
        stack, "P", cfg=cfg, data=data, guardrails=g, agents=agents, backend_code=code
    )
    ScanApi(
        stack,
        "Api",
        cfg=cfg,
        data=data,
        guardrails=g,
        pipeline=pipeline,
        agents=agents,
        backend_code=code,
        proxy_role_name="phish-ui-proxy-dev",
    )
    return Template.from_stack(stack)


def test_routes_match_interface():
    assert ROUTES == [
        ("POST", "/scan"),
        ("GET", "/scans/lookup"),
        ("GET", "/scans/*"),
        ("GET", "/scans/*/report"),
        ("POST", "/scans/*/retry"),
        ("POST", "/batches"),
        ("GET", "/batches"),
        ("GET", "/batches/*"),
        ("GET", "/batches/*/report"),
        ("POST", "/batches/*/retry-failed"),
        ("GET", "/history"),
        ("GET", "/stats"),
        ("GET", "/stats/export"),
        ("GET", "/feed/phishing"),
        ("GET", "/health"),
    ]


def test_health_is_the_only_unauthenticated_route(t):
    ms = t.find_resources("AWS::ApiGateway::Method")
    open_ = [m for m in ms.values() if m["Properties"]["AuthorizationType"] == "NONE"]
    assert len(open_) == 1
    assert len(ms) == len(ROUTES)


def test_path_parameter_is_id(t):
    parts = {
        r["Properties"]["PathPart"] for r in t.find_resources("AWS::ApiGateway::Resource").values()
    }
    assert "{id}" in parts
    assert not {p for p in parts if p.startswith("{") and p != "{id}"}


def test_resource_policy_has_no_deny_with_not_resource(t):
    # Cross-account IAM callers need an Allow in the resource policy too, and only /health has
    # one, so no Deny with NotResource (a high-risk IAM pattern) is needed to keep them out.
    rest_api = next(iter(t.find_resources("AWS::ApiGateway::RestApi").values()))
    statements = rest_api["Properties"]["Policy"]["Statement"]
    assert all(s["Effect"] == "Allow" for s in statements)
    assert all("NotResource" not in s for s in statements)


def test_resource_policy_allows_only_health(t):
    # No account-wide Allow: a same-account principal is authorized by its own identity policy
    # (the web proxy role, or a holder of ApiInvokePolicy), not by the API resource policy.
    rest_api = next(iter(t.find_resources("AWS::ApiGateway::RestApi").values()))
    statements = rest_api["Properties"]["Policy"]["Statement"]
    allows = [s for s in statements if s["Effect"] == "Allow"]
    assert [s["Resource"] for s in allows] == ["execute-api:/*/GET/health"]


def test_stage_throttles_and_logs_without_bodies(t):
    t.has_resource_properties(
        "AWS::ApiGateway::Stage",
        {
            "StageName": "dev",
            "TracingEnabled": True,
            "MethodSettings": [
                Match.object_like(
                    {
                        "DataTraceEnabled": False,
                        "LoggingLevel": "INFO",
                        "ThrottlingRateLimit": 50,
                        "ThrottlingBurstLimit": 100,
                    }
                )
            ],
            "AccessLogSetting": Match.object_like({"DestinationArn": Match.any_value()}),
        },
    )


def test_batch_model_caps_json_list_at_50(t):
    t.has_resource_properties(
        "AWS::ApiGateway::Model",
        {
            "Name": "BatchRequest",
            "Schema": Match.object_like(
                {
                    "properties": Match.object_like(
                        {
                            "urls": Match.object_like({"maxItems": 50}),
                            "count": Match.object_like({"minimum": 1, "maximum": 1000}),
                        }
                    )
                }
            ),
        },
    )


def test_api_lambda_env(t):
    t.has_resource_properties(
        "AWS::Lambda::Function",
        {
            "Handler": "phish_backend.api.app.handler",
            "Environment": {
                "Variables": Match.object_like(
                    {
                        "PROXY_ROLE_ARN": Match.any_value(),
                        "SCAN_QUEUE_URL": Match.any_value(),
                        "GUARDRAIL_INPUT_ID": Match.any_value(),
                        "GUARDRAIL_INPUT_VERSION": Match.any_value(),
                        "RETENTION_DAYS": "90",
                        "UI_BATCH_MAX": "200",
                        "API_BATCH_MAX": "1000",
                        "JSON_BATCH_MAX": "50",
                    }
                )
            },
        },
    )


def test_api_role_reads_stats_with_batch_get(t):
    (fn,) = t.find_resources(
        "AWS::Lambda::Function", {"Properties": {"Handler": "phish_backend.api.app.handler"}}
    ).values()
    role = fn["Properties"]["Role"]["Fn::GetAtt"][0]
    text = str(
        [
            p
            for p in t.find_resources("AWS::IAM::Policy").values()
            if {"Ref": role} in p["Properties"]["Roles"]
        ]
    )
    for action in ("dynamodb:BatchGetItem", "s3:PutObject", "bedrock:ApplyGuardrail"):
        assert action in text, action


def test_security_metric_filters_and_alarms(t):
    t.resource_count_is("AWS::Logs::MetricFilter", 2)
    names = {
        a["Properties"]["AlarmName"] for a in t.find_resources("AWS::CloudWatch::Alarm").values()
    }
    assert {
        "phish-api-4xx-dev",
        "phish-api-5xx-dev",
        "phish-auth-failures-dev",
        "phish-unauth-access-dev",
    } <= names


def test_invoke_policy_lists_every_route(t):
    policy = next(iter(t.find_resources("AWS::IAM::ManagedPolicy").values()))
    statement = policy["Properties"]["PolicyDocument"]["Statement"][0]
    assert len(statement["Resource"]) == len(ROUTES)


def test_api_outputs_have_exact_keys(t):
    assert {"ApiUrl", "ApiInvokePolicyArn"} <= set(t.find_outputs("*"))


def _api_s3_keys(t, action):
    (fn,) = t.find_resources(
        "AWS::Lambda::Function", {"Properties": {"Handler": "phish_backend.api.app.handler"}}
    ).values()
    role = fn["Properties"]["Role"]["Fn::GetAtt"][0]
    keys = set()
    for p in t.find_resources("AWS::IAM::Policy").values():
        if {"Ref": role} not in p["Properties"]["Roles"]:
            continue
        for st in p["Properties"]["PolicyDocument"]["Statement"]:
            if st["Action"] != action:
                continue
            resources = st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]]
            for r in resources:
                keys.add(r["Fn::Join"][1][-1].lstrip("/"))
    return keys


def test_api_reads_only_screenshots_and_reports(t):
    assert _api_s3_keys(t, "s3:GetObject") == {
        "scans/*/screenshot.png",
        "scans/*/report.html",
        "batches/*/report.html",
    }


def test_api_writes_only_uploads_and_reports(t):
    assert _api_s3_keys(t, "s3:PutObject") == {
        "uploads/*",
        "scans/*/report.html",
        "batches/*/report.html",
    }


def test_report_resources_are_get_only(t):
    resources = t.find_resources("AWS::ApiGateway::Resource")
    report_ids = {k for k, r in resources.items() if r["Properties"]["PathPart"] == "report"}
    assert len(report_ids) == 2
    methods = [
        m["Properties"]
        for m in t.find_resources("AWS::ApiGateway::Method").values()
        if m["Properties"]["ResourceId"].get("Ref") in report_ids
    ]
    assert [m["HttpMethod"] for m in methods] == ["GET", "GET"]
    assert {m["AuthorizationType"] for m in methods} == {"AWS_IAM"}


def _api_statements(t):
    (fn,) = t.find_resources(
        "AWS::Lambda::Function", {"Properties": {"Handler": "phish_backend.api.app.handler"}}
    ).values()
    role = fn["Properties"]["Role"]["Fn::GetAtt"][0]
    return fn, [
        st
        for p in t.find_resources("AWS::IAM::Policy").values()
        if {"Ref": role} in p["Properties"]["Roles"]
        for st in p["Properties"]["PolicyDocument"]["Statement"]
    ]


def test_idempotency_table_is_wired_with_least_privilege(t):
    fn, statements = _api_statements(t)
    tables = t.find_resources(
        "AWS::DynamoDB::Table", {"Properties": {"TableName": "phish-idempotency-dev"}}
    )
    (table_id,) = tables
    assert fn["Properties"]["Environment"]["Variables"]["IDEMPOTENCY_TABLE"] == {"Ref": table_id}
    arn = {"Fn::GetAtt": [table_id, "Arn"]}
    grants = [
        st
        for st in statements
        if arn in (st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]])
    ]
    # One statement on the table ARN only (no index, no wildcard), exactly the three actions.
    assert len(grants) == 1
    assert sorted(grants[0]["Action"]) == [
        "dynamodb:DeleteItem",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
    ]
