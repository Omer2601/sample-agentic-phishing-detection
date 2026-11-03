# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""POST /scan dedup flag, the dedup index, GET /scans/lookup and the force field."""

import aws_cdk as cdk
import pytest
from aws_cdk import aws_lambda as lambda_
from aws_cdk.assertions import Match, Template

from phish_infra.config import load_config
from phish_infra.constructs.agents import AgentsLayer
from phish_infra.constructs.api import ScanApi
from phish_infra.constructs.data import DataLayer
from phish_infra.constructs.guardrails import Guardrails
from phish_infra.constructs.pipeline import ScanPipeline


def synth(app_context, test_env, code_dir, **extra):
    app = cdk.App(context={**app_context, **extra})
    stack = cdk.Stack(app, "S", env=test_env)
    cfg = load_config(app.node)
    data = DataLayer(stack, "Data", cfg=cfg)
    g = Guardrails(stack, "G", cfg=cfg)
    agents = AgentsLayer(
        stack, "Agents", cfg=cfg, key=data.key, artifacts_bucket=data.artifacts_bucket
    )
    code = lambda_.Code.from_asset(str(code_dir))
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


@pytest.fixture(scope="module")
def t(app_context, test_env, tmp_path_factory):
    return synth(app_context, test_env, tmp_path_factory.mktemp("code"))


def api_env(template):
    (fn,) = template.find_resources(
        "AWS::Lambda::Function", {"Properties": {"Handler": "phish_backend.api.app.handler"}}
    ).values()
    return fn["Properties"]["Environment"]["Variables"]


def test_dedup_is_off_by_default_and_the_flag_turns_it_on(app_context, test_env, tmp_path, t):
    assert load_config(cdk.App(context=app_context).node).scan_dedup is False
    assert api_env(t)["SCAN_DEDUP_ENABLED"] == "0"
    on = synth(app_context, test_env, tmp_path, scanDedup="true")
    assert api_env(on)["SCAN_DEDUP_ENABLED"] == "1"


def test_the_dedup_index_projects_only_status_and_completed_at(t):
    t.has_resource_properties(
        "AWS::DynamoDB::Table",
        {
            "TableName": "phish-scans-dev",
            "GlobalSecondaryIndexes": Match.array_with(
                [
                    {
                        "IndexName": "dedup-queued_at",
                        "KeySchema": [
                            {"AttributeName": "dedup_key", "KeyType": "HASH"},
                            {"AttributeName": "queued_at", "KeyType": "RANGE"},
                        ],
                        "Projection": {
                            "ProjectionType": "INCLUDE",
                            "NonKeyAttributes": ["status", "completed_at"],
                        },
                    }
                ]
            ),
        },
    )


def test_lookup_is_a_get_with_iam_auth(t):
    resources = t.find_resources("AWS::ApiGateway::Resource")
    (lookup_id,) = [k for k, r in resources.items() if r["Properties"]["PathPart"] == "lookup"]
    methods = [
        m["Properties"]
        for m in t.find_resources("AWS::ApiGateway::Method").values()
        if m["Properties"]["ResourceId"].get("Ref") == lookup_id
    ]
    assert [(m["HttpMethod"], m["AuthorizationType"]) for m in methods] == [("GET", "AWS_IAM")]


def test_scan_model_accepts_force_and_nothing_else_new(t):
    t.has_resource_properties(
        "AWS::ApiGateway::Model",
        {
            "Name": "ScanRequest",
            "Schema": Match.object_like(
                {
                    "required": ["url"],
                    "additionalProperties": False,
                    "properties": {
                        "url": Match.object_like({"type": "string"}),
                        "force": {"type": "boolean"},
                    },
                }
            ),
        },
    )
