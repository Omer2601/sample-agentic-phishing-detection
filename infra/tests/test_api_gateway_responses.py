# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Errors API Gateway builds itself must carry the same disclaimer as Lambda-built ones."""

import json

import aws_cdk as cdk
import pytest
from aws_cdk import aws_lambda as lambda_
from aws_cdk.assertions import Template

from phish_contracts.disclaimer import DISCLAIMER_TEXT as CONTRACT_DISCLAIMER
from phish_infra.config import load_config
from phish_infra.constructs.agents import AgentsLayer
from phish_infra.constructs.api import (
    DISCLAIMER_TEXT,
    FIXED_GATEWAY_MESSAGES,
    GATEWAY_ERROR_TYPES,
    ScanApi,
)
from phish_infra.constructs.data import DataLayer
from phish_infra.constructs.guardrails import Guardrails
from phish_infra.constructs.pipeline import ScanPipeline

EXPECTED_TYPES = {
    "BAD_REQUEST_BODY",
    "BAD_REQUEST_PARAMETERS",
    "MISSING_AUTHENTICATION_TOKEN",
    "ACCESS_DENIED",
    "UNAUTHORIZED",
    "INVALID_SIGNATURE",
    "EXPIRED_TOKEN",
    "THROTTLED",
    "RESOURCE_NOT_FOUND",
    "DEFAULT_4XX",
    "DEFAULT_5XX",
}
SIGV4_TYPES = {"INVALID_SIGNATURE", "EXPIRED_TOKEN"}


@pytest.fixture(scope="module")
def responses(app_context, test_env, tmp_path_factory):
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
    found = Template.from_stack(stack).find_resources("AWS::ApiGateway::GatewayResponse")
    return {r["Properties"]["ResponseType"]: r["Properties"] for r in found.values()}


def test_disclaimer_copy_equals_contract():
    assert DISCLAIMER_TEXT == CONTRACT_DISCLAIMER


def test_every_error_type_is_covered_exactly_once(responses):
    assert set(responses) == EXPECTED_TYPES
    assert len(GATEWAY_ERROR_TYPES) == len(EXPECTED_TYPES)


@pytest.mark.parametrize("response_type", sorted(EXPECTED_TYPES - SIGV4_TYPES))
def test_template_is_the_error_envelope_and_valid_json(responses, response_type):
    template = responses[response_type]["ResponseTemplates"]["application/json"]
    # API Gateway swaps the placeholder for the (already JSON-quoted) message.
    body = json.loads(template.replace("$context.error.messageString", '"Invalid request body"'))
    assert body == {"error": "Invalid request body", "disclaimer": CONTRACT_DISCLAIMER}


@pytest.mark.parametrize(
    ("response_type", "gw_id"),
    [("INVALID_SIGNATURE", "InvalidSignature"), ("EXPIRED_TOKEN", "ExpiredToken")],
)
def test_sigv4_errors_use_a_fixed_message_and_never_echo_the_request(
    responses, response_type, gw_id
):
    template = responses[response_type]["ResponseTemplates"]["application/json"]
    # The service message for these types is multi-line (invalid JSON once substituted) and
    # repeats the canonical request, so no $context.error field may appear.
    assert "$context" not in template
    assert json.loads(template) == {
        "error": FIXED_GATEWAY_MESSAGES[gw_id],
        "disclaimer": CONTRACT_DISCLAIMER,
    }


@pytest.mark.parametrize("response_type", sorted(EXPECTED_TYPES))
def test_headers_json_and_no_status_override(responses, response_type):
    props = responses[response_type]
    headers = props["ResponseParameters"]
    assert headers["gatewayresponse.header.Content-Type"] == "'application/json'"
    assert headers["gatewayresponse.header.Cache-Control"] == "'no-store'"
    assert headers["gatewayresponse.header.X-Content-Type-Options"] == "'nosniff'"
    # The default status code of each type is kept; no CORS headers because browsers reach
    # the API through the web proxy, and no other API response sets them.
    assert "StatusCode" not in props
    assert not [h for h in headers if "Access-Control" in h]
