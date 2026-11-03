# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Match, Template

from phish_infra.config import load_config
from phish_infra.stacks.edge_waf import EdgeWafStack

# Every *_BODY rule per group, confirmed with `wafv2 describe-managed-rule-group`
# (CLOUDFRONT scope, us-east-1) on 2026-09-29.
SCAN_BODY_RULES = {
    "SizeRestrictions_BODY",
    "EC2MetaDataSSRF_BODY",
    "GenericLFI_BODY",
    "GenericRFI_BODY",
    "CrossSiteScripting_BODY",
}
BAD_INPUT_BODY_RULES = {"JavaDeserializationRCE_BODY", "Log4JRCE_BODY", "ReactJSRCE_BODY"}


@pytest.fixture(scope="module")
def t(app_context):
    app = cdk.App(context=app_context)
    stack = EdgeWafStack(
        app,
        "PhishTriageAgenticEdge",
        cfg=load_config(app.node),
        env=cdk.Environment(account="123456789012", region="us-east-1"),
    )
    return Template.from_stack(stack)


@pytest.fixture(scope="module")
def rules(t):
    acl = next(iter(t.find_resources("AWS::WAFv2::WebACL").values()))
    return {r["Name"]: r for r in acl["Properties"]["Rules"]}


def test_cloudfront_scoped_acl_keeps_every_managed_group(t, rules):
    t.has_resource_properties(
        "AWS::WAFv2::WebACL", {"Scope": "CLOUDFRONT", "DefaultAction": {"Allow": {}}}
    )
    assert list(rules) == [
        "RegisterRateLimit",
        "RateLimit",
        "AWSManagedCommonRuleSet",
        "AWSManagedCommonRuleSetScanRoutes",
        "AWSManagedKnownBadInputs",
        "AWSManagedKnownBadInputsScanRoutes",
    ]


def test_rate_limit_leaves_room_for_polling(rules):
    # One user polling a batch every 2 s and Insights every 5 s is about 210 requests per 5 min.
    assert rules["RateLimit"]["Statement"]["RateBasedStatement"]["Limit"] == 3000


def _scope(rule):
    return rule["Statement"]["ManagedRuleGroupStatement"]["ScopeDownStatement"]


def test_scan_routes_never_hit_a_blocking_body_rule(rules):
    # Evidence (v1 WAF logs, 2026-09-29): SizeRestrictions_BODY blocked 14 batch uploads and
    # EC2MetaDataSSRF_BODY blocked one POST /api/scan, because phishing URLs look like attacks.
    for full, scan, body_rules in (
        ("AWSManagedCommonRuleSet", "AWSManagedCommonRuleSetScanRoutes", SCAN_BODY_RULES),
        ("AWSManagedKnownBadInputs", "AWSManagedKnownBadInputsScanRoutes", BAD_INPUT_BODY_RULES),
    ):
        assert "NotStatement" in _scope(rules[full])
        assert "OrStatement" in _scope(rules[scan])
        overrides = rules[scan]["Statement"]["ManagedRuleGroupStatement"]["RuleActionOverrides"]
        assert {o["Name"] for o in overrides if o["ActionToUse"] == {"Count": {}}} == body_rules
        assert "RuleActionOverrides" not in rules[full]["Statement"]["ManagedRuleGroupStatement"]


def test_scan_route_prefixes(rules):
    scope = _scope(rules["AWSManagedCommonRuleSetScanRoutes"])
    prefixes = {s["ByteMatchStatement"]["SearchString"] for s in scope["OrStatement"]["Statements"]}
    assert prefixes == {"/api/scan", "/api/batches"}  # /api/scan also matches /api/scans/...


def test_blocked_and_counted_requests_are_logged(t):
    t.has_resource_properties(
        "AWS::Logs::LogGroup",
        {"LogGroupName": "aws-waf-logs-phish-edge-dev", "RetentionInDays": 30},
    )
    t.has_resource_properties(
        "AWS::WAFv2::LoggingConfiguration",
        {"LoggingFilter": Match.object_like({"DefaultBehavior": "DROP"})},
    )
    config = next(iter(t.find_resources("AWS::WAFv2::LoggingConfiguration").values()))
    conditions = config["Properties"]["LoggingFilter"]["Filters"][0]["Conditions"]
    assert {c["ActionCondition"]["Action"] for c in conditions} == {"BLOCK", "COUNT"}
    t.has_output("EdgeWebAclArn", {})


def test_waf_logs_are_encrypted_with_a_rotating_cmk(t):
    t.has_resource_properties("AWS::KMS::Key", {"EnableKeyRotation": True})
    (log_group,) = t.find_resources("AWS::Logs::LogGroup").values()
    assert "KmsKeyId" in log_group["Properties"]
    (key,) = t.find_resources("AWS::KMS::Key").values()
    assert "logs.us-east-1.amazonaws.com" in str(key["Properties"]["KeyPolicy"])
    assert key["DeletionPolicy"] == "Delete"


def test_register_has_its_own_tighter_rate_limit_first(rules):
    rule = rules["RegisterRateLimit"]
    assert rule["Priority"] < rules["RateLimit"]["Priority"]
    # Block with a JSON 429, not Challenge or CAPTCHA: the register form posts with fetch and
    # can neither solve a Challenge (202, empty body) nor render a CAPTCHA (bare 405).
    assert rule["Action"] == {
        "Block": {
            "CustomResponse": {
                "ResponseCode": 429,
                "CustomResponseBodyKey": "too_many_registrations",
            }
        }
    }
    rate = rule["Statement"]["RateBasedStatement"]
    assert rate["Limit"] == 10 and rate["AggregateKeyType"] == "IP"
    assert rate["EvaluationWindowSec"] == 300
    statements = rate["ScopeDownStatement"]["AndStatement"]["Statements"]
    matches = {
        (s["ByteMatchStatement"]["SearchString"], s["ByteMatchStatement"]["PositionalConstraint"])
        for s in statements
    }
    assert matches == {("/auth/register", "EXACTLY"), ("POST", "EXACTLY")}


def test_register_block_answers_with_a_json_body_the_form_understands(t):
    (acl,) = t.find_resources("AWS::WAFv2::WebACL").values()
    body = acl["Properties"]["CustomResponseBodies"]["too_many_registrations"]
    assert body == {
        "ContentType": "APPLICATION_JSON",
        "Content": '{"error":"too_many_registrations"}',
    }
