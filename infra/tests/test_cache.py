# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import aws_cdk as cdk
import pytest
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk.assertions import Match, Template

from phish_infra.common import apply_tags
from phish_infra.config import load_config
from phish_infra.constructs.cache import ResultCache


def build(app_context, test_env, context=None, **kwargs):
    app = cdk.App(context={**app_context, **(context or {})})
    stack = cdk.Stack(app, "S", env=test_env)
    cfg = load_config(app.node)
    key = kms.Key(stack, "Key", enable_key_rotation=True)
    cache = ResultCache(stack, "Cache", cfg=cfg, key=key, **kwargs)
    role = iam.Role(stack, "Role", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
    cache.grant_read_write(role)
    apply_tags(stack, cfg)
    return cache, Template.from_stack(stack)


@pytest.fixture(scope="module")
def built(app_context, test_env):
    return build(app_context, test_env)


def test_table_schema_ttl_and_billing(built):
    _, t = built
    t.has_resource_properties(
        "AWS::DynamoDB::Table",
        {
            "TableName": "phish-cache-dev",
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
            "BillingMode": "PAY_PER_REQUEST",
            "TimeToLiveSpecification": {"AttributeName": "ttl", "Enabled": True},
        },
    )


def test_encrypted_with_the_cmk_and_pitr(built):
    _, t = built
    t.has_resource_properties(
        "AWS::DynamoDB::Table",
        {
            "SSESpecification": Match.object_like(
                {"SSEEnabled": True, "SSEType": "KMS", "KMSMasterKeyId": Match.any_value()}
            ),
            "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
        },
    )
    table = next(iter(t.find_resources("AWS::DynamoDB::Table").values()))
    key_id = table["Properties"]["SSESpecification"]["KMSMasterKeyId"]
    assert "Fn::GetAtt" in key_id and key_id["Fn::GetAtt"][0].startswith("Key")


def test_dev_table_is_destroyed_and_prod_retained(app_context, test_env):
    _, dev = build(app_context, test_env)
    assert next(iter(dev.find_resources("AWS::DynamoDB::Table").values()))["DeletionPolicy"] == (
        "Delete"
    )
    _, prod = build(app_context, test_env, {"environment": "prod"})
    table = next(iter(prod.find_resources("AWS::DynamoDB::Table").values()))
    assert table["DeletionPolicy"] == "Retain"
    assert table["Properties"]["TableName"] == "phish-cache-prod"


def test_tags_follow_the_other_constructs(built):
    _, t = built
    table = next(iter(t.find_resources("AWS::DynamoDB::Table").values()))
    keys = {tag["Key"] for tag in table["Properties"]["Tags"]}
    assert {"Project", "Owner", "Environment"} <= keys


def policy_statements(t):
    out = []
    for policy in t.find_resources("AWS::IAM::Policy").values():
        out.extend(policy["Properties"]["PolicyDocument"]["Statement"])
    return out


def as_list(value):
    return value if isinstance(value, list) else [value]


def test_grant_is_point_access_on_this_table_only(built):
    _, t = built
    dynamo = [
        s
        for s in policy_statements(t)
        if any(a.startswith("dynamodb:") for a in as_list(s["Action"]))
    ]
    assert len(dynamo) == 1
    assert sorted(as_list(dynamo[0]["Action"])) == [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
    ]
    resources = as_list(dynamo[0]["Resource"])
    assert len(resources) == 1
    assert resources[0]["Fn::GetAtt"][0].startswith("CacheTable")
    assert resources[0]["Fn::GetAtt"][1] == "Arn"


def test_grant_has_kms_on_the_cmk_and_no_wildcard_resources(built):
    _, t = built
    statements = policy_statements(t)
    kms_stmts = [s for s in statements if any(a.startswith("kms:") for a in as_list(s["Action"]))]
    assert kms_stmts, "the table CMK needs a grant for the role"
    for stmt in kms_stmts:
        resources = as_list(stmt["Resource"])
        assert all(r["Fn::GetAtt"][0].startswith("Key") for r in resources)
    for stmt in statements:
        assert "*" not in as_list(stmt["Resource"]), stmt
        assert not any(a.endswith(":*") or a == "*" for a in as_list(stmt["Action"])), stmt
        for r in as_list(stmt["Resource"]):
            assert not (isinstance(r, str) and "*" in r)


def test_agent_environment_and_default_ttls(built):
    cache, _ = built
    assert cache.rdap_ttl_s == 604800
    assert cache.web_search_ttl_s == 86400
    env = cache.agent_environment
    assert set(env) == {
        "PHISH_CACHE_TABLE",
        "PHISH_RDAP_CACHE_TTL_S",
        "PHISH_WEBSEARCH_CACHE_TTL_S",
    }
    assert env["PHISH_RDAP_CACHE_TTL_S"] == "604800"
    assert env["PHISH_WEBSEARCH_CACHE_TTL_S"] == "86400"


def test_custom_ttls(app_context, test_env):
    cache, _ = build(app_context, test_env, rdap_ttl_hours=24, web_search_ttl_hours=1)
    assert cache.rdap_ttl_s == 86400
    assert cache.web_search_ttl_s == 3600


@pytest.mark.parametrize("bad", [0, -1, 9000])
def test_ttl_bounds(app_context, test_env, bad):
    with pytest.raises(ValueError, match="rdapCacheTtlHours"):
        build(app_context, test_env, rdap_ttl_hours=bad)
    with pytest.raises(ValueError, match="webSearchCacheTtlHours"):
        build(app_context, test_env, web_search_ttl_hours=bad)
