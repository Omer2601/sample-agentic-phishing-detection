# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import fnmatch
import json
import re

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from phish_infra.common import LOGS_KEY_ACTIONS
from phish_infra.config import load_config
from phish_infra.stacks.edge_waf import EdgeWafStack
from phish_infra.stacks.main import PhishTriageStack

# plans/interfaces.md, Stack outputs (InviteCodeSecretArn only in invite mode).
EXPECTED_OUTPUTS = {
    "WebUrl",
    "ApiUrl",
    "ApiInvokePolicyArn",
    "OrchestratorHarnessArn",
    "GatewayArn",
    "UrlAnalystRuntimeArn",
    "BrandVisualRuntimeArn",
    "CodeAnalystRuntimeArn",
    "UserPoolId",
    "ManagedLoginUrl",
    "ScanQueueUrl",
    "ScanDlqUrl",
    "ScansTableName",
    "BatchesTableName",
    "StatsTableName",
    "ArtifactsBucketName",
    "UploadBucketName",
    "InputGuardrailArn",
    "OutputGuardrailArn",
    "WebFunctionName",
    "OwnerTag",
    # The DynamoDB cache of RDAP and web search results (all modes).
    "CacheTableName",
    # episodicMemory=true (the default).
    "ScanMemoryId",
    "ScanMemoryArn",
}
# The tools server, its Gateway and the dispatcher (every deployment).
TOOLS_OUTPUTS = {
    "ToolsGatewayArn",
    "ToolsGatewayUrl",
    "ToolsServerRuntimeArn",
    "DispatcherRuntimeArn",
}
# -c agentRegistry=true in a Region with AWS Agent Registry.
REGISTRY_OUTPUTS = {"RegistryArn", "RegistryMcpUrl"}
LWA_ACCOUNT = "753240598075"
# Not next to another hex digit: asset hashes (sha256 hex) can start with 12 decimal digits.
TWELVE_DIGITS = re.compile(r"(?<![0-9a-f])[0-9]{12}(?![0-9a-f])")


def main_template(app_context, test_env, **extra):
    app = cdk.App(context={**app_context, **extra})
    stack = PhishTriageStack(
        app, "PhishTriageAgentic", cfg=load_config(app.node), web_acl_arn=None, env=test_env
    )
    return Template.from_stack(stack)


@pytest.fixture(scope="module")
def template(app_context, test_env):
    return main_template(app_context, test_env)


def test_outputs_are_exactly_the_interface_list(template):
    assert set(template.find_outputs("*")) == EXPECTED_OUTPUTS | TOOLS_OUTPUTS


def test_agent_registry_adds_only_the_registry_outputs(app_context, test_env):
    outputs = set(main_template(app_context, test_env, agentRegistry=True).find_outputs("*"))
    assert outputs == EXPECTED_OUTPUTS | TOOLS_OUTPUTS | REGISTRY_OUTPUTS


def test_invite_mode_adds_the_secret_output(app_context, test_env):
    outputs = set(main_template(app_context, test_env, inviteCode=True).find_outputs("*"))
    assert outputs == EXPECTED_OUTPUTS | TOOLS_OUTPUTS | {"InviteCodeSecretArn"}


def test_no_hardcoded_account_ids_except_placeholder_and_lwa(template):
    body = json.dumps(template.to_json())
    assert set(TWELVE_DIGITS.findall(body)) <= {"123456789012", LWA_ACCOUNT}


@pytest.mark.parametrize(
    "account, region", [("111111111111", "eu-central-1"), ("222222222222", "ap-southeast-2")]
)
def test_portable_to_any_account_and_region(app_context, account, region):
    # Synthesize both stacks for a customer-like account and region; the only 12-digit literals
    # allowed are that account (resolved by CDK from the env) and the AWS-published LWA account.
    app = cdk.App(context=app_context)
    cfg = load_config(app.node)
    edge = EdgeWafStack(
        app,
        "Edge",
        cfg=cfg,
        env=cdk.Environment(account=account, region="us-east-1"),
        cross_region_references=True,
    )
    main = PhishTriageStack(
        app,
        "Main",
        cfg=cfg,
        web_acl_arn=edge.web_acl_arn,
        web_search=edge.web_search,
        env=cdk.Environment(account=account, region=region),
        cross_region_references=True,
    )
    for stack in (edge, main):
        body = json.dumps(Template.from_stack(stack).to_json())
        assert set(TWELVE_DIGITS.findall(body)) <= {account, LWA_ACCOUNT}
        assert "arn:aws:" not in body, "ARNs must use the partition pseudo parameter"
        assert "us-west-2" not in body, "no fixed deploy region"
    assert region in json.dumps(Template.from_stack(main).to_json())


def test_every_taggable_resource_has_project_owner_environment(template):
    expected = {"Project": "phish-triage", "Owner": "phish-triage-owner", "Environment": "dev"}
    for logical_id, res in template.to_json()["Resources"].items():
        tags = res.get("Properties", {}).get("Tags")
        if isinstance(tags, list):
            found = {t["Key"]: t["Value"] for t in tags if isinstance(t, dict) and "Key" in t}
        elif isinstance(tags, dict):
            found = tags
        else:
            continue
        assert {k: found.get(k) for k in expected} == expected, logical_id


def test_guardrails_and_gateway_are_tagged(template):
    for type_ in ("AWS::Bedrock::Guardrail", "AWS::BedrockAgentCore::Gateway"):
        for logical_id, res in template.find_resources(type_).items():
            assert res["Properties"].get("Tags"), logical_id


def test_stateful_resources_are_destroyed_in_dev(template):
    for logical_id, res in template.to_json()["Resources"].items():
        if res["Type"] in {
            "AWS::DynamoDB::Table",
            "AWS::S3::Bucket",
            "AWS::KMS::Key",
            "AWS::Cognito::UserPool",
            "AWS::SQS::Queue",
            "AWS::Logs::LogGroup",
        }:
            assert res.get("DeletionPolicy") == "Delete", logical_id


def test_prod_retains_stateful_resources(app_context, test_env):
    template = main_template(app_context, test_env, environment="prod")
    for type_ in ("AWS::DynamoDB::Table", "AWS::KMS::Key", "AWS::Cognito::UserPool"):
        for logical_id, res in template.find_resources(type_).items():
            assert res.get("DeletionPolicy") == "Retain", logical_id


def _logs_key_patterns(template):
    (key_id,) = [
        k
        for k, v in template.find_resources("AWS::KMS::Key").items()
        if "AllowCloudWatchLogs" in str(v)
    ]
    key = template.find_resources("AWS::KMS::Key")[key_id]
    (statement,) = [
        s
        for s in key["Properties"]["KeyPolicy"]["Statement"]
        if s.get("Sid") == "AllowCloudWatchLogs"
    ]
    arns = statement["Condition"]["ArnLike"]["kms:EncryptionContext:aws:logs:arn"]
    return key_id, [a["Fn::Join"][1][-1].split(":log-group:")[1] for a in arns]


def test_logs_key_grant_names_only_this_stacks_log_groups(template):
    _, patterns = _logs_key_patterns(template)
    assert sorted(patterns) == [
        "/aws/apigateway/phish-access-dev",
        "/aws/bedrock-agentcore/runtimes/phish_*",
        "/phish/dev/*",
    ]


def test_every_cmk_log_group_falls_under_the_key_grant(template):
    key_id, patterns = _logs_key_patterns(template)
    groups = [
        g["Properties"]
        for g in template.find_resources("AWS::Logs::LogGroup").values()
        if key_id in str(g["Properties"].get("KmsKeyId"))
    ]
    # Runtime log groups are adopted by custom resources (test_agents), not declared here.
    assert len(groups) >= 8
    for props in groups:
        name = props.get("LogGroupName")
        assert name is not None, "a generated name cannot be matched by the key grant"
        parts = [name] if isinstance(name, str) else name["Fn::Join"][1]
        # The only token in a log group name is a runtime id, which starts with its phish_ name.
        literal = "".join(p if isinstance(p, str) else "phish_RUNTIMEID" for p in parts)
        assert any(fnmatch.fnmatchcase(literal, p) for p in patterns), literal
    runtime_names = [
        r["Properties"]["AgentRuntimeName"]
        for r in template.find_resources("AWS::BedrockAgentCore::Runtime").values()
    ]
    assert runtime_names and all(n.startswith("phish_") for n in runtime_names)


def test_owner_tag_output_tells_the_deployer_to_set_it(template):
    output = template.find_outputs("OwnerTag")["OwnerTag"]
    assert output["Value"] == "phish-triage-owner"
    assert "-c owner=" in output["Description"]


def test_every_deleted_bucket_is_emptied_before_it_is_written(template):
    # Third deploy (2026-09-29): the SPA BucketDeployment filled WebAssets while its
    # AutoDeleteObjects resource was still waiting on the bucket policy (which waits on the
    # CloudFront distribution), so the rollback left a non-empty bucket and ROLLBACK_FAILED.
    resources = template.to_json()["Resources"]
    auto_delete = {
        json.dumps(r["Properties"]["BucketName"]): logical_id
        for logical_id, r in resources.items()
        if r["Type"] == "Custom::S3AutoDeleteObjects"
    }
    for logical_id, bucket in resources.items():
        if bucket["Type"] == "AWS::S3::Bucket" and bucket.get("DeletionPolicy") == "Delete":
            assert json.dumps({"Ref": logical_id}) in auto_delete, logical_id
    deployments = [r for r in resources.values() if r["Type"] == "Custom::CDKBucketDeployment"]
    assert deployments
    for deployment in deployments:
        target = json.dumps(deployment["Properties"]["DestinationBucketName"])
        assert auto_delete[target] in deployment.get("DependsOn", []), target


def _logs_statement(template):
    return next(
        s
        for key in template.find_resources("AWS::KMS::Key").values()
        for s in key["Properties"]["KeyPolicy"]["Statement"]
        if s.get("Sid") == "AllowCloudWatchLogs"
    )


@pytest.mark.parametrize("stack", ["main", "edge"])
def test_logs_key_policies_name_every_kms_action(app_context, test_env, template, stack):
    # Least privilege: no wildcard KMS actions for Logs.
    if stack == "edge":
        app = cdk.App(context=app_context)
        edge = EdgeWafStack(
            app,
            "PhishTriageAgenticEdge",
            cfg=load_config(app.node),
            env=cdk.Environment(account="123456789012", region="us-east-1"),
        )
        template = Template.from_stack(edge)
    actions = _logs_statement(template)["Action"]
    assert sorted(actions) == sorted(LOGS_KEY_ACTIONS)
    assert not any("*" in a for a in actions)


def test_api_knows_the_console_url_for_batch_report_links(template):
    (fn,) = template.find_resources(
        "AWS::Lambda::Function", {"Properties": {"Handler": "phish_backend.api.app.handler"}}
    ).values()
    console = json.dumps(fn["Properties"]["Environment"]["Variables"]["CONSOLE_URL"])
    assert "https://" in console and "DomainName" in console


def _runtime_env(template, runtime_name):
    for res in template.find_resources("AWS::BedrockAgentCore::Runtime").values():
        props = res["Properties"]
        if props.get("AgentRuntimeName", "").startswith(runtime_name):
            return {
                v["Name"] if "Name" in v else k: v
                for k, v in props.get("EnvironmentVariables", {}).items()
            }
    raise AssertionError(f"runtime {runtime_name} not found")


def test_result_cache_is_wired_to_url_analyst_brand_visual_and_tools(template):
    tables = template.find_resources("AWS::DynamoDB::Table")
    cache_tables = [
        t
        for t in tables.values()
        if "ttl" in json.dumps(t["Properties"].get("TimeToLiveSpecification", {}))
    ]
    assert len(cache_tables) == 1, "exactly one table has the ttl attribute enabled"
    for name in ("phish_url_analyst", "phish_brand_visual", "phish_tools_server"):
        env = _runtime_env(template, name)
        assert "PHISH_CACHE_TABLE" in env, name
        assert "PHISH_RDAP_CACHE_TTL_S" in env and "PHISH_WEBSEARCH_CACHE_TTL_S" in env, name
    # code_analyst has no cache use, so it must not get the table name or the grant.
    assert "PHISH_CACHE_TABLE" not in _runtime_env(template, "phish_code_analyst")


NAME_KEYS = (
    "Name",
    "RuntimeName",
    "HarnessName",
    "TableName",
    "QueueName",
    "TopicName",
    "FunctionName",
    "UserPoolName",
    "LogGroupName",
    "AlarmName",
    "ManagedPolicyName",
)
# Names unique only inside their parent (an API, a Gateway, a registry), not the account.
CHILD_SCOPED = {
    "AWS::ApiGateway::Model",
    "AWS::BedrockAgentCore::GatewayTarget",
    "AWS::AgentRegistry::RegistryRecord",
}


def _named(app_context, test_env, **extra) -> set[str]:
    app = cdk.App(context={**app_context, **extra})
    cfg = load_config(app.node)
    stack = PhishTriageStack(app, cfg.stack_prefix, cfg=cfg, web_acl_arn=None, env=test_env)
    names = set()
    for resource in Template.from_stack(stack).to_json()["Resources"].values():
        if resource["Type"] in CHILD_SCOPED:
            continue
        for key in NAME_KEYS:
            value = resource.get("Properties", {}).get(key)
            if isinstance(value, str):
                names.add(value)
    return names


def test_a_second_app_name_shares_no_resource_name_with_the_default(app_context, test_env):
    # Two copies in one account and Region (for example a fresh deploy test next to a live
    # demo) collide on any fixed name, so every literal name must carry the appName prefix.
    default = _named(app_context, test_env)
    other = _named(app_context, test_env, appName="verify")
    assert default and other
    assert default.isdisjoint(other), sorted(default & other)


def _kms_actions(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "Action":
                for action in value if isinstance(value, list) else [value]:
                    if isinstance(action, str) and action.startswith("kms:"):
                        yield action
            else:
                yield from _kms_actions(value)
    elif isinstance(node, list):
        for item in node:
            yield from _kms_actions(item)


def test_key_policies_and_our_kms_grants_name_explicit_actions(template):
    # The key policies and the grants this repo writes spell out each KMS action. Only CDK's
    # own grant helpers (suppressed in nag.py with a reason) may still add a wildcard.
    resources = template.to_json()["Resources"]
    keys = [r for r in resources.values() if r["Type"] == "AWS::KMS::Key"]
    assert keys
    # CDK's default first statement gives the account root kms:* so IAM policies can manage
    # the key; without it the key would be unmanageable. Every other statement is checked.
    statements = [
        s
        for k in keys
        for s in k["Properties"]["KeyPolicy"]["Statement"]
        if ":root" not in json.dumps(s.get("Principal", {}))
    ]
    assert statements
    assert [a for s in statements for a in _kms_actions(s) if "*" in a] == []
    from phish_infra.common import LOGS_KEY_ACTIONS
    from phish_infra.constructs.cache import KEY_ACTIONS

    assert [a for a in (*LOGS_KEY_ACTIONS, *KEY_ACTIONS) if "*" in a] == []


def test_cloudwatch_alarms_may_publish_to_the_ssl_only_topic(template):
    # Found live on 2026-10-15: with only the SSL deny in the topic policy every alarm action
    # failed with "CloudWatch Alarms is not authorized to perform: SNS:Publish".
    policies = template.find_resources("AWS::SNS::TopicPolicy")
    statements = [
        s for p in policies.values() for s in p["Properties"]["PolicyDocument"]["Statement"]
    ]
    allow = [s for s in statements if s["Effect"] == "Allow"]
    assert len(allow) == 1
    assert allow[0]["Principal"] == {"Service": "cloudwatch.amazonaws.com"}
    assert allow[0]["Action"] == "sns:Publish"
    assert "aws:SourceAccount" in allow[0]["Condition"]["StringEquals"]
    assert "aws:SourceArn" in allow[0]["Condition"]["ArnLike"]
