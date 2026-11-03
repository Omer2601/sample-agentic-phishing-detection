# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import aws_cdk as cdk
from aws_cdk import aws_iam as iam
from aws_cdk.assertions import Template
from constructs import Construct

from phish_infra.common import (
    apply_tags,
    bedrock_invoke_statements,
    build_python_asset,
    foundation_model_id,
    stack_output,
)
from phish_infra.config import load_config


def test_foundation_model_id_strips_profile_prefix():
    assert foundation_model_id("us.anthropic.claude-opus-5-5") == "anthropic.claude-opus-5-5"
    assert (
        foundation_model_id("global.anthropic.claude-sonnet-5-5") == "anthropic.claude-sonnet-5-5"
    )
    assert foundation_model_id("anthropic.x") == "anthropic.x"


def _flat(value):
    """Turn {"Fn::Join": ["", ["arn:", {"Ref": "AWS::Partition"}, ...]]} into "arn:aws:..."."""
    if isinstance(value, dict) and "Fn::Join" in value:
        sep, parts = value["Fn::Join"]
        return sep.join("aws" if p == {"Ref": "AWS::Partition"} else _flat(p) for p in parts)
    if isinstance(value, dict):
        return {k: _flat(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_flat(v) for v in value]
    return value


def _resolved(stack, model_ids):
    statements = bedrock_invoke_statements(stack, model_ids)
    return [_flat(stack.resolve(s.to_statement_json())) for s in statements]


def test_bedrock_profile_is_regional_and_models_need_the_profile(test_env):
    stack = cdk.Stack(cdk.App(), "S", env=test_env)
    profile, routed = _resolved(stack, ["global.anthropic.claude-sonnet-5-5"])
    assert profile["Resource"] == (
        "arn:aws:bedrock:us-west-2:123456789012:inference-profile/global.anthropic.claude-sonnet-5-5"
    )
    assert "Condition" not in profile
    # The Region wildcard on the models only applies through this stack's profile.
    assert routed["Resource"] == [
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-5-5",
        "arn:aws:bedrock:::foundation-model/anthropic.claude-sonnet-5-5",
    ]
    assert routed["Condition"] == {
        "StringEquals": {"bedrock:InferenceProfileArn": [profile["Resource"]]}
    }
    assert profile["Action"] == ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]


def test_us_profile_has_no_regionless_model(test_env):
    stack = cdk.Stack(cdk.App(), "S", env=test_env)
    _, routed = _resolved(stack, ["us.anthropic.claude-opus-5-5"])
    assert routed["Resource"] == "arn:aws:bedrock:*::foundation-model/anthropic.claude-opus-5-5"


def test_bare_model_id_is_scoped_to_this_region_without_a_condition(test_env):
    stack = cdk.Stack(cdk.App(), "S", env=test_env)
    (only,) = _resolved(stack, ["anthropic.claude-haiku-5-5"])
    assert (
        only["Resource"] == "arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-haiku-5-5"
    )


def test_apply_tags(test_env, app_context):
    app = cdk.App(context=app_context)
    stack = cdk.Stack(app, "S", env=test_env)
    iam.Role(stack, "R", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
    apply_tags(stack, load_config(app.node))
    tags = Template.from_stack(stack).find_resources("AWS::IAM::Role")
    role_tags = {t["Key"]: t["Value"] for t in next(iter(tags.values()))["Properties"]["Tags"]}
    assert role_tags == {
        "Project": "phish-triage",
        "Owner": "phish-triage-owner",
        "Environment": "dev",
    }


def test_skip_asset_build_returns_stub_dir():
    path = build_python_asset("unit-test-stub", package=None, sources={}, platform="x", skip=True)
    assert cdk.FileSystem.fingerprint(path)


def test_stack_output_keeps_its_exact_key_inside_a_construct(test_env):
    # Scripts read outputs by OutputKey, so a nested construct must not hash the logical id.
    stack = cdk.Stack(cdk.App(), "S", env=test_env)
    nested = Construct(stack, "Nested")
    stack_output(nested, "ApiUrl", "https://example.com", "doc")
    assert list(Template.from_stack(stack).find_outputs("*")) == ["ApiUrl"]


def test_asset_builds_start_only_allowlisted_tools_from_one_call_site():
    import inspect

    import pytest

    from phish_infra import common

    assert common.BUILD_TOOLS == {"uv", "npm"}
    with pytest.raises(RuntimeError, match="not an allowed build tool"):
        common.run_build_step(["sh", "-c", "true"])
    import ast

    heads = []
    for node in ast.walk(ast.parse(inspect.getsource(common))):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "run":
            argv = node.args[0]
            first = argv.elts[0] if isinstance(argv, ast.List) and argv.elts else None
            heads.append(first.value if isinstance(first, ast.Constant) else None)
    # One call per tool, each naming its program literally: no variable argv[0].
    assert sorted(heads) == ["npm", "uv"]


def test_run_build_step_starts_the_named_tool_with_the_given_args(monkeypatch, tmp_path):
    from phish_infra import common

    seen = []
    monkeypatch.setattr(common.subprocess, "run", lambda argv, **kw: seen.append((argv, kw["cwd"])))
    common.run_build_step(["uv", "export", "a b;c"], tmp_path)
    common.run_build_step(["npm", "ci"], tmp_path)
    assert seen == [(["uv", "export", "a b;c"], tmp_path), (["npm", "ci"], tmp_path)]
