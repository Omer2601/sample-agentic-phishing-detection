# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Fail fast if the aws-cdk-lib version in uv.lock lacks the AgentCore L2 names this app uses."""

import inspect

from aws_cdk import aws_bedrockagentcore as agentcore


def test_runtime_l2_names_exist():
    assert hasattr(agentcore, "Runtime")
    assert hasattr(agentcore.AgentRuntimeArtifact, "from_ecr_repository")
    assert hasattr(agentcore.ProtocolType, "MCP")
    assert hasattr(agentcore.RuntimeNetworkConfiguration, "using_public_network")
    assert hasattr(agentcore, "LifecycleConfiguration")


def test_runtime_accepts_the_props_we_pass():
    params = inspect.signature(agentcore.Runtime.__init__).parameters
    for name in [
        "runtime_name",
        "agent_runtime_artifact",
        "protocol_configuration",
        "network_configuration",
        "environment_variables",
        "lifecycle_configuration",
        "description",
        "tracing_enabled",
    ]:
        assert name in params, name


def test_lifecycle_configuration_fields():
    params = inspect.signature(agentcore.LifecycleConfiguration.__init__).parameters
    assert "idle_runtime_session_timeout" in params
    assert "max_lifetime" in params


def test_runtime_exposes_arn_and_id():
    members = dict(inspect.getmembers(agentcore.Runtime))
    assert "agent_runtime_arn" in members
    assert "agent_runtime_id" in members
    assert "role" in members
