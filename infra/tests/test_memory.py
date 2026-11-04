# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from phish_infra.config import load_config
from phish_infra.constructs.memory import MEMORY_ACTIONS, MEMORY_KEY_ACTIONS, memory_name
from phish_infra.stacks.main import PhishTriageStack

WORKER = "phish_backend.worker.run_scan.handler"


def synth(app_context, test_env, **extra):
    app = cdk.App(context={**app_context, **extra})
    stack = PhishTriageStack(
        app, "PhishTriageAgentic", cfg=load_config(app.node), web_acl_arn=None, env=test_env
    )
    return Template.from_stack(stack)


@pytest.fixture(scope="module")
def on(app_context, test_env):
    return synth(app_context, test_env)


@pytest.fixture(scope="module")
def off(app_context, test_env):
    return synth(app_context, test_env, episodicMemory="false")


def memory_resource(t):
    (logical_id, resource), *rest = t.find_resources("AWS::BedrockAgentCore::Memory").items()
    assert not rest
    return logical_id, resource


def worker(t):
    (fn,) = t.find_resources("AWS::Lambda::Function", {"Properties": {"Handler": WORKER}}).values()
    return fn


def worker_statements(t):
    role = worker(t)["Properties"]["Role"]["Fn::GetAtt"][0]
    return [
        s
        for p in t.find_resources("AWS::IAM::Policy").values()
        if {"Ref": role} in p["Properties"]["Roles"]
        for s in p["Properties"]["PolicyDocument"]["Statement"]
    ]


def test_one_memory_per_deployment_encrypted_with_the_stack_key(on):
    _, memory = memory_resource(on)
    props = memory["Properties"]
    assert props["Name"] == memory_name("phish", "dev") == "phish_scan_memory_dev"
    assert "EncryptionKeyArn" in props
    # Records are written verbatim by the worker, so no extraction strategy (and no model
    # reads hostile page text a second time).
    assert not props.get("MemoryStrategies")
    assert memory["DeletionPolicy"] == "Delete"


def test_memory_name_is_per_environment():
    assert memory_name("phish", "prod") == "phish_scan_memory_prod"


def test_worker_gets_the_memory_id(on):
    env = worker(on)["Properties"]["Environment"]["Variables"]
    logical_id, _ = memory_resource(on)
    assert logical_id in str(env["MEMORY_ID"])


def test_worker_memory_grant_is_least_privilege(on):
    logical_id, _ = memory_resource(on)
    grants = [s for s in worker_statements(on) if "Memory" in str(s["Action"])]
    assert len(grants) == 1
    (grant,) = grants
    assert (
        sorted(grant["Action"])
        == sorted(MEMORY_ACTIONS)
        == [
            "bedrock-agentcore:BatchCreateMemoryRecords",
            "bedrock-agentcore:RetrieveMemoryRecords",
        ]
    )
    assert grant["Resource"] == {"Fn::GetAtt": [logical_id, "MemoryArn"]}


def test_worker_can_use_the_memory_key_only_through_agentcore(on, test_env):
    # AgentCore Memory calls KMS with the worker's own credentials; without DescribeKey on
    # the memory's key every read and write is AccessDeniedException.
    _, memory = memory_resource(on)
    key_ref = memory["Properties"]["EncryptionKeyArn"]
    (grant,) = [s for s in worker_statements(on) if "kms:DescribeKey" in str(s["Action"])]
    assert (
        sorted(grant["Action"])
        == sorted(MEMORY_KEY_ACTIONS)
        == [
            "kms:Decrypt",
            "kms:DescribeKey",
            "kms:GenerateDataKey",
        ]
    )
    assert grant["Resource"] == key_ref
    assert grant["Condition"] == {
        "StringEquals": {"kms:ViaService": f"bedrock-agentcore.{test_env.region}.amazonaws.com"}
    }


def test_memory_outputs(on, off):
    assert {"ScanMemoryId", "ScanMemoryArn"} <= set(on.find_outputs("*"))
    assert not {"ScanMemoryId", "ScanMemoryArn"} & set(off.find_outputs("*"))


def test_opt_out_removes_memory_env_and_grant(off):
    assert off.find_resources("AWS::BedrockAgentCore::Memory") == {}
    assert "MEMORY_ID" not in worker(off)["Properties"]["Environment"]["Variables"]
    assert not [s for s in worker_statements(off) if "MemoryRecords" in str(s["Action"])]
    assert not [s for s in worker_statements(off) if "kms:DescribeKey" in str(s["Action"])]
