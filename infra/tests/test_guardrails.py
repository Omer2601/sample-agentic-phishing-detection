# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Match, Template

from phish_infra.config import load_config
from phish_infra.constructs.guardrails import Guardrails


@pytest.fixture(scope="module")
def t(app_context, test_env):
    app = cdk.App(context=app_context)
    stack = cdk.Stack(app, "S", env=test_env)
    Guardrails(stack, "G", cfg=load_config(app.node))
    return Template.from_stack(stack)


def test_two_guardrails_each_with_a_version(t):
    t.resource_count_is("AWS::Bedrock::Guardrail", 2)
    t.resource_count_is("AWS::Bedrock::GuardrailVersion", 2)


def test_version_description_carries_config_hash(t):
    descriptions = {
        v["Properties"]["Description"]
        for v in t.find_resources("AWS::Bedrock::GuardrailVersion").values()
    }
    assert len(descriptions) == 2
    assert all(d.startswith("phish guardrail, config ") for d in descriptions)


def test_input_filters_prompt_attack_and_malicious_creation(t):
    t.has_resource_properties(
        "AWS::Bedrock::Guardrail",
        {
            "Name": "phish-guardrail-input-dev",
            "ContentPolicyConfig": {
                "FiltersConfig": Match.array_with(
                    [{"Type": "PROMPT_ATTACK", "InputStrength": "HIGH", "OutputStrength": "NONE"}]
                )
            },
            "TopicPolicyConfig": {
                "TopicsConfig": [Match.object_like({"Name": "malicious-creation", "Type": "DENY"})]
            },
        },
    )


def test_input_blocks_and_output_masks_secrets_and_payment_data(t):
    masked = {"US_SOCIAL_SECURITY_NUMBER", "CREDIT_DEBIT_CARD_NUMBER", "AWS_ACCESS_KEY"}
    want = {
        "phish-guardrail-input-dev": ("BLOCK", masked | {"AWS_SECRET_KEY"}),
        # AWS_SECRET_KEY masked random pages.dev host names in reports, so output drops it.
        "phish-guardrail-output-dev": ("ANONYMIZE", masked),
    }
    for g in t.find_resources("AWS::Bedrock::Guardrail").values():
        config = g["Properties"]["SensitiveInformationPolicyConfig"]["PiiEntitiesConfig"]
        action, types = want[g["Properties"]["Name"]]
        assert {e["Type"] for e in config} == types
        # Output masks only the match: BLOCK replaced a whole report with one line.
        assert {e["Action"] for e in config} == {action}


def test_output_has_no_content_or_topic_policy(t):
    t.has_resource_properties(
        "AWS::Bedrock::Guardrail",
        {
            "Name": "phish-guardrail-output-dev",
            "ContentPolicyConfig": Match.absent(),
            "TopicPolicyConfig": Match.absent(),
        },
    )


def test_guardrail_outputs_have_exact_keys(t):
    outputs = t.find_outputs("*")
    assert outputs["InputGuardrailArn"]["Value"]["Fn::GetAtt"][1] == "GuardrailArn"
    assert outputs["OutputGuardrailArn"]["Value"]["Fn::GetAtt"][1] == "GuardrailArn"
