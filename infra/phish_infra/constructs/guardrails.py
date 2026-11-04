# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Bedrock Guardrails applied by the backend: input on the caller's URL, output on the report."""

from __future__ import annotations

import hashlib
import json

import aws_cdk as cdk
from constructs import Construct

from phish_infra.common import cfn_tag_list, stack_output
from phish_infra.config import AppConfig

_PII_TYPES = (
    "US_SOCIAL_SECURITY_NUMBER",
    "CREDIT_DEBIT_CARD_NUMBER",
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
)


def _pii(action: str, types: tuple[str, ...] = _PII_TYPES) -> dict:
    return {"PiiEntitiesConfig": [{"Type": t, "Action": action} for t in types]}


# A submitted URL that carries a secret is refused outright. A report only masks the match:
# reports quote phishing kits (test card numbers in fake payment forms), and BLOCK replaced the
# whole report with one line for a single match, losing the analysis. The report does not
# mask AWS_SECRET_KEY: that detector matches any long random-looking token, and it masked
# the random host names of free-hosting phishing pages (pages.dev subdomains), which are
# the evidence the report is about. The input guardrail still blocks it.
_PII_BLOCK = _pii("BLOCK")
_PII_MASK = _pii("ANONYMIZE", tuple(t for t in _PII_TYPES if t != "AWS_SECRET_KEY"))


class Guardrails(Construct):
    def __init__(self, scope: Construct, id: str, *, cfg: AppConfig) -> None:
        super().__init__(scope, id)
        base = f"{cfg.app_name}-guardrail"
        input_props = {
            "Name": f"{base}-input-{cfg.environment}",
            "Description": "Filters caller-supplied scan input",
            "BlockedInputMessaging": (
                "Your request was blocked by security policy. "
                "Please submit a valid URL for analysis."
            ),
            "BlockedOutputsMessaging": "Blocked by security policy.",
            "ContentPolicyConfig": {
                "FiltersConfig": [
                    {"Type": t, "InputStrength": "HIGH", "OutputStrength": "NONE"}
                    for t in (
                        "SEXUAL",
                        "VIOLENCE",
                        "HATE",
                        "INSULTS",
                        "MISCONDUCT",
                        "PROMPT_ATTACK",
                    )
                ]
            },
            "TopicPolicyConfig": {
                "TopicsConfig": [
                    {
                        "Name": "malicious-creation",
                        "Definition": (
                            "Requests asking the agent to CREATE phishing pages, malware, "
                            "credential harvesters, or help set up attacks. This does NOT include "
                            "analyzing existing phishing sites."
                        ),
                        "Examples": [
                            "Create a phishing page that looks like PayPal",
                            "Write a credential harvesting script for me",
                            "Generate HTML for a fake login form I can deploy",
                            "Help me set up a phishing campaign",
                        ],
                        "Type": "DENY",
                    }
                ]
            },
            "SensitiveInformationPolicyConfig": _PII_BLOCK,
        }
        output_props = {
            "Name": f"{base}-output-{cfg.environment}",
            "Description": "Masks secrets and payment data in generated reports",
            "BlockedInputMessaging": "Blocked by security policy.",
            "BlockedOutputsMessaging": (
                "The analysis was withheld because the generated report contained sensitive data."
            ),
            "SensitiveInformationPolicyConfig": _PII_MASK,
        }
        for props in (input_props, output_props):
            props["Tags"] = cfn_tag_list(cfg)
        self.input_id, self.input_version, self.input_arn = self._create("Input", input_props)
        self.output_id, self.output_version, self.output_arn = self._create("Output", output_props)
        stack_output(self, "InputGuardrailArn", self.input_arn, "Input guardrail (scan URLs)")
        stack_output(self, "OutputGuardrailArn", self.output_arn, "Output guardrail (reports)")

    def _create(self, id_: str, props: dict) -> tuple[str, str, str]:
        # L1: no L2 for Bedrock Guardrails in aws-cdk-lib. A version is an immutable
        # snapshot; hashing the config into its description publishes a new version
        # whenever the policy changes, otherwise the backend keeps enforcing the old one.
        guardrail = cdk.CfnResource(self, id_, type="AWS::Bedrock::Guardrail", properties=props)
        digest = hashlib.sha256(json.dumps(props, sort_keys=True).encode()).hexdigest()[:12]
        version = cdk.CfnResource(
            self,
            f"{id_}Version",
            type="AWS::Bedrock::GuardrailVersion",
            properties={
                "GuardrailIdentifier": guardrail.get_att("GuardrailId").to_string(),
                "Description": f"phish guardrail, config {digest}",
            },
        )
        return (
            guardrail.get_att("GuardrailId").to_string(),
            version.get_att("Version").to_string(),
            guardrail.get_att("GuardrailArn").to_string(),
        )
