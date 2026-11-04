# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Episodic memory of past scans: one AgentCore Memory per deployment (-c episodicMemory)."""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import aws_bedrockagentcore as agentcore
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from constructs import Construct

from phish_infra.common import stack_output
from phish_infra.config import AppConfig

# The worker only appends one record per completed scan and runs one semantic search per
# scan. It never lists, reads by id, deletes, or touches events.
MEMORY_ACTIONS = (
    "bedrock-agentcore:BatchCreateMemoryRecords",
    "bedrock-agentcore:RetrieveMemoryRecords",
)
# AgentCore Memory encrypts with the stack key using the caller's own credentials (forward
# access sessions), so the worker needs these on the key, but only through AgentCore. Without
# DescribeKey every read and write fails with AccessDeniedException (seen in the v2.1 deploy).
MEMORY_KEY_ACTIONS = ("kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey")
# The event expiry must be between 7 and 365 days. The worker writes no events, so this
# only bounds anything written through the API outside the worker.
_EXPIRY_MIN_DAYS, _EXPIRY_MAX_DAYS = 7, 365


def memory_name(app_name: str, environment: str) -> str:
    # Memory names allow letters, digits and underscores only.
    return f"{app_name}_scan_memory_{environment}".replace("-", "_")


class ScanMemory(Construct):
    def __init__(self, scope: Construct, id: str, *, cfg: AppConfig, key: kms.IKey) -> None:
        super().__init__(scope, id)
        self.key = key
        expiry = min(max(cfg.retention_days, _EXPIRY_MIN_DAYS), _EXPIRY_MAX_DAYS)
        # No memory strategy: the worker writes finished one-line records itself, so there is
        # nothing to extract and no model cost per record.
        self.memory = agentcore.Memory(
            self,
            "Memory",
            memory_name=memory_name(cfg.app_name, cfg.environment),
            description="Episodic memory: one-line summaries of completed phishing scans",
            expiration_duration=cdk.Duration.days(expiry),
            kms_key=key,
        )
        # The L2 does not expose its CfnMemory as the default child, so find it.
        for child in self.memory.node.find_all():
            if isinstance(child, agentcore.CfnMemory):
                child.apply_removal_policy(cfg.removal_policy)
        self.memory_id = self.memory.memory_id
        self.memory_arn = self.memory.memory_arn
        stack_output(self, "ScanMemoryId", self.memory_id, "Episodic scan memory id")
        stack_output(self, "ScanMemoryArn", self.memory_arn, "Episodic scan memory ARN")

    def grant_worker(self, grantee: iam.IGrantable) -> None:
        iam.Grant.add_to_principal(
            grantee=grantee, actions=list(MEMORY_ACTIONS), resource_arns=[self.memory_arn]
        )
        via = f"bedrock-agentcore.{cdk.Stack.of(self).region}.amazonaws.com"
        grantee.grant_principal.add_to_principal_policy(
            iam.PolicyStatement(
                actions=list(MEMORY_KEY_ACTIONS),
                resources=[self.key.key_arn],
                conditions={"StringEquals": {"kms:ViaService": via}},
            )
        )
