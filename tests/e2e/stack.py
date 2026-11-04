# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Read the deployed stack's outputs so tests never hardcode endpoints."""

import os
from functools import lru_cache

import boto3

STACK = os.environ.get("PHISH_STACK", "PhishTriageAgentic")
REGION = os.environ.get("AWS_REGION", "us-west-2")


@lru_cache(maxsize=4)
def outputs(stack_name: str = STACK, region: str = REGION) -> dict[str, str]:
    cfn = boto3.client("cloudformation", region_name=region)
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
