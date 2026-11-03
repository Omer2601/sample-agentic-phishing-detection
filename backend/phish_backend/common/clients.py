# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AWS clients, created lazily so tests can swap in moto."""

from functools import lru_cache

import boto3
from botocore.config import Config

from phish_backend.common.config import settings

_STANDARD = Config(
    retries={"mode": "standard", "max_attempts": 5}, connect_timeout=5, read_timeout=30
)
# invoke_harness streams for minutes and is not idempotent, so botocore must never
# retry it on its own. aws_retry.invoke_with_throttle_retry decides instead.
# 270 s: above the harness TimeoutSeconds (240) and below the worker Lambda timeout (300).
HARNESS_READ_TIMEOUT_SECONDS = 270
_AGENTCORE = Config(
    retries={"total_max_attempts": 1},
    connect_timeout=10,
    read_timeout=HARNESS_READ_TIMEOUT_SECONDS,
)
# Episodic memory is optional context, so a slow or failing call gives up fast instead of
# eating into the harness call's share of the 300 s worker timeout.
_MEMORY = Config(retries={"total_max_attempts": 1}, connect_timeout=2, read_timeout=4)
# The precheck must never hold a scan up: one attempt, short timeouts. The caller adds a
# hard overall deadline on top (a trickling response can outlast a per-read timeout).
# 22 s covers the tool's 11 s browser deadline plus its 8 s plain HTTP probe (site_down).
PRECHECK_TIMEOUT_SECONDS = 22
_PRECHECK = Config(
    retries={"total_max_attempts": 1},
    connect_timeout=3,
    read_timeout=PRECHECK_TIMEOUT_SECONDS,
)
# Direct orchestration. The dispatcher call is not idempotent (each call is a billed run of
# all three specialists), so one attempt; its own deadline is 50 s, plus session start-up.
DISPATCH_TIMEOUT_SECONDS = 70
_DISPATCHER = Config(
    retries={"total_max_attempts": 1},
    connect_timeout=5,
    read_timeout=DISPATCH_TIMEOUT_SECONDS,
)
# The orchestrator verdict and report turns (Converse). Throttling is retried by
# aws_retry.invoke_with_throttle_retry, not by botocore.
_BEDROCK = Config(retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=120)
# Virtual-host addressing on the regional endpoint, so presigned POST URLs work from
# the browser immediately after a bucket is created (the global endpoint can 307).
_S3 = Config(
    signature_version="s3v4",
    s3={"addressing_style": "virtual"},
    retries={"mode": "standard", "max_attempts": 5},
)


@lru_cache(maxsize=1)
def dynamodb():
    return boto3.resource("dynamodb", region_name=settings().region, config=_STANDARD)


@lru_cache(maxsize=1)
def s3():
    return boto3.client("s3", region_name=settings().region, config=_S3)


@lru_cache(maxsize=1)
def sqs():
    return boto3.client("sqs", region_name=settings().region, config=_STANDARD)


@lru_cache(maxsize=1)
def agentcore():
    return boto3.client("bedrock-agentcore", region_name=settings().region, config=_AGENTCORE)


@lru_cache(maxsize=1)
def memory():
    return boto3.client("bedrock-agentcore", region_name=settings().region, config=_MEMORY)


@lru_cache(maxsize=1)
def tools_runtime():
    return boto3.client("bedrock-agentcore", region_name=settings().region, config=_PRECHECK)


@lru_cache(maxsize=1)
def dispatcher_runtime():
    return boto3.client("bedrock-agentcore", region_name=settings().region, config=_DISPATCHER)


@lru_cache(maxsize=1)
def bedrock_runtime():
    return boto3.client("bedrock-runtime", region_name=settings().region, config=_BEDROCK)


_CLIENTS = (
    dynamodb,
    s3,
    sqs,
    agentcore,
    memory,
    tools_runtime,
    dispatcher_runtime,
    bedrock_runtime,
)


def reset() -> None:
    """Drop cached clients and settings (tests only)."""
    for fn in (*_CLIENTS, settings):
        fn.cache_clear()
