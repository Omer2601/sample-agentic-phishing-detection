# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Moto-backed AWS for backend unit tests. Shapes mirror plans/interfaces.md."""

import boto3
import pytest
from moto import mock_aws

REGION = "us-west-2"
ACCOUNT = "123456789012"
FAKE_KEY = "testing"
ENV = {
    "AWS_REGION": REGION,
    "AWS_DEFAULT_REGION": REGION,
    # moto's documented placeholder, shared by both halves of the fake key pair.
    "AWS_ACCESS_KEY_ID": FAKE_KEY,
    "AWS_SECRET_ACCESS_KEY": FAKE_KEY,
    "SCANS_TABLE": "phish-scans",
    "BATCHES_TABLE": "phish-batches",
    "STATS_TABLE": "phish-stats",
    # Account and region scoped, like the deployed names, so the pattern is not squattable.
    "UPLOAD_BUCKET": f"phish-uploads-{ACCOUNT}-{REGION}",
    "ARTIFACTS_BUCKET": f"phish-artifacts-{ACCOUNT}-{REGION}",
    "HARNESS_ARN": f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:harness/phish_orchestrator",
    "PROXY_ROLE_ARN": f"arn:aws:iam::{ACCOUNT}:role/ProxyRole",
    "IDEMPOTENCY_TABLE": "phish-idempotency",
}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    from phish_backend.common import clients

    clients.reset()
    yield
    clients.reset()


def _create(ddb, name, key, gsis=(), stream=False, sort=None):
    attrs = {key: "S"}
    schema = [{"AttributeName": key, "KeyType": "HASH"}]
    if sort:
        attrs[sort] = "S"
        schema.append({"AttributeName": sort, "KeyType": "RANGE"})
    indexes = []
    for index_name, pk, sk, *include in gsis:
        attrs[pk] = "S"
        attrs[sk] = "S"
        projection = {"ProjectionType": "ALL"}
        if include:
            projection = {"ProjectionType": "INCLUDE", "NonKeyAttributes": include[0]}
        indexes.append(
            {
                "IndexName": index_name,
                "KeySchema": [
                    {"AttributeName": pk, "KeyType": "HASH"},
                    {"AttributeName": sk, "KeyType": "RANGE"},
                ],
                "Projection": projection,
            }
        )
    kwargs = {
        "TableName": name,
        "KeySchema": schema,
        "AttributeDefinitions": [
            {"AttributeName": a, "AttributeType": t} for a, t in attrs.items()
        ],
        "BillingMode": "PAY_PER_REQUEST",
    }
    if indexes:
        kwargs["GlobalSecondaryIndexes"] = indexes
    if stream:
        kwargs["StreamSpecification"] = {
            "StreamEnabled": True,
            "StreamViewType": "NEW_AND_OLD_IMAGES",
        }
    ddb.create_table(**kwargs)


@pytest.fixture
def aws(monkeypatch):
    with mock_aws():
        ddb = boto3.client("dynamodb", region_name=REGION)
        _create(
            ddb,
            ENV["SCANS_TABLE"],
            "scan_id",
            gsis=[
                ("owner-queued_at", "owner", "queued_at"),
                ("batch-queued_at", "batch_id", "queued_at"),
                # Same projection as infra/phish_infra/constructs/data.py.
                (
                    "status-queued_at",
                    "status",
                    "queued_at",
                    ["owner", "url", "batch_id", "enqueued_at", "retried_at"],
                ),
                ("dedup-queued_at", "dedup_key", "queued_at", ["status", "completed_at"]),
            ],
            stream=True,
        )
        _create(
            ddb,
            ENV["BATCHES_TABLE"],
            "batch_id",
            gsis=[("owner-created_at", "owner", "created_at")],
        )
        _create(ddb, ENV["STATS_TABLE"], "owner", sort="bucket")
        _create(ddb, ENV["IDEMPOTENCY_TABLE"], "pk")
        s3 = boto3.client("s3", region_name=REGION)
        for bucket in (ENV["UPLOAD_BUCKET"], ENV["ARTIFACTS_BUCKET"]):
            s3.create_bucket(
                Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": REGION}
            )
        queue_url = boto3.client("sqs", region_name=REGION).create_queue(QueueName="phish-scans")[
            "QueueUrl"
        ]
        monkeypatch.setenv("SCAN_QUEUE_URL", queue_url)
        from phish_backend.common import clients

        clients.reset()
        yield {"queue_url": queue_url}
