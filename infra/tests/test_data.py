# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Match, Template

from phish_infra.config import load_config
from phish_infra.constructs.data import DataLayer


@pytest.fixture(scope="module")
def t(app_context, test_env):
    app = cdk.App(context=app_context)
    stack = cdk.Stack(app, "S", env=test_env)
    DataLayer(stack, "Data", cfg=load_config(app.node))
    return Template.from_stack(stack)


def test_cmk_rotates(t):
    t.has_resource_properties("AWS::KMS::Key", {"EnableKeyRotation": True})


def test_key_policy_lets_logs_and_alarms_use_it(t):
    key = next(iter(t.find_resources("AWS::KMS::Key").values()))
    principals = str(key["Properties"]["KeyPolicy"])
    assert "logs." in principals and "cloudwatch.amazonaws.com" in principals


@pytest.mark.parametrize(
    "name,pk,sk",
    [
        ("phish-scans-dev", "scan_id", None),
        ("phish-batches-dev", "batch_id", None),
        ("phish-stats-dev", "owner", "bucket"),
        ("phish-idempotency-dev", "pk", None),
    ],
)
def test_tables_keys_and_encryption(t, name, pk, sk):
    schema = [{"AttributeName": pk, "KeyType": "HASH"}]
    if sk:
        schema.append({"AttributeName": sk, "KeyType": "RANGE"})
    t.has_resource_properties(
        "AWS::DynamoDB::Table",
        {
            "TableName": name,
            "KeySchema": schema,
            "BillingMode": "PAY_PER_REQUEST",
            "SSESpecification": Match.object_like({"SSEEnabled": True, "SSEType": "KMS"}),
            "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
        },
    )


def test_scans_table_indexes_and_stream(t):
    t.has_resource_properties(
        "AWS::DynamoDB::Table",
        {
            "TableName": "phish-scans-dev",
            "StreamSpecification": {"StreamViewType": "NEW_AND_OLD_IMAGES"},
            "TimeToLiveSpecification": {"AttributeName": "expires_at", "Enabled": True},
            "GlobalSecondaryIndexes": Match.array_with(
                [
                    Match.object_like(
                        {
                            "IndexName": "owner-queued_at",
                            "KeySchema": [
                                {"AttributeName": "owner", "KeyType": "HASH"},
                                {"AttributeName": "queued_at", "KeyType": "RANGE"},
                            ],
                            "Projection": {"ProjectionType": "ALL"},
                        }
                    ),
                    Match.object_like(
                        {
                            "IndexName": "batch-queued_at",
                            "KeySchema": [
                                {"AttributeName": "batch_id", "KeyType": "HASH"},
                                {"AttributeName": "queued_at", "KeyType": "RANGE"},
                            ],
                        }
                    ),
                    # The requeue sweeper's index: only what it needs is projected.
                    Match.object_like(
                        {
                            "IndexName": "status-queued_at",
                            "KeySchema": [
                                {"AttributeName": "status", "KeyType": "HASH"},
                                {"AttributeName": "queued_at", "KeyType": "RANGE"},
                            ],
                            "Projection": {
                                "ProjectionType": "INCLUDE",
                                "NonKeyAttributes": [
                                    "owner",
                                    "url",
                                    "batch_id",
                                    "enqueued_at",
                                    "retried_at",
                                ],
                            },
                        }
                    ),
                ]
            ),
        },
    )


def test_stats_batches_and_idempotency_expire_on_expires_at(t):
    for name in ("phish-batches-dev", "phish-stats-dev", "phish-idempotency-dev"):
        t.has_resource_properties(
            "AWS::DynamoDB::Table",
            {
                "TableName": name,
                "TimeToLiveSpecification": {"AttributeName": "expires_at", "Enabled": True},
            },
        )


def test_batches_owner_index(t):
    t.has_resource_properties(
        "AWS::DynamoDB::Table",
        {
            "TableName": "phish-batches-dev",
            "GlobalSecondaryIndexes": [Match.object_like({"IndexName": "owner-created_at"})],
        },
    )


def test_every_bucket_is_private_and_tls_only(t):
    buckets = t.find_resources("AWS::S3::Bucket")
    assert len(buckets) == 3
    for b in buckets.values():
        assert b["Properties"]["PublicAccessBlockConfiguration"] == {
            "BlockPublicAcls": True,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        }
    policies = str(t.find_resources("AWS::S3::BucketPolicy"))
    assert policies.count("aws:SecureTransport") >= 3


def test_content_buckets_use_cmk_and_log_access(t):
    logged = [
        b["Properties"]
        for b in t.find_resources("AWS::S3::Bucket").values()
        if "LoggingConfiguration" in b["Properties"]
    ]
    assert len(logged) == 2
    for props in logged:
        rule = props["BucketEncryption"]["ServerSideEncryptionConfiguration"][0]
        assert rule["ServerSideEncryptionByDefault"]["SSEAlgorithm"] == "aws:kms"


def test_upload_objects_expire_after_one_day(t):
    t.has_resource_properties(
        "AWS::S3::Bucket",
        {
            "LifecycleConfiguration": {
                "Rules": Match.array_with(
                    [
                        Match.object_like(
                            {"Id": "ExpireUploads", "ExpirationInDays": 1, "Status": "Enabled"}
                        )
                    ]
                )
            },
        },
    )


def test_alarm_topic_is_encrypted(t):
    t.has_resource_properties("AWS::SNS::Topic", {"KmsMasterKeyId": Match.any_value()})


def test_upload_origin_is_derived_without_a_bucket_reference(app_context, test_env):
    app = cdk.App(context=app_context)
    stack = cdk.Stack(app, "S", env=test_env)
    data = DataLayer(stack, "Data", cfg=load_config(app.node))
    origin = stack.resolve(data.upload_origin)
    assert "Ref" not in str(origin) or "AWS::URLSuffix" in str(origin)
    assert "phish-uploads-dev-123456789012-us-west-2" in str(origin)
