# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Customer data at rest: one CMK, three buckets, four tables, one alarm topic."""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_sns as sns
from constructs import Construct

from phish_infra.common import LOGS_KEY_ACTIONS, log_group_prefix
from phish_infra.config import AppConfig

_STRING = dynamodb.AttributeType.STRING


class DataLayer(Construct):
    def __init__(self, scope: Construct, id: str, *, cfg: AppConfig) -> None:
        super().__init__(scope, id)
        stack = cdk.Stack.of(self)
        name = cfg.app_name
        env = cfg.environment
        removal = cfg.removal_policy

        self.key = kms.Key(
            self,
            "DataKey",
            alias=f"{name}-data-{env}",
            description="CMK for scan data: DynamoDB, S3, SQS, SNS, logs, Lambda environment",
            enable_key_rotation=True,
            removal_policy=removal,
        )
        # CloudWatch Logs encrypts log groups with this key; scoped to this stack's log groups:
        # the Lambda groups under /phish/<env>/, the API access log, and the specialist runtime
        # groups (runtime ids start with their phish_ runtime name).
        log_group_arn = f"arn:{stack.partition}:logs:{stack.region}:{stack.account}:log-group:"
        self.key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchLogs",
                principals=[iam.ServicePrincipal(f"logs.{stack.region}.amazonaws.com")],
                actions=list(LOGS_KEY_ACTIONS),
                # Key policy: KMS requires Resource "*", which here means only this key (it can
                # name no other resource). The condition, not the resource, does the scoping.
                resources=["*"],
                conditions={
                    "ArnLike": {
                        "kms:EncryptionContext:aws:logs:arn": [
                            f"{log_group_arn}{log_group_prefix(cfg)}/*",
                            f"{log_group_arn}/aws/apigateway/{name}-access-{env}",
                            f"{log_group_arn}/aws/bedrock-agentcore/runtimes/{name}_*",
                        ]
                    }
                },
            )
        )
        # Alarms publish to the encrypted SNS topic: SNS calls GenerateDataKey for the message
        # data key and Decrypt to read it. Explicit actions, no wildcards.
        self.key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchAlarms",
                principals=[iam.ServicePrincipal("cloudwatch.amazonaws.com")],
                actions=["kms:Decrypt", "kms:GenerateDataKey"],
                # Key policy: Resource "*" is this key only; aws:SourceAccount scopes the caller.
                resources=["*"],
                conditions={"StringEquals": {"aws:SourceAccount": stack.account}},
            )
        )

        # Server access log destination. It does not log itself: that would recurse
        # without adding a detection (cdk-nag S1 suppressed with this reason).
        self.access_logs_bucket = s3.Bucket(
            self,
            "AccessLogs",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            removal_policy=removal,
            auto_delete_objects=not cfg.is_prod,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="ExpireOldLogs",
                    expiration=cdk.Duration.days(365),
                    noncurrent_version_expiration=cdk.Duration.days(365),
                )
            ],
        )

        def content_bucket(
            id_: str, prefix: str, rules: list[s3.LifecycleRule], bucket_name: str | None = None
        ) -> s3.Bucket:
            return s3.Bucket(
                self,
                id_,
                bucket_name=bucket_name,
                encryption=s3.BucketEncryption.KMS,
                encryption_key=self.key,
                bucket_key_enabled=True,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                enforce_ssl=True,
                versioned=True,
                removal_policy=removal,
                auto_delete_objects=not cfg.is_prod,
                server_access_logs_bucket=self.access_logs_bucket,
                server_access_logs_prefix=f"{prefix}/",
                lifecycle_rules=rules,
            )

        # Screenshots, DOM captures and findings. Hostile page content: short retention.
        self.artifacts_bucket = content_bucket(
            "Artifacts",
            "artifacts",
            [
                s3.LifecycleRule(
                    id="ExpireArtifacts",
                    expiration=cdk.Duration.days(30),
                    noncurrent_version_expiration=cdk.Duration.days(1),
                ),
            ],
        )
        # CSV uploads are consumed once by split_csv; keep them one day. The name is derived
        # from pseudo parameters so the console can know the upload origin (CSP) without a
        # reference to the bucket: the bucket's CORS rule names the console origin, so a
        # reference in both directions would be a dependency cycle.
        upload_bucket_name = f"{name}-uploads-{env}-{stack.account}-{stack.region}"
        self.upload_origin = f"https://{upload_bucket_name}.s3.{stack.region}.{stack.url_suffix}"
        self.upload_bucket = content_bucket(
            "Uploads",
            "uploads",
            [
                s3.LifecycleRule(
                    id="ExpireUploads",
                    expiration=cdk.Duration.days(1),
                    noncurrent_version_expiration=cdk.Duration.days(1),
                    abort_incomplete_multipart_upload_after=cdk.Duration.days(1),
                ),
            ],
            bucket_name=upload_bucket_name,
        )

        def table(id_: str, table_name: str, pk: str, sk: str | None = None, **extra):
            return dynamodb.Table(
                self,
                id_,
                table_name=f"{name}-{table_name}-{env}",
                partition_key=dynamodb.Attribute(name=pk, type=_STRING),
                sort_key=dynamodb.Attribute(name=sk, type=_STRING) if sk else None,
                billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
                encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
                encryption_key=self.key,
                point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                    point_in_time_recovery_enabled=True
                ),
                removal_policy=removal,
                **extra,
            )

        def index(tbl: dynamodb.Table, index_name: str, pk: str, sk: str) -> None:
            tbl.add_global_secondary_index(
                index_name=index_name,
                partition_key=dynamodb.Attribute(name=pk, type=_STRING),
                sort_key=dynamodb.Attribute(name=sk, type=_STRING),
                projection_type=dynamodb.ProjectionType.ALL,
            )

        # Rows carry expires_at = queued_at + retentionDays (default 90), written by the backend.
        # The stats table keeps day and all-time aggregates forever, so Insights survives expiry.
        self.scans_table = table(
            "Scans",
            "scans",
            "scan_id",
            time_to_live_attribute="expires_at",
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
        )
        index(self.scans_table, "owner-queued_at", "owner", "queued_at")
        index(self.scans_table, "batch-queued_at", "batch_id", "queued_at")
        # The requeue sweeper queries status = PENDING here, so its reads scale with scans in
        # flight, not with every stored scan (a full table Scan every 5 minutes did). The key
        # is the status attribute itself, so every write path is indexed with no extra code
        # and adding the index to a deployed table backfills it in place. Only the fields
        # the sweeper needs are projected, so the index stays small and writes that do not
        # touch them (findings, calls, the report) never reach it.
        # ponytail: one partition per status value; shard the key if scan creation ever
        # nears 1,000 writes per second.
        self.scans_table.add_global_secondary_index(
            index_name="status-queued_at",
            partition_key=dynamodb.Attribute(name="status", type=_STRING),
            sort_key=dynamodb.Attribute(name="queued_at", type=_STRING),
            projection_type=dynamodb.ProjectionType.INCLUDE,
            non_key_attributes=["owner", "url", "batch_id", "enqueued_at", "retried_at"],
        )

        # POST /scan dedup and GET /scans/lookup: the owner's newest scan of a normalised URL.
        # dedup_key is written on every new row, flag on or off; older rows have none and are
        # not indexed. Adding it to a deployed table backfills in place (lookup answers
        # not-found until the index is ACTIVE).
        self.scans_table.add_global_secondary_index(
            index_name="dedup-queued_at",
            partition_key=dynamodb.Attribute(name="dedup_key", type=_STRING),
            sort_key=dynamodb.Attribute(name="queued_at", type=_STRING),
            projection_type=dynamodb.ProjectionType.INCLUDE,
            non_key_attributes=["status", "completed_at"],
        )

        self.batches_table = table(
            "Batches", "batches", "batch_id", time_to_live_attribute="expires_at"
        )
        index(self.batches_table, "owner-created_at", "owner", "created_at")

        # POST /scan Idempotency-Key claims: pk = <owner>#<key>, removed by TTL after 24 hours.
        self.idempotency_table = table(
            "Idempotency", "idempotency", "pk", time_to_live_attribute="expires_at"
        )

        # Only hour buckets and idempotency markers set expires_at (8 days); day and all-time
        # rows never expire.
        self.stats_table = table(
            "Stats", "stats", "owner", "bucket", time_to_live_attribute="expires_at"
        )

        self.alarm_topic = sns.Topic(
            self,
            "AlarmTopic",
            topic_name=f"{name}-alarms-{env}",
            display_name="Phish triage alarms",
            master_key=self.key,
            enforce_ssl=True,
        )
        # enforce_ssl attaches a topic policy, which replaces the SNS default policy, so
        # CloudWatch needs its own Allow or every alarm action fails with "not authorized to
        # perform SNS:Publish". Scoped to this account's alarms named <app>-*-<env>.
        self.alarm_topic.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchAlarmsPublish",
                principals=[iam.ServicePrincipal("cloudwatch.amazonaws.com")],
                actions=["sns:Publish"],
                resources=[self.alarm_topic.topic_arn],
                conditions={
                    "StringEquals": {"aws:SourceAccount": stack.account},
                    "ArnLike": {
                        "aws:SourceArn": (
                            f"arn:{stack.partition}:cloudwatch:{stack.region}:{stack.account}"
                            f":alarm:{name}-*-{env}"
                        )
                    },
                },
            )
        )
