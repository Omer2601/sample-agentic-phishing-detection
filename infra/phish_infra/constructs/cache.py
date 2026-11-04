# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Result cache: RDAP lookups per registered domain and web search results per brand.

One small DynamoDB table, encrypted with the data CMK. Rows are public-source lookup results
(registration data, search result titles and snippets), never scan content. Everything else the
agents do stays uncached. Agent code treats the table as optional and fails open.
"""

from __future__ import annotations

from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from constructs import Construct

from phish_infra.common import stack_output
from phish_infra.config import AppConfig

DEFAULT_RDAP_TTL_HOURS = 168  # 7 days: registration data changes rarely
# Short on purpose: a poisoned search result cannot stay cached for long (docs/security.md).
DEFAULT_WEB_SEARCH_TTL_HOURS = 24
MAX_TTL_HOURS = 8760

# Only point reads and writes by key. No Query, Scan or DeleteItem: the agents never need them.
CACHE_ACTIONS = ("dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem")
# What DynamoDB calls on a customer managed key for point reads and writes, as explicit
# actions (CDK's Table.grantReadWriteData would add the GenerateDataKey and ReEncrypt wildcards).
KEY_ACTIONS = (
    "kms:Decrypt",
    "kms:DescribeKey",
    "kms:Encrypt",
    "kms:GenerateDataKey",
)


def _hours(value: int, flag: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_TTL_HOURS:
        raise ValueError(f"{flag} must be an integer between 1 and {MAX_TTL_HOURS}, got {value!r}")
    return value


class ResultCache(Construct):
    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        cfg: AppConfig,
        key: kms.IKey,
        rdap_ttl_hours: int = DEFAULT_RDAP_TTL_HOURS,
        web_search_ttl_hours: int = DEFAULT_WEB_SEARCH_TTL_HOURS,
    ) -> None:
        super().__init__(scope, id)
        self.rdap_ttl_s = _hours(rdap_ttl_hours, "rdapCacheTtlHours") * 3600
        self.web_search_ttl_s = _hours(web_search_ttl_hours, "webSearchCacheTtlHours") * 3600

        # Keys are "rdap#<registered domain>" and "websearch#<normalized brand>". The agents
        # write the epoch-seconds `ttl` attribute; DynamoDB deletes expired rows lazily (up
        # to about 48 h late), so the reader also checks `ttl` itself.
        self.table = dynamodb.Table(
            self,
            "Table",
            table_name=f"{cfg.app_name}-cache-{cfg.environment}",
            partition_key=dynamodb.Attribute(name="pk", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=key,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            time_to_live_attribute="ttl",
            removal_policy=cfg.removal_policy,
        )
        self.table_name = self.table.table_name
        self._key = key

        stack_output(self, "CacheTableName", self.table_name, "RDAP and web search result cache")

    @property
    def agent_environment(self) -> dict[str, str]:
        """The environment variables the url_analyst, tools and brand_visual runtimes read."""
        return {
            "PHISH_CACHE_TABLE": self.table_name,
            "PHISH_RDAP_CACHE_TTL_S": str(self.rdap_ttl_s),
            "PHISH_WEBSEARCH_CACHE_TTL_S": str(self.web_search_ttl_s),
        }

    def grant_read_write(self, grantee: iam.IGrantable) -> iam.Grant:
        # Table.grant with explicit actions adds no KMS statement, so the CMK grant is spelled
        # out here: on the data key only, for the table encryption.
        self._key.grant(grantee, *KEY_ACTIONS)
        return self.table.grant(grantee, *CACHE_ACTIONS)
