# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The regional stack: data, agents, pipeline, API and console, wired in dependency order."""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import aws_lambda as lambda_
from constructs import Construct

from phish_infra.common import REPO_ROOT, apply_tags, build_python_asset, stack_output
from phish_infra.config import DEFAULT_OWNER, AppConfig
from phish_infra.constructs.agents import AgentsLayer
from phish_infra.constructs.api import ScanApi
from phish_infra.constructs.cache import ResultCache
from phish_infra.constructs.data import DataLayer
from phish_infra.constructs.frontend import WebFrontend, proxy_role_name
from phish_infra.constructs.guardrails import Guardrails
from phish_infra.constructs.memory import ScanMemory
from phish_infra.constructs.pipeline import ScanPipeline
from phish_infra.constructs.web_search import WebSearchEndpoint


class PhishTriageStack(cdk.Stack):
    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        cfg: AppConfig,
        web_acl_arn: str | None,
        web_search: WebSearchEndpoint | None = None,
        **kwargs,
    ) -> None:
        super().__init__(scope, id, **kwargs)
        apply_tags(self, cfg)

        # One code asset for every backend Lambda: pinned wheels from uv.lock plus the
        # backend and contracts sources (plans/interfaces.md, Repo and packaging).
        backend_code = lambda_.Code.from_asset(
            build_python_asset(
                "lambda-backend",
                package="phish-backend",
                sources={
                    "phish_backend": REPO_ROOT / "backend" / "phish_backend",
                    "phish_contracts": REPO_ROOT / "contracts" / "phish_contracts",
                },
                platform="aarch64-manylinux2014",
                skip=cfg.skip_asset_build,
            )
        )

        data = DataLayer(self, "Data", cfg=cfg)
        guardrails = Guardrails(self, "Guardrails", cfg=cfg)
        cache = ResultCache(
            self,
            "Cache",
            cfg=cfg,
            key=data.key,
            rdap_ttl_hours=cfg.rdap_cache_ttl_hours,
            web_search_ttl_hours=cfg.web_search_cache_ttl_hours,
        )
        agents = AgentsLayer(
            self,
            "Agents",
            cfg=cfg,
            key=data.key,
            artifacts_bucket=data.artifacts_bucket,
            web_search=web_search,
            cache=cache,
        )
        memory = ScanMemory(self, "Memory", cfg=cfg, key=data.key) if cfg.episodic_memory else None
        pipeline = ScanPipeline(
            self,
            "Pipeline",
            cfg=cfg,
            data=data,
            guardrails=guardrails,
            agents=agents,
            backend_code=backend_code,
            memory=memory,
        )
        api = ScanApi(
            self,
            "Api",
            cfg=cfg,
            data=data,
            guardrails=guardrails,
            pipeline=pipeline,
            agents=agents,
            backend_code=backend_code,
            proxy_role_name=proxy_role_name(cfg),
        )
        WebFrontend(
            self,
            "Web",
            cfg=cfg,
            api=api,
            data=data,
            backend_code=backend_code,
            web_acl_arn=web_acl_arn,
        )

        stack_output(self, "ArtifactsBucketName", data.artifacts_bucket.bucket_name)
        stack_output(self, "UploadBucketName", data.upload_bucket.bucket_name)
        stack_output(self, "ScansTableName", data.scans_table.table_name)
        stack_output(self, "BatchesTableName", data.batches_table.table_name)
        stack_output(self, "StatsTableName", data.stats_table.table_name)
        stack_output(
            self,
            "OwnerTag",
            cfg.owner,
            "Owner tag on every resource. Redeploy with -c owner=<your team or alias> so cost "
            "shows up under your name in Cost Explorer"
            + (" (still the neutral default)" if cfg.owner == DEFAULT_OWNER else ""),
        )
