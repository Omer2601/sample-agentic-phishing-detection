# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Orchestrator Harness, the AgentCore Gateway in front of the specialists, and the Runtimes.

The specialists Gateway has a `dispatcher` target (one no-model Runtime that runs the three
specialists concurrently, because the Harness runs same-turn Gateway tool calls one after
another) and one target per specialist for the optional second round. A tools Runtime
(browser, screenshot, RDAP) sits behind a second Gateway that only the specialists can call;
the worker also calls it directly for the no-model precheck.

With -c agentRegistry=true there is also an AWS Agent Registry cataloging the MCP servers. Its
MCP endpoint is a `registry` target on the specialists Gateway, and the orchestrator prompt
gains a lookup step before round one (which is still one dispatcher call).
"""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import aws_bedrockagentcore as agentcore
from aws_cdk import aws_ecr_assets as ecr_assets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_s3 as s3
from aws_cdk import custom_resources as cr
from constructs import Construct

from phish_infra.common import (
    REPO_ROOT,
    agentcore_principal,
    bedrock_invoke_statements,
    depend_on_role_policy,
    stack_output,
)
from phish_infra.config import AppConfig
from phish_infra.constructs.cache import ResultCache
from phish_infra.constructs.registry import SIGV4_SERVICE as REGISTRY_SIGV4_SERVICE
from phish_infra.constructs.registry import SUPPORTED_REGIONS as REGISTRY_REGIONS
from phish_infra.constructs.registry import McpRecord, SpecialistRegistry
from phish_infra.constructs.web_search import (
    WebSearchEndpoint,
    WebSearchGateway,
    web_search_folds,
)

SPECIALISTS = ("url_analyst", "brand_visual", "code_analyst")
# Gateway target names allow letters, digits and single hyphens only.
TARGET_NAMES = {
    "url_analyst": "url-analyst",
    "brand_visual": "brand-visual",
    "code_analyst": "code-analyst",
}
# The tool names the registry records advertise (the Gateway prefixes them with the target).
_URL_SCHEMA = {"type": "string", "description": "The URL under analysis."}
_SCAN_SCHEMA = {"type": "string", "description": "Scan id, 8 to 64 letters, digits, hyphens."}
_PAIR = {
    "type": "object",
    "properties": {"url": _URL_SCHEMA, "scan_id": _SCAN_SCHEMA},
    "required": ["url", "scan_id"],
}
SPECIALIST_TOOLS = ({"name": "analyze", "description": "Analyze one URL.", "inputSchema": _PAIR},)
TOOLS_SERVER_TOOLS = (
    {
        "name": "capture_page",
        "description": "Screenshot (stored in S3), title, final URL and visible text.",
        "inputSchema": _PAIR,
    },
    {
        "name": "capture_page_code",
        "description": "Forms, scripts, requests, listeners and sinks of the rendered page.",
        "inputSchema": _PAIR,
    },
    {
        "name": "whois_lookup",
        "description": "RDAP registration data for the URL's registered domain.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": _URL_SCHEMA},
            "required": ["url"],
        },
    },
)
# Only brand_visual confirms a brand's official website, so only its role reaches web search.
WEB_SEARCH_AGENTS = ("brand_visual",)
# Specialists that use the result cache: url_analyst (RDAP) and brand_visual (web search).
CACHE_AGENTS = ("url_analyst", "brand_visual")
# A plain int: SDK call parameters need the day count, and a jsii RetentionDays enum
# serializes to its name ("ONE_MONTH"), which PutRetentionPolicy rejects.
RUNTIME_LOG_RETENTION_DAYS = 30
# The only key each specialist writes (plans/interfaces.md). Per-agent keys mean a
# prompt-injected specialist cannot overwrite another specialist's Finding; the screenshot and
# capture.json come from the tools Runtime.
FINDING_KEYS = {name: (f"scans/*/findings/{name}.json",) for name in SPECIALISTS}
DESCRIPTIONS = {
    "url_analyst": "URL structure, domain reputation and WHOIS analysis",
    "brand_visual": "Brand impersonation and visual lookalike analysis in AgentCore Browser",
    "code_analyst": "Rendered DOM and script analysis for credential theft in AgentCore Browser",
}
# One tools MCP server on its own Gateway. A separate Gateway keeps these tools out of the
# orchestrator's tool list: the harness role can invoke phish-specialists only.
TOOLS_GATEWAY_SUFFIX = "-tools"  # phish-tools for the default appName
TOOLS_TARGET_NAME = "tools"
TOOLS_RUNTIME = "tools_server"
# -c directTools: the specialists that capture pages call the tools Runtime directly.
DIRECT_TOOLS_AGENTS = ("brand_visual", "code_analyst")
# -c splitToolsRuntimes: each capturing specialist gets its own copy of the tools server (same
# image, AGENT=tools_server), so the worker's precheck and the two captures of a scan draw on
# three Runtimes' session start capacity instead of one. The source fork measured that past a
# burst of about 18 to 27 calls a Runtime makes each further call wait 9 to 12 s to start.
CAPTURE_RUNTIMES = {"brand_visual": "tools_brand", "code_analyst": "tools_code"}
TOOLS_DESCRIPTION = "Shared tools: AgentCore Browser capture, screenshot and RDAP lookup"
# What the tools Runtime writes. Specialists write only their own Finding.
TOOLS_ARTIFACT_KEYS = ("scans/*/screenshot.png", "scans/*/capture.json")
# The dispatcher: one Gateway tool (dispatcher___analyze_all) that invokes the three specialist
# Runtimes concurrently. It makes no model call and writes only an error Finding for a
# specialist that could not run.
DISPATCHER_RUNTIME = "dispatcher"
DISPATCHER_TARGET_NAME = "dispatcher"
DISPATCHER_DESCRIPTION = "Runs the three specialists concurrently and returns their Findings"
DISPATCHER_TOOLS = (
    {
        "name": "analyze_all",
        "description": "Run url_analyst, brand_visual and code_analyst concurrently on one URL.",
        "inputSchema": _PAIR,
    },
)
# -c agentRegistry=true: the Agent Registry MCP endpoint as one more target on the specialists
# Gateway,
# so the orchestrator can search the catalog (registry___search_discoverable_registry_records).
REGISTRY_TARGET_NAME = "registry"
REGISTRY_TARGET_DESCRIPTION = "Agent Registry search over the phish MCP server records"
GATEWAY_SUFFIX = "-specialists"
GATEWAY_TOOL_NAME = "specialists"
HARNESS_SUFFIX = "_orchestrator"
MANAGED_BROWSER_ID = "aws.browser.v1"
SIGNED_BROWSER_SUFFIX = "_signed_browser"
ORCHESTRATOR_PROMPT = REPO_ROOT / "agents" / "orchestrator" / "prompt.md"
# Inserted before "## Step 1" of the prompt only with -c agentRegistry=true, so a deployment
# without the registry never sees a lookup step or a registry tool name.
ORCHESTRATOR_REGISTRY_STEP = REPO_ROOT / "agents" / "orchestrator" / "registry_step.md"
ROUND_ONE_HEADING = "## Step 1"
# Build context is the repo root so the image can install the shared contracts package.
IMAGE_CONTEXT = REPO_ROOT
IMAGE_DOCKERFILE = "agents/Dockerfile"
IMAGE_EXCLUDES = [
    "**",
    "!agents/**",
    "!contracts/**",
    "!pyproject.toml",
    "!uv.lock",
    "!backend/pyproject.toml",
    "!infra/pyproject.toml",
    "**/tests/**",
    "**/__pycache__/**",
    "**/.venv/**",
    "**/*.pyc",
]
BROWSER_ACTIONS = [
    "bedrock-agentcore:StartBrowserSession",
    "bedrock-agentcore:StopBrowserSession",
    "bedrock-agentcore:GetBrowserSession",
    "bedrock-agentcore:ConnectBrowserAutomationStream",
]


def pascal(name: str) -> str:
    return "".join(part.title() for part in name.split("_"))


def orchestrator_prompt(agent_registry: bool) -> str:
    """The Harness system prompt: prompt.md, plus the registry lookup step when enabled."""
    for path in (ORCHESTRATOR_PROMPT, *((ORCHESTRATOR_REGISTRY_STEP,) if agent_registry else ())):
        if not path.exists():
            raise FileNotFoundError(f"Orchestrator prompt missing: {path}")
    prompt = ORCHESTRATOR_PROMPT.read_text(encoding="utf-8")
    if not agent_registry:
        return prompt
    if prompt.count(ROUND_ONE_HEADING) != 1:
        raise ValueError(f"Orchestrator prompt must contain {ROUND_ONE_HEADING!r} exactly once")
    step = ORCHESTRATOR_REGISTRY_STEP.read_text(encoding="utf-8").strip()
    return prompt.replace(ROUND_ONE_HEADING, f"{step}\n\n{ROUND_ONE_HEADING}")


def runtime_and_endpoint_arns(runtimes: list[agentcore.Runtime]) -> list[str]:
    """What InvokeAgentRuntime is authorized against: each Runtime and its endpoints."""
    return [
        arn
        for runtime in runtimes
        for arn in (runtime.agent_runtime_arn, f"{runtime.agent_runtime_arn}/runtime-endpoint/*")
    ]


def runtime_mcp_endpoint(scope: Construct, runtime_id: str) -> str:
    """The Runtime MCP invocation URL, with the runtime ARN URL-encoded as the service
    requires."""
    stack = cdk.Stack.of(scope)
    encoded_arn = cdk.Fn.join(
        "",
        [
            "arn%3A",
            stack.partition,
            "%3Abedrock-agentcore%3A",
            stack.region,
            "%3A",
            stack.account,
            "%3Aruntime%2F",
            runtime_id,
        ],
    )
    return cdk.Fn.join(
        "",
        [
            "https://bedrock-agentcore.",
            stack.region,
            ".",
            stack.url_suffix,
            "/runtimes/",
            encoded_arn,
            "/invocations?qualifier=DEFAULT",
        ],
    )


class AgentsLayer(Construct):
    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        cfg: AppConfig,
        key: kms.IKey,
        artifacts_bucket: s3.IBucket,
        web_search: WebSearchEndpoint | None = None,
        cache: ResultCache | None = None,
    ) -> None:
        super().__init__(scope, id)
        self.web_search = web_search
        self.web_search_gateway: WebSearchGateway | None = None
        self.cache = cache
        stack = cdk.Stack.of(self)
        arn_base = f"arn:{stack.partition}:bedrock-agentcore:{stack.region}"
        self.harness_name = cfg.app_name + HARNESS_SUFFIX
        self.gateway_name = cfg.app_name + GATEWAY_SUFFIX
        self.tools_gateway_name = cfg.app_name + TOOLS_GATEWAY_SUFFIX
        self.runtimes: dict[str, agentcore.Runtime] = {}
        self.tools_gateway: agentcore.Gateway | None = None
        self.registry: SpecialistRegistry | None = None
        self.browser: agentcore.BrowserCustom | None = None
        if cfg.browser_signing:
            self.browser = agentcore.BrowserCustom(
                self,
                "SignedBrowser",
                browser_custom_name=cfg.app_name + SIGNED_BROWSER_SUFFIX,
                description="Web Bot Auth signed browser for page captures",
                browser_signing=agentcore.BrowserSigning.ENABLED,
                network_configuration=agentcore.BrowserNetworkConfiguration.using_public_network(),
            )
            self.browser.apply_removal_policy(cfg.removal_policy)
        self.browser_id = self.browser.browser_id if self.browser else MANAGED_BROWSER_ID

        self.tools_runtime = self._tools_runtime(cfg, key, artifacts_bucket, arn_base)
        # Specialist -> the tools Runtime copy its captures call (-c splitToolsRuntimes).
        self.capture_runtimes: dict[str, agentcore.Runtime] = {}
        if cfg.direct_tools and cfg.split_tools_runtimes:
            for agent, runtime_name in CAPTURE_RUNTIMES.items():
                self.capture_runtimes[agent] = self._tools_runtime(
                    cfg, key, artifacts_bucket, arn_base, name=runtime_name
                )
        tools_target = self._tools_gateway(cfg, stack, self.tools_runtime)
        for name in SPECIALISTS:
            self.runtimes[name] = self._specialist(name, cfg, key, artifacts_bucket)
            # Ready before a specialist can take traffic, not just before the harness.
            self.runtimes[name].node.add_dependency(tools_target)
            if name in WEB_SEARCH_AGENTS and self.web_search_gateway is not None:
                self.runtimes[name].node.add_dependency(self.web_search_gateway)
        self.dispatcher = self._dispatcher(cfg, key, artifacts_bucket)
        runtime_arns = runtime_and_endpoint_arns([*self.runtimes.values(), self.dispatcher])

        # ── Gateway ────────────────────────────────────────────────────────────
        gateway_role = iam.Role(
            self,
            "GatewayRole",
            assumed_by=agentcore_principal(stack, f"gateway/{self.gateway_name}"),
            description="phish Gateway: SigV4 caller of the specialist tools",
        )
        gateway = agentcore.Gateway(
            self,
            "Gateway",
            gateway_name=self.gateway_name,
            description="Specialist agents for the phishing orchestrator",
            # SigV4 inbound: only principals granted InvokeGateway (the harness role) get in.
            authorizer_configuration=agentcore.GatewayAuthorizer.using_aws_iam(),
            # An empty MCP block is rejected at create time ("MCP configuration cannot be
            # empty"), so list the protocol versions the harness MCP client may negotiate.
            protocol_configuration=agentcore.McpProtocolConfiguration(
                supported_versions=[
                    agentcore.MCPProtocolVersion.MCP_2025_03_26,
                    agentcore.MCPProtocolVersion.MCP_2025_06_18,
                ]
            ),
            role=gateway_role,
        )
        gateway.apply_removal_policy(cfg.removal_policy)
        self.gateway_arn = gateway.gateway_arn
        targets: list[agentcore.GatewayTarget] = []

        gateway_role.add_to_principal_policy(
            iam.PolicyStatement(
                actions=["bedrock-agentcore:InvokeAgentRuntime"],
                resources=runtime_arns,
            )
        )
        # The dispatcher serves round one; the per-specialist targets serve only the optional
        # second round (one specialist, once).
        mcp_targets = [
            ("DispatcherTarget", DISPATCHER_TARGET_NAME, DISPATCHER_DESCRIPTION, self.dispatcher),
            *(
                (f"{pascal(name)}Target", TARGET_NAMES[name], DESCRIPTIONS[name], runtime)
                for name, runtime in self.runtimes.items()
            ),
        ]
        for construct_id, target_name, description, runtime in mcp_targets:
            targets.append(
                gateway.add_mcp_server_target(
                    construct_id,
                    gateway_target_name=target_name,
                    description=description,
                    endpoint=runtime_mcp_endpoint(self, runtime.agent_runtime_id),
                    # SigV4 to AgentCore Runtime with the gateway role.
                    credential_provider_configurations=[
                        agentcore.GatewayCredentialProvider.from_iam_role(
                            service="bedrock-agentcore"
                        )
                    ],
                )
            )

        registry_available = cfg.agent_registry and (
            cdk.Token.is_unresolved(stack.region) or stack.region in REGISTRY_REGIONS
        )
        if registry_available:
            targets.append(self._registry_target(cfg, gateway, gateway_role))
        elif cfg.agent_registry:
            # Everything else works in any AgentCore Region; only the catalog needs Agent
            # Registry, so the lookup step is left out of the prompt as well.
            cdk.Annotations.of(self).add_warning(
                f"Agent Registry is offered in {', '.join(REGISTRY_REGIONS)}, not "
                f"{stack.region}: the MCP server catalog and its lookup are skipped."
            )

        for target in targets:
            target.apply_removal_policy(cfg.removal_policy)
            depend_on_role_policy(target, gateway_role)

        # ── Orchestrator Harness ──────────────────────────────────────────────
        system_prompt = orchestrator_prompt(registry_available)
        harness_role = self._harness_role(cfg, gateway, stack, arn_base)

        # L1: aws-cdk-lib 2.271 has no L2 for AWS::BedrockAgentCore::Harness.
        H = agentcore.CfnHarness
        harness = H(
            self,
            "Harness",
            harness_name=self.harness_name,
            execution_role_arn=harness_role.role_arn,
            model=H.HarnessModelConfigurationProperty(
                bedrock_model_config=H.HarnessBedrockModelConfigProperty(
                    model_id=cfg.orchestrator_model
                )
            ),
            system_prompt=[H.HarnessSystemContentBlockProperty(text=system_prompt)],
            tools=[
                H.HarnessToolProperty(
                    type="agentcore_gateway",
                    name=GATEWAY_TOOL_NAME,
                    config=H.HarnessToolConfigurationProperty(
                        agent_core_gateway=H.HarnessAgentCoreGatewayConfigProperty(
                            gateway_arn=self.gateway_arn,
                            # SigV4 from the harness role, which holds InvokeGateway on this
                            # gateway only.
                            outbound_auth=H.HarnessGatewayOutboundAuthProperty(aws_iam={}),
                        )
                    ),
                )
            ],
            # Gateway tools only: drops the built-in shell and file tools from an agent
            # whose input is a caller URL and hostile page text.
            allowed_tools=[f"@{GATEWAY_TOOL_NAME}/*"],
            # Per InvokeHarness call (the docs scope both limits to one invocation, so a second
            # turn on the same session gets its own budget): an optional registry search, the
            # dispatcher call, one second-round call, one retry, and the final answer, with
            # room to spare.
            max_iterations=8,
            # Below the worker Lambda's 300 s timeout so no session outlives its caller; the
            # worker passes a smaller per-call timeoutSeconds for a second turn.
            timeout_seconds=240,
            max_tokens=cfg.harness_max_tokens,
            # No managed memory. A scan's two turns share one runtime session, which keeps the
            # conversation (verified live 2026-10-16 with memory disabled), and similar past
            # scans come from the app's own owner-scoped episodic memory. Managed memory kept
            # long-term facts and summaries under one shared actor ("default"), so one user's
            # scan text, including hostile page text, could be retrieved into another's scan.
            memory=H.HarnessMemoryConfigurationProperty(disabled={}),
            # No guardrail property: the Harness type has none. The backend applies guardrails.
            tags=[cdk.CfnTag(key="Role", value="orchestrator")],
        )
        harness.apply_removal_policy(cfg.removal_policy)
        for target in targets:
            # A Gateway with no target is READY but advertises zero tools.
            harness.node.add_dependency(target)
        depend_on_role_policy(harness, harness_role)
        self.harness_arn = harness.attr_arn

        stack_output(self, "OrchestratorHarnessArn", self.harness_arn, "Orchestrator Harness ARN")
        stack_output(self, "GatewayArn", self.gateway_arn, "Specialists Gateway ARN")
        dispatcher_arn = self.dispatcher.agent_runtime_arn
        stack_output(self, "DispatcherRuntimeArn", dispatcher_arn, "Dispatcher Runtime ARN")
        for name, runtime in self.runtimes.items():
            stack_output(
                self, f"{pascal(name)}RuntimeArn", runtime.agent_runtime_arn, f"{name} Runtime ARN"
            )

    def _adopt_runtime_log_group(
        self, name: str, runtime: agentcore.Runtime, cfg: AppConfig, key: kms.IKey
    ) -> None:
        """Give the runtime's log group the CMK and a retention without owning its creation.

        The service creates /aws/bedrock-agentcore/runtimes/{agentRuntimeId}-DEFAULT as soon as
        the Runtime starts, which races an AWS::Logs::LogGroup of the same name and fails the
        deploy with AlreadyExists. So: create it if still missing (with the CMK), then set the
        retention and associate the CMK either way. In dev the group is deleted with the stack.
        """
        group = f"/aws/bedrock-agentcore/runtimes/{runtime.agent_runtime_id}-DEFAULT"
        group_arn = cdk.Stack.of(self).format_arn(
            service="logs",
            resource="log-group",
            resource_name=group,
            arn_format=cdk.ArnFormat.COLON_RESOURCE_NAME,
        )
        physical_id = cr.PhysicalResourceId.of(group)
        # CreateLogGroup with a kmsKeyId and AssociateKmsKey check the key as the caller.
        describe_key = iam.PolicyStatement(actions=["kms:DescribeKey"], resources=[key.key_arn])
        policy = cr.AwsCustomResourcePolicy.from_statements(
            [
                iam.PolicyStatement(
                    actions=[
                        "logs:CreateLogGroup",
                        "logs:PutRetentionPolicy",
                        "logs:AssociateKmsKey",
                        "logs:DeleteLogGroup",
                    ],
                    resources=[group_arn, f"{group_arn}:*"],
                ),
                describe_key,
            ]
        )
        # -c splitToolsRuntimes adds two Runtimes, and three copies of this policy per Runtime
        # then overflow the custom resources' shared role (IAM's 10,240-byte inline limit). All
        # three steps run as that one role, after the first step, so only the first carries
        # the log-group statement; the source fork used a log-group wildcard instead.
        later_policy = (
            cr.AwsCustomResourcePolicy.from_statements([describe_key])
            if cfg.split_tools_runtimes
            else policy
        )
        delete = (
            cr.AwsSdkCall(
                service="CloudWatchLogs",
                action="deleteLogGroup",
                parameters={"logGroupName": group},
                ignore_error_codes_matching="ResourceNotFoundException",
            )
            if cfg.removal_policy == cdk.RemovalPolicy.DESTROY
            else None
        )
        steps = [
            (
                "Create",
                "createLogGroup",
                {"logGroupName": group, "kmsKeyId": key.key_arn},
                "ResourceAlreadyExistsException",
                delete,
            ),
            (
                "Retention",
                "putRetentionPolicy",
                {"logGroupName": group, "retentionInDays": RUNTIME_LOG_RETENTION_DAYS},
                None,
                None,
            ),
            (
                "Key",
                "associateKmsKey",
                {"logGroupName": group, "kmsKeyId": key.key_arn},
                None,
                None,
            ),
        ]
        previous: cr.AwsCustomResource | None = None
        for suffix, action, parameters, ignore, on_delete in steps:
            call = cr.AwsSdkCall(
                service="CloudWatchLogs",
                action=action,
                parameters=parameters,
                physical_resource_id=physical_id,
                ignore_error_codes_matching=ignore,
            )
            step = cr.AwsCustomResource(
                self,
                f"{pascal(name)}RuntimeLogs{suffix}",
                on_create=call,
                on_update=call,
                on_delete=on_delete,
                policy=policy if previous is None else later_policy,
                install_latest_aws_sdk=False,
            )
            if previous is not None:
                step.node.add_dependency(previous)
            previous = step

    def _web_search_env(self, name: str) -> dict[str, str]:
        if name not in WEB_SEARCH_AGENTS or self.web_search is None:
            return {}
        return {
            "WEB_SEARCH_GATEWAY_URL": self.web_search.gateway_url,
            "WEB_SEARCH_REGION": self.web_search.region,
            "WEB_SEARCH_TOOL_NAME": self.web_search.tool_name,
        }

    def _runtime(
        self,
        name: str,
        description: str,
        environment: dict[str, str],
        cfg: AppConfig,
        key: kms.IKey,
        agent: str | None = None,
    ) -> agentcore.Runtime:
        """One MCP Runtime from the shared image (AGENT picks what it serves; default name)."""
        if cfg.capture_recovery:
            environment = {**environment, "CAPTURE_RECOVERY": "1"}
        if cfg.capture_block_retry:
            environment = {**environment, "CAPTURE_BLOCK_RETRY": "1"}
        if cfg.latency_budgets:
            environment = {**environment, "LATENCY_BUDGETS": "1"}
        if cfg.code_text_budget == "half":
            # The capture runs in the tools Runtime and the retry view in code_analyst.
            environment = {**environment, "CODE_TEXT_BUDGET": "half"}
        image = ecr_assets.DockerImageAsset(
            self,
            f"{pascal(name)}Image",
            directory=str(IMAGE_CONTEXT),
            file=IMAGE_DOCKERFILE,
            # A tools Runtime copy builds the same image as the tools server (one ECR asset).
            build_args={"AGENT": agent or name},
            # AgentCore Runtime only runs ARM64 images; amd64 never reaches READY.
            platform=ecr_assets.Platform.LINUX_ARM64,
            exclude=IMAGE_EXCLUDES,
            ignore_mode=cdk.IgnoreMode.DOCKER,
        )
        runtime = agentcore.Runtime(
            self,
            f"{pascal(name)}Runtime",
            runtime_name=f"{cfg.app_name}_{name}",
            description=f"phish {name}: {description}",
            agent_runtime_artifact=agentcore.AgentRuntimeArtifact.from_ecr_repository(
                image.repository, image.image_tag
            ),
            protocol_configuration=agentcore.ProtocolType.MCP,
            # PUBLIC: RDAP lookups and the AgentCore Browser need outbound HTTPS.
            network_configuration=agentcore.RuntimeNetworkConfiguration.using_public_network(),
            environment_variables=environment,
            # Sessions are one scan long; 60 s idle is the service floor and frees microVMs.
            lifecycle_configuration=agentcore.LifecycleConfiguration(
                idle_runtime_session_timeout=cdk.Duration.seconds(60),
                max_lifetime=cdk.Duration.seconds(1800),
            ),
            tracing_enabled=True,
        )
        self._adopt_runtime_log_group(name, runtime, cfg, key)
        return runtime

    def _browser_statement(self, arn_base: str) -> iam.PolicyStatement:
        stack = cdk.Stack.of(self)
        return iam.PolicyStatement(
            actions=BROWSER_ACTIONS,
            # The signed custom browser (or the AWS-managed one); sessions are sub-resources.
            resources=[
                self.browser.browser_arn
                if self.browser
                else f"{arn_base}:aws:browser/{MANAGED_BROWSER_ID}",
                f"{arn_base}:{stack.account}:browser-session/*",
            ],
        )

    def _direct_tools_env(self, name: str) -> dict[str, str]:
        if name not in DIRECT_TOOLS_AGENTS:
            return {"LOCAL_RDAP": "1"}
        return {
            "TOOLS_RUNTIME_ARN": self._capture_runtime(name).agent_runtime_arn,
            "TOOLS_SESSION_PER_SCAN": "1",
        }

    def _capture_runtime(self, name: str) -> agentcore.Runtime:
        return self.capture_runtimes.get(name, self.tools_runtime)

    def _specialist(
        self, name: str, cfg: AppConfig, key: kms.IKey, artifacts_bucket: s3.IBucket
    ) -> agentcore.Runtime:
        assert self.tools_gateway is not None
        environment = {
            "ARTIFACTS_BUCKET": artifacts_bucket.bucket_name,
            "MODEL_ID": cfg.specialist_model,
            "LOG_LEVEL": "INFO",
            # Browser capture and RDAP run in the tools Runtime, behind this Gateway.
            "TOOLS_GATEWAY_URL": self.tools_gateway.gateway_url or "",
            "TOOLS_GATEWAY_REGION": cdk.Stack.of(self).region,
            # -c directTools: the same tools Runtime, invoked directly (no Gateway hop), on one
            # tools session per scan; url_analyst runs RDAP in process instead (its own
            # SSRF-guarded client and the RDAP cache), so it needs no tools Runtime at all.
            **(self._direct_tools_env(name) if cfg.direct_tools else {}),
            **self._web_search_env(name),
        }
        if name == "url_analyst" and cfg.local_rdap:
            environment["LOCAL_RDAP"] = "1"
        if name == "code_analyst" and cfg.code_model_view == "compact":
            environment["CODE_MODEL_VIEW"] = "compact"
        if self.cache is not None and name in CACHE_AGENTS:
            environment.update(self.cache.agent_environment)
        runtime = self._runtime(name, DESCRIPTIONS[name], environment, cfg, key)
        role = runtime.role
        if self.cache is not None and name in CACHE_AGENTS:
            # url_analyst caches RDAP, brand_visual caches web search; fail-open reads and writes.
            self.cache.grant_read_write(role)
        # Each specialist reaches its own model only, so a prompt-injected specialist cannot
        # call Opus.
        for statement in bedrock_invoke_statements(self, [cfg.specialist_model]):
            role.add_to_principal_policy(statement)
        # The tools Runtime writes the screenshot and capture.json, so a specialist writes its
        # own Finding only.
        role.add_to_principal_policy(
            iam.PolicyStatement(
                actions=["s3:PutObject"],
                resources=[artifacts_bucket.arn_for_objects(k) for k in FINDING_KEYS[name]],
            )
        )
        role.add_to_principal_policy(
            iam.PolicyStatement(
                actions=["kms:GenerateDataKey", "kms:Encrypt"], resources=[key.key_arn]
            )
        )
        if cfg.direct_tools and name in DIRECT_TOOLS_AGENTS:
            # Its own tools Runtime and endpoints only; tools Runtimes stay the only ones that
            # may start a browser session, and specialists still cannot reach each other.
            role.add_to_principal_policy(
                iam.PolicyStatement(
                    actions=["bedrock-agentcore:InvokeAgentRuntime"],
                    resources=runtime_and_endpoint_arns([self._capture_runtime(name)]),
                )
            )
        gateways = [self.tools_gateway.gateway_arn]
        if name in WEB_SEARCH_AGENTS and self.web_search is not None:
            # SigV4 to the Web Search Gateway: the edge stack's (us-east-1) or, when the
            # Region offers the connector, this stack's own.
            gateways.append(self.web_search.gateway_arn)
        role.add_to_principal_policy(
            iam.PolicyStatement(
                actions=["bedrock-agentcore:InvokeGateway"],
                resources=list(dict.fromkeys(gateways)),
            )
        )
        if name == "brand_visual":
            # Reads back the screenshot the tools Runtime stored, only to show the model.
            role.add_to_principal_policy(
                iam.PolicyStatement(
                    actions=["s3:GetObject"],
                    resources=[artifacts_bucket.arn_for_objects("scans/*/screenshot.png")],
                )
            )
            role.add_to_principal_policy(
                iam.PolicyStatement(actions=["kms:Decrypt"], resources=[key.key_arn])
            )
        return runtime

    def _dispatcher(
        self, cfg: AppConfig, key: kms.IKey, artifacts_bucket: s3.IBucket
    ) -> agentcore.Runtime:
        """The no-model Runtime behind dispatcher___analyze_all.

        Its role invokes the three specialist Runtimes only (not the tools Runtime, not
        itself) and writes only the three Finding keys, for the error Finding of a specialist
        that could not run. No Bedrock, browser, Gateway or cache grant.
        """
        runtime = self._runtime(
            DISPATCHER_RUNTIME,
            DISPATCHER_DESCRIPTION,
            {
                "ARTIFACTS_BUCKET": artifacts_bucket.bucket_name,
                "LOG_LEVEL": "INFO",
                **{
                    f"{name.upper()}_RUNTIME_ARN": runtime.agent_runtime_arn
                    for name, runtime in self.runtimes.items()
                },
            },
            cfg,
            key,
        )
        role = runtime.role
        role.add_to_principal_policy(
            iam.PolicyStatement(
                actions=["bedrock-agentcore:InvokeAgentRuntime"],
                resources=runtime_and_endpoint_arns(list(self.runtimes.values())),
            )
        )
        role.add_to_principal_policy(
            iam.PolicyStatement(
                actions=["s3:PutObject"],
                resources=[
                    artifacts_bucket.arn_for_objects(k)
                    for name in SPECIALISTS
                    for k in FINDING_KEYS[name]
                ],
            )
        )
        role.add_to_principal_policy(
            iam.PolicyStatement(
                actions=["kms:GenerateDataKey", "kms:Encrypt"], resources=[key.key_arn]
            )
        )
        return runtime

    def _tools_runtime(
        self,
        cfg: AppConfig,
        key: kms.IKey,
        artifacts_bucket: s3.IBucket,
        arn_base: str,
        name: str = TOOLS_RUNTIME,
    ) -> agentcore.Runtime:
        """The only Runtimes that may start a browser session or write a screenshot: the tools
        server, and with -c splitToolsRuntimes its copies for the capturing specialists."""
        runtime = self._runtime(
            name,
            TOOLS_DESCRIPTION,
            {
                "ARTIFACTS_BUCKET": artifacts_bucket.bucket_name,
                "BROWSER_ID": self.browser_id,
                "LOG_LEVEL": "INFO",
                **(self.cache.agent_environment if self.cache is not None else {}),
            },
            cfg,
            key,
            agent=TOOLS_RUNTIME,
        )
        role = runtime.role
        if self.cache is not None:
            # whois_lookup runs here and shares the RDAP cache.
            self.cache.grant_read_write(role)
        # No Bedrock statement: the tools make no model call.
        role.add_to_principal_policy(self._browser_statement(arn_base))
        role.add_to_principal_policy(
            iam.PolicyStatement(
                actions=["s3:PutObject"],
                resources=[artifacts_bucket.arn_for_objects(k) for k in TOOLS_ARTIFACT_KEYS],
            )
        )
        role.add_to_principal_policy(
            iam.PolicyStatement(
                actions=["kms:GenerateDataKey", "kms:Encrypt"], resources=[key.key_arn]
            )
        )
        return runtime

    def _tools_gateway(
        self, cfg: AppConfig, stack: cdk.Stack, tools_runtime: agentcore.Runtime
    ) -> agentcore.GatewayTarget:
        """One Gateway, one MCP server target, several tools (tools___capture_page, ...).

        SigV4 inbound: the three specialist roles hold InvokeGateway on it; the harness role
        does not, so the orchestrator cannot call a browser tool. IAM is per Gateway, not per
        tool, so any specialist role could call any tool here. The tools server therefore
        validates every input itself (URL guard, scan id), and brand_visual, code_analyst and
        url_analyst are not told about each other's tools. Residual risk: a prompt-injected
        specialist could call a sibling's tool, for example url_analyst calling capture_page;
        the tool is read-only apart from one S3 object under scans/<scan id>/. A Gateway
        interceptor Lambda that checks the caller per tool would close it, at the cost of
        the hop this mode removes.
        """
        role = iam.Role(
            self,
            "ToolsGatewayRole",
            assumed_by=agentcore_principal(stack, f"gateway/{self.tools_gateway_name}"),
            description="phish tools Gateway: SigV4 caller of the tools server",
        )
        role.add_to_principal_policy(
            iam.PolicyStatement(
                actions=["bedrock-agentcore:InvokeAgentRuntime"],
                resources=runtime_and_endpoint_arns([tools_runtime]),
            )
        )
        gateway = agentcore.Gateway(
            self,
            "ToolsGateway",
            gateway_name=self.tools_gateway_name,
            description="Shared browser, screenshot and RDAP tools for the specialists",
            authorizer_configuration=agentcore.GatewayAuthorizer.using_aws_iam(),
            # The Gateway negotiates only these; see common/gateway_mcp.py for the client pin.
            protocol_configuration=agentcore.McpProtocolConfiguration(
                supported_versions=[
                    agentcore.MCPProtocolVersion.MCP_2025_03_26,
                    agentcore.MCPProtocolVersion.MCP_2025_06_18,
                ]
            ),
            role=role,
        )
        gateway.apply_removal_policy(cfg.removal_policy)
        self.tools_gateway = gateway
        target = gateway.add_mcp_server_target(
            "ToolsTarget",
            gateway_target_name=TOOLS_TARGET_NAME,
            description=TOOLS_DESCRIPTION,
            endpoint=runtime_mcp_endpoint(self, tools_runtime.agent_runtime_id),
            credential_provider_configurations=[
                agentcore.GatewayCredentialProvider.from_iam_role(service="bedrock-agentcore")
            ],
        )
        target.apply_removal_policy(cfg.removal_policy)
        depend_on_role_policy(target, role)
        if web_search_folds(cfg, stack.region):
            # The Web Search Gateway moves into this stack (no edge stack, no cross-region
            # reference) but stays a Gateway of its own: IAM is per Gateway, so a target here
            # would let url_analyst and code_analyst search the web too. Only brand_visual holds
            # InvokeGateway on it.
            self.web_search_gateway = WebSearchGateway(self, "WebSearch", cfg=cfg)
            self.web_search = self.web_search_gateway.endpoint
        stack_output(self, "ToolsGatewayArn", gateway.gateway_arn, "Tools Gateway ARN")
        stack_output(self, "ToolsGatewayUrl", gateway.gateway_url or "", "Tools Gateway MCP URL")
        stack_output(
            self, "ToolsServerRuntimeArn", tools_runtime.agent_runtime_arn, "Tools Runtime ARN"
        )
        return target

    def _registry_target(
        self, cfg: AppConfig, gateway: agentcore.Gateway, gateway_role: iam.Role
    ) -> agentcore.GatewayTarget:
        """The registry's MCP endpoint as a SigV4 MCP server target (registry___* tools).

        The Gateway role signs for agent-registry and may search this one registry only. A
        record can only name tools; the orchestrator can still call only this Gateway's targets.
        """
        self._registry_and_outputs(cfg)
        assert self.registry is not None
        self.registry.grant_discovery(gateway_role)
        target = gateway.add_mcp_server_target(
            "RegistryTarget",
            gateway_target_name=REGISTRY_TARGET_NAME,
            description=REGISTRY_TARGET_DESCRIPTION,
            endpoint=self.registry.mcp_url,
            credential_provider_configurations=[
                agentcore.GatewayCredentialProvider.from_iam_role(service=REGISTRY_SIGV4_SERVICE)
            ],
        )
        # The Gateway lists the target's tools when it creates it, and the first search after a
        # deploy should find every record: wait for the records and their submit step.
        target.node.add_dependency(self.registry)
        return target

    def _registry_and_outputs(self, cfg: AppConfig) -> None:
        records = [
            McpRecord(
                name=pascal(name),
                slug=TARGET_NAMES[name],
                description=DESCRIPTIONS[name],
                endpoint=runtime_mcp_endpoint(self, runtime.agent_runtime_id),
                tools=SPECIALIST_TOOLS,
            )
            for name, runtime in self.runtimes.items()
        ]
        records.append(
            McpRecord(
                name="Dispatcher",
                slug=DISPATCHER_TARGET_NAME,
                description=DISPATCHER_DESCRIPTION,
                endpoint=runtime_mcp_endpoint(self, self.dispatcher.agent_runtime_id),
                tools=DISPATCHER_TOOLS,
            )
        )
        records.append(
            McpRecord(
                name="PhishTools",
                slug="tools",
                description=TOOLS_DESCRIPTION,
                endpoint=runtime_mcp_endpoint(self, self.tools_runtime.agent_runtime_id),
                tools=TOOLS_SERVER_TOOLS,
            )
        )
        self.registry = SpecialistRegistry(self, "Registry", cfg=cfg, records=records)

    def _harness_role(
        self, cfg: AppConfig, gateway: agentcore.Gateway, stack: cdk.Stack, arn_base: str
    ) -> iam.Role:
        role = iam.Role(
            self,
            "HarnessRole",
            # The harness runs on a runtime it creates, named harness_<harness name>, and that
            # runtime's creation validates this role against its own ARN.
            assumed_by=agentcore_principal(
                stack, f"harness/{self.harness_name}", f"runtime/harness_{self.harness_name}"
            ),
            description="phish orchestrator Harness execution role",
        )
        for statement in bedrock_invoke_statements(self, [cfg.orchestrator_model]):
            role.add_to_principal_policy(statement)
        role.add_to_principal_policy(
            iam.PolicyStatement(
                actions=["bedrock-agentcore:InvokeGateway"], resources=[gateway.gateway_arn]
            )
        )
        # No memory grants: the Harness runs with memory disabled (see memory= on CfnHarness).
        # Scoped by name prefix because the harness ARN carries a service suffix, and
        # referencing the harness attribute here would make a dependency cycle.
        role.add_to_principal_policy(
            iam.PolicyStatement(
                actions=["bedrock-agentcore:GetHarness"],
                resources=[f"{arn_base}:{stack.account}:harness/{self.harness_name}-*"],
            )
        )
        role.add_to_principal_policy(
            iam.PolicyStatement(
                actions=["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                resources=[
                    f"arn:{stack.partition}:logs:{stack.region}:{stack.account}"
                    f":log-group:/aws/bedrock-agentcore/{self.harness_name}*"
                ],
            )
        )
        return role

    def grant_invoke_tools(self, grantee: iam.IGrantable) -> None:
        """Let the worker call the tools Runtime directly (precheck_url), not through a Gateway.

        The grant is scoped to the tools Runtime and its endpoints: the worker still cannot
        reach a specialist, nor the dispatcher unless -c directOrchestration grants it.
        """
        iam.Grant.add_to_principal(
            grantee=grantee,
            actions=["bedrock-agentcore:InvokeAgentRuntime"],
            resource_arns=runtime_and_endpoint_arns([self.tools_runtime]),
        )

    def grant_invoke_dispatcher(self, grantee: iam.IGrantable) -> None:
        """-c directOrchestration: the worker calls the dispatcher Runtime itself. Scoped to the
        dispatcher and its endpoints; the specialists stay reachable only through it."""
        iam.Grant.add_to_principal(
            grantee=grantee,
            actions=["bedrock-agentcore:InvokeAgentRuntime"],
            resource_arns=runtime_and_endpoint_arns([self.dispatcher]),
        )

    def grant_invoke_specialists(self, grantee: iam.IGrantable) -> None:
        """-c directSpecialists: the worker runs round one itself, without the dispatcher.

        The three specialist Runtimes and their endpoints only; never a tools Runtime, so the
        worker still cannot start a browser session or capture a page itself.
        """
        iam.Grant.add_to_principal(
            grantee=grantee,
            actions=["bedrock-agentcore:InvokeAgentRuntime"],
            resource_arns=runtime_and_endpoint_arns(list(self.runtimes.values())),
        )

    def grant_invoke_harness(self, grantee: iam.IGrantable) -> None:
        # The Runtime ARNs are deliberately absent: callers reach specialists only through the
        # orchestrator. InvokeHarness is authorized as InvokeAgentRuntime on the harness ARN.
        iam.Grant.add_to_principal(
            grantee=grantee,
            actions=[
                "bedrock-agentcore:InvokeHarness",
                "bedrock-agentcore:InvokeAgentRuntime",
                "bedrock-agentcore:StopRuntimeSession",
            ],
            # AgentCore authorizes runtime calls against the endpoint ARN as well as the harness
            # ARN; with only the bare ARN, StopRuntimeSession was denied after every scan. Both
            # ARNs belong to this one harness, so nothing else becomes reachable.
            resource_arns=[self.harness_arn, f"{self.harness_arn}/runtime-endpoint/*"],
        )
