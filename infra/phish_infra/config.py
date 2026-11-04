# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Context flags, parsed and validated once so constructs never read raw context."""

from __future__ import annotations

import re
from dataclasses import dataclass

import aws_cdk as cdk
from constructs import Node

DEFAULT_OWNER = "phish-triage-owner"
# -c specialistMode (registry or direct) was replaced by -c agentRegistry. Every deployment
# now has the dispatcher and the shared tools server; the flag only adds the AWS Agent
# Registry catalog and the orchestrator's lookup step. An old specialistMode fails the synth
# with this message rather than being mapped silently, because neither old value means what
# it did: registry was the default and is now opt-in, and direct no longer exists.
SPECIALIST_MODE_REMOVED = (
    "specialistMode was removed. The dispatcher and the shared tools server are always "
    "deployed; add -c agentRegistry=true for the AWS Agent Registry catalog and lookup "
    "(the old registry mode), or drop the flag (direct mode no longer exists)."
)
DEFAULT_ORCHESTRATOR_MODEL = "us.anthropic.claude-opus-5-5"
DEFAULT_SPECIALIST_MODEL = "global.anthropic.claude-sonnet-5-5"
# The orchestrator writes a Verdict JSON plus a Markdown report of up to 450 words
# (about 1,000 tokens, more once JSON-escaped) after its own thinking, in its last turn.
# Too low truncates the verdict (stop_reason=max_tokens, no verdict); too high
# reserves quota Bedrock holds up front, which lowers effective concurrency.
DEFAULT_HARNESS_MAX_TOKENS = 8192
HARNESS_MAX_TOKENS_FLOOR = 4096
# Opus 5.5 always thinks (it cannot be disabled) and defaults to effort "medium"; effort is
# the only lever on reasoning tokens, which are part of the orchestrator's output time.
# The default is "medium" (cdk.json ships it too). Measured 2026-10-16 on the verify
# stack, registry lookup plus three serial specialist calls, the same 5 URLs per effort:
# "low" gave a median of 40.7 s to the verdict but 2 of 5 turn-1 answers were not valid JSON
# (an unquoted value), which costs a whole retried scan; "medium" gave 43.0 s and 5 of 5
# valid. Empty sends nothing and keeps the model default. Override with
# -c orchestratorEffort=<value>, and check verdict quality with eval/evaluate_agents.py.
DEFAULT_ORCHESTRATOR_EFFORT = "medium"
ORCHESTRATOR_EFFORTS = ("", "low", "medium", "high")
# Prefix of every named resource and of the stack names. Lowercase letters and digits only,
# because it lands in Runtime and Harness names (underscores) and in S3-style names (hyphens).
DEFAULT_APP_NAME = "phish"
_APP_NAME = re.compile(r"^[a-z][a-z0-9]{1,11}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# CloudFront only accepts viewer certificates from ACM in us-east-1.
_CLOUDFRONT_CERT = re.compile(r"^arn:aws[a-z-]*:acm:us-east-1:[0-9]{12}:certificate/[A-Za-z0-9-]+$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


CODE_MODEL_VIEWS = ("full", "compact")
CODE_TEXT_BUDGETS = ("full", "half")


def _choice(value: object, flag: str, allowed: tuple[str, ...]) -> str:
    text = str(value).strip().lower()
    if text not in allowed:
        raise ValueError(f"{flag} must be one of {', '.join(allowed)}, got {value!r}")
    return text


def _as_int(value: object, flag: str, low: int, high: int | None) -> int:
    bounds = f"between {low} and {high}" if high is not None else f"of at least {low}"
    try:
        number = int(str(value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{flag} must be an integer {bounds}, got {value!r}") from exc
    if number < low or (high is not None and number > high):
        raise ValueError(f"{flag} must be an integer {bounds}, got {number}")
    return number


def normalize_domains(value: object) -> tuple[str, ...]:
    """Accept a comma string or a list; '*' and '' both mean unrestricted."""
    items = value if isinstance(value, list) else str(value or "").split(",")
    out: list[str] = []
    for raw in items:
        domain = str(raw).strip().lower()
        if not domain or domain == "*":
            continue
        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError(f"allowedEmailDomains: {raw!r} is not a domain") from exc
        if not _DOMAIN.match(domain):
            raise ValueError(f"allowedEmailDomains: {raw!r} is not a domain")
        if domain not in out:
            out.append(domain)
    return tuple(out)


@dataclass(frozen=True)
class AppConfig:
    owner: str
    environment: str
    sign_up_mode: str
    invite_code: bool
    allowed_email_domains: tuple[str, ...]
    retention_days: int
    scan_concurrency: int
    orchestrator_model: str
    specialist_model: str
    harness_max_tokens: int
    skip_asset_build: bool
    orchestrator_effort: str = ""
    # On by default: Bedrock prompt caching on the orchestrator's Harness calls. The worker sends
    # cache_control per invocation (the Harness resource has no caching setting).
    orchestrator_prompt_cache: bool = True
    # None: Cognito's own email (50 messages per day per account). Set: SES from this address.
    ses_from_address: str | None = None
    # "optional": TOTP offered at sign-in, not forced. "required": every user enrols TOTP.
    mfa: str = "optional"
    # "essentials" (no threat protection) or "plus" (threat protection enforced, billed per MAU).
    cognito_plan: str = "essentials"
    # Both set or both None: a custom console domain with its ACM (us-east-1) certificate.
    domain_name: str | None = None
    certificate_arn: str | None = None
    # On by default: the worker recalls similar past scans and stores a summary of each one.
    episodic_memory: bool = True
    # AgentCore Web Search for brand_visual: a Gateway in the us-east-1 edge stack.
    web_search: bool = True
    # TTLs of the DynamoDB result cache: RDAP per registered domain, web search per brand.
    rdap_cache_ttl_hours: int = 168
    web_search_cache_ttl_hours: int = 24
    # Off by default, as in load_config and cdk.json. True: one custom AgentCore Browser that
    # signs its requests (Web Bot Auth), so sites behind bot walls that accept verified bots let
    # the capture through. False keeps the AWS-managed aws.browser.v1.
    browser_signing: bool = False
    # -c appName: a second copy in the same account and Region needs its own prefix.
    app_name: str = DEFAULT_APP_NAME
    # Off by default. True: an AWS Agent Registry that catalogs the MCP servers, a `registry`
    # target on the specialists Gateway, and a lookup step at the start of the orchestrator
    # prompt. The lookup is informational: round one is still one dispatcher call.
    agent_registry: bool = False
    # "compact" by default (it won the 2026-11-02 A/B, see docs/evaluation.md): code_analyst's
    # model reads a ranked, budgeted extract of the page capture (every form, sink, redirect and
    # POST target kept verbatim, library bundles named but not shown); its heuristics still run on
    # the full capture. "full" sends the whole capture.
    code_model_view: str = "compact"
    # On by default (same A/B). True: every agent Runtime gets CAPTURE_RECOVERY=1: S3 website
    # endpoints are fetched over http, a certificate error gets one certificate-tolerant retry (the
    # verdict is then never legitimate/allow), a download is fingerprinted and never opened, and a
    # transient DNS failure is retried once. False keeps the earlier capture behaviour.
    capture_recovery: bool = True
    # Off by default (as upstream ships it). True: every agent Runtime gets CAPTURE_BLOCK_RETRY=1:
    # a bot wall (403/429 block page, 503 bot-wall title, bot-check page) gets one retry in a
    # fresh context with a desktop Chrome profile inside the same navigation budget, a browser
    # refusal (ERR_BLOCKED_BY_CLIENT) gets the certificate-tolerant retry, and a page still behind
    # a wall is recorded as page_state bot_blocked. The verdict logic is unchanged.
    capture_block_retry: bool = False
    # On by default (-c directOrchestration=false for the Harness; off when agentRegistry=true).
    # True: the worker starts the dispatcher itself, alongside the pre-check, and
    # asks the orchestrator model for the verdict and the report with two Converse calls instead
    # of an AgentCore Harness session. No second round, no Harness trace.
    direct_orchestration: bool = False
    # On by default. True: url_analyst runs its RDAP lookup in process (same SSRF-guarded client
    # and cache) instead of through the tools Runtime.
    local_rdap: bool = False
    # On by default; only with directOrchestration. True: the worker stores `legitimate` without
    # a verdict turn when all three specialists answer legitimate at confidence 80 or more, no
    # capture missed the page and nothing above medium was raised. The caps and the report turn
    # still run.
    unanimous_fast_path: bool = False
    # On by default; only with directOrchestration. True: the worker invokes the three
    # specialist Runtimes itself, without the dispatcher hop, and gets InvokeAgentRuntime on
    # them (never on a tools Runtime).
    direct_specialists: bool = False
    # On by default. True: brand_visual and code_analyst call the tools Runtime directly (no
    # tools Gateway hop) on one tools session per scan, shared with the worker's precheck;
    # url_analyst runs RDAP in process. The tools Gateway stays deployed.
    direct_tools: bool = False
    # On by default; only with directTools. True: brand_visual and code_analyst each call their
    # own copy of the tools Runtime, so a scan's precheck and two captures draw on three
    # Runtimes' session start capacity instead of one.
    split_tools_runtimes: bool = False
    # On by default. True: every agent Runtime gets LATENCY_BUDGETS=1: code_analyst's capture
    # budget 18 s (3 s raw HTML fallback, 1.5 s settle, 20 s server backstop), brand_visual's
    # screenshot 1.5 to 5 s (a failed one keeps the loaded page), capture client timeouts 28 and
    # 30 s, page-specialist deadline 42 s and dispatcher read timeout 52 s.
    latency_budgets: bool = False
    # "half" by default. "half": code_analyst's capture keeps 10 KB per script, 30 KB of script
    # text in total and 12 KB of rendered DOM (15, 60 and 20 KB otherwise).
    code_text_budget: str = "full"
    # Off by default. True: POST /scan from a direct API caller hands back the caller's own
    # PENDING or RUNNING scan of the same URL, or one COMPLETE within 24 hours, unless the
    # body sets "force": true. The web console is never deduplicated.
    scan_dedup: bool = False

    @property
    def stack_prefix(self) -> str:
        """PhishTriageAgentic for the default app name, <AppName>TriageAgentic otherwise."""
        return f"{self.app_name.capitalize()}TriageAgentic"

    @property
    def is_prod(self) -> bool:
        return self.environment == "prod"

    @property
    def removal_policy(self) -> cdk.RemovalPolicy:
        return cdk.RemovalPolicy.RETAIN if self.is_prod else cdk.RemovalPolicy.DESTROY


def load_config(node: Node) -> AppConfig:
    def ctx(key: str, default: object) -> object:
        value = node.try_get_context(key)
        return default if value is None else value

    sign_up_mode = str(ctx("signUpMode", "app"))
    if sign_up_mode not in {"app", "cognito"}:
        raise ValueError(f'signUpMode must be "app" or "cognito", got "{sign_up_mode}"')
    invite_code = _as_bool(ctx("inviteCode", False))
    if invite_code and sign_up_mode == "cognito":
        raise ValueError(
            "inviteCode=true needs signUpMode=app (native Cognito sign-up has no invite step)"
        )

    if node.try_get_context("specialistMode") is not None:
        raise ValueError(SPECIALIST_MODE_REMOVED)

    effort = (
        str(
            ctx(
                "orchestratorEffort",
                DEFAULT_ORCHESTRATOR_EFFORT,
            )
        )
        .strip()
        .lower()
    )
    if effort not in ORCHESTRATOR_EFFORTS:
        raise ValueError(
            f'orchestratorEffort must be "", "low", "medium" or "high", got "{effort}"'
        )
    mfa = str(ctx("mfa", "optional")).strip().lower()
    if mfa not in {"optional", "required"}:
        raise ValueError(f'mfa must be "optional" or "required", got "{mfa}"')
    cognito_plan = str(ctx("cognitoPlan", "essentials")).strip().lower()
    if cognito_plan not in {"essentials", "plus"}:
        raise ValueError(f'cognitoPlan must be "essentials" or "plus", got "{cognito_plan}"')

    app_name = str(ctx("appName", DEFAULT_APP_NAME)).strip().lower()
    if not _APP_NAME.match(app_name):
        raise ValueError(
            f"appName must be 2 to 12 lowercase letters or digits, starting with a letter, "
            f"got {app_name!r}"
        )

    agent_registry = _as_bool(ctx("agentRegistry", False))
    # The latency flags are on by default (2026-11-03 A/B, see docs/evaluation.md). Each flag
    # that depends on another defaults to its parent, so turning a parent off needs one flag,
    # and agentRegistry=true falls back to the Harness path unless directOrchestration is set.
    direct_orchestration = _as_bool(ctx("directOrchestration", not agent_registry))
    if direct_orchestration and agent_registry:
        # The registry lookup is a step of the Harness prompt; direct orchestration has none.
        raise ValueError("directOrchestration=true cannot be combined with agentRegistry=true")
    unanimous_fast_path = _as_bool(ctx("unanimousFastPath", direct_orchestration))
    direct_specialists = _as_bool(ctx("directSpecialists", direct_orchestration))
    for flag, on in (
        ("unanimousFastPath", unanimous_fast_path),
        ("directSpecialists", direct_specialists),
    ):
        if on and not direct_orchestration:
            # Both act on the worker's direct path; the Harness path has neither step.
            raise ValueError(f"{flag}=true needs directOrchestration=true")
    direct_tools = _as_bool(ctx("directTools", True))
    split_tools_runtimes = _as_bool(ctx("splitToolsRuntimes", direct_tools))
    if split_tools_runtimes and not direct_tools:
        # Through the tools Gateway every capture reaches the one Gateway target.
        raise ValueError("splitToolsRuntimes=true needs directTools=true")

    return AppConfig(
        # Neutral default so a customer's Cost Explorer never shows the sample author; the
        # OwnerTag stack output reminds the deployer to pass -c owner=<team or alias>.
        owner=str(ctx("owner", DEFAULT_OWNER)),
        environment=str(ctx("environment", "dev")),
        sign_up_mode=sign_up_mode,
        invite_code=invite_code,
        allowed_email_domains=normalize_domains(ctx("allowedEmailDomains", "")),
        retention_days=_as_int(ctx("retentionDays", 90), "retentionDays", 1, 3650),
        # SQS event source maximumConcurrency accepts 2 to 1000.
        scan_concurrency=_as_int(ctx("scanConcurrency", 25), "scanConcurrency", 2, 1000),
        orchestrator_model=str(ctx("orchestratorModel", DEFAULT_ORCHESTRATOR_MODEL)),
        specialist_model=str(ctx("specialistModel", DEFAULT_SPECIALIST_MODEL)),
        harness_max_tokens=_as_int(
            ctx("harnessMaxTokens", DEFAULT_HARNESS_MAX_TOKENS),
            "harnessMaxTokens",
            HARNESS_MAX_TOKENS_FLOOR,
            None,
        ),
        skip_asset_build=_as_bool(ctx("skipAssetBuild", False)),
        orchestrator_effort=effort,
        orchestrator_prompt_cache=_as_bool(ctx("orchestratorPromptCache", True)),
        ses_from_address=_ses_from_address(ctx("sesFromAddress", "")),
        mfa=mfa,
        cognito_plan=cognito_plan,
        episodic_memory=_as_bool(ctx("episodicMemory", True)),
        **_custom_domain(ctx("domainName", ""), ctx("certificateArn", "")),
        web_search=_as_bool(ctx("webSearch", True)),
        rdap_cache_ttl_hours=_as_int(ctx("rdapCacheTtlHours", 168), "rdapCacheTtlHours", 1, 8760),
        web_search_cache_ttl_hours=_as_int(
            ctx("webSearchCacheTtlHours", 24), "webSearchCacheTtlHours", 1, 8760
        ),
        browser_signing=_as_bool(ctx("browserSigning", False)),
        app_name=app_name,
        agent_registry=agent_registry,
        capture_recovery=_as_bool(ctx("captureRecovery", True)),
        capture_block_retry=_as_bool(ctx("captureBlockRetry", False)),
        direct_orchestration=direct_orchestration,
        local_rdap=_as_bool(ctx("localRdap", True)),
        unanimous_fast_path=unanimous_fast_path,
        direct_specialists=direct_specialists,
        direct_tools=direct_tools,
        split_tools_runtimes=split_tools_runtimes,
        latency_budgets=_as_bool(ctx("latencyBudgets", True)),
        code_text_budget=_choice(
            ctx("codeTextBudget", "half"), "codeTextBudget", CODE_TEXT_BUDGETS
        ),
        code_model_view=_choice(ctx("codeModelView", "compact"), "codeModelView", CODE_MODEL_VIEWS),
        scan_dedup=_as_bool(ctx("scanDedup", False)),
    )


def _custom_domain(domain: object, certificate: object) -> dict[str, str | None]:
    name = str(domain or "").strip().lower().rstrip(".")
    arn = str(certificate or "").strip()
    if not name and not arn:
        return {"domain_name": None, "certificate_arn": None}
    if not (name and arn):
        raise ValueError("domainName and certificateArn must be set together (or neither)")
    if not _DOMAIN.match(name):
        raise ValueError(f"domainName: {domain!r} is not a domain name")
    if not _CLOUDFRONT_CERT.match(arn):
        raise ValueError(
            f"certificateArn must be an ACM certificate ARN in us-east-1 (CloudFront), got {arn!r}"
        )
    return {"domain_name": name, "certificate_arn": arn}


def _ses_from_address(value: object) -> str | None:
    address = str(value or "").strip()
    if not address:
        return None
    if not _EMAIL.match(address):
        raise ValueError(f"sesFromAddress must be an SES-verified email address, got {address!r}")
    return address
