# Deploy

You can deploy this sample into your own AWS account, in any Region where Amazon Bedrock AgentCore and the two Claude models are available. Deploying takes about 8 minutes the first time and about 4 minutes for an update (measured in our test account, see [3. Deploy](#3-deploy-about-8-minutes)). Everything below runs against the account and Region your AWS credentials point at, so check them first.

**On this page:** [Prerequisites](#prerequisites) · [1. Check your account](#1-choose-a-region-and-check-your-account-2-minutes) · [2. Bootstrap](#2-bootstrap-cdk-in-both-regions-one-time) · [3. Deploy](#3-deploy-about-8-minutes) · [Options](#options) · [Sign-in and MFA](#sign-in-and-mfa) · [Custom domain](#custom-domain) · [Verify](#verify) · [Clean up](#clean-up) · [Troubleshooting](#troubleshooting)

## Prerequisites

| You need                           | Why                                                                                                                                                                                            | Check                               |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| Credentials for your AWS account   | Every command creates resources in that account                                                                                                                                                | `aws sts get-caller-identity`       |
| Node.js 22                         | Runs the AWS CDK CLI and builds the web app                                                                                                                                                    | `node --version`                    |
| Python 3.13 and uv                 | The CDK app, Lambdas and agents are Python                                                                                                                                                     | `uv --version`                      |
| Docker or Finch, with ARM64 builds | Builds the agent container images                                                                                                                                                              | `docker version` or `finch version` |
| Amazon Bedrock model access        | Claude Opus 5.5 (orchestrator) and Claude Sonnet 5.5 (specialists) in your Region. Request it in the Amazon Bedrock console under **Model access**                                             | `scripts/preflight.py` (step 1)     |
| A supported Region                 | AgentCore Harness, Runtime, Gateway and Browser must all be available. See [AgentCore supported Regions](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-regions.html) | `scripts/preflight.py` (step 1)     |
| CDK bootstrap                      | In your Region and in `us-east-1`                                                                                                                                                              | `scripts/preflight.py` (step 1)     |

## 1. Choose a Region and check your account (2 minutes)

```bash
git clone https://github.com/aws-samples/sample-agentic-phishing-detection.git
cd sample-agentic-phishing-detection
uv sync --all-packages
export AWS_REGION=<your-region>
uv run python scripts/preflight.py --profile <your-profile> --region "$AWS_REGION"
```

Add `--agent-registry` if you will deploy with `-c agentRegistry=true`; it also checks that AWS Agent Registry answers in your Region.

The preflight script checks, in your account:

- Both inference profiles are `AUTHORIZED` for you.
- The AgentCore control plane answers in your Region.
- The CDK bootstrap stack `CDKToolkit` exists in your Region and in `us-east-1`.
- A container runtime (`docker` or `finch`) is on your `PATH`.
- Node.js 22 is installed.

Every failed check prints one line that tells you how to fix it.

## 2. Bootstrap CDK in both Regions (one time)

```bash
npx aws-cdk@2.1143.0 bootstrap aws://<account-id>/$AWS_REGION aws://<account-id>/us-east-1
```

The application deploys to your Region (`AWS_REGION`). Only the `PhishTriageAgenticEdge` stack, which holds the AWS WAF web ACL for CloudFront, deploys to `us-east-1`, because AWS requires web ACLs for CloudFront to be created there. CDK deploys only to bootstrapped Regions, so bootstrap both once per account. If your Region is `us-east-1`, one bootstrap covers both.

## 3. Deploy (about 8 minutes)

```bash
cd infra
export CDK_DOCKER=docker   # or finch
npx aws-cdk@2.1143.0 deploy --all -c owner=<team or alias>
```

Set `owner` to your team or alias. Without it every resource is tagged `Owner=phish-triage-owner`, and nobody can tell from Cost Explorer who is paying. This creates two stacks: `PhishTriageAgenticEdge` in `us-east-1` (the web ACL and, with the default `-c webSearch=true`, the AgentCore Web Search Gateway; in a Region that offers Web Search, that target moves to the regional tools Gateway and the edge stack has no Gateway) and `PhishTriageAgentic` in your Region (everything else).

Measured durations, from our test account in `us-west-2` on 2026-09-30 with Finch on an Apple silicon laptop: creating `PhishTriageAgentic` took 476 s (about 8 minutes), and in-place updates took 220 s and 238 s. These are per-stack times for `PhishTriageAgentic` only. Updating a stack deployed before the scans table had its `status-queued_at` index adds that index in place (the table is not replaced); DynamoDB backfills it from the stored scans before that update finishes, so that one update takes longer on a table with many stored scans. A timed first `deploy --all` of a second copy (`-c appName=verify`, same account, laptop and Region, 2026-10-15) took 540 s end to end, including both stacks and the container image builds, and its first scans answered at once. Your times depend on your network and container runtime.

## Options

Pass options with `-c name=value` on the deploy command.

| Option | Default | Change it when |
| --- | --- | --- |
| `owner` | `phish-triage-owner` | Always set it: every resource gets an `Owner` tag with this value, so cost shows up against your team in Cost Explorer. `-c owner=<team or alias>`. The `OwnerTag` stack output echoes the value |
| `environment` | `dev` | Sets the `Environment` tag and the suffix of table, queue and function names. `prod` switches the removal policy from destroy to retain |
| `appName` | `phish` | You deploy a second copy into an account and Region that already has one: `-c appName=demo2` prefixes every named resource and renames the stacks to `Demo2TriageAgentic` and `Demo2TriageAgenticEdge`. 2 to 12 lowercase letters or digits, starting with a letter. Pass the same value to every later deploy and destroy of that copy |
| `signUpMode` | `app` | You want native Cognito self sign-up with email verification: `-c signUpMode=cognito` |
| `inviteCode` | `false` | You want an invite code on the Register page: `-c inviteCode=true` (app mode only) |
| `allowedEmailDomains` | empty (anyone) | Only some email domains may register: `-c allowedEmailDomains=example.com` |
| `sesFromAddress` | empty (Cognito default email, 50 per day) | Send sign-up email through Amazon SES: `-c sesFromAddress=<SES-verified address>` |
| `mfa` | `optional` | Users are offered an authenticator app (TOTP, never SMS) and may skip it. `-c mfa=required` makes every user enrol one at first sign-in |
| `cognitoPlan` | `essentials` | You want Cognito threat protection (compromised credentials, adaptive authentication) enforced: `-c cognitoPlan=plus`. The Plus plan is billed per monthly active user and has no free tier |
| `domainName`, `certificateArn` | unset | You want your own console domain. Pass both: `-c domainName=phish.example.com -c certificateArn=<ACM certificate ARN in us-east-1>`. See [Custom domain](#custom-domain) |
| `retentionDays` | `90` | Keep scans for a different time (1 to 3650): `-c retentionDays=30` |
| `orchestratorModel` | `us.anthropic.claude-opus-5-5` | You want another orchestrator model or inference profile |
| `specialistModel` | `global.anthropic.claude-sonnet-5-5` | You want another model, or to keep specialist traffic in the US: `-c specialistModel=<id>` |
| `harnessMaxTokens` | `8192` (at least `4096`) | Longer reports get cut off |
| `episodicMemory` | `true` | One Amazon Bedrock AgentCore Memory per deployment keeps a one-line summary of every completed scan (defanged URL, verdict, risk, reason). Before each scan the worker retrieves up to 3 similar summaries and passes them to the orchestrator labelled as context, not evidence. Summaries are shared within the deployment as model context, but the result page lists only the user's own matching scans. A failed memory read or write never fails a scan. `-c episodicMemory=false` removes the memory and its permissions |
| `orchestratorEffort` | `medium` (shipped in `cdk.json`) | `output_config.effort` sent with each orchestrator call. Opus 5.5 always thinks, so effort is the only way to shorten its reasoning. `medium` is the default because `low` broke the verdict JSON in 2 of 5 scans when the orchestrator called the specialists itself (2026-10-16, before the dispatcher); `medium` was valid 5 of 5 and about 2.3 s slower. Passed to the Harness inside `additionalModelRequestFields.output_config.effort` (verified live on Opus 5.5). Check verdict quality with scans on a test stack after changing it: `eval/evaluate_agents.py` calls the Harness without the worker's effort setting, so it cannot measure this flag. Override with `-c orchestratorEffort=low` (or `high`), or `-c orchestratorEffort=` to send nothing and keep the model default (`medium` on Opus 5.5) |
| `orchestratorPromptCache` | `true` | Bedrock prompt caching on the orchestrator. The Harness resource has no caching setting, so the worker sends Anthropic's top-level `cache_control` (`{"type": "ephemeral"}`) inside `additionalModelRequestFields` on every `InvokeHarness` call. Each later model call in a scan (after the dispatcher returns, and the report turn) then reads the earlier prompt back at the cache-read price instead of the full input price. `-c orchestratorPromptCache=false` sends no cache hint |
| `agentRegistry` | `false` (shipped in `cdk.json`) | `-c agentRegistry=true` adds AWS Agent Registry (part of Amazon Bedrock AgentCore) with five auto-approved MCP records (the dispatcher, the three specialists and the tools server), a `registry` target on the `phish-specialists` Gateway (its role may search that one registry only), and a lookup step at the start of the orchestrator prompt. The lookup is informational: round one is still one `dispatcher___analyze_all` call, and the second round may use only a specialist tool whose record the search returned. Offered in `us-west-2` and `us-east-1`; elsewhere synth warns and deploys no registry and no lookup step. Off: no registry resources, target, IAM or prompt step. Every deployment has the [dispatcher](agents/dispatcher.md), the shared tools server behind the `phish-tools` Gateway, the pre-check with its Error 404 and Site down fast paths, and the result cache. The old `specialistMode` flag was removed: any `-c specialistMode=...` fails synth with a message pointing here (`registry` is now `-c agentRegistry=true`; `direct` no longer exists). Latency of this design before orchestrator prompt caching (2026-10-21, test stack): median 24.5 s and 35.0 s to the verdict for one scan on an idle stack, p50 42.5 s and p95 77.8 s to the verdict in a 50-URL batch; with caching (2026-10-24 and 2026-10-25): median 33.1 s and 33.9 s for one scan, p50 48.5 s in the same batch on a loaded machine; earlier designs are in [evaluation.md](evaluation.md#latency-history) |
| `scanConcurrency` | `25` | You have higher or lower Bedrock quotas (2 to 1000), or want a different trade-off between batch throughput and per-scan tail latency. More scans at once finish a batch sooner but slow each scan: in our test account (2026-09-29, the earlier Lambda fan-out design) the orchestrator overhead p95 was 29 s with 5 or fewer scans in flight and 82 s with 16 to 30. For example, `-c scanConcurrency=10` favors single-scan latency |
| `lambdaWebAdapterAccount`, `lambdaWebAdapterVersion` | per-Region lookup | The AWS Lambda Web Adapter layer is not published for your Region under the default account or version |
| `rdapCacheTtlHours` | `168` (7 days; 1 to 8760) | How long an RDAP lookup is cached per registered domain in the `phish-cache-{env}` DynamoDB table. Registration data changes rarely. A lookup that fails or is empty is never cached |
| `webSearchCacheTtlHours` | `24` (1 to 8760) | How long a brand's web search result is cached. Deliberately short: a poisoned search result ages out within a day, see [security.md](security.md#network). Raise it only if you accept that exposure |
| `webSearch` | `true` | `brand_visual` gets AgentCore Web Search to confirm a brand's official website, through a small AgentCore Gateway in the `us-east-1` edge stack, or, when the regional stack is in a Region that offers Web Search (`us-east-1`, `eu-west-1`, `ap-northeast-1`), through a target on the regional tools Gateway (at most 2 queries per URL; the [README cost estimate](../README.md#what-it-costs) assumes $7 per 1,000 queries, and prices can change, so check the [Amazon Bedrock AgentCore pricing page](https://aws.amazon.com/bedrock/agentcore/pricing/)). `-c webSearch=false` removes the Gateway (or target) and the tool; the specialist then works as before |
| `browserSigning` | `false` | When `true`: one custom AgentCore Browser, `phish_signed_browser`, with Web Bot Auth request signing (preview) and public network mode. The one runtime that opens a browser, `tools_server`, gets its id as `BROWSER_ID`, and its browser IAM statement names that browser's ARN only. Sites behind AWS WAF, Cloudflare, HUMAN or Akamai bot checks that accept verified bots then let the capture through instead of a CAPTCHA. Its execution role has no permissions and recording is off. Signing only identifies the browser: capture stays passive, so a bot check that is still shown is recorded as `bot_challenge`, not solved. Off by default: in a 2026-10-11 test the signed browser added 1 to 4 s per page load, and no bot check turned up in 28 live URLs to show its benefit. On 2026-10-26, 30 public-feed URLs behind a Cloudflare "Suspected Phishing" or "Suspected Malware" warning ended exactly as on the default browser: 0 of 30 got past the warning (25 proceed buttons stayed behind Turnstile, 5 warnings had none), so signing did not help with these warnings. The default is the AWS-managed `aws.browser.v1` |
| `directOrchestration` | `true` (`false` with `agentRegistry=true`) | On by default since the 2026-11-03 A/B ([evaluation.md](evaluation.md#latency-flags-on-by-default-2026-11-03)): takes the AgentCore Harness out of the scan path: the worker starts the dispatcher itself, at the same time as the pre-check, and then asks the orchestrator model for the verdict and for the report with two Bedrock Converse calls (same prompt rules, effort and prompt caching; episodic memory and the output guardrail still apply). It saves the Harness planning turn and its cold start. What you give up: the optional second round in which the orchestrator re-runs one specialist, and the Harness trace in AgentCore observability. The worker role gains `InvokeAgentRuntime` on the dispatcher runtime and `InvokeModel` on the orchestrator model. A URL the pre-check finds dead (Error 404, Site down) still pays for the specialists, which already started. Cannot be combined with `-c agentRegistry=true`: with the registry on it defaults to `false`, and an explicit `true` fails synth. `-c directOrchestration=false` brings back the Harness path and turns `unanimousFastPath` and `directSpecialists` off with it |
| `localRdap` | `true` | `url_analyst` runs its RDAP lookup in its own process (the same SSRF-guarded client and result cache) instead of through the tools runtime, which saves one tools-runtime session per scan. `-c localRdap=false` sends it through the tools runtime. No IAM change |
| `captureRecovery` | `true` | On by default since the 2026-11-02 A/B (see [evaluation.md](evaluation.md#capture-compact-view-and-latency-flags-2026-11-02)): the stack sets `CAPTURE_RECOVERY=1` on every agent Runtime and turns on four capture fixes: an Amazon S3 website endpoint (`*.s3-website*.amazonaws.com`, which has no TLS listener) is opened over `http`; a certificate error (self-signed, unknown CA, wrong host name, expired) gets one retry in a browser context that ignores certificate checks, adds the low `tls_certificate_error` signal, and the verdict can then never be `legitimate` or `allow` (a would-be legitimate becomes `unknown` and `warn` with an "Untrusted certificate" note); a URL that answers with a download is fingerprinted (SHA-256, size, type and a sanitised file name, 10 MiB cap) with one pinned GET and never opened, with a `download_response` signal; and a transient DNS failure is retried once after 250 ms and reported as `dns_transient_error` instead of failing the capture. `-c captureRecovery=false` leaves the variable unset and keeps the earlier behaviour. `page_state` on findings and `verdict.verdict_detail` (taken down, parked, S3 access denied) are recorded either way: they never change the verdict |
| `codeModelView` | `compact` | The default since the 2026-11-02 A/B: `code_analyst`'s model gets a ranked, size-budgeted extract of the page capture instead of the whole capture: every form, iframe, redirect, listener, data sink, derived signal and non-GET, XHR, fetch, WebSocket, beacon or document request stays verbatim, requests are summarised per host, vendor library and analytics bundles (recognised by the host that serves them, never by a banner in the page) are named but not shown, other scripts are shown whole or as excerpts around security-relevant code, and the DOM drops styles, SVG and comments. The budget is about 15,000 tokens (`CODE_MODEL_VIEW_TOKENS` on the Runtime, 2,000 to 30,000). The heuristics still run on the full capture, and a guardrail retry still sends the full sanitized view. `-c codeModelView=full` sends the whole capture, as before; see [evaluation.md](evaluation.md#capture-compact-view-and-latency-flags-2026-11-02) |
| `unanimousFastPath` | same as `directOrchestration` | Needs direct orchestration; `-c unanimousFastPath=false` turns it off alone. When all three specialists answer `legitimate` at confidence 80 or more, no capture reports the page unobserved (at least one saw it), no specialist errored and nothing above medium was raised, the worker stores `legitimate`, risk 5, `allow` without the verdict turn. The page-not-observed and untrusted-certificate caps still run, and the report is still written by the orchestrator model from the stored verdict and findings, with its notes and disclaimer. Every other outcome, including any disagreement, still goes to the model. Saves one orchestrator turn (3 to 4 s) on clean legitimate pages. Ported from a fork of this sample |
| `directSpecialists` | same as `directOrchestration` | Needs direct orchestration; `-c directSpecialists=false` keeps the dispatcher hop. The worker invokes the three specialist Runtimes itself, concurrently, instead of through the dispatcher: one Runtime hop and one session start less. Each specialist keeps its own deadline and still writes its own Finding; a specialist that fails writes nothing and becomes an error Finding when the worker reads the findings back (the dispatcher's own error Finding, with its reason, is lost). The worker role gains `InvokeAgentRuntime` on the three specialist Runtimes and their endpoints, never on a tools Runtime. The dispatcher and the specialists Gateway stay deployed for the Harness path |
| `directTools` | `true` | `brand_visual` and `code_analyst` call the tools Runtime with `InvokeAgentRuntime` instead of through the tools Gateway, on one tools session per scan that the worker's pre-check opens (`TOOLS_SESSION_PER_SCAN=1`), and `url_analyst` runs RDAP in process (as `-c localRdap=true`). Each of the two capturing specialists gains `InvokeAgentRuntime` on the tools Runtime and its endpoints. The tools Gateway stays deployed. `-c directTools=false` routes the captures through the Gateway again and turns `splitToolsRuntimes` off with it |
| `splitToolsRuntimes` | same as `directTools` | Needs direct tools; `-c splitToolsRuntimes=false` keeps one tools Runtime. Two more copies of the tools Runtime (`<appName>_tools_brand`, `<appName>_tools_code`, same image and role grants as the tools server), one per capturing specialist, so a scan's pre-check and two captures draw on three Runtimes' session start capacity instead of one under load. Each specialist can invoke only its own copy |
| `latencyBudgets` | `true` | Sets `LATENCY_BUDGETS=1` on every agent Runtime: `code_analyst`'s capture budget 18 s instead of 20 s (raw HTML fallback 3 s instead of 4 s, network-idle settle 1.5 s instead of 2.5 s, tools server backstop 20 s instead of 22 s); `brand_visual`'s screenshot at least 1.5 s and up to 5 s of unused budget, and a screenshot that fails after the page loaded keeps the page (the model is told the appearance is unknown, not benign); capture client timeouts 28 s and 30 s instead of 22 s and 25 s, with one retry of a direct tools Runtime call that failed fast; the two page specialists' deadline 42 s instead of 35 s and the dispatcher's read timeout 52 s instead of 45 s, so a model turn still fits after the longest capture wait. Sized for the tools Runtime's session start lag; worst-case scan time grows when captures are slow. `-c latencyBudgets=false` keeps the earlier budgets |
| `codeTextBudget` | `half` | `half` keeps 10 KB per script, 30 KB of script text in total and 12 KB of rendered DOM in `code_analyst`'s capture (15, 60 and 20 KB otherwise), which shortens its final model turn. The heuristics see the same, smaller capture; `-c codeTextBudget=full` keeps the larger one. `brand_visual`'s page text limit is unchanged |
| `scanDedup` | `false` | `-c scanDedup=true` sets `SCAN_DEDUP_ENABLED=1` on the API Lambda: `POST /scan` from a direct API caller returns the caller's own `PENDING` or `RUNNING` scan of the same normalised URL, or one `COMPLETE` within 24 hours, with `"deduplicated": true` instead of scanning again (`"force": true` bypasses it, FAILED scans are never reused). The web console is never deduplicated. The `dedup-queued_at` index on the scans table and `GET /scans/lookup` exist either way; on an existing deployment the index backfills after the update and lookup answers not-found until it is active. See [api.md](api.md#reuse-a-recent-scan-lookup-and-dedup) |
| `skipAssetBuild` | `false` | Synth without building container images or Lambda bundles, for lint and CI: `-c skipAssetBuild=true`. Never deploy with it |

> **The latency flags are on by default.** Since the 2026-11-03 A/B ([evaluation.md](evaluation.md#latency-flags-on-by-default-2026-11-03)) a default deploy runs `directOrchestration`, `localRdap`, `unanimousFastPath`, `directSpecialists`, `directTools`, `splitToolsRuntimes`, `latencyBudgets` and `codeTextBudget=half`. For the AgentCore Harness path, with its optional second round and Harness trace, deploy with `-c directOrchestration=false`; `-c agentRegistry=true` selects it on its own. To deploy the layout of before that date: `-c directOrchestration=false -c localRdap=false -c directTools=false -c latencyBudgets=false -c codeTextBudget=full` (the two worker flags and `splitToolsRuntimes` follow their parents).

> [!NOTE]
> **Agent Registry is off by default.** The default deploy has no registry, no `registry` Gateway target, no registry permissions and no lookup step in the orchestrator prompt. `-c agentRegistry=true` adds all four (in `us-west-2` and `us-east-1` only); scans work the same either way, because the lookup never routes a call. See [architecture.md](architecture.md#agent-registry-opt-in).

**Prompt caching.** The specialists use Bedrock prompt caching, on by default (the agent code reads the environment variable `PHISH_PROMPT_CACHE`; the stack does not set it, and setting it to `0` on a specialist runtime turns caching off). url_analyst and brand_visual cache the tools, the system prompt and the last message; code_analyst caches only the tools and the system prompt, because its last message is the captured page code, which its final answer never reads back. The orchestrator is cached through `orchestratorPromptCache` (above): the AgentCore Harness has no cache point field (its system prompt blocks take text only), but it passes `additionalModelRequestFields` to the model, and Opus 5.5 on Bedrock accepts a top-level `cache_control` there. A one-off call would only pay the cache write premium (1.25 times the input price); every model-backed scan makes at least two orchestrator model calls, so the second reads the first back. Check `cache_read_tokens` on the `orchestrator` call of a scan (`GET /scans/{id}`) after a deploy.

**Harness limits are per call.** `max_iterations` (8) and `timeout_seconds` (240) apply to one `InvokeHarness` call. A second turn on the same session, such as the report turn that follows the verdict, gets its own budget, and the 240 s ceiling stays under the 300 s worker timeout. The worker owns the overall deadline.

Sign-up works through the app by default (`signUpMode=app`): you enter your email on the Register page, Cognito emails a temporary password, and your first sign-in sets a new one. If you prefer Cognito's own sign-up flow with email verification, deploy with `-c signUpMode=cognito`. Cognito's default email sender allows 50 emails per day per account. For real use, deploy with `-c sesFromAddress=<address>`, an address verified in Amazon SES in your Region (and out of the SES sandbox).

## Sign-in and MFA

Users sign in with Cognito managed login. By default (`-c mfa=optional`) the first sign-in offers an authenticator app (TOTP) and the user may skip it. Deploy with `-c mfa=required` to make every user enrol an authenticator at first sign-in. SMS is never used. With `-c cognitoPlan=plus` the user pool also enforces Cognito threat protection, which is billed per monthly active user.

## Register rate limit

The edge web ACL allows 10 `POST /auth/register` requests per 5 minutes from one IP address. Past that, AWS WAF answers `429` with `{"error":"too_many_registrations"}` and the Register page says "Too many sign-up attempts from your network, try again in a few minutes". Behind the WAF, the web tier allows 5 registrations per client IP per 15 minutes in each running function instance and answers `429` the same way. Both limits protect the Cognito email quota. People behind one NAT address share them, so a workshop room that signs up together should wait a few minutes between groups or use `-c signUpMode=cognito`. Every other route has the general limit of 3,000 requests per 5 minutes per IP.

## Custom domain

By default the console is served on its `*.cloudfront.net` name, and CloudFront ignores the minimum TLS version with that certificate. To use your own domain:

1. Request or import an ACM certificate for the name in `us-east-1` (CloudFront reads certificates only from there).
2. Deploy with `-c domainName=<name> -c certificateArn=<certificate ARN>`. Pass both or neither. The distribution then requires TLS 1.2 (`TLSv1.2_2021`), and `WebUrl` becomes `https://<name>`.
3. Create a CNAME (or a Route 53 alias) from the name to the `DistributionDomainName` stack output.

## Verify

1. Open the `WebUrl` stack output in a browser.
2. Register with your email, open the email from Cognito, and sign in with the temporary password. Choose a new password when asked.
3. Scan `https://example.com`. You should get **legitimate**, and the report panel shows a progress note until the full report is ready.

## Clean up

```bash
cd infra
npx aws-cdk@2.1143.0 destroy --all
# a second copy deployed with -c appName=<name>: pass the same flag
npx aws-cdk@2.1143.0 destroy --all -c appName=<name>
```

This deletes both stacks and their data: tables, buckets, the user pool (and every user in it), agents and keys. That holds for the default `-c environment=dev`. A stack deployed with `-c environment=prod` uses the `RETAIN` removal policy, so `destroy` removes the stacks but leaves the KMS key, DynamoDB tables, S3 buckets and their objects, SQS queues, log groups, the Cognito user pool (with deletion protection on), AgentCore Memory, the Harness, Runtimes and Gateways, all with their data. Pass the same `-c environment=prod` to `destroy`. To remove what is retained, list it with the tag check below (add `Key=Environment,Values=prod`), turn off deletion protection on the user pool, empty and delete the buckets, delete the tables, queues, log groups and AgentCore resources, and schedule the KMS key for deletion last, because the other stores are encrypted with it. A few things stay behind in every environment:

| Left behind                                  | How to remove it                                                                                                            |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| The orchestrator harness log group           | AgentCore creates it on the first scan, under `/aws/bedrock-agentcore/` with `phish_orchestrator` in its name, with no retention. Delete it, or set a retention after the first scan with `aws logs put-retention-policy` |
| The orchestrator's former managed memory     | Only on a stack first deployed before 2026-10-16: the harness ran with managed memory then (`<appName>_orchestrator-*` in AgentCore Memory). An update turns it off and detaches it but does not delete it or its records; delete it in the AgentCore console or with `aws bedrock-agentcore-control delete-memory` |
| CDK bootstrap stacks (`CDKToolkit`)          | Keep them if you use CDK elsewhere. Otherwise delete the stack in both Regions, then its staging bucket                     |
| Container images in the CDK asset repository | Removed with the bootstrap stack, or delete the images in Amazon ECR                                                        |

Confirm nothing tagged for this sample is left:

```bash
aws resourcegroupstaggingapi get-resources --tag-filters Key=Project,Values=phish-triage --region "$AWS_REGION"
aws resourcegroupstaggingapi get-resources --tag-filters Key=Project,Values=phish-triage --region us-east-1
```

## Troubleshooting

| Symptom                                          | Likely cause                                  | Fix                                                                        |
| ------------------------------------------------ | --------------------------------------------- | -------------------------------------------------------------------------- |
| `AccessDeniedException` on a model               | No model access in this Region                | Request access to both models in the Bedrock console, then rerun preflight |
| `Cannot connect to the Docker daemon`            | Docker or Finch is not running                | Start it (`finch vm start`), set `CDK_DOCKER` to match                     |
| Image build fails with `exec format error`       | ARM64 emulation missing on an x86 machine     | Enable ARM64 emulation in Docker or Finch                                  |
| `PhishTriageAgenticEdge` fails: not bootstrapped | No CDK bootstrap in `us-east-1`               | Run step 2 for `us-east-1`                                                 |
| AgentCore resource type not supported            | AgentCore is not in this Region               | Pick a supported Region and redeploy                                       |
| AgentCore or Bedrock quota errors                | Account limits (sessions, tokens per minute)  | Lower `-c scanConcurrency`, or request a quota increase                    |
| A scan shows FAILED                              | A step failed 3 times in a row                | Read the reason on the scan, then press **Retry**                          |
| HTTP 429 in the app or API                       | Throttling                                    | The app retries on its own. API callers retry with backoff                 |
| Stack stuck in `DELETE_FAILED`                   | A resource was changed outside CloudFormation | Read the stack events, remove the named resource, run destroy again        |
