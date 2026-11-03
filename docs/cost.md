# Cost

What the sample costs to run in your account: a small fixed amount while it sits idle, plus a per-scan amount that is mostly model tokens. Every figure on this page is either measured on a test stack (and says when) or an estimate built from measured usage and AWS list prices (and says so).

**On this page:** [Summary](#summary) · [Per scan, current default](#per-scan-current-default) · [By service](#by-service) · [Monthly examples](#monthly-examples) · [How the service estimates were made](#how-the-service-estimates-were-made) · [Track your own spend](#track-your-own-spend)

## Summary

| Item | Amount | Basis |
| --- | --- | --- |
| Idle stacks, per month | About $14 to $15 | Estimate; Cost Explorer agreed for the tagged stacks over 2026-10-15 to 2026-10-18. Mostly the AWS WAF web ACL ($11) and two KMS keys ($2) |
| Model tokens per model-backed scan, current default | $0.090 mean | Measured 2026-11-03, 407 live URLs, `cost_usd` per scan ([evaluation.md](evaluation.md#latency-flags-on-by-default-2026-11-03)) |
| Other services per scan | About $0.015 | Estimate from the 2026-10-19 usage measurement on the earlier Harness path; not re-measured on the current default |
| Dead link (HTTP 404, Site down) | No orchestrator call | On the default path the specialists start with the pre-check and still bill their tokens, although the scan's `cost_usd` is `0` ([architecture.md](architecture.md#fast-paths-error-404-and-site-down)) |

## Per scan, current default

Measured on 2026-11-03 on a test stack in `us-west-2`, 448 URLs submitted at once (224 from a public phishing feed, 224 legitimate pages), 407 live, episodic memory off, `scanConcurrency` 25:

| Configuration | Model cost per scan, mean | Scan time, median / p90 |
| --- | --- | --- |
| Current default (all latency flags on) | **$0.090** | **18.6 s / 31.2 s** |
| Previous default (2026-11-02) | $0.134 | 37.8 s / 71.9 s |

Earlier measurements (2026-10-18 to 2026-11-02) are in [evaluation.md](evaluation.md#cost-history). Long pages cost more than short ones; `cost_usd` on each scan record has the exact figure.

## By service

This breakdown was measured on 2026-10-25 on the default of that date (the AgentCore Harness path with the dispatcher, orchestrator prompt caching on, `codeModelView=full`, `captureRecovery=false`), on 43 model-backed scans of a 50-URL batch. It is kept because it is the most recent full per-service measurement. Token rows are measured; the rest are estimates from measured usage. The current default's tokens are lower ($0.090 per scan instead of $0.153, above).

| Service                                                | What drives cost                                                              | Idle per month                     | Per 100 URLs     | Basis                           |
| ------------------------------------------------------ | ----------------------------------------------------------------------------- | ---------------------------------- | ---------------- | ------------------------------- |
| Amazon Bedrock, Claude Opus 5.5                        | Orchestrator tokens: verdict turn and report turn, with prompt caching       | $0                                 | $8.54            | Measured                        |
| Amazon Bedrock, Claude Sonnet 5.5                      | Specialist tokens, 3 per URL, with prompt caching                             | $0                                 | $6.72            | Measured                        |
| AgentCore Harness and Runtime                          | Active vCPU and memory: orchestrator, dispatcher, 3 specialists, tools server | $0                                 | $0.80 to $1.05   | Estimate from measured usage    |
| AgentCore Browser                                      | The pre-check and two page captures                                           | $0                                 | $0.05 to $0.07   | Estimate from measured usage    |
| AgentCore Gateway                                      | About 7 calls per URL across both Gateways                                    | Under $0.01                        | $0.01            | Estimate                        |
| AgentCore Memory                                       | 1 event and about 1 retrieval per URL; records kept                           | About $0.0005 per stored scan      | $0.06 to $0.15   | Estimate                        |
| AgentCore Web Search                                   | 0 to 2 searches per URL (0.18 measured), $7 per 1,000                         | $0                                 | $0.13            | Estimate from measured count    |
| Amazon Bedrock Guardrails                              | URL input check, report output check                                          | $0                                 | $0.08            | Estimate                        |
| AWS Lambda                                             | Worker time while it waits on the agents, API, stats, sweeper                 | About $0.03                        | $0.06            | Estimate from measured duration |
| Amazon DynamoDB                                        | On-demand reads and writes; the sweeper queries a status index                | Under $0.01                        | $0.01 to $0.02   | Estimate from measured units    |
| Amazon S3                                              | 5 objects per scan, about 100 KB                                              | Under $0.10                        | Under $0.01      | Estimate                        |
| Amazon SQS                                             | Messages and idle Lambda polling                                              | About $0.36                        | Under $0.01      | Estimate from measured requests |
| API Gateway, CloudFront, Cognito                       | Requests; Cognito is free under 10,000 monthly active users                   | $0                                 | About $0.02      | Estimate                        |
| AWS WAF                                                | 1 web ACL and 6 rules                                                         | $11.00                             | Under $0.01      | Estimate, Cost Explorer agrees  |
| AWS KMS                                                | 2 customer managed keys                                                       | $2.00                              | Under $0.01      | Estimate, Cost Explorer agrees  |
| Amazon CloudWatch                                      | 10 alarms, logs, custom metrics                                               | $1.00 (up to $7 with hourly scans) | $0.02 to $0.05   | Estimate from measured bytes    |
| Amazon ECR and data transfer                           | Agent container images, regional transfer                                     | $0.10 to $1.00                     | About $0.02      | Estimate                        |
| **Total**                                              |                                                                               | **About $14 to $15**               | **About $16.75** | Tokens measured, rest estimated |
| AWS Agent Registry (only with `-c agentRegistry=true`) | 5 records, 1 search per URL, 1 more Gateway call                              | $0 (free tier)                     | About $0.0005    | Estimate                        |

## Monthly examples

Computed from the current measured token mean ($0.090 per model-backed scan), the other-services estimate ($0.015 per scan), the idle estimate, and AgentCore Memory records for 90 days of scans (about $0.0005 per stored scan per month, three months kept). `us-west-2` application, `us-east-1` edge stack, on-demand prices, no free tier.

| Scans per month | Model tokens | Other per-scan services | Idle stacks | Stored data | Total |
| --- | --- | --- | --- | --- | --- |
| 1,000 | $90 | $15 | $14 to $21 | $1.50 | **About $120 to $130** |
| 10,000 | $900 | $150 | $21 | $15 | **About $1,090** |
| 100,000 | $9,000 | $1,500 | $21 | $150 | **About $10,670** |

Assumptions and limits:

- Token prices from `backend/phish_backend/common/pricing.json` (AWS Price List API, checked 2026-10-21): the `us.` Opus 5.5 profile at $4.40 input and $22.00 output per million tokens, the `global.` Sonnet 5.5 profile at $2.00 and $10.00, cache reads at 0.05 times and cache writes at 1.25 times the input price.
- The $0.090 mean was measured with episodic memory off; with it on (the default) the orchestrator also reads up to three short past-scan summaries.
- Your URL mix changes the mean: clean legitimate pages often take the unanimous fast path (no verdict turn), long pages with large scripts cost more.
- The idle range tops out at $21 when CloudWatch custom metrics are published every hour.

### How the service estimates were made

Token rows come from the scan records of the 2026-10-25 rerun of the same 50 URLs (recorded `cost_usd` matched a recomputation from stored usage on 43 of 43 model-backed scans). Other usage comes from the 50-URL batch window (2026-10-19 03:11 to 03:16 UTC, test stack, nothing else running) and the stored scan records, multiplied by AWS list prices from the AWS Price List API and the [AgentCore pricing page](https://aws.amazon.com/bedrock/agentcore/pricing/), checked 2026-10-18.

| Service                                                | Observed for 50 URLs                                                                                       | Unit price (us-west-2 unless noted)                                                                           | Per 100 URLs                                 |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| AgentCore Runtime (Harness, specialists, tools server) | 1.64 vCPU-hours, 26.5 GB-hours                                                                             | $0.0895 per vCPU-hour, $0.00945 per GB-hour                                                                   | $0.79 ($0.97 on a busier day, Cost Explorer) |
| AgentCore Runtime, dispatcher                          | Not metered separately: it waits on the specialists for about 30 s per scan and does no compute of its own | Same                                                                                                          | Up to about $0.05, mostly memory time        |
| AgentCore Browser                                      | 0.184 vCPU-hours, 0.913 GB-hours                                                                           | Same                                                                                                          | $0.05 ($0.06 on a busier day)                |
| AgentCore Gateway                                      | About 7 invocations per scan                                                                               | $0.005 per 1,000                                                                                              | $0.005                                       |
| AgentCore Memory                                       | 1 event, about 1.1 retrievals per scan                                                                     | $0.50 per 1,000 retrievals; $1.00 per GB ingested (12 KB minimum); $0.25 to $0.75 per 1,000 records per month | $0.06 to $0.15                               |
| AgentCore Web Search (us-east-1)                       | 9 searches                                                                                                 | $7 per 1,000                                                                                                  | $0.13                                        |
| Bedrock Guardrails                                     | 1 text unit in, about 4 out                                                                                | $0.15 per 1,000 text units (content and topic), $0.10 (sensitive information)                                 | $0.08                                        |
| Lambda                                                 | Worker 4,489 s at 512 MB Arm for 51 invocations                                                            | $0.0000133334 per GB-second, $0.20 per million requests                                                       | $0.06                                        |
| DynamoDB                                               | 2,745 read and 3,848 write request units, plus index writes                                                | $0.125 per million reads, $0.625 per million writes                                                           | $0.01 to $0.02                               |
| SQS                                                    | About 230 requests                                                                                         | $0.40 per million                                                                                             | Under $0.01                                  |
| S3                                                     | 5 PUTs and about 100 KB per scan                                                                           | $0.005 per 1,000 PUTs, $0.023 per GB-month                                                                    | Under $0.01                                  |
| CloudWatch                                             | 12.7 MB of logs and spans                                                                                  | $0.50 per GB ingested                                                                                         | $0.02 to $0.05                               |

Idle items: AWS WAF $5 per web ACL and $1 per rule per month; AWS KMS $1 per key per month; CloudWatch $0.10 per alarm per month and up to $6 for 20 custom metrics when scans run every hour; SQS long polling by the Lambda event source mappings (about 30,000 empty receives per day); the sweeper Lambda every 5 minutes. The status index adds about 6 write request units per scan (about $0.38 per 100,000 URLs); before it, the sweeper read the whole table, about $0.0015 per stored scan per month (about $450 per month at 100,000 URLs per month). Cost Explorer for the tagged stacks over 2026-10-15 to 2026-10-18 matched the idle and per-scan figures within the ranges above.

The token cost of each scan is in the scan record (`cost_usd`). A model with no price in `pricing.json` is listed in `unpriced_models` and shown as unknown cost, not as free. Costs of earlier designs are in [evaluation.md](evaluation.md#cost-history).


## Track your own spend

> **Tip:** For your real spend, open the Insights page: it shows token cost per URL, per batch and per model. For everything else, filter Cost Explorer on the `Project` and `Owner` tags.
