# Deploy

You can deploy this sample into your own AWS account, in any Region where Amazon Bedrock AgentCore and the two Claude models are available. Deploying takes about 8 minutes the first time with warm container caches, 16 minutes from a fresh clone, and about 4 minutes for an update (measured in our test account, see [3. Deploy](#3-deploy-8-to-16-minutes)). Everything below runs against the account and Region your AWS credentials point at, so check them first.

**On this page:** [Prerequisites](#prerequisites) · [1. Check your account](#1-choose-a-region-and-check-your-account-2-minutes) · [2. Bootstrap](#2-bootstrap-cdk-in-both-regions-one-time) · [3. Deploy](#3-deploy-8-to-16-minutes) · [Options](#options) · [Sign-in and MFA](#sign-in-and-mfa) · [Custom domain](#custom-domain) · [Verify](#verify) · [Clean up](#clean-up) · [Troubleshooting](#troubleshooting)

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

## 3. Deploy (8 to 16 minutes)

```bash
cd infra
export CDK_DOCKER=docker   # or finch
npx aws-cdk@2.1143.0 deploy --all -c owner=<team or alias>
```

Set `owner` to your team or alias. Without it every resource is tagged `Owner=phish-triage-owner`, and nobody can tell from Cost Explorer who is paying. This creates two stacks: `PhishTriageAgenticEdge` in `us-east-1` (the web ACL and, with the default `-c webSearch=true`, the AgentCore Web Search Gateway; in a Region that offers Web Search, that Gateway moves to the regional stack instead, still a Gateway of its own and never a target on the tools Gateway, and the edge stack has no Gateway) and `PhishTriageAgentic` in your Region (everything else).

Measured durations, from our test account in `us-west-2` on 2026-09-30 with Finch on an Apple silicon laptop: creating `PhishTriageAgentic` took 476 s (about 8 minutes), and in-place updates took 220 s and 238 s. These are per-stack times for `PhishTriageAgentic` only. Updating a stack deployed before the scans table had its `status-queued_at` index adds that index in place (the table is not replaced); DynamoDB backfills it from the stored scans before that update finishes, so that one update takes longer on a table with many stored scans. A timed first `deploy --all` of a second copy (`-c appName=verify`, same account, laptop and Region, 2026-10-15) took 540 s end to end, including both stacks and the container image builds, and its first scans answered at once. A first `deploy --all` from a fresh clone on 2026-11-03 took about 16 minutes, most of it building the container images. Your times depend on your network and container runtime.

## Options

Every deploy option, with its default and when to change it, is in [configuration.md](configuration.md).

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
| The orchestrator harness log group           | Only if a scan ran on the Harness path (`-c directOrchestration=false` or `-c agentRegistry=true`): AgentCore creates it on the first such scan, under `/aws/bedrock-agentcore/` with `phish_orchestrator` in its name, with no retention. Delete it, or set a retention after the first scan with `aws logs put-retention-policy` |
| The orchestrator's former managed memory     | Only on a stack first deployed before 2026-10-16: the harness ran with managed memory then (`<appName>_orchestrator-*` in AgentCore Memory). An update turns it off and detaches it but does not delete it or its records; delete it in the AgentCore console or with `aws bedrock-agentcore-control delete-memory` |
| CDK bootstrap stacks (`CDKToolkit`)          | Keep them if you use CDK elsewhere. Otherwise delete the stack in both Regions, then its staging bucket                     |
| Container images in the CDK asset repository | Removed with the bootstrap stack, or delete the images in Amazon ECR                                                        |

Confirm nothing tagged for this sample is left:

```bash
aws resourcegroupstaggingapi get-resources --tag-filters Key=Project,Values=phish-triage --region "$AWS_REGION"
aws resourcegroupstaggingapi get-resources --tag-filters Key=Project,Values=phish-triage --region us-east-1
```

## Troubleshooting

See [troubleshooting.md](troubleshooting.md).
