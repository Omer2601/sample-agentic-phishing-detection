# Troubleshooting

Symptoms you may see while you deploy, scan or call the API, with the likely cause and the fix. Start with the preflight check, which catches most deploy problems in one run:

```bash
uv run python scripts/preflight.py --profile <your-profile> --region "$AWS_REGION"
```

**On this page:** [Deploy](#deploy) · [Scans](#scans) · [API](#api) · [Clean up](#clean-up)

## Deploy

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Preflight says a model is not `AUTHORIZED`, or `AccessDeniedException` on a model | No Amazon Bedrock model access in this Region | Request access to both models in the Amazon Bedrock console, then rerun preflight |
| `Cannot connect to the Docker daemon` | Docker or Finch is not running | Start it (`finch vm start`), set `CDK_DOCKER` to match |
| Image build fails with `exec format error` | ARM64 emulation missing on an x86 machine | Enable ARM64 emulation in Docker or Finch |
| `PhishTriageAgenticEdge` fails: not bootstrapped | No CDK bootstrap in `us-east-1` | Run the bootstrap step for both Regions ([deploy.md](deploy.md#2-bootstrap-cdk-in-both-regions-one-time)) |
| AgentCore resource type not supported | AgentCore is not in this Region | Pick a supported Region and redeploy |
| Synth fails on `specialistMode` | The option was removed | Drop it, or use `-c agentRegistry=true` |
| Synth fails on `directOrchestration` with `agentRegistry` | The two cannot be combined | Drop `-c directOrchestration=true`; with the registry on, the Harness path is selected for you |

## Scans

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| A scan shows `FAILED` | A step failed 3 times in a row | Read the reason on the scan, then press **Retry** |
| AgentCore or Bedrock quota errors | Account limits (sessions, tokens per minute) | Lower `-c scanConcurrency`, or request a quota increase |
| Batch scans wait a long time before they start | More scans queued than `scanConcurrency` allows at once | Expected: scans run 25 at a time by default. Raise `-c scanConcurrency` if your quotas allow |
| Cost shows as unknown | A model override with no price in `pricing.json` | Add the model's prices, or read the tokens in the scan record |
| Verdict is Suspicious with "Page not observed" | A provider warning, bot check or failed capture hid the real page | Send it to a person; see the [FAQ in the README](../README.md#faq) |

## API

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `403` | Request not signed, or the principal lacks the invoke policy | Sign with SigV4 and attach the `ApiInvokePolicyArn` stack output to your principal ([api.md](api.md)) |
| `429` | Throttling | Retry with backoff; the web app does this for you |
| `400` | The body is not valid (not a URL, wrong type, missing field) | Read the `error` field in the response |

## Clean up

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Stack stuck in `DELETE_FAILED` | A resource was changed outside CloudFormation | Read the stack events, remove the named resource, run destroy again |
| Resources left after destroy | Deployed with `-c environment=prod` (retain policy), or a log group created at run time | Follow [deploy.md](deploy.md#clean-up) |
