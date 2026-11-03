# dispatcher

Runs the three specialists at the same time and hands the orchestrator their three Findings in one reply. It makes no model call of its own.

|           |                                                                                                                                                                           |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Runs on   | Amazon Bedrock AgentCore Runtime (`phish_dispatcher`), as an MCP server, from the same container image as the specialists (`AGENT=dispatcher`)                            |
| Model     | None. It only invokes the three specialist Runtimes; it never calls Bedrock                                                                                               |
| Called by | The orchestrator, once per scan in the first round, through AgentCore Gateway `phish-specialists` as `dispatcher___analyze_all`                                           |
| Tools     | Exposes `analyze_all(url, scan_id)`. It calls the `url_analyst`, `brand_visual` and `code_analyst` Runtimes concurrently with `InvokeAgentRuntime` (their `analyze` tool) |
| Prompt    | None                                                                                                                                                                      |
| Code      | [`agents/phish_agents/dispatcher/server.py`](../../agents/phish_agents/dispatcher/server.py)                                                                              |

## What it does

The AgentCore Harness runs same-turn Gateway tool calls one after another, so three specialist tools in one message cost the sum of the three. The dispatcher puts the three behind one tool, so the first round costs about the slowest specialist. See [orchestrator.md](orchestrator.md#why-a-dispatcher) for the measurements.

On each call it:

1. Validates the `scan_id`, then invokes the three specialist Runtimes at the same time (`asyncio.gather` over a thread pool sized to the three), each with the same `url` and `scan_id`, each with its own timeout.
2. Returns `{"findings": [...]}` with one Finding each, in `url_analyst`, `brand_visual`, `code_analyst` order. Each Finding is the specialist's own: its status, signals, `latency_ms`, token usage and calls pass through unchanged.

The optional second round does not use the dispatcher: the orchestrator calls one specialist tool (`url-analyst___analyze`, `brand-visual___analyze` or `code-analyst___analyze`) once more on the same Gateway. The specialists still capture pages and look up RDAP through the shared tools server behind the `phish-tools` Gateway.

## It never raises

A specialist that errors, times out or is throttled comes back as an error Finding in its slot, so the orchestrator always receives three Findings in order. Each specialist writes its own Finding to S3; the dispatcher writes an error Finding to `scans/{scan_id}/findings/<agent>.json` only if that key does not exist yet (`If-None-Match`), so a real Finding from a specialist that finished just after the dispatcher gave up is never overwritten. A failed invoke is logged with a short reference id that also appears in the error Finding.

## Timeouts

| Limit                                     | Value                                                                        |
| ----------------------------------------- | ---------------------------------------------------------------------------- |
| Specialist deadline (inside each Runtime) | 30 s for url_analyst, 35 s for the two page specialists, brand_visual and code_analyst (a browser capture plus their longest model turn: code_analyst runs reached 29.4 s, and brand_visual's model ran out of time on 5 of 317 scans at 30 s); the specialist answers with its own error Finding at that point |
| Read timeout per specialist invoke        | 45 s, one attempt only (a retry would start a second, billed specialist run) |
| Backstop per specialist                   | 50 s (`asyncio.wait_for`), so a hung socket cannot hold the Gateway call     |

## Permissions

Its role may call `InvokeAgentRuntime` on the three specialist Runtimes and their endpoints only (not the tools Runtime, not itself), `s3:PutObject` on the three `scans/*/findings/<agent>.json` keys only, and `kms:GenerateDataKey` and `kms:Encrypt` on the data key. It has no Bedrock, browser, Gateway or cache grant. The `phish-specialists` Gateway role may invoke the dispatcher and the three specialist Runtimes.

## How it is timed

The dispatcher adds no row of its own. The worker gives each specialist a `kind=specialist` row that starts at the dispatcher call's start and lasts the Finding's `latency_ms`; each specialist's own model, browser and RDAP calls are inside its Finding.

## When it fails

| What happened                                  | What the orchestrator sees                                               |
| ---------------------------------------------- | ------------------------------------------------------------------------ |
| A specialist errors, times out or is throttled | An error Finding in that specialist's slot; the other two are unaffected |
| The `scan_id` is invalid                       | Three error Findings, one per specialist, and no specialist call         |
| The runtime client cannot be created           | Three error Findings, one per specialist                                 |
