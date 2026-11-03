# Architecture diagram tooling

`docs/architecture.drawio` is generated. Do not edit it by hand: edit the layout in `build_architecture.py`, then run from the repo root:

```bash
uv run python docs/diagram/build_architecture.py
uv run --with defusedxml==0.7.1 python docs/diagram/validate_diagram.py docs/architecture.drawio
/Applications/draw.io.app/Contents/MacOS/draw.io -x -f png -s 2 -b 20 -o docs/architecture.png docs/architecture.drawio
```

The validator fails on a diagonal line, a crossing, an overlap, a line through an icon or a long label. The diagram draws the default deploy: the scan path in the AgentCore group with solid, numbered lines (the numbers match the steps in [architecture.md](../architecture.md#how-a-scan-works)), the optional second round as the one dashed line, and anything off the scan path in the supporting services group with no lines. AWS Agent Registry sits in that group, labelled off by default, because it is deployed only with `-c agentRegistry=true`. Icons: AWS Architecture Icons release 07312026.

All icons are draw.io built-ins (`mxgraph.aws4`). The 07312026 package has no separate AgentCore Harness, Runtime, Gateway or Browser icons, so all four, the tools Gateway, the dispatcher, the tools server, AgentCore Memory and the AWS Agent Registry (part of Amazon Bedrock AgentCore) use `bedrock_agentcore` and are told apart by label. No icon files are committed.
