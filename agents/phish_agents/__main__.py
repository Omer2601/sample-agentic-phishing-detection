# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Image default command: `python -m phish_agents` runs the specialist named by $AGENT.

The Dockerfile bakes AGENT in at build time (one image per specialist). Keeping the
dispatch here instead of in a shell ENTRYPOINT means the image CMD is an exec form
that any `finch run IMAGE <command>` replaces, and python runs as PID 1.
"""

import importlib
import os
from collections.abc import Mapping

SPECIALISTS = ("url_analyst", "brand_visual", "code_analyst")
# The shared tools MCP server and the dispatcher run from the same image.
AGENTS = (*SPECIALISTS, "tools_server", "dispatcher")


def main(env: Mapping[str, str] = os.environ) -> None:
    agent = env.get("AGENT", "")
    if agent not in AGENTS:
        raise SystemExit(f"AGENT must be one of {', '.join(AGENTS)}; got {agent!r}")
    importlib.import_module(f"phish_agents.{agent}.server").main()


if __name__ == "__main__":
    main()
