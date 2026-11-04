# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from phish_agents.brand_visual.agent import analyze
from phish_agents.common.server import build_server, serve


def main() -> None:
    serve(build_server("brand_visual", analyze))


if __name__ == "__main__":
    main()
