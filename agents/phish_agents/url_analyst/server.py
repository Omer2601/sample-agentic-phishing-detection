# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from phish_agents.common.server import build_server, serve
from phish_agents.url_analyst.agent import analyze


def main() -> None:
    serve(build_server("url_analyst", analyze))


if __name__ == "__main__":
    main()
