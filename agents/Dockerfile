# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# One image for all three specialists, the shared tools server (AGENT=tools_server) and the dispatcher (AGENT=dispatcher). Build from the repo root so contracts/ is in context:
#   finch build --platform linux/arm64 -f agents/Dockerfile --build-arg AGENT=url_analyst .
FROM public.ecr.aws/docker/library/python:3.13-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install uv==0.12.20
WORKDIR /src
# The workspace root, its lock and every member's pyproject are enough for uv export.
COPY pyproject.toml pyproject.toml
COPY uv.lock uv.lock
COPY contracts contracts
COPY agents/pyproject.toml agents/pyproject.toml
# Every transitive dependency comes from uv.lock with hashes, so the image matches the
# versions the tests ran against; the two workspace packages are installed on top.
RUN uv export --frozen --package phish-agents --no-dev --no-emit-workspace -o /tmp/req.txt
COPY agents/phish_agents agents/phish_agents
# --no-config: the root pyproject's [tool.uv] constraint-dependencies would otherwise be added
# as unpinned requirements and fail --require-hashes; the exported lock already honors them.
RUN uv venv /opt/venv \
 && VIRTUAL_ENV=/opt/venv uv pip install --no-config --no-cache --require-hashes -r /tmp/req.txt \
 && VIRTUAL_ENV=/opt/venv uv pip install --no-config --no-cache --no-deps ./contracts ./agents

FROM public.ecr.aws/docker/library/python:3.13-slim AS runtime
ARG AGENT
RUN test -n "$AGENT" && useradd --system --create-home --shell /usr/sbin/nologin --uid 10001 agent
COPY --from=builder /opt/venv /opt/venv
# AWS_REGION is injected by AgentCore Runtime; the image stays region-neutral.
# HOST: AgentCore Runtime requires the server on 0.0.0.0:8000 inside the container; the
# code default is loopback (phish_agents/common/server.py bind_host).
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    AGENT=${AGENT} LOG_LEVEL=INFO HOST=0.0.0.0
USER agent
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import socket; socket.create_connection(('127.0.0.1', 8000), 2)"]
# Exec form with no ENTRYPOINT: AgentCore Runtime runs this default, and a local
# `finch run IMAGE python -c ...` replaces it. phish_agents/__main__.py reads AGENT.
CMD ["python", "-m", "phish_agents"]
