#!/bin/sh
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Single gunicorn entrypoint for the web Lambda.
#
# WHY THIS FILE EXISTS: the app runs on Lambda through the AWS Lambda Web Adapter
# (LWA). LWA is wired as an exec wrapper (AWS_LAMBDA_EXEC_WRAPPER=/opt/bootstrap)
# and the function's handler value is the name of this script, so the gunicorn
# command line has to live in a file the sandbox can exec.
set -eu

# Application root. Lambda unpacks the deployment package to $LAMBDA_TASK_ROOT
# (/var/task) and starts the process there; a local run falls back to the current
# directory. It goes on PYTHONPATH because gunicorn is started as a module (see below)
# and has to import server.wsgi from here.
APP_ROOT="${LAMBDA_TASK_ROOT:-$(pwd)}"
cd "$APP_ROOT"
PYTHONPATH="${APP_ROOT}${PYTHONPATH:+:${PYTHONPATH}}"
export PYTHONPATH

# LWA connects to AWS_LWA_PORT, so bind to that value rather than to a second
# constant that can silently disagree with it. 8080 is the local default.
PORT="${AWS_LWA_PORT:-8080}"

# Workers: a Lambda sandbox handles exactly one request at a time, so infra sets
# GUNICORN_WORKERS=1 there; the default of two is for local runs. Threads stay high
# because a request is spent almost entirely waiting on the upstream API, not on
# CPU.
#
# Timeouts: CloudFront's origin read timeout is 60 seconds, the function timeout
# matches it, and UPSTREAM_TIMEOUT is set below both so a slow upstream returns a
# proxy error rather than a 504 with no body. Scans are asynchronous (POST /scan
# returns at once and the SPA polls), so no request needs longer.
#
# Keep-alive: the Lambda Web Adapter reuses pooled connections to gunicorn across
# requests (hyper's client pool, 90 s idle by default). gunicorn's own default
# keep-alive is 2 s, so with the SPA polling every 2 s gunicorn kept closing a
# connection at the moment the adapter reused it, and the adapter answered 502
# ("ConnectionReset, os error 104"). A keep-alive longer than the adapter's pool
# idle time means the adapter always retires an idle connection first. The worker
# class is pinned to gthread (what --threads above 1 selects anyway) because it
# parks idle keep-alive sockets instead of tying up a worker on them.
#
# `python3 -m gunicorn` rather than the `gunicorn` console script: in the Lambda
# deployment package pip writes console scripts under bin/ with the build host's
# interpreter in the shebang, and bin/ is not on PATH in the sandbox. The module
# entry point behaves identically locally and on Lambda.
#
# Custom access log format. gunicorn's default logs %(r)s, the full request line
# including the query string, so the OAuth callback (/auth/callback?code=...) would
# write the one-time authorization code into CloudWatch Logs and the access log
# bucket. %(m)s %(U)s records the method and path only, and %(U)s excludes the
# query string, so the code never reaches the logs. Status, response size and
# latency are kept for operations, plus the trace id as a request id. Authorization
# and Cookie headers are never referenced, so they are never logged.
exec python3 -m gunicorn \
  --bind "0.0.0.0:${PORT}" \
  --workers "${GUNICORN_WORKERS:-2}" \
  --worker-class gthread \
  --threads "${GUNICORN_THREADS:-8}" \
  --keep-alive "${GUNICORN_KEEPALIVE:-120}" \
  --timeout "${GUNICORN_TIMEOUT:-300}" \
  --graceful-timeout 30 \
  --access-logfile - \
  --access-logformat '%(h)s %(t)s %(m)s %(U)s %(s)s %(b)s %(D)sus rid=%({x-amzn-trace-id}i)s' \
  server.wsgi:app
