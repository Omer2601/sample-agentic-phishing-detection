# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Tests for web/run.sh, the gunicorn command line the web Lambda runs.

run.sh is executed for real with a stub python3 first on PATH, so the test sees
the exact arguments gunicorn would receive rather than grepping the script.
"""

from __future__ import annotations

import os
import pathlib
import shlex
import subprocess

RUN_SH = pathlib.Path(__file__).resolve().parent.parent / "run.sh"

# The Lambda Web Adapter keeps its connections to gunicorn in a hyper client pool
# and reuses them between polls. hyper's default pool idle timeout is 90 s; the
# server's keep-alive must outlast it so the adapter, not gunicorn, is always the
# side that retires an idle connection. Otherwise gunicorn closes a socket the
# adapter is just reusing and the adapter answers 502 (ConnectionReset, os error
# 104), as seen in UI e2e run 2 (D4) with gunicorn's 2 s default.
ADAPTER_POOL_IDLE_S = 90


def _gunicorn_args(tmp_path: pathlib.Path, **env: str) -> list[str]:
    out = tmp_path / "argv"
    stub = tmp_path / "python3"
    # Writes one argument per line, so the test sees gunicorn's argv verbatim.
    record = f'for a in "$@"; do printf "%s\\n" "$a"; done > {shlex.quote(str(out))}'
    stub.write_text(f"#!/bin/sh\n{record}\n")
    stub.chmod(0o755)
    run_env = {
        "PATH": f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}",
        "LAMBDA_TASK_ROOT": str(tmp_path),
        **env,
    }
    # Fixed argv: the repo's own run.sh under /bin/sh, no user input involved.
    subprocess.run(["/bin/sh", str(RUN_SH)], env=run_env, check=True, timeout=10)  # noqa: S603  # nosec B603: fixed argv, literal program, no shell, no untrusted input
    return out.read_text().splitlines()


def _flag(args: list[str], name: str) -> str:
    return args[args.index(name) + 1]


def test_keep_alive_outlasts_the_adapter_connection_pool(tmp_path):
    args = _gunicorn_args(tmp_path, GUNICORN_WORKERS="1")
    assert int(_flag(args, "--keep-alive")) > ADAPTER_POOL_IDLE_S


def test_keep_alive_can_be_overridden(tmp_path):
    args = _gunicorn_args(tmp_path, GUNICORN_KEEPALIVE="150")
    assert _flag(args, "--keep-alive") == "150"


def test_threaded_worker_so_idle_keep_alive_sockets_do_not_block_requests(tmp_path):
    # With the sync worker a held keep-alive socket occupies the only worker; the
    # gthread worker parks idle connections and keeps threads free for requests.
    args = _gunicorn_args(tmp_path, GUNICORN_WORKERS="1")
    assert _flag(args, "--worker-class") == "gthread"
    assert int(_flag(args, "--threads")) > 1
    assert _flag(args, "--workers") == "1"
