# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The specialist image must install exactly what uv.lock pins."""

import re
import shutil
import subprocess  # nosec B404: test runs a fixed uv argv, no shell
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = (ROOT / "agents" / "Dockerfile").read_text()
EXPORT = "uv export --frozen --package phish-agents --no-dev"


def test_builder_exports_the_lock_and_installs_with_hashes():
    assert "uv.lock" in DOCKERFILE
    assert EXPORT in DOCKERFILE
    assert "--require-hashes" in DOCKERFILE
    # The workspace packages go in without re-resolving their dependencies.
    assert re.search(r"uv pip install[^\n]*--no-deps[^\n]*\./contracts \./agents", DOCKERFILE)


def test_export_works_from_only_the_files_the_dockerfile_copies(tmp_path):
    uv = shutil.which("uv")
    if not uv:
        pytest.skip("uv not on PATH")
    for src in re.findall(r"^COPY (?!--from)(\S+) ", DOCKERFILE, re.M):
        path = ROOT / src
        dest = tmp_path / src
        dest.parent.mkdir(parents=True, exist_ok=True)
        if path.is_dir():
            shutil.copytree(path, dest, ignore=shutil.ignore_patterns("__pycache__", "tests"))
        else:
            shutil.copy(path, dest)
    cmd = re.search(r"(uv export [^\n&]*)", DOCKERFILE).group(1).split()
    cmd[cmd.index("-o") + 1] = "req.txt"
    assert cmd[:2] == ["uv", "export"]
    # The program is the literal "uv"; only the Dockerfile's export arguments vary. No shell.
    subprocess.run(["uv", *cmd[1:]], cwd=tmp_path, check=True, capture_output=True)  # noqa: S603, S607  # nosec B603 B607: fixed argv, literal program resolved from PATH on purpose, no shell, no untrusted input
    req = (tmp_path / "req.txt").read_text()
    assert "strands-agents==1.63.0" in req and "--hash=sha256:" in req
    assert "-e ./" not in req


def test_default_command_is_overridable_exec_form():
    """No ENTRYPOINT: `finch run IMAGE python -c ...` must replace the server command.

    AgentCore Runtime runs the image default, an exec form CMD so python is PID 1
    and receives SIGTERM directly.
    """
    assert not re.search(r"^ENTRYPOINT", DOCKERFILE, re.M)
    cmds = re.findall(r"^CMD (.+)$", DOCKERFILE, re.M)
    assert cmds == ['["python", "-m", "phish_agents"]']


def test_pip_installs_ignore_the_workspace_uv_config():
    # uv pip reads [tool.uv] from /src/pyproject.toml, and its constraint-dependencies
    # (urllib3>=2.7.0) then fail --require-hashes as an unpinned requirement (2026-09-29).
    # The exported lock already carries those floors, so the installs skip the config.
    installs = re.findall(r"uv pip install[^\n]*", DOCKERFILE)
    assert len(installs) == 2
    assert all("--no-config" in line for line in installs), installs
