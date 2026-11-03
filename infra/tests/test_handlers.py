# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Every Lambda handler the stack wires must exist in the package that ships it.

Skipped per package while that package's worktree has not merged (backend/phish_backend or
agents/phish_agents absent), so the infra worktree stays green on its own; after the merge a
renamed or missing handler module fails here instead of at the first invoke.
"""

from pathlib import Path

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from phish_infra.common import REPO_ROOT
from phish_infra.config import load_config
from phish_infra.stacks.main import PhishTriageStack

# Top-level Python package -> its source directory in the repo.
PACKAGE_DIRS = {
    "phish_backend": Path("backend") / "phish_backend",
    "phish_agents": Path("agents") / "phish_agents",
}
CONTEXTS = [
    {},
    {"agentRegistry": True},
    {"signUpMode": "cognito", "allowedEmailDomains": "example.com"},
]


def wired_handlers(app_context, test_env) -> set[str]:
    handlers: set[str] = set()
    for extra in CONTEXTS:
        app = cdk.App(context={**app_context, **extra})
        stack = PhishTriageStack(
            app, "PhishTriageAgentic", cfg=load_config(app.node), web_acl_arn=None, env=test_env
        )
        for fn in Template.from_stack(stack).find_resources("AWS::Lambda::Function").values():
            handler = fn["Properties"].get("Handler", "")
            if handler.split(".")[0] in PACKAGE_DIRS:
                handlers.add(handler)
    return handlers


def missing_handlers(handlers: set[str], root: Path) -> tuple[list[str], set[str]]:
    """(handlers whose module or function is missing, packages absent and so not checked)."""
    missing, absent = [], set()
    for handler in sorted(handlers):
        *module, function = handler.split(".")
        package_dir = root / PACKAGE_DIRS[module[0]]
        if not package_dir.is_dir():
            absent.add(module[0])
            continue
        path = package_dir.joinpath(*module[1:]).with_suffix(".py")
        if not path.is_file() or f"def {function}(" not in path.read_text(encoding="utf-8"):
            missing.append(f"{handler} (expected def {function} in {path.relative_to(root)})")
    return missing, absent


@pytest.fixture(scope="module")
def handlers(app_context, test_env):
    return wired_handlers(app_context, test_env)


def test_requeue_sweeper_is_wired(handlers):
    assert "phish_backend.worker.requeue_stuck.handler" in handlers


def test_detects_a_missing_handler_module(tmp_path, handlers):
    worker = tmp_path / "backend" / "phish_backend" / "worker"
    worker.mkdir(parents=True)
    (worker / "run_scan.py").write_text("def handler(event, context):\n    return None\n")
    missing, absent = missing_handlers(handlers, tmp_path)
    assert not any(m.startswith("phish_backend.worker.run_scan.handler") for m in missing)
    assert any(m.startswith("phish_backend.worker.requeue_stuck.handler") for m in missing)


def test_every_wired_handler_exists(handlers):
    missing, absent = missing_handlers(handlers, REPO_ROOT)
    assert not missing, "\n".join(missing)
    if absent == set(PACKAGE_DIRS):
        pytest.skip(f"handler packages not merged yet: {sorted(absent)}")
