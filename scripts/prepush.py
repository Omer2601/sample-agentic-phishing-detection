# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Pre-push gate. Install it as the pre-push hook with --install-hook.

Order is cheapest first. Every step must pass; there is no skip flag in the hook.
Manual use: uv run python scripts/prepush.py [--only lint,test]
Install the hook: uv run python scripts/prepush.py --install-hook
"""

import argparse
import logging
import os
import stat
import subprocess  # nosec B404: fixed argv lists, no shell, used only to run the gate's tools
import sys
from pathlib import Path

logger = logging.getLogger("prepush")
ROOT = Path(__file__).resolve().parents[1]
DASHES = ("\u2014", "\u2013")
STEPS = (
    "dashes",
    "headers",
    "lint",
    "test",
    "web",
    "synth",
    "cfn-lint",
    "checkov",
)
CDK_OUT = ROOT / "infra" / "cdk.out"
# The accepted-exception configs live next to the CDK app they describe.
CFNLINT_CONFIG = ROOT / "infra" / ".cfnlintrc.yaml"
CHECKOV_CONFIG = ROOT / "infra" / ".checkov.yaml"
# Exact CLI version so every synth (here, CI and the docs) uses the same toolchain.
CDK_CLI = ("npx", "-y", "aws-cdk@2.1143.0")
# Scanners run as isolated uv tools, pinned, so their own exact dependency pins (checkov
# holds urllib3 and asteval back) never enter the workspace lock.
CFN_LINT = "cfn-lint@1.57.1"
CHECKOV = "checkov@3.3.20"


class GateError(Exception):
    pass


# The only programs the gate starts: git reads the repository, the others run the steps.
PROGRAMS = frozenset({"git", "uv", "npx", "npm"})


# A pre-push hook runs with these set for the repository being pushed. They override
# `git -C <repo>`, so anything the gate starts (including the test suite) would write to
# that repository instead of the one it names. Each child finds its repo from its own path.
_GIT_LOCATION_VARS = frozenset(
    {
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
        "GIT_PREFIX",
    }
)


def _clean_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k not in _GIT_LOCATION_VARS}


def execute(
    program: str, args: list[str], *, cwd: Path = ROOT, capture: bool = False, check: bool = False
) -> subprocess.CompletedProcess:
    """Start one allowlisted program. The only place the gate creates a process.

    There is no Python API for git's plumbing or for these CLIs, so a process is the only
    way. Each argv is a list that starts with a literal program name, never a shell string,
    so a caller chooses arguments but never which executable runs, and shell
    metacharacters in an argument are passed through literally.
    """
    opts = {"cwd": cwd, "check": check, "capture_output": capture, "env": _clean_env()}
    match program:
        case "git":
            return subprocess.run(["git", *args], **opts)  # nosec B603 B607: fixed argv, literal program resolved from PATH on purpose, no shell, no untrusted input
        case "uv":
            return subprocess.run(["uv", *args], **opts)  # nosec B603 B607: fixed argv, literal program resolved from PATH on purpose, no shell, no untrusted input
        case "npx":
            return subprocess.run(["npx", *args], **opts)  # nosec B603 B607: fixed argv, literal program resolved from PATH on purpose, no shell, no untrusted input
        case "npm":
            return subprocess.run(["npm", *args], **opts)  # nosec B603 B607: fixed argv, literal program resolved from PATH on purpose, no shell, no untrusted input
    raise GateError(f"{program} is not a program the gate runs")


def run(cmd: list[str], cwd: Path = ROOT) -> None:
    logger.info("$ %s", " ".join(cmd))
    program, *args = cmd
    result = execute(program, args, cwd=cwd)
    if result.returncode != 0:
        raise GateError(f"{program} exited with {result.returncode}")


def _git(repo: Path, *args: str) -> str:
    return execute("git", ["-C", str(repo), *args], capture=True, check=True).stdout.decode()


def find_dashes(repo: Path = ROOT) -> list[str]:
    files = _git(repo, "ls-files", "-z").split("\0")
    hits = []
    for name in filter(None, files):
        path = repo / name
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if any(d in line for d in DASHES):
                hits.append(f"{name}:{number}")
    return hits


HEADER_LINES = (
    "Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.",
    "SPDX-License-Identifier: MIT-0",
)
# Comment prefix per source type that carries the license header (plus Dockerfiles).
# Everything else (json, md, lock, svg) carries none.
HEADER_PREFIX = {".py": "#", ".sh": "#", ".ts": "//", ".tsx": "//", ".js": "//", ".jsx": "//"}


def header_prefix(name: str) -> str | None:
    path = Path(name)
    return "#" if path.name == "Dockerfile" else HEADER_PREFIX.get(path.suffix)


def has_header(text: str, prefix: str) -> bool:
    lines = text.splitlines()
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    return lines[:2] == [f"{prefix} {line}" for line in HEADER_LINES]


def find_missing_headers(repo: Path = ROOT) -> list[str]:
    missing = []
    for name in filter(None, _git(repo, "ls-files", "-z").split("\0")):
        prefix = header_prefix(name)
        path = repo / name
        if prefix and path.is_file() and not has_header(path.read_text("utf-8"), prefix):
            missing.append(name)
    return missing


def step_dashes() -> None:
    hits = find_dashes()
    if hits:
        raise GateError("em or en dashes found: " + ", ".join(hits[:50]))


def step_headers() -> None:
    missing = find_missing_headers()
    if missing:
        raise GateError("missing the MIT-0 license header: " + ", ".join(missing[:50]))


def step_lint() -> None:
    run(["uv", "run", "ruff", "check", "."])
    run(["uv", "run", "ruff", "format", "--check", "."])


def step_test() -> None:
    run(["uv", "run", "--all-packages", "pytest", "-q"])


def step_web() -> None:
    # web/package-lock.json is the committed lockfile, so npm is the one package manager.
    web = ROOT / "web"
    run(["npm", "run", "lint"], cwd=web)
    run(["npm", "test", "--", "--run"], cwd=web)
    run(["npm", "run", "build"], cwd=web)


def step_synth() -> None:
    run(
        [*CDK_CLI, "synth", "--quiet", "--all", "-o", str(CDK_OUT)],
        cwd=ROOT / "infra",
    )


def _config(path: Path) -> Path:
    # A missing config would silently drop every accepted exception and fail on noise,
    # or worse, pass with defaults that differ from what infra/tests asserts.
    if not path.is_file():
        raise GateError(f"missing {path.relative_to(ROOT)}")
    return path


def step_cfn_lint() -> None:
    templates = sorted(str(p) for p in CDK_OUT.glob("*.template.json"))
    if not templates:
        raise GateError("no synthesized templates; run the synth step first")
    run(["uv", "tool", "run", CFN_LINT, "--config-file", str(_config(CFNLINT_CONFIG)), *templates])


def step_checkov() -> None:
    cmd = [
        "uv",
        "tool",
        "run",
        CHECKOV,
        "-d",
        str(CDK_OUT),
        "--framework",
        "cloudformation",
        "--quiet",
        "--compact",
    ]
    cmd += ["--config-file", str(_config(CHECKOV_CONFIG))]
    run(cmd)


# The hook marker: any existing hook that runs this script is ours to replace.
HOOK_MARKER = "scripts/prepush.py"
HOOK = f"""#!/bin/sh
# Installed by {HOOK_MARKER} --install-hook. Runs the full pre-push gate.
cd "$(git rev-parse --show-toplevel)" || exit 1
exec uv run python {HOOK_MARKER} "$@"
"""


def install_hook(repo: Path = ROOT) -> Path:
    """Write the pre-push hook. Safe to rerun; never replaces a hook it did not write.

    Hooks live in the common git dir, so one install covers every worktree.
    """
    common = _git(repo, "rev-parse", "--git-common-dir").strip()
    hook = (repo / common).resolve() / "hooks" / "pre-push"
    if hook.exists() and HOOK_MARKER not in hook.read_text(errors="replace"):
        raise GateError(f"{hook} exists and is not the gate hook; move it aside first")
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(HOOK)
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return hook


STEP_FUNCS = {
    "dashes": step_dashes,
    "headers": step_headers,
    "lint": step_lint,
    "test": step_test,
    "web": step_web,
    "synth": step_synth,
    "cfn-lint": step_cfn_lint,
    "checkov": step_checkov,
}


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="[prepush] %(message)s")
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default=",".join(STEPS))
    parser.add_argument("--install-hook", action="store_true", help="install, run no steps")
    args, _ = parser.parse_known_args(argv)  # git passes remote name and url; ignored
    if args.install_hook:
        try:
            logger.info("installed %s", install_hook())
        except GateError as exc:
            logger.error("FAILED install-hook: %s", exc)
            return 1
        return 0
    wanted = [s for s in STEPS if s in args.only.split(",")]
    for name in wanted:
        logger.info("== %s", name)
        try:
            STEP_FUNCS[name]()
        except GateError as exc:
            logger.error("FAILED %s: %s", name, exc)
            return 1
    logger.info("all %d steps passed", len(wanted))
    return 0


if __name__ == "__main__":
    sys.exit(main())
