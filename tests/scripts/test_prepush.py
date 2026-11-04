# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("prepush", ROOT / "scripts" / "prepush.py")
prepush = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepush)


def git_repo(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    prepush._git(tmp_path, "init", "-q")
    prepush._git(tmp_path, "config", "user.email", "t@example.com")
    prepush._git(tmp_path, "config", "user.name", "t")
    return tmp_path


def commit(repo, name, text):
    (repo / name).write_text(text, encoding="utf-8")
    prepush._git(repo, "add", name)
    prepush._git(repo, "commit", "-qm", "c")


def test_find_dashes_flags_tracked_files_only(tmp_path):
    repo = git_repo(tmp_path)
    commit(repo, "ok.md", "plain - hyphen\n")
    commit(repo, "bad.md", "line one\nuses \u2014 an em dash\n")
    (repo / "untracked.md").write_text("\u2013", encoding="utf-8")
    assert prepush.find_dashes(repo) == ["bad.md:2"]


HEADER = (
    "Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.\n"
    "{p} SPDX-License-Identifier: MIT-0\n"
)


def test_has_header_per_comment_syntax():
    assert prepush.has_header("# " + HEADER.format(p="#") + "x = 1\n", "#")
    assert prepush.has_header("#!/bin/sh\n# " + HEADER.format(p="#"), "#")
    assert prepush.has_header("// " + HEADER.format(p="//"), "//")
    assert not prepush.has_header("# " + HEADER.format(p="#"), "//")
    assert not prepush.has_header("x = 1\n# " + HEADER.format(p="#"), "#")
    assert not prepush.has_header(
        "# Copyright 2026 Amazon.com\n# SPDX-License-Identifier: MIT\n", "#"
    )


def test_find_missing_headers_checks_source_files_only(tmp_path):
    repo = git_repo(tmp_path)
    commit(repo, "ok.py", "# " + HEADER.format(p="#") + "x = 1\n")
    commit(repo, "bad.ts", "export const x = 1;\n")
    commit(repo, "Dockerfile", "FROM scratch\n")
    commit(repo, "notes.md", "no header needed\n")
    commit(repo, "data.json", "{}\n")
    assert prepush.find_missing_headers(repo) == ["Dockerfile", "bad.ts"]


def test_repo_source_files_all_carry_the_header():
    assert prepush.find_missing_headers() == []


def test_every_step_has_a_function():
    assert set(prepush.STEP_FUNCS) == set(prepush.STEPS)


def _captured_commands(monkeypatch, tmp_path):
    out = tmp_path / "cdk.out"
    out.mkdir()
    (out / "PhishTriageAgentic.template.json").write_text("{}")
    monkeypatch.setattr(prepush, "CDK_OUT", out)
    calls: list[list[str]] = []
    monkeypatch.setattr(prepush, "run", lambda cmd, cwd=None: calls.append(cmd))
    return calls


def _config_arg(cmd: list[str]) -> Path:
    return Path(cmd[cmd.index("--config-file") + 1])


def test_cfn_lint_uses_the_infra_config(monkeypatch, tmp_path):
    calls = _captured_commands(monkeypatch, tmp_path)
    prepush.step_cfn_lint()
    config = _config_arg(calls[0])
    assert config == ROOT / "infra" / ".cfnlintrc.yaml"
    assert config.is_file()


def test_checkov_uses_the_infra_config(monkeypatch, tmp_path):
    calls = _captured_commands(monkeypatch, tmp_path)
    prepush.step_checkov()
    config = _config_arg(calls[0])
    assert config == ROOT / "infra" / ".checkov.yaml"
    assert config.is_file()


def test_every_cdk_cli_reference_uses_the_prepush_pin():
    pin = prepush.CDK_CLI[-1]
    seen = set()
    for name in filter(None, prepush._git(ROOT, "ls-files", "-z").split("\0")):
        path = ROOT / name
        if not path.is_file() or name.endswith(("package-lock.json", "uv.lock")):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        seen.update(re.findall(r"aws-cdk@[\w.]+", text))
    assert seen == {pin}


def test_run_starts_only_allowlisted_programs():
    with pytest.raises(prepush.GateError, match="not a program the gate runs"):
        prepush.run(["sh", "-c", "true"])
    with pytest.raises(prepush.GateError, match="not a program the gate runs"):
        prepush.execute("/bin/sh", ["-c", "true"])
    assert prepush.PROGRAMS == {"git", "uv", "npx", "npm"}


def _literal_heads(source: str) -> list[str | None]:
    """The program named by each subprocess.run call: its literal argv[0], or None."""
    import ast

    heads: list[str | None] = []
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "run"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
        ):
            argv = node.args[0] if node.args else None
            first = argv.elts[0] if isinstance(argv, ast.List) and argv.elts else None
            literal = isinstance(first, ast.Constant) and isinstance(first.value, str)
            heads.append(first.value if literal else None)
    return heads


def test_every_process_names_its_program_literally_in_one_launcher():
    # Each argv starts with a literal program name, one per allowlisted program, all inside
    # execute(): a caller picks arguments, never the executable, and the source shows which
    # executables can run without tracing a variable (static analysis flags a variable head).
    source = (ROOT / "scripts" / "prepush.py").read_text()
    assert sorted(_literal_heads(source)) == sorted(prepush.PROGRAMS)


@pytest.mark.parametrize("program", sorted(prepush.PROGRAMS))
def test_execute_starts_the_named_program_with_the_given_args(monkeypatch, program):
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"], seen["cwd"] = argv, kwargs["cwd"]
        return prepush.subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(prepush.subprocess, "run", fake_run)
    prepush.execute(program, ["--version", "a b;c"], cwd=ROOT)
    assert seen == {"argv": [program, "--version", "a b;c"], "cwd": ROOT}


def test_web_step_uses_npm_with_the_committed_lockfile(monkeypatch):
    # web/package-lock.json is the committed lockfile, so the gate needs no second
    # JavaScript package manager (and no second process launcher for one).
    calls = []
    monkeypatch.setattr(prepush, "run", lambda cmd, cwd=prepush.ROOT: calls.append(cmd))
    prepush.step_web()
    assert (prepush.ROOT / "web" / "package-lock.json").exists()
    assert calls == [
        ["npm", "run", "lint"],
        ["npm", "test", "--", "--run"],
        ["npm", "run", "build"],
    ]


def _hook_path(repo: Path) -> Path:
    common = prepush._git(repo, "rev-parse", "--git-common-dir").strip()
    return (repo / common).resolve() / "hooks" / "pre-push"


def test_install_hook_writes_an_executable_gate_hook(tmp_path):
    repo = git_repo(tmp_path)
    hook = prepush.install_hook(repo)
    assert hook == _hook_path(repo)
    text = hook.read_text()
    assert text.startswith("#!/bin/sh\n")
    assert 'exec uv run python scripts/prepush.py "$@"' in text
    assert hook.stat().st_mode & 0o111 == 0o111


def test_install_hook_is_idempotent(tmp_path):
    repo = git_repo(tmp_path)
    first = prepush.install_hook(repo).read_text()
    hook = prepush.install_hook(repo)
    assert hook.read_text() == first
    installed = [p.name for p in hook.parent.iterdir() if p.suffix != ".sample"]
    assert installed == ["pre-push"]


def test_install_hook_from_a_worktree_uses_the_common_git_dir(tmp_path):
    repo = git_repo(tmp_path / "main")
    commit(repo, "app.py", "x = 1\n")
    tree = tmp_path / "wt"
    prepush._git(repo, "worktree", "add", "-q", str(tree))
    hook = prepush.install_hook(tree)
    assert hook == (repo / ".git" / "hooks" / "pre-push").resolve()


def test_install_hook_replaces_an_older_gate_hook(tmp_path):
    repo = git_repo(tmp_path)
    hook = _hook_path(repo)
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\nexec uv run --package phish-backend python scripts/prepush.py\n")
    prepush.install_hook(repo)
    assert hook.read_text() == prepush.HOOK


def test_install_hook_never_clobbers_a_foreign_hook(tmp_path):
    repo = git_repo(tmp_path)
    hook = _hook_path(repo)
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho mine\n")
    with pytest.raises(prepush.GateError, match="not the gate"):
        prepush.install_hook(repo)
    assert hook.read_text() == "#!/bin/sh\necho mine\n"


def test_main_install_hook_installs_and_runs_no_steps(monkeypatch):
    installed: list[Path] = []
    monkeypatch.setattr(prepush, "install_hook", lambda repo=prepush.ROOT: installed.append(repo))
    ran: list[str] = []
    monkeypatch.setattr(
        prepush, "STEP_FUNCS", {name: (lambda n=name: ran.append(n)) for name in prepush.STEPS}
    )
    assert prepush.main(["--install-hook"]) == 0
    assert installed == [prepush.ROOT]
    assert ran == []


def test_main_install_hook_reports_a_foreign_hook(monkeypatch):
    def refuse(repo=prepush.ROOT):
        raise prepush.GateError("not the gate")

    monkeypatch.setattr(prepush, "install_hook", refuse)
    assert prepush.main(["--install-hook"]) == 1


def test_git_location_variables_never_leak_into_another_repo(tmp_path, monkeypatch):
    # A pre-push hook exports GIT_DIR (and in a worktree GIT_WORK_TREE etc.); they override
    # `git -C`, so without the guard a test's scratch commits landed in the real repository.
    sentinel = git_repo(tmp_path / "sentinel")
    commit(sentinel, "keep.txt", "keep\n")
    before = prepush._git(sentinel, "rev-parse", "HEAD").strip()
    monkeypatch.setenv("GIT_DIR", str(sentinel / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(sentinel))
    monkeypatch.setenv("GIT_INDEX_FILE", str(sentinel / ".git" / "index"))
    scratch = git_repo(tmp_path / "scratch")
    commit(scratch, "app.py", "x = 1\n")
    assert prepush._git(sentinel, "rev-parse", "HEAD").strip() == before
    assert "app.py" in prepush._git(scratch, "ls-files")
