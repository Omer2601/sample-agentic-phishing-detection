# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""`python -m phish_agents` (the image CMD) starts the specialist named by $AGENT."""

import runpy
import types

import pytest

from phish_agents import __main__ as entry


@pytest.mark.parametrize(
    "agent", ["url_analyst", "brand_visual", "code_analyst", "tools_server", "dispatcher"]
)
def test_runs_the_named_specialist_server(monkeypatch, agent):
    started: list[str] = []
    fake = types.SimpleNamespace(main=lambda: started.append(agent))
    monkeypatch.setattr(entry.importlib, "import_module", lambda name: fake)
    entry.main({"AGENT": agent})
    assert started == [agent]


@pytest.mark.parametrize("value", ["", "../x", "url_analyst.server"])
def test_rejects_anything_but_a_specialist(value):
    with pytest.raises(SystemExit, match="AGENT must be one of"):
        entry.main({"AGENT": value})


def test_module_entry_calls_main(monkeypatch):
    monkeypatch.setenv("AGENT", "")
    with pytest.raises(SystemExit, match="AGENT must be one of"):
        runpy.run_module("phish_agents", run_name="__main__")
