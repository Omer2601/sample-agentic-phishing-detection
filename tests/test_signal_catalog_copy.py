# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The web app ships its own copy of the signal catalog; it must match the contracts one."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_web_signal_catalog_is_a_byte_identical_copy():
    source = ROOT / "contracts" / "phish_contracts" / "signal_catalog.json"
    copy = ROOT / "web" / "src" / "lib" / "signalCatalog.json"
    assert copy.read_bytes() == source.read_bytes(), (
        "web/src/lib/signalCatalog.json differs from contracts/phish_contracts/"
        "signal_catalog.json; copy the contracts file over the web one"
    )
