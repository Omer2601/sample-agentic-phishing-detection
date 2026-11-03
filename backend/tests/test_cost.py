# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json
import logging
from decimal import Decimal
from importlib import resources

import pytest

from phish_backend.common import cost
from phish_contracts.models import Usage

# AWS Price List API (AmazonBedrockFoundationModels, on-demand), read 2026-10-21.
GLOBAL = {"opus": (4.00, 20.00), "sonnet": (2.00, 10.00), "haiku": (1.00, 5.00)}
REGIONAL = {"opus": (4.40, 22.00), "sonnet": (2.20, 11.00), "haiku": (1.10, 5.50)}
BASE = {
    "opus": "anthropic.claude-opus-5-5",
    "sonnet": "anthropic.claude-sonnet-5-5",
    "haiku": "anthropic.claude-haiku-4-5-20251001-v1:0",
}
PREFIXES = ["us.", "eu.", "apac.", "au.", "jp.", ""]


def pricing():
    return json.loads(resources.files("phish_backend.common").joinpath("pricing.json").read_text())


def one_million_each(model_id: str) -> Usage:
    return Usage(input_tokens=1_000_000, output_tokens=1_000_000, model_id=model_id)


def test_pricing_records_its_source_and_check_date():
    data = pricing()
    assert data["source"].startswith("AWS Price List API")
    assert data["checked"] == "2026-10-21"
    assert set(data["geo_prefixes"]) == {"us", "eu", "apac", "au", "jp"}


@pytest.mark.parametrize("model", sorted(BASE))
def test_global_profile_gets_the_global_rate(model):
    rate_in, rate_out = GLOBAL[model]
    priced = cost.price_usage(one_million_each(f"global.{BASE[model]}"))
    assert priced == Decimal(str(rate_in)) + Decimal(str(rate_out))


@pytest.mark.parametrize("prefix", PREFIXES)
@pytest.mark.parametrize("model", sorted(BASE))
def test_geo_profiles_and_bare_ids_get_the_in_region_rate(model, prefix):
    # The report that found this: au.anthropic.claude-opus-5-5 had no price and cost $0.
    rate_in, rate_out = REGIONAL[model]
    priced = cost.price_usage(one_million_each(f"{prefix}{BASE[model]}"))
    assert priced == Decimal(str(rate_in)) + Decimal(str(rate_out))


def test_the_au_opus_tokens_from_the_report_are_priced():
    usage = Usage(input_tokens=24_784, output_tokens=1_635, model_id="au.anthropic.claude-opus-5-5")
    # 24,784 x $4.40 + 1,635 x $22.00 per 1M tokens.
    assert cost.price_usage(usage) == Decimal("0.1450196")


@pytest.mark.parametrize(
    "model_id",
    [
        "x.unknown",
        "ca.anthropic.claude-opus-5-5",
        "us.anthropic.claude-future-9",
        "global.anthropic.claude-future-9",
        "arn:aws:bedrock:us-west-2:123456789012:application-inference-profile/abc",
    ],
)
def test_unknown_ids_have_no_price(model_id):
    assert cost.resolve_rates(model_id) is None
    assert cost.price_usage(one_million_each(model_id)) is None


def test_unknown_model_is_flagged_with_one_warning_and_not_priced_as_zero(caplog):
    usages = [
        Usage(input_tokens=1000, output_tokens=10, model_id="us.anthropic.claude-opus-5-5"),
        Usage(input_tokens=5, output_tokens=5, model_id="x.unknown"),
        Usage(input_tokens=7, output_tokens=7, model_id="x.unknown"),
    ]
    with caplog.at_level(logging.WARNING):
        priced = cost.price_scan(usages)
    assert priced.unpriced_models == ["x.unknown"]
    assert priced.cost == cost.price_usage(usages[0]).quantize(Decimal("0.000001"))
    assert sum("x.unknown" in r.getMessage() for r in caplog.records) == 1


def test_fully_priced_scan_has_no_unpriced_models():
    priced = cost.price_scan([one_million_each("au.anthropic.claude-opus-5-5")])
    assert priced.unpriced_models == [] and priced.cost == Decimal("26.400000")


@pytest.mark.parametrize(
    ("model_id", "expected"),
    [
        # 1M plain at $2.00, 1M cache reads at $0.10, 1M cache writes at $2.50.
        ("global.anthropic.claude-sonnet-5-5", Decimal("4.60")),
        # In-Region: $2.20, $0.11, $2.75.
        ("us.anthropic.claude-sonnet-5-5", Decimal("5.06")),
    ],
)
def test_cache_reads_and_writes_are_priced_at_their_own_rates(model_id, expected):
    usage = Usage(
        input_tokens=3_000_000,
        output_tokens=0,
        model_id=model_id,
        cache_read_tokens=1_000_000,
        cache_write_tokens=1_000_000,
    )
    assert cost.price_usage(usage) == expected
