# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Token cost from pricing.json. Token cost only, by design (spec section 2.5).

pricing.json is keyed by the model id without its inference profile prefix. resolve_rates
maps any id a deploy can use to its rates: `global.<model>` gets the global rate, a
geographic profile (`us.`, `eu.`, `apac.`, `au.`, `jp.`) or a bare model id gets the
in-Region rate. Anything else (a new prefix, an unknown model, an ARN) has no price: it is
logged and reported as unpriced, never silently counted as free.
"""

import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from decimal import Decimal
from importlib import resources

from phish_contracts.models import Usage

logger = logging.getLogger(__name__)

_DATA = json.loads(resources.files("phish_backend.common").joinpath("pricing.json").read_text())
_MODELS: dict[str, dict[str, dict[str, float]]] = _DATA["models"]
_GEO_PREFIXES = frozenset(_DATA["geo_prefixes"])
PRICES_CHECKED: str = _DATA["checked"]
_MILLION = Decimal(1_000_000)
_QUANTUM = Decimal("0.000001")


@dataclass(frozen=True)
class ScanPrice:
    cost: Decimal
    # Model ids with no rate in pricing.json. Their tokens are counted but not in `cost`,
    # so `cost` is a lower bound whenever this is not empty.
    unpriced_models: list[str] = field(default_factory=list)


def resolve_rates(model_id: str) -> dict[str, float] | None:
    """USD per 1M tokens (input, output, cache_read, cache_write) for a model id, or None."""
    prefix, _, rest = model_id.partition(".")
    if prefix == "global":
        scope, base = "global", rest
    elif prefix in _GEO_PREFIXES:
        scope, base = "regional", rest
    else:
        scope, base = "regional", model_id
    rates = _MODELS.get(base)
    return None if rates is None else rates[scope]


def price_usage(usage: Usage) -> Decimal | None:
    rates = resolve_rates(usage.model_id)
    if rates is None:
        return None
    # input_tokens counts every prompt token; the cached ones are billed at their own rates.
    plain = max(usage.input_tokens - usage.cache_read_tokens - usage.cache_write_tokens, 0)
    return (
        Decimal(plain) * Decimal(str(rates["input"]))
        + Decimal(usage.cache_read_tokens) * Decimal(str(rates["cache_read"]))
        + Decimal(usage.cache_write_tokens) * Decimal(str(rates["cache_write"]))
        + Decimal(usage.output_tokens) * Decimal(str(rates["output"]))
    ) / _MILLION


def price_scan(usages: Iterable[Usage]) -> ScanPrice:
    total = Decimal(0)
    unpriced: list[str] = []
    for usage in usages:
        priced = price_usage(usage)
        if priced is None:
            if usage.model_id not in unpriced:
                unpriced.append(usage.model_id)
                logger.warning(
                    "no price for model %s; the scan cost is marked unknown (add it to "
                    "pricing.json)",
                    usage.model_id,
                )
            continue
        total += priced
    return ScanPrice(cost=total.quantize(_QUANTUM), unpriced_models=unpriced)


def scan_cost(usages: Iterable[Usage]) -> Decimal:
    return price_scan(usages).cost
