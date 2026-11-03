# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""API Lambda entry point: resolve the owner, dispatch on (method, resource)."""

import logging

from phish_backend.api.http import ApiError, json_response, request_from_event
from phish_backend.api.routes import (
    batches,
    health,
    history,
    live_feed,
    reports,
    retry,
    scans,
    stats,
)
from phish_backend.common import identity, log, store

logger = logging.getLogger(__name__)

ROUTES = {
    ("POST", "/scan"): scans.create,
    ("GET", "/scans/lookup"): scans.lookup,
    ("GET", "/scans/{id}"): scans.get,
    ("GET", "/scans/{id}/report"): reports.scan_report,
    ("POST", "/scans/{id}/retry"): retry.retry_scan,
    ("POST", "/batches/{id}/retry-failed"): retry.retry_failed_in_batch,
    ("POST", "/batches"): batches.create,
    ("GET", "/batches"): batches.list_batches,
    ("GET", "/batches/{id}"): batches.get,
    ("GET", "/batches/{id}/report"): reports.batch_report,
    ("GET", "/history"): history.list_history,
    ("GET", "/stats"): stats.get,
    ("GET", "/stats/export"): stats.export,
    ("GET", "/feed/phishing"): live_feed.get,
}
PUBLIC_ROUTES = {("GET", "/health"): health.get}


def handler(event, context):
    log.configure()
    key = (event.get("httpMethod", ""), event.get("resource", ""))
    try:
        if key in PUBLIC_ROUTES:
            return PUBLIC_ROUTES[key](request_from_event(event, owner=""))
        route = ROUTES.get(key)
        if route is None:
            raise ApiError(404, "not found")
        owner = identity.resolve_owner(event)
        if owner == "anonymous":
            raise ApiError(403, "forbidden")
        return route(request_from_event(event, owner, console=identity.is_console(event)))
    except ApiError as exc:
        return json_response(exc.status, {"error": exc.message})
    except store.BadCursor:
        return json_response(400, {"error": "invalid pagination cursor"})
    except Exception as exc:  # noqa: BLE001 - the only place an unexpected error becomes a 500
        ref = log.correlation_ref(f"{key[0]} {key[1]}", exc)
        return json_response(500, {"error": f"Internal error. Correlation ID: {ref}"})
