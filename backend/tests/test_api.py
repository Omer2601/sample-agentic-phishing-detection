# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json

import boto3
from backend_testkit import DIRECT_CALLER, OWNER_A, api_event, utcnow

from phish_backend.api import app
from phish_backend.common import store


def call(event):
    response = app.handler(event, None)
    body = response["body"]
    ctype = response["headers"]["Content-Type"]
    return response["statusCode"], (
        json.loads(body) if ctype.startswith("application/json") else body
    )


def test_health_needs_no_identity(aws):
    status, body = call(api_event("GET", "/health", caller="", sub=None))
    assert status == 200 and body == {"ok": True}


def test_anonymous_is_forbidden(aws):
    status, _ = call(
        api_event("POST", "/scan", body={"url": "https://a.example/"}, caller="", sub=None)
    )
    assert status == 403


def test_unknown_route_is_404(aws):
    assert call(api_event("GET", "/nope"))[0] == 404


def test_post_scan_queues_and_get_is_owner_scoped(aws):
    status, body = call(api_event("POST", "/scan", body={"url": "https://a.example/"}))
    assert status == 202 and body["status"] == "PENDING"
    scan_id = body["scan_id"]
    msgs = boto3.client("sqs", region_name="us-west-2").receive_message(QueueUrl=aws["queue_url"])[
        "Messages"
    ]
    assert json.loads(msgs[0]["Body"])["scan_id"] == scan_id
    status, got = call(api_event("GET", "/scans/{id}", path={"id": scan_id}))
    assert status == 200 and got["artifacts"] == {"screenshot": None}
    # The caller identity (account id, role name) is never returned; the row is still owned.
    assert "owner" not in got
    assert store.get_scan(scan_id).owner == OWNER_A
    assert call(api_event("GET", "/scans/{id}", path={"id": scan_id}, sub="user-b"))[0] == 404


def test_post_scan_validation(aws):
    status, body = call(api_event("POST", "/scan", body={"url": "ftp://x"}))
    assert status == 400 and "http://" in body["error"]
    assert call(api_event("POST", "/scan", body=None))[0] == 400
    event = api_event("POST", "/scan")
    event["body"] = "[1,2]"
    assert call(event)[0] == 400


def test_json_batch_cap_and_create(aws):
    urls = [f"https://h{i}.example/" for i in range(51)]
    assert call(api_event("POST", "/batches", body={"urls": urls}))[0] == 400
    status, body = call(api_event("POST", "/batches", body={"urls": urls[:3] + urls[:1]}))
    assert status == 202
    batch = store.get_batch(body["batch_id"])
    assert batch.total == 3 and batch.source == "api"


def test_upload_batch_returns_presigned_post_with_bound_owner(aws):
    status, body = call(
        api_event("POST", "/batches", body={"upload": True, "count": 200, "source": "ui"})
    )
    assert status == 202
    fields = body["upload_fields"]
    assert fields["x-amz-meta-owner"] == OWNER_A and fields["x-amz-meta-source"] == "ui"
    assert fields["key"].endswith(f"/{body['batch_id']}.csv")
    assert store.get_batch_item(body["batch_id"])["awaiting_upload"] is True
    assert (
        call(api_event("POST", "/batches", body={"upload": True, "count": 201, "source": "ui"}))[0]
        == 400
    )
    assert (
        call(api_event("POST", "/batches", body={"upload": True, "count": 1000, "source": "api"}))[
            0
        ]
        == 202
    )
    assert (
        call(api_event("POST", "/batches", body={"upload": True, "count": 1001, "source": "api"}))[
            0
        ]
        == 400
    )


def test_batch_detail_list_and_isolation(aws):
    _, body = call(
        api_event("POST", "/batches", body={"urls": ["https://a.example/", "https://b.example/"]})
    )
    batch_id = body["batch_id"]
    status, detail = call(
        api_event("GET", "/batches/{id}", path={"id": batch_id}, query={"limit": "1"})
    )
    assert (
        status == 200
        and detail["batch"]["total"] == 2
        and len(detail["items"]) == 1
        and detail["next"]
    )
    assert "findings" not in detail["items"][0]
    assert detail["invalid_rows"] == [] and detail["error"] is None
    status, page = call(
        api_event(
            "GET",
            "/batches/{id}",
            path={"id": batch_id},
            query={"limit": "1", "next": detail["next"]},
        )
    )
    assert status == 200 and len(page["items"]) == 1
    assert call(api_event("GET", "/batches/{id}", path={"id": batch_id}, sub="user-b"))[0] == 404
    status, listing = call(api_event("GET", "/batches"))
    assert [b["batch_id"] for b in listing["items"]] == [batch_id]


def test_history_bad_cursor_is_400(aws):
    assert call(api_event("GET", "/history", query={"next": "garbage"}))[0] == 400
    assert call(api_event("GET", "/history", query={"limit": "0"}))[0] == 400


def test_stats_and_export(aws):
    status, body = call(api_event("GET", "/stats", query={"range": "7d"}))
    assert status == 200 and body["range"] == "7d" and "totals" in body
    assert call(api_event("GET", "/stats", query={"range": "1y"}))[0] == 400
    response = app.handler(api_event("GET", "/stats/export", query={"range": "all"}), None)
    assert response["statusCode"] == 200
    assert response["headers"]["Content-Type"].startswith("text/csv")
    assert response["body"].startswith("scan_id,batch_id,url_defanged")


def test_direct_caller_cannot_forge_a_user(aws):
    _, body = call(
        api_event(
            "POST", "/scan", body={"url": "https://a.example/"}, caller=DIRECT_CALLER, sub="user-a"
        )
    )
    assert store.get_scan(body["scan_id"]).owner.endswith("assumed-role/ApiClientRole")


def test_internal_error_hides_detail(aws, monkeypatch):
    from phish_backend.api.routes import history

    def boom(req):
        raise RuntimeError("arn:aws:iam::123456789012:role/secret")

    monkeypatch.setitem(app.ROUTES, ("GET", "/history"), boom)
    status, body = call(api_event("GET", "/history"))
    assert status == 500 and "arn:" not in body["error"] and "Correlation ID" in body["error"]
    assert history  # imported module stays referenced


def test_malformed_path_ids_are_404(aws):
    for bad in ("../x", "a" * 65, "id with space", ""):
        for method, resource in (
            ("GET", "/scans/{id}"),
            ("GET", "/batches/{id}"),
            ("POST", "/scans/{id}/retry"),
            ("POST", "/batches/{id}/retry-failed"),
        ):
            assert call(api_event(method, resource, path={"id": bad}))[0] == 404, (resource, bad)


def test_proxy_call_without_user_sub_is_forbidden(aws):
    for sub in (None, "bad sub/../"):
        status, _ = call(api_event("GET", "/history", sub=sub))
        assert status == 403


def test_batch_p95_in_the_open_bucket_is_capped_and_flagged(aws):
    from backend_testkit import put_batch_for_tests

    put_batch_for_tests("b9", OWNER_A, total=2)
    boto3.resource("dynamodb", region_name="us-west-2").Table("phish-batches").update_item(
        Key={"batch_id": "b9"},
        UpdateExpression="SET #a = :one, #b = :one",
        ExpressionAttributeNames={"#a": "lat#40000", "#b": "lat#999999999"},
        ExpressionAttributeValues={":one": 1},
    )
    status, body = call(api_event("GET", "/batches/{id}", path={"id": "b9"}))
    assert status == 200
    assert body["p50_ms"] == 40000 and body["p95_ms"] == 120000
    assert body["p95_over_max"] is True


def test_batch_list_and_detail_carry_the_upload_lifecycle_fields(aws):
    """GET /batches and GET /batches/{id} expose awaiting_upload, split_at and error
    on every BatchRecord, so the console can stop polling a batch that is waiting
    on an upload that will never come or that failed to split."""
    _, body = call(api_event("POST", "/batches", body={"upload": True, "count": 3, "source": "ui"}))
    batch_id = body["batch_id"]
    _, listing = call(api_event("GET", "/batches"))
    (waiting,) = [b for b in listing["items"] if b["batch_id"] == batch_id]
    assert waiting["awaiting_upload"] is True
    assert waiting["split_at"] is None and waiting["error"] is None

    store.mark_batch_error(batch_id, "CSV was never uploaded", utcnow())
    _, listing = call(api_event("GET", "/batches"))
    (failed,) = [b for b in listing["items"] if b["batch_id"] == batch_id]
    assert failed["awaiting_upload"] is False
    assert failed["error"] == "CSV was never uploaded"
    assert failed["split_at"] and failed["completed_at"]
    _, detail = call(api_event("GET", "/batches/{id}", path={"id": batch_id}))
    assert detail["batch"]["error"] == "CSV was never uploaded"
    assert detail["error"] == "CSV was never uploaded"


def test_a_plain_json_batch_is_not_awaiting_an_upload(aws):
    _, body = call(api_event("POST", "/batches", body={"urls": ["https://a.example/"]}))
    _, detail = call(api_event("GET", "/batches/{id}", path={"id": body["batch_id"]}))
    assert detail["batch"]["awaiting_upload"] is False and detail["batch"]["error"] is None


def _complete_scan(scan_id, owner, matches=()):
    from phish_backend.common import scans

    scans.create_and_enqueue([scans.new_scan(owner, "https://a.example/", scan_id=scan_id)])
    boto3.resource("dynamodb", region_name="us-west-2").Table("phish-scans").update_item(
        Key={"scan_id": scan_id},
        UpdateExpression="SET memory_matches = :m",
        ExpressionAttributeValues={":m": list(matches)},
    )


def test_similar_scans_only_list_the_requesters_own_scans(aws):
    from backend_testkit import OWNER_B

    _complete_scan("a-old", OWNER_A)
    _complete_scan("b-old", OWNER_B)
    matches = [
        {"scan_id": "a-old", "summary": "hxxps://a[.]example/ | verdict=phishing | own"},
        {"scan_id": "b-old", "summary": "hxxps://b[.]example/ | verdict=phishing | other"},
        {"scan_id": "gone", "summary": "expired scan"},
        {"scan_id": None, "summary": "record without a scan id"},
        {"scan_id": "a-new", "summary": "this scan itself"},
    ]
    _complete_scan("a-new", OWNER_A, matches)
    status, got = call(api_event("GET", "/scans/{id}", path={"id": "a-new"}))
    assert status == 200
    assert got["similar_scans"] == [
        {"scan_id": "a-old", "summary": "hxxps://a[.]example/ | verdict=phishing | own"}
    ]
    raw = json.dumps(got)
    for leak in ("b-old", "other", "gone", "expired", "memory_matches", OWNER_B):
        assert leak not in raw


def test_similar_scans_isolated_for_the_other_owner_too(aws):
    from backend_testkit import OWNER_B

    _complete_scan("a-old", OWNER_A)
    _complete_scan(
        "b-new", OWNER_B, [{"scan_id": "a-old", "summary": "hxxps://a[.]example/ | owner a"}]
    )
    status, got = call(api_event("GET", "/scans/{id}", path={"id": "b-new"}, sub="user-b"))
    assert status == 200 and got["similar_scans"] == []
    assert "a-old" not in json.dumps(got)


def test_similar_scans_lookup_failure_hides_the_list(aws, monkeypatch):
    from botocore.exceptions import ClientError

    _complete_scan("a-old", OWNER_A)
    _complete_scan("a-new", OWNER_A, [{"scan_id": "a-old", "summary": "s"}])

    def fail(ids):
        raise ClientError({"Error": {"Code": "ProvisionedThroughputExceededException"}}, "Get")

    monkeypatch.setattr(store, "scan_owners", fail)
    status, got = call(api_event("GET", "/scans/{id}", path={"id": "a-new"}))
    assert status == 200 and got["similar_scans"] == []


def test_other_routes_never_carry_memory_matches(aws):
    _complete_scan("a-new", OWNER_A, [{"scan_id": "x-other", "summary": "s"}])
    status, body = call(api_event("GET", "/history"))
    assert status == 200 and "x-other" not in json.dumps(body)


def _time_batch_scans(batch_id, durations_ms):
    """Give a batch's scans these total_ms values and its counters the matching buckets."""
    from phish_backend.stats.updates import lat_bucket

    ddb = boto3.resource("dynamodb", region_name="us-west-2")
    scans_page, _ = store.scans_for_batch(batch_id, 200, None)
    for scan, ms in zip(scans_page, durations_ms, strict=True):
        ddb.Table("phish-scans").update_item(
            Key={"scan_id": scan.scan_id},
            UpdateExpression="SET total_ms = :t",
            ExpressionAttributeValues={":t": ms},
        )
    for ms in durations_ms:
        ddb.Table("phish-batches").update_item(
            Key={"batch_id": batch_id},
            UpdateExpression="ADD #b :one, sum_scan_ms :t",
            ExpressionAttributeNames={"#b": f"lat#{lat_bucket(ms)}"},
            ExpressionAttributeValues={":one": 1, ":t": ms},
        )


def _timed_batch(durations_ms):
    urls = [f"https://u{i}.example/" for i in range(len(durations_ms))]
    _, body = call(api_event("POST", "/batches", body={"urls": urls}))
    _time_batch_scans(body["batch_id"], durations_ms)
    return body["batch_id"]


def test_batch_percentiles_are_exact_when_the_page_holds_every_timed_scan(aws):
    # 41 s sits in the 40 to 60 s bucket; the tile used to show the 60 s edge as the p50.
    batch_id = _timed_batch([33_000, 41_000, 44_000, 52_000, 125_000])
    status, body = call(api_event("GET", "/batches/{id}", path={"id": batch_id}))
    assert status == 200
    assert body["p50_ms"] == 44_000 and body["p50_bound"] is False
    assert body["p95_ms"] == 125_000 and body["p95_bound"] is False
    assert body["p95_over_max"] is False and body["p50_over_max"] is False


def test_batch_percentiles_are_flagged_as_bounds_when_the_page_is_partial(aws):
    batch_id = _timed_batch([33_000, 41_000, 44_000])
    status, body = call(
        api_event("GET", "/batches/{id}", path={"id": batch_id}, query={"limit": "1"})
    )
    assert status == 200 and body["next"]
    assert body["p50_ms"] == 60_000 and body["p50_bound"] is True
    assert body["p95_ms"] == 60_000 and body["p95_bound"] is True


def test_a_single_timed_scan_reports_its_own_duration(aws):
    from backend_testkit import put_batch_for_tests

    put_batch_for_tests("b1", OWNER_A, total=1)
    boto3.resource("dynamodb", region_name="us-west-2").Table("phish-batches").update_item(
        Key={"batch_id": "b1"},
        UpdateExpression="SET #b = :one, sum_scan_ms = :t",
        ExpressionAttributeNames={"#b": "lat#60000"},
        ExpressionAttributeValues={":one": 1, ":t": 41_500},
    )
    status, body = call(api_event("GET", "/batches/{id}", path={"id": "b1"}))
    assert status == 200
    assert body["p50_ms"] == 41_500 and body["p95_ms"] == 41_500
    assert body["p50_bound"] is False and body["p95_bound"] is False


def test_every_json_response_carries_the_disclaimer_except_health(aws):
    from phish_contracts.disclaimer import DISCLAIMER_TEXT

    _, created = call(api_event("POST", "/scan", body={"url": "https://a.example/"}))
    assert created["disclaimer"] == DISCLAIMER_TEXT
    _, got = call(api_event("GET", "/scans/{id}", path={"id": created["scan_id"]}))
    assert got["disclaimer"] == DISCLAIMER_TEXT
    _, listing = call(api_event("GET", "/history"))
    assert listing["disclaimer"] == DISCLAIMER_TEXT
    _, stats = call(api_event("GET", "/stats", query={"range": "7d"}))
    assert stats["disclaimer"] == DISCLAIMER_TEXT
    # Errors carry it too, so a client that logs bodies always sees the notice.
    _, missing = call(api_event("GET", "/nope"))
    assert missing["disclaimer"] == DISCLAIMER_TEXT and "error" in missing
    _, health = call(api_event("GET", "/health", caller="", sub=None))
    assert "disclaimer" not in health


def test_export_csv_route_ends_every_row_with_the_disclaimer(aws):
    import csv
    import io

    from phish_contracts.disclaimer import DISCLAIMER_TEXT

    call(api_event("POST", "/scan", body={"url": "https://a.example/"}))
    response = app.handler(api_event("GET", "/stats/export", query={"range": "all"}), None)
    rows = list(csv.reader(io.StringIO(response["body"])))
    assert rows[0][-1] == "disclaimer" and len(rows) >= 2
    assert all(len(r) == len(rows[0]) and r[-1] == DISCLAIMER_TEXT for r in rows[1:])
