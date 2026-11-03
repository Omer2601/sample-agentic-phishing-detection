# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Shared constants and event builders for backend tests."""

import json

from phish_backend.common import store
from phish_backend.common.timeutil import utcnow
from phish_contracts.models import BatchRecord, BatchSource

ACCOUNT = "123456789012"
PROXY_CALLER = f"arn:aws:sts::{ACCOUNT}:assumed-role/ProxyRole/web-session"
DIRECT_CALLER = f"arn:aws:sts::{ACCOUNT}:assumed-role/ApiClientRole/cli"
OWNER_A = f"arn:aws:sts::{ACCOUNT}:assumed-role/ProxyRole:user-a"
OWNER_B = f"arn:aws:sts::{ACCOUNT}:assumed-role/ProxyRole:user-b"


def api_event(
    method, resource, *, path=None, query=None, body=None, sub="user-a", caller=PROXY_CALLER
):
    headers = {"x-console-user-sub": sub} if sub else {}
    return {
        "httpMethod": method,
        "resource": resource,
        "pathParameters": path,
        "queryStringParameters": query,
        "headers": headers,
        "body": json.dumps(body) if body is not None else None,
        "isBase64Encoded": False,
        "requestContext": {"identity": {"userArn": caller}},
    }


__all__ = ["utcnow"]


def put_batch_for_tests(batch_id, owner, *, total):
    store.put_batch(
        BatchRecord(
            batch_id=batch_id, owner=owner, source=BatchSource.API, total=total, created_at=utcnow()
        ),
        awaiting_upload=False,
    )


class FailingSqs:
    """An SQS client whose sends always fail, for the stuck-PENDING paths."""

    def __init__(self, raise_error=False):
        self.raise_error = raise_error
        self.sent = 0

    def send_message_batch(self, QueueUrl, Entries):  # noqa: N803 - boto3 parameter names
        self.sent += 1
        if self.raise_error:
            from botocore.exceptions import ClientError

            raise ClientError({"Error": {"Code": "InternalError", "Message": "x"}}, "Send")
        return {
            "Failed": [
                {"Id": e["Id"], "Code": "InternalError", "SenderFault": False} for e in Entries
            ]
        }


def patch_sqs(monkeypatch, fake):
    from phish_backend.common import clients

    def factory():
        return fake

    factory.cache_clear = lambda: None  # clients.reset() clears every cached client
    monkeypatch.setattr(clients, "sqs", factory)
