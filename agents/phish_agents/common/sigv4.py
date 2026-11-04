# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""SigV4 request signing as an httpx.Auth, for MCP calls to an IAM-authorized AgentCore Gateway.

botocore already implements SigV4, so no extra signing package is needed. Credentials are read
per request so the runtime role's rotating session credentials are always current.
"""

from __future__ import annotations

from collections.abc import Callable, Generator

import boto3
import httpx
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

SERVICE = "bedrock-agentcore"
# Only these request headers are signed. The transport adds others (MCP session and protocol
# headers, user agent) that the service does not require in the signature.
_SIGNED_HEADERS = ("content-type",)


def _default_credentials() -> Credentials | None:
    return boto3.Session().get_credentials()


class SigV4HttpxAuth(httpx.Auth):
    requires_request_body = True

    def __init__(
        self,
        region: str,
        *,
        service: str = SERVICE,
        credentials_provider: Callable[[], Credentials | None] = _default_credentials,
    ) -> None:
        self.region, self.service = region, service
        self._credentials_provider = credentials_provider

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response]:
        credentials = self._credentials_provider()
        if credentials is None:
            raise RuntimeError("SigV4: no AWS credentials available to sign the gateway request")
        headers = {k: request.headers[k] for k in _SIGNED_HEADERS if k in request.headers}
        headers["host"] = request.url.netloc.decode("ascii")
        aws_request = AWSRequest(
            method=request.method, url=str(request.url), data=request.content, headers=headers
        )
        SigV4Auth(credentials.get_frozen_credentials(), self.service, self.region).add_auth(
            aws_request
        )
        for name in ("Authorization", "X-Amz-Date", "X-Amz-Security-Token"):
            if name in aws_request.headers:
                request.headers[name] = aws_request.headers[name]
        yield request
