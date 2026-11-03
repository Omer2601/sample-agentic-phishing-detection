# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import pytest
from botocore.exceptions import ClientError, ReadTimeoutError

from phish_backend.common import aws_retry


def client_error(code, message="x", retry_after=None):
    headers = {"retry-after": retry_after} if retry_after is not None else {}
    return ClientError(
        {"Error": {"Code": code, "Message": message}, "ResponseMetadata": {"HTTPHeaders": headers}},
        "InvokeHarness",
    )


class Flaky:
    def __init__(self, errors, result="ok"):
        self.errors = list(errors)
        self.calls = 0
        self.result = result

    def __call__(self):
        self.calls += 1
        if self.errors:
            raise self.errors.pop(0)
        return self.result


def test_success_is_called_once():
    fn = Flaky([])
    assert aws_retry.invoke_with_throttle_retry(fn, what="t", sleep=lambda s: None) == "ok"
    assert fn.calls == 1


@pytest.mark.parametrize("code", sorted(aws_retry.THROTTLE_ERROR_CODES))
def test_each_throttle_code_is_retried(code):
    fn = Flaky([client_error(code)])
    assert aws_retry.invoke_with_throttle_retry(fn, what="t", sleep=lambda s: None) == "ok"
    assert fn.calls == 2


def test_non_throttle_error_raised_immediately():
    fn = Flaky([client_error("ValidationException")])
    with pytest.raises(ClientError):
        aws_retry.invoke_with_throttle_retry(fn, what="t", sleep=lambda s: None)
    assert fn.calls == 1


def test_read_timeout_is_never_retried():
    fn = Flaky([ReadTimeoutError(endpoint_url="https://x")])
    with pytest.raises(ReadTimeoutError):
        aws_retry.invoke_with_throttle_retry(fn, what="t", sleep=lambda s: None)
    assert fn.calls == 1


def test_attempts_are_bounded():
    fn = Flaky([client_error("ThrottlingException")] * 10)
    with pytest.raises(ClientError):
        aws_retry.invoke_with_throttle_retry(fn, what="t", sleep=lambda s: None)
    assert fn.calls == aws_retry.MAX_ATTEMPTS


def test_retry_after_is_honoured():
    slept = []
    fn = Flaky([client_error("ThrottlingException", retry_after="2.5")])
    aws_retry.invoke_with_throttle_retry(fn, what="t", sleep=slept.append)
    assert slept == [2.5]


def test_runtime_not_ready_is_retried_but_mid_flight_error_is_not():
    ready = client_error("RuntimeClientError", "Runtime health check failed")
    assert aws_retry.is_runtime_not_ready(ready)
    assert not aws_retry.is_runtime_not_ready(client_error("RuntimeClientError", "tool crashed"))


class Remaining:
    def __init__(self, ms):
        self.ms = ms

    def get_remaining_time_in_millis(self):
        return self.ms


def test_no_sleep_without_room_for_another_full_harness_call():
    # 280 s left is less than the 270 s harness read timeout plus the 15 s margin.
    slept = []
    aws_retry.set_lambda_context(Remaining(280_000))
    try:
        fn = Flaky([client_error("ThrottlingException")])
        with pytest.raises(aws_retry.ThrottleDeferred):
            aws_retry.invoke_with_throttle_retry(fn, what="t", sleep=slept.append)
    finally:
        aws_retry.set_lambda_context(None)
    assert slept == [] and fn.calls == 1


def test_sleep_is_capped_by_headroom_after_the_next_call():
    slept = []
    aws_retry.set_lambda_context(Remaining(290_000))
    try:
        fn = Flaky([client_error("ThrottlingException", retry_after="20")])
        aws_retry.invoke_with_throttle_retry(fn, what="t", sleep=slept.append)
    finally:
        aws_retry.set_lambda_context(None)
    assert slept == [pytest.approx(5.0)]


SESSION_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")


def test_session_id_is_per_attempt_and_valid():
    scan_id = "0b8f5f3e-5d0a-4b8e-9a3c-2f1d7c9e4a11"
    assert aws_retry.scan_session_id(scan_id, 1) == f"{scan_id}-a1"
    assert aws_retry.scan_session_id(scan_id, 2) == f"{scan_id}-a2"
    for sid in (aws_retry.scan_session_id("abc", 1), aws_retry.scan_session_id("a/b_c.d", 3)):
        assert 33 <= len(sid) <= 256 and set(sid) <= SESSION_CHARS
    assert aws_retry.scan_session_id("abc", 1).endswith("-a1")
    assert aws_retry.scan_session_id("abc", 1) != aws_retry.scan_session_id("abc", 2)
    assert len(aws_retry.scan_session_id("x" * 300, 12)) <= 256
    assert aws_retry.scan_session_id("x" * 300, 12).endswith("-a12")


def test_stop_session_never_raises():
    class Boom:
        def stop_runtime_session(self, **kwargs):
            raise client_error("AccessDeniedException")

    assert aws_retry.stop_harness_session(Boom(), "scan-" + "x" * 40, "arn") is False


def test_stop_session_swallows_connection_errors():
    from botocore.exceptions import EndpointConnectionError

    class Offline:
        def stop_runtime_session(self, **kwargs):
            raise EndpointConnectionError(endpoint_url="https://x")

    assert aws_retry.stop_harness_session(Offline(), "scan-" + "x" * 40, "arn") is False
