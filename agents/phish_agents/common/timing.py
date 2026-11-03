# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Per-call timing. Every AgentCore, model, browser and WHOIS call becomes one Call row."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime

from phish_contracts.models import Call, CallKind, Usage


@dataclass
class CallHandle:
    status: str = "ok"
    usage: Usage | None = None


class CallRecorder:
    def __init__(self) -> None:
        self.calls: list[Call] = []

    @contextmanager
    def record(
        self, kind: CallKind, name: str, *, keep_cancelled: bool = True
    ) -> Iterator[CallHandle]:
        """Record the wrapped call as one Call row; any exception marks it ``error``.

        With ``keep_cancelled=False`` a call cancelled before it finished leaves no row: for
        work started speculatively (an eager lookup the model may never ask for), the
        cancellation is not a failure and the call never served the scan.
        """
        handle = CallHandle()
        started_at = datetime.now(UTC)
        t0 = time.monotonic()
        cancelled = False
        try:
            yield handle
        except asyncio.CancelledError:
            cancelled = True
            handle.status = "error"
            raise
        except BaseException:
            handle.status = "error"
            raise
        finally:
            if keep_cancelled or not cancelled:
                self.calls.append(
                    Call(
                        kind=kind,
                        name=name,
                        started_at=started_at,
                        duration_ms=int((time.monotonic() - t0) * 1000),
                        status=handle.status,
                        usage=handle.usage,
                    )
                )
