# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import asyncio

from phish_agents.common.remote_tools import settle_capture


async def test_settle_waits_for_a_capture_still_running():
    done = []

    async def capture():
        await asyncio.sleep(0.05)
        done.append(True)

    task = asyncio.ensure_future(capture())
    await settle_capture(task, 2.0)
    assert done == [True] and task.done() and not task.cancelled()


async def test_settle_cancels_a_capture_past_its_time():
    task = asyncio.ensure_future(asyncio.sleep(30))
    await settle_capture(task, 0.05)
    await asyncio.sleep(0)
    assert task.cancelled()


async def test_settle_consumes_a_failed_capture():
    async def capture():
        raise RuntimeError("browser gone")

    task = asyncio.ensure_future(capture())
    await settle_capture(task, 1.0)
    assert isinstance(task.exception(), RuntimeError)


async def test_one_capture_serves_every_tool_call():
    runs = []

    async def capture():
        runs.append(1)
        await asyncio.sleep(0.02)
        return {"ok": True}

    task = asyncio.ensure_future(capture())
    first, second = await asyncio.gather(asyncio.shield(task), asyncio.shield(task))
    await settle_capture(task, 1.0)
    assert runs == [1] and first == second == {"ok": True}


class _Body:
    def __init__(self, url: str, delay_s: float, text: str = "x", error: bool = False) -> None:
        self.url, self.delay_s, self.body, self.error = url, delay_s, text, error

    async def text(self) -> str:
        await asyncio.sleep(self.delay_s)
        if self.error:
            raise RuntimeError("gone")
        return self.body


async def test_script_bodies_are_read_concurrently_and_cut_at_the_deadline():
    import time

    from phish_agents.code_analyst.capture import _script_bodies

    responses = [_Body(f"https://a.example/{i}.js", 0.3, text=f"b{i}") for i in range(10)]
    responses.append(_Body("https://a.example/slow.js", 5.0))
    responses.append(_Body("https://a.example/broken.js", 0.0, error=True))
    started = time.monotonic()
    bodies = await _script_bodies(responses, time.monotonic() + 1.0)
    elapsed = time.monotonic() - started
    assert 0.9 <= elapsed < 1.5  # ten 0.3 s reads in parallel, then the slow one is cut
    assert bodies == {f"https://a.example/{i}.js": f"b{i}" for i in range(10)}
    assert await _script_bodies([], time.monotonic() + 1.0) == {}
