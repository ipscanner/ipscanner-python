from __future__ import annotations

import json

import httpx
import pytest
from conftest import json_response, make_async_client, make_client

import ipscanner

LINES = [
    {"type": "meta", "total": 3, "processed": 1, "metered": 3},
    {"type": "result", "input": "1.1.1.1", "ip": "1.1.1.1", "verdict": "clean", "score": 98},
    {"type": "error", "index": 1, "input": "10.0.0.1", "reason": "reserved"},
    {"type": "result", "index": 2, "input": "8.8.8.8", "ip": "8.8.8.8", "isTorExit": True},
    {"type": "done", "reason": "complete", "processed": 2, "failed": 1, "total": 3},
]


def ndjson(lines: list[dict]) -> httpx.Response:
    text = "\n".join(json.dumps(line) for line in lines) + "\n\n"
    return httpx.Response(200, text=text, headers={"content-type": "application/x-ndjson"})


def check_events(events: list[dict]) -> None:
    assert [e["type"] for e in events] == ["meta", "result", "error", "result", "done"]
    first = events[1]
    assert first["index"] == 0
    assert first["anonymized"] is False
    assert first["confidence"] == 0.0
    assert first["asn"] == ""
    assert events[2]["index"] == 1
    assert events[3]["isTorExit"] is True
    assert events[-1]["complete"] is True
    assert "complete" not in events[0]


def test_stream_events() -> None:
    client, rec = make_client(lambda _: ndjson(LINES))
    events = list(client.bulk.stream(["1.1.1.1", "10.0.0.1", "8.8.8.8", "1.1.1.1"]))
    check_events(events)
    assert rec.last.url.path == "/v1/ip/bulk"
    assert rec.last.extensions["timeout"]["read"] == 300.0


def test_stream_done_incomplete_when_deadline_hit() -> None:
    lines = [
        {"type": "meta", "total": 5},
        {"type": "done", "reason": "complete", "processed": 2, "total": 5},
    ]
    client, _ = make_client(lambda _: ndjson(lines))
    done = list(client.bulk.stream(input="x"))[-1]
    assert done["complete"] is False


def test_stream_done_quota_exceeded() -> None:
    lines = [{"type": "done", "reason": "quota_exceeded", "processed": 3, "total": 3}]
    client, _ = make_client(lambda _: ndjson(lines))
    assert list(client.bulk.stream(["1.1.1.1"]))[-1]["complete"] is False


def test_stream_pre_stream_error() -> None:
    client, _ = make_client(json_response(429, {"error": "rate_limit_exceeded", "retryAfter": 5}))
    with pytest.raises(ipscanner.RateLimitError) as info:
        list(client.bulk.stream(["1.1.1.1"]))
    assert info.value.retry_after == 5


def test_stream_requires_input() -> None:
    client, _ = make_client(json_response())
    with pytest.raises(ValueError):
        client.bulk.stream()


def test_stream_locked_lines() -> None:
    lines = [
        {"type": "meta", "total": 2, "metered": 2, "planRequired": "Starter"},
        {
            "type": "result",
            "ip": "1.1.1.1",
            "classification": "hosting",
            "score": None,
            "grade": None,
            "verdict": None,
            "vpnProvider": None,
            "locked": ["score", "grade", "verdict", "vpnProvider"],
        },
        {"type": "result", "index": 1, "ip": "185.65.135.1", "vpnProvider": "Mullvad"},
        {"type": "done", "reason": "complete", "processed": 2, "total": 2},
    ]
    client, _ = make_client(lambda _: ndjson(lines))
    meta, locked, unlocked, done = list(client.bulk.stream(["1.1.1.1", "185.65.135.1"]))
    assert meta["planRequired"] == "Starter"
    assert (locked["score"], locked["grade"], locked["verdict"], locked["vpnProvider"]) == (
        0,
        "",
        "",
        "",
    )
    assert locked["locked"] == ["score", "grade", "verdict", "vpnProvider"]
    assert unlocked["vpnProvider"] == "Mullvad"
    assert "locked" not in unlocked
    assert unlocked["planRequired"] == ""
    assert done["complete"] is True


@pytest.mark.anyio
async def test_async_stream_events() -> None:
    client, _ = make_async_client(lambda _: ndjson(LINES))
    async with client:
        events = [event async for event in client.bulk.stream(["1.1.1.1"])]
    check_events(events)


@pytest.mark.anyio
async def test_async_stream_pre_stream_error() -> None:
    client, _ = make_async_client(json_response(400, {"error": "bad_request", "message": "no"}))
    with pytest.raises(ipscanner.APIError) as info:
        async for _ in client.bulk.stream(["x"]):
            pass
    assert info.value.code == "bad_request"
