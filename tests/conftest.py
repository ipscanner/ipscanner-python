from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

import ipscanner


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IPSCANNER_API_KEY", raising=False)
    monkeypatch.delenv("IPSCANNER_API_URL", raising=False)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_async_sleep(_: float) -> None:
        return None

    monkeypatch.setattr("ipscanner._client.time.sleep", lambda _: None)
    monkeypatch.setattr("ipscanner._client.asyncio.sleep", fake_async_sleep)


Handler = Callable[[httpx.Request], httpx.Response]


class Recorder:
    def __init__(self, handler: Handler) -> None:
        self.handler = handler
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        request.read()
        self.requests.append(request)
        return self.handler(request)

    @property
    def last(self) -> httpx.Request:
        return self.requests[-1]

    def body(self, index: int = -1) -> Any:
        return json.loads(self.requests[index].content)


def json_response(status: int = 200, data: Any = None, **kwargs: Any) -> Handler:
    return lambda _: httpx.Response(status, json=data if data is not None else {}, **kwargs)


def make_client(handler: Handler, **kwargs: Any) -> tuple[ipscanner.Client, Recorder]:
    rec = Recorder(handler)
    http = httpx.Client(transport=httpx.MockTransport(rec))
    return ipscanner.Client(http_client=http, **kwargs), rec


def make_async_client(handler: Handler, **kwargs: Any) -> tuple[ipscanner.AsyncClient, Recorder]:
    rec = Recorder(handler)
    http = httpx.AsyncClient(transport=httpx.MockTransport(rec))
    return ipscanner.AsyncClient(http_client=http, **kwargs), rec
