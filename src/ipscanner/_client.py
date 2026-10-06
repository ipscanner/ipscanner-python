from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Iterator
from types import TracebackType
from typing import Any

import httpx

from . import _resources as r
from ._base import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT,
    RETRY_STATUSES,
    BaseClient,
    Request,
    parse_stream_line,
)
from ._errors import connection_error, error_from_response


class Client(BaseClient):
    """Synchronous IPScanner API client."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        http_client: httpx.Client | None = None,
    ) -> None:
        super().__init__(api_key, base_url, timeout, max_retries)
        self._owns_http = http_client is None
        self._http = http_client if http_client is not None else httpx.Client()
        self.ip = r.IP(self)
        self.bulk = r.Bulk(self)
        self.agentscan = r.Agentscan(self)
        self.provenance = r.Provenance(self)
        self.account = r.Account(self)
        self.asn_directory = r.AsnDirectory(self)
        self.crawlers = r.Crawlers(self)

    def close(self) -> None:
        """Close the underlying HTTP client if this client created it."""
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _request(self, req: Request) -> Any:
        kwargs = self._build(req)
        attempt = 0
        while True:
            try:
                response = self._http.request(**kwargs)
            except httpx.TransportError as exc:
                if self._can_retry(req, attempt):
                    time.sleep(self._backoff(attempt))
                    attempt += 1
                    continue
                raise connection_error(exc) from exc
            if response.status_code in RETRY_STATUSES and self._can_retry(req, attempt):
                response.close()
                time.sleep(self._backoff(attempt))
                attempt += 1
                continue
            return self._parse(req, response)

    def _stream(self, req: Request) -> Iterator[Any]:
        kwargs = self._build(req)
        try:
            with self._http.stream(**kwargs) as response:
                if response.status_code >= 400:
                    response.read()
                    raise error_from_response(response)
                for line in response.iter_lines():
                    event = parse_stream_line(line)
                    if event is not None:
                        yield event
        except httpx.TransportError as exc:
            raise connection_error(exc) from exc


class AsyncClient(BaseClient):
    """Asynchronous IPScanner API client."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(api_key, base_url, timeout, max_retries)
        self._owns_http = http_client is None
        self._http = http_client if http_client is not None else httpx.AsyncClient()
        self.ip = r.AsyncIP(self)
        self.bulk = r.AsyncBulk(self)
        self.agentscan = r.AsyncAgentscan(self)
        self.provenance = r.AsyncProvenance(self)
        self.account = r.AsyncAccount(self)
        self.asn_directory = r.AsyncAsnDirectory(self)
        self.crawlers = r.AsyncCrawlers(self)

    async def close(self) -> None:
        """Close the underlying HTTP client if this client created it."""
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> AsyncClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

    async def _request(self, req: Request) -> Any:
        kwargs = self._build(req)
        attempt = 0
        while True:
            try:
                response = await self._http.request(**kwargs)
            except httpx.TransportError as exc:
                if self._can_retry(req, attempt):
                    await asyncio.sleep(self._backoff(attempt))
                    attempt += 1
                    continue
                raise connection_error(exc) from exc
            if response.status_code in RETRY_STATUSES and self._can_retry(req, attempt):
                await response.aclose()
                await asyncio.sleep(self._backoff(attempt))
                attempt += 1
                continue
            return self._parse(req, response)

    async def _stream(self, req: Request) -> AsyncIterator[Any]:
        kwargs = self._build(req)
        try:
            async with self._http.stream(**kwargs) as response:
                if response.status_code >= 400:
                    await response.aread()
                    raise error_from_response(response)
                async for line in response.aiter_lines():
                    event = parse_stream_line(line)
                    if event is not None:
                        yield event
        except httpx.TransportError as exc:
            raise connection_error(exc) from exc
