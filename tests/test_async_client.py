from __future__ import annotations

import httpx
import pytest
from conftest import json_response, make_async_client

import ipscanner

pytestmark = pytest.mark.anyio


async def test_auth_header_and_ipv6_escaping() -> None:
    client, rec = make_async_client(json_response(data={"ip": "::1"}), api_key="pk_test_abc")
    result = await client.ip.vpn("2001:db8::1")
    assert result == {"ip": "::1"}
    assert rec.last.headers["authorization"] == "Bearer pk_test_abc"
    assert rec.last.url.raw_path == b"/v1/vpn/2001%3Adb8%3A%3A1"


async def test_auth_header_absent() -> None:
    client, rec = make_async_client(json_response())
    await client.crawlers.list()
    assert "authorization" not in rec.last.headers


async def test_snake_case_body() -> None:
    client, rec = make_async_client(json_response())
    await client.agentscan.self_check(user_agent="curl/8", ja4="t13d")
    assert rec.body() == {"user_agent": "curl/8", "ja4": "t13d"}


async def test_get_retries_on_503() -> None:
    responses = iter([httpx.Response(503), httpx.Response(200, json={"ok": True})])
    client, rec = make_async_client(lambda _: next(responses))
    assert await client.provenance.verify() == {"ok": True}
    assert len(rec.requests) == 2


async def test_post_not_retried() -> None:
    client, rec = make_async_client(lambda _: httpx.Response(503))
    with pytest.raises(ipscanner.APIError):
        await client.provenance.verify_anchored()
    assert len(rec.requests) == 1


async def test_rate_limit_header_fallback() -> None:
    client, _ = make_async_client(
        json_response(429, {"error": "rate_limit_exceeded"}, headers={"Retry-After": "7"})
    )
    with pytest.raises(ipscanner.RateLimitError) as info:
        await client.account.limits()
    assert info.value.retry_after == 7


async def test_not_found() -> None:
    client, _ = make_async_client(json_response(404, {"error": "not_found", "message": "x"}))
    with pytest.raises(ipscanner.NotFoundError):
        await client.asn_directory.get(4294967295)


async def test_context_manager_closes_owned_client() -> None:
    async with ipscanner.AsyncClient(api_key="k") as client:
        http = client._http
    assert http.is_closed
