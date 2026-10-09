from __future__ import annotations

import httpx
import pytest
from conftest import json_response, make_client

import ipscanner


@pytest.mark.parametrize(
    ("status", "cls"),
    [
        (400, ipscanner.APIError),
        (401, ipscanner.AuthenticationError),
        (403, ipscanner.AuthenticationError),
        (404, ipscanner.NotFoundError),
        (429, ipscanner.RateLimitError),
        (500, ipscanner.APIError),
    ],
)
def test_status_maps_to_error_class(status: int, cls: type[ipscanner.APIError]) -> None:
    client, _ = make_client(json_response(status, {"error": "some_code", "message": "nope"}))
    with pytest.raises(cls) as info:
        client.ip.vpn("1.1.1.1")
    assert info.value.status == status
    assert info.value.code == "some_code"
    assert info.value.message == "nope"


def test_bulk_details_are_exposed() -> None:
    body = {"error": "bad_request", "message": "No valid IP addresses found"}
    body["details"] = {"invalid": ["nope"]}
    client, _ = make_client(json_response(400, body))
    with pytest.raises(ipscanner.APIError) as info:
        client.bulk.check(["nope"])
    assert info.value.details == {"invalid": ["nope"]}
    assert info.value.body == body


def test_non_json_error_body() -> None:
    client, _ = make_client(lambda _: httpx.Response(502, text="<html>bad gateway</html>"))
    with pytest.raises(ipscanner.APIError) as info:
        client.ip.lookup("1.1.1.1")
    assert info.value.code == "http_502"
    assert info.value.message == "Bad Gateway"


def test_rate_limit_quota_body() -> None:
    body = {
        "error": "rate_limit_exceeded",
        "reason": "insufficient_for_batch",
        "message": "Not enough allowance",
        "meter": "request",
        "plan": "free",
        "limit": 1000,
        "usage": 990,
        "remaining": 10,
        "needed": 50,
        "resetDate": "2026-11-01",
        "resetAt": "2026-11-01T00:00:00Z",
        "retryAfter": 3600,
        "softBlock": False,
        "upgrade": {"url": "https://ipscanner.io/pricing", "message": "Upgrade"},
    }
    headers = {"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "10", "Retry-After": "60"}
    client, _ = make_client(json_response(429, body, headers=headers))
    with pytest.raises(ipscanner.RateLimitError) as info:
        client.bulk.check(["1.1.1.1"])
    err = info.value
    assert err.reason == "insufficient_for_batch"
    assert err.retry_after == 3600
    assert err.reset_at == "2026-11-01T00:00:00Z"
    assert (err.limit, err.usage, err.remaining, err.needed) == (1000, 990, 10, 50)
    assert err.plan == "free"
    assert err.upgrade_url == "https://ipscanner.io/pricing"
    assert err.rate_limit["limit"] == 1000
    assert err.rate_limit["remaining"] == 10


def test_rate_limit_retry_after_header_fallback() -> None:
    client, rec = make_client(
        lambda _: httpx.Response(429, text="Too Many Requests", headers={"Retry-After": "42"})
    )
    with pytest.raises(ipscanner.RateLimitError) as info:
        client.ip.vpn("1.1.1.1")
    assert info.value.retry_after == 42
    assert info.value.code == "http_429"
    assert len(rec.requests) == 1


def test_get_retries_on_503_then_succeeds() -> None:
    responses = iter([httpx.Response(503), httpx.Response(503), httpx.Response(200, json={})])
    client, rec = make_client(lambda _: next(responses))
    assert client.ip.vpn("1.1.1.1") == {}
    assert len(rec.requests) == 3


def test_get_gives_up_after_max_retries() -> None:
    client, rec = make_client(lambda _: httpx.Response(504), max_retries=1)
    with pytest.raises(ipscanner.APIError) as info:
        client.ip.vpn("1.1.1.1")
    assert info.value.status == 504
    assert len(rec.requests) == 2


def test_post_is_never_retried() -> None:
    client, rec = make_client(lambda _: httpx.Response(503))
    with pytest.raises(ipscanner.APIError):
        client.ip.lookup("1.1.1.1")
    assert len(rec.requests) == 1


def test_connection_error_retried_then_raised() -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client, rec = make_client(fail)
    with pytest.raises(ipscanner.APIConnectionError):
        client.ip.vpn("1.1.1.1")
    assert len(rec.requests) == 3


def test_timeout_error() -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    client, _ = make_client(fail, max_retries=0)
    with pytest.raises(ipscanner.APITimeoutError):
        client.ip.vpn("1.1.1.1")


@pytest.mark.parametrize(
    ("status", "code", "cls"),
    [
        (401, "invalid_secret", ipscanner.AuthenticationError),
        (400, "already_used", ipscanner.APIError),
        (503, "unavailable", ipscanner.APIError),
    ],
)
def test_gate_verify_errors(status: int, code: str, cls: type[ipscanner.APIError]) -> None:
    body = {"success": False, "error": code, "message": "nope"}
    client, rec = make_client(json_response(status, body))
    with pytest.raises(cls) as info:
        client.gate.verify("gs_secret", "tok_1")
    assert (info.value.status, info.value.code, info.value.message) == (status, code, "nope")
    assert info.value.body == body
    assert len(rec.requests) == 1


def test_sites_policy_unknown_site() -> None:
    client, _ = make_client(json_response(404, {"error": "unknown_site", "message": "x"}))
    with pytest.raises(ipscanner.NotFoundError) as info:
        client.sites.policy("site_x")
    assert info.value.code == "unknown_site"
