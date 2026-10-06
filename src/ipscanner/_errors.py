from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import httpx

from .types import RateLimitInfo

__all__ = [
    "IPScannerError",
    "APIError",
    "AuthenticationError",
    "NotFoundError",
    "RateLimitError",
    "APIConnectionError",
    "APITimeoutError",
]


class IPScannerError(Exception):
    """Base class for every error raised by this library."""


class APIConnectionError(IPScannerError):
    """The API could not be reached."""


class APITimeoutError(APIConnectionError):
    """The request timed out."""


class APIError(IPScannerError):
    """The API answered with an error status."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        details: Any = None,
        body: Any = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message
        self.details = details
        self.body = body
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}


class AuthenticationError(APIError):
    """401 or 403: the key is missing, invalid, or the account is suspended."""


class NotFoundError(APIError):
    """404."""


class RateLimitError(APIError):
    """429: a quota or rate limit was hit."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        details: Any = None,
        body: Any = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(status, code, message, details, body, headers)
        data = body if isinstance(body, dict) else {}
        upgrade = data.get("upgrade") if isinstance(data.get("upgrade"), dict) else {}
        self.rate_limit = _rate_limit_info(self.headers)
        self.reason: str | None = data.get("reason")
        retry_after = _to_int(data.get("retryAfter"))
        self.retry_after = (
            retry_after if retry_after is not None else self.rate_limit.get("retry_after")
        )
        self.reset_at: str | None = data.get("resetAt")
        self.limit: int | None = data.get("limit")
        self.usage: int | None = data.get("usage")
        self.remaining: int | None = data.get("remaining")
        self.needed: int | None = data.get("needed")
        self.plan: str | None = data.get("plan")
        self.upgrade_url: str | None = upgrade.get("url") or self.headers.get("x-quota-upgrade-url")


_HEADER_FIELDS = {
    "x-ratelimit-meter": ("meter", str),
    "x-ratelimit-limit": ("limit", int),
    "x-ratelimit-remaining": ("remaining", int),
    "x-ratelimit-reset": ("reset", int),
    "x-ratelimit-daily-limit": ("daily_limit", int),
    "x-ratelimit-daily-remaining": ("daily_remaining", int),
    "x-ratelimit-daily-reset": ("daily_reset", int),
    "x-ratelimit-hourly-limit": ("hourly_limit", int),
    "x-ratelimit-hourly-remaining": ("hourly_remaining", int),
    "x-ratelimit-hourly-reset": ("hourly_reset", int),
    "x-ratelimit-usage-percent": ("usage_percent", int),
    "x-quota-upgrade-hint": ("upgrade_hint", str),
    "x-quota-upgrade-url": ("upgrade_url", str),
    "x-quota-upgrade-plan": ("upgrade_plan", str),
    "retry-after": ("retry_after", int),
}


def _to_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _rate_limit_info(headers: Mapping[str, str]) -> RateLimitInfo:
    info: dict[str, Any] = {}
    for header, (key, kind) in _HEADER_FIELDS.items():
        raw = headers.get(header)
        if raw is None:
            continue
        value = _to_int(raw) if kind is int else raw
        if value is not None:
            info[key] = value
    return info  # type: ignore[return-value]


def error_from_response(response: httpx.Response) -> APIError:
    status = response.status_code
    try:
        body: Any = json.loads(response.content)
    except ValueError:
        body = response.text
    if isinstance(body, dict) and isinstance(body.get("error"), str):
        code = body["error"]
        message = body.get("message") or response.reason_phrase
        details = body.get("details")
    else:
        code = f"http_{status}"
        message = response.reason_phrase
        details = None
    if status in (401, 403):
        cls: type[APIError] = AuthenticationError
    elif status == 404:
        cls = NotFoundError
    elif status == 429:
        cls = RateLimitError
    else:
        cls = APIError
    return cls(status, code, message, details, body, response.headers)


def connection_error(exc: httpx.TransportError) -> APIConnectionError:
    if isinstance(exc, httpx.TimeoutException):
        return APITimeoutError(str(exc) or "Request timed out")
    return APIConnectionError(str(exc) or "Connection error")
