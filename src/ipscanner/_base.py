from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

import httpx

from ._errors import APIError, error_from_response
from ._version import __version__

DEFAULT_BASE_URL = "https://ipscanner.io"
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 2
STREAM_TIMEOUT = 300.0
USER_AGENT = f"ipscanner-python/{__version__}"
RETRY_STATUSES = frozenset({502, 503, 504})

_STREAM_DEFAULTS: dict[str, Any] = {
    "type": "",
    "index": 0,
    "total": 0,
    "input": "",
    "reason": "",
    "message": "",
    "error": "",
    "ip": "",
    "verdict": "",
    "classification": "",
    "confidence": 0.0,
    "anonymized": False,
    "score": 0,
    "grade": "",
    "isTorExit": False,
    "asn": "",
    "asnName": "",
    "asnType": "",
    "country": "",
    "processed": 0,
    "failed": 0,
    "metered": 0,
}


@dataclass(frozen=True)
class Request:
    method: str
    path: str
    params: dict[str, Any] | None = None
    body: Any = None
    raw: bool = False
    timeout: float | None = None


class BaseClient:
    def __init__(
        self,
        api_key: str | None,
        base_url: str | None,
        timeout: float,
        max_retries: int,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get("IPSCANNER_API_KEY")
        url = base_url or os.environ.get("IPSCANNER_API_URL") or DEFAULT_BASE_URL
        self.base_url = url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries

    def _build(self, req: Request) -> dict[str, Any]:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/csv" if req.raw else "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        kwargs: dict[str, Any] = {
            "method": req.method,
            "url": self.base_url + req.path,
            "headers": headers,
            "timeout": req.timeout if req.timeout is not None else self.timeout,
        }
        if req.params:
            params = {k: v for k, v in req.params.items() if v is not None}
            if params:
                kwargs["params"] = params
        if req.body is not None:
            kwargs["json"] = req.body
        return kwargs

    def _can_retry(self, req: Request, attempt: int) -> bool:
        return req.method == "GET" and attempt < self.max_retries

    @staticmethod
    def _backoff(attempt: int) -> float:
        return 0.5 * (2**attempt)

    @staticmethod
    def _parse(req: Request, response: httpx.Response) -> Any:
        if response.status_code >= 400:
            raise error_from_response(response)
        if req.raw:
            return response.text
        try:
            return response.json()
        except ValueError:
            raise APIError(
                response.status_code,
                "invalid_json",
                "Response body is not valid JSON",
                body=response.text,
                headers=response.headers,
            ) from None


def parse_stream_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    event = {**_STREAM_DEFAULTS, **json.loads(line)}
    if event["type"] == "done":
        event["complete"] = (
            event["reason"] == "complete" and event["processed"] + event["failed"] >= event["total"]
        )
    return event
