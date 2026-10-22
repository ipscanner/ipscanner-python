"""Any status, headers and body give the decoded JSON or an ipscanner error, never anything else."""

import json
import sys

import atheris
import httpx
from jsonvalues import dumps, json_object, json_value, same

with atheris.instrument_imports(include=["ipscanner"]):
    import ipscanner

HEADERS = [
    "retry-after",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-ratelimit-meter",
    "x-ratelimit-usage-percent",
    "x-quota-upgrade-url",
]
CONTENT_TYPES = [b"application/json", b"text/plain", b"text/html; charset=utf-8"]
ENCODINGS = [b"identity", b"gzip", b"deflate"]
BODY_KEYS = ["error", "message", "details", "reason", "retryAfter", "resetAt", "limit", "upgrade"]
ERRORS = {
    401: ipscanner.AuthenticationError,
    403: ipscanner.AuthenticationError,
    404: ipscanner.NotFoundError,
    429: ipscanner.RateLimitError,
}
SERVED = {}


def handler(request):
    status, headers, body = SERVED["spec"]
    SERVED["response"] = httpx.Response(status, headers=headers, stream=httpx.ByteStream(body))
    return SERVED["response"]


CLIENT = ipscanner.Client(
    api_key="test-key",
    max_retries=0,
    http_client=httpx.Client(transport=httpx.MockTransport(handler)),
)


def check_error(err, status, content):
    assert err.status == status, (err.status, status)
    assert all(k == k.lower() for k in err.headers)
    str(err)
    if status < 400:
        assert type(err) is ipscanner.APIError and err.code == "invalid_json", err
        return
    assert type(err) is ERRORS.get(status, ipscanner.APIError), (status, type(err))
    try:
        parsed = json.loads(content)
    except (ValueError, RecursionError):
        parsed = None
    if isinstance(parsed, dict) and isinstance(parsed.get("error"), str):
        assert err.code == parsed["error"], err
    else:
        assert err.code == f"http_{status}", err
    if isinstance(err, ipscanner.RateLimitError):
        assert err.retry_after is None or type(err.retry_after) is int, err.retry_after
        assert all(type(v) in (int, str) for v in err.rate_limit.values()), err.rate_limit


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    status = fdp.ConsumeIntInRange(200, 599)
    headers = [(b"content-type", fdp.PickValueInList(CONTENT_TYPES))]
    encoded = fdp.ConsumeBool()
    if encoded:
        headers.append((b"content-encoding", fdp.PickValueInList(ENCODINGS)))
    for _ in range(fdp.ConsumeIntInRange(0, 4)):
        value = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 24))
        headers.append((fdp.PickValueInList(HEADERS).encode(), value))
    mode = fdp.ConsumeIntInRange(0, 2)
    if mode == 0:
        body = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 1024))
    elif mode == 1:
        body = dumps(fdp, json_object(fdp, BODY_KEYS))
    else:
        body = dumps(fdp, json_value(fdp, BODY_KEYS))
    SERVED["spec"] = (status, headers, body)
    try:
        result = CLIENT.ip.lookup("1.1.1.1")
    except ipscanner.APIError as err:
        check_error(err, status, SERVED["response"].content)
        return
    except ipscanner.APIConnectionError:
        assert encoded, "connection error without a content-encoding"
        return
    assert status < 400, status
    assert same(result, json.loads(SERVED["response"].content)), (result, body)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
