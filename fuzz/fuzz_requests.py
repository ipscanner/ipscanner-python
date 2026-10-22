"""Path segments, query strings and JSON bodies reach the API unchanged and on the right route."""

import json
import re
import sys
from urllib.parse import unquote

import atheris
import httpx
from jsonvalues import text

with atheris.instrument_imports(include=["ipscanner"]):
    import ipscanner

SEGMENT_ROUTES = [
    ("/v1/vpn/", "", lambda c, v: c.ip.vpn(v)),
    ("/v1/proxy/", "", lambda c, v: c.ip.proxy(v)),
    ("/v1/geo/", "", lambda c, v: c.ip.geo(v)),
    ("/v1/asn/", "", lambda c, v: c.ip.asn(v)),
    ("/v1/whois/", "", lambda c, v: c.ip.whois(v)),
    ("/v1/demo/", "", lambda c, v: c.ip.demo(v)),
    ("/v1/sites/", "/policy", lambda c, v: c.sites.policy(v)),
]
ENCODED_SEGMENT = re.compile(r"(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})*")
SENT = []


def handler(request):
    request.read()
    SENT.append(request)
    assert request.headers["authorization"] == "Bearer test-key"
    assert request.headers["user-agent"] == f"ipscanner-python/{ipscanner.__version__}"
    return httpx.Response(200, json={})


CLIENT = ipscanner.Client(
    api_key="test-key",
    max_retries=0,
    http_client=httpx.Client(transport=httpx.MockTransport(handler)),
)


def encodable(value):
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def check_segment(fdp):
    prefix, suffix, call = fdp.PickValueInList(SEGMENT_ROUTES)
    value = text(fdp, 64)
    try:
        call(CLIENT, value)
    except ValueError:
        assert value in (".", "..") or not encodable(value), repr(value)
        return
    url = SENT[-1].url
    raw = url.raw_path.decode("ascii")
    assert raw.startswith(prefix) and raw.endswith(suffix) and not url.query, (value, raw)
    segment = raw[len(prefix) : len(raw) - len(suffix)]
    assert ENCODED_SEGMENT.fullmatch(segment), (value, raw)
    assert unquote(segment, errors="strict") == value, (value, raw)


def check_asn(fdp):
    value = text(fdp) if fdp.ConsumeBool() else fdp.ConsumeInt(8)
    try:
        CLIENT.asn_directory.get(value)
    except ValueError:
        assert isinstance(value, str), value
        return
    raw = SENT[-1].url.raw_path.decode("ascii")
    prefix = "/v1/asn/directory/"
    assert raw.startswith(prefix), (value, raw)
    number = raw[len(prefix) :]
    assert number.isascii() and str(int(number)) == number, (value, raw)
    assert not isinstance(value, int) or int(number) == value, (value, raw)


def check_query(fdp):
    q = text(fdp, 64)
    limit = fdp.ConsumeIntInRange(0, 1 << 31) if fdp.ConsumeBool() else None
    try:
        CLIENT.asn_directory.search(q, limit=limit)
    except ValueError:
        assert not encodable(q), repr(q)
        return
    params = SENT[-1].url.params
    assert params.get("q") == q, (q, str(SENT[-1].url))
    assert params.get("limit") == (None if limit is None else str(limit)), str(SENT[-1].url)


def check_body(fdp):
    ip = text(fdp, 64)
    fields = {k: text(fdp, 64) if fdp.ConsumeBool() else None for k in ("user_agent", "ja4")}
    values = [ip, *(v for v in fields.values() if v is not None)]
    try:
        CLIENT.agentscan.check(ip, **fields)
    except ValueError:
        assert not all(encodable(v) for v in values), values
        return
    expected = {"ip": ip, **{k: v for k, v in fields.items() if v is not None}}
    assert json.loads(SENT[-1].content) == expected, (expected, SENT[-1].content)


CHECKS = [check_segment, check_asn, check_query, check_body]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    SENT.clear()
    fdp.PickValueInList(CHECKS)(fdp)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
