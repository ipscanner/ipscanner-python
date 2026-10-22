"""NDJSON streams split only on newlines, however chunked, and yield events or ipscanner errors."""

import json
import sys

import atheris
import httpx
from jsonvalues import dumps, json_object, json_value, same

with atheris.instrument_imports(include=["ipscanner"]):
    import ipscanner
    from ipscanner._base import _STREAM_DEFAULTS

KEYS = ["type", "index", "total", "input", "reason", "processed", "failed", "ip", "score"]
TYPES = ["meta", "result", "error", "done"]
CHUNKS = []


def handler(request):
    headers = {"content-type": "application/x-ndjson"}
    return httpx.Response(200, headers=headers, content=iter(list(CHUNKS)))


CLIENT = ipscanner.Client(
    api_key="test-key",
    max_retries=0,
    http_client=httpx.Client(transport=httpx.MockTransport(handler)),
)


def line(fdp):
    mode = fdp.ConsumeIntInRange(0, 9)
    if mode == 0:
        return fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 64))
    if mode == 1:
        return dumps(fdp, json_value(fdp, KEYS))
    obj = json_object(fdp, KEYS)
    if fdp.ConsumeBool():
        obj["type"] = fdp.PickValueInList(TYPES)
    if fdp.ConsumeBool():
        obj["reason"] = "complete"
    return dumps(fdp, obj)


def expected(body):
    events = []
    for text in body.decode("utf-8", "replace").split("\n"):
        text = text.strip()
        if not text:
            continue
        try:
            obj = json.loads(text)
        except (ValueError, RecursionError):
            return events, True
        if not isinstance(obj, dict):
            return events, True
        events.append(obj)
    return events, False


def check_event(event, obj):
    fields = {**_STREAM_DEFAULTS, **{k: v for k, v in obj.items() if v is not None}}
    for key, value in fields.items():
        assert same(event[key], value), (key, event, obj)
    if event["type"] == "done":
        assert type(event["complete"]) is bool, event
        assert not event["complete"] or event["reason"] == "complete", event


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    lines = [line(fdp) for _ in range(fdp.ConsumeIntInRange(0, 6))]
    body = b"".join(item + fdp.PickValueInList([b"\n", b"\r\n", b"\n\n"]) for item in lines)
    cuts = sorted({fdp.ConsumeIntInRange(0, len(body)) for _ in range(fdp.ConsumeIntInRange(0, 8))})
    CHUNKS[:] = [body[a:b] for a, b in zip([0, *cuts], [*cuts, len(body)])]
    want, bad = expected(body)
    got = []
    try:
        for event in CLIENT.bulk.stream(["1.1.1.1"]):
            got.append(event)
    except ipscanner.APIError as err:
        assert bad and err.code == "invalid_json", (err, body)
    else:
        assert not bad, body
    assert len(got) == len(want), (got, want, body)
    for event, obj in zip(got, want):
        check_event(event, obj)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
