import json

TRICKY = ["", ".", "..", "/", "%2e", "\r", "\n", "\x00", "\x85", "\u2028", "\ufeff", "\ud800"]


def text(fdp, max_len=24):
    if fdp.ConsumeIntInRange(0, 7) == 0:
        parts = [fdp.PickValueInList(TRICKY), fdp.ConsumeUnicode(4), fdp.PickValueInList(TRICKY)]
        return "".join(parts[: fdp.ConsumeIntInRange(1, 3)])
    return fdp.ConsumeUnicode(fdp.ConsumeIntInRange(0, max_len))


def json_value(fdp, keys, depth=0):
    kind = fdp.ConsumeIntInRange(0, 6 if depth < 3 else 4)
    if kind == 0:
        return None
    if kind == 1:
        return fdp.ConsumeBool()
    if kind == 2:
        return fdp.ConsumeInt(fdp.ConsumeIntInRange(1, 12))
    if kind == 3:
        return fdp.ConsumeFloat()
    if kind == 4:
        return text(fdp)
    if kind == 5:
        return [json_value(fdp, keys, depth + 1) for _ in range(fdp.ConsumeIntInRange(0, 3))]
    return json_object(fdp, keys, depth + 1)


def json_object(fdp, keys, depth=0):
    obj = {}
    for _ in range(fdp.ConsumeIntInRange(0, 6)):
        key = fdp.PickValueInList(keys) if fdp.ConsumeBool() else text(fdp, 8)
        obj[key] = json_value(fdp, keys, depth)
    return obj


def dumps(fdp, value):
    return json.dumps(value, ensure_ascii=fdp.ConsumeBool()).encode("utf-8", "surrogatepass")


def same(a, b):
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
