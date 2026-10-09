from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import date
from typing import Any, Union
from urllib.parse import quote

from ._base import STREAM_TIMEOUT, Request

DateLike = Union[str, date]


def _seg(value: object) -> str:
    return quote(str(value), safe="")


def _compact(values: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in values.items() if v is not None}


def _date(value: DateLike | None) -> str | None:
    if value is None or isinstance(value, str):
        return value
    return value.isoformat()


def _bulk_body(ips: Iterable[str] | None, input: str | None) -> dict[str, Any]:
    if ips is None and input is None:
        raise ValueError("pass ips or input")
    return _compact({"ips": list(ips) if ips is not None else None, "input": input})


def _asn_number(asn: int | str) -> int:
    if isinstance(asn, int):
        return asn
    text = asn.strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    return int(text)


def ip_lookup(target: str) -> Request:
    return Request("POST", "/v1/ip/lookup", body={"target": target})


def ip_vpn(ip: str) -> Request:
    return Request("GET", f"/v1/vpn/{_seg(ip)}")


def ip_proxy(ip: str) -> Request:
    return Request("GET", f"/v1/proxy/{_seg(ip)}")


def ip_geo(ip: str) -> Request:
    return Request("GET", f"/v1/geo/{_seg(ip)}")


def ip_asn(ip: str) -> Request:
    return Request("GET", f"/v1/asn/{_seg(ip)}")


def ip_whois(domain: str) -> Request:
    return Request("GET", f"/v1/whois/{_seg(domain)}")


def ip_history(limit: int | None, before: int | None, verdict: str | None) -> Request:
    params = {"limit": limit, "before": before, "verdict": verdict}
    return Request("GET", "/v1/ip/history", params=params)


def ip_demo(ip: str) -> Request:
    return Request("GET", f"/v1/demo/{_seg(ip)}")


def ip_myip() -> Request:
    return Request("GET", "/v1/myip")


def bulk_check(ips: Iterable[str] | None, input: str | None) -> Request:
    return Request("POST", "/v1/bulk/check", body=_bulk_body(ips, input))


def bulk_stream(ips: Iterable[str] | None, input: str | None) -> Request:
    return Request("POST", "/v1/ip/bulk", body=_bulk_body(ips, input), timeout=STREAM_TIMEOUT)


def agentscan_check(
    ip: str,
    user_agent: str | None,
    ja4: str | None,
    headers: Mapping[str, str] | None,
    headless_flags: Mapping[str, bool] | None,
    request_id: str | None,
) -> Request:
    body = _compact(
        {
            "ip": ip,
            "user_agent": user_agent,
            "ja4": ja4,
            "headers": dict(headers) if headers is not None else None,
            "headless_flags": dict(headless_flags) if headless_flags is not None else None,
            "request_id": request_id,
        }
    )
    return Request("POST", "/v1/agentscan/check", body=body)


def agentscan_batch(lines: Iterable[Mapping[str, Any]]) -> Request:
    return Request("POST", "/v1/agentscan/batch", body={"lines": [dict(line) for line in lines]})


def agentscan_verify(ip: str, bot: str | None, user_agent: str | None) -> Request:
    if not bot and not user_agent:
        raise ValueError("pass bot or user_agent")
    body = _compact({"ip": ip, "bot": bot, "user_agent": user_agent})
    return Request("POST", "/v1/agentscan/verify", body=body)


def agentscan_allowlist() -> Request:
    return Request("GET", "/v1/agentscan/allowlist")


def agentscan_self(
    ip: str | None,
    user_agent: str | None,
    headers: Mapping[str, str] | None,
    ja4: str | None,
) -> Request:
    body = _compact(
        {
            "ip": ip,
            "user_agent": user_agent,
            "headers": dict(headers) if headers is not None else None,
            "ja4": ja4,
        }
    )
    return Request("POST", "/v1/agentscan/self", body=body)


def edge_check(
    ip: str,
    site: str | None,
    user_agent: str | None,
    ja4: str | None,
    headers: Mapping[str, str] | None,
    headless_flags: Mapping[str, bool] | None,
    request_id: str | None,
) -> Request:
    body = _compact(
        {
            "site": site,
            "ip": ip,
            "user_agent": user_agent,
            "ja4": ja4,
            "headers": dict(headers) if headers is not None else None,
            "headless_flags": dict(headless_flags) if headless_flags is not None else None,
            "request_id": request_id,
        }
    )
    return Request("POST", "/v1/edge/check", body=body)


def sites_policy(site_id: str) -> Request:
    return Request("GET", f"/v1/sites/{_seg(site_id)}/policy")


def gate_verify(secret: str, token: str, remote_ip: str | None) -> Request:
    body = _compact({"secret": secret, "token": token, "remote_ip": remote_ip})
    return Request("POST", "/v1/gate/verify", body=body, auth=False)


def provenance_check(
    ip: str,
    claimed_jurisdiction: str | None,
    request_context: Mapping[str, Any] | None,
) -> Request:
    body = _compact(
        {
            "ip": ip,
            "claimed_jurisdiction": claimed_jurisdiction,
            "request_context": dict(request_context) if request_context is not None else None,
        }
    )
    return Request("POST", "/v1/provenance/check", body=body)


def provenance_verify() -> Request:
    return Request("GET", "/v1/provenance/verify")


def provenance_verify_anchored() -> Request:
    return Request("POST", "/v1/provenance/verify", body={})


def provenance_chain(limit: int | None, before: int | None) -> Request:
    return Request("GET", "/v1/provenance/chain", params={"limit": limit, "before": before})


def provenance_jurisdictions() -> Request:
    return Request("GET", "/v1/provenance/jurisdictions")


def provenance_export(from_: DateLike | None, to: DateLike | None) -> Request:
    params = {"from": _date(from_), "to": _date(to)}
    return Request("GET", "/v1/provenance/export", params=params, raw=True)


def account_limits() -> Request:
    return Request("GET", "/v1/user/limits")


def account_usage() -> Request:
    return Request("GET", "/v1/usage/summary")


def asn_top(top: int | None, by: str | None) -> Request:
    return Request("GET", "/v1/asn/directory", params={"top": top, "by": by})


def asn_search(q: str, limit: int | None) -> Request:
    return Request("GET", "/v1/asn/directory", params={"q": q, "limit": limit})


def asn_get(asn: int | str) -> Request:
    return Request("GET", f"/v1/asn/directory/{_asn_number(asn)}")


def crawlers_list() -> Request:
    return Request("GET", "/v1/crawlers")
