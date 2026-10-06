from __future__ import annotations

import json
from datetime import date

import httpx
import pytest
from conftest import json_response, make_client

import ipscanner


def test_auth_header_present() -> None:
    client, rec = make_client(json_response(data={"ip": "1.1.1.1"}), api_key="pk_test_abc")
    client.ip.vpn("1.1.1.1")
    assert rec.last.headers["authorization"] == "Bearer pk_test_abc"
    assert rec.last.headers["user-agent"] == "ipscanner-python/0.1.0"
    assert rec.last.headers["accept"] == "application/json"


def test_auth_header_absent_without_key() -> None:
    client, rec = make_client(json_response())
    client.ip.myip()
    assert "authorization" not in rec.last.headers


def test_env_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IPSCANNER_API_KEY", "pk_test_env")
    monkeypatch.setenv("IPSCANNER_API_URL", "http://localhost:8080/")
    client, rec = make_client(json_response())
    client.crawlers.list()
    assert rec.last.headers["authorization"] == "Bearer pk_test_env"
    assert str(rec.last.url) == "http://localhost:8080/v1/crawlers"


def test_ipv6_path_is_escaped() -> None:
    client, rec = make_client(json_response())
    client.ip.geo("2001:db8::1")
    assert rec.last.url.raw_path == b"/v1/geo/2001%3Adb8%3A%3A1"


def test_lookup_body_and_content_type() -> None:
    client, rec = make_client(json_response(data={"networkClass": "hosting"}))
    result = client.ip.lookup("8.8.8.8")
    assert result["networkClass"] == "hosting"
    assert rec.last.method == "POST"
    assert rec.last.url.path == "/v1/ip/lookup"
    assert rec.last.headers["content-type"] == "application/json"
    assert rec.body() == {"target": "8.8.8.8"}


def test_history_query_params_skip_none() -> None:
    client, rec = make_client(json_response(data={"events": [], "nextBefore": 0}))
    client.ip.history(limit=10, verdict="vpn")
    assert dict(rec.last.url.params) == {"limit": "10", "verdict": "vpn"}


def test_agentscan_check_snake_case_body() -> None:
    client, rec = make_client(json_response(data={"class": "human"}))
    client.agentscan.check(
        "1.2.3.4",
        user_agent="Mozilla/5.0",
        ja4="t13d",
        headers={"accept-language": "en"},
        headless_flags={"webdriver": True},
        request_id="req_1",
    )
    assert rec.body() == {
        "ip": "1.2.3.4",
        "user_agent": "Mozilla/5.0",
        "ja4": "t13d",
        "headers": {"accept-language": "en"},
        "headless_flags": {"webdriver": True},
        "request_id": "req_1",
    }


def test_agentscan_self_check_empty_body() -> None:
    client, rec = make_client(json_response())
    client.agentscan.self_check()
    assert rec.last.url.path == "/v1/agentscan/self"
    assert rec.body() == {}


def test_agentscan_verify_requires_bot_or_user_agent() -> None:
    client, rec = make_client(json_response())
    with pytest.raises(ValueError):
        client.agentscan.verify("1.2.3.4")
    client.agentscan.verify("66.249.66.1", bot="googlebot")
    assert rec.body() == {"ip": "66.249.66.1", "bot": "googlebot"}


def test_provenance_snake_case_body() -> None:
    client, rec = make_client(json_response())
    client.provenance.check("1.2.3.4", claimed_jurisdiction="EU", request_context={"path": "/"})
    assert rec.body() == {
        "ip": "1.2.3.4",
        "claimed_jurisdiction": "EU",
        "request_context": {"path": "/"},
    }


def test_provenance_verify_anchored_posts_empty_object() -> None:
    client, rec = make_client(json_response(data={"ok": True}))
    client.provenance.verify_anchored()
    assert rec.last.method == "POST"
    assert rec.body() == {}


def test_provenance_export_returns_csv_text() -> None:
    csv = "id,ts,ip\n1,2026-01-01T00:00:00Z,1.2.3.4\n"
    client, rec = make_client(
        lambda _: httpx.Response(200, text=csv, headers={"content-type": "text/csv"})
    )
    out = client.provenance.export(from_=date(2026, 1, 1), to="2026-02-01")
    assert out == csv
    assert dict(rec.last.url.params) == {"from": "2026-01-01", "to": "2026-02-01"}


def test_asn_directory_get_accepts_prefixed_number() -> None:
    client, rec = make_client(json_response())
    client.asn_directory.get("AS15169")
    assert rec.last.url.path == "/v1/asn/directory/15169"
    client.asn_directory.search("google", limit=5)
    assert dict(rec.last.url.params) == {"q": "google", "limit": "5"}


def test_bulk_check_body() -> None:
    client, rec = make_client(json_response())
    client.bulk.check(["1.1.1.1", "8.8.8.8"])
    assert rec.body() == {"ips": ["1.1.1.1", "8.8.8.8"]}
    client.bulk.check(input="1.1.1.1\n8.8.8.8")
    assert rec.body() == {"input": "1.1.1.1\n8.8.8.8"}
    with pytest.raises(ValueError):
        client.bulk.check()


def test_agentscan_batch_body() -> None:
    client, rec = make_client(json_response())
    client.agentscan.batch([{"line": 1, "ip": "1.2.3.4", "user_agent": "curl/8"}])
    assert rec.body() == {"lines": [{"line": 1, "ip": "1.2.3.4", "user_agent": "curl/8"}]}


def test_context_manager_closes_owned_client() -> None:
    with ipscanner.Client(api_key="k") as client:
        http = client._http
    assert http.is_closed


def test_context_manager_leaves_external_client_open() -> None:
    http = httpx.Client()
    with ipscanner.Client(http_client=http):
        pass
    assert not http.is_closed
    http.close()


def test_invalid_json_success_body() -> None:
    client, _ = make_client(lambda _: httpx.Response(200, text="<html>"))
    with pytest.raises(ipscanner.APIError) as info:
        client.ip.myip()
    assert info.value.code == "invalid_json"


def test_resource_methods_hit_expected_routes() -> None:
    client, rec = make_client(json_response())
    calls = [
        (lambda: client.ip.vpn("1.1.1.1"), "GET", "/v1/vpn/1.1.1.1"),
        (lambda: client.ip.proxy("1.1.1.1"), "GET", "/v1/proxy/1.1.1.1"),
        (lambda: client.ip.asn("1.1.1.1"), "GET", "/v1/asn/1.1.1.1"),
        (lambda: client.ip.whois("example.com"), "GET", "/v1/whois/example.com"),
        (lambda: client.ip.demo("1.1.1.1"), "GET", "/v1/demo/1.1.1.1"),
        (lambda: client.agentscan.allowlist(), "GET", "/v1/agentscan/allowlist"),
        (lambda: client.provenance.verify(), "GET", "/v1/provenance/verify"),
        (lambda: client.provenance.chain(limit=5), "GET", "/v1/provenance/chain"),
        (lambda: client.provenance.jurisdictions(), "GET", "/v1/provenance/jurisdictions"),
        (lambda: client.account.limits(), "GET", "/v1/user/limits"),
        (lambda: client.account.usage(), "GET", "/v1/usage/summary"),
        (lambda: client.asn_directory.top(top=10, by="prefixes"), "GET", "/v1/asn/directory"),
    ]
    for call, method, path in calls:
        call()
        assert (rec.last.method, rec.last.url.path) == (method, path)


def test_json_body_is_compact_json() -> None:
    client, rec = make_client(json_response())
    client.ip.lookup("1.1.1.1")
    assert json.loads(rec.last.content) == {"target": "1.1.1.1"}
