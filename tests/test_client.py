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
    assert rec.last.headers["user-agent"] == "ipscanner-python/0.3.1"
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


@pytest.mark.parametrize("value", [".", ".."])
def test_dot_path_segment_is_rejected(value: str) -> None:
    client, rec = make_client(json_response())
    with pytest.raises(ValueError):
        client.ip.vpn(value)
    with pytest.raises(ValueError):
        client.sites.policy(value)
    assert rec.requests == []


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


def test_edge_check_request_and_decoding() -> None:
    data = {
        "class": "vpn",
        "agent": {"class": "human", "confidence": 0.9, "action": "allow", "signals": {}},
        "network": {
            "networkClass": "vpn",
            "anonymized": True,
            "riskScore": 80,
            "provider": None,
            "vpnProvider": None,
            "evidence": ["vpn_server_list"],
            "asn": 9009,
        },
        "site": {"id": "site_1", "mode": "monitor", "policyVersion": 3},
        "locked": ["network.provider", "network.vpnProvider"],
        "planRequired": "Starter",
        "futureField": 1,
    }
    client, rec = make_client(json_response(data=data), api_key="pk_test_abc")
    result = client.edge.check(
        "203.0.113.7",
        site="site_1",
        user_agent="Mozilla/5.0",
        headers={"accept": "text/html"},
        request_id="req_1",
    )
    assert (rec.last.method, rec.last.url.path) == ("POST", "/v1/edge/check")
    assert rec.last.headers["authorization"] == "Bearer pk_test_abc"
    assert rec.body() == {
        "site": "site_1",
        "ip": "203.0.113.7",
        "user_agent": "Mozilla/5.0",
        "headers": {"accept": "text/html"},
        "request_id": "req_1",
    }
    network = result["network"]
    assert network is not None
    assert network["provider"] is None and network["vpnProvider"] is None
    assert network["evidence"] == ["vpn_server_list"]
    assert result["locked"] == ["network.provider", "network.vpnProvider"]
    assert result["planRequired"] == "Starter"


def test_edge_check_degraded_halves_are_null() -> None:
    data = {"class": "human", "agent": None, "network": None, "site": None, "degraded": ["agent"]}
    client, _ = make_client(json_response(data=data))
    result = client.edge.check("203.0.113.7")
    assert result["agent"] is None and result["site"] is None
    assert result["degraded"] == ["agent"]


def test_sites_policy() -> None:
    data = {
        "site": "site 1",
        "mode": "enforce",
        "policy": {"verified_bot": "allow", "relay": "flag"},
        "version": 4,
        "updatedAt": "2026-10-09T10:00:00.123456789Z",
    }
    client, rec = make_client(json_response(data=data), api_key="pk_test_abc")
    result = client.sites.policy("site 1")
    assert rec.last.method == "GET"
    assert rec.last.url.raw_path == b"/v1/sites/site%201/policy"
    assert result["policy"]["relay"] == "flag"


def test_gate_verify_sends_no_api_key() -> None:
    data = {
        "success": True,
        "class": "relay",
        "action": "allow",
        "mode": "monitor",
        "confidence": 0.95,
        "network": {
            "classification": "relay",
            "anonymized": True,
            "provider": None,
            "vpn_provider": None,
        },
        "signals": ["relay_range"],
        "hostname": "example.com",
        "issued_at": "2026-10-09T10:00:00Z",
        "ip_match": True,
        "locked": ["network.provider", "network.vpn_provider"],
        "planRequired": "Starter",
    }
    client, rec = make_client(json_response(data=data), api_key="pk_test_abc")
    result = client.gate.verify("gs_secret", "tok_1")
    assert (rec.last.method, rec.last.url.path) == ("POST", "/v1/gate/verify")
    assert "authorization" not in rec.last.headers
    assert rec.last.headers["content-type"] == "application/json"
    assert rec.body() == {"secret": "gs_secret", "token": "tok_1"}
    assert result["network"]["vpn_provider"] is None
    assert result["locked"] == ["network.provider", "network.vpn_provider"]
    client.gate.verify("gs_secret", "tok_2", remote_ip="203.0.113.7")
    assert rec.body() == {"secret": "gs_secret", "token": "tok_2", "remote_ip": "203.0.113.7"}


def test_gate_verify_is_not_retried() -> None:
    client, rec = make_client(lambda _: httpx.Response(503))
    with pytest.raises(ipscanner.APIError):
        client.gate.verify("gs_secret", "tok_1")
    assert len(rec.requests) == 1


def test_locked_lookup_decodes_nulls_and_markers() -> None:
    data = {
        "target": {"raw": "example.com", "kind": "hostname", "ip": "93.184.215.14"},
        "reserved": {"reserved": False},
        "verdict": {
            "classification": "relay",
            "anonymized": True,
            "confidence": 0.9,
            "method": "range",
            "evidence": ["relay_range"],
        },
        "purity": None,
        "networkClass": "relay",
        "isVpn": False,
        "isProxy": False,
        "isTor": False,
        "provider": None,
        "vpnProvider": None,
        "riskScore": 40,
        "geo": {
            "ip": "93.184.215.14",
            "country": "United States",
            "countryCode": "US",
            "city": "",
            "region": "",
            "postalCode": None,
            "latitude": None,
            "longitude": None,
            "timezone": "",
            "accuracyRadius": None,
        },
        "whoisStatus": "timeout",
        "at": "2026-10-09T10:00:00.123456789Z",
        "locked": ["purity", "provider", "vpnProvider", "geo.latitude"],
        "planRequired": "Starter",
    }
    client, _ = make_client(json_response(data=data))
    result = client.ip.lookup("example.com")
    assert result["purity"] is None
    assert result["vpnProvider"] is None
    assert result["verdict"]["evidence"] == ["relay_range"]
    assert result["geo"]["latitude"] is None
    assert result["whoisStatus"] == "timeout"
    assert "whois" not in result
    assert result["planRequired"] == "Starter"


def test_vpn_provider_and_evidence() -> None:
    data = {
        "ip": "185.65.135.1",
        "isVpn": True,
        "isTor": False,
        "networkClass": "vpn",
        "anonymized": True,
        "provider": "M247",
        "vpnProvider": "Mullvad",
        "riskScore": 90,
        "evidence": ["vpn_operator"],
    }
    client, _ = make_client(json_response(data=data))
    result = client.ip.vpn("185.65.135.1")
    assert result["vpnProvider"] == "Mullvad"
    assert result["evidence"] == ["vpn_operator"]
    assert "locked" not in result


def test_whois_status_unavailable_is_not_an_error() -> None:
    data = {
        "domain": "example.com",
        "registrar": "",
        "registeredOn": "",
        "expiresOn": "",
        "lastUpdated": "",
        "nameservers": [],
        "status": [],
        "privacyProtection": False,
        "whoisStatus": "unavailable",
    }
    client, _ = make_client(json_response(data=data))
    assert client.ip.whois("example.com")["whoisStatus"] == "unavailable"


def test_locked_bulk_check_rows() -> None:
    row = {
        "input": "1.1.1.1",
        "ip": "1.1.1.1",
        "score": None,
        "grade": None,
        "verdict": None,
        "classification": "hosting",
        "confidence": 0.8,
        "anonymized": True,
        "vpnProvider": None,
        "isTorExit": False,
        "inVpnRange": False,
        "inDatacenterRange": True,
        "deductions": None,
        "locked": ["score", "grade", "verdict", "deductions", "vpnProvider"],
    }
    data = {
        "submitted": 1,
        "unique": 1,
        "duplicates": 0,
        "invalid": [],
        "summary": {},
        "results": [row],
        "planRequired": "Starter",
    }
    client, _ = make_client(json_response(data=data))
    result = client.bulk.check(["1.1.1.1"])
    first = result["results"][0]
    assert first["score"] is None and first["deductions"] is None
    assert first["locked"] == ["score", "grade", "verdict", "deductions", "vpnProvider"]
    assert result["planRequired"] == "Starter"
