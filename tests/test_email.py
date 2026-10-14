from __future__ import annotations

import pytest
from conftest import json_response, make_async_client, make_client

ANSWER = {
    "email": "jane@outlok.com",
    "status": "risky",
    "reason": "typo",
    "suggestion": "jane@outlook.com",
    "domain": "outlok.com",
    "checks": {
        "syntax": True,
        "mx": None,
        "disposable": False,
        "role": False,
        "freeProvider": False,
    },
    "mailbox": "not_checked",
}


def test_email_check_posts_with_the_key() -> None:
    client, rec = make_client(json_response(data=ANSWER), api_key="pk_test_abc")
    result = client.email.check("jane@outlok.com")
    assert (rec.last.method, rec.last.url.path) == ("POST", "/v1/email/check")
    assert rec.last.headers["authorization"] == "Bearer pk_test_abc"
    assert rec.body() == {"email": "jane@outlok.com"}
    assert result["suggestion"] == "jane@outlook.com"
    assert result["checks"]["mx"] is None


@pytest.mark.anyio
async def test_async_email_check() -> None:
    client, rec = make_async_client(json_response(data=ANSWER), api_key="pk_test_abc")
    result = await client.email.check("jane@outlok.com")
    assert rec.body() == {"email": "jane@outlok.com"}
    assert result["reason"] == "typo"


def test_gate_verify_sends_the_email() -> None:
    data = {
        "success": True,
        "class": "human",
        "action": "block",
        "mode": "enforce",
        "confidence": 0.6,
        "network": {
            "classification": "residential_clean",
            "anonymized": False,
            "provider": None,
            "vpn_provider": None,
        },
        "signals": [],
        "hostname": "example.com",
        "issued_at": "2026-10-14T10:00:00Z",
        "ip_match": True,
        "email": {
            "status": "risky",
            "reason": "disposable",
            "suggestion": None,
            "domain": "mailinator.com",
            "action": "block",
        },
    }
    client, rec = make_client(json_response(data=data))
    result = client.gate.verify("gs_secret", "tok_1", email="x@mailinator.com")
    assert rec.body() == {"secret": "gs_secret", "token": "tok_1", "email": "x@mailinator.com"}
    assert result["email"]["action"] == "block"


@pytest.mark.anyio
async def test_async_gate_verify_sends_the_email() -> None:
    client, rec = make_async_client(json_response(data={"success": True}))
    await client.gate.verify("gs_secret", "tok_1", remote_ip="1.2.3.4", email="a@b.io")
    assert rec.body() == {
        "secret": "gs_secret",
        "token": "tok_1",
        "remote_ip": "1.2.3.4",
        "email": "a@b.io",
    }


def test_proxy_locked_purity_count() -> None:
    data = {
        "ip": "5.6.7.8",
        "isProxy": False,
        "isTor": False,
        "networkClass": "hosting",
        "anonymized": True,
        "provider": None,
        "vpnProvider": None,
        "riskScore": 60,
        "purity": None,
        "deductionCount": 3,
        "locked": ["purity", "provider", "vpnProvider"],
        "planRequired": "Starter",
    }
    client, _ = make_client(json_response(data=data))
    result = client.ip.proxy("5.6.7.8")
    assert result["purity"] is None
    assert result["deductionCount"] == 3
