# IPScanner Python SDK

Official Python client for the [IPScanner](https://ipscanner.io) API.

## Install

```sh
pip install ipscanner-io
```

Requires Python 3.9 or later.

## Quick start

```python
import ipscanner

client = ipscanner.Client(api_key="pk_live_...")

result = client.ip.lookup("8.8.8.8")
print(result["networkClass"], result["purity"]["grade"])
```

The async client has the same methods:

```python
import asyncio
import ipscanner


async def main():
    async with ipscanner.AsyncClient() as client:
        result = await client.ip.lookup("8.8.8.8")
        print(result["verdict"]["classification"])


asyncio.run(main())
```

Responses are plain dicts that keep the API's JSON key names. Their shapes are
described as `TypedDict`s in `ipscanner.types`.

`vpnProvider` is the VPN brand (Mullvad, NordVPN, ...) when known, else `None`;
`provider` is the network owner. On the Free plan premium fields such as
`purity`, `provider`, `vpnProvider` and precise geo come back as `None`, listed
in `locked`, with `planRequired` naming the plan that unlocks them.

Full API reference: https://ipscanner.io/api-documentation

## Usage

### IP

```python
client.ip.lookup("8.8.8.8")  # IP, CIDR or hostname
client.ip.vpn("1.1.1.1")
client.ip.proxy("1.1.1.1")
client.ip.geo("2001:4860:4860::8888")
client.ip.asn("1.1.1.1")
client.ip.whois("example.com")
client.ip.history(limit=50, verdict="vpn")
client.ip.demo("1.1.1.1")  # no key needed
client.ip.myip()  # no key needed
```

`vpn` and `proxy` carry `purity` (the score breakdown) on paid plans; a locked answer has
`deductionCount` instead.

### Email

```python
result = client.email.check("jane@outlok.com")
# result["status"] "risky", result["reason"] "typo", result["suggestion"] "jane@outlook.com"
```

Checks syntax, throwaway domains, whether the domain receives mail, typos of big webmail
domains and role addresses. The mailbox itself is not probed. One request per address.

### Bulk

```python
client.bulk.check(["1.1.1.1", "8.8.8.8"])
client.bulk.check(input="1.1.1.1\n8.8.8.8:443")

for event in client.bulk.stream(["1.1.1.1", "8.8.8.8"]):
    if event["type"] == "result":
        print(event["ip"], event["verdict"])
    elif event["type"] == "done" and not event["complete"]:
        print("stopped early:", event["reason"])
```

`bulk.stream` reads the NDJSON response line by line. Every event has all
fields, with missing ones set to their zero value. The `done` event also has
`complete`, which is false when the run hit the quota or the server deadline.
Fields locked by the plan are zero values too and are listed in `locked`.
On `AsyncClient` use `async for`.

### Agentscan

```python
client.agentscan.check(
    "203.0.113.7",
    user_agent="Mozilla/5.0 ...",
    headers={"accept-language": "en-US"},
)
client.agentscan.batch([{"line": 1, "ip": "203.0.113.7", "user_agent": "GPTBot/1.0"}])
client.agentscan.verify("66.249.66.1", bot="googlebot")
client.agentscan.allowlist()
client.agentscan.self_check()
```

### Edge

```python
client.edge.check("203.0.113.7", site="site_...", user_agent="Mozilla/5.0 ...")
```

### Sites

```python
client.sites.policy("site_...")
```

### Gate

```python
result = client.gate.verify("gs_...", token, remote_ip="203.0.113.7", email=form_email)
```

`email` is optional. With it, `result["email"]` holds the check and its action, and
`result["action"]` is the stricter of the network and email actions.

`gate.verify` sends no API key: the site secret is the credential. It is never
retried.

### Provenance

```python
client.provenance.check("203.0.113.7", claimed_jurisdiction="EU")
client.provenance.verify()
client.provenance.verify_anchored()
client.provenance.chain(limit=100)
client.provenance.jurisdictions()
csv_text = client.provenance.export(from_="2026-01-01", to="2026-02-01")
```

### Account

```python
client.account.limits()
client.account.usage()
```

### ASN directory

```python
client.asn_directory.top(top=20, by="prefixes")
client.asn_directory.search("cloudflare", limit=5)
client.asn_directory.get("AS15169")
```

### Crawlers

```python
client.crawlers.list()
```

## Errors

All errors inherit from `ipscanner.IPScannerError`.

| Error | When |
| --- | --- |
| `APIError` | Any error response. Has `status`, `code`, `message`, `details`, `body`. |
| `AuthenticationError` | 401 or 403 |
| `NotFoundError` | 404 |
| `RateLimitError` | 429. Adds `reason`, `retry_after`, `reset_at`, `limit`, `usage`, `remaining`, `needed`, `plan`, `upgrade_url`, `rate_limit`. |
| `APIConnectionError` | The API could not be reached. |
| `APITimeoutError` | The request timed out. |

```python
try:
    client.bulk.check(ips)
except ipscanner.RateLimitError as e:
    print(e.reason, e.retry_after, e.upgrade_url)
except ipscanner.APIError as e:
    print(e.status, e.code, e.message)
```

GET requests are retried up to `max_retries` times on connection errors and
502, 503 and 504 responses. POST requests and 429 responses are never retried.

## Configuration

```python
client = ipscanner.Client(
    api_key="pk_live_...",  # default: IPSCANNER_API_KEY
    base_url="https://ipscanner.io",  # default: IPSCANNER_API_URL or https://ipscanner.io
    timeout=30.0,
    max_retries=2,
    http_client=None,  # bring your own httpx.Client
)
```

Use the client as a context manager, or call `client.close()` when done.

## Licence

MIT
