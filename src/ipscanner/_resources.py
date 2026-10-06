from __future__ import annotations

from collections.abc import AsyncIterator, Iterable, Iterator, Mapping
from typing import TYPE_CHECKING, Any

from . import _endpoints as ep
from .types import (
    AgentscanBatchLine,
    AgentscanBatchResponse,
    AgentscanCheckResult,
    AgentscanSelfResult,
    AgentscanVerifyResult,
    AllowlistResponse,
    AsnDetail,
    AsnResponse,
    AsnSearchResponse,
    AsnTopResponse,
    BulkCheckResponse,
    BulkStreamEvent,
    CrawlerList,
    GeolocationResponse,
    HistoryPage,
    JurisdictionsResponse,
    LimitsResponse,
    LookupResult,
    MyIPResponse,
    ProvenanceAnchoredResult,
    ProvenanceChain,
    ProvenanceCheckResult,
    ProvenanceVerifyResult,
    ProxyResponse,
    UsageSummary,
    VpnResponse,
    WhoisResponse,
)

if TYPE_CHECKING:
    from ._client import AsyncClient, Client


class _Resource:
    def __init__(self, client: Client) -> None:
        self._client = client


class _AsyncResource:
    def __init__(self, client: AsyncClient) -> None:
        self._client = client


class IP(_Resource):
    def lookup(self, target: str) -> LookupResult:
        """Full lookup of an IP, CIDR or hostname."""
        return self._client._request(ep.ip_lookup(target))

    def vpn(self, ip: str) -> VpnResponse:
        """VPN and Tor detection for one IP."""
        return self._client._request(ep.ip_vpn(ip))

    def proxy(self, ip: str) -> ProxyResponse:
        """Proxy detection for one IP."""
        return self._client._request(ep.ip_proxy(ip))

    def geo(self, ip: str) -> GeolocationResponse:
        """Geolocation for one IP."""
        return self._client._request(ep.ip_geo(ip))

    def asn(self, ip: str) -> AsnResponse:
        """Autonomous system for one IP."""
        return self._client._request(ep.ip_asn(ip))

    def whois(self, domain: str) -> WhoisResponse:
        """WHOIS record for a domain."""
        return self._client._request(ep.ip_whois(domain))

    def history(
        self,
        *,
        limit: int | None = None,
        before: int | None = None,
        verdict: str | None = None,
    ) -> HistoryPage:
        """Your past lookups, newest first."""
        return self._client._request(ep.ip_history(limit, before, verdict))

    def demo(self, ip: str) -> LookupResult:
        """Keyless demo lookup."""
        return self._client._request(ep.ip_demo(ip))

    def myip(self) -> MyIPResponse:
        """The caller's own IP with geolocation and ASN."""
        return self._client._request(ep.ip_myip())


class AsyncIP(_AsyncResource):
    async def lookup(self, target: str) -> LookupResult:
        """Full lookup of an IP, CIDR or hostname."""
        return await self._client._request(ep.ip_lookup(target))

    async def vpn(self, ip: str) -> VpnResponse:
        """VPN and Tor detection for one IP."""
        return await self._client._request(ep.ip_vpn(ip))

    async def proxy(self, ip: str) -> ProxyResponse:
        """Proxy detection for one IP."""
        return await self._client._request(ep.ip_proxy(ip))

    async def geo(self, ip: str) -> GeolocationResponse:
        """Geolocation for one IP."""
        return await self._client._request(ep.ip_geo(ip))

    async def asn(self, ip: str) -> AsnResponse:
        """Autonomous system for one IP."""
        return await self._client._request(ep.ip_asn(ip))

    async def whois(self, domain: str) -> WhoisResponse:
        """WHOIS record for a domain."""
        return await self._client._request(ep.ip_whois(domain))

    async def history(
        self,
        *,
        limit: int | None = None,
        before: int | None = None,
        verdict: str | None = None,
    ) -> HistoryPage:
        """Your past lookups, newest first."""
        return await self._client._request(ep.ip_history(limit, before, verdict))

    async def demo(self, ip: str) -> LookupResult:
        """Keyless demo lookup."""
        return await self._client._request(ep.ip_demo(ip))

    async def myip(self) -> MyIPResponse:
        """The caller's own IP with geolocation and ASN."""
        return await self._client._request(ep.ip_myip())


class Bulk(_Resource):
    def check(
        self, ips: Iterable[str] | None = None, *, input: str | None = None
    ) -> BulkCheckResponse:
        """Grade a list of IPs in one request."""
        return self._client._request(ep.bulk_check(ips, input))

    def stream(
        self, ips: Iterable[str] | None = None, *, input: str | None = None
    ) -> Iterator[BulkStreamEvent]:
        """Look up a list of IPs, yielding one event per NDJSON line."""
        return self._client._stream(ep.bulk_stream(ips, input))


class AsyncBulk(_AsyncResource):
    async def check(
        self, ips: Iterable[str] | None = None, *, input: str | None = None
    ) -> BulkCheckResponse:
        """Grade a list of IPs in one request."""
        return await self._client._request(ep.bulk_check(ips, input))

    def stream(
        self, ips: Iterable[str] | None = None, *, input: str | None = None
    ) -> AsyncIterator[BulkStreamEvent]:
        """Look up a list of IPs, yielding one event per NDJSON line. Use with async for."""
        return self._client._stream(ep.bulk_stream(ips, input))


class Agentscan(_Resource):
    def check(
        self,
        ip: str,
        *,
        user_agent: str | None = None,
        ja4: str | None = None,
        headers: Mapping[str, str] | None = None,
        headless_flags: Mapping[str, bool] | None = None,
        request_id: str | None = None,
    ) -> AgentscanCheckResult:
        """Classify one request as human, bot or agent."""
        req = ep.agentscan_check(ip, user_agent, ja4, headers, headless_flags, request_id)
        return self._client._request(req)

    def batch(
        self, lines: Iterable[AgentscanBatchLine | Mapping[str, Any]]
    ) -> AgentscanBatchResponse:
        """Classify parsed access log lines."""
        return self._client._request(ep.agentscan_batch(lines))

    def verify(
        self, ip: str, *, bot: str | None = None, user_agent: str | None = None
    ) -> AgentscanVerifyResult:
        """Check whether an IP really belongs to the crawler it claims to be."""
        return self._client._request(ep.agentscan_verify(ip, bot, user_agent))

    def allowlist(self) -> AllowlistResponse:
        """Agents on your allowlist."""
        return self._client._request(ep.agentscan_allowlist())

    def self_check(
        self,
        *,
        ip: str | None = None,
        user_agent: str | None = None,
        headers: Mapping[str, str] | None = None,
        ja4: str | None = None,
    ) -> AgentscanSelfResult:
        """Classify the caller's own connection. Not metered."""
        return self._client._request(ep.agentscan_self(ip, user_agent, headers, ja4))


class AsyncAgentscan(_AsyncResource):
    async def check(
        self,
        ip: str,
        *,
        user_agent: str | None = None,
        ja4: str | None = None,
        headers: Mapping[str, str] | None = None,
        headless_flags: Mapping[str, bool] | None = None,
        request_id: str | None = None,
    ) -> AgentscanCheckResult:
        """Classify one request as human, bot or agent."""
        req = ep.agentscan_check(ip, user_agent, ja4, headers, headless_flags, request_id)
        return await self._client._request(req)

    async def batch(
        self, lines: Iterable[AgentscanBatchLine | Mapping[str, Any]]
    ) -> AgentscanBatchResponse:
        """Classify parsed access log lines."""
        return await self._client._request(ep.agentscan_batch(lines))

    async def verify(
        self, ip: str, *, bot: str | None = None, user_agent: str | None = None
    ) -> AgentscanVerifyResult:
        """Check whether an IP really belongs to the crawler it claims to be."""
        return await self._client._request(ep.agentscan_verify(ip, bot, user_agent))

    async def allowlist(self) -> AllowlistResponse:
        """Agents on your allowlist."""
        return await self._client._request(ep.agentscan_allowlist())

    async def self_check(
        self,
        *,
        ip: str | None = None,
        user_agent: str | None = None,
        headers: Mapping[str, str] | None = None,
        ja4: str | None = None,
    ) -> AgentscanSelfResult:
        """Classify the caller's own connection. Not metered."""
        return await self._client._request(ep.agentscan_self(ip, user_agent, headers, ja4))


class Provenance(_Resource):
    def check(
        self,
        ip: str,
        *,
        claimed_jurisdiction: str | None = None,
        request_context: Mapping[str, Any] | None = None,
    ) -> ProvenanceCheckResult:
        """Attest the network origin of a request and get a policy action."""
        req = ep.provenance_check(ip, claimed_jurisdiction, request_context)
        return self._client._request(req)

    def verify(self) -> ProvenanceVerifyResult:
        """Verify the attestation hash chain."""
        return self._client._request(ep.provenance_verify())

    def verify_anchored(self) -> ProvenanceAnchoredResult:
        """Verify the chain against the latest daily anchor."""
        return self._client._request(ep.provenance_verify_anchored())

    def chain(self, *, limit: int | None = None, before: int | None = None) -> ProvenanceChain:
        """Page through your attestations, newest first."""
        return self._client._request(ep.provenance_chain(limit, before))

    def jurisdictions(self) -> JurisdictionsResponse:
        """Supported jurisdictions and their policy rules."""
        return self._client._request(ep.provenance_jurisdictions())

    def export(self, *, from_: ep.DateLike | None = None, to: ep.DateLike | None = None) -> str:
        """Attestations as CSV text."""
        return self._client._request(ep.provenance_export(from_, to))


class AsyncProvenance(_AsyncResource):
    async def check(
        self,
        ip: str,
        *,
        claimed_jurisdiction: str | None = None,
        request_context: Mapping[str, Any] | None = None,
    ) -> ProvenanceCheckResult:
        """Attest the network origin of a request and get a policy action."""
        req = ep.provenance_check(ip, claimed_jurisdiction, request_context)
        return await self._client._request(req)

    async def verify(self) -> ProvenanceVerifyResult:
        """Verify the attestation hash chain."""
        return await self._client._request(ep.provenance_verify())

    async def verify_anchored(self) -> ProvenanceAnchoredResult:
        """Verify the chain against the latest daily anchor."""
        return await self._client._request(ep.provenance_verify_anchored())

    async def chain(
        self, *, limit: int | None = None, before: int | None = None
    ) -> ProvenanceChain:
        """Page through your attestations, newest first."""
        return await self._client._request(ep.provenance_chain(limit, before))

    async def jurisdictions(self) -> JurisdictionsResponse:
        """Supported jurisdictions and their policy rules."""
        return await self._client._request(ep.provenance_jurisdictions())

    async def export(
        self, *, from_: ep.DateLike | None = None, to: ep.DateLike | None = None
    ) -> str:
        """Attestations as CSV text."""
        return await self._client._request(ep.provenance_export(from_, to))


class Account(_Resource):
    def limits(self) -> LimitsResponse:
        """Plan limits and current usage."""
        return self._client._request(ep.account_limits())

    def usage(self) -> UsageSummary:
        """Usage summary for the current billing period."""
        return self._client._request(ep.account_usage())


class AsyncAccount(_AsyncResource):
    async def limits(self) -> LimitsResponse:
        """Plan limits and current usage."""
        return await self._client._request(ep.account_limits())

    async def usage(self) -> UsageSummary:
        """Usage summary for the current billing period."""
        return await self._client._request(ep.account_usage())


class AsnDirectory(_Resource):
    def top(self, *, top: int | None = None, by: str | None = None) -> AsnTopResponse:
        """Largest autonomous systems by addresses or prefixes."""
        return self._client._request(ep.asn_top(top, by))

    def search(self, q: str, *, limit: int | None = None) -> AsnSearchResponse:
        """Search autonomous systems by name or number."""
        return self._client._request(ep.asn_search(q, limit))

    def get(self, asn: int | str) -> AsnDetail:
        """One autonomous system. Accepts 15169 or "AS15169"."""
        return self._client._request(ep.asn_get(asn))


class AsyncAsnDirectory(_AsyncResource):
    async def top(self, *, top: int | None = None, by: str | None = None) -> AsnTopResponse:
        """Largest autonomous systems by addresses or prefixes."""
        return await self._client._request(ep.asn_top(top, by))

    async def search(self, q: str, *, limit: int | None = None) -> AsnSearchResponse:
        """Search autonomous systems by name or number."""
        return await self._client._request(ep.asn_search(q, limit))

    async def get(self, asn: int | str) -> AsnDetail:
        """One autonomous system. Accepts 15169 or "AS15169"."""
        return await self._client._request(ep.asn_get(asn))


class Crawlers(_Resource):
    def list(self) -> CrawlerList:
        """Crawlers that can be verified, and how."""
        return self._client._request(ep.crawlers_list())


class AsyncCrawlers(_AsyncResource):
    async def list(self) -> CrawlerList:
        """Crawlers that can be verified, and how."""
        return await self._client._request(ep.crawlers_list())
