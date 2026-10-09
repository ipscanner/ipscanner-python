"""Response and request shapes. Keys match the API's JSON names."""

from typing import Any, Optional, TypedDict


class PremiumMarkers(TypedDict, total=False):
    """Set when the plan nulled premium fields: their paths and the plan that unlocks them."""

    locked: list[str]
    planRequired: str


class _VpnResponseBase(TypedDict):
    ip: str
    isVpn: bool
    isTor: bool
    networkClass: str
    anonymized: bool
    provider: Optional[str]
    vpnProvider: Optional[str]
    riskScore: int


class VpnResponse(_VpnResponseBase, PremiumMarkers, total=False):
    evidence: list[str]


class _ProxyResponseBase(TypedDict):
    ip: str
    isProxy: bool
    isTor: bool
    networkClass: str
    anonymized: bool
    provider: Optional[str]
    vpnProvider: Optional[str]
    riskScore: int


class ProxyResponse(_ProxyResponseBase, PremiumMarkers, total=False):
    evidence: list[str]


class _GeolocationResponseBase(TypedDict):
    ip: str
    country: str
    countryCode: str
    city: str
    region: str
    postalCode: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    timezone: str
    accuracyRadius: Optional[int]


class GeolocationResponse(_GeolocationResponseBase, PremiumMarkers, total=False):
    pass


class AsnResponse(TypedDict):
    ip: str
    asn: str
    name: str
    type: str
    country: str


class _WhoisResponseBase(TypedDict):
    domain: str
    registrar: str
    registeredOn: str
    expiresOn: str
    lastUpdated: str
    nameservers: list[str]
    status: list[str]
    privacyProtection: bool


class WhoisResponse(_WhoisResponseBase, total=False):
    whoisStatus: str


class _LookupTargetBase(TypedDict):
    raw: str
    kind: str
    ip: str


class LookupTarget(_LookupTargetBase, total=False):
    hostname: str
    network: str
    addresses: int


class _ReservedRangeBase(TypedDict):
    reserved: bool


class ReservedRange(_ReservedRangeBase, total=False):
    label: str
    detail: str


class _VerdictBase(TypedDict):
    classification: str
    anonymized: bool
    confidence: float
    method: str


class Verdict(_VerdictBase, total=False):
    evidence: list[str]


class Deduction(TypedDict):
    factor: str
    points: int
    detail: str


class Purity(TypedDict):
    score: int
    grade: str
    verdict: str
    deductions: list[Deduction]


class _LookupResultBase(TypedDict):
    target: LookupTarget
    reserved: ReservedRange
    verdict: Verdict
    purity: Optional[Purity]
    networkClass: str
    isVpn: bool
    isProxy: bool
    isTor: bool
    vpnProvider: Optional[str]
    riskScore: int
    at: str


class LookupResult(_LookupResultBase, PremiumMarkers, total=False):
    provider: Optional[str]
    networkType: str
    geo: GeolocationResponse
    asn: AsnResponse
    whois: WhoisResponse
    whoisStatus: str
    degraded: list[str]


class HistoryEvent(TypedDict):
    id: int
    at: str
    target: str
    ip: str
    verdict: str
    confidence: float
    asn: str
    asnName: str
    country: str
    anonymized: bool
    source: str


class HistoryPage(TypedDict):
    events: list[HistoryEvent]
    nextBefore: int
    asOf: str


class _MyIPBase(TypedDict):
    country: str
    countryCode: str
    city: str
    region: str
    postalCode: str
    latitude: float
    longitude: float
    timezone: str
    accuracyRadius: int
    asn: str
    asnName: str
    asnType: str
    asnCountry: str


class MyIPResponse(_MyIPBase, total=False):
    ipv4: str
    ipv6: str


class _BulkResultBase(TypedDict):
    input: str
    ip: str
    score: Optional[int]
    grade: Optional[str]
    verdict: Optional[str]
    classification: str
    confidence: float
    anonymized: bool
    vpnProvider: Optional[str]
    isTorExit: bool
    inVpnRange: bool
    inDatacenterRange: bool
    deductions: Optional[list[Deduction]]


class BulkResult(_BulkResultBase, total=False):
    port: int
    asn: str
    asnName: str
    asnType: str
    country: str
    locked: list[str]


class _BulkCheckResponseBase(TypedDict):
    submitted: int
    unique: int
    duplicates: int
    invalid: list[str]
    summary: dict[str, int]
    results: list[BulkResult]


class BulkCheckResponse(_BulkCheckResponseBase, total=False):
    planRequired: str


class _BulkStreamEventBase(TypedDict):
    type: str
    index: int
    total: int
    input: str
    reason: str
    message: str
    error: str
    ip: str
    verdict: str
    classification: str
    confidence: float
    anonymized: bool
    vpnProvider: str
    score: int
    grade: str
    isTorExit: bool
    asn: str
    asnName: str
    asnType: str
    country: str
    processed: int
    failed: int
    metered: int
    planRequired: str


class BulkStreamEvent(_BulkStreamEventBase, total=False):
    complete: bool
    locked: list[str]


AgentscanCheckResult = TypedDict(
    "AgentscanCheckResult",
    {"class": str, "confidence": float, "action": str, "signals": dict[str, Any]},
)


class _AgentscanBatchLineBase(TypedDict):
    line: int
    ip: str


class AgentscanBatchLine(_AgentscanBatchLineBase, total=False):
    user_agent: str
    ja4: str
    headers: dict[str, str]
    path: str
    status: int


_AgentscanBatchResultOptional = TypedDict(
    "_AgentscanBatchResultOptional",
    {
        "userAgent": str,
        "class": str,
        "confidence": float,
        "action": str,
        "signals": dict[str, Any],
        "error": str,
    },
    total=False,
)


class AgentscanBatchResult(_AgentscanBatchResultOptional):
    line: int
    ip: str


class AgentscanBatchResponse(TypedDict):
    submitted: int
    processed: int
    failed: int
    truncated: bool
    reason: str
    byClass: dict[str, int]
    results: list[AgentscanBatchResult]
    asOf: str


class VerifyCheck(TypedDict):
    name: str
    status: str
    detail: str


class _AgentscanVerifyResultBase(TypedDict):
    ip: str
    slug: str
    crawler: str
    outcome: str
    method: str
    summary: str
    checks: list[VerifyCheck]
    networkOrigin: str
    anonymized: bool
    checkedAt: str


class AgentscanVerifyResult(_AgentscanVerifyResultBase, total=False):
    userAgent: str
    asn: str
    asnName: str
    country: str
    hostname: str
    docs: str


class AllowlistAgent(TypedDict):
    id: int
    ident: str
    type: str
    verificationMethod: str
    customerId: Optional[int]
    createdAt: str


class AllowlistResponse(TypedDict):
    agents: list[AllowlistAgent]


_AgentscanSelfResultBase = TypedDict(
    "_AgentscanSelfResultBase",
    {
        "ip": str,
        "userAgent": str,
        "ja4": str,
        "ja4Source": str,
        "class": str,
        "confidence": float,
        "action": str,
        "signals": dict[str, Any],
        "metered": bool,
        "asOf": str,
    },
)


class AgentscanSelfResult(_AgentscanSelfResultBase, PremiumMarkers, total=False):
    asn: AsnResponse
    geo: GeolocationResponse


class _EdgeNetworkBase(TypedDict):
    networkClass: str
    anonymized: bool
    riskScore: int
    vpnProvider: Optional[str]


class EdgeNetwork(_EdgeNetworkBase, total=False):
    provider: Optional[str]
    evidence: list[str]
    country: str
    asn: int
    asnName: str


class EdgeSite(TypedDict):
    id: str
    mode: str
    policyVersion: int


_EdgeCheckResultBase = TypedDict(
    "_EdgeCheckResultBase",
    {
        "class": str,
        "agent": Optional[AgentscanCheckResult],
        "network": Optional[EdgeNetwork],
        "site": Optional[EdgeSite],
    },
)


class EdgeCheckResult(_EdgeCheckResultBase, PremiumMarkers, total=False):
    degraded: list[str]


class SitePolicy(TypedDict):
    site: str
    mode: str
    policy: dict[str, str]
    version: int
    updatedAt: str


class GateNetwork(TypedDict):
    classification: str
    anonymized: bool
    provider: Optional[str]
    vpn_provider: Optional[str]


_GateVerifyResultBase = TypedDict(
    "_GateVerifyResultBase",
    {
        "success": bool,
        "class": str,
        "action": str,
        "mode": str,
        "confidence": float,
        "network": GateNetwork,
        "signals": list[str],
        "hostname": str,
        "issued_at": str,
        "ip_match": bool,
    },
)


class GateVerifyResult(_GateVerifyResultBase, PremiumMarkers, total=False):
    pass


class ProvenanceCheckResult(TypedDict):
    network_origin: str
    anonymized: bool
    method: str
    confidence: float
    policy_action: str
    attestation_id: int


class ProvenanceVerifyResult(TypedDict):
    ok: bool
    count: int
    brokenAt: int


class Anchor(TypedDict):
    day: str
    rootHash: str
    lastId: int


class ProvenanceAnchoredResult(TypedDict):
    ok: bool
    count: int
    brokenAt: int
    yours: int
    anchor: Optional[Anchor]
    at: str


class ChainLink(TypedDict):
    id: int
    ts: str
    ip: str
    claimedJurisdiction: str
    networkOrigin: str
    anonymized: bool
    method: str
    confidence: float
    policyAction: str
    entryHash: str
    prevHash: str
    prevId: int
    entryOk: bool
    linkOk: bool


class ChainSummary(TypedDict):
    allow: int
    step_up: int
    block: int


class _JurisdictionBase(TypedDict):
    code: str
    label: str
    strict: bool
    cleanAction: str
    maskedAction: str
    rule: str


class Jurisdiction(_JurisdictionBase, total=False):
    law: str


class ProvenanceChain(TypedDict):
    links: list[ChainLink]
    nextBefore: int
    total: int
    summary: ChainSummary
    anchor: Optional[Anchor]
    jurisdictions: list[Jurisdiction]
    asOf: str


class JurisdictionsResponse(TypedDict):
    jurisdictions: list[Jurisdiction]


class Window(TypedDict):
    limit: int
    used: int
    remaining: int
    resetAt: str


class LimitsResponse(TypedDict):
    accountType: str
    limit: int
    usage: int
    remaining: int
    resetDate: str
    daily: Optional[Window]
    hourly: Optional[Window]


class UsageSummary(TypedDict):
    plan: str
    used: int
    limit: int
    unlimited: bool
    remaining: int
    percent: float
    softBlocked: bool
    blockedBy: str
    upgradeHint: bool
    bulkCap: int
    daily: Optional[Window]
    hourly: Optional[Window]
    periodStart: str
    resetDate: str
    asOf: str


class AsnSummary(TypedDict):
    asn: int
    label: str
    org: str
    networkType: str
    ipv4Prefixes: int
    ipv6Prefixes: int
    prefixes: int
    addresses: int


class _AsnSampleBase(TypedDict):
    prefix: str
    version: int


class AsnSample(_AsnSampleBase, total=False):
    addresses: int


class AsnDetail(AsnSummary):
    samplePrefixes: list[AsnSample]
    vpnRangePrefixes: int
    datacenterRangePrefixes: int
    rangesLoaded: bool


class AsnTopResponse(TypedDict):
    total: int
    by: str
    count: int
    results: list[AsnSummary]


class AsnSearchResponse(TypedDict):
    total: int
    query: str
    count: int
    results: list[AsnSummary]


class _CrawlerBase(TypedDict):
    slug: str
    name: str
    tokens: list[str]
    method: str
    verifiable: bool


class Crawler(_CrawlerBase, total=False):
    reverseDns: list[str]
    prefixFiles: list[str]
    asns: list[int]
    docs: str
    note: str


class CrawlerList(TypedDict):
    crawlers: list[Crawler]
    count: int
    note: str


class RateLimitInfo(TypedDict, total=False):
    meter: str
    limit: int
    remaining: int
    reset: int
    daily_limit: int
    daily_remaining: int
    daily_reset: int
    hourly_limit: int
    hourly_remaining: int
    hourly_reset: int
    usage_percent: int
    upgrade_hint: str
    upgrade_url: str
    upgrade_plan: str
    retry_after: int
