"""Server-enforced MCP target and runtime policy."""

from __future__ import annotations

import ipaddress
import os
import re
import time
from collections import deque
from dataclasses import asdict, dataclass


SUPPORTED_PROTOCOLS = ("ssh", "ftp", "telnet", "redis", "mysql", "pgsql")
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)


class RequestValidationError(ValueError):
    """Raised when an MCP request violates server policy."""


@dataclass(frozen=True)
class RuntimeLimits:
    probe_banner_max_hosts: int = 20
    scan_batch_max_hosts: int = 100
    probe_banner_default_concurrency: int = 5
    probe_banner_max_concurrency: int = 20
    scan_batch_default_concurrency: int = 20
    scan_batch_max_concurrency: int = 50
    global_max_concurrency: int = 100
    max_retries: int = 5
    max_request_body_bytes: int = 1024 * 1024
    max_resolved_ips_per_host: int = 16
    max_banner_preview_bytes: int = 4096
    max_evidence_preview_bytes: int = 1024
    request_timeout_seconds: float = 300.0
    max_requests_per_minute: int = 60

    def to_dict(self) -> dict:
        return asdict(self)


def _networks(value: str) -> tuple[ipaddress._BaseNetwork, ...]:
    return tuple(
        ipaddress.ip_network(item.strip(), strict=False)
        for item in value.split(",") if item.strip()
    )


@dataclass(frozen=True)
class TargetPolicy:
    allowlist: tuple[ipaddress._BaseNetwork, ...] = ()
    denylist: tuple[ipaddress._BaseNetwork, ...] = ()
    allowed_domains: tuple[str, ...] = ()
    private_network_policy: str = "allow"

    @classmethod
    def from_env(cls) -> "TargetPolicy":
        private_policy = os.environ.get("BANNER_SCANNER_PRIVATE_NETWORK_POLICY", "allow").lower()
        if private_policy not in {"allow", "deny", "allowlist_only"}:
            raise ValueError(
                "BANNER_SCANNER_PRIVATE_NETWORK_POLICY must be allow, deny, or allowlist_only"
            )
        return cls(
            allowlist=_networks(os.environ.get("BANNER_SCANNER_ALLOWLIST", "")),
            denylist=_networks(os.environ.get("BANNER_SCANNER_DENYLIST", "")),
            allowed_domains=tuple(
                item.strip().casefold()
                for item in os.environ.get("BANNER_SCANNER_ALLOWED_DOMAINS", "").split(",")
                if item.strip()
            ),
            private_network_policy=private_policy,
        )

    @property
    def allowlist_enabled(self) -> bool:
        return bool(self.allowlist or self.allowed_domains)

    def validate_host(self, host: str) -> str:
        if not isinstance(host, str):
            raise RequestValidationError("Each host must be a string")
        candidate = host.strip()
        if not candidate:
            raise RequestValidationError("Host cannot be empty")
        if any(token in candidate for token in ("://", "/", "?", "#")):
            raise RequestValidationError(f"Host must not contain a URL or path: {host!r}")

        try:
            address = ipaddress.ip_address(candidate.strip("[]"))
        except ValueError:
            if ":" in candidate:
                raise RequestValidationError(
                    f"Custom ports are not accepted in host values: {host!r}"
                )
            try:
                ascii_host = candidate.rstrip(".").encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise RequestValidationError(f"Invalid domain name: {host!r}") from exc
            if not HOSTNAME_RE.fullmatch(ascii_host):
                raise RequestValidationError(f"Invalid IP address or domain: {host!r}")
            if self.allowed_domains and not any(
                ascii_host.casefold() == domain
                or ascii_host.casefold().endswith(f".{domain}")
                for domain in self.allowed_domains
            ):
                raise RequestValidationError(f"Domain is outside the configured allowlist: {host!r}")
            return ascii_host

        self.validate_address(address)
        return str(address)

    def validate_address(self, address: ipaddress._BaseAddress) -> None:
        if address.is_unspecified or address.is_multicast:
            raise RequestValidationError(f"Target address is not probeable: {address}")
        if any(address in network for network in self.denylist):
            raise RequestValidationError(f"Target address is denied by server policy: {address}")
        allowed = any(address in network for network in self.allowlist)
        if self.allowlist and not allowed:
            raise RequestValidationError(f"Target address is outside the configured allowlist: {address}")
        if address.is_private:
            if self.private_network_policy == "deny":
                raise RequestValidationError(f"Private-network target is disabled: {address}")
            if self.private_network_policy == "allowlist_only" and not allowed:
                raise RequestValidationError(f"Private-network target is not allowlisted: {address}")

    def to_dict(self) -> dict:
        return {
            "allowlist_enabled": self.allowlist_enabled,
            "denylist_enabled": bool(self.denylist),
            "private_network_policy": self.private_network_policy,
        }


@dataclass(frozen=True)
class ValidatedProbeRequest:
    hosts: list[str]
    protocols: list[str]
    concurrency: int
    retries: int
    detail_level: str
    result_mode: str


def validate_probe_request(*, hosts, protocols, concurrency, retries,
                           detail_level: str, authorization_confirmed: bool,
                           batch: bool, limits: RuntimeLimits,
                           target_policy: TargetPolicy,
                           result_mode: str = "full") -> ValidatedProbeRequest:
    if authorization_confirmed is not True:
        raise RequestValidationError(
            "authorization_confirmed=true is required and records intent only; "
            "server target policy is enforced separately"
        )
    if not isinstance(hosts, list):
        raise RequestValidationError("hosts must be an array")
    max_hosts = limits.scan_batch_max_hosts if batch else limits.probe_banner_max_hosts
    if not 1 <= len(hosts) <= max_hosts:
        raise RequestValidationError(f"hosts must contain between 1 and {max_hosts} targets")
    normalized_hosts = [target_policy.validate_host(host) for host in hosts]
    if len(set(normalized_hosts)) != len(normalized_hosts):
        normalized_hosts = list(dict.fromkeys(normalized_hosts))

    if protocols is None:
        normalized_protocols = list(SUPPORTED_PROTOCOLS)
    elif not isinstance(protocols, list) or not protocols:
        raise RequestValidationError("protocols must be a non-empty array")
    else:
        normalized_protocols = [str(protocol).lower() for protocol in protocols]
    invalid = [protocol for protocol in normalized_protocols if protocol not in SUPPORTED_PROTOCOLS]
    if invalid:
        raise RequestValidationError(f"Unsupported protocols: {invalid}")
    if batch and len(normalized_protocols) != 1:
        raise RequestValidationError("scan_batch accepts exactly one protocol")

    try:
        concurrency = int(concurrency)
        retries = int(retries)
    except (TypeError, ValueError) as exc:
        raise RequestValidationError("concurrency and retries must be integers") from exc
    max_concurrency = (
        limits.scan_batch_max_concurrency if batch else limits.probe_banner_max_concurrency
    )
    if not 1 <= concurrency <= max_concurrency:
        raise RequestValidationError(f"concurrency must be between 1 and {max_concurrency}")
    if not 0 <= retries <= limits.max_retries:
        raise RequestValidationError(f"retries must be between 0 and {limits.max_retries}")
    if detail_level not in {"summary", "evidence"}:
        raise RequestValidationError("detail_level must be summary or evidence")
    if result_mode not in {"full", "unique"}:
        raise RequestValidationError("result_mode must be full or unique")

    return ValidatedProbeRequest(
        hosts=normalized_hosts,
        protocols=normalized_protocols,
        concurrency=concurrency,
        retries=retries,
        detail_level=detail_level,
        result_mode=result_mode,
    )


class RateLimiter:
    """Small in-process request limiter for trusted local deployments."""

    def __init__(self, max_requests: int, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps: deque[float] = deque()

    def check(self) -> None:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        while self._timestamps and self._timestamps[0] <= cutoff:
            self._timestamps.popleft()
        if len(self._timestamps) >= self.max_requests:
            raise RequestValidationError("MCP request rate limit exceeded")
        self._timestamps.append(now)
