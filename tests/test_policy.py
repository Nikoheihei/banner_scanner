"""MCP runtime-policy tests."""

import ipaddress

from banner_scanner.server.policy import (
    RequestValidationError,
    RuntimeLimits,
    TargetPolicy,
    validate_probe_request,
)


def _validate(**overrides):
    values = {
        "hosts": ["192.0.2.1"],
        "protocols": ["ssh"],
        "concurrency": 5,
        "retries": 2,
        "detail_level": "evidence",
        "batch": False,
        "limits": RuntimeLimits(),
        "target_policy": TargetPolicy(),
    }
    values.update(overrides)
    return validate_probe_request(**values)


def test_ip_in_allowlist_is_allowed():
    policy = TargetPolicy(
        allowlist=(ipaddress.ip_network("8.8.8.0/24"),),
    )

    request = _validate(hosts=["8.8.8.8"], target_policy=policy)

    assert request.hosts == ["8.8.8.8"]


def test_ip_outside_allowlist_is_rejected():
    policy = TargetPolicy(
        allowlist=(ipaddress.ip_network("8.8.8.0/24"),),
    )

    try:
        _validate(hosts=["1.1.1.1"], target_policy=policy)
        assert False, "Expected allowlist failure"
    except RequestValidationError as exc:
        assert "outside the configured allowlist" in str(exc)


def test_ip_in_denylist_is_rejected():
    policy = TargetPolicy(
        denylist=(ipaddress.ip_network("1.2.3.4/32"),),
    )

    try:
        _validate(hosts=["1.2.3.4"], target_policy=policy)
        assert False, "Expected denylist failure"
    except RequestValidationError as exc:
        assert "denied by server policy" in str(exc)


def test_denylist_takes_precedence_over_allowlist():
    policy = TargetPolicy(
        allowlist=(ipaddress.ip_network("1.2.3.0/24"),),
        denylist=(ipaddress.ip_network("1.2.3.4/32"),),
    )

    try:
        _validate(hosts=["1.2.3.4"], target_policy=policy)
        assert False, "Expected denylist precedence failure"
    except RequestValidationError as exc:
        assert "denied by server policy" in str(exc)


def test_private_network_allowlist_only_rejects_unlisted_private_ip():
    policy = TargetPolicy(private_network_policy="allowlist_only")

    try:
        _validate(hosts=["10.0.0.1"], target_policy=policy)
        assert False, "Expected private allowlist-only failure"
    except RequestValidationError as exc:
        assert "not allowlisted" in str(exc)


def test_private_network_allowlist_only_accepts_allowlisted_private_ip():
    policy = TargetPolicy(
        allowlist=(ipaddress.ip_network("10.0.0.0/24"),),
        private_network_policy="allowlist_only",
    )

    request = _validate(hosts=["10.0.0.1"], target_policy=policy)

    assert request.hosts == ["10.0.0.1"]


def test_domain_in_allowed_domains_is_allowed():
    policy = TargetPolicy(allowed_domains=("example.com",))

    request = _validate(hosts=["service.example.com"], target_policy=policy)

    assert request.hosts == ["service.example.com"]


def test_domain_is_accepted_for_later_ip_policy_check_when_no_domain_allowlist_exists():
    policy = TargetPolicy(
        allowlist=(ipaddress.ip_network("203.0.113.0/24"),),
    )

    request = _validate(hosts=["service.example.com"], target_policy=policy)

    assert request.hosts == ["service.example.com"]


def test_domain_outside_allowed_domains_is_rejected():
    policy = TargetPolicy(allowed_domains=("example.com",))

    try:
        _validate(hosts=["example.net"], target_policy=policy)
        assert False, "Expected domain allowlist failure"
    except RequestValidationError as exc:
        assert "outside the configured allowlist" in str(exc)


def test_urls_and_custom_ports_are_rejected():
    for host in ("https://example.com", "example.com:22"):
        try:
            _validate(hosts=[host])
            assert False, f"Expected invalid host failure for {host}"
        except RequestValidationError:
            pass


def test_tool_specific_concurrency_is_enforced():
    try:
        _validate(concurrency=21)
        assert False, "Expected concurrency limit failure"
    except RequestValidationError as exc:
        assert "between 1 and 20" in str(exc)


def test_scan_batch_requires_one_protocol():
    try:
        _validate(batch=True, protocols=["ssh", "ftp"])
        assert False, "Expected batch protocol failure"
    except RequestValidationError as exc:
        assert "exactly one protocol" in str(exc)


def test_result_mode_is_validated():
    try:
        _validate(result_mode="compact")
        assert False, "Expected invalid result mode failure"
    except RequestValidationError as exc:
        assert "full or unique" in str(exc)


def test_private_network_policy_is_server_enforced():
    policy = TargetPolicy(private_network_policy="deny")
    try:
        policy.validate_address(ipaddress.ip_address("10.0.0.1"))
        assert False, "Expected private-network policy failure"
    except RequestValidationError:
        pass
