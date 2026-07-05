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
        "authorization_confirmed": True,
        "batch": False,
        "limits": RuntimeLimits(),
        "target_policy": TargetPolicy(),
    }
    values.update(overrides)
    return validate_probe_request(**values)


def test_authorization_confirmation_is_required():
    try:
        _validate(authorization_confirmed=False)
        assert False, "Expected authorization confirmation failure"
    except RequestValidationError as exc:
        assert "records intent only" in str(exc)


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


def test_private_network_policy_is_server_enforced():
    policy = TargetPolicy(private_network_policy="deny")
    try:
        policy.validate_address(ipaddress.ip_address("10.0.0.1"))
        assert False, "Expected private-network policy failure"
    except RequestValidationError:
        pass
