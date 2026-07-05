"""Internal offline-identification regression tests."""

from banner_scanner.core.database_matcher import DatabaseFingerprintMatcher
from banner_scanner.core.identify import OfflineIdentifier
from banner_scanner.core.matcher import FingerprintMatcher


def test_offline_identifier_uses_banner_and_structured_fields():
    matcher = FingerprintMatcher.load_from_dict({
        "protocol": "SSH",
        "vendors": [{
            "id": "ssh.software.openssh",
            "name": "OpenSSH",
            "pattern": "OpenSSH",
            "result_type": "software",
            "match_level": "software_name",
            "evidence_strength": "strong",
            "primary_eligible": True,
        }],
    })
    identifier = OfflineIdentifier(
        matcher=matcher,
        database_matcher=DatabaseFingerprintMatcher([]),
    )
    result = identifier.identify(
        "ssh",
        raw_banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu",
        structured_fields={"software": "OpenSSH", "version": "8.9p1"},
    )

    assert result.primary_identification is not None
    assert result.primary_identification.name == "OpenSSH"
    assert result.primary_identification.version == "8.9p1"
    assert result.evidence_trace[0].operation == "offline_evidence"


def test_offline_identifier_rejects_unknown_protocol():
    identifier = OfflineIdentifier(
        matcher=FingerprintMatcher([]),
        database_matcher=DatabaseFingerprintMatcher([]),
    )
    try:
        identifier.identify("smtp", raw_banner="220 hello")
        assert False, "Expected unsupported protocol failure"
    except ValueError as exc:
        assert "Unsupported protocol" in str(exc)
