"""Regression cases derived from the original six-protocol Banner corpora."""

from banner_scanner.core.identify import OfflineIdentifier
from banner_scanner.evaluation.active_fingerprint_eval import truth_label
from banner_scanner.server.serialization import banner_result_to_dict


def _identify(protocol: str, banner: str):
    return OfflineIdentifier.load_default().identify(protocol, raw_banner=banner)


def test_filezilla_enterprise_keeps_parent_family_without_conflict():
    result = _identify("FTP", "220-FileZilla Pro Enterprise Server 1.12.6\r\n")

    assert result.identification_status == "identified"
    assert result.primary_identification.name == "FileZilla Pro Enterprise"
    assert result.findings["software_family"][0]["name"] == "FileZilla"


def test_weonlydo_product_and_provider_are_parallel_facts():
    result = _identify("SSH", "SSH-2.0-WeOnlyDo-wodFTPD 3.3.0.424\r\n")

    assert result.identification_status == "identified"
    assert result.primary_identification.name == "wodFTPD"
    assert result.primary_identification.version == "3.3.0.424"
    assert result.findings["provider"][0]["name"] == "WeOnlyDo"


def test_mikrotik_banner_with_core_hostname_is_not_core_ftp_truth():
    banner = "220 Fun Valley Core Router FTP server (MikroTik 6.47.9) ready"
    assert truth_label("FTP", banner) != "Core FTP Server"


def test_ftp_response_on_telnet_probe_is_protocol_mismatch():
    result = _identify("TELNET", "220 Microsoft FTP Service\r\n")
    payload = banner_result_to_dict(result)

    assert result.protocol_status == "mismatch"
    assert result.observed_protocol == "FTP"
    assert result.primary_identification is None
    assert payload["protocol_status"] == "mismatch"
    assert payload["expected_protocol"] == "TELNET"
    assert payload["observed_protocol"] == "FTP"


def test_smtp_response_on_telnet_probe_is_protocol_mismatch():
    result = _identify(
        "TELNET",
        "220 mail.example Microsoft ESMTP MAIL Service ready\r\n",
    )
    assert result.protocol_status == "mismatch"
    assert result.observed_protocol == "SMTP"


def test_ssh_identification_line_allows_crlf_and_following_packets():
    result = _identify(
        "SSH",
        "SSH-2.0-mod_sftp/0.9.9\r\n\x00\x00\x00\x10binary-kex-data",
    )

    assert result.primary_identification.name == "mod_sftp"


def test_specific_ssh_aliases_have_clean_canonical_output():
    cases = (
        ("SSH-2.0-MaverickSynergy\r\n", "Maverick SSHD"),
        ("SSH-2.0-SFTPPlus TRIAL\r\n", "SFTPPlus"),
        (
            "SSH-2.0-1.82 sshlib: WinSSHD 4.21\r\n",
            "Bitvise SSH Server",
        ),
    )
    for banner, expected in cases:
        result = _identify("SSH", banner)
        assert result.primary_identification.name == expected

    bitvise = _identify("SSH", cases[-1][0])
    assert bitvise.primary_identification.version == "4.21"
    labels = bitvise.findings["software"][0]["labels"]
    assert "WinSSHD" in labels["aliases"]
    assert labels["provider"] == "Bitvise"
    assert bitvise.findings["software"][0]["extracted"]["component"] == "sshlib"


def test_paramiko_identification_line_may_include_ssh_comments():
    result = _identify(
        "SSH",
        "SSH-2.0-paramiko_2.1.3 501 command not implemented ERROR\r\n",
    )
    assert result.primary_identification.name == "Paramiko"


def test_wing_truth_requires_product_name_not_hostname_substring():
    assert truth_label("FTP", "220 Welcome to Liberwing FTP service.") == ""
    assert truth_label("FTP", "220 Welcome to E-CREWING FTP service.") == ""


def test_xlight_name_survives_damaged_greeting_text():
    result = _identify("FTP", "220 FTP-������ Xlight �������")
    assert result.primary_identification.name == "xlightftpd"


def test_telnet_ios_version_is_direct_cisco_software_evidence():
    result = _identify(
        "TELNET",
        "Router C2901\r\nModel - 2901 IOS version 15.2(4)M6\r\n",
    )
    assert result.primary_identification.name == "Cisco IOS telnetd"
