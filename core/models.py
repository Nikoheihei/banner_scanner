"""数据结构定义。"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SshBanner:
    version_string: str = ""
    protocol_version: str = ""
    software: str = ""
    version: str = ""


@dataclass
class FtpFeatures:
    features: str = ""
    utf8: bool = False
    auth_tls: bool = False
    auth_ssl: bool = False
    size_cmd: bool = False
    mdtm: bool = False
    mldst: bool = False
    tvfs: bool = False
    xcrc: bool = False
    xcup: bool = False


@dataclass
class FingerprintMatch:
    vendor_id: int = 0
    vendor_name: str = ""
    pattern: str = ""
    confidence: float = 1.0
    source: str = ""


@dataclass
class BannerResult:
    protocol: str
    host: str
    port: int
    accessible: bool = False
    banner: str = ""
    banner_truncated: bool = False
    response_time_ms: float = 0.0
    error: str = ""
    ssh: Optional[SshBanner] = None
    ftp: Optional[FtpFeatures] = None
    vendor: str = ""
    vendor_id: int = 0
    vendor_confidence: float = 0.0
    matched_rules: list[FingerprintMatch] = field(default_factory=list)


@dataclass
class HostResult:
    host: str
    results: dict[str, BannerResult] = field(default_factory=dict)
    total_time_ms: float = 0.0


@dataclass
class ProbeConfig:
    connect_timeout: float = 3.0
    read_timeout: float = 4.0
    max_banner_bytes: int = 65536
    fingerprint_path: Optional[str] = None
    protocol_config: dict[str, "ProtocolConfig"] = field(default_factory=dict)

    def __post_init__(self):
        if not self.protocol_config:
            self.protocol_config = {
                "ssh": ProtocolConfig(ports=[22]),
                "ftp": ProtocolConfig(ports=[21, 990]),
                "telnet": ProtocolConfig(ports=[23]),
            }


@dataclass
class ProtocolConfig:
    ports: list[int] = field(default_factory=list)
    enabled: bool = True
    send_feat: bool = True
