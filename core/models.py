"""数据结构定义，与 C++ ProtocolAttributes / ProtocolResult 对应。"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SshBanner:
    """SSH 版本标识结构化信息"""
    version_string: str = ""
    protocol_version: str = ""
    software: str = ""
    version: str = ""


@dataclass
class FtpFeatures:
    """FTP FEAT 扩展特性"""
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
    """单条指纹匹配结果"""
    vendor_id: int = 0
    vendor_name: str = ""
    pattern: str = ""
    confidence: float = 1.0  # 匹配置信度 (0-1)
    source: str = ""         # 匹配来源（如 "banner"、"ssh.software"）


@dataclass
class BannerResult:
    """单个协议的探测结果"""
    protocol: str
    host: str
    port: int
    accessible: bool = False
    banner: str = ""
    banner_truncated: bool = False
    response_time_ms: float = 0.0
    error: str = ""

    # 协议特定结构化信息
    ssh: Optional[SshBanner] = None
    ftp: Optional[FtpFeatures] = None

    # 指纹匹配结果
    vendor: str = ""                       # 主服务商名称
    vendor_id: int = 0                     # 主服务商 ID
    vendor_confidence: float = 0.0         # 主匹配置信度
    matched_rules: list[FingerprintMatch] = field(default_factory=list)


@dataclass
class HostResult:
    """一个主机的全部协议探测结果"""
    host: str
    results: dict[str, BannerResult] = field(default_factory=dict)
    total_time_ms: float = 0.0


@dataclass
class ProbeConfig:
    """全局探测配置"""
    connect_timeout: float = 3.0
    read_timeout: float = 4.0
    max_banner_bytes: int = 65536
    max_concurrent_hosts: int = 50
    fingerprint_path: Optional[str] = None    # 指纹库文件路径
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
    """单协议配置"""
    ports: list[int] = field(default_factory=list)
    enabled: bool = True
    send_feat: bool = True


@dataclass
class CircuitBreakerState:
    """熔断器状态"""
    failures: int = 0
    last_failure_time: float = 0.0
    open_until: float = 0.0
    max_failures: int = 10
    cooldown_seconds: float = 30.0
