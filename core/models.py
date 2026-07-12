"""数据结构定义。"""

from dataclasses import dataclass, field
from typing import Any, Optional


RESULT_TYPES = (
    "software",
    "software_family",
    "device_family",
    "service_status",
    "capability",
    "authentication",
    "deployment",
    "provider",
    "protocol_identity",
)

EVIDENCE_STRENGTHS = ("conclusive", "strong", "moderate", "weak")


@dataclass
class SshBanner:
    """SSH Banner 解析结果，含软件版本 + OS 指纹"""
    version_string: str = ""
    protocol_version: str = ""
    software: str = ""
    version: str = ""
    # OS 信息 (从 comments 中提取)
    os_type: str = ""          # e.g. "Ubuntu", "Debian", "FreeBSD", "Windows"
    os_version: str = ""       # e.g. "3ubuntu0.13", "2+deb12u5"
    os_distro: str = ""        # e.g. "Ubuntu-3ubuntu0.13", "Debian-2+deb12u5"
    comments: str = ""         # banner 中 comments 部分原始文本


@dataclass
class FtpFeatures:
    """FTP FEAT 特性 + 软件识别"""
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
    # 软件信息 (从 Banner 提取)
    software: str = ""         # e.g. "vsFTPd", "ProFTPD", "FileZilla Server"
    version: str = ""          # e.g. "3.0.5", "1.3.5rc3"
    full_banner: str = ""      # 完整原始 banner (多行)


@dataclass
class TelnetBanner:
    """Telnet 探测解析结果"""
    banner: str = ""           # 过滤控制字符后的文本
    banner_raw_hex: str = ""   # 原始 hex (前 64 字节)
    has_login_prompt: bool = False   # 是否有登录提示
    has_iac_negotiation: bool = False  # 是否有 IAC 协商
    extracted_text: str = ""   # 提取的可读文本
    detected_service: str = "" # 检测到的服务类型


@dataclass
class RedisInfo:
    """Redis/RESP 主动探测结果。"""
    ping_response: str = ""
    info_response: str = ""
    fields: dict[str, str] = field(default_factory=dict)
    implementation: str = ""
    version: str = ""
    mode: str = ""
    os: str = ""


@dataclass
class MysqlInfo:
    """MySQL-compatible 初始握手字段。"""
    protocol_version: int = 0
    version: str = ""
    connection_id: int = 0
    capability_flags: int = 0
    character_set: int = 0
    status_flags: int = 0
    auth_plugin: str = ""
    implementation: str = ""
    error_code: int = 0
    sqlstate: str = ""
    error_message: str = ""


@dataclass
class PgsqlInfo:
    """PostgreSQL SSL/Startup 握手字段。"""
    protocol_version: int = 196608
    ssl_response: str = ""
    fields: dict[str, str] = field(default_factory=dict)
    auth_code: Optional[int] = None
    auth_method: str = ""
    parameters: dict[str, str] = field(default_factory=dict)
    message_types: list[str] = field(default_factory=list)
    implementation: str = ""


@dataclass
class FingerprintMatch:
    vendor_id: int | str = 0
    vendor_name: str = ""
    pattern: str = ""
    confidence: float = 1.0
    source: str = ""
    category: str = ""
    labels: dict[str, Any] = field(default_factory=dict)
    extracted: dict[str, str] = field(default_factory=dict)
    result_type: str = "software"
    match_level: str = "software_name"
    evidence_strength: str = "strong"
    primary_eligible: bool = True
    explanation: str = ""
    match_length: int = 0
    specificity: int = 0


@dataclass
class Identification:
    """A semantic identification returned to MCP clients.

    ``evidence_strength`` is an ordinal rule-evidence label.  It is not a
    probability and is intentionally kept separate from evaluation metrics.
    """

    result_type: str
    name: str
    version: str = ""
    evidence_strength: str = "strong"
    explanation: str = ""


@dataclass
class EvidenceStep:
    """Bounded evidence about one probe exchange step."""

    operation: str
    direction: str
    byte_count: int
    preview: str = ""
    elapsed_ms: float = 0.0


@dataclass
class ProbeFailure:
    """Structured reason for a failed or incomplete probe exchange.

    ``phase`` describes where the failure occurred. ``detail_code`` is a
    stable machine-readable diagnosis; it is an observation, not a statement
    about who or what caused a network failure.
    """

    phase: str
    detail_code: str
    message: str
    elapsed_ms: float = 0.0
    os_error: int | None = None


@dataclass
class BannerResult:
    protocol: str
    host: str
    port: int
    # The service may receive a domain and connect to one resolved address.
    # Keep both values so MCP callers can see exactly what was requested and used.
    input_host: str = ""
    resolved_ip: str = ""
    selected_ip: str = ""
    resolved_ips: list[str] = field(default_factory=list)
    attempted_ips: list[dict[str, Any]] = field(default_factory=list)
    accessible: bool = False
    banner: str = ""
    banner_truncated: bool = False
    response_time_ms: float = 0.0
    error: str = ""
    failure: Optional[ProbeFailure] = None
    ssh: Optional[SshBanner] = None
    ftp: Optional[FtpFeatures] = None
    telnet: Optional[TelnetBanner] = None
    redis: Optional[RedisInfo] = None
    mysql: Optional[MysqlInfo] = None
    pgsql: Optional[PgsqlInfo] = None
    banner_raw_hex: str = ""     # 原始字节 hex (用于 IAC 指纹匹配)
    response_sha256: str = ""    # 完整已捕获响应的 SHA-256，不保留原始副本
    vendor: str = ""
    vendor_id: int | str = 0
    vendor_confidence: float = 0.0
    matched_rules: list[FingerprintMatch] = field(default_factory=list)
    fingerprint_details: dict[str, Any] = field(default_factory=dict)
    protocol_status: str = "not_observed"
    observed_protocol: str = ""
    identification_status: str = "unidentified"
    primary_identification: Optional[Identification] = None
    identification_candidates: list[Identification] = field(default_factory=list)
    findings: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    evidence_trace: list[EvidenceStep] = field(default_factory=list)
    # 重试信息
    retry_count: int = 0                # 实际重试次数
    retry_attempts: int = 1             # 总尝试次数 (含首次)
    retry_elapsed_ms: float = 0.0       # 含重试的总耗时 (ms)
    retry_history: list[dict[str, Any]] = field(default_factory=list)
    # 统一提取信息 (跨协议)
    info: dict = field(default_factory=dict)  # {service_name, service_version, os, ...}


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
    database_fingerprint_path: Optional[str] = None
    protocol_config: dict[str, "ProtocolConfig"] = field(default_factory=dict)
    max_retries: int = 2         # 最大重试次数 (0 = 不重试)
    retry_base_delay: float = 1.0  # 重试基础延迟 (秒)

    def __post_init__(self):
        if not self.protocol_config:
            self.protocol_config = {
                "ssh": ProtocolConfig(ports=[22], connect_timeout=3.0, read_timeout=4.0),
                "ftp": ProtocolConfig(ports=[21, 990], connect_timeout=3.0, read_timeout=4.0),
                "telnet": ProtocolConfig(ports=[23], connect_timeout=5.0, read_timeout=8.0),
                "redis": ProtocolConfig(ports=[6379], connect_timeout=3.0, read_timeout=3.0),
                "mysql": ProtocolConfig(ports=[3306], connect_timeout=3.0, read_timeout=3.0),
                "pgsql": ProtocolConfig(ports=[5432], connect_timeout=3.0, read_timeout=3.0),
            }


@dataclass
class ProtocolConfig:
    ports: list[int] = field(default_factory=list)
    enabled: bool = True
    send_feat: bool = True
    connect_timeout: Optional[float] = None  # 覆盖全局 connect_timeout
    read_timeout: Optional[float] = None     # 覆盖全局 read_timeout


def get_effective_timeout(config: ProbeConfig, protocol: str) -> tuple:
    """获取某协议的有效超时 (connect_timeout, read_timeout)"""
    pc = config.protocol_config.get(protocol.lower())
    ct = (pc.connect_timeout if pc and pc.connect_timeout is not None
          else config.connect_timeout)
    rt = (pc.read_timeout if pc and pc.read_timeout is not None
          else config.read_timeout)
    return ct, rt
