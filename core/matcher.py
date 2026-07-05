"""
指纹加载与匹配模块。

职责：
- 从 JSON/YAML 等格式文件加载指纹库
- 对 BannerResult 执行正则/子串匹配
- 将匹配结果写入 BannerResult.vendor / matched_rules

指纹库格式（与 C++ 版 vendors.json 兼容）：
```json
{
  "vendors": [
    {
      "id": 401,
      "name": "OpenSSH",
      "pattern": ".*OpenSSH.*"
    }
  ]
}
```
"""

import json
import logging
import re
from pathlib import Path
from typing import Optional

from .identification import (
    LEGACY_CONFIDENCE,
    finalize_identification,
    legacy_rule_metadata,
    match_rank,
)
from .models import (
    BannerResult,
    EVIDENCE_STRENGTHS,
    FingerprintMatch,
    RESULT_TYPES,
)

logger = logging.getLogger("banner_scanner.matcher")
DEFAULT_PROTOCOL_LIBRARY_DIR = Path(__file__).resolve().parent.parent / "fingerprints" / "protocols"


# ==================== 指纹加载 ====================

class FingerprintRule:
    """单条指纹规则"""

    def __init__(self, vendor_id: int | str, name: str, pattern: str, protocol: str = "",
                 category: str = "implementation", priority: int = 100,
                 result_type: str = "", match_level: str = "",
                 evidence_strength: str = "", primary_eligible: Optional[bool] = None,
                 tie_breaker: int = 0, explanation: str = "",
                 labels: Optional[dict] = None, extract: Optional[list[dict]] = None):
        self.vendor_id = vendor_id
        self.name = name
        self.pattern = pattern
        self.protocol = protocol.upper()
        self.category = category
        self.priority = priority  # v1 compatibility only; never the primary rank.
        legacy = legacy_rule_metadata(category, priority)
        self.result_type = result_type or legacy["result_type"]
        self.match_level = match_level or legacy["match_level"]
        self.evidence_strength = evidence_strength or legacy["evidence_strength"]
        self.primary_eligible = (
            legacy["primary_eligible"] if primary_eligible is None else primary_eligible
        )
        self.tie_breaker = tie_breaker
        self.explanation = explanation
        self.labels = labels or {}
        self.extract = extract or []
        self._regex: Optional[re.Pattern] = None

    @property
    def specificity(self) -> int:
        literal = re.sub(r"\\.", "x", self.pattern)
        literal = re.sub(r"[^A-Za-z0-9]+", "", literal)
        return len(literal)

    @property
    def regex(self) -> re.Pattern:
        if self._regex is None:
            self._regex = re.compile(self.pattern, re.IGNORECASE)
        return self._regex

    def match(self, text: str) -> bool:
        return bool(self.regex.search(text))

    def to_dict(self) -> dict:
        return {
            "vendor_id": self.vendor_id,
            "vendor_name": self.name,
            "protocol": self.protocol,
            "category": self.category,
            "priority": self.priority,
            "result_type": self.result_type,
            "match_level": self.match_level,
            "evidence_strength": self.evidence_strength,
            "primary_eligible": self.primary_eligible,
            "tie_breaker": self.tie_breaker,
            "labels": self.labels,
            "extract": self.extract,
            "pattern": self.pattern,
        }


class FingerprintLoader:
    """指纹库加载器，支持多种格式"""

    @staticmethod
    def load(path: str | Path) -> list[FingerprintRule]:
        path = Path(path)

        if path.exists() and path.is_dir():
            files = sorted(path.glob("*_fingerprints.json"))
            if not files:
                raise FileNotFoundError(
                    f"No protocol fingerprint files found in: {path}"
                )
            rules = []
            for file_path in files:
                rules.extend(FingerprintLoader._load_json(file_path))
            _validate_rule_set(rules)
            logger.info(
                "Loaded %d fingerprint rules from %d protocol libraries in %s",
                len(rules), len(files), path,
            )
            return rules

        suffix = path.suffix.lower()
        loaders = {
            ".json": FingerprintLoader._load_json,
        }

        loader = loaders.get(suffix)
        if loader is None:
            raise ValueError(
                f"Unsupported fingerprint format: {suffix}. "
                f"Supported: {list(loaders.keys())}"
            )

        if not path.exists():
            raise FileNotFoundError(f"Fingerprint file not found: {path}")

        rules = loader(path)
        _validate_rule_set(rules)
        logger.info(
            "Loaded %d fingerprint rules from %s", len(rules), path
        )
        return rules

    @staticmethod
    def _load_json(path: Path) -> list[FingerprintRule]:
        with open(path, "r") as f:
            data = json.load(f)

        vendors = data.get("vendors", [])
        library_protocol = str(data.get("protocol") or "").upper()
        rules = [
            FingerprintRule(
                vendor_id=v["id"],
                name=v["name"],
                pattern=v["pattern"],
                protocol=str(v.get("protocol") or library_protocol),
                category=str(v.get("category") or ""),
                priority=int(v.get("priority", 100)),
                result_type=str(v.get("result_type") or ""),
                match_level=str(v.get("match_level") or ""),
                evidence_strength=str(v.get("evidence_strength") or ""),
                primary_eligible=v.get("primary_eligible"),
                tie_breaker=int(v.get("tie_breaker", 0)),
                explanation=str(v.get("explanation") or ""),
                labels=dict(v.get("labels") or {}),
                extract=list(v.get("extract") or []),
            )
            for v in vendors
        ]
        _validate_rule_set(rules)
        return rules


def _validate_rule_set(rules: list[FingerprintRule]) -> None:
    seen: set[int | str] = set()
    for rule in rules:
        if rule.vendor_id in seen:
            raise ValueError(f"Duplicate fingerprint rule id: {rule.vendor_id}")
        seen.add(rule.vendor_id)
        if rule.result_type not in RESULT_TYPES:
            raise ValueError(
                f"Invalid result_type {rule.result_type!r} in rule {rule.vendor_id}"
            )
        if rule.evidence_strength not in EVIDENCE_STRENGTHS:
            raise ValueError(
                "Invalid evidence_strength "
                f"{rule.evidence_strength!r} in rule {rule.vendor_id}"
            )
        try:
            rule.regex
        except re.error as exc:
            raise ValueError(f"Invalid regex in rule {rule.vendor_id}: {exc}") from exc


# ==================== 指纹匹配器 ====================

class FingerprintMatcher:
    """指纹匹配器。加载指纹库并对探测结果执行匹配。"""

    def __init__(self, rules: Optional[list[FingerprintRule]] = None):
        self._rules = rules or []

    @classmethod
    def load(cls, path: str | Path) -> "FingerprintMatcher":
        """从文件加载指纹库并创建匹配器"""
        rules = FingerprintLoader.load(path)
        return cls(rules=rules)

    @classmethod
    def load_from_dict(cls, data: dict) -> "FingerprintMatcher":
        """从字典加载指纹库（用于测试/动态加载）"""
        vendors = data.get("vendors", [])
        library_protocol = str(data.get("protocol") or "").upper()
        rules = [
            FingerprintRule(
                vendor_id=v["id"],
                name=v["name"],
                pattern=v["pattern"],
                protocol=str(v.get("protocol") or library_protocol),
                category=str(v.get("category") or ""),
                priority=int(v.get("priority", 100)),
                result_type=str(v.get("result_type") or ""),
                match_level=str(v.get("match_level") or ""),
                evidence_strength=str(v.get("evidence_strength") or ""),
                primary_eligible=v.get("primary_eligible"),
                tie_breaker=int(v.get("tie_breaker", 0)),
                explanation=str(v.get("explanation") or ""),
                labels=dict(v.get("labels") or {}),
                extract=list(v.get("extract") or []),
            )
            for v in vendors
        ]
        _validate_rule_set(rules)
        return cls(rules=rules)

    # ---- 匹配入口 ----

    def match(self, result: BannerResult) -> BannerResult:
        """对单个 BannerResult 执行指纹匹配，结果写入 vendor / matched_rules"""
        if not result.accessible:
            return result
        if not result.banner and not result.banner_raw_hex:
            return result

        candidates = self._collect_candidates(result)
        matches: list[FingerprintMatch] = []
        result_protocol = result.protocol.upper()

        for rule in self._rules:
            if rule.protocol and rule.protocol != result_protocol:
                continue
            for source, text in candidates:
                m = rule.regex.search(text)
                if m:
                    match_len = m.end() - m.start()
                    extracted = {}
                    for extractor in rule.extract:
                        field = str(extractor.get("field") or "")
                        group = extractor.get("group")
                        if not field or group in (None, ""):
                            continue
                        try:
                            value = m.group(group)
                        except (IndexError, KeyError):
                            continue
                        if value:
                            extracted[field] = str(value).strip()
                    fm = FingerprintMatch(
                        vendor_id=rule.vendor_id,
                        vendor_name=rule.name,
                        pattern=rule.pattern,
                        confidence=LEGACY_CONFIDENCE.get(rule.evidence_strength, 0.0),
                        source=source,
                        category=rule.category,
                        labels=rule.labels,
                        extracted=extracted,
                        result_type=rule.result_type,
                        match_level=rule.match_level,
                        evidence_strength=rule.evidence_strength,
                        primary_eligible=rule.primary_eligible,
                        tie_breaker=rule.tie_breaker,
                        explanation=rule.explanation,
                        match_length=match_len,
                        specificity=rule.specificity,
                    )
                    matches.append(fm)

        matches.sort(key=match_rank, reverse=True)
        seen_ids = set()
        unique: list[FingerprintMatch] = []
        for fm in matches:
            if fm.vendor_id not in seen_ids:
                seen_ids.add(fm.vendor_id)
                unique.append(fm)

        result.matched_rules = unique
        return finalize_identification(result)

    def match_host(self, host_result) -> None:
        """对 HostResult 中所有协议的 BannerResult 执行匹配"""
        for br in host_result.results.values():
            self.match(br)

    # ---- 内部 ----

    def _collect_candidates(self, result: BannerResult) -> list[tuple[str, str]]:
        """收集待匹配的文本来源"""
        candidates = []
        if result.banner:
            candidates.append(("banner", result.banner))

        # SSH：用结构化字段做额外匹配
        if result.ssh:
            if result.ssh.software:
                candidates.append(("ssh.software", result.ssh.software))

        # Telnet IAC 字节 hex + 标准化签名
        if result.banner_raw_hex:
            candidates.append(("telnet_raw_hex", result.banner_raw_hex))
        if result.info and result.info.get("iac_signature"):
            candidates.append(("iac_signature", result.info["iac_signature"]))
        if result.info and result.info.get("micro_features"):
            mf = result.info["micro_features"]
            micro_text = f"PROMPT={mf.get('prompt_type','')} LE={mf.get('line_ending','')} TS={'1' if mf.get('trailing_space') else '0'} LCRLF={mf.get('leading_crlf',0)} ANSI={'1' if mf.get('has_ansi') else '0'}"
            # 长度簇
            if mf.get("length_cluster"):
                micro_text += f" LEN={mf['length_cluster']}"
            candidates.append(("micro_features", micro_text))

        # TCP 层指纹
        if result.info and result.info.get("tcp_info"):
            ti = result.info["tcp_info"]
            tcp_text = f"MSS={ti.get('mss','?')} BUF={ti.get('sndbuf','?')}"
            candidates.append(("tcp_info", tcp_text))

        # 长度+填充指纹
        if result.info:
            if result.info.get("length_cluster"):
                candidates.append(("length_cluster", f"LEN={result.info['length_cluster']}"))
            if result.info.get("padding"):
                candidates.append(("padding", f"PAD={result.info['padding']}"))

        return candidates

    # ---- 查询 ----

    def get_vendor_name(self, vendor_id: int | str) -> Optional[str]:
        for r in self._rules:
            if r.vendor_id == vendor_id:
                return r.name
        return None

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def stats(self) -> dict:
        by_protocol = {}
        for rule in self._rules:
            protocol = rule.protocol or "UNSCOPED"
            by_protocol[protocol] = by_protocol.get(protocol, 0) + 1
        return {
            "total_rules": len(self._rules),
            "rules_by_protocol": by_protocol,
            "vendors": list(set(r.name for r in self._rules)),
        }


# ==================== Banner 标准化 ====================

def normalize_banner(banner: str) -> str:
    """标准化 Banner 字符串，去除干扰匹配的动态内容。

    与 C++ 版 normalize_banner / extract_banner_key 功能一致。
    - 去除首尾空白
    - 去除 Cruise ID / 时间戳（如 [1234567890] 格式的括号内数字）
    - 统一空白字符
    """
    if not banner:
        return banner

    text = banner.strip()

    # 去除方括号内的纯数字（常见于邮件服务的时间戳/ID）
    text = re.sub(r"\[\d+\]", "", text)

    # 去除 IP 地址（避免干扰厂商识别）
    text = re.sub(r"\[?\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b\]?", "", text)

    # 统一空白
    text = re.sub(r"\s+", " ", text).strip()

    return text


def extract_banner_key(banner: str) -> str:
    """提取 Banner 中的关键识别信息。

    与 C++ 版 extract_banner_key 对应：
    - 取第一行
    - 归一化空白
    - 截断到 120 字符
    """
    if not banner:
        return ""

    first_line = banner.split("\n")[0].strip()
    key = re.sub(r"\s+", " ", first_line)
    return key[:120]


# ==================== 文件级便捷匹配 ====================

def match_banner(
    banner: str,
    rules: list[FingerprintRule],
) -> list[FingerprintMatch]:
    """对单条 Banner 文本执行匹配，返回匹配结果列表"""
    matches = []
    for rule in rules:
        if rule.match(banner):
            matches.append(FingerprintMatch(
                vendor_id=rule.vendor_id,
                vendor_name=rule.name,
                pattern=rule.pattern,
            ))
    return matches
