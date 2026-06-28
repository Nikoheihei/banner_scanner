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

from .models import BannerResult, FingerprintMatch

logger = logging.getLogger("banner_scanner.matcher")
DEFAULT_PROTOCOL_LIBRARY_DIR = Path(__file__).resolve().parent.parent / "fingerprints" / "protocols"


# ==================== 指纹加载 ====================

class FingerprintRule:
    """单条指纹规则"""

    def __init__(self, vendor_id: int, name: str, pattern: str, protocol: str = "",
                 category: str = "implementation", priority: int = 100):
        self.vendor_id = vendor_id
        self.name = name
        self.pattern = pattern
        self.protocol = protocol.upper()
        self.category = category
        self.priority = priority
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
        return [
            FingerprintRule(
                vendor_id=v["id"],
                name=v["name"],
                pattern=v["pattern"],
                protocol=str(v.get("protocol") or library_protocol),
                category=str(v.get("category") or "implementation"),
                priority=int(v.get("priority", 100)),
            )
            for v in vendors
        ]


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
                category=str(v.get("category") or "implementation"),
                priority=int(v.get("priority", 100)),
            )
            for v in vendors
        ]
        return cls(rules=rules)

    # ---- 匹配入口 ----

    def match(self, result: BannerResult) -> BannerResult:
        """对单个 BannerResult 执行指纹匹配，结果写入 vendor / matched_rules"""
        if not result.accessible:
            return result
        if not result.banner and not result.banner_raw_hex:
            return result

        candidates = self._collect_candidates(result)
        matches = []
        result_protocol = result.protocol.upper()

        for rule in self._rules:
            if rule.protocol and rule.protocol != result_protocol:
                continue
            for source, text in candidates:
                m = rule.regex.search(text)
                if m:
                    match_len = m.end() - m.start()
                    fm = FingerprintMatch(
                        vendor_id=rule.vendor_id,
                        vendor_name=rule.name,
                        pattern=rule.pattern,
                        confidence=min(1.0, match_len / max(len(text), 1) * 2),
                        source=source,
                        category=rule.category,
                    )
                    matches.append((rule.priority, rule.specificity, match_len, fm))

        # 明确实现优先于设备族、状态和兜底模板；同级再比较规则特异性。
        matches.sort(key=lambda x: (-x[0], -x[1], -x[2]))
        seen_ids = set()
        unique: list[FingerprintMatch] = []
        for _, _, _, fm in matches:
            if fm.vendor_id not in seen_ids:
                seen_ids.add(fm.vendor_id)
                unique.append(fm)

        result.matched_rules = unique
        if unique:
            primary = unique[0]
            result.vendor = primary.vendor_name
            result.vendor_id = primary.vendor_id
            result.vendor_confidence = primary.confidence

        return result

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
            if result.ssh.version_string:
                candidates.append(("ssh.version_string", result.ssh.version_string))

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

    def get_vendor_name(self, vendor_id: int) -> Optional[str]:
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
