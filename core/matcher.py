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


# ==================== 指纹加载 ====================

class FingerprintRule:
    """单条指纹规则"""

    def __init__(self, vendor_id: int, name: str, pattern: str):
        self.vendor_id = vendor_id
        self.name = name
        self.pattern = pattern
        self._regex: Optional[re.Pattern] = None

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
            "pattern": self.pattern,
        }


class FingerprintLoader:
    """指纹库加载器，支持多种格式"""

    @staticmethod
    def load(path: str | Path) -> list[FingerprintRule]:
        path = Path(path)

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
        return [
            FingerprintRule(
                vendor_id=v["id"],
                name=v["name"],
                pattern=v["pattern"],
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
        rules = [
            FingerprintRule(
                vendor_id=v["id"],
                name=v["name"],
                pattern=v["pattern"],
            )
            for v in vendors
        ]
        return cls(rules=rules)

    # ---- 匹配入口 ----

    def match(self, result: BannerResult) -> BannerResult:
        """对单个 BannerResult 执行指纹匹配，结果写入 vendor / matched_rules"""
        if not result.accessible or not result.banner:
            return result

        candidates = self._collect_candidates(result)
        matches = []

        for rule in self._rules:
            for source, text in candidates:
                if rule.match(text):
                    fm = FingerprintMatch(
                        vendor_id=rule.vendor_id,
                        vendor_name=rule.name,
                        pattern=rule.pattern,
                        confidence=1.0,
                        source=source,
                    )
                    matches.append(fm)

        # 去重：同 vendor 只保留第一个匹配
        seen_ids = set()
        unique: list[FingerprintMatch] = []
        for m in matches:
            if m.vendor_id not in seen_ids:
                seen_ids.add(m.vendor_id)
                unique.append(m)

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
        candidates = [("banner", result.banner)]

        # SSH：用结构化字段做额外匹配
        if result.ssh:
            if result.ssh.software:
                candidates.append(("ssh.software", result.ssh.software))
            if result.ssh.version_string:
                candidates.append(("ssh.version_string", result.ssh.version_string))

        # FTP：banner 已经覆盖了 FEAT 里的信息
        # 但如果想单独匹配 FEAT 特征，可以在这里扩展

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
        return {
            "total_rules": len(self._rules),
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
