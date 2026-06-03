# Banner Scanner — 架构文档

## 概述

Banner Scanner 是一个轻量级网络协议 Banner 探测工具，支持从指定 IP 地址获取 **SSH**、**FTP**、**Telnet** 等协议的 Banner 信息。从 C++ [protocol_scanner](https://github.com/Open-Coder-oss/protocol_scanner) 项目提取核心探测逻辑，用 Python asyncio 重新实现，**零第三方依赖**。

---

## 设计原则

1. **精简聚焦** — 只做一件事：给定 IP，获取 Banner。不做大规模并发扫描。
2. **协议精确性** — 严格遵循各协议规范的握手/数据交换顺序。
3. **异步 I/O** — 使用 `asyncio` 统一管理连接超时和读写。
4. **结构化解析** — Banner 不是字符串，是结构化数据（软件名、版本号、协议版本、特性列表）。

---

## 模块结构

```
banner_scanner/
├── __init__.py          # 包声明
├── __main__.py          # CLI 入口（argparse + asyncio 调度）
├── probes.py            # 核心探测逻辑（三个协议实现 + 统一接口）
├── docs/
│   ├── ARCHITECTURE.md  # 本文档
│   └── PROTOCOLS.md     # 各协议 Banner 格式与解析规范
├── tests/
│   ├── test_parsers.py  # 单元测试：SSH/FTP/Telnet Banner 解析逻辑
│   └── test_probes.py   # 集成测试：对已知公共服务的探测验证
└── README.md            # 用户文档
```

---

## 核心模块说明

### `probes.py`

由三层组成：

```
probe_all(host, protocols, timeout)
    │
    ├─ probe_ssh(host, port, timeout)
    │     └─ parse_ssh_banner(banner) → SshBanner
    │
    ├─ probe_ftp(host, port, timeout, send_feat)
    │     ├─ parse_ftp_features(features_csv) → FtpFeatures
    │     └─ FTP 协议: 读取 Banner → 发送 FEAT → 读取特性列表
    │
    └─ probe_telnet(host, port, timeout)
          └─ 过滤 Telnet IAC 控制字符 → 提取可读文本
```

### 数据流

```
TCP connect ──→ 接收服务端初始数据 ──→ 提取 Banner ──→ 结构化解析 ──→ ProtocolResult
     │                    │                      │
  超时/拒绝             原始字节              SSH: 分割版本行
                                             FTP: 取第一行 + FEAT
                                             Telnet: 过滤控制字符
```

---

## 与 C++ 版的对比

| 维度 | C++ protocol_scanner | Python banner_scanner |
|------|---------------------|----------------------|
| **定位** | 大规模批量扫描（2600 IP/s） | 单/少量 IP 手工探测 |
| **并发** | 双线程池（CPU + IO） | asyncio 协程 |
| **依赖** | Boost.Asio, spdlog, fmt 等 | 纯标准库 |
| **协议解析** | 相同算法 | 相同算法（完整移植）|
| **用途** | 生产环境、数据中心 | 教学、调试、快速验证 |

---

## 错误处理策略

| 场景 | 行为 |
|------|------|
| 连接超时 | `error = "X probe timed out after Ns"`，返回结果而非抛出异常 |
| 连接被拒 | `error = "Connection refused"` |
| DNS 解析失败 | Python 标准 `OSError`，由 `probe_all` 统一捕获 |
| TCP 连接成功但无数据（Telnet 常见） | 视为成功（`accessible=True`），banner 为空字符串 |
| 数据截断 | `banner_truncated=True` 标记 |
