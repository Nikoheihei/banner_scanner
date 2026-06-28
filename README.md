# Banner Scanner - Network Protocol Fingerprint Scanner

> Probe SSH, FTP, Telnet, Redis, MySQL, and PostgreSQL endpoints, extract structured protocol fields, and classify implementations with 209 protocol-scoped banner rules plus 59 database fingerprint rules.
> The project rewrites the core ideas from [protocol_scanner](https://github.com/Open-Coder-oss/protocol_scanner) in Python asyncio with zero third-party runtime dependencies.

---

## Quick Start

```bash
# Single-IP probing with fingerprint matching
python3 -m banner_scanner 192.168.1.1

# Probe database protocols only and return structured JSON
python3 -m banner_scanner 192.168.1.1 -p redis,mysql,pgsql --json

# High-concurrency random batch scan
python3 batch_scanner.py -c 300 --random --limit 10000 --protocol SSH --output result.txt

# Build a fingerprint database from SQLite
python3 build_fingerprints.py --db fingerprint.db --output-dir fingerprints/protocols
```

## Protocol Probing Flow

### SSH

```
TCP connection (port 22)
    |
    `-> async_read_some -> read the first line
            |
            +- Extract software: OpenSSH, Dropbear, Cisco, AWS_SFTP ...
            +- Extract version: 8.9p1, 7.6p1 ...
            +- Extract OS: Ubuntu, Debian, FreeBSD, Windows ...
            `- Fingerprint match -> vendor
```

| Metric | Value | Notes |
|--------|-------|-------|
| Banner acquisition rate | 99.1% | SSH servers usually send the version line immediately after TCP handshake |
| Fingerprint hit rate | **97.1%** | Text banners naturally include vendor/software identifiers |
| Timeout | connect=3s, read=4s | |

### FTP

```
TCP connection (port 21/990)
    |
    +- Stage 1: read welcome banner, such as "220 ProFTPD 1.3.5 Server"
    |       `-> Extract software and version
    |
    +- Stage 2: send HELP/SYST if the banner is empty
    |
    `- Stage 3: send FEAT\r\n and recursively read until the "211 " terminator
            `-> Parse UTF8, AUTH TLS, MLSD, SIZE, MDTM, and other features
```

| Metric | Value | Notes |
|--------|-------|-------|
| Banner acquisition rate | 99.4% | |
| Fingerprint hit rate | **94.9%** | Text banner plus recursive FEAT reads |
| Timeout | connect=3s, read=4s | Uses TCP_NODELAY, following the C++ reference behavior |
| Upper-bound reason | The remaining 5.1% are generic greetings such as `220 Welcome.` without vendor signals | |

### Telnet

Telnet is the hardest of the three protocols to fingerprint because many servers expose only a `login:` prompt instead of a software name. This project uses six probing and matching layers plus 205 rules to reach an 87.5% effective hit rate:

```
TCP connection (port 23)
    |
    +- Stage 1: passive receive
    +- Stage 2: IAC negotiation, replying WONT/DONT to trigger more data
    +- Stage 3: send \r\n to refresh bare login prompts
    +- Stage 4: second probe; if only login: appears, send admin\r\n to trigger password prompts
    `- Fingerprint matching: six rule layers
            +- Layer 1: IAC bytes in hex
            +- Layer 2: normalized IAC signatures
            +- Layer 3: text device names
            +- Layer 4: micro-features such as whitespace, line endings, and ANSI sequences
            +- Layer 5: fallback families such as "Embedded/Gateway"
            `- Layer 6: service status such as connection refused
```

| Metric | Value | Notes |
|--------|-------|-------|
| Banner acquisition rate | 91% | |
| Device identification | 84.6% | Specific vendor/model classes |
| Fallback family | 2.9% | Generic but useful device families |
| Service status | 9.4% | Classified separately and not treated as failed device identification |
| Effective hit rate | **87.5%** | Device plus fallback family |
| Total classification rate | **96.9%** | Every IP receives a clear output category |
| Timeout | connect=5s, read=8s | Telnet responses are usually slower |

### Redis / MySQL / PostgreSQL

| Protocol | Active probe | Structured fingerprint output | Safety boundary |
|----------|--------------|-------------------------------|-----------------|
| Redis | RESP `PING`, then `INFO server` | implementation, version, mode, OS and stable INFO fields | Does not authenticate or change data |
| MySQL | Read the protocol-v10 initial server handshake | implementation, version, capabilities, charset and auth plugin | Sends no login packet and executes no SQL |
| PostgreSQL | Send `SSLRequest`; on `N`, send a minimal protocol-v3 `StartupMessage` | SSL behavior, SQLSTATE/error fields, auth method, ParameterStatus and implementation hints | Sends no password and executes no SQL; stops after `S` instead of negotiating TLS |

The structured libraries under `fingerprints/databases/` are loaded automatically. Historical validation of those libraries used independent holdouts and authorized online reprobes:

| Library | Corpus / holdout | Main validation result |
|---------|------------------|------------------------|
| Redis | 7,338 records; random 10% online IP sample | 100% protocol match among responses; 96.64% implementation/version extraction |
| MySQL | 422,199 records; 42,220-record holdout | 100% protocol/version extraction on holdout; 100% on 482 online responses |
| PostgreSQL | 2,053 records; 205-record holdout | 100% protocol match; 88.78% SQLSTATE extraction on holdout |

PostgreSQL SQLSTATE is present only in `ErrorResponse`. SSL-only and authentication responses can be valid PGSQL fingerprints without containing SQLSTATE.

## Testing

```bash
python3 tests/test_parsers.py
python3 tests/test_matcher.py
python3 tests/test_database_matcher.py
python3 tests/test_probes.py
```

### Batch Scan Tests

```bash
# 100k random SSH targets
python3 batch_scanner.py -c 300 --random --limit 100000 --protocol SSH --timeout 3.0 --output ssh_output.txt

# 100k random FTP targets
python3 batch_scanner.py -c 300 --random --limit 100000 --protocol FTP --timeout 3.0 --output ftp_output.txt

# 50k random Telnet targets
python3 batch_scanner.py -c 200 --random --limit 50000 --protocol TELNET --timeout 5.0 --output telnet_output.txt
```

### Success-Rate Analysis

```bash
python3 -c "
import json
with open('telnet_final.txt') as f:
    rows = [json.loads(l) for l in f if l.strip()]
has_b = [r for r in rows if r['accessible']==1 and (r['banner'].strip() or r.get('banner_raw_hex',''))]
device = sum(1 for r in has_b if r.get('fingerprint_vendor','') and not r['fingerprint_vendor'].startswith('[Status]'))
total = sum(1 for r in has_b if r.get('fingerprint_vendor','') or r['fingerprint_vendor'].startswith('[Status]') or r.get('fingerprint_vendor',''))
print(f'Device identification: {device}/{len(has_b)} ({device/len(has_b)*100:.1f}%)')
print(f'Total classification: {total}/{len(has_b)} ({total/len(has_b)*100:.1f}%)')
"
```

## Fingerprint Library

Build a JSON fingerprint library from a SQLite database:

```bash
python3 build_fingerprints.py --db fingerprint.db --output-dir fingerprints/protocols
```

Each output file contains rules for exactly one protocol. Example format:

```json
{
  "protocol": "SSH",
  "rule_count": 55,
  "vendors": [
    {"id": 1, "name": "OpenSSH", "protocol": "SSH", "pattern": ".*OpenSSH.*", "count": 1923}
  ]
}
```

## Retry Strategy

All probes include exponential-backoff retries:

```
connection timeout / read timeout -> wait base_delay * 2^attempt -> retry
maximum retries: 2 by default
```

## TCP-Level Optimizations

- `TCP_NODELAY`: disables Nagle's algorithm to reduce small-packet latency.
- MSS/SNDBUF/RCVBUF metadata collection: used for cross-layer fingerprinting.

## CLI Options

```bash
python3 -m banner_scanner [hosts...] [options]

  hosts               Target IP addresses
  -p, --protocols     Protocol list (default: ssh,ftp,telnet,redis,mysql,pgsql)
  -t, --timeout       Connection timeout in seconds (default: 3.0)
  --read-timeout      Read timeout in seconds (default: 4.0)
  --retries           Maximum retries (default: 2)
  --json              Output JSON
  --no-feat           Do not send FTP FEAT
  --health            Print engine health
  --fingerprint       Fingerprint library path
  --database-fingerprints  Structured Redis/MySQL/PGSQL library directory
  --verbose, -v       DEBUG logging
```

## MCP Service

The scanner can be exposed as an MCP service so AI clients such as Cherry Studio or Claude Desktop can call the scanning tools directly.

### Start the Service

```bash
cd banner_scanner
PYTHONPATH="$(dirname $(pwd)):$PYTHONPATH" python3 -m server.mcp_http_server
```

The service listens on `http://127.0.0.1:8877` by default. Change it with `MCP_PORT`.

### Client Configuration

Import `mcp.json` into an MCP client:

```json
{
  "mcpServers": {
    "banner-scanner": {
      "type": "streamableHttp",
      "url": "http://127.0.0.1:8877"
    }
  }
}
```

### Available Tools

| Tool | Description |
|------|-------------|
| `health_check` | Engine health and fingerprint-library status |
| `probe_banner` | Probe SSH / FTP / Telnet / Redis / MySQL / PGSQL and match fingerprints |
| `scan_batch` | Scan multiple IP addresses |

### Supported Transports

| Transport | Endpoint | Description |
|-----------|----------|-------------|
| POST `/message` | JSON-RPC 2.0 | Tool calls |
| GET `/sse` | Server-Sent Events | Session setup |

Some models may respond with text instead of invoking MCP tools. That is a client/model tool-calling limitation, not a server-side issue. Function-calling-capable models are recommended.

## Project Structure

```
banner_scanner/
├── core/
│   ├── engine.py         Probe engine with retry and single-port probing
│   ├── models.py         Data structures
│   ├── parsers.py        Text and database wire-protocol parsers
│   ├── transport.py      TCP/TLS transport plus TCP metadata
│   ├── matcher.py        Fingerprint loading and longest-match engine
│   ├── database_matcher.py Structured database fingerprint matcher
│   └── retry.py          Exponential-backoff retry strategy
├── probes/
│   ├── ssh.py            SSH probing
│   ├── ftp.py            FTP probing
│   ├── telnet.py         Telnet probing
│   ├── redis.py          RESP PING + INFO server
│   ├── mysql.py          Initial handshake parsing
│   └── pgsql.py          SSLRequest + minimal StartupMessage
├── fingerprints/protocols/ 55 SSH + 52 FTP + 102 Telnet isolated rules
├── fingerprints/databases/ 59 validated structured rules
├── build_fingerprints.py Build fingerprints from SQLite
├── batch_scanner.py      High-concurrency batch scanner
├── vendors.json          Legacy combined migration source (not loaded by default)
└── tests/                Unit tests
```

## License

MIT

---

# 中文版

# Banner Scanner — 网络协议指纹探测与识别系统

> 从 IP 地址探测 SSH / FTP / Telnet / Redis / MySQL / PostgreSQL，提取协议结构化字段，并通过 209 条协议隔离 Banner 规则和 59 条数据库指纹规则识别实现与版本。
> 基于 [protocol_scanner](https://github.com/Open-Coder-oss/protocol_scanner)（C++）核心逻辑，Python asyncio 重写，零第三方依赖。

---

## 快速开始

```bash
# 单 IP 探测 + 指纹识别
python3 -m banner_scanner 192.168.1.1

# 仅探测数据库协议，输出结构化 JSON
python3 -m banner_scanner 192.168.1.1 -p redis,mysql,pgsql --json

# 批量随机扫描
python3 batch_scanner.py -c 300 --random --limit 10000 --protocol SSH --output result.txt

# 从 SQLite 数据库构建指纹库
python3 build_fingerprints.py --db fingerprint.db --output-dir fingerprints/protocols
```

## 协议探测流程

### SSH

```
TCP 连接 (port 22)
    │
    └─→ async_read_some → 取第一行
            │
            ├─ 提取软件名: OpenSSH, Dropbear, Cisco, AWS_SFTP …
            ├─ 提取版本号: 8.9p1, 7.6p1 …
            ├─ 提取 OS: Ubuntu, Debian, FreeBSD, Windows …
            └─ 指纹匹配 → 输出 vendor
```

| 指标 | 数值 | 说明 |
|------|------|------|
| Banner 获取率 | 99.1% | SSH 服务端在 TCP 握手后立即主动发送版本行 |
| 指纹命中率 | **97.1%** | 文本 Banner 天然携带厂商标识 |
| 超时配置 | connect=3s, read=4s | |

### FTP

```
TCP 连接 (port 21/990)
    │
    ├─→ 阶段①: 读取欢迎 Banner (首行), 如 "220 ProFTPD 1.3.5 Server"
    │       └─→ 提取软件名 + 版本号
    │
    ├─→ 阶段②: 若 Banner 为空, 主动发送 HELP/SYST 触发响应
    │
    └─→ 阶段③: 发送 FEAT\r\n → 递归逐行读取至 "211 " 结束标记
            └─→ 解析 UTF8, AUTH TLS, MLSD, SIZE, MDTM 等特性
```

| 指标 | 数值 | 说明 |
|------|------|------|
| Banner 获取率 | 99.4% | |
| 指纹命中率 | **94.9%** | 文本 Banner + FEAT 递归读取 |
| 超时配置 | connect=3s, read=4s | TCP_NODELAY 优化（参照 C++ 原版） |
| 命中上限原因 | 剩余 5.1% 是 `220 Welcome.` 等 **无厂商标识的通用欢迎语** | |

### Telnet

Telnet 是三个协议中**最难指纹识别**的——服务器不发软件名，Banner 常常只是 `login:`。
我们采用 **6 层探测 + 101 条 Telnet 专用规则** 实现多层指纹识别：

```
TCP 连接 (port 23)
    │
    ├─→ 阶段①: 被动接收 (等服务器主动发数据)
    ├─→ 阶段②: IAC 协商 (发送 WONT/DONT 响应, 触发更多信息)
    ├─→ 阶段③: 发送 \r\n (刺激裸 Login 设备重显 Prompt)
    ├─→ 阶段④: 二次探测 (若只有裸 login:, 输 admin\r\n 触发 Password 提示)
    │
    └─→ 指纹匹配: 6 层规则
            ├─ Layer 1: IAC 字节 hex (fffb01fffb03 → Cisco IOS)
            ├─ Layer 2: IAC 标准化签名 (WILL(1),WILL(3) → Linux netkit)
            ├─ Layer 3: 文本设备名 (Ubuntu, Synology, ASUS RT-AC, TANDBERG …)
            ├─ Layer 4: 微特征 (尾部空格/换行符模式/ANSI 序列)
            ├─ Layer 5: 兜底族 (login:/password: → "Embedded/Gateway")
            └─ Layer 6: 服务状态 (Connection refused → "[Status]")
```

| 指标 | 数值 | 说明 |
|------|------|------|
| Banner 获取率 | 91% | |
| 设备识别 | 84.6% | 具体厂商/型号 |
| 兜底族 | 2.9% | 极简设备输出通用类别 |
| 服务状态 | 9.4% | 独立分类（不算失败） |
| **有效命中率** | **87.5%** | 设备+兜底 |
| **总分类率** | **96.9%** | 每个 IP 都有明确输出 |
| 超时配置 | connect=5s, read=8s | Telnet 响应较慢 |
| 命中上限原因 | 剩余 3.1% 是真信息论不可区分的样本（单例孤立簇 + 无 IAC 无特征纯 login:） | |

### Redis / MySQL / PostgreSQL

| 协议 | 主动探测过程 | 结构化指纹输出 | 操作边界 |
|------|--------------|----------------|----------|
| Redis | RESP `PING`，随后执行 `INFO server` | 实现、版本、运行模式、OS、稳定 INFO 字段 | 不认证、不修改数据 |
| MySQL | 仅读取 protocol-v10 初始服务端握手 | 实现、版本、能力位、字符集、认证插件 | 不发送登录包、不执行 SQL |
| PostgreSQL | 先发 `SSLRequest`；收到 `N` 后发送最小 protocol-v3 `StartupMessage` | SSL 行为、SQLSTATE/错误字段、认证方式、ParameterStatus、实现线索 | 不发送密码、不执行 SQL；收到 `S` 后停止，不继续 TLS |

`fingerprints/databases/` 下的三套结构化指纹库由引擎自动加载。其历史独立留出集与授权公网重探结果如下：

| 指纹库 | 语料 / 测试集 | 主要验证结果 |
|--------|---------------|--------------|
| Redis | 7,338 条记录；每次随机 10% IP 在线复测 | 有响应目标协议匹配 100%；实现/版本提取 96.64% |
| MySQL | 422,199 条记录；42,220 条留出集 | 留出集协议/版本提取 100%；482 个在线响应均匹配 |
| PostgreSQL | 2,053 条记录；205 条留出集 | 协议匹配 100%；留出集 SQLSTATE 提取 88.78% |

PostgreSQL 的 SQLSTATE 只存在于 `ErrorResponse`。SSL 响应和认证响应可以形成有效 PGSQL 指纹，但协议本身不携带 SQLSTATE。

### 命中率演进

```
Telnet 指纹命中率演进:
  V1 原始 (仅文本):     5.2%
  V2 +IAC hex:         54%
  V3 +文本设备指纹:    64.3%
  V4 +匹配长度优先:    77.1%
  V5 +IAC签名+微特征:  83.8%
  V6 +TCP元数据:       82.5%
  V7 +纯文本补漏:      88%
  V8 +联合聚类:        89.3%
  V9 +服务状态分离:    90.7%
  Final +兜底族:       87.5% 有效命中 / 96.9% 总分类
```

### 三协议上限分析

| 协议 | 有效命中 | 上限 | 剩余无法识别的原因 |
|------|---------|------|--------------------|
| **SSH** | 97.1% | ~98% | `Exceeded MaxStartups`（后台限流，非真实 Banner） |
| **FTP** | 94.9% | ~95% | `220 Welcome.` 等完全无厂商标识的通用欢迎语 |
| **Telnet** | 87.5% | ~90% | 已分离 9.4% 服务状态（`Connection refused` 等），剩余 3.1% 是清洗后仍无法归并的单例文本簇 |

## 测试方式

```bash
python3 tests/test_parsers.py
python3 tests/test_matcher.py
python3 tests/test_database_matcher.py
python3 tests/test_probes.py
```

### 批量扫描测试

```bash
# SSH 10 万随机
python3 batch_scanner.py -c 300 --random --limit 100000 --protocol SSH --timeout 3.0 --output ssh_output.txt

# FTP 10 万随机
python3 batch_scanner.py -c 300 --random --limit 100000 --protocol FTP --timeout 3.0 --output ftp_output.txt

# Telnet 5 万随机
python3 batch_scanner.py -c 200 --random --limit 50000 --protocol TELNET --timeout 5.0 --output telnet_output.txt
```

### 成功率分析

```bash
python3 -c "
import json
with open('telnet_final.txt') as f:
    rows = [json.loads(l) for l in f if l.strip()]
has_b = [r for r in rows if r['accessible']==1 and (r['banner'].strip() or r.get('banner_raw_hex',''))]
device = sum(1 for r in has_b if r.get('fingerprint_vendor','') and not r['fingerprint_vendor'].startswith('[Status]'))
total = sum(1 for r in has_b if r.get('fingerprint_vendor','') or r['fingerprint_vendor'].startswith('[Status]') or r.get('fingerprint_vendor',''))
print(f'设备识别: {device}/{len(has_b)} ({device/len(has_b)*100:.1f}%)')
print(f'总分类:   {total}/{len(has_b)} ({total/len(has_b)*100:.1f}%)')
"
```

## 指纹库构建

从 SQLite 数据库（`fingerprint.db`）提取模板，自动识别厂商名，分别生成 SSH、FTP、Telnet JSON 指纹库：

```bash
python3 build_fingerprints.py --db fingerprint.db --output-dir fingerprints/protocols
```

指纹库格式示例：

```json
{
  "vendors": [
    {"id": 1, "name": "OpenSSH", "pattern": ".*OpenSSH.*", "count": 1923},
    {"id": 100, "name": "Cisco IOS telnetd", "pattern": ".*ff[fb-fe]01.*ff[fb-fe]03.*ff[fb-fe]18.*ff[fb-fe]1f.*"},
    {"id": 200, "name": "Embedded/Gateway (login)", "pattern": "(?<![A-Za-z])[Ll]ogin:"}
  ]
}
```

## 重试策略

所有探测内置指数退避重试：

```
连接超时 / 读取超时 → 等待 base_delay × 2^attempt → 重试
最大重试次数: 2 (默认)
```

## TCP 层优化

- `TCP_NODELAY`：关闭 Nagle 算法，减少小包延迟（参照 C++ 原版）
- MSS/SNDBUF/RCVBUF 元数据采集（用于跨层指纹）

## CLI 参数

```bash
python3 -m banner_scanner [hosts...] [options]

  hosts               目标 IP 地址（可多个）
  -p, --protocols     协议列表 (默认: ssh,ftp,telnet,redis,mysql,pgsql)
  -t, --timeout       连接超时秒数 (默认: 3.0)
  --read-timeout      读取超时秒数 (默认: 4.0)
  --retries           最大重试次数 (默认: 2)
  --json              JSON 格式输出
  --no-feat           FTP 不发送 FEAT
  --health            引擎健康状态
  --fingerprint       指纹库文件路径
  --database-fingerprints  Redis/MySQL/PGSQL 结构化指纹库目录
  --verbose, -v       DEBUG 日志
```

## MCP 服务

支持通过 MCP（Model Context Protocol）在 AI 客户端中直接调用扫描能力，例如 Cherry Studio、Claude Desktop 等。

### 启动服务

```bash
cd banner_scanner
PYTHONPATH="$(dirname $(pwd)):$PYTHONPATH" python3 -m server.mcp_http_server
```

服务默认监听 `http://127.0.0.1:8877`，可通过环境变量 `MCP_PORT` 修改端口。

### 客户端配置

将 `mcp.json` 导入 MCP 客户端：

```json
{
  "mcpServers": {
    "banner-scanner": {
      "type": "streamableHttp",
      "url": "http://127.0.0.1:8877"
    }
  }
}
```

### 可用工具

| 工具 | 说明 |
|------|------|
| `health_check` | 引擎健康状态和指纹库信息 |
| `probe_banner` | 探测 SSH / FTP / Telnet / Redis / MySQL / PGSQL，自动指纹识别 |
| `scan_batch` | 批量扫描多个 IP |

### 协议支持

| 传输方式 | 端点 | 说明 |
|----------|------|------|
| POST `/message` | JSON-RPC 2.0 | 工具调用 |
| GET `/sse` | Server-Sent Events | 会话建立 |

> **注意**：部分模型（如 Qwen）可能不主动调用 MCP 工具，表现为只给出文字回复而非实际调用接口。这是模型能力差异，非服务端问题。推荐使用支持 function calling 的模型。

## 项目结构

```
banner_scanner/
├── core/
│   ├── engine.py         探测引擎（+ 重试 + 单端口探测）
│   ├── models.py         文本协议与数据库协议结构化结果
│   ├── parsers.py        Banner 与数据库线协议解析器
│   ├── transport.py      传输层（TCP/TLS + TCP_NODELAY + TCP 元数据）
│   ├── matcher.py        指纹加载 + 匹配长度优先引擎
│   ├── database_matcher.py 数据库结构化规则匹配器
│   └── retry.py          指数退避重试策略
├── probes/
│   ├── ssh.py            SSH 探测（取首行 → 解析软件/OS）
│   ├── ftp.py            FTP 探测（读 Banner → HELP/SYST → FEAT 递归）
│   ├── telnet.py         Telnet 探测（被动接收 → IAC 协商 → \r\n → 二次探测 → 微特征）
│   ├── redis.py          RESP PING + INFO server
│   ├── mysql.py          初始握手读取与解析
│   └── pgsql.py          SSLRequest + 最小 StartupMessage
├── fingerprints/protocols/ SSH 55条、FTP 52条、Telnet 102条独立规则
├── fingerprints/databases/ 59 条已验证结构化规则
├── build_fingerprints.py 从 SQLite 构建指纹库
├── batch_scanner.py      高并发批量扫描器（分块 + 断点续传）

├── vendors.json          旧版合并迁移源（默认不加载）
└── tests/                单元测试
```

## License

MIT
