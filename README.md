# Banner Scanner MCP

面向已授权目标的六协议主动 Banner 探测与指纹识别服务。项目以 MCP 为主要入口，支持 SSH、FTP、Telnet、Redis、MySQL 和 PostgreSQL，并保留 CLI 作为本地调试入口。

## 安装

项目固定使用 MCP Python SDK `1.28.1`，并额外提供 `fastmcp==2.12.4` 入口，避免传输行为随依赖升级变化。

```bash
python3 -m pip install -e .
```

需要 Python 3.10 或更高版本。依赖声明位于 `pyproject.toml`。

## 启动 MCP

### stdio

```bash
banner-scanner-mcp
```

### Streamable HTTP

```bash
banner-scanner-mcp-http --host 127.0.0.1 --port 8877
```

默认 MCP 地址为 `http://127.0.0.1:8877/mcp`，可直接使用仓库中的 `mcp.json`。

### SSE 兼容入口

推荐在 Cherry Studio 等只配置 SSE URL 的客户端中使用 FastMCP 入口：

```bash
banner-scanner-fastmcp --transport sse --host 127.0.0.1 --port 8877
```

客户端 URL 填写：

```text
http://127.0.0.1:8877/sse
```

如果服务需要给同一局域网内的其他机器访问，监听地址可以改为 `0.0.0.0`。此时必须显式确认允许远程监听，并配置目标 allowlist，避免 MCP 客户端把服务用来探测未授权目标：

```bash
export BANNER_SCANNER_ALLOW_REMOTE_BIND=1
export BANNER_SCANNER_ALLOWLIST="203.0.113.0/24,198.51.100.10/32"
banner-scanner-fastmcp --transport sse --host 0.0.0.0 --port 8877
```

Cherry Studio 中填写运行服务这台机器的局域网地址，例如：

```text
http://192.168.1.23:8877/sse
```

项目也保留官方 MCP SDK 的 SSE 入口：

```bash
banner-scanner-mcp-http --transport sse --host 127.0.0.1 --port 8877
```

SSE 地址为 `/sse`，仅用于 legacy compatibility 和教学验收；新的客户端应优先使用 Streamable HTTP。stdio、Streamable HTTP、官方 SDK SSE 和 FastMCP SSE 共用同一套参数校验、探测、匹配和输出代码。

## MCP 工具

三个工具是并列关系：

| 工具 | 用途 | 主要限制 |
|---|---|---|
| `probe_banner` | 少量目标、多协议探测，默认返回证据详情 | 最多 20 个目标；默认并发 5，上限 20 |
| `scan_batch` | 较多目标、单协议筛查，默认返回摘要 | 最多 100 个目标；默认并发 20，上限 50 |
| `health_check` | 查看服务状态、六协议规则数、传输和运行上限 | 不建立外部连接 |

`probe_banner` 的 `protocols` 可省略。省略时依次探测六种协议，因此只传 IP 或域名即可；指定 `protocols` 可以减少无关连接。`scan_batch` 必须传一个 `protocol`。

### `probe_banner`

```json
{
  "hosts": ["192.0.2.10"],
  "protocols": ["ssh", "redis"],
  "retries": 2,
  "concurrency": 5,
  "detail_level": "evidence",
  "authorization_confirmed": true
}
```

### `scan_batch`

```json
{
  "hosts": ["192.0.2.10", "192.0.2.11"],
  "protocol": "mysql",
  "retries": 1,
  "concurrency": 20,
  "detail_level": "summary",
  "authorization_confirmed": true
}
```

`authorization_confirmed` 只记录调用者已确认授权范围，不是唯一安全机制。目标范围和运行上限仍由服务端强制执行。

## 结果解释

单个探测结果的主要结构如下：

```json
{
  "network_status": "connected",
  "protocol_status": "confirmed",
  "identification_status": "identified",
  "endpoint": {"host": "192.0.2.10", "port": 22, "protocol": "SSH"},
  "primary_identification": {
    "result_type": "software",
    "name": "OpenSSH",
    "version": "8.9p1",
    "evidence_strength": "conclusive",
    "explanation": "Matched software name evidence for OpenSSH."
  },
  "observations": {},
  "findings": {}
}
```

- `network_status` 表示连接结果，包括 `connected`、`timeout`、`refused`、`dns_error`、`cancelled` 和 `unreachable`。
- `protocol_status` 表示响应是否符合预期协议。端口返回其他明确协议时为 `mismatch`，并同时返回 `expected_protocol` 和 `observed_protocol`。
- `identification_status` 为 `identified`、`unidentified` 或 `conflict`。
- `primary_identification` 是便于调用方直接读取的具体软件结论。
- `findings` 并列保留软件家族、设备族、提供商、认证、能力、部署方式、服务状态和协议身份等其他事实，不会覆盖主要软件结论。
- `observations` 是协议解析得到的事实字段。`evidence` 模式还包含截断后的 Banner、原始字节预览和探测步骤；`summary` 模式只保留关键字段。

`evidence_strength` 的顺序为 `conclusive > strong > moderate > weak`。它是规则预设的证据强弱，用于同一结果类型内排序，不代表统计准确率或运行时概率。

父产品和具体软件不是冲突。例如 FileZilla Pro Enterprise 可以作为主要软件，同时在 `findings.software_family` 中保留 FileZilla。只有同一层级出现互斥软件证据，例如同时指向 OpenSSH 和 Dropbear，才返回：

```json
{
  "identification_status": "conflict",
  "primary_identification": null,
  "candidates": [
    {"result_type": "software", "name": "OpenSSH", "evidence_strength": "strong"},
    {"result_type": "software", "name": "Dropbear", "evidence_strength": "strong"}
  ]
}
```

MCP 输出不暴露规则编号、正则表达式、`matched_rules` 或全部内部候选。内部离线识别入口仅用于规则回归和冲突审查，不注册为 MCP 工具。

## 探测与识别流程

```text
MCP request
  -> authorization and target policy
  -> runtime limits and global concurrency budget
  -> protocol-specific active probe
  -> protocol parser
  -> protocol mismatch detection
  -> isolated fingerprint library
  -> primary identification + parallel findings
  -> shared MCP serializer
```

| 协议 | 主动交互 | 识别输入 | 不执行的操作 |
|---|---|---|---|
| SSH | 读取 SSH identification line | 版本行、解析的软件名、首包特征 | 不认证、不执行命令 |
| FTP | 读取欢迎语，必要时请求 `HELP/SYST/FEAT` | 欢迎语、功能列表、解析字段 | 不登录、不上传下载 |
| Telnet | 被动读取并处理 IAC 协商 | 文本、IAC、提示符和微特征 | 不提交口令 |
| Redis | `PING`，随后读取 `INFO server` | RESP 文本和 INFO 字段 | 不认证、不修改数据 |
| MySQL | 读取 protocol-v10 初始握手 | 版本、能力位、字符集、认证插件 | 不发送登录包、不执行 SQL |
| PostgreSQL | `SSLRequest`，必要时完成 TLS 并发送最小 StartupMessage | SSL 行为、认证消息、错误字段和参数 | 不发送密码、不执行 SQL |

## 指纹库

六种协议严格使用独立文件：

| 协议 | 文件 | 规则数 |
|---|---|---:|
| SSH | `fingerprints/protocols/ssh_fingerprints.json` | 76 |
| FTP | `fingerprints/protocols/ftp_fingerprints.json` | 61 |
| Telnet | `fingerprints/protocols/telnet_fingerprints.json` | 103 |
| Redis | `fingerprints/databases/redis_fingerprints.json` | 24 |
| MySQL | `fingerprints/databases/mysql_fingerprints.json` | 16 |
| PostgreSQL | `fingerprints/databases/pgsql_fingerprints.json` | 21 |

文本协议规则直接对协议限定的 Banner 和解析文本执行正则匹配。规则可以附带静态标签和正则分组提取：

```json
{
  "id": "ssh.software.bitvise-ssh-server",
  "name": "Bitvise SSH Server",
  "protocol": "SSH",
  "pattern": "^SSH\\-[12]\\.[0-9]+\\-(?:[0-9.]+\\s+)?(?:(?P<component>FlowSsh|sshlib):\\s*)?(?:Bitvise\\s+SSH\\s+Server|WinSSHD)\\b[^\\r\\n]*(?=\\r?\\n|\\r|$)",
  "result_type": "software",
  "match_level": "software_name",
  "evidence_strength": "strong",
  "primary_eligible": true,
  "labels": {"aliases": ["WinSSHD"], "provider": "Bitvise"},
  "extract": [{"field": "component", "group": "component"}]
}
```

Redis、MySQL 和 PostgreSQL 规则组合 Banner 与协议字段。`all`、`any` 和 `none` 可以递归嵌套；嵌套只表达布尔逻辑，不改变证据强度。

```json
{
  "id": "mysql.impl.mariadb",
  "name": "MariaDB",
  "description": "Identifies MariaDB by version marker.",
  "match": {"field_regex": {"mysql.version": "MariaDB"}},
  "extract": [{"field": "version", "source": "mysql.version"}],
  "labels": {"implementation": "MariaDB"},
  "result_type": "software",
  "match_level": "software_name",
  "evidence_strength": "conclusive",
  "primary_eligible": true
}
```

当多条规则同时命中时，程序先比较识别层级和证据强度，再比较规则具体程度、实际命中长度和规则编号。数据库规则不再使用容易被误解为概率的 `confidence` 字段。

从原始 SQLite 模板重建三个文本库：

```bash
python3 build_fingerprints.py \
  --db /path/to/fingerprint.db \
  --output-dir fingerprints/protocols
```

## 安全配置

默认只监听本机。可通过环境变量设置服务端策略：

| 变量 | 含义 |
|---|---|
| `BANNER_SCANNER_ALLOWLIST` | 允许的 IP/CIDR，逗号分隔 |
| `BANNER_SCANNER_DENYLIST` | 禁止的 IP/CIDR，逗号分隔 |
| `BANNER_SCANNER_ALLOWED_DOMAINS` | 允许的域名后缀 |
| `BANNER_SCANNER_PRIVATE_NETWORK_POLICY` | `allow`、`deny` 或 `allowlist_only` |
| `BANNER_SCANNER_AUTH_TOKEN` | HTTP Bearer token |
| `BANNER_SCANNER_CORS_ORIGINS` | 明确允许的浏览器 Origin，不支持通配符 |

非回环地址监听还必须设置 `BANNER_SCANNER_ALLOW_REMOTE_BIND=1`、Bearer token 和目标 allowlist。服务同时限制请求体、目标数、重试、单请求并发、全局并发、请求频率和总执行时间。

审计日志不默认记录完整 Banner，只记录截断预览和完整已捕获响应的 SHA-256 `banner_hash`。

## 验证

运行不依赖外网的单元测试：

```bash
python3 -m banner_scanner.tests.run_tests
```

使用六种协议的原始 Banner 做离线规则回归：

```bash
python3 -m banner_scanner.evaluation.validate_fingerprint_corpora \
  --fingerprint-db /path/to/fingerprint.db \
  --redis /path/to/scan_results.jsonl \
  --mysql /path/to/mysql_results.jsonl \
  --pgsql /path/to/pgsql_results.jsonl \
  --per-class 384 \
  --output validation.json
```

当前规则对 13,355 条分层历史样本的构建回归结果为 13,355/13,355，冲突和拒识均为 0。该结果只验证规则覆盖与冲突行为，不是公网主动探测性能。

主动性能测试和 MCP 流程测试必须重新连接目标：

```bash
python3 -m banner_scanner.evaluation.active_fingerprint_eval \
  --fingerprint-db /path/to/fingerprint.db \
  --redis-results /path/to/scan_results.jsonl \
  --mysql-results /path/to/mysql_results.jsonl \
  --pgsql-results /path/to/pgsql_results.jsonl \
  --output-dir evaluation/run \
  --confirm-authorized
```

性能统计保留所有类别，不会删除 0% 连接类别。连接率按全部样本计算；Precision 和 Recall 只在已连接样本上计算，因此不可连接目标不会进入 Recall 分母。流程测试通过官方 MCP Streamable HTTP 客户端调用 `scan_batch`，不绕过 MCP 服务。

## 代码结构

```text
banner_scanner/
├── core/                     探测编排、解析结果、协议识别和两类匹配器
├── probes/                   六种协议的主动探测实现
├── fingerprints/protocols/   SSH、FTP、Telnet 独立文本规则
├── fingerprints/databases/   Redis、MySQL、PostgreSQL 独立结构化规则
├── server/                   MCP 工具、策略、审计、序列化和传输入口
├── evaluation/               原始样本回归与主动性能/流程测试
├── tests/                    单元和回归测试
├── build_fingerprints.py     文本指纹库重建工具
├── migrate_fingerprints_v2.py 规则 v2 迁移工具
├── mcp.json                  Streamable HTTP 客户端配置示例
└── pyproject.toml            包信息、SDK 锁定和命令入口
```

## 能力边界

- 目标可连接不等于软件一定可识别；证据不足时返回 `unidentified`，不会用 Unknown 模板伪装成软件结论。
- Banner 可以伪造，结果表示协议响应中的可观察证据，不是主机真实性证明。
- 网络状态和公网资产会变化，历史 IP 只能用于抽样，正式指标必须来自本次主动连接。
- PostgreSQL 未认证路径通常不暴露版本，代理、连接池和云服务也可能重写错误消息。
- SSE 是兼容入口，不是新的首选传输。
