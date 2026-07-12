# Banner Scanner MCP

面向已授权目标的六协议主动 Banner 探测与指纹识别 MCP 服务。支持 SSH、FTP、Telnet、Redis、MySQL 和 PostgreSQL。

## 代码结构

```text
banner_scanner/
├── core/                     探测编排、结果模型、解析与指纹匹配
├── probes/                   六种协议的主动探测实现
├── fingerprints/             六种协议的指纹规则库
├── server/                   MCP 工具、目标策略、日志和传输入口
├── evaluation/               评测与样本处理脚本
├── tests/                    单元与回归测试
├── examples/                 MCP 客户端配置示例
├── tools/                    维护、迁移和诊断工具
├── cli.py                    本地命令行入口
└── pyproject.toml            依赖和命令入口
```

## 安装

需要 Python 3.10 或更高版本。在项目根目录执行：

```bash
python3 -m pip install -e .
```

## 启动前配置

默认情况下服务只监听本机，目标策略允许直接提交 IP 或域名。可按部署需要设置以下环境变量：

| 变量 | 作用 |
|---|---|
| `BANNER_SCANNER_ALLOWLIST` | 允许访问的 IP 或 CIDR，多个值用逗号分隔 |
| `BANNER_SCANNER_DENYLIST` | 禁止访问的 IP 或 CIDR，优先于 allowlist |
| `BANNER_SCANNER_ALLOWED_DOMAINS` | 可选的域名后缀限制；不设置时不限制域名后缀，仍检查解析出的 IP |
| `BANNER_SCANNER_PRIVATE_NETWORK_POLICY` | 私网策略：`allow`、`deny` 或 `allowlist_only` |
| `BANNER_SCANNER_LOG_FILE` | 日志文件路径，默认 `logs/mcp_server.log` |
| `BANNER_SCANNER_LOG_PARAMS` | 默认记录完整目标和调用参数；设为 `0` 时隐藏目标地址 |
| `BANNER_SCANNER_ALLOW_REMOTE_BIND` | 监听非本机地址时必须设为 `1` |

仅供本机 Cherry Studio 使用时，通常只需配置日志：

```bash
export BANNER_SCANNER_LOG_FILE="<project-root>/logs/cherry_stdio.log"
```

若服务需要扫描任意公网 IPv4/IPv6，但不允许访问私网：

```bash
export BANNER_SCANNER_ALLOWLIST="0.0.0.0/0,::/0"
export BANNER_SCANNER_PRIVATE_NETWORK_POLICY="deny"
```

对外提供 HTTP/SSE 服务时，还应设置明确的 allowlist、`BANNER_SCANNER_ALLOW_REMOTE_BIND=1`，并按部署环境配置 Bearer token 与网络访问控制。

## 启动和客户端配置

### Cherry Studio：stdio

这是本机使用时推荐的方式。stdio 不监听 IP 或端口；Cherry Studio 每次启用或调用时会启动一个新的 MCP 子进程。

在 Cherry Studio 的“设置 → MCP 服务器 → 添加服务器”中填写：

| 字段 | 值 |
|---|---|
| 名称 | `banner-scanner-stdio` |
| 类型 | `STDIO` |
| 命令 | `<project-root>/.venv/bin/banner-scanner-mcp` |
| 参数 | 留空 |

将 `<project-root>` 替换为项目所在目录。`banner-scanner-mcp` 是由 stdio 客户端启动的命令；不需要另开一个监听端口的后台服务。

### Streamable HTTP

```bash
banner-scanner-mcp-http --host 127.0.0.1 --port 8877
```

客户端地址：

```text
http://127.0.0.1:8877/mcp
```

### SSE

SSE 用于兼容仍要求该传输方式的客户端：

```bash
banner-scanner-fastmcp --transport sse --host 127.0.0.1 --port 8877
```

客户端地址：

```text
http://127.0.0.1:8877/sse
```

同一局域网的其他机器访问时，监听地址改为 `0.0.0.0`，但客户端 URL 必须填写运行服务机器的实际局域网 IP，不能填写 `0.0.0.0`。

## MCP 工具

| 工具 | 用途 | 限制 |
|---|---|---|
| `probe_banner` | 少量目标、多协议探测，默认返回证据详情 | 最多 20 个目标；默认并发 5，上限 20 |
| `scan_batch` | 较多目标、单协议筛查，默认返回摘要 | 最多 100 个目标；默认并发 20，上限 50 |
| `health_check` | 查看服务状态、规则数量、目标策略和运行上限 | 不建立外部连接 |

`probe_banner` 不传 `protocols` 时会依次探测六种协议。`scan_batch` 必须指定一个 `protocol`。

### `probe_banner`

```json
{
  "hosts": ["example.com"],
  "protocols": ["ssh", "ftp"],
  "retries": 1,
  "concurrency": 5,
  "detail_level": "evidence"
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
  "result_mode": "full"
}
```

工具调用表达客户端希望发起探测；是否真正连接由服务端的 allowlist、denylist、私网策略、并发和频率限制决定。

## 结果解释

单个结果的主要结构如下：

```json
{
  "network_status": "connected",
  "protocol_status": "confirmed",
  "identification_status": "identified",
  "endpoint": {
    "host": "example.com",
    "resolved_ip": "192.0.2.10",
    "port": 22,
    "protocol": "SSH"
  },
  "target_resolution": {
    "input_host": "example.com",
    "resolved_ips": ["192.0.2.10", "192.0.2.11"],
    "attempted_ips": [{"ip": "192.0.2.10", "port": 22, "status": "connected"}],
    "selected_ip": "192.0.2.10"
  },
  "primary_identification": {
    "result_type": "software",
    "name": "OpenSSH",
    "version": "8.9p1",
    "evidence_strength": "conclusive"
  },
  "observations": {},
  "findings": {}
}
```

- `network_status`：`connected`、`timeout`、`refused`、`dns_error`、`cancelled` 或 `unreachable`。
- `protocol_status`：响应是否符合预期协议；`mismatch` 表示端口返回了另一种明确协议。
- `identification_status`：`identified`、`unidentified` 或 `conflict`。
- `endpoint.host`：调用时输入的 IP 或域名；`endpoint.resolved_ip`：实际连接的 IP。
- `target_resolution`：域名的全部解析 IP、按顺序尝试过的 IP 以及最终连接的 IP。一个 IP 失败后才会尝试下一个，不会同时扫描全部解析地址。
- `primary_identification`：最便于调用方读取的软件结论。
- `findings`：提供商、设备族、认证、能力、部署方式、服务状态和协议身份等并列事实。
- `observations`：协议解析所得字段；`evidence` 模式包含截断 Banner 和探测步骤，`summary` 模式只保留关键字段。

`evidence_strength` 按 `conclusive > strong > moderate > weak` 排序，只表示规则证据的明确程度，不表示统计正确率。

## 探测与识别方式

| 协议 | 主动交互 | 不执行的操作 |
|---|---|---|
| SSH | 读取版本行，必要时发送标准识别行 | 不认证、不执行命令 |
| FTP | 读取欢迎语，必要时请求 `HELP`、`SYST`、`FEAT` | 不登录、不上传下载 |
| Telnet | 被动读取并处理 IAC 协商 | 不提交口令 |
| Redis | `PING` 后读取 `INFO server` | 不认证、不修改数据 |
| MySQL | 读取初始握手 | 不发送登录包、不执行 SQL |
| PostgreSQL | `SSLRequest` 后发送最小 StartupMessage | 不发送密码、不执行 SQL |

## 指纹库

每种协议都使用与其报文格式对应的规则：SSH、FTP、Telnet 从 Banner 文本和解析字段中识别软件、设备或服务事实；Redis、MySQL、PostgreSQL 从握手、错误响应、版本、认证和能力字段中组合判断实现信息。

规则可输出软件、软件家族、设备族、提供商、认证、能力、部署方式、服务状态和协议身份等事实。具体软件结论作为 `primary_identification` 返回，其余可识别事实保留在 `findings`，不会互相覆盖。

## 日志

服务默认写入 `logs/mcp_server.log`，同时输出到终端。日志记录调用参数、目标解析 IP、实际尝试的 IP:端口、结果摘要、错误原因和 `request_id`；默认不保存完整 Banner，只保存截断预览和响应摘要哈希。

## 能力边界

- 目标可连接不等于一定能识别软件；证据不足时返回 `unidentified`。
- Banner 可以伪造，识别结果表示可观察到的协议证据，不是主机真实性证明。
- 公网资产和服务状态会变化，历史 IP 不能代替本次主动连接结果。
- PostgreSQL 未认证路径通常不公开版本；代理、连接池和云服务也可能重写响应。
