# Banner Scanner

> 网络协议 Banner 探测工具 — 从 IP 地址获取 SSH、FTP、Telnet 等协议的 Banner 信息，  
> 支持加载指纹库自动识别服务商，支持 MCP 服务与 CLI 两种使用方式。  
> 从 [protocol_scanner](https://github.com/Open-Coder-oss/protocol_scanner)（C++）提取核心逻辑，Python asyncio 重写，零第三方依赖。

---

## 快速开始

```bash
# 探测 + 指纹识别
python -m banner_scanner 192.168.1.1 --fingerprint config/vendors.json

# 仅探测
python -m banner_scanner 192.168.1.1

# JSON 输出
python -m banner_scanner 192.168.1.1 --json

# 引擎状态
python -m banner_scanner --health

# MCP 服务
pip install mcp
python -m banner_scanner.server.mcp_server
```

## 功能清单

- **协议探测**：SSH（22）、FTP（21/990）、Telnet（23）
- **Banner 解析**：SSH 版本行结构化提取（软件名、版本号、协议版本）
- **FTP FEAT**：自动发送 FEAT 命令，解析 9 种扩展特性（UTF8、AUTH TLS 等）
- **指纹匹配**：加载外部 JSON 指纹库，正则匹配，结果写入 vendor / matched_rules
- **TLS 支持**：FTPS 端口 990 自动升级 TLS
- **并发控制**：TaskGroup 协议级并发 + 信号量主机级限流
- **熔断保护**：连续失败自动跳过，防止资源浪费
- **健康检查**：引擎运行状态实时查询
- **MCP 服务**：fastmcp 封装，支持 AI 客户端调用（`probe_banner`、`health_check`）
- **结构化日志**：支持 JSON 格式输出，可接入 ELK/Loki

## CLI 参数

```bash
python -m banner_scanner [hosts...] [options]

  hosts                 目标 IP 地址（可多个）
  -p, --protocols       协议列表 (默认: ssh,ftp,telnet)
  -t, --timeout         连接超时秒数 (默认: 3.0)
  --read-timeout        读取超时秒数 (默认: 4.0)
  --max-banner          Banner 最大字节数 (默认: 65536)
  --concurrent          最大并发主机数 (默认: 50)
  --json                JSON 格式输出
  --json-log            JSON 格式日志
  --no-feat             FTP 不发送 FEAT
  --health              引擎健康状态
  --fingerprint         指纹库文件路径
  --verbose, -v         DEBUG 日志
```

## 指纹识别

指纹库为 JSON 格式，与 C++ 项目 `config/vendors.json` 兼容。通过 `--fingerprint` 加载后，探测结果自动匹配：

```
==================================================
  SSH (192.168.1.1:22)
==================================================
  ✅ 可访问
  📋 Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
  🏷️  指纹匹配: OpenSSH
```

## MCP 服务

```bash
pip install mcp
python -m banner_scanner.server.mcp_server
```

暴露两个 Tool：

- `probe_banner` — 探测 Banner + 指纹匹配
- `health_check` — 引擎健康状态

## 项目结构

```
banner_scanner/
├── __init__.py / __main__.py  包入口
├── cli.py                     命令行界面
├── core/
│   ├── engine.py              探测引擎
│   ├── models.py              数据结构
│   ├── parsers.py             Banner 解析器
│   ├── transport.py           传输层
│   ├── matcher.py             指纹加载与匹配
│   ├── breaker.py             熔断器
│   └── log.py                 日志
├── probes/
│   ├── ssh.py                 SSH 探测
│   ├── ftp.py                 FTP 探测（含 FEAT）
│   └── telnet.py              Telnet 探测
├── server/
│   └── mcp_server.py          MCP 服务
├── tests/                     35 个测试
└── docs/                      架构 + 协议规范文档
```

## 与 C++ 版对照

| C++ protocol_scanner | Python banner_scanner |
|----------------------|----------------------|
| `SshProtocol::async_probe` | `probes/ssh.py` |
| `FtpProtocol::async_probe` | `probes/ftp.py` |
| `TelnetProtocol::async_probe` | `probes/telnet.py` |
| `parse_ssh_version` | `core/parsers.py::parse_ssh_banner` |
| `parse_ftp_feat` | `core/parsers.py::parse_ftp_features` |
| `VendorDetector` | `core/matcher.py::FingerprintMatcher` |
| `vendors.json` | 直接兼容 |

## 测试

```bash
python -m banner_scanner.tests.test_parsers   # 解析器
python -m banner_scanner.tests.test_probes    # 集成
python -m banner_scanner.tests.test_matcher   # 指纹匹配
```
