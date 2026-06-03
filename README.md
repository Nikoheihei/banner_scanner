# Banner Scanner

> 网络协议 Banner 探测工具 — 从 IP 地址获取 SSH、FTP、Telnet 等协议的 Banner 信息，  
> 支持加载指纹库自动识别服务商，支持 MCP 服务与 CLI 两种使用方式。  
> 从 [protocol_scanner](https://github.com/Open-Coder-oss/protocol_scanner)（C++）提取核心逻辑，Python asyncio 重写，零第三方依赖。

---

## 快速开始

```bash
# 探测 + 指纹识别
python3 -m banner_scanner 192.168.1.1 --fingerprint vendors.json

# 仅探测
python3 -m banner_scanner 192.168.1.1

# JSON 输出
python3 -m banner_scanner 192.168.1.1 --json

# 引擎状态
python3 -m banner_scanner --health

# MCP 服务
pip install mcp
python3 -m banner_scanner.server.mcp_server
```

## 工作流程

```
用户输入 IP
    │
    ├─ CLI:  python3 -m banner_scanner 192.168.1.1
    ├─ MCP:  probe_banner({"hosts": ["192.168.1.1"]})
    └─ API:  await engine.probe_host("192.168.1.1")
                │
                ├─ SSH(22)  ──→ TCP 连接 → 读版本行 → 解析软件名/版本号
                ├─ FTP(21)  ──→ TCP 连接 → 读 Banner → 发 FEAT → 解析扩展特性
                └─ Telnet(23) → TCP 连接 → 读数据 → 过滤 IAC 控制字符
                    │
                    └─────── 合并结果 ──── 指纹匹配 ──── 输出
```

## 功能

### 协议探测
- **SSH** — 读取 `SSH-2.0-OpenSSH_8.9p1` 版本行，解析软件名、版本号、协议版本
- **FTP** — 读取欢迎 Banner，自动发送 `FEAT` 解析 UTF8、AUTH TLS、SIZE、MDTM 等特性
- **Telnet** — 读取登录提示文本，过滤 IAC 控制字节

### 指纹识别
- 加载 JSON 指纹库（本项目自带 `vendors.json`，26 条规则）
- 正则匹配 Banner 原文 + 结构化字段（如 `ssh.software`）
- 结果写入 `vendor` / `matched_rules`，多规则命中自动去重

### TLS 支持
- FTPS 端口 990 自动升级 TLS 连接

### MCP 服务
- `probe_banner` — 探测 Banner + 指纹匹配
- `health_check` — 引擎运行状态

## CLI 参数

```bash
python3 -m banner_scanner [hosts...] [options]

  hosts               目标 IP 地址（可多个）
  -p, --protocols     协议列表 (默认: ssh,ftp,telnet)
  -t, --timeout       连接超时秒数 (默认: 3.0)
  --read-timeout      读取超时秒数 (默认: 4.0)
  --json              JSON 格式输出
  --no-feat           FTP 不发送 FEAT
  --health            引擎健康状态
  --fingerprint       指纹库文件路径
  --verbose, -v       DEBUG 日志
```

## 项目结构

```
banner_scanner/
├── __init__.py / __main__.py  包入口
├── cli.py                     命令行界面
├── vendors.json               指纹库（26 条规则）
├── core/
│   ├── engine.py              探测引擎
│   ├── models.py              数据结构
│   ├── parsers.py             Banner 解析器
│   ├── transport.py           传输层（TCP/TLS）
│   ├── matcher.py             指纹加载与匹配
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

## 测试

```bash
cd banner_scanner
python3 tests/test_parsers.py    # 12 解析器
python3 tests/test_probes.py     # 5  集成
python3 tests/test_matcher.py    # 18 指纹匹配
```
