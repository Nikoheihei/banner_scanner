# Banner Scanner — 网络协议指纹探测与识别系统

> 从 IP 地址探测 SSH / FTP / Telnet Banner，提取服务商、版本号、操作系统，并通过 205 条指纹规则自动识别设备类型。  
> 基于 [protocol_scanner](https://github.com/Open-Coder-oss/protocol_scanner)（C++）核心逻辑，Python asyncio 重写，零第三方依赖。

---

## 快速开始

```bash
# 单 IP 探测 + 指纹识别
python3 -m banner_scanner 192.168.1.1 --fingerprint vendors.json

# 批量随机扫描
python3 batch_scanner.py -c 300 --random --limit 10000 --protocol SSH --output result.txt

# 从 SQLite 数据库构建指纹库
python3 build_fingerprints.py --db fingerprint.db --output vendors.json
```

## 三协议探测流程

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
我们采用 **6 层探测 + 205 条规则** 实现 87.5% 有效命中：

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

从 SQLite 数据库（`fingerprint.db`）提取模板，自动识别厂商名，生成 JSON 指纹库：

```bash
python3 build_fingerprints.py --db fingerprint.db --output vendors.json
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
  -p, --protocols     协议列表 (默认: ssh,ftp,telnet)
  -t, --timeout       连接超时秒数 (默认: 3.0)
  --read-timeout      读取超时秒数 (默认: 4.0)
  --retries           最大重试次数 (默认: 2)
  --json              JSON 格式输出
  --no-feat           FTP 不发送 FEAT
  --health            引擎健康状态
  --fingerprint       指纹库文件路径
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
| `probe_banner` | 探测 IP 的 SSH / FTP / Telnet Banner，自动指纹识别 |
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
│   ├── models.py         数据结构（BannerResult, SshBanner, FtpFeatures, TelnetBanner）
│   ├── parsers.py        Banner 解析器（SSH/OS 指纹、FTP 软件/特性、Telnet 文本）
│   ├── transport.py      传输层（TCP/TLS + TCP_NODELAY + TCP 元数据）
│   ├── matcher.py        指纹加载 + 匹配长度优先引擎
│   └── retry.py          指数退避重试策略
├── probes/
│   ├── ssh.py            SSH 探测（取首行 → 解析软件/OS）
│   ├── ftp.py            FTP 探测（读 Banner → HELP/SYST → FEAT 递归）
│   └── telnet.py         Telnet 探测（被动接收 → IAC 协商 → \r\n → 二次探测 → 微特征）
├── build_fingerprints.py 从 SQLite 构建指纹库
├── batch_scanner.py      高并发批量扫描器（分块 + 断点续传）

├── vendors.json          205 条指纹规则
└── tests/                单元测试
```

## License

MIT
