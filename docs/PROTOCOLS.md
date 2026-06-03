# 协议 Banner 格式与解析规范

> 本文档参考 [protocol_scanner](https://github.com/Open-Coder-oss/protocol_scanner) 的协议实现编写。

---

## 1. SSH

### Banner 格式

```
SSH-{proto_ver}-{software_id}[ {comments}]
```

- **proto_ver**: 协议版本号（如 `2.0`、`1.99`）
- **software_id**: 软件标识 + 版本（如 `OpenSSH_8.9p1`、`dropbear_2022.82`）
- **comments**（可选）: 注释信息（如 `Ubuntu-3`）

### 真实示例

| Banner | 软件 | 版本 |
|--------|------|------|
| `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3` | OpenSSH | 8.9p1 |
| `SSH-2.0-dropbear_2022.82` | dropbear | 2022.82 |
| `SSH-1.99-Cisco-1.25` | Cisco | 1.25 |
| `SSH-2.0-libssh_0.9.6` | libssh | 0.9.6 |

### 解析算法

1. 检查是否以 `SSH-` 开头（否则跳过）
2. 分割识别 `proto_ver`（第一段和第二段 dash 之间）
3. 从第三段中提取 `software_version`（空格之前）
4. 用 `_` 或 `-` 分割 `software_version` 为 `software` + `version`

> 算法来源: [protocol_scanner 的 parse_capabilities](https://github.com/Open-Coder-oss/protocol_scanner/blob/main/src/scanner/protocols/ssh_protocol.cpp)

---

## 2. FTP

### Banner 格式

```
{digit}{digit}{digit} {message}\r\n
```

状态码第三位为空格时表示首行（或最后一行），为 `-` 表示多行续行。

### FEAT 命令

FTP 的 `FEAT` 命令用于获取服务端支持的扩展特性列表：

```
C: FEAT\r\n
S: 211-Extensions supported:\r\n
S:  UTF8\r\n
S:  AUTH TLS\r\n
S:  SIZE\r\n
S:  MDTM\r\n
S:  MLSD\r\n
S:  TVFS\r\n
S: 211 End\r\n
```

解析后的特性字段和含义：

| 特性 | 含义 |
|------|------|
| `UTF8` | 支持 UTF-8 编码文件名 |
| `AUTH TLS` | 支持 TLS 加密认证 |
| `AUTH SSL` | 支持 SSL 加密认证 |
| `SIZE` | 支持文件大小查询 |
| `MDTM` | 支持修改时间查询 |
| `MLSD` / `MLST` | 支持机器可读目录列表 |
| `TVFS` | 支持可移植虚拟文件系统 |
| `XCRC` | 支持 CRC 校验 |
| `XCUP` | 支持切换到上级目录 |

### Banner 示例

```
220 vsftpd 3.0.5 ready.\r\n
220 ProFTPD 1.3.5 Server ready.\r\n
220 Microsoft FTP Service\r\n
```

> 算法来源: [protocol_scanner 的 FtpProtocol](https://github.com/Open-Coder-oss/protocol_scanner/blob/main/src/scanner/protocols/ftp_protocol.cpp)

---

## 3. Telnet

### 特点

Telnet 协议比较特殊——服务端连接后**可能发数据也可能不发**，且数据中夹杂大量 **IAC（Interpret As Command）** 控制字节（`0xFF`）。

### 处理策略

1. 建立 TCP 连接
2. 等待一小段时间接收服务端发送的数据
3. 过滤掉 IAC 控制字节（`0xFF` 及后续的命令对）
4. 取前 256 字节可读内容作为 Banner
5. 如果服务端什么都没发（很多设备默认行为），视为连接成功但无 Banner

### 常见 Banner

```
Ubuntu 22.04 LTS
linux login:

Cisco IOS Software, C1900 Software
User Access Verification
Password:

FreeBSD/arm (target) (ttyu0)

login:
```

> 算法来源: [protocol_scanner 的 TelnetProtocol](https://github.com/Open-Coder-oss/protocol_scanner/blob/main/src/scanner/protocols/telnet_protocol.cpp)
