"""MCP HTTP 服务 — 标准 streamableHttp 传输（SSE + JSON-RPC）"""
import asyncio
import json
import os
import sys
import uuid
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

_project_root = str(Path(__file__).parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from banner_scanner.core.engine import ProbeEngine
from banner_scanner.core.models import ProbeConfig, BannerResult
from banner_scanner.core.log import setup_logging
from banner_scanner.core.matcher import DEFAULT_PROTOCOL_LIBRARY_DIR, FingerprintMatcher

_DEFAULT_FINGERPRINT = str(DEFAULT_PROTOCOL_LIBRARY_DIR)

setup_logging(level="INFO")
config = ProbeConfig()
matcher = None
if os.path.exists(_DEFAULT_FINGERPRINT):
    matcher = FingerprintMatcher.load(_DEFAULT_FINGERPRINT)
engine = ProbeEngine(config)
if matcher:
    engine._matcher = matcher
    engine.config.fingerprint_path = _DEFAULT_FINGERPRINT

SYSTEM_INFO = {
    "protocolVersion": "2024-11-05",
    "serverInfo": {"name": "banner-scanner", "version": "0.5.0"},
    "capabilities": {"tools": {}},
    "instructions": "Banner Scanner MCP — 探测 SSH/FTP/Telnet/Redis/MySQL/PGSQL 并指纹识别",
}


def _banner_to_dict(br: BannerResult) -> dict:
    d = {
        "protocol": br.protocol, "host": br.host, "port": br.port,
        "accessible": br.accessible, "banner": br.banner,
        "response_time_ms": round(br.response_time_ms, 1), "error": br.error,
    }
    if br.ssh:
        d["ssh"] = {"software": br.ssh.software, "version": br.ssh.version,
                    "protocol_version": br.ssh.protocol_version,
                    "os": br.ssh.os_type, "os_version": br.ssh.os_version}
    if br.ftp:
        d["ftp"] = {"software": br.ftp.software, "version": br.ftp.version,
                    "features": br.ftp.features, "utf8": br.ftp.utf8,
                    "auth_tls": br.ftp.auth_tls, "mldst": br.ftp.mldst}
    if br.telnet:
        d["telnet"] = {"detected_service": br.telnet.detected_service,
                       "has_login_prompt": br.telnet.has_login_prompt,
                       "has_iac": br.telnet.has_iac_negotiation}
    if br.redis:
        d["redis"] = {"implementation": br.redis.implementation,
                      "version": br.redis.version, "mode": br.redis.mode,
                      "os": br.redis.os, "fields": br.redis.fields}
    if br.mysql:
        d["mysql"] = {"protocol_version": br.mysql.protocol_version,
                      "version": br.mysql.version,
                      "implementation": br.mysql.implementation,
                      "capability_flags": br.mysql.capability_flags,
                      "auth_plugin": br.mysql.auth_plugin}
    if br.pgsql:
        d["pgsql"] = {"protocol_version": br.pgsql.protocol_version,
                      "ssl_response": br.pgsql.ssl_response,
                      "implementation": br.pgsql.implementation,
                      "auth_method": br.pgsql.auth_method,
                      "fields": br.pgsql.fields,
                      "parameters": br.pgsql.parameters,
                      "message_types": br.pgsql.message_types}
    if br.vendor:
        d["fingerprint"] = br.vendor
        d["fingerprint_id"] = br.vendor_id
        d["confidence"] = br.vendor_confidence
    if br.info:
        d["info"] = br.info
    if br.fingerprint_details:
        d["fingerprint_details"] = br.fingerprint_details
    if br.retry_count:
        d["retries"] = br.retry_count
    return d


def handle_method(method: str, params: dict):
    if method == "initialize":
        return SYSTEM_INFO
    elif method == "tools/list":
        return {"tools": [
            {"name": "probe_banner",
             "description": "探测 IP 的 SSH/FTP/Telnet/Redis/MySQL/PGSQL，返回结构化字段和指纹。",
             "inputSchema": {"type": "object", "properties": {
                 "hosts": {"type": "array", "items": {"type": "string"},
                           "description": "目标 IP 或域名列表"},
                 "protocols": {"type": "array",
                               "items": {"type": "string", "enum": [
                                   "ssh", "ftp", "telnet", "redis", "mysql", "pgsql"]},
                               "description": "协议列表，默认全部"},
                 "retries": {"type": "integer", "description": "最大重试次数，默认 2"},
                 "concurrency": {"type": "integer", "minimum": 1, "maximum": 100,
                                 "description": "并发目标数，默认 1"}},
                 "required": ["hosts"]}},
            {"name": "scan_batch",
             "description": "批量扫描多个 IP",
             "inputSchema": {"type": "object", "properties": {
                 "hosts": {"type": "array", "items": {"type": "string"},
                           "description": "目标 IP 列表"},
                 "protocol": {"type": "string", "enum": [
                     "ssh", "ftp", "telnet", "redis", "mysql", "pgsql"],
                              "description": "协议，默认 SSH"},
                 "concurrency": {"type": "integer", "minimum": 1, "maximum": 100,
                                 "description": "并发数，默认 100"}},
                 "required": ["hosts"]}},
            {"name": "health_check",
             "description": "引擎健康状态和指纹库信息",
             "inputSchema": {"type": "object", "properties": {}}},
        ]}
    elif method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        if tool_name == "probe_banner":
            hosts = arguments.get("hosts", [])
            protocols = arguments.get("protocols")
            retries = arguments.get("retries", 2)
            concurrency = arguments.get("concurrency", 1)
            config.max_retries = retries
            results = asyncio.run(engine.probe_hosts(
                hosts, protocols=protocols, concurrency=concurrency,
            ))
            output = []
            for hr in results:
                for proto, br in hr.results.items():
                    output.append(_banner_to_dict(br))
            text = json.dumps({
                "total_hosts": len(hosts), "total_probes": len(output),
                "accessible": sum(1 for o in output if o["accessible"]),
                "fingerprint_matched": sum(1 for o in output if o.get("fingerprint")),
                "results": output,
            }, indent=2, ensure_ascii=False)
            return {"content": [{"type": "text", "text": text}]}
        elif tool_name == "scan_batch":
            hosts = arguments.get("hosts", [])
            protocol = arguments.get("protocol", "ssh")
            concurrency = arguments.get("concurrency", 100)
            results = asyncio.run(engine.probe_hosts(
                hosts, protocols=[protocol], concurrency=concurrency,
            ))
            output = []
            for hr in results:
                br = hr.results.get(protocol)
                if br:
                    output.append(_banner_to_dict(br))
            text = json.dumps({
                "protocol": protocol.upper(), "total": len(hosts),
                "accessible": sum(1 for o in output if o["accessible"]),
                "matched": sum(1 for o in output if o.get("fingerprint")),
                "results": output,
            }, indent=2, ensure_ascii=False)
            return {"content": [{"type": "text", "text": text}]}
        elif tool_name == "health_check":
            health = asyncio.run(engine.health_check())
            health["fingerprint_rules"] = matcher.rule_count if matcher else 0
            health["fingerprint_rules_by_protocol"] = (
                matcher.stats()["rules_by_protocol"] if matcher else {}
            )
            health["database_fingerprint_rules"] = engine._database_matcher.rule_count
            health["fingerprint_path"] = _DEFAULT_FINGERPRINT
            text = json.dumps(health, indent=2, ensure_ascii=False)
            return {"content": [{"type": "text", "text": text}]}
        raise ValueError(f"Unknown tool: {tool_name}")
    elif method == "notifications/initialized":
        return {}
    raise ValueError(f"Unknown method: {method}")


class MCPHandler(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Mcp-Session-Id")
        self.send_header("Access-Control-Expose-Headers", "Mcp-Session-Id")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/sse":
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            sid = str(uuid.uuid4())
            self.wfile.write(f"event: endpoint\ndata: /message?sessionId={sid}\n\n".encode())
            self.wfile.flush()
            import time
            while True:
                try:
                    self.wfile.write(f": heartbeat\n\n".encode())
                    self.wfile.flush()
                    time.sleep(30)
                except (BrokenPipeError, ConnectionResetError):
                    break
        elif parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"banner-scanner MCP HTTP server running")
        elif parsed.path.startswith("/message"):
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"jsonrpc": "2.0", "id": None, "result": {}}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        cl = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl) if cl else b"{}"
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return

        method = payload.get("method", "")
        params = payload.get("params", {})
        req_id = payload.get("id")

        sys.stderr.write(f"[MCP] → {method} | params={json.dumps(params, ensure_ascii=False)[:200]}\n")
        try:
            result = handle_method(method, params)
            resp = {"jsonrpc": "2.0", "id": req_id, "result": result}
        except Exception as e:
            resp = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}}
            sys.stderr.write(f"[MCP] ✗ ERROR: {e}\n")

        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(resp, ensure_ascii=False).encode())

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/message"):
            self.send_response(200)
            self._cors()
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        sys.stderr.write(f"[MCP] {self.client_address[0]} - {format % args}\n")


def main():
    port = int(os.environ.get("MCP_PORT", 8877))
    server = HTTPServer(("127.0.0.1", port), MCPHandler)
    print(f"banner-scanner MCP (streamableHttp) → http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
