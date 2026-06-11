#!/usr/bin/env python3
"""MCP 客户端验证脚本 — 连接 banner-scanner 并依次验证所有功能"""
import json
import urllib.request

URL = "http://127.0.0.1:8877/message"
next_id = 1

def rpc(method, params=None):
    global next_id
    req = {"jsonrpc": "2.0", "id": next_id, "method": method, "params": params or {}}
    next_id += 1
    data = json.dumps(req).encode()
    resp = urllib.request.urlopen(urllib.request.Request(URL, data=data, headers={"Content-Type": "application/json"}))
    return json.loads(resp.read())

def check(label, ok):
    print(f"  {'✅' if ok else '❌'} {label}")
    return ok

all_ok = True

print("=" * 50)
print("1. initialize")
r = rpc("initialize")
all_ok &= check("协议版本 2024-11-05", r["result"]["protocolVersion"] == "2024-11-05")
all_ok &= check("服务名 banner-scanner", r["result"]["serverInfo"]["name"] == "banner-scanner")

print("\n2. tools/list")
r = rpc("tools/list")
tools = {t["name"] for t in r["result"]["tools"]}
all_ok &= check("probe_banner 已注册", "probe_banner" in tools)
all_ok &= check("scan_batch 已注册", "scan_batch" in tools)
all_ok &= check("health_check 已注册", "health_check" in tools)

print("\n3. tools/call health_check")
r = rpc("tools/call", {"name": "health_check", "arguments": {}})
text = r["result"]["content"][0]["text"]
data = json.loads(text)
all_ok &= check("healthy=true", data["healthy"] is True)
all_ok &= check(f"指纹规则={data['fingerprint_rules']}", data["fingerprint_rules"] > 0)

print("\n4. tools/call probe_banner (github.com SSH)")
r = rpc("tools/call", {"name": "probe_banner", "arguments": {"hosts": ["github.com"], "protocols": ["ssh"]}})
text = r["result"]["content"][0]["text"]
data = json.loads(text)
all_ok &= check(f"hosts={data['total_hosts']} probes={data['total_probes']}", data["total_hosts"] > 0)
all_ok &= check(f"accessible={data['accessible']}", data["accessible"] > 0)
if data["results"]:
    br = data["results"][0]
    all_ok &= check(f"Banner: {br['banner'][:40]}", bool(br["banner"]))

print("\n5. notifications/initialized")
r = rpc("notifications/initialized")
all_ok &= check("返回成功", "result" in r)

print("\n" + "=" * 50)
if all_ok:
    print("🎉 全部通过！MCP 服务正常")
else:
    print("⚠️  部分失败，请检查服务状态")
