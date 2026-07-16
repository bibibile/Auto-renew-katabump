#!/usr/bin/env python3
"""将代理分享链接 (vless:// hysteria2:// tuic:// socks://) 转换为 sing-box 配置文件 (安全脱敏诊断版)"""

import json
import sys
import urllib.parse

# 强制让所有 print 语句实时刷新，防止 GitHub Actions 缓存日志
print("=== 🛠️ DEBUG: convert.py 脚本已成功启动 ===", flush=True)

INBOUND = {
    "type": "http",
    "tag": "local-in",
    "listen": "127.0.0.1",
    "listen_port": 8080
}


def _frag(link: str):
    """从 URL fragment 提取节点名称"""
    h = urllib.parse.urlparse(link)
    return urllib.parse.unquote(h.fragment) if h.fragment else ""


# ── vless:// ─────────────────────────────────────────────
def _vless(link: str) -> dict:
    u = urllib.parse.urlparse(link)
    if u.scheme != "vless":
        raise ValueError(f"不支持的协议: {u.scheme}")

    uuid = u.username or ""
    server = u.hostname
    port = u.port or 443
    q = dict(urllib.parse.parse_qsl(u.query))

    ob = {
        "type": "vless",
        "server": server,
        "server_port": port,
        "uuid": uuid,
    }

    sec    = q.get("security", "tls")
    sni    = q.get("sni", q.get("host", server))
    fp     = q.get("fp", "chrome")
    alpn_s = q.get("alpn", "")
    alpn   = [a for a in alpn_s.split(",") if a]

    # ── transport ──
    t_type = q.get("type", "tcp")
    if t_type == "ws":
        t = {"type": "ws"}
        if q.get("path"):
            t["path"] = q["path"]
        if q.get("host"):
            t["headers"] = {"Host": q["host"]}
        ob["transport"] = t
    elif t_type == "grpc":
        t = {"type": "grpc"}
        if q.get("serviceName"):
            t["service_name"] = q["serviceName"]
        ob["transport"] = t
    elif t_type == "http":
        t = {"type": "http"}
        if q.get("host"):
            t["host"] = [q["host"]]
        if q.get("path"):
            t["path"] = q["path"]
        ob["transport"] = t

    # ── tls ──
    if sec in ("tls", "reality"):
        tls = {"enabled": True, "server_name": sni}
        if alpn:
            tls["alpn"] = alpn

        if sec == "reality":
            reality = {"enabled": True}
            if q.get("pbk"):
                reality["public_key"] = q["pbk"]
            if q.get("sid"):
                reality["short_id"] = q["sid"]
            tls["reality"] = reality
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        else:
            tls["utls"] = {"enabled": True, "fingerprint": fp}

        ob["tls"] = tls

        flow = q.get("flow", "")
        if flow:
            ob["flow"] = flow

    return ob


# ── hysteria2:// ─────────────────────────────────────────
def _hysteria2(link: str) -> dict:
    u = urllib.parse.urlparse(link)
    if u.scheme not in ("hysteria2", "hy2"):
        raise ValueError(f"不支持的协议: {u.scheme}")

    password = urllib.parse.unquote(u.username or "")
    q = dict(urllib.parse.parse_qsl(u.query))

    ob = {
        "type": "hysteria2",
        "server": u.hostname,
        "server_port": u.port or 443,
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": q.get("sni", u.hostname),
            "insecure": q.get("insecure", "0") == "1",
        },
    }

    if q.get("obfs") and q.get("obfs-password"):
        ob["obfs"] = {"type": q["obfs"], "password": q["obfs-password"]}

    return ob


# ── tuic:// ──────────────────────────────────────────────
def _tuic(link: str) -> dict:
    u = urllib.parse.urlparse(link)
    if u.scheme != "tuic":
        raise ValueError(f"不支持的协议: {u.scheme}")

    raw_user = u.username or ""
    if ":" in raw_user:
        uuid, password = raw_user.split(":", 1)
    else:
        uuid, password = raw_user, ""

    q = dict(urllib.parse.parse_qsl(u.query))

    return {
        "type": "tuic",
        "server": u.hostname,
        "server_port": u.port or 443,
        "uuid": uuid,
        "password": password,
        "congestion_control": q.get("congestion_control", "bbr"),
        "udp_relay_mode": q.get("udp_relay_mode", "native"),
        "tls": {
            "enabled": True,
            "server_name": q.get("sni", u.hostname),
            "alpn": [a for a in q.get("alpn", "h3").split(",") if a],
        },
    }


# ── socks:// ─────────────────────────────────────────────
def _socks(link: str) -> dict:
    u = urllib.parse.urlparse(link)
    if u.scheme != "socks":
        raise ValueError(f"不支持的协议: {u.scheme}")

    ob = {
        "type": "socks",
        "server": u.hostname,
        "server_port": u.port or 1080,
        "version": "5",
    }
    if u.username:
        ob["username"] = urllib.parse.unquote(u.username)
    if u.password:
        ob["password"] = urllib.parse.unquote(u.password)
    return ob


# ── 自动识别并解析 ──────────────────────────────────────
def parse_link(link: str) -> dict:
    link = link.strip()

    if link.startswith("vless://"):
        return _vless(link)
    if link.startswith("hysteria2://") or link.startswith("hy2://"):
        return _hysteria2(link)
    if link.startswith("tuic://"):
        return _tuic(link)
    if link.startswith("socks://") or link.startswith("socks5://"):
        return _socks(link)

    raise ValueError(
        f"不支持的链接格式，仅支持: vless:// hysteria2:// hy2:// tuic:// socks://\n"
        f"收到: {link[:50]}..."
    )


# ── 安全脱敏打印工具 ────────────────────────────────────
def mask_ip(ip: str) -> str:
    if not ip:
        return "***"
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.xxx.xxx.{parts[-1]}"
    return "xxx.xxx.xxx.xxx"


def main():
    if len(sys.argv) < 2:
        print("❌ 错误: 未传入节点链接参数！", flush=True)
        sys.exit(1)

    link = sys.argv[1].strip()
    if not link:
        print("❌ 错误: 传入的链接为空字符串！", flush=True)
        sys.exit(1)
    
    u = urllib.parse.urlparse(link)
    scheme = u.scheme if u.scheme else "unknown"
    print(f"🔗 解析链接: {scheme}://***@***:***", flush=True)

    try:
        outbound = parse_link(link)
    except Exception as e:
        print(f"❌ 解析链接失败: {str(e)}", flush=True)
        sys.exit(1)
    
    print(f"   协议: {outbound['type']}", flush=True)
    print(f"   服务器: {mask_ip(outbound['server'])}:***", flush=True)

    config = {
        "log": {"level": "warn"},
        "inbounds": [INBOUND],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"}
        ],
        "route": {
            "rules": [
                {"ip_is_private": True, "outbound": "direct"}
            ]
        }
    }

    try:
        with open("config.json", "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        print("   配置已成功写入 config.json", flush=True)
    except Exception as e:
        print(f"❌ 写入 config.json 失败: {str(e)}", flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
