"""Generate subscription files from tested-alive nodes.

Outputs:
  clash.yaml      - proxies + url-test group AUTO (generate_204, 300s
                    interval) + select group PROXY, rules: MATCH -> AUTO
  shadowrocket.txt - base64 of one-link-per-line (vmess/vless/trojan/ss only)

Link -> clash-dict converters cover vmess/vless/trojan/ss/hysteria2.
Clash-dict -> link converters cover vmess/vless/trojan/ss.
"""
import base64
import json
import os
from datetime import datetime, timezone
from urllib.parse import quote

import yaml

BASE = os.path.dirname(os.path.abspath(__file__))

CLASH_LINK_PROTOCOLS = ("vmess", "vless", "trojan", "ss", "hysteria2")
SR_LINK_PROTOCOLS = ("vmess", "vless", "trojan", "ss")


# ---------- link -> clash proxy dict ----------

def vmess_link_to_clash(node):
    d = node["_vmess"]
    p = {"name": node["name"], "type": "vmess",
         "server": node["server"], "port": node["port"],
         "uuid": d.get("id", ""), "alterId": int(d.get("aid", 0) or 0),
         "cipher": d.get("scy", "auto") or "auto"}
    if d.get("tls") == "tls":
        p["tls"] = True
        if d.get("sni"):
            p["servername"] = d["sni"]
    net = d.get("net", "tcp") or "tcp"
    if net != "tcp":
        p["network"] = net
    if net == "ws":
        opts = {"path": d.get("path", "/") or "/"}
        if d.get("host"):
            opts["headers"] = {"Host": d["host"]}
        p["ws-opts"] = opts
    elif net == "grpc":
        p["grpc-opts"] = {"grpc-service-name": d.get("path", "") or ""}
    return p


def vless_trojan_link_to_clash(node):
    q = node["_params"]
    p = {"name": node["name"], "type": node["protocol"],
         "server": node["server"], "port": node["port"]}
    if node["protocol"] == "vless":
        p["uuid"] = node["_user"]
        p["encryption"] = q.get("encryption", "none")
    else:
        p["password"] = node["_user"]
    sec = q.get("security", "")
    if sec in ("tls", "reality"):
        p["tls"] = True
    if q.get("sni"):
        p["servername"] = q["sni"]
    if q.get("flow"):
        p["flow"] = q["flow"]
    if q.get("fp"):
        p["fingerprint"] = q["fp"]
    if q.get("alpn"):
        p["alpn"] = [a.strip() for a in q["alpn"].split(",")]
    net = q.get("type", "tcp") or "tcp"
    if net == "ws":
        p["network"] = "ws"
        opts = {"path": q.get("path", "/") or "/"}
        if q.get("host"):
            opts["headers"] = {"Host": q["host"]}
        p["ws-opts"] = opts
    elif net == "grpc":
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name":
                          q.get("serviceName", q.get("path", ""))}
    if sec == "reality":
        p["reality-opts"] = {"public-key": q.get("pbk", ""),
                             "short-id": q.get("sid", "")}
    return p


def ss_link_to_clash(node):
    p = {"name": node["name"], "type": "ss",
         "server": node["server"], "port": node["port"],
         "cipher": node["_method"], "password": node["_password"]}
    plugin = node.get("_plugin", "")
    if plugin.startswith("obfs-local"):
        p["plugin"] = "obfs"
        opts = {}
        for part in plugin.split(";")[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                opts[{"obfs": "mode", "obfs-host": "host"}.get(k, k)] = v
        if opts:
            p["plugin-opts"] = opts
    return p


def hy2_link_to_clash(node):
    q = node["_params"]
    p = {"name": node["name"], "type": "hysteria2",
         "server": node["server"], "port": node["port"],
         "password": node.get("_auth", "")}
    if q.get("sni"):
        p["sni"] = q["sni"]
    if q.get("insecure") == "1":
        p["skip-cert-verify"] = True
    return p


LINK_TO_CLASH = {
    "vmess": vmess_link_to_clash,
    "vless": vless_trojan_link_to_clash,
    "trojan": vless_trojan_link_to_clash,
    "ss": ss_link_to_clash,
    "hysteria2": hy2_link_to_clash,
}


# ---------- clash proxy dict -> link ----------

def clash_to_vmess_link(p):
    ws = p.get("ws-opts", {}) or {}
    headers = ws.get("headers", {}) or {}
    data = {
        "v": "2", "ps": p.get("name", ""),
        "add": p.get("server", ""), "port": str(p.get("port", "")),
        "id": p.get("uuid", ""), "aid": str(p.get("alterId", 0)),
        "scy": p.get("cipher", "auto") or "auto",
        "net": p.get("network", "tcp") or "tcp", "type": "none",
        "host": headers.get("Host", ""),
        "path": ws.get("path", "") if isinstance(ws, dict) else "",
        "tls": "tls" if p.get("tls") else "",
        "sni": p.get("servername", "") or "",
        "alpn": ",".join(p.get("alpn", []) or []),
        "fp": p.get("fingerprint", "") or p.get("client-fingerprint", "") or "",
    }
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    return "vmess://" + base64.b64encode(raw).decode()


def _qp(params):
    return "&".join(f"{k}={quote(str(v), safe='')}"
                    for k, v in params if v not in (None, ""))


def clash_to_vless_trojan_link(p):
    proto = p["type"]
    cred = quote(str(p.get("uuid" if proto == "vless" else "password", "")),
                 safe="")
    params = []
    if proto == "vless":
        params.append(("encryption", p.get("encryption", "none")))
    if p.get("tls"):
        params.append(("security", "tls"))
    elif p.get("reality-opts"):
        params.append(("security", "reality"))
    for key, qk in (("servername", "sni"), ("flow", "flow"),
                    ("fingerprint", "fp"), ("client-fingerprint", "fp")):
        if p.get(key):
            params.append((qk, p[key]))
            break
    if p.get("alpn"):
        params.append(("alpn", ",".join(p["alpn"])))
    net = p.get("network", "tcp") or "tcp"
    params.append(("type", net))
    if net == "ws":
        ws = p.get("ws-opts", {}) or {}
        params.append(("path", ws.get("path", "/")))
        host = (ws.get("headers", {}) or {}).get("Host", "")
        if host:
            params.append(("host", host))
    elif net == "grpc":
        grpc = p.get("grpc-opts", {}) or {}
        params.append(("serviceName",
                        grpc.get("grpc-service-name", "")))
    ro = p.get("reality-opts", {}) or {}
    if ro.get("public-key"):
        params.append(("pbk", ro["public-key"]))
    if ro.get("short-id"):
        params.append(("sid", ro["short-id"]))
    return (f"{proto}://{cred}@{p.get('server')}:{p.get('port')}"
            f"?{_qp(params)}#{quote(str(p.get('name', '')), safe='')}")


def clash_to_ss_link(p):
    userinfo = base64.b64encode(
        f"{p.get('cipher')}:{p.get('password')}".encode()).decode()
    return (f"ss://{userinfo}@{p.get('server')}:{p.get('port')}"
            f"#{quote(str(p.get('name', '')), safe='')}")


CLASH_TO_LINK = {
    "vmess": clash_to_vmess_link,
    "vless": clash_to_vless_trojan_link,
    "trojan": clash_to_vless_trojan_link,
    "ss": clash_to_ss_link,
}


# ---------- builders ----------

def unique_names(nodes):
    used, out = set(), []
    for n in nodes:
        name = str(n.get("name") or "node").strip() or "node"
        cand, i = name, 2
        while cand in used:
            cand = f"{name}-{i}"
            i += 1
        used.add(cand)
        out.append(cand)
    return out


def node_to_clash_proxy(node, name):
    """Return a clash proxy dict for an alive node, or None if unsupported."""
    if node.get("clash"):
        p = dict(node["clash"])
        p["name"] = name
        return p
    conv = LINK_TO_CLASH.get(node["protocol"])
    if not conv:
        return None
    try:
        p = conv(node)
        p["name"] = name
        return p
    except Exception:  # noqa: BLE001 - skip unconvertible
        return None


def node_to_link(node, name):
    """Return a share link for an alive node, or None if unsupported."""
    proto = node["protocol"]
    if proto not in SR_LINK_PROTOCOLS:
        return None
    try:
        if node.get("link"):
            link = node["link"]
            head = link.split("#", 1)[0]
            return f"{head}#{quote(name, safe='')}"
        conv = CLASH_TO_LINK.get(proto)
        if not conv or not node.get("clash"):
            return None
        p = dict(node["clash"])
        p["name"] = name
        return conv(p)
    except Exception:  # noqa: BLE001
        return None


def build_clash_yaml(alive):
    names = unique_names(alive)
    proxies = []
    for node, name in zip(alive, names):
        p = node_to_clash_proxy(node, name)
        if p:
            proxies.append(p)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    proxy_names = [p["name"] for p in proxies]
    doc = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "AUTO", "type": "url-test",
             "url": "http://www.gstatic.com/generate_204",
             "interval": 300, "tolerance": 50,
             "proxies": proxy_names},
            {"name": "PROXY", "type": "select",
             "proxies": ["AUTO"] + proxy_names},
        ],
        "rules": ["MATCH,PROXY"],
    }
    header = (f"# node-sub generated {ts} | {len(proxies)} nodes "
              f"(TCP-tested, sorted by latency)\n")
    return header + yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)


def build_shadowrocket_txt(alive):
    names = unique_names(alive)
    links = []
    for node, name in zip(alive, names):
        link = node_to_link(node, name)
        if link:
            links.append(link)
    raw = "\n".join(links)
    return base64.b64encode(raw.encode("utf-8")).decode()


def generate(alive):
    return build_clash_yaml(alive), build_shadowrocket_txt(alive)
