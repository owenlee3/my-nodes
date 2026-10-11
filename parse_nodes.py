"""Parse fetched sources into normalized node dicts.

Normalized node:
    {"name": str, "protocol": str, "server": str, "port": int,
     "link": str|None,            # original share link (link sources)
     "clash": dict|None}         # clash proxy dict (yaml sources, or converted)

Handles: vmess://, vless://, trojan://, ss://, ssr://, hy2://,
hysteria2:// links, plus clash yaml `proxies` lists.
Malformed entries are skipped, never fatal.
"""
import base64
import binascii
import json
import os
import re
from urllib.parse import unquote, urlparse, parse_qs

import yaml

BASE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(BASE, "work")

SUPPORTED_LINK_SCHEMES = ("vmess", "vless", "trojan", "ss", "ssr",
                          "hy2", "hysteria2")


def b64decode(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def split_link(link):
    """Return (head, query, fragment-name)."""
    frag = ""
    if "#" in link:
        link, frag = link.split("#", 1)
    name = unquote(frag).strip()
    return link, name


def parse_vmess(link):
    head, name = split_link(link)
    data = json.loads(b64decode(head[8:]).decode("utf-8", errors="replace"))
    server = str(data.get("add", "")).strip()
    port = int(str(data.get("port", 0)).strip() or 0)
    if not server or not port:
        raise ValueError("vmess missing server/port")
    return {"name": name or str(data.get("ps", "vmess")).strip() or "vmess",
            "protocol": "vmess", "server": server, "port": port,
            "link": link, "clash": None, "_vmess": data}


def parse_vless_trojan(link, protocol):
    head, name = split_link(link)
    u = urlparse(head)
    q = parse_qs(u.query)
    server = (u.hostname or "").strip()
    port = u.port or 443
    if not server:
        raise ValueError(f"{protocol} missing server")
    user = unquote(u.username or "")
    if not user:
        raise ValueError(f"{protocol} missing credentials")
    return {"name": name or f"{protocol}-{server}:{port}",
            "protocol": protocol, "server": server, "port": port,
            "link": link, "clash": None,
            "_user": user, "_params": {k: v[0] for k, v in q.items()}}


def parse_ss(link):
    head, name = split_link(link)
    body = head[5:]
    plugin = ""
    if "?" in body:
        body, query = body.split("?", 1)
        m = re.search(r"plugin=([^&]+)", query)
        if m:
            plugin = unquote(m.group(1))
    if "@" in body:
        userinfo_b64, hostport = body.rsplit("@", 1)
        try:
            userinfo = b64decode(userinfo_b64).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            userinfo = unquote(userinfo_b64)
    else:
        decoded = b64decode(body).decode("utf-8", errors="replace")
        if "@" in decoded:
            userinfo, hostport = decoded.rsplit("@", 1)
        else:
            raise ValueError("ss missing host")
    if ":" not in userinfo:
        raise ValueError("ss missing method:password")
    method, password = userinfo.split(":", 1)
    hostport = hostport.strip().rstrip("/")
    if ":" in hostport:
        server, port_s = hostport.rsplit(":", 1)
    else:
        server, port_s = hostport, "8388"
    server = server.strip().strip("[]")
    port = int(port_s or 0)
    if not server or not port:
        raise ValueError("ss missing server/port")
    return {"name": name or f"ss-{server}:{port}",
            "protocol": "ss", "server": server, "port": port,
            "link": link, "clash": None,
            "_method": method.strip(), "_password": password,
            "_plugin": plugin}


def parse_ssr(link):
    head, name = split_link(link)
    body = head[6:].split("/")[0].split("?")[0]
    decoded = b64decode(body).decode("utf-8", errors="replace")
    parts = decoded.split(":")
    if len(parts) < 6:
        raise ValueError("ssr malformed")
    server, port = parts[0], int(parts[1] or 0)
    if not server or not port:
        raise ValueError("ssr missing server/port")
    return {"name": name or f"ssr-{server}:{port}",
            "protocol": "ssr", "server": server, "port": port,
            "link": link, "clash": None}


def parse_hy2(link):
    scheme = "hysteria2" if link.startswith("hysteria2://") else "hy2"
    head, name = split_link(link)
    u = urlparse(head)
    q = parse_qs(u.query)
    server = (u.hostname or "").strip()
    port = u.port or 443
    if not server:
        raise ValueError("hysteria2 missing server")
    auth = unquote(u.username or "")
    params = {k: v[0] for k, v in q.items()}
    return {"name": name or f"hy2-{server}:{port}",
            "protocol": "hysteria2", "server": server, "port": port,
            "link": link, "clash": None,
            "_auth": auth, "_params": params}


LINK_PARSERS = {
    "vmess": parse_vmess,
    "vless": lambda l: parse_vless_trojan(l, "vless"),
    "trojan": lambda l: parse_vless_trojan(l, "trojan"),
    "ss": parse_ss,
    "ssr": parse_ssr,
    "hy2": parse_hy2,
    "hysteria2": parse_hy2,
}


def parse_link(link):
    link = link.strip()
    if not link or link.startswith("#"):
        return None
    scheme = link.split("://", 1)[0].lower()
    if scheme not in LINK_PARSERS:
        return None
    try:
        return LINK_PARSERS[scheme](link)
    except Exception:  # noqa: BLE001 - skip malformed, never crash
        return None


def parse_link_text(text):
    """Parse text that may be plain links or whole-file base64 of links."""
    text = text.strip()
    if not text:
        return []
    if "://" not in text:
        # likely whole-file base64 (standard v2ray subscription)
        try:
            decoded = b64decode(text).decode("utf-8", errors="replace")
            if "://" in decoded:
                text = decoded
        except (binascii.Error, ValueError):
            pass
    nodes, seen_lines = [], set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line in seen_lines:
            continue
        seen_lines.add(line)
        # some lists nest base64-per-line
        if "://" not in line:
            try:
                d = b64decode(line).decode("utf-8", errors="replace").strip()
                if "://" in d:
                    line = d
            except (binascii.Error, ValueError):
                continue
        node = parse_link(line)
        if node:
            nodes.append(node)
    return nodes


def parse_clash_yaml(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = yaml.safe_load(f)
    except Exception:  # noqa: BLE001
        return []
    proxies = (data or {}).get("proxies") or []
    nodes = []
    for p in proxies:
        try:
            if not isinstance(p, dict):
                continue
            server = str(p.get("server", "")).strip()
            port = int(p.get("port") or 0)
            if not server or not port:
                continue
            proto = str(p.get("type", "")).strip().lower()
            name = str(p.get("name", "")).strip() or f"{proto}-{server}:{port}"
            nodes.append({"name": name, "protocol": proto or "unknown",
                          "server": server, "port": port,
                          "link": None, "clash": dict(p)})
        except Exception:  # noqa: BLE001
            continue
    return nodes


def parse_all(fetch_results):
    all_nodes, stats = [], {}
    for r in fetch_results:
        if not r.get("ok"):
            stats[r["name"]] = {"fetched": 0, "parsed": 0, "error": r.get("error")}
            continue
        path, fmt = r["path"], r["format"]
        try:
            if fmt == "clash-yaml":
                nodes = parse_clash_yaml(path)
            else:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    nodes = parse_link_text(f.read())
        except Exception as e:  # noqa: BLE001
            nodes = []
            print(f"[parse] {r['name']}: reader error {e}")
        stats[r["name"]] = {"fetched": len(nodes), "parsed": len(nodes)}
        print(f"[parse] {r['name']}: {len(nodes)} nodes")
        all_nodes.extend(nodes)

    # dedupe by server:port (case-insensitive host), keep first seen
    seen, deduped = set(), []
    for n in all_nodes:
        key = (n["server"].lower().strip("[]"), n["port"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(n)
    print(f"[parse] total {len(all_nodes)} -> {len(deduped)} after dedupe")
    return deduped, stats


if __name__ == "__main__":
    import fetch_sources
    results = fetch_sources.fetch_all()
    nodes, stats = parse_all(results)
    print(f"parsed {len(nodes)} unique nodes")
