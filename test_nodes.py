"""TCP connectivity test for parsed nodes.

Concurrent (default 50 workers), 5s timeout per node. Keeps successes,
records latency in ms, sorts by latency, caps at 150 nodes.
"""
import socket
import time
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 5.0
WORKERS = 50
MAX_NODES = 150


def tcp_ping(node, timeout=TIMEOUT):
    start = time.monotonic()
    try:
        sock = socket.create_connection((node["server"], node["port"]),
                                        timeout=timeout)
        sock.close()
        return (time.monotonic() - start) * 1000.0
    except Exception:  # noqa: BLE001 - dead node, just skip
        return None


def test_all(nodes, workers=WORKERS, timeout=TIMEOUT, cap=MAX_NODES):
    alive = []

    def check(node):
        lat = tcp_ping(node, timeout)
        if lat is not None:
            node["latency_ms"] = round(lat, 1)
            return node
        return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(check, nodes):
            if result is not None:
                alive.append(result)

    alive.sort(key=lambda n: n["latency_ms"])
    print(f"[test] {len(alive)}/{len(nodes)} nodes alive "
          f"(TCP {timeout}s timeout, {workers} workers)")
    if len(alive) > cap:
        print(f"[test] capped to fastest {cap}")
        alive = alive[:cap]
    return alive


if __name__ == "__main__":
    import json
    import fetch_sources
    import parse_nodes
    results = fetch_sources.fetch_all()
    nodes, _ = parse_nodes.parse_all(results)
    alive = test_all(nodes)
    print(json.dumps(
        [{"name": n["name"], "protocol": n["protocol"],
          "server": n["server"], "port": n["port"],
          "latency_ms": n["latency_ms"]} for n in alive[:10]],
        ensure_ascii=False, indent=1))
