"""node-sub pipeline: fetch -> parse -> test -> generate.

Writes intermediate files to work/, final subscriptions to output/
ATOMICALLY: output/ is only replaced when at least one node survives.
If zero nodes survive, previous output is kept untouched and we exit 2.
"""
import json
import os
import sys
from datetime import datetime, timezone

import fetch_sources
import parse_nodes
import test_nodes
import generate_subs

BASE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(BASE, "work")
OUT = os.path.join(BASE, "output")


def main():
    os.makedirs(WORK, exist_ok=True)
    os.makedirs(OUT, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"=== node-sub run {ts} ===")

    # 1. fetch
    results = fetch_sources.fetch_all()
    with open(os.path.join(WORK, "fetch.json"), "w") as f:
        json.dump(results, f, ensure_ascii=False, indent=1)

    # 2. parse + dedupe
    nodes, stats = parse_nodes.parse_all(results)
    with open(os.path.join(WORK, "nodes.json"), "w") as f:
        json.dump([{k: n.get(k) for k in
                    ("name", "protocol", "server", "port")}
                   for n in nodes], f, ensure_ascii=False)

    # 3. test
    alive = test_nodes.test_all(nodes)
    with open(os.path.join(WORK, "alive.json"), "w") as f:
        json.dump([{k: n.get(k) for k in
                    ("name", "protocol", "server", "port", "latency_ms")}
                   for n in alive], f, ensure_ascii=False, indent=1)

    # 4. generate (atomic: only touch output/ on success)
    if not alive:
        print("[pipeline] ERROR: zero nodes survived; "
              "keeping previous output untouched")
        return 2
    clash_yaml, sr_txt = generate_subs.generate(alive)
    tmp_clash = os.path.join(WORK, "clash.yaml.new")
    tmp_sr = os.path.join(WORK, "shadowrocket.txt.new")
    with open(tmp_clash, "w", encoding="utf-8") as f:
        f.write(clash_yaml)
    with open(tmp_sr, "w", encoding="utf-8") as f:
        f.write(sr_txt)
    os.replace(tmp_clash, os.path.join(OUT, "clash.yaml"))
    os.replace(tmp_sr, os.path.join(OUT, "shadowrocket.txt"))

    n_clash = clash_yaml.count("\n- name:")
    n_sr = len(sr_txt)
    print(f"[pipeline] wrote output/clash.yaml, output/shadowrocket.txt "
          f"({len(alive)} alive nodes)")
    print(f"[pipeline] DONE {ts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
