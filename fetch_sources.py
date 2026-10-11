"""Fetch raw node lists from the public sources in sources.yaml.

Polite fetching: ~1s delay between sources, 10s timeout per fetch,
browser-like User-Agent. Saves each source to work/raw_<name>.
"""
import os
import time
import urllib.request
import yaml

BASE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(BASE, "work")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


def fetch_all(sources_path=None, delay=1.0, timeout=10):
    sources_path = sources_path or os.path.join(BASE, "sources.yaml")
    os.makedirs(WORK, exist_ok=True)
    with open(sources_path, "r", encoding="utf-8") as f:
        sources = yaml.safe_load(f).get("sources", [])

    results = []
    for i, src in enumerate(sources):
        name = src.get("name", f"src{i}")
        url = src.get("url", "")
        fmt = src.get("format", "links")
        dest = os.path.join(WORK, f"raw_{name}")
        if i > 0:
            time.sleep(delay)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            if not data:
                raise ValueError("empty response")
            with open(dest, "wb") as f:
                f.write(data)
            print(f"[fetch] OK  {name} ({len(data)} bytes, {fmt})")
            results.append({"name": name, "format": fmt, "path": dest,
                            "ok": True, "size": len(data)})
        except Exception as e:  # noqa: BLE001 - tolerant, keep going
            print(f"[fetch] FAIL {name}: {type(e).__name__}: {e}")
            results.append({"name": name, "format": fmt, "path": dest,
                            "ok": False, "error": f"{type(e).__name__}: {e}"})
    return results


if __name__ == "__main__":
    res = fetch_all()
    ok = sum(1 for r in res if r["ok"])
    print(f"[fetch] {ok}/{len(res)} sources fetched")
