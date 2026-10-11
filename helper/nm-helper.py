#!/usr/bin/env python3
"""nginx-manager data-plane helper.

Runs on each nginx server (systemd unit nginx-manager-helper, unprivileged). Every interval it
  - probes the backends listed in helper.json (TCP connect, or an HTTP(S) request), and
  - reads nginx's loopback-only stub_status,
and sends the results to nginx-manager as JSON over UDP syslog (tag nginx_health).

The target list is written by nginx-manager through NGINX Agent; this script never needs
updating for config changes. Python 3 standard library only.
"""

import concurrent.futures
import http.client
import json
import os
import socket
import ssl
import sys
import time
import urllib.request

VERSION = "1.0"
CONFIG = sys.argv[1] if len(sys.argv) > 1 else "/etc/nginx/nginx-manager/helper.json"
HOSTNAME = socket.gethostname().split(".")[0] or "nginx"
CHUNK = 25


def load():
    try:
        with open(CONFIG, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def expect_ok(code, spec):
    for part in str(spec or "200-399").split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            if int(lo) <= code <= int(hi):
                return True
        elif part and int(part) == code:
            return True
    return False


def probe(t, timeout):
    start = time.monotonic()
    try:
        if t.get("type") == "http":
            ctx = ssl._create_unverified_context() if t.get("tls") else None   # backends often use self-signed certs
            cls = http.client.HTTPSConnection if t.get("tls") else http.client.HTTPConnection
            kw = {"context": ctx} if ctx else {}
            conn = cls(t["host"], int(t["port"]), timeout=timeout, **kw)
            headers = {"User-Agent": "nginx-manager-health/" + VERSION, "Connection": "close"}
            if t.get("hostHeader"):
                headers["Host"] = t["hostHeader"]
            conn.request("GET", t.get("path") or "/", headers=headers)
            code = conn.getresponse().status
            conn.close()
            ok = expect_ok(code, t.get("expect"))
            return {"k": t["k"], "ok": ok, "ms": round((time.monotonic() - start) * 1000, 1), "code": code,
                    "err": "" if ok else "HTTP %d" % code}
        with socket.create_connection((t["host"], int(t["port"])), timeout=timeout):
            pass
        return {"k": t["k"], "ok": True, "ms": round((time.monotonic() - start) * 1000, 1)}
    except Exception as e:  # noqa: BLE001 — any failure is a failed probe
        msg = str(e) or e.__class__.__name__
        if isinstance(e, socket.timeout) or "timed out" in msg:
            msg = "timed out after %ss" % timeout
        return {"k": t["k"], "ok": False, "ms": round((time.monotonic() - start) * 1000, 1), "err": msg[:200]}


def stub_status(url, timeout):
    if not url:
        return None
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            text = r.read(4096).decode("ascii", "replace")
    except Exception:  # noqa: BLE001
        return None
    lines = [l.split() for l in text.splitlines()]
    try:
        out = {"active": int(lines[0][2])}
        out["accepts"], out["handled"], out["requests"] = (int(x) for x in lines[2][:3])
        out["reading"], out["writing"], out["waiting"] = int(lines[3][1]), int(lines[3][3]), int(lines[3][5])
        return out
    except (IndexError, ValueError):
        return None


def send(sock, addr, payload):
    stamp = time.strftime("%b %d %H:%M:%S")
    msg = "<134>%s %s %s: %s" % (stamp, HOSTNAME, "nginx_health", json.dumps(payload, separators=(",", ":")))
    try:
        sock.sendto(msg.encode("utf-8"), addr)
    except OSError:
        pass


def main():
    sock = None
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=16)
    while True:
        cfg = load()
        if not cfg or not cfg.get("report"):
            time.sleep(30)
            continue
        interval = max(5, int(cfg.get("interval", 10)))
        timeout = max(1, min(int(cfg.get("timeout", 3)), interval - 1))
        started = time.monotonic()
        try:
            host, port = cfg["report"]["host"], int(cfg["report"]["port"])
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            if sock is None or sock.family != family:
                sock = socket.socket(family, socket.SOCK_DGRAM)
            targets = cfg.get("targets") or []
            results = list(pool.map(lambda t: probe(t, timeout), targets))
            status = stub_status(cfg.get("status"), timeout)
            chunks = [results[i:i + CHUNK] for i in range(0, len(results), CHUNK)] or [[]]
            for i, chunk in enumerate(chunks):
                payload = {"helper": VERSION, "results": chunk}
                if i == 0 and status is not None:
                    payload["status"] = status
                send(sock, (host, port), payload)
        except Exception as e:  # noqa: BLE001 — keep running; systemd restarts us if we die anyway
            print("nm-helper: %s" % e, file=sys.stderr, flush=True)
        time.sleep(max(1, interval - (time.monotonic() - started)))


if __name__ == "__main__":
    if os.environ.get("NM_HELPER_ONCE"):
        cfg = load() or {}
        print(json.dumps({"results": [probe(t, int(cfg.get("timeout", 3))) for t in cfg.get("targets", [])],
                          "status": stub_status(cfg.get("status"), 3)}, indent=2))
    else:
        main()
