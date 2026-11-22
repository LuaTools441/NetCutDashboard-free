#!/usr/bin/env python3
"""
netcut_gui.py - a local web dashboard for the net_tree / netcut engine.

Starts a tiny HTTP server bound to 127.0.0.1 ONLY (never exposed to the LAN) and opens the
dashboard in your browser. The page (web/) talks to a small JSON API that drives the same
scanner and ARP engine as the terminal tool.

Run:
    python netcut_gui.py
Build to a single exe:
    python build_exe.py      (uses PyInstaller; the exe requests Administrator automatically)

Cutting/protecting needs Administrator + Npcap, exactly like the terminal tool.
Only use this on a network you own or manage.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import net_tree
import netcut

# When frozen by PyInstaller the web/ folder is unpacked next to the temp _MEIPASS root.
BASE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
WEB = BASE / "web"
HOST = "127.0.0.1"

MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".ico": "image/x-icon",
        ".json": "application/json; charset=utf-8"}


class State:
    """Holds the scanner map, the ARP engine and protection, shared by all requests."""

    def __init__(self):
        self.nm = net_tree.NetMap()
        self.env = netcut.Env.detect(prefix=self.nm.my_network.prefixlen)
        if not self.env.gateway_mac:
            gw = self.nm.devices.get(self.nm.gateway)
            if gw and gw.mac:
                self.env.gateway_mac = gw.mac
        self.mgr = netcut.CutManager(self.env)
        self.protector = None
        self.scanning = False
        self.scan_error = ""
        self.last_scan = ""
        self._lock = threading.Lock()

    # ---- scanning ----
    def scan(self):
        with self._lock:
            if self.scanning:
                return
            self.scanning = True
            self.scan_error = ""
        def run():
            try:
                self.nm.scan(self.nm.my_network)
                if not self.env.gateway_mac:
                    gw = self.nm.devices.get(self.nm.gateway)
                    if gw and gw.mac:
                        self.env.gateway_mac = gw.mac
                self.last_scan = self.nm.scanned_at
            except Exception as e:
                self.scan_error = f"{type(e).__name__}: {e}"
            finally:
                self.scanning = False
        threading.Thread(target=run, daemon=True).start()

    # ---- snapshot for the UI ----
    def snapshot(self):
        self.mgr.sample_rates()
        cuts = {c[0]: c for c in self.mgr.status()}
        devices = []
        for d in self.nm.devices.values():
            st = cuts.get(d.ip)
            cut = None
            if st:
                _, _, secs, sent, mode, level, inter, esc = st
                c = self.mgr.get(d.ip)
                recent = bool(c and c.last_intercept and (time.time() - c.last_intercept) < 8)
                cut = {"mode": mode, "level": level, "seconds": secs, "sent": sent,
                       "intercepted": inter, "escapes": esc, "intercepting": inter > 0 and recent,
                       "throttle": round(getattr(c, "throttle", 0.0), 2) if c else 0.0,
                       "stack": c.stack if c else "both",
                       "log_total": c.log_total if c else 0,
                       "log": self.mgr.top_traffic(d.ip, 30)}
                if mode == "shape" and c:
                    moving = (c.down_rate + c.up_rate) > 0.05 or (c.down_bytes + c.up_bytes) > 0
                    cut.update({"down_mbps": c.down_mbps, "up_mbps": c.up_mbps,
                                "down_rate": max(0, round(c.down_rate, 2)),
                                "up_rate": max(0, round(c.up_rate, 2)), "dropped": c.dropped,
                                "forwarded": c.down_bytes + c.up_bytes,
                                "holding": moving})
            devices.append({
                "ip": d.ip, "name": d.name() or "", "vendor": d.vendor or "", "mac": d.mac or "",
                "kind": d.kind or "", "os": d.os_guess or "", "is_me": d.is_me,
                "is_gateway": d.is_gateway, "random_mac": d.random_mac,
                "online": d.answers_ping or bool(d.mac), "cut": cut,
            })
        return {
            "me": self.env.my_ip, "gateway": self.env.gateway_ip,
            "gateway_mac": self.env.gateway_mac, "network": str(self.nm.my_network),
            "admin": netcut.is_admin(), "scapy": netcut.SCAPY_OK,
            "scanning": self.scanning, "scan_error": self.scan_error, "last_scan": self.last_scan,
            "protection": self.protector is not None, "device_count": len(self.nm.devices),
            "active_cuts": len(cuts), "devices": devices,
            "rules": self.mgr.list_rules(), "block_doh": self.mgr.block_doh,
            "mitm_ok": netcut.MITM_OK, "https_intercept": self.mgr.https_intercept,
            "ca_url": self.mgr.ca_info()["url"],
        }

    # ---- actions ----
    def _mac(self, ip):
        d = self.nm.devices.get(ip)
        return d.mac if d else ""

    def cut(self, ip, stack="both"):
        if self.mgr.is_cut(ip):
            self.mgr.set_mode(ip, "full")
            self.mgr.set_stack(ip, stack)
        else:
            self.mgr.start(ip, self._mac(ip), mode="full", stack=stack)

    def monitor(self, ip, stack="both"):
        if self.mgr.is_cut(ip):
            return  # already active; use the card to switch mode if needed
        self.mgr.start(ip, self._mac(ip), mode="monitor", stack=stack)

    def set_stack(self, ip, stack):
        return self.mgr.set_stack(ip, stack)

    def add_rule(self, from_domain, target, scope="all", html=None):
        rule = self.mgr.set_rule(from_domain, target, scope, html=html or None)
        # a rule only works while the device is in our path, so auto-Watch it
        if scope and scope != "all" and not self.mgr.is_cut(scope):
            try:
                self.mgr.start(scope, self._mac(scope), mode="monitor")
            except Exception:
                pass
        return rule

    def set_block_doh(self, on):
        return self.mgr.set_block_doh(on)

    def set_https(self, on):
        return self.mgr.set_https_intercept(on)

    def remove_rule(self, from_domain):
        self.mgr.remove_rule(from_domain)

    def clear_traffic(self, ip):
        self.mgr.clear_log(ip)

    def shape(self, ip, down_mbps, up_mbps):
        if self.mgr.is_cut(ip):
            return self.mgr.set_shape(ip, down_mbps, up_mbps)
        self.mgr.start(ip, self._mac(ip), mode="shape", down_mbps=down_mbps, up_mbps=up_mbps)
        return {"down_mbps": float(down_mbps or 0), "up_mbps": float(up_mbps or 0)}

    def weakwifi(self, ip, strength, stack="both"):
        if self.mgr.is_cut(ip):
            self.mgr.set_mode(ip, "throttle", strength)
            self.mgr.set_stack(ip, stack)
        else:
            self.mgr.start(ip, self._mac(ip), mode="throttle", throttle=strength, stack=stack)

    def resume(self, ip):
        if ip == "all":
            self.mgr.stop_all(do_heal=True)
        else:
            self.mgr.stop_cut(ip, do_heal=True)

    def set_level(self, ip, level):
        return self.mgr.set_level(ip, int(level))

    def verify(self, ip):
        return self.mgr.verify(ip, window=4)

    def protect(self, on):
        if on and not self.protector:
            p = netcut.Protector(self.env)
            ok, msg = p.pin_gateway()
            p.start_watch()
            self.protector = p
            return {"ok": ok, "message": msg}
        if not on and self.protector:
            self.protector.shutdown()
            self.protector = None
            return {"ok": True, "message": "protection off"}
        return {"ok": True, "message": "no change"}

    def shutdown(self):
        self.mgr.stop_all(do_heal=True)
        self.mgr.stop_services()
        if self.protector:
            self.protector.shutdown()


STATE: State | None = None


class Handler(BaseHTTPRequestHandler):
    server_version = "netcut-gui"

    def log_message(self, *a):
        pass  # quiet

    # ---- helpers ----
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else str(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj).encode("utf-8"))

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    # ---- routing ----
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/state":
            return self._json(STATE.snapshot())
        self._static(path)

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        body = self._body()
        ip = str(body.get("ip", ""))
        try:
            if path == "/api/scan":
                STATE.scan(); return self._json({"ok": True})
            if path == "/api/cut":
                STATE.cut(ip, body.get("stack", "both")); return self._json({"ok": True})
            if path == "/api/monitor":
                STATE.monitor(ip, body.get("stack", "both")); return self._json({"ok": True})
            if path == "/api/stack":
                return self._json({"ok": True, "stack": STATE.set_stack(ip, body.get("stack", "both"))})
            if path == "/api/cleartraffic":
                STATE.clear_traffic(ip); return self._json({"ok": True})
            if path == "/api/rule":
                return self._json({"ok": True, "rule": STATE.add_rule(
                    body.get("from", ""), body.get("to", ""), body.get("scope", "all"), body.get("html"))})
            if path == "/api/block_doh":
                return self._json({"ok": True, "block_doh": STATE.set_block_doh(bool(body.get("on")))})
            if path == "/api/https":
                return self._json(STATE.set_https(bool(body.get("on"))))
            if path == "/api/rule_remove":
                STATE.remove_rule(body.get("from", "")); return self._json({"ok": True})
            if path == "/api/weakwifi":
                STATE.weakwifi(ip, body.get("strength", "medium"), body.get("stack", "both"))
                return self._json({"ok": True})
            if path == "/api/shape":
                r = STATE.shape(ip, body.get("down", 0), body.get("up", 0))
                return self._json({"ok": True, "result": r})
            if path == "/api/resume":
                STATE.resume(ip); return self._json({"ok": True})
            if path == "/api/level":
                lv = STATE.set_level(ip, body.get("level", 1)); return self._json({"ok": True, "level": lv})
            if path == "/api/verify":
                return self._json({"ok": True, "result": STATE.verify(ip)})
            if path == "/api/protect":
                return self._json(STATE.protect(bool(body.get("on"))))
            return self._json({"ok": False, "error": "unknown endpoint"}, 404)
        except Exception as e:
            return self._json({"ok": False, "error": f"{type(e).__name__}: {e}"}, 400)

    def _static(self, path):
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        root = WEB.resolve()
        target = (root / rel).resolve()
        if root != target and root not in target.parents:  # path-traversal guard
            return self._send(403, b"forbidden", "text/plain")
        if not target.is_file():
            return self._send(404, b"not found", "text/plain")
        ctype = MIME.get(target.suffix.lower(), "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)


def find_port(start=8733):
    import socket
    for p in range(start, start + 40):
        with socket.socket() as s:
            try:
                s.bind((HOST, p))
                return p
            except OSError:
                continue
    return start


def main():
    global STATE
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if os.name == "nt":
        os.system("")
    STATE = State()
    port = find_port()
    httpd = ThreadingHTTPServer((HOST, port), Handler)
    url = f"http://{HOST}:{port}/"

    print(netcut.col("\n  net_tree / NetCut dashboard", "c", "b"))
    print(f"  Serving at {netcut.col(url, 'g')}  (local only)")
    if not netcut.SCAPY_OK:
        print(netcut.col("  scapy/Npcap missing - scanning works, cutting will not.", "y"))
    if not netcut.is_admin():
        print(netcut.col("  Not Administrator - cutting/protecting will fail. Relaunch as admin.", "y"))
    print(netcut.col("  Close this window (or Ctrl-C) to stop the server and resume all cuts.\n", "dim"))

    STATE.scan()  # kick off a first scan immediately
    threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        print(netcut.col("\n  Resuming all cuts and shutting down ...", "g"))
        STATE.shutdown()
        httpd.shutdown()


if __name__ == "__main__":
    main()
