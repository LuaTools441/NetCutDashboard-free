#!/usr/bin/env python3
"""
net_tree.py - map and inspect the devices on YOUR OWN local network.

Usage:
    python net_tree.py                      # interactive menu
    python net_tree.py 192.168.1.0/24       # scan that subnet, print the tree, then open the menu
    python net_tree.py 192.168.1.0/24 --no-menu
    python net_tree.py --deep 192.168.1.1   # scan your network, then deep-inspect one device

Uses only the Python standard library (no pip installs, no Npcap needed).
Only scan networks you own or are allowed to scan.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import html
import ipaddress
import json
import os
import platform
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

import mini_nmap
import netcut

IS_WIN = platform.system() == "Windows"
HERE = Path(__file__).resolve().parent
VENDOR_CACHE = HERE / "vendors_cache.json"
REPORTS_DIR = HERE / "reports"

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
if IS_WIN:
    os.system("")  # enables ANSI colours in the Windows console

_C = {"r": "\033[0m", "b": "\033[1m", "dim": "\033[2m", "g": "\033[32m", "y": "\033[33m",
      "c": "\033[36m", "red": "\033[31m", "m": "\033[35m"}


def col(text, *styles):
    return "".join(_C[s] for s in styles) + str(text) + _C["r"]


def run(cmd, timeout=15):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
        return (p.stdout or "") + (p.stderr or "")
    except Exception:
        return ""


# ----------------------------------------------------------------------------- data

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    135: "MS-RPC (Windows)", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB (file sharing)",
    548: "AFP (Mac file sharing)", 554: "RTSP (camera/stream)", 631: "IPP (printer)", 1080: "SOCKS proxy",
    1883: "MQTT (IoT)", 2049: "NFS", 3306: "MySQL", 3389: "RDP (Remote Desktop)", 5000: "UPnP / Synology",
    5001: "Synology HTTPS", 5432: "PostgreSQL", 5555: "ADB (Android debug)", 5900: "VNC",
    6668: "Tuya IoT", 7000: "AirPlay", 7547: "TR-069 (ISP remote mgmt)", 8000: "HTTP-alt",
    8008: "Chromecast / Google", 8009: "Chromecast / Google", 8080: "HTTP-alt", 8081: "HTTP-alt",
    8443: "HTTPS-alt", 8888: "HTTP-alt", 9000: "HTTP-alt", 9100: "Printer (RAW)",
    9999: "TP-Link smart plug", 32400: "Plex", 49152: "UPnP", 62078: "Apple iPhone/iPad sync",
}
HTTP_PORTS = {80, 5000, 7000, 8000, 8008, 8080, 8081, 8888, 9000, 32400, 49152}
HTTPS_PORTS = {443, 5001, 8443}
BANNER_PORTS = {21, 22, 23, 25, 110, 143, 3306, 5900}
# Checked on every device during the normal scan: each one strongly hints at what the device is.
QUICK_PORTS = [62078, 5555, 548, 7000, 445, 135, 3389, 9100, 631, 554, 8009]


@dataclass
class Device:
    ip: str
    mac: str = ""
    vendor: str = ""
    random_mac: bool = False
    ttl: int | None = None
    answers_ping: bool = False
    hostname: str = ""
    netbios: str = ""
    workgroup: str = ""
    mdns: str = ""
    upnp: dict = field(default_factory=dict)
    ssdp_server: str = ""
    open_ports: dict = field(default_factory=dict)  # port -> banner / info
    os_guess: str = ""
    kind: str = ""
    is_gateway: bool = False
    is_me: bool = False
    deep_scanned: bool = False

    def name(self):
        for n in (self.upnp.get("friendlyName"), self.mdns, self.netbios, self.hostname):
            if n:
                return n
        return ""

    def sort_key(self):
        return ipaddress.ip_address(self.ip)


# ----------------------------------------------------------------------------- local network info

def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # no packet is sent; just picks the outgoing interface
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def default_gateway():
    if IS_WIN:
        out = run(["route", "print", "-4", "0.0.0.0"])
        m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)
    else:
        out = run(["ip", "route", "show", "default"])
        m = re.search(r"via (\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def interface_details(ip):
    """Return (prefix_length, own_mac) for the interface holding `ip`."""
    prefix, mac = 24, ""
    if IS_WIN:
        ps = (f"$a = Get-NetIPAddress -IPAddress {ip} -ErrorAction SilentlyContinue | Select-Object -First 1; "
              "if ($a) { $a.PrefixLength; (Get-NetAdapter -InterfaceIndex $a.InterfaceIndex).MacAddress }")
        out = run(["powershell", "-NoProfile", "-Command", ps]).split()
        if out and out[0].isdigit():
            prefix = int(out[0])
        if len(out) > 1:
            mac = norm_mac(out[1])
    else:
        out = run(["ip", "-o", "-4", "addr", "show"])
        m = re.search(rf"inet {re.escape(ip)}/(\d+)", out)
        if m:
            prefix = int(m.group(1))
            iface = out[:m.start()].rsplit("\n", 1)[-1].split()[1]
            try:
                mac = norm_mac(Path(f"/sys/class/net/{iface}/address").read_text().strip())
            except Exception:
                pass
    return prefix, mac


# ----------------------------------------------------------------------------- discovery primitives

def norm_mac(mac):
    mac = re.sub(r"[^0-9a-fA-F]", "", mac or "").upper()
    return ":".join(mac[i:i + 2] for i in range(0, 12, 2)) if len(mac) == 12 else ""


def ping(ip, timeout_ms=700):
    cmd = (["ping", "-n", "1", "-w", str(timeout_ms), ip] if IS_WIN
           else ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip])
    m = re.search(r"ttl[=:]\s*(\d+)", run(cmd, timeout=5), re.I)
    return int(m.group(1)) if m else None


def arp_table():
    """ip -> mac, from the OS neighbour cache (filled by the ping sweep)."""
    out = run(["arp", "-a"]) + ("" if IS_WIN else run(["ip", "neigh"]))
    table = {}
    for line in out.splitlines():
        ipm = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        macm = re.search(r"([0-9a-fA-F]{1,2}(?:[-:][0-9a-fA-F]{1,2}){5})", line)
        if not (ipm and macm):
            continue
        mac = norm_mac(":".join(p.zfill(2) for p in re.split(r"[-:]", macm.group(1))))
        if not mac or mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00") or mac.startswith(("01:00:5E", "33:33")):
            continue
        table[ipm.group(1)] = mac
    return table


def mac_is_random(mac):
    return bool(mac) and (int(mac[1], 16) & 0x2) != 0  # "locally administered" bit


class Vendors:
    """MAC vendor lookup. Only the first 3 bytes (manufacturer prefix) are sent online; results are cached."""

    def __init__(self):
        try:
            self.cache = json.loads(VENDOR_CACHE.read_text(encoding="utf-8"))
        except Exception:
            self.cache = {}
        self.last = 0.0
        self.online = True

    def lookup(self, mac):
        if not mac:
            return ""
        if mac_is_random(mac):
            return "Private/random MAC"
        oui = mac[:8]
        if oui in self.cache:
            return self.cache[oui]
        if not self.online:
            return ""
        time.sleep(max(0.0, 1.1 - (time.time() - self.last)))  # free API allows ~1 request/second
        self.last = time.time()
        vendor = None
        try:
            req = urllib.request.Request(f"https://api.macvendors.com/{oui}", headers={"User-Agent": "net_tree"})
            with urllib.request.urlopen(req, timeout=5) as r:
                vendor = r.read().decode("utf-8", "replace").strip()
        except urllib.error.HTTPError as e:
            vendor = "Unknown" if e.code == 404 else None
        except Exception:
            self.online = False  # no internet; stop trying for this run
        if vendor is not None:
            self.cache[oui] = vendor
            try:
                VENDOR_CACHE.write_text(json.dumps(self.cache, indent=1, sort_keys=True), encoding="utf-8")
            except Exception:
                pass
        return vendor or ""


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def netbios_info(ip, timeout=1.0):
    """NetBIOS node-status query (what `nbtstat -A` does). Windows PCs, NAS boxes, Samba servers answer."""
    try:
        tid = random.randint(0, 0xFFFF)
        raw_name = b"*" + b"\x00" * 15
        enc = bytes(b for c in raw_name for b in (0x41 + (c >> 4), 0x41 + (c & 0xF)))
        pkt = struct.pack(">HHHHHH", tid, 0, 1, 0, 0, 0) + b"\x20" + enc + b"\x00" + struct.pack(">HH", 0x21, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(pkt, (ip, 137))
            data, _ = s.recvfrom(4096)
        num, off, names = data[56], 57, []
        for _ in range(num):
            if off + 18 > len(data):
                break
            nm = data[off:off + 15].decode("ascii", "replace").strip()
            suffix, flags = data[off + 15], struct.unpack(">H", data[off + 16:off + 18])[0]
            names.append((nm, suffix, bool(flags & 0x8000)))
            off += 18
        host = next((n for n, s_, g in names if s_ == 0 and not g), "")
        group = next((n for n, s_, g in names if s_ == 0 and g), "")
        return host, group
    except Exception:
        return "", ""


def _dns_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\x00"


def _dns_read_name(data, off):
    labels, end, hops = [], None, 0
    while True:
        hops += 1
        if hops > 100 or off >= len(data):
            raise ValueError("bad name")
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((ln & 0x3F) << 8) | data[off + 1]
            continue
        labels.append(data[off + 1:off + 1 + ln].decode("utf-8", "replace"))
        off += 1 + ln
    return ".".join(labels), (end if end is not None else off)


def mdns_name(ip, timeout=1.0):
    """Ask the device itself (mDNS / Bonjour) for its .local name. iPhones, Macs, Androids, printers answer."""
    try:
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        q = struct.pack(">HHHHHH", random.randint(1, 0xFFFF), 0, 1, 0, 0, 0) + _dns_name(rev) + struct.pack(">HH", 12, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(q, (ip, 5353))
            data, _ = s.recvfrom(4096)
        qd, an = struct.unpack(">HH", data[4:8])
        off = 12
        for _ in range(qd):
            _, off = _dns_read_name(data, off)
            off += 4
        for _ in range(an):
            _, off = _dns_read_name(data, off)
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype == 12:
                return _dns_read_name(data, off)[0].rstrip(".")
            off += rdlen
    except Exception:
        pass
    return ""


def ssdp_discover(my_ip, wait=3.0):
    """UPnP/SSDP multicast discovery. Smart TVs, routers, Chromecasts, consoles, NAS, printers answer."""
    found = {}
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
           "MX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(my_ip))
        except OSError:
            pass
        s.settimeout(0.5)
        for _ in range(2):
            s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + wait
        while time.time() < end:
            try:
                data, (src, _) = s.recvfrom(8192)
            except socket.timeout:
                continue
            headers = {}
            for line in data.decode("utf-8", "replace").split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            entry = found.setdefault(src, {"server": "", "locations": set()})
            entry["server"] = entry["server"] or headers.get("server", "")
            if headers.get("location"):
                entry["locations"].add(headers["location"])
        s.close()
    except Exception:
        pass
    return found


def upnp_describe(url, timeout=3):
    """Download a UPnP device description XML and pull the useful fields out of it."""
    want = ("friendlyName", "manufacturer", "modelName", "modelNumber", "modelDescription",
            "deviceType", "serialNumber", "presentationURL", "manufacturerURL")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "net_tree"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            root = ET.fromstring(r.read(200_000))
        info = {}
        for el in root.iter():
            tag = el.tag.split("}")[-1]
            if tag in want and tag not in info and el.text and el.text.strip():
                info[tag] = el.text.strip()
        return info
    except Exception:
        return {}


# ----------------------------------------------------------------------------- deep probing

def port_open(ip, port, timeout=0.6):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def http_info(ip, port, tls):
    try:
        sock = socket.create_connection((ip, port), timeout=3)
        tls_ver = ""
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock)
            tls_ver = sock.version() or ""
        sock.settimeout(3)
        sock.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: net_tree\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while len(data) < 65536:
            try:
                chunk = sock.recv(8192)
            except Exception:
                break
            if not chunk:
                break
            data += chunk
        sock.close()
        text = data.decode("utf-8", "replace")
        head, _, body = text.partition("\r\n\r\n")
        parts = []
        status = head.split("\r\n", 1)[0]
        if status:
            parts.append(status.replace("HTTP/1.1 ", "").replace("HTTP/1.0 ", ""))
        for hname in ("Server", "X-Powered-By", "WWW-Authenticate", "Location"):
            m = re.search(rf"^{hname}:\s*(.+)$", head, re.I | re.M)
            if m:
                parts.append(f"{hname}: {m.group(1).strip()[:80]}")
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if m and m.group(1).strip():
            parts.append("Title: " + re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()[:80])
        if tls_ver:
            parts.append(tls_ver)
        return " | ".join(parts)
    except Exception as e:
        return f"(no HTTP answer: {type(e).__name__})"


def raw_banner(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            s.settimeout(2)
            data = s.recv(512)
        line = data.decode("utf-8", "replace").strip().splitlines()
        return re.sub(r"[^\x20-\x7e]", "", line[0])[:100] if line else ""
    except Exception:
        return ""


def port_detail(ip, port):
    if port in HTTP_PORTS:
        return http_info(ip, port, tls=False)
    if port in HTTPS_PORTS:
        return http_info(ip, port, tls=True)
    if port in BANNER_PORTS:
        return raw_banner(ip, port)
    return ""


def classify(d: Device):
    ports = set(int(p) for p in d.open_ports)
    v = (d.vendor or "").lower()
    up = " ".join(d.upnp.values()).lower()
    names = " ".join([d.name(), d.hostname, d.mdns, d.ssdp_server, *map(str, d.open_ports.values())]).lower()
    blob = " ".join([v, up, names])

    # operating system
    os_ = ""
    if 62078 in ports or "iphone" in blob or "ipad" in blob:
        os_ = "Apple iOS / iPadOS"
    elif 548 in ports or "macbook" in blob or "imac" in blob:
        os_ = "Apple macOS"
    elif 5555 in ports or "android" in blob or "galaxy" in blob:
        os_ = "Android"
    elif ports & {135, 3389} or (445 in ports and d.ttl and 65 <= d.ttl <= 128):
        os_ = "Windows"
    elif d.ttl:
        os_ = ("Linux / Android / iOS / macOS (TTL 64)" if d.ttl <= 64 else
               "Windows (TTL 128)" if d.ttl <= 128 else "Network device / embedded (TTL 255)")

    # device type
    kind = ""
    if d.is_me:
        kind = "This PC"
    elif d.is_gateway or "internetgatewaydevice" in up:
        kind = "Router / gateway"
    elif ports & {9100, 631} or "printer" in blob:
        kind = "Printer"
    elif 554 in ports or "camera" in blob or "hikvision" in v or "dahua" in v:
        kind = "IP camera"
    elif ports & {8008, 8009} or "chromecast" in blob or "google cast" in blob:
        kind = "Chromecast / Google TV / smart speaker"
    elif "mediarenderer" in up or re.search(r"\btv\b|television|bravia|webos|tizen|roku", blob):
        kind = "Smart TV / media player"
    elif "playstation" in blob or "xbox" in blob or "nintendo" in blob:
        kind = "Game console"
    elif "synology" in blob or "qnap" in blob or "nas" in names:
        kind = "NAS / storage"
    elif "raspberry" in v:
        kind = "Raspberry Pi"
    elif re.search(r"espressif|tuya|shelly|sonoff|broadlink|xiaomi|yeelight|tp-link.*plug", blob) or ports & {1883, 6668, 9999}:
        kind = "Smart home / IoT"
    elif 62078 in ports:
        kind = "iPhone / iPad (most likely)"
    elif os_.startswith(("Apple iOS", "Android")):
        kind = "Phone / tablet"
    elif d.random_mac:
        kind = "Phone / tablet / laptop (private MAC)"
    elif os_ == "Windows" or os_ == "Apple macOS":
        kind = "Computer"
    d.os_guess, d.kind = os_, kind or "Unknown"


# ----------------------------------------------------------------------------- the network map

class NetMap:
    def __init__(self):
        self.my_ip = local_ip()
        self.gateway = default_gateway()
        prefix, self.my_mac = interface_details(self.my_ip)
        self.my_network = ipaddress.ip_network(f"{self.my_ip}/{prefix}", strict=False)
        self.network: ipaddress.IPv4Network | None = None
        self.devices: dict[str, Device] = {}
        self.vendors = Vendors()
        self.ssdp: dict = {}
        self.scanned_at = ""

    # ---- full network scan
    def scan(self, network: ipaddress.IPv4Network):
        hosts = [str(h) for h in network.hosts()]
        if not hosts:
            print(col("No host addresses in that network.", "red"))
            return
        t0 = time.time()
        print(col(f"\n[1/5] Pinging {len(hosts)} addresses in {network} ...", "c"))
        ttls = {}
        with cf.ThreadPoolExecutor(min(128, len(hosts))) as ex:
            futs = {ex.submit(ping, ip): ip for ip in hosts}
            for i, f in enumerate(cf.as_completed(futs), 1):
                ttl = f.result()
                if ttl is not None:
                    ttls[futs[f]] = ttl
                if i % 16 == 0 or i == len(hosts):
                    print(f"\r      {i}/{len(hosts)} checked, {len(ttls)} answered", end="", flush=True)
        print()

        print(col("[2/5] Reading ARP table (finds devices that block ping) + UPnP discovery ...", "c"))
        with cf.ThreadPoolExecutor(1) as ex:
            ssdp_f = ex.submit(ssdp_discover, self.my_ip)
            arp = {ip: mac for ip, mac in arp_table().items() if ipaddress.ip_address(ip) in network}
            self.ssdp = ssdp_f.result()

        alive = set(ttls) | set(arp) | {ip for ip in self.ssdp if ipaddress.ip_address(ip) in network}
        if ipaddress.ip_address(self.my_ip) in network:
            alive.add(self.my_ip)
        alive.discard(str(network.network_address))
        alive.discard(str(network.broadcast_address))

        old = self.devices if self.network == network else {}
        devices = {}
        for ip in alive:
            d = old.get(ip) or Device(ip=ip)
            d.ttl = ttls.get(ip, d.ttl)
            d.answers_ping = ip in ttls
            d.mac = arp.get(ip) or d.mac
            d.is_me = ip == self.my_ip
            d.is_gateway = ip == self.gateway
            if d.is_me:
                d.mac = self.my_mac or d.mac
                d.hostname = d.hostname or socket.gethostname()
            d.random_mac = mac_is_random(d.mac)
            devices[ip] = d
        self.devices = dict(sorted(devices.items(), key=lambda kv: kv[1].sort_key()))
        self.network = network

        print(col(f"[3/5] Asking {len(self.devices)} devices for their names (DNS / NetBIOS / mDNS) ...", "c"))
        self._lookup_names(list(self.devices.values()))

        print(col("[4/5] Looking up manufacturers from MAC addresses ...", "c"))
        todo = [d for d in self.devices.values() if d.mac and not d.vendor]
        for i, d in enumerate(todo, 1):
            print(f"\r      {i}/{len(todo)}", end="", flush=True)
            d.vendor = self.vendors.lookup(d.mac)
        if todo:
            print()
        if not self.vendors.online:
            print(col("      (no internet - vendor names only from cache)", "dim"))

        print(col("[5/5] Reading UPnP descriptions + quick fingerprint ports (62078 = iPhone, 5555 = Android ...) ...", "c"))
        self._apply_ssdp()
        self._quick_ports([d for d in self.devices.values() if not d.is_me and not d.deep_scanned])
        for d in self.devices.values():
            classify(d)
        self.scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(col(f"Done in {time.time() - t0:.1f}s - {len(self.devices)} devices found.\n", "g", "b"))

    def _lookup_names(self, devs):
        ex = cf.ThreadPoolExecutor(64)
        jobs = {}
        for d in devs:
            jobs[ex.submit(reverse_dns, d.ip)] = (d, "dns")
            jobs[ex.submit(netbios_info, d.ip)] = (d, "nb")
            jobs[ex.submit(mdns_name, d.ip)] = (d, "mdns")
        done, _ = cf.wait(jobs, timeout=8)
        for f in done:
            d, kind = jobs[f]
            res = f.result()
            if kind == "dns" and res and res != d.ip:
                d.hostname = res
            elif kind == "nb" and res[0]:
                d.netbios, d.workgroup = res
            elif kind == "mdns" and res:
                d.mdns = res
        ex.shutdown(wait=False, cancel_futures=True)

    def _quick_ports(self, devs):
        for d in devs:
            d.open_ports = {}
        # Pass 2 retries silent devices more slowly: sleeping phones (iPhones especially) need a
        # moment to wake their Wi-Fi, so the first connection attempt often times out.
        for timeout in (0.8, 2.0):
            pairs = [(d, p) for d in devs for p in QUICK_PORTS]
            if not pairs:
                break
            with cf.ThreadPoolExecutor(128) as ex:
                results = list(ex.map(lambda dp: port_open(dp[0].ip, dp[1], timeout=timeout), pairs))
            for (d, p), ok in zip(pairs, results):
                if ok:
                    d.open_ports[p] = ""
            devs = [d for d in devs if not d.open_ports]

    def _apply_ssdp(self):
        jobs = {}
        with cf.ThreadPoolExecutor(16) as ex:
            for ip, entry in self.ssdp.items():
                d = self.devices.get(ip)
                if not d:
                    continue
                d.ssdp_server = entry["server"]
                for loc in sorted(entry["locations"]):
                    if urllib.parse.urlparse(loc).hostname == ip:  # only fetch from the device itself
                        jobs[ex.submit(upnp_describe, loc)] = d
            for f in cf.as_completed(jobs):
                info = f.result()
                d = jobs[f]
                # prefer the "root" description (the one with a friendlyName we don't have yet)
                for k, val in info.items():
                    d.upnp.setdefault(k, val)

    # ---- one device, as much info as possible
    def deep(self, ip, extended=False):
        d = self.devices.get(ip)
        if not d:
            d = Device(ip=ip)
            self.devices[ip] = d
            self.devices = dict(sorted(self.devices.items(), key=lambda kv: kv[1].sort_key()))
        print(col(f"\nDeep scan of {ip} ...", "c"))
        d.ttl = ping(ip) or d.ttl
        d.answers_ping = d.ttl is not None
        if not d.mac:
            d.mac = arp_table().get(ip, "")
        d.random_mac = mac_is_random(d.mac)
        d.is_gateway, d.is_me = ip == self.gateway, ip == self.my_ip
        if d.mac and not d.vendor:
            d.vendor = self.vendors.lookup(d.mac)
        self._lookup_names([d])

        ports = set(COMMON_PORTS)
        if extended:
            ports |= set(range(1, 1025))
        print(f"  scanning {len(ports)} TCP ports ...")
        with cf.ThreadPoolExecutor(200) as ex:
            res = dict(zip(sorted(ports), ex.map(lambda p: port_open(ip, p), sorted(ports))))
        open_ports = [p for p, ok in res.items() if ok]
        print(f"  {len(open_ports)} open - reading banners ...")
        with cf.ThreadPoolExecutor(16) as ex:
            details = dict(zip(open_ports, ex.map(lambda p: port_detail(ip, p), open_ports)))
        d.open_ports = {p: details[p] for p in open_ports}

        if ip in self.ssdp:
            self._apply_ssdp()
        classify(d)
        d.deep_scanned = True
        return d


# ----------------------------------------------------------------------------- output

def device_line(i, d: Device):
    tag = col(" (this PC)", "g") if d.is_me else col(" (router)", "y") if d.is_gateway else ""
    name = f"{(d.name() or '-')[:26]:<26}"  # pad before colouring, or escape codes break the columns
    if not d.name():
        name = col(name, "dim")
    vendor = d.vendor or ""
    ping_note = "" if d.answers_ping or d.is_me else col(" [no ping]", "dim")
    deep = col(" *", "m") if d.deep_scanned else ""
    return (f"{col(f'[{i:>2}]', 'dim')} {col(f'{d.ip:<15}', 'b')} {name} "
            f"{vendor[:24]:<24} {d.kind}{tag}{ping_note}{deep}")


def print_tree(nm: NetMap):
    if not nm.devices:
        print(col("No scan yet - choose 1 or 2 first.", "y"))
        return
    devs = list(nm.devices.values())
    gw = nm.devices.get(nm.gateway)
    print(col("Internet", "c", "b"))
    if gw:
        print(f"└── {col('ROUTER', 'y', 'b')} {device_line(devs.index(gw) + 1, gw)}")
        prefix = "    "
    else:
        print(f"└── {col(str(nm.network), 'c')}")
        prefix = "    "
    children = [d for d in devs if d is not gw]
    for n, d in enumerate(children):
        branch = "└──" if n == len(children) - 1 else "├──"
        print(f"{prefix}{branch} {device_line(devs.index(d) + 1, d)}")
    print(col(f"\n{len(devs)} devices  |  [no ping] = blocks ping but seen in ARP  |  * = deep-scanned", "dim"))


def print_device(d: Device):
    def row(label, value):
        if value not in (None, "", {}, []):
            print(f"  {col(f'{label:<22}', 'c')} {value}")

    print(col(f"\n══════ {d.ip}  {d.name()} ══════", "b"))
    row("Type", d.kind)
    row("OS guess", d.os_guess)
    row("MAC", d.mac + ("  (randomised / private address)" if d.random_mac else ""))
    row("Manufacturer", d.vendor)
    row("DNS name", d.hostname)
    row("NetBIOS name", d.netbios)
    row("Workgroup", d.workgroup)
    row("mDNS name", d.mdns)
    row("Ping TTL", d.ttl if d.answers_ping else "no reply (firewall)")
    row("UPnP server", d.ssdp_server)
    for k in ("friendlyName", "manufacturer", "modelName", "modelNumber", "modelDescription",
              "deviceType", "serialNumber", "presentationURL"):
        row(f"UPnP {k}", d.upnp.get(k))
    if d.deep_scanned:
        if d.open_ports:
            print(f"  {col('Open ports', 'c')}")
            for p, info in d.open_ports.items():
                svc = COMMON_PORTS.get(int(p), "")
                print(f"    {col(f'{p:>5}/tcp', 'g')}  {svc:<26} {col(info, 'dim')}")
        else:
            print(f"  {col('Open ports', 'c')}       none found (device firewall blocks everything)")
    else:
        if d.open_ports:
            quick = ", ".join(f"{p} {COMMON_PORTS.get(int(p), '')}" for p in d.open_ports)
            row("Quick ports", quick)
        print(col("  (choose 'Deep info' to scan all ports and grab banners)", "dim"))


def export(nm: NetMap):
    REPORTS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    data = {"network": str(nm.network), "scanned_at": nm.scanned_at, "this_pc": nm.my_ip,
            "gateway": nm.gateway, "devices": [asdict(d) for d in nm.devices.values()]}
    jpath = REPORTS_DIR / f"net_tree_{stamp}.json"
    jpath.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    e = html.escape
    cards = []
    for d in nm.devices.values():
        rows = [("Type", d.kind), ("OS guess", d.os_guess), ("MAC", d.mac), ("Manufacturer", d.vendor),
                ("DNS", d.hostname), ("NetBIOS", d.netbios), ("mDNS", d.mdns),
                ("Ping TTL", d.ttl if d.answers_ping else "no reply"), ("UPnP server", d.ssdp_server)]
        rows += [(f"UPnP {k}", v) for k, v in d.upnp.items()]
        rows += [(f"Port {p} {COMMON_PORTS.get(int(p), '')}", info or "open") for p, info in d.open_ports.items()]
        body = "".join(f"<tr><th>{e(str(k))}</th><td>{e(str(v))}</td></tr>" for k, v in rows if v not in ("", None))
        cls = "gw" if d.is_gateway else "me" if d.is_me else ""
        badge = " · router" if d.is_gateway else " · this PC" if d.is_me else ""
        cards.append(f'<details class="card {cls}"{" open" if d.is_gateway else ""}><summary><b>{e(d.ip)}</b>'
                     f'<span>{e(d.name() or "—")}</span><i>{e(d.kind)}{badge}</i></summary><table>{body}</table></details>')
    page = f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Map</title><style>
:root{{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--mut:#6b7385;--line:#e3e6ec;--acc:#2f6fed;--gw:#e8a317;--me:#1f9d55}}
@media (prefers-color-scheme:dark){{:root{{--bg:#12151b;--card:#1b1f27;--fg:#e6e9ef;--mut:#8d95a6;--line:#2a303b}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,Segoe UI,sans-serif;padding:24px 16px}}
.wrap{{max-width:900px;margin:auto}} h1{{margin:0 0 4px;font-size:24px}} .sub{{color:var(--mut);margin-bottom:20px}}
.card{{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--acc);border-radius:10px;margin:8px 0;overflow:hidden}}
.card.gw{{border-left-color:var(--gw)}} .card.me{{border-left-color:var(--me)}}
summary{{cursor:pointer;padding:12px 14px;display:flex;gap:14px;flex-wrap:wrap;align-items:baseline}}
summary b{{min-width:120px;font-variant-numeric:tabular-nums}} summary i{{color:var(--mut);font-style:normal;margin-left:auto}}
table{{width:100%;border-collapse:collapse;font-size:14px}} th,td{{text-align:left;padding:6px 14px;border-top:1px solid var(--line);vertical-align:top}}
th{{color:var(--mut);font-weight:500;width:34%}} td{{word-break:break-word}}
</style></head><body><div class="wrap"><h1>Network map — {e(str(nm.network))}</h1>
<div class="sub">Scanned {e(nm.scanned_at)} · {len(nm.devices)} devices · router {e(str(nm.gateway))} · this PC {e(nm.my_ip)}</div>
{''.join(cards)}</div></body></html>"""
    hpath = REPORTS_DIR / f"net_tree_{stamp}.html"
    hpath.write_text(page, encoding="utf-8")
    print(col(f"Saved:\n  {hpath}\n  {jpath}", "g"))
    try:
        webbrowser.open(hpath.as_uri())
    except Exception:
        pass


# ----------------------------------------------------------------------------- menu

def ask(prompt):
    try:
        return input(col(prompt, "b")).replace("﻿", "").strip()
    except EOFError:
        return "0"


def parse_network(text):
    text = text.strip()
    if "/" not in text:
        text += "/24"
    net = ipaddress.ip_network(text, strict=False)
    if net.version != 4:
        raise ValueError("only IPv4 is supported")
    if not net.is_private:
        raise ValueError(f"{net} is not a private (LAN) range - this tool only maps local networks")
    if net.num_addresses > 4096:
        raise ValueError(f"{net} has {net.num_addresses} addresses - use /20 or smaller")
    return net


def pick_device(nm: NetMap):
    if not nm.devices:
        print(col("No scan yet - choose 1 or 2 first.", "y"))
        return None
    for i, d in enumerate(nm.devices.values(), 1):
        print(device_line(i, d))
    choice = ask("\nDevice number or IP: ")
    devs = list(nm.devices.values())
    if choice.isdigit() and 1 <= int(choice) <= len(devs):
        return devs[int(choice) - 1].ip
    try:
        ipaddress.ip_address(choice)
        return choice
    except ValueError:
        print(col("Not a valid choice.", "red"))
        return None


def nmap_scan(nm: NetMap):
    """Menu 7: run our mini_nmap (-sV) on one device or all of them."""
    if not nm.devices:
        print(col("No scan yet - choose 1 or 2 first.", "y"))
        return
    devs = list(nm.devices.values())
    for i, d in enumerate(devs, 1):
        print(device_line(i, d))
    choice = ask("\nDevice number, IP, or 'all': ").lower()
    if choice == "all":
        targets = [d.ip for d in devs if not d.is_me]
    elif choice.isdigit() and 1 <= int(choice) <= len(devs):
        targets = [devs[int(choice) - 1].ip]
    else:
        ipaddress.ip_address(choice)  # raises ValueError on junk
        targets = [choice]
    spec = ask("Ports [Enter = top 113 | 1-1024 | - = all 65535 | e.g. 22,80,8000-8100]: ")
    ports = mini_nmap.parse_ports(spec)

    t0, hosts, out = time.time(), [], [mini_nmap.header()]
    print(col(out[0], "c"))
    for ip in targets:
        d = nm.devices.get(ip) or Device(ip=ip)
        nm.devices.setdefault(ip, d)
        if len(targets) > 1:
            print(col(f"\n>>> {ip} {d.name()}", "b"))
        h = mini_nmap.scan_host(ip, ports, True, hostname=d.name(), mac=d.mac, vendor=d.vendor)
        hosts.append(h)
        report = mini_nmap.format_report(h)
        out += ["", report]
        print()
        for line in report.splitlines():  # light colouring of the nmap-style table
            if re.match(r"^\d+/tcp", line):
                print(col(line, "g"))
            elif line.startswith("|"):
                print(col(line, "dim"))
            else:
                print(line)
        if h.up:
            d.open_ports = {p.port: " ".join(x for x in (p.display_service(), p.version_str()) if x) for p in h.ports}
            d.deep_scanned = True
            classify(d)
    out += ["", mini_nmap.footer(hosts, time.time() - t0)]
    print("\n" + col(out[-1], "c"))
    REPORTS_DIR.mkdir(exist_ok=True)
    name = targets[0] if len(targets) == 1 else "all"
    path = REPORTS_DIR / f"nmap_{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(col(f"Saved: {path}", "dim"))


def _netcut_cleanup(nm: NetMap):
    """Heal every cut and drop protection - must run before the program exits."""
    mgr = getattr(nm, "_nc_mgr", None)
    if mgr and mgr.cuts:
        print(col("\nResuming all cut devices before exit ...", "g"))
        mgr.stop_all(do_heal=True)
    if mgr:
        mgr.stop_services()
    prot = getattr(nm, "_nc_prot", None)
    if prot:
        prot.shutdown()


def _nc_env(nm: NetMap):
    env = getattr(nm, "_nc_env", None)
    if env is None:
        env = netcut.Env.detect(prefix=nm.my_network.prefixlen)
        # reuse the gateway MAC net_tree already learned, if netcut couldn't resolve it
        if not env.gateway_mac:
            gw = nm.devices.get(nm.gateway)
            if gw and gw.mac:
                env.gateway_mac = gw.mac
        nm._nc_env = env
    return env


def netcut_menu(nm: NetMap):
    """Menu 8: NetCut-style cut / resume / protect. Cuts run in background threads."""
    if not netcut.SCAPY_OK:
        print(netcut.INSTALL_HELP)
        print(col(f"\nimport error: {netcut.SCAPY_ERR}", "dim"))
        return
    env = _nc_env(nm)
    mgr = getattr(nm, "_nc_mgr", None) or netcut.CutManager(env)
    nm._nc_mgr = mgr
    netcut.preflight(env)
    admin = netcut.is_admin()
    if not admin:
        print(col("\nYou are NOT running as Administrator - cutting/protecting will fail.", "red", "b"))
        print(col("Close this and run:  right-click PowerShell -> Run as administrator,  then start net_tree again.", "y"))
    if not env.gateway_mac:
        print(col("Gateway MAC unknown - run option 1 (scan) first, or run as admin.", "y"))

    def resolve(tok):
        """A device number from the list, or a raw IP -> (ip, mac). None on junk."""
        devs = list(nm.devices.values())
        if tok.isdigit() and 1 <= int(tok) <= len(devs):
            d = devs[int(tok) - 1]
            return d.ip, d.mac
        try:
            ipaddress.ip_address(tok)
            d = nm.devices.get(tok)
            return tok, (d.mac if d else "")
        except ValueError:
            return None

    def start_cut(ip, mac, mode, throttle="medium"):
        try:
            cut = mgr.start(ip, mac or "", mode=mode, throttle=throttle)
            d = nm.devices.get(ip)
            if d:
                d.open_ports[netcut.BOGUS_HINT] = "weak-wifi" if mode == "throttle" else "cut"
            if mode == "throttle":
                print(col(f"  WEAK-WIFI  {ip}  ({cut.mac}) - {throttle} throttle, laggy but not fully dead.", "y", "b"))
            else:
                print(col(f"  CUT        {ip}  ({cut.mac}) - dropping it off the internet.", "red", "b"))
            return cut
        except Exception as e:
            print(col(f"  cannot hit {ip}: {e}", "y"))
            return None

    def do_resume(ip):
        if mgr.stop_cut(ip, do_heal=True):
            d = nm.devices.get(ip)
            if d:
                d.open_ports.pop(netcut.BOGUS_HINT, None)
            print(col(f"  RESUME {ip} - back online.", "g"))

    def do_verify(ip):
        if not mgr.is_cut(ip):
            print(col(f"  {ip} is not being cut.", "dim")); return
        print(col(f"  Watching {ip} for 4s to confirm the cut ...", "c"))
        v = mgr.verify(ip, window=4)
        if not v:
            return
        if v["intercepting"]:
            print(col(f"  CONFIRMED: {ip} has no internet - we are intercepting its traffic "
                      f"({v['intercepted_total']} frames caught, level {v['level']}).", "g", "b"))
        else:
            print(col(f"  {ip}: no internet traffic captured. It is idle, OR still connected.", "y"))
            print(col(f"     (escape attempts seen: {v['escapes_now']}. If it stays online, press "
                      f"'l {ip} 3' to hit it harder, or it auto-escalates.)", "dim"))

    while True:
        devs = list(nm.devices.values())
        cuts = {c[0]: c for c in mgr.status()}  # ip -> (ip,mac,secs,sent,mode,level,intercepted,escapes)
        print(col("\n┌──────────────── NetCut ────────────────┐", "m"))
        print(f"  Active: {col(len(cuts), 'red', 'b') if cuts else '0'}   "
              f"Protection: {col('ON', 'g') if getattr(nm, '_nc_prot', None) else 'off'}   "
              f"Admin: {col('yes', 'g') if admin else col('NO', 'red')}")
        print(col("└─────────────────────────────────────────┘", "m"))
        if devs:
            for i, d in enumerate(devs, 1):
                st = cuts.get(d.ip)
                if st:
                    _, _, secs, sent, mode, level, inter, esc = st
                    if mode == "shape":
                        mgr.sample_rates()
                        cc = mgr.get(d.ip)
                        dl = f"{cc.down_mbps:g}" if cc.down_mbps else "∞"
                        ul = f"{cc.up_mbps:g}" if cc.up_mbps else "∞"
                        tag = col("  ⇅ LIMIT", "y", "b") + col(
                            f"  [↓{cc.down_rate:.1f}/{dl} ↑{cc.up_rate:.1f}/{ul} Mbps]", "dim")
                    else:
                        verdict = col("has NO internet", "g") if inter else col("no traffic yet", "y")
                        tag = (col(f"  ✖ CUT L{level}", "red", "b") if mode == "full"
                               else col("  ~ WEAK-WIFI", "y", "b"))
                        tag += col(f"  [{verdict}{col('', 'r')}, {inter} caught]", "dim")
                else:
                    tag = ""
                lock = col("  (you)", "g") if d.is_me else col("  (router)", "y") if d.is_gateway else ""
                print(f"{col(f'[{i:>2}]', 'dim')} {col(f'{d.ip:<15}', 'b')} "
                      f"{(d.name() or '-')[:22]:<22} {(d.vendor or '')[:20]:<20}{lock}{tag}")
        else:
            print(col("  (no devices yet - run option 1 to scan first, or type an IP)", "dim"))
        print(col("\n  N / IP = cut (toggle)   w N = weak wifi   sp N = limit Mbps   mon N = watch traffic", "dim"))
        print(col("  st N ipv4|ipv6|both = pick pipe    tr N = show traffic    v N = verify   l N 1..3 = level", "dim"))
        print(col("  red <from> <to> = DNS redirect (red- <from> removes, red = list)    p = protect   s = status", "dim"))
        print(col("  all / resume    b = back", "dim"))
        raw = ask("netcut> ")
        parts = raw.split()
        c = parts[0].lower() if parts else ""

        if c in ("b", "0", ""):
            return
        elif c == "all":
            for d in devs:
                if not d.is_me and not d.is_gateway and not mgr.is_cut(d.ip):
                    start_cut(d.ip, d.mac, "full")
        elif c == "resume":
            for ip in list(cuts):
                do_resume(ip)
            print(col("  All devices resumed.", "g", "b"))
        elif c == "w":
            t = resolve(parts[1]) if len(parts) > 1 else None
            if t:
                s = ask("  strength [light/medium/heavy, Enter=medium]: ").lower() or "medium"
                if s not in netcut.THROTTLE:
                    s = "medium"
                if mgr.is_cut(t[0]):
                    mgr.set_mode(t[0], "throttle", s)
                    d = nm.devices.get(t[0])
                    if d:
                        d.open_ports[netcut.BOGUS_HINT] = "weak-wifi"
                    print(col(f"  {t[0]} switched to weak-wifi ({s}).", "y"))
                else:
                    start_cut(t[0], t[1], "throttle", s)
            else:
                print(col("  Usage: w <device number or IP>", "red"))
        elif c == "st":
            t = resolve(parts[1]) if len(parts) > 1 else None
            stack = parts[2].lower() if len(parts) > 2 else ""
            if t and stack in ("ipv4", "ipv6", "both"):
                if mgr.set_stack(t[0], stack):
                    print(col(f"  {t[0]} now blocking {stack}.", "y"))
                else:
                    print(col(f"  {t[0]} is not being cut — cut it first.", "dim"))
            else:
                print(col("  Usage: st <device> <ipv4|ipv6|both>", "red"))
        elif c == "mon":
            t = resolve(parts[1]) if len(parts) > 1 else None
            if t:
                try:
                    mgr.start(t[0], t[1], mode="monitor")
                    d = nm.devices.get(t[0])
                    if d:
                        d.open_ports[netcut.BOGUS_HINT] = "watching"
                    print(col(f"  Watching {t[0]} — it stays online. Use 'tr {parts[1]}' to see requests.", "g"))
                except Exception as e:
                    print(col(f"  cannot watch {t[0]}: {e}", "y"))
            else:
                print(col("  Usage: mon <device number or IP>", "red"))
        elif c == "tr":
            t = resolve(parts[1]) if len(parts) > 1 else None
            rows = mgr.top_traffic(t[0], 40) if t else []
            if not t:
                print(col("  Usage: tr <device number or IP>", "red"))
            elif not rows:
                print(col("  No requests logged yet (cut or watch it, then let it use the net).", "dim"))
            else:
                print(col(f"\n  Traffic for {t[0]}:", "c", "b"))
                for r in rows:
                    print(f"    {col(r['kind'].upper()[:4].ljust(4), 'dim')} "
                          f"{r['name'][:48]:<48} {col('x' + str(r['count']), 'y', 'b')}")
        elif c == "red":
            if len(parts) == 1:
                rules = mgr.list_rules()
                if not rules:
                    print(col("  No redirects. Usage: red <from-domain> <to>  (watch a device first)", "dim"))
                for r in rules:
                    print(f"    {col(r['from'], 'b')} → {col(r['url'] or r['ip'], 'c')} [{r['kind']}]")
            elif len(parts) >= 3:
                try:
                    r = mgr.set_rule(parts[1], parts[2])
                    print(col(f"  {parts[1]} → {r['url'] or r['ip']} ({r['kind']})", "y", "b"))
                except Exception as e:
                    print(col(f"  {e}", "y"))
            else:
                print(col("  Usage: red <from-domain> <to-domain/IP/URL>", "red"))
        elif c == "red-":
            if len(parts) >= 2:
                mgr.remove_rule(parts[1]); print(col(f"  removed {parts[1]}", "y"))
            else:
                print(col("  Usage: red- <from-domain>", "red"))
        elif c == "sp":
            t = resolve(parts[1]) if len(parts) > 1 else None
            if t:
                try:
                    dn = float(ask("  download limit Mbps [0 = unlimited]: ") or "0")
                    up = float(ask("  upload limit Mbps [0 = unlimited]: ") or "0")
                    if mgr.is_cut(t[0]):
                        mgr.set_shape(t[0], dn, up)
                    else:
                        mgr.start(t[0], t[1], mode="shape", down_mbps=dn, up_mbps=up)
                    d = nm.devices.get(t[0])
                    if d:
                        d.open_ports[netcut.BOGUS_HINT] = "shaped"
                    print(col(f"  {t[0]} limited to {dn or '∞'} Mbps down / {up or '∞'} Mbps up.", "y", "b"))
                except Exception as e:
                    print(col(f"  cannot shape {t[0]}: {e}", "y"))
            else:
                print(col("  Usage: sp <device number or IP>", "red"))
        elif c == "v":
            t = resolve(parts[1]) if len(parts) > 1 else None
            do_verify(t[0]) if t else print(col("  Usage: v <device number or IP>", "red"))
        elif c == "l":
            t = resolve(parts[1]) if len(parts) > 1 else None
            if t and len(parts) > 2 and parts[2].isdigit():
                lv = mgr.set_level(t[0], int(parts[2]))
                print(col(f"  {t[0]} attack level set to {lv} (auto-escalation off)." if lv
                          else f"  {t[0]} is not being cut.", "y"))
            else:
                print(col("  Usage: l <device> <1|2|3>", "red"))
        elif c == "s":
            if cuts:
                for ip, mac, secs, sent, mode, level, inter, esc in cuts.values():
                    kind = f"weak-wifi" if mode == "throttle" else f"cut L{level}"
                    print(f"  {col('✖' if mode=='full' else '~', 'red' if mode=='full' else 'y')} "
                          f"{ip:<15} {mac}  {kind:<11} {secs}s  {sent} frames sent  "
                          f"{inter} intercepted  {esc} escape-attempts")
            else:
                print(col("  Nothing is being cut.", "dim"))
        elif c == "p":
            prot = getattr(nm, "_nc_prot", None)
            if prot:
                prot.shutdown()
                nm._nc_prot = None
                print(col("  Protection OFF - static ARP entry removed.", "y"))
            else:
                prot = netcut.Protector(env)
                ok, msg = prot.pin_gateway()
                print(col("  " + msg, "g" if ok else "y"))
                prot.start_watch()
                nm._nc_prot = prot
                print(col("  Protection ON - gateway pinned, watching for ARP spoofing.", "g", "b"))
        else:
            t = resolve(c)
            if not t:
                print(col("  Not a valid choice.", "red"))
            elif mgr.is_cut(t[0]):
                do_resume(t[0])
            else:
                start_cut(t[0], t[1], "full")


def menu(nm: NetMap):
    while True:
        net_txt = str(nm.network) if nm.network else "not scanned yet"
        print(col("\n╔══════════════════ net_tree ══════════════════╗", "c"))
        print(f"  This PC: {nm.my_ip}   Router: {nm.gateway}   LAN: {nm.my_network}")
        print(f"  Current map: {net_txt}  ({len(nm.devices)} devices)")
        print(col("╚══════════════════════════════════════════════╝", "c"))
        print(f"  1) Scan my network ({nm.my_network})")
        print("  2) Scan a different subnet (e.g. 192.168.1.0/24)")
        print("  3) Show the network tree")
        print("  4) Deep info on one device (ports, banners, OS, model)")
        print("  5) Deep info on ALL devices")
        print("  6) Export report (HTML + JSON)")
        print("  7) Nmap-style scan (-sV): services & versions")
        print(col("  8) NetCut: cut / resume a device + protect yourself", "m"))
        print("  0) Exit")
        c = ask("> ")
        try:
            if c == "1":
                nm.scan(nm.my_network)
                print_tree(nm)
            elif c == "2":
                net = parse_network(ask("Subnet (e.g. 192.168.1.0/24): "))
                nm.scan(net)
                print_tree(nm)
            elif c == "3":
                print_tree(nm)
            elif c == "4":
                ip = pick_device(nm)
                if ip:
                    ext = ask("Also scan ports 1-1024? (slower) [y/N]: ").lower().startswith("y")
                    print_device(nm.deep(ip, extended=ext))
            elif c == "5":
                if not nm.devices:
                    print(col("No scan yet - choose 1 or 2 first.", "y"))
                    continue
                for ip in list(nm.devices):
                    print_device(nm.deep(ip))
            elif c == "6":
                if nm.devices:
                    export(nm)
                else:
                    print(col("No scan yet - choose 1 or 2 first.", "y"))
            elif c == "7":
                nmap_scan(nm)
            elif c == "8":
                netcut_menu(nm)
            elif c == "0":
                _netcut_cleanup(nm)
                return
        except ValueError as ex:
            print(col(f"Error: {ex}", "red"))
        except KeyboardInterrupt:
            print(col("\n(interrupted)", "y"))


def main():
    ap = argparse.ArgumentParser(description="Map and inspect devices on your local network.")
    ap.add_argument("subnet", nargs="?", help="private subnet to scan, e.g. 192.168.1.0/24")
    ap.add_argument("--deep", metavar="IP", help="deep-scan this device after the network scan")
    ap.add_argument("--extended", action="store_true", help="with --deep: also scan ports 1-1024")
    ap.add_argument("--no-menu", action="store_true", help="exit after scanning instead of opening the menu")
    ap.add_argument("--export", action="store_true", help="save an HTML + JSON report after scanning")
    args = ap.parse_args()

    nm = NetMap()
    try:
        if args.subnet or args.deep or args.no_menu or args.export:
            nm.scan(parse_network(args.subnet) if args.subnet else nm.my_network)
            print_tree(nm)
            if args.deep:
                print_device(nm.deep(args.deep, extended=args.extended))
            if args.export:
                export(nm)
        if not args.no_menu:
            menu(nm)
    except ValueError as ex:
        print(col(f"Error: {ex}", "red"))
        sys.exit(1)
    except KeyboardInterrupt:
        print(col("\nBye.", "dim"))
    finally:
        _netcut_cleanup(nm)  # never leave a device cut, whatever happened


if __name__ == "__main__":
    main()
