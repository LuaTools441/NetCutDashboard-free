#!/usr/bin/env python3
"""
mini_nmap.py - our own small nmap: TCP connect scan + service/version detection (-sV).

Usage:
    python mini_nmap.py 192.168.1.1                 # top ports, open/closed only
    python mini_nmap.py -sV 192.168.1.1             # + service & version detection
    python mini_nmap.py -sV -p 22,80,8000-8100 192.168.1.9
    python mini_nmap.py -sV -p- 192.168.1.9         # all 65535 ports
    python mini_nmap.py -sV 192.168.1.0/24          # every host in a (private) subnet

Standard library only. Also used by net_tree.py (menu option 7).

How -sV works here (same idea as nmap's service probes):
  * NULL probe   - connect and wait: SSH, FTP, SMTP, POP3, IMAP, VNC, MySQL, telnet talk first
  * TLS probe    - try a TLS handshake, read the certificate, then speak HTTP inside it
  * HTTP probe   - GET /, read Server header, title, auth realm, redirects
  * special probes for ports where a protocol-specific question reveals more:
      445 SMB (NTLM: Windows version, computer name, domain), 3389 RDP, 53 DNS version.bind,
      5555 ADB (Android model), 62078 Apple lockdownd, 7000 AirPlay (/info), 8008 Chromecast,
      554 RTSP, 6379 Redis
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import html
import ipaddress
import json
import os
import platform
import plistlib
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

VERSION = "1.0"
IS_WIN = platform.system() == "Windows"

TOP_PORTS = sorted({
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144,
    179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990,
    993, 995, 1025, 1026, 1027, 1028, 1029, 1080, 1110, 1433, 1720, 1723, 1755, 1883, 1900, 2000, 2001,
    2049, 2121, 2717, 2869, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5001, 5009, 5051, 5060, 5101,
    5190, 5357, 5432, 5555, 5631, 5666, 5800, 5900, 6000, 6001, 6379, 6646, 6668, 7000, 7070, 7547,
    8000, 8008, 8009, 8080, 8081, 8443, 8554, 8888, 9000, 9100, 9999, 10000, 32400, 32768, 49152,
    49153, 49154, 49155, 49156, 49157, 62078,
})

NMAP_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 81: "http", 88: "kerberos-sec",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 515: "printer", 548: "afp", 554: "rtsp", 587: "submission",
    631: "ipp", 993: "imaps", 995: "pop3s", 1883: "mqtt", 1900: "upnp", 2869: "icslap", 3306: "mysql",
    3389: "ms-wbt-server", 5000: "upnp", 5001: "commplex-link", 5357: "wsdapi", 5432: "postgresql",
    5555: "adb", 5900: "vnc", 6466: "androidtv-remote", 6467: "androidtv-pairing", 6379: "redis", 6668: "tuya", 7000: "airplay", 7547: "cwmp", 8000: "http-alt",
    8008: "http", 8009: "ajp13", 8080: "http-proxy", 8081: "blackice-icecap", 8443: "https-alt",
    8554: "rtsp-alt", 8888: "sun-answerbook", 9100: "jetdirect", 9999: "abyss", 32400: "plex",
    49152: "unknown", 62078: "iphone-sync",
}

TLS_FIRST = {443, 465, 636, 853, 993, 995, 5001, 5986, 8443, 9443}
HTTP_FIRST = {80, 81, 591, 2869, 3000, 5000, 5357, 7080, 8000, 8008, 8080, 8081, 8088, 8888, 9000,
              10000, 32400, 49152, 49153, 49154, 49155, 49156, 49157}
NO_PROBE = {9100, 9101, 9102, 9103}  # like nmap: printers can print probe data as a page of junk


def service_name(port):
    if port in NMAP_NAMES:
        return NMAP_NAMES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


# ----------------------------------------------------------------------------- results

@dataclass
class PortResult:
    port: int
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extra: str = ""
    tunnel: str = ""                                # "ssl" when the service runs inside TLS
    scripts: list = field(default_factory=list)     # [(name, text)], text may contain \n
    os_hint: str = ""
    device_hint: str = ""

    def display_service(self):
        return (f"{self.tunnel}/" if self.tunnel else "") + (self.service or "unknown")

    def version_str(self):
        parts = [self.product, self.version, f"({self.extra})" if self.extra else ""]
        return " ".join(p for p in parts if p)


@dataclass
class HostResult:
    ip: str
    up: bool = False
    latency: float | None = None
    ports: list = field(default_factory=list)       # open PortResults
    scanned: int = 0
    not_shown_state: str = "closed"                 # closed | filtered | closed|filtered
    elapsed: float = 0.0
    hostname: str = ""
    mac: str = ""
    vendor: str = ""


# ----------------------------------------------------------------------------- socket helpers

def _tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    return ctx


def connect(ip, port, timeout=3.0, tls=False):
    s = socket.create_connection((ip, port), timeout=timeout)
    if tls:
        try:
            s = _tls_context().wrap_socket(s)
        except Exception:
            s.close()
            raise
    s.settimeout(timeout)
    return s


def recv_all(s, limit=65536, timeout=3.0, until=None):
    s.settimeout(timeout)
    data = b""
    while len(data) < limit:
        try:
            chunk = s.recv(8192)
        except (socket.timeout, TimeoutError, OSError):
            break
        if not chunk:
            break
        data += chunk
        if until and until(data):
            break
    return data


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def exchange(ip, port, payload=b"", timeout=3.0, tls=False, limit=65536, until=None):
    with closing(connect(ip, port, timeout, tls)) as s:
        if payload:
            s.sendall(payload)
        return recv_all(s, limit, timeout, until)


def port_state(ip, port, timeout):
    """'open' / 'closed' / 'filtered', plus the round-trip time when the host answered."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        s.connect((ip, port))
        state = "open"
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("hh" if IS_WIN else "ii", 1, 0))
    except ConnectionRefusedError:
        state = "closed"
    except OSError:
        state = "filtered"
    rtt = time.perf_counter() - t0
    s.close()
    return state, (rtt if state != "filtered" else None)


def ping(ip, timeout_ms=1000):
    cmd = (["ping", "-n", "1", "-w", str(timeout_ms), ip] if IS_WIN
           else ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip])
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=5).stdout
    except Exception:
        return False
    return bool(re.search(r"ttl[=:]\s*\d+", out, re.I))


def printable(data: bytes, n=80):
    return re.sub(r"[^\x20-\x7e]", ".", data[:n].decode("latin-1"))


# ----------------------------------------------------------------------------- HTTP

def http_request(ip, port, path="/", tls=False, timeout=3.0, method="GET", extra_headers=""):
    req = (f"{method} {path} HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: Mozilla/5.0 (mini_nmap)\r\n"
           f"Accept: */*\r\n{extra_headers}Connection: close\r\n\r\n").encode()
    return exchange(ip, port, req, timeout=timeout, tls=tls, limit=200_000)


def _dechunk(body: bytes):
    out, i = b"", 0
    while i < len(body):
        j = body.find(b"\r\n", i)
        if j < 0:
            break
        try:
            size = int(body[i:j].split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        out += body[j + 2:j + 2 + size]
        i = j + 2 + size + 2
    return out


def parse_http(raw: bytes):
    """-> (status_line, headers{lower: value}, title, body_bytes) or None."""
    if not raw.startswith((b"HTTP/", b"RTSP/")):
        return None
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.setdefault(k.strip().lower(), v.strip())
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = _dechunk(body)
    m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    title = ""
    if m:
        title = re.sub(r"\s+", " ", html.unescape(m.group(1).decode("utf-8", "replace"))).strip()[:100]
    return lines[0], headers, title, body


HTTP_SERVERS = [  # (regex on Server header, product, os)
    (r"Microsoft-IIS/([\d.]+)", "Microsoft IIS httpd", "Windows"),
    (r"Microsoft-HTTPAPI/([\d.]+)", "Microsoft HTTPAPI httpd", "Windows"),
    (r"Apache/([\d.]+)", "Apache httpd", ""),
    (r"nginx/([\d.]+)", "nginx", ""),
    (r"lighttpd/([\d.]+)", "lighttpd", ""),
    (r"mini_httpd/([\d.]+)", "mini_httpd", ""),
    (r"GoAhead-(?:Webs|http)/?([\d.]*)", "GoAhead WebServer", ""),
    (r"Boa/([\w.]+)", "Boa HTTPd", "Linux"),
    (r"uhttpd/?([\d.]*)", "uhttpd", "Linux"),
    (r"Jetty\(([\w.\-]+)\)", "Jetty", ""),
    (r"CUPS/([\d.]+)", "CUPS", ""),
    (r"AirTunes/([\w.]+)", "Apple AirTunes rtspd", ""),
    (r"Werkzeug/([\d.]+)", "Werkzeug httpd", ""),
]


def apply_server_header(r: PortResult, server: str):
    if not server:
        return
    for rx, product, os_ in HTTP_SERVERS:
        m = re.search(rx, server, re.I)
        if m:
            r.product, r.version = product, m.group(1)
            rest = server.replace(m.group(0), "").strip(" ,;")
            if rest:
                r.extra = rest.strip("()")
            r.os_hint = r.os_hint or os_ or _os_from_text(server)
            return
    # "Linux/4.19, UPnP/1.0, Portable SDK for UPnP devices/1.14.17"  (UPnP-style server strings)
    m = re.match(r"\s*([^/,]+)/([\w.\-]+),\s*UPnP/([\d.]+),\s*(.+?)/([\w.\-]+)\s*$", server)
    if m:
        r.product, r.version = m.group(4), m.group(5)
        r.extra = f"{m.group(1)} {m.group(2)}; UPnP {m.group(3)}"
        r.os_hint = r.os_hint or _os_from_text(m.group(1))
        return
    m = re.match(r"\s*([A-Za-z][\w\-. ]*?)/v?(\d[\w.\-]*)\s*(.*)", server)
    if m:
        r.product, r.version, r.extra = m.group(1), m.group(2), m.group(3).strip("() ")
    else:
        r.product = server[:60]
    r.os_hint = r.os_hint or _os_from_text(server)


def _os_from_text(text):
    t = text.lower()
    if "windows" in t or "win32" in t or "win64" in t or "microsoft" in t:
        return "Windows"
    if any(k in t for k in ("ubuntu", "debian", "centos", "fedora", "red hat", "linux", "openwrt", "raspbian")):
        return "Linux"
    if "darwin" in t or "mac os" in t or "macos" in t:
        return "macOS"
    if "freebsd" in t:
        return "FreeBSD"
    return ""


def describe_http(r: PortResult, parsed, tls_on=False):
    status, headers, title, _ = parsed
    r.service = "rtsp" if status.startswith("RTSP/") else "http"
    apply_server_header(r, headers.get("server", ""))
    if title:
        r.scripts.append(("http-title", title))
    if headers.get("server"):
        r.scripts.append(("http-server-header", headers["server"]))
    auth = headers.get("www-authenticate")
    if auth:
        r.scripts.append(("http-auth", f"{status.split(' ', 1)[-1]} - {auth[:100]}"))
    loc = headers.get("location")
    if loc:
        r.scripts.append(("http-redirect", loc[:120]))
    powered = headers.get("x-powered-by")
    if powered:
        r.scripts.append(("http-powered-by", powered[:80]))
        r.os_hint = r.os_hint or _os_from_text(powered)


# ----------------------------------------------------------------------------- generic probes

BANNER_SIGS = [  # (service, regex, product, version, extra, os)   $N = regex group N
    ("ssh", r"^SSH-([\d.]+)-OpenSSH_([\w.]+)[ -]*([^\r\n]*)", "OpenSSH", "$2", "$3; protocol $1", ""),
    ("ssh", r"^SSH-([\d.]+)-dropbear_([\w.]+)", "Dropbear sshd", "$2", "protocol $1", "Linux"),
    ("ssh", r"^SSH-([\d.]+)-([^\r\n]+)", "$2", "", "protocol $1", ""),
    ("ftp", r"^220[ -][^\r\n]*\(vsFTPd ([\w.]+)\)", "vsftpd", "$1", "", "Unix"),
    ("ftp", r"^220[ -][^\r\n]*ProFTPD ([\w.]+)", "ProFTPD", "$1", "", "Unix"),
    ("ftp", r"^220[ -][^\r\n]*FileZilla Server(?: version)? ?([\w.]*)", "FileZilla ftpd", "$1", "", "Windows"),
    ("ftp", r"^220[ -][^\r\n]*Pure-FTPd", "Pure-FTPd", "", "", ""),
    ("ftp", r"^220[ -]Microsoft FTP Service", "Microsoft ftpd", "", "", "Windows"),
    ("smtp", r"^220 [^\r\n]*ESMTP Postfix", "Postfix smtpd", "", "", "Linux"),
    ("smtp", r"^220 [^\r\n]*ESMTP Exim ([\w.]+)", "Exim smtpd", "$1", "", ""),
    ("smtp", r"^220 ([^\r\n]*E?SMTP[^\r\n]*)", "", "", "$1", ""),
    ("ftp", r"^220[ -]([^\r\n]*)", "", "", "$1", ""),
    ("pop3", r"^\+OK ([^\r\n]*)", "", "", "$1", ""),
    ("imap", r"^\* OK ([^\r\n]*)", "", "", "$1", ""),
    ("vnc", r"^RFB 0*(\d+)\.0*(\d+)", "VNC", "", "protocol $1.$2", ""),
    ("telnet", r"^\xff[\xfb-\xfe]", "", "", "", ""),
    ("http", r"^HTTP/1\.[01] ", "", "", "", ""),
]


def _fill(tpl, m):
    return re.sub(r"\$(\d)", lambda x: (m.group(int(x.group(1))) or ""), tpl).strip(" ;")


def match_banner(r: PortResult, data: bytes):
    text = data.decode("latin-1")
    # MySQL / MariaDB greeting: [3-byte len][seq][0x0a protocol][version\0]
    if len(data) > 6 and data[4] == 0x0A and data[3] == 0:
        ver = data[5:data.find(b"\0", 5)].decode("latin-1", "replace")
        if re.match(r"\d+\.\d+", ver):
            r.service = "mysql"
            if "mariadb" in ver.lower():
                r.product, r.version = "MariaDB", re.sub(r"-?MariaDB.*", "", ver, flags=re.I).split("-")[-1]
            else:
                r.product, r.version = "MySQL", ver
            return True
    for service, rx, prod, ver, extra, os_ in BANNER_SIGS:
        m = re.search(rx, text)
        if m:
            r.service, r.product, r.version, r.extra = service, _fill(prod, m), _fill(ver, m), _fill(extra, m)
            r.os_hint = r.os_hint or os_ or _os_from_text(text[:200])
            return True
    return False


def null_probe(ip, port, r, timeout):
    with closing(connect(ip, port, timeout)) as s:
        data = recv_all(s, 4096, timeout, until=lambda d: True)
    if not data:
        return False
    if match_banner(r, data):
        return True
    r.service = service_name(port)
    r.scripts.append(("banner", printable(data)))
    return True


def http_probe(ip, port, r, timeout, tls=False):
    raw = http_request(ip, port, tls=tls, timeout=timeout)
    parsed = parse_http(raw)
    if parsed:
        describe_http(r, parsed)
        return True
    if raw:
        if not match_banner(r, raw):
            r.service = service_name(port)
            r.scripts.append(("fingerprint", printable(raw)))
        return True
    return False


def tls_probe(ip, port, r, timeout):
    with closing(connect(ip, port, timeout, tls=True)) as s:
        der = s.getpeercert(binary_form=True)
        tls_ver, cipher = s.version(), (s.cipher() or ("",))[0]
    r.tunnel = "ssl"
    cert = cert_summary(der) if der else ""
    try:
        if not http_probe(ip, port, r, timeout, tls=True):
            r.service = service_name(port).replace("https", "http")
    except Exception:
        r.service = service_name(port)
    if r.service == "https":
        r.service = "http"
    # Google Cast devices carry a Widevine cert whose issuer names the exact hardware,
    # e.g. "Shenzhen SEI Robotics TV SEI800Y Amlogic AMLS905X4 Cast ICA"
    m = re.search(r"Issuer: .*commonName=(.+?) Cast ICA", cert)
    if m:
        r.product = r.product or "Google Cast"
        r.extra = r.extra or m.group(1).strip()
        r.device_hint = r.device_hint or "media device / TV"
    if port == 8009:
        r.service, r.product = "castv2", r.product or "Google Cast protocol"
        r.device_hint = r.device_hint or "media device / TV"
    if cert:
        r.scripts.append(("ssl-cert", cert))
    r.scripts.append(("ssl-info", f"{tls_ver}, {cipher}"))
    return True


def cert_summary(der):
    try:
        fd, path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
        try:
            d = ssl._ssl._test_decode_cert(path)  # CPython helper, decodes without verifying
        finally:
            os.remove(path)
    except Exception:
        return ""
    subj = ", ".join(f"{k}={v}" for rdn in d.get("subject", ()) for k, v in rdn)
    issuer = ", ".join(f"{k}={v}" for rdn in d.get("issuer", ()) for k, v in rdn)
    lines = [f"Subject: {subj or '-'}"]
    san = ", ".join(f"{t}:{v}" for t, v in d.get("subjectAltName", ()))
    if san:
        lines.append(f"Subject Alternative Name: {san[:150]}")
    lines.append(f"Issuer: {issuer or '-'}")
    lines.append(f"Not valid before: {d.get('notBefore', '?')}")
    lines.append(f"Not valid after:  {d.get('notAfter', '?')}")
    return "\n".join(lines)


# ----------------------------------------------------------------------------- special probes

def _der(tag, content):
    n = len(content)
    length = bytes([n]) if n < 128 else (b"\x81" + bytes([n]) if n < 256 else b"\x82" + struct.pack(">H", n))
    return bytes([tag]) + length + content


def _smb2_header(cmd, msg_id):
    return struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, 0, 0, cmd, 31, 0, 0, msg_id, 0, 0, 0, b"\0" * 16)


def _smb_send(s, payload):
    s.sendall(struct.pack(">I", len(payload)) + payload)
    length = struct.unpack(">I", recv_exact(s, 4))[0] & 0xFFFFFF
    return recv_exact(s, length)


def _windows_name(major, minor, build):
    if major == 10:
        return f"Windows 11 (build {build})" if build >= 22000 else f"Windows 10 / Server 2016-2022 (build {build})"
    return {(6, 3): "Windows 8.1 / Server 2012 R2", (6, 2): "Windows 8 / Server 2012",
            (6, 1): "Windows 7 / Server 2008 R2", (6, 0): "Windows Vista / Server 2008"}.get(
        (major, minor), f"Windows NT {major}.{minor}") + f" (build {build})"


def smb_probe(ip, port, r, timeout):
    """SMB2 NEGOTIATE + NTLM SESSION_SETUP (anonymous, never completes a login).
    The NTLM CHALLENGE the server sends back contains its OS version, computer name and domain."""
    dialects = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1"}
    with closing(connect(ip, port, timeout)) as s:
        neg = struct.pack("<HHHHI16sQ", 36, 4, 1, 0, 0, uuid.uuid4().bytes, 0) + struct.pack("<4H", 0x0202, 0x0210, 0x0300, 0x0302)
        resp = _smb_send(s, _smb2_header(0, 0) + neg)
        if resp[:4] != b"\xfeSMB":
            if resp[:4] == b"\xffSMB":
                r.service, r.product = "netbios-ssn" if port == 139 else "microsoft-ds", "SMBv1 only"
                return True
            return False
        body = resp[64:]
        sec_mode, dialect = struct.unpack("<HH", body[2:6])
        systime = struct.unpack("<Q", body[40:48])[0]
        r.service = "microsoft-ds" if port == 445 else "netbios-ssn"
        r.product = f"SMB {dialects.get(dialect, hex(dialect))}"
        r.scripts.append(("smb2-security-mode", "Message signing enabled and required" if sec_mode & 2
                          else "Message signing enabled but not required"))
        if systime:
            dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=systime / 10)
            r.scripts.append(("smb2-time", dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")))

        ntlm = (b"NTLMSSP\0" + struct.pack("<II", 1, 0xE2088297) + struct.pack("<HHI", 0, 0, 0) * 2
                + bytes([10, 0]) + struct.pack("<H", 19041) + b"\0\0\0\x0f")
        ntlm_oid, spnego_oid = bytes.fromhex("2b06010401823702020a"), bytes.fromhex("2b0601050502")
        token = _der(0x60, _der(0x06, spnego_oid) + _der(0xA0, _der(0x30,
                     _der(0xA0, _der(0x30, _der(0x06, ntlm_oid))) + _der(0xA2, _der(0x04, ntlm)))))
        setup = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 64 + 24, len(token), 0) + token
        resp = _smb_send(s, _smb2_header(1, 1) + setup)
    off, ln = struct.unpack("<HH", resp[64 + 4:64 + 8])
    blob = resp[off:off + ln]
    i = blob.find(b"NTLMSSP\0")
    if i < 0:
        return True
    ch = blob[i:]
    flags = struct.unpack("<I", ch[20:24])[0]
    ti_len, _, ti_off = struct.unpack("<HHI", ch[40:48])
    major = minor = build = 0
    # The 8-byte Version field only exists when NEGOTIATE_VERSION is set (Windows sets it, Samba doesn't)
    if flags & 0x02000000 and ti_off >= 56 and 5 <= ch[48] <= 10:
        major, minor, build = ch[48], ch[49], struct.unpack("<H", ch[50:52])[0]
    av, info, p = ch[ti_off:ti_off + ti_len], {}, 0
    names = {1: "NetBIOS computer name", 2: "NetBIOS domain name", 3: "DNS computer name",
             4: "DNS domain name", 5: "DNS tree name"}
    while p + 4 <= len(av):
        av_id, av_len = struct.unpack("<HH", av[p:p + 4])
        if av_id == 0:
            break
        if av_id in names:
            info[names[av_id]] = av[p + 4:p + 4 + av_len].decode("utf-16-le", "replace")
        p += 4 + av_len
    lines = [f"{k}: {v}" for k, v in info.items()]
    if major and build:
        os_name = _windows_name(major, minor, build)
        lines.append(f"Product version: {major}.{minor}.{build}  ->  {os_name}")
        r.os_hint, r.extra = "Windows", os_name
    else:
        lines.append("Product version: not sent (typical of Samba on Linux - routers, NAS, TV boxes)")
        r.product, r.os_hint = f"Samba smbd ({r.product})", "Linux/Unix"
    r.scripts.append(("smb-ntlm-info", "\n".join(lines) or "(no target info)"))
    return True


def rdp_probe(ip, port, r, timeout):
    req = bytes.fromhex("030000130ee000000000000100080003000000")
    data = exchange(ip, port, req, timeout=timeout, until=lambda d: len(d) >= 11)
    if len(data) < 11 or data[0] != 3 or data[5] != 0xD0:
        return False
    r.service, r.product, r.os_hint = "ms-wbt-server", "Microsoft Terminal Services", "Windows"
    if len(data) >= 19:
        if data[11] == 2:
            proto = struct.unpack("<I", data[15:19])[0]
            r.scripts.append(("rdp-security", {0: "standard RDP", 1: "TLS", 2: "CredSSP (NLA)",
                                               8: "RDSTLS"}.get(proto, hex(proto))))
        elif data[11] == 3:
            r.scripts.append(("rdp-security", f"negotiation failure code {data[15]}"))
    return True


def _dns_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\x00"


def _dns_skip_name(msg, off):
    while off < len(msg):
        ln = msg[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            return off + 2
        off += 1 + ln
    raise ValueError("bad name")


def dns_probe(ip, port, r, timeout):
    q = struct.pack(">HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0) + _dns_name("version.bind") + struct.pack(">HH", 16, 3)
    data = exchange(ip, port, struct.pack(">H", len(q)) + q, timeout=timeout,
                    until=lambda d: len(d) >= 2 and len(d) >= 2 + struct.unpack(">H", d[:2])[0])
    if len(data) < 14:
        return False
    msg = data[2:]
    r.service = "domain"
    qd, an = struct.unpack(">HH", msg[4:8])
    off = 12
    for _ in range(qd):
        off = _dns_skip_name(msg, off) + 4
    for _ in range(an):
        off = _dns_skip_name(msg, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        off += 10
        if rtype == 16 and rdlen:
            txt = msg[off + 1:off + 1 + msg[off]].decode("utf-8", "replace")
            m = re.match(r"([A-Za-z][\w ]*?)[- /]v?(\d[\w.\-]*)(.*)", txt)
            if txt.strip().lower() in ("", "unknown", "none"):
                r.scripts.append(("dns-nsid", f"bind.version: {txt} (hidden)"))
                return True
            if m:
                r.product, r.version, r.extra = m.group(1), m.group(2), m.group(3).strip(" -()")
            else:
                r.product = txt
            r.scripts.append(("dns-nsid", f"bind.version: {txt}"))
            return True
        off += rdlen
    r.scripts.append(("dns-nsid", "version.bind not disclosed"))
    return True


def adb_probe(ip, port, r, timeout):
    payload = b"host::\0"
    cnxn = 0x4E584E43
    hdr = struct.pack("<6I", cnxn, 0x01000001, 256 * 1024, len(payload), sum(payload), cnxn ^ 0xFFFFFFFF)
    data = exchange(ip, port, hdr + payload, timeout=timeout,
                    until=lambda d: len(d) >= 24 and len(d) >= 24 + struct.unpack("<I", d[12:16])[0])
    if len(data) < 24 or data[:4] not in (b"CNXN", b"AUTH", b"STLS"):
        return False
    r.service, r.product, r.os_hint, r.device_hint = "adb", "Android Debug Bridge", "Android", "phone/TV/box"
    if data[:4] == b"CNXN":
        banner = data[24:].decode("utf-8", "replace").strip("\0")
        props = dict(kv.split("=", 1) for kv in banner.split("::", 1)[-1].split(";") if "=" in kv)
        r.extra = "NO authentication - device fully open!"
        lines = [f"{k}: {v}" for k, v in props.items() if k.startswith("ro.")]
        r.scripts.append(("adb-info", "\n".join(lines) or banner[:150]))
        if props.get("ro.product.model"):
            r.extra = f"{props['ro.product.model']}; NO authentication!"
    elif data[:4] == b"STLS":
        r.extra = "TLS required (wireless debugging)"
    else:
        r.extra = "authentication required"
    return True


def lockdown_probe(ip, port, r, timeout):
    with closing(connect(ip, port, timeout)) as s:
        def req(d):
            body = plistlib.dumps(d)
            s.sendall(struct.pack(">I", len(body)) + body)
            ln = struct.unpack(">I", recv_exact(s, 4))[0]
            if ln > 1_000_000:
                raise ValueError("too big")
            return plistlib.loads(recv_exact(s, ln))

        r.service, r.product = "iphone-sync", "Apple iOS lockdownd"
        r.os_hint, r.device_hint = "iOS / iPadOS", "phone / tablet"
        try:
            resp = req({"Label": "mini_nmap", "Request": "QueryType"})
        except ConnectionError:
            # Over Wi-Fi iOS resets the connection for any computer it isn't paired with.
            # That instant reset on 62078 is itself the iPhone/iPad fingerprint.
            r.extra = "only answers paired computers"
            r.scripts.append(("lockdown-info", "connection reset right after the request - "
                                               "typical iPhone/iPad behaviour towards unpaired hosts"))
            return True
        if "lockdown" not in str(resp.get("Type", "")):
            return False
        try:
            v = req({"Label": "mini_nmap", "Request": "GetValue"})
            if isinstance(v.get("Value"), dict):
                keys = ("DeviceName", "ProductType", "ProductVersion", "BuildVersion", "DeviceClass", "ModelNumber")
                lines = [f"{k}: {v['Value'][k]}" for k in keys if k in v["Value"]]
                if lines:
                    r.scripts.append(("lockdown-info", "\n".join(lines)))
            elif v.get("Error"):
                r.scripts.append(("lockdown-info", f"device details refused ({v['Error']}) - phone is not paired with this PC"))
        except Exception:
            pass
    return True


def airplay_probe(ip, port, r, timeout):
    raw = http_request(ip, port, "/info", timeout=timeout, extra_headers="X-Apple-ProtocolVersion: 1\r\n")
    parsed = parse_http(raw)
    if not parsed:
        return False
    status, headers, _, body = parsed
    r.service = "airplay"
    apply_server_header(r, headers.get("server", ""))
    info = {}
    try:
        info = plistlib.loads(body) if body else {}
    except Exception:
        pass
    if isinstance(info, dict) and info:
        keys = ("name", "model", "manufacturer", "osBuildVersion", "sourceVersion", "deviceID", "macAddress")
        lines = [f"{k}: {info[k]}" for k in keys if k in info and not isinstance(info[k], (dict, list, bytes))]
        if lines:
            r.scripts.append(("airplay-info", "\n".join(lines)))
        if info.get("model"):
            r.extra = str(info["model"])
            model = str(info["model"]).lower()
            r.device_hint = ("phone / tablet" if model.startswith(("iphone", "ipad")) else
                             "Apple TV" if "appletv" in model else "Mac" if "mac" in model else r.device_hint)
            r.os_hint = r.os_hint or ("iOS / iPadOS" if model.startswith(("iphone", "ipad")) else
                                      "macOS" if "mac" in model else "")
    elif status:
        r.scripts.append(("airplay-info", status))
    if not r.product:
        r.product = "AirPlay receiver"
    return True


def eureka_probe(ip, port, r, timeout):
    raw = http_request(ip, port, "/setup/eureka_info?params=name,build_info,device_info", timeout=timeout)
    parsed = parse_http(raw)
    if not parsed or " 200" not in parsed[0]:
        return False
    try:
        j = json.loads(parsed[3].decode("utf-8", "replace"))
    except ValueError:
        return False
    r.service, r.product, r.device_hint = "http", "Google Cast (Chromecast) httpd", "media device / TV"
    dev, build = j.get("device_info", {}), j.get("build_info", {})
    lines = [f"name: {j.get('name')}" if j.get("name") else "",
             f"manufacturer: {dev.get('manufacturer')}" if dev.get("manufacturer") else "",
             f"model: {dev.get('model_name')}" if dev.get("model_name") else "",
             f"cast build: {build.get('cast_build_revision')}" if build.get("cast_build_revision") else "",
             f"system build: {build.get('system_build_number')}" if build.get("system_build_number") else ""]
    lines = [x for x in lines if x]
    if lines:
        r.scripts.append(("cast-info", "\n".join(lines)))
    if build.get("cast_build_revision"):
        r.version = build["cast_build_revision"]
    return True


def rtsp_probe(ip, port, r, timeout):
    raw = exchange(ip, port, f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: mini_nmap\r\n\r\n".encode(),
                   timeout=timeout, until=lambda d: b"\r\n\r\n" in d)
    parsed = parse_http(raw)
    if not parsed or not parsed[0].startswith("RTSP/"):
        return False
    r.service = "rtsp"
    apply_server_header(r, parsed[1].get("server", ""))
    if parsed[1].get("public"):
        r.scripts.append(("rtsp-methods", parsed[1]["public"]))
    r.device_hint = r.device_hint or "camera / media streamer"
    return True


def redis_probe(ip, port, r, timeout):
    data = exchange(ip, port, b"INFO server\r\n", timeout=timeout, until=lambda d: b"redis_version" in d or d.startswith(b"-"))
    if not data:
        return False
    text = data.decode("latin-1")
    if "redis_version" in text or text.startswith(("-NOAUTH", "-ERR", "-DENIED")):
        r.service, r.product = "redis", "Redis key-value store"
        m = re.search(r"redis_version:([\w.]+)", text)
        if m:
            r.version = m.group(1)
        m = re.search(r"os:([^\r\n]+)", text)
        if m:
            r.extra, r.os_hint = m.group(1), _os_from_text(m.group(1))
        if text.startswith("-"):
            r.extra = "authentication required"
        return True
    return False


SPECIAL = {
    445: smb_probe, 3389: rdp_probe, 53: dns_probe, 5555: adb_probe, 62078: lockdown_probe,
    7000: airplay_probe, 8008: eureka_probe, 554: rtsp_probe, 8554: rtsp_probe, 6379: redis_probe,
}


def detect(ip, port, timeout=3.0):
    r = PortResult(port, service=service_name(port))
    if port in NO_PROBE:
        r.scripts.append(("note", "not probed (printers may print the probe data)"))
        return r
    special = SPECIAL.get(port)
    if special:
        try:
            if special(ip, port, r, timeout):
                return r
        except Exception:
            pass
        r = PortResult(port, service=service_name(port))
    tls = lambda: tls_probe(ip, port, r, timeout)
    http = lambda: http_probe(ip, port, r, timeout)
    null = lambda: null_probe(ip, port, r, min(timeout, 2.5))
    order = [tls, http, null] if port in TLS_FIRST else [http, tls, null] if port in HTTP_FIRST else [null, http, tls]
    answered = False
    for probe in order:
        try:
            if probe():
                return r
            answered = True
        except Exception:
            continue
    r.service = (service_name(port) + "?") if answered else "tcpwrapped"
    return r


# ----------------------------------------------------------------------------- scanning

def parse_ports(spec):
    spec = (spec or "").strip()
    if spec in ("", "top"):
        return list(TOP_PORTS)
    if spec in ("-", "all"):
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a or 1), int(b or 65535) + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad or not ports:
        raise ValueError(f"bad port list: {spec}")
    return sorted(ports)


def scan_host(ip, ports, service_detection=True, progress=True, hostname="", mac="", vendor=""):
    t0 = time.time()
    h = HostResult(ip=ip, hostname=hostname, mac=mac, vendor=vendor, scanned=len(ports))
    pinged = ping(ip)          # also wakes sleeping phones before the port scan
    big = len(ports) > 2000
    timeout, threads = (0.7, 400) if big else (1.2, 200)

    states, rtts = {}, []

    def work(p):
        return p, port_state(ip, p, timeout)

    with cf.ThreadPoolExecutor(threads) as ex:
        for i, (p, (state, rtt)) in enumerate(ex.map(work, ports), 1):
            states[p] = state
            if rtt is not None:
                rtts.append(rtt)
            if progress and (i % max(1, len(ports) // 20) == 0 or i == len(ports)):
                n_open = sum(1 for s in states.values() if s == "open")
                print(f"\r  Connect scan: {i}/{len(ports)} ports ({i * 100 // len(ports)}%), {n_open} open",
                      end="", flush=True)
    if progress:
        print()

    open_ports = [p for p in ports if states[p] == "open"]
    # Windows takes ~2s to report a refused connection, so the fast pass can't tell closed from
    # filtered. Re-check a few non-open ports slowly to find out which one this host does.
    rest = [p for p in ports if states[p] != "open"]
    if rest:
        sample = rest[:: max(1, len(rest) // 4)][:4]
        with cf.ThreadPoolExecutor(4) as ex:
            slow = list(ex.map(lambda p: port_state(ip, p, 3.5), sample))
        if any(s == "closed" for s, _ in slow):
            h.not_shown_state = "closed"
            rtts += [t for s, t in slow if t is not None]
        elif all(s == "filtered" for s, _ in slow):
            h.not_shown_state = "filtered"
        else:
            h.not_shown_state = "closed|filtered"

    h.up = pinged or bool(open_ports) or h.not_shown_state == "closed"
    h.latency = min(rtts) if rtts else None

    if service_detection and open_ports:
        if progress:
            print(f"  Service detection on {len(open_ports)} open port(s) ...")
        with cf.ThreadPoolExecutor(16) as ex:
            h.ports = list(ex.map(lambda p: detect(ip, p), open_ports))
    else:
        h.ports = [PortResult(p, service=service_name(p)) for p in open_ports]
    h.elapsed = time.time() - t0
    return h


# ----------------------------------------------------------------------------- output

def format_report(h: HostResult, service_detection=True):
    L = [f"mini_nmap scan report for {h.ip}" + (f" ({h.hostname})" if h.hostname else "")]
    if not h.up:
        L.append("Host seems down or blocks everything (no ping reply, no TCP answer).")
    else:
        L.append("Host is up" + (f" ({h.latency:.4f}s latency)." if h.latency else "."))
    not_shown = h.scanned - len(h.ports)
    reason = {"closed": "conn-refused", "filtered": "no-response"}.get(h.not_shown_state, "no-response")
    if h.ports and not_shown:
        L.append(f"Not shown: {not_shown} {h.not_shown_state} tcp ports ({reason})")
    if h.ports:
        rows = [(f"{p.port}/tcp", "open", p.display_service(), p.version_str() if service_detection else "")
                for p in h.ports]
        w0 = max(4, *(len(r[0]) for r in rows)) + 1
        w2 = max(7, *(len(r[2]) for r in rows)) + 1
        L.append(f"{'PORT':<{w0}} STATE {'SERVICE':<{w2}}" + (" VERSION" if service_detection else ""))
        for p, row in zip(h.ports, rows):
            L.append(f"{row[0]:<{w0}} {row[1]:<5} {row[2]:<{w2}} {row[3]}".rstrip())
            lines = []
            for name, text in p.scripts:
                parts = str(text).split("\n")
                lines.append(f"{name}: {parts[0]}")
                lines += [f"  {x}" for x in parts[1:]]
            for i, line in enumerate(lines):
                L.append(("|_" if i == len(lines) - 1 else "| ") + line)
    elif h.up:
        L.append(f"All {h.scanned} scanned ports on {h.ip} are in ignored states.")
        L.append(f"Not shown: {h.scanned} {h.not_shown_state} tcp ports ({reason})")
    if h.mac:
        L.append(f"MAC Address: {h.mac}" + (f" ({h.vendor})" if h.vendor else ""))
    oses = [p.os_hint for p in h.ports if p.os_hint]
    devices = [p.device_hint for p in h.ports if p.device_hint]
    info = []
    if oses:
        info.append("OS: " + max(set(oses), key=oses.count))
    if devices:
        info.append("Device: " + max(set(devices), key=devices.count))
    if info and service_detection:
        L.append("Service Info: " + "; ".join(info))
    return "\n".join(L)


def header():
    return f"Starting mini_nmap {VERSION} at {datetime.now().strftime('%Y-%m-%d %H:%M')}"


def footer(hosts, elapsed, service_detection=True):
    up = sum(1 for h in hosts if h.up)
    pre = "Service detection performed. " if service_detection else ""
    return (f"{pre}mini_nmap done: {len(hosts)} IP address{'es' if len(hosts) != 1 else ''} "
            f"({up} host{'s' if up != 1 else ''} up) scanned in {elapsed:.2f} seconds")


# ----------------------------------------------------------------------------- CLI

def expand_targets(target):
    if "/" in target:
        net = ipaddress.ip_network(target, strict=False)
        if not net.is_private:
            raise ValueError("subnet scans are limited to private (LAN) ranges")
        if net.num_addresses > 4096:
            raise ValueError("subnet too large (max /20)")
        return [str(h) for h in net.hosts()]
    return [socket.gethostbyname(target)]


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="mini_nmap - TCP connect scan with service/version detection")
    ap.add_argument("targets", nargs="+", help="IP, hostname or private subnet (e.g. 192.168.1.0/24)")
    ap.add_argument("-sV", dest="sV", action="store_true", help="probe open ports to determine service/version")
    ap.add_argument("-p", dest="ports", default="", help="ports: 22,80,8000-8100 | - (all 65535) | default: top ports")
    ap.add_argument("-F", dest="fast", action="store_true", help="fast: top ports (default)")
    ap.add_argument("--open", action="store_true", help="only list hosts that have open ports")
    args = ap.parse_args()

    ports = parse_ports(args.ports)
    targets = [t for spec in args.targets for t in expand_targets(spec)]
    print(header())
    arp, vendors = {}, None
    try:
        import net_tree  # optional: MAC + vendor like nmap's "MAC Address:" line
        arp, vendors = net_tree.arp_table(), net_tree.Vendors()
    except Exception:
        pass

    t0 = time.time()
    hosts = []
    multi = len(targets) > 1
    for ip in targets:
        if multi and not ping(ip, 600) and ip not in arp:
            hosts.append(HostResult(ip=ip))
            continue
        mac = arp.get(ip, "")
        try:
            vendor = vendors.lookup(mac) if (vendors and mac) else ""
        except Exception:
            vendor = ""
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            name = ""
        h = scan_host(ip, ports, args.sV, progress=not multi, hostname=name, mac=mac, vendor=vendor)
        hosts.append(h)
        if args.open and not h.ports:
            continue
        print()
        print(format_report(h, args.sV))
    print()
    print(footer(hosts, time.time() - t0, args.sV))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
