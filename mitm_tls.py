#!/usr/bin/env python3
"""
mitm_tls.py - HTTPS interception for netcut's serve/redirect, so it works on https sites.

How it works (same idea as mitmproxy / Fiddler / a corporate proxy):
  * A local root CA is generated once (ca/netcut-ca.crt + .key).
  * The user installs that CA on their phone, once, as a trusted certificate.
  * When a DNS-spoofed device connects to us on 443, we read the TLS SNI (the hostname), mint a
    certificate for that exact host signed by our CA on the fly, finish the handshake, and serve
    our page / 302 redirect. Because the phone trusts our CA, there is no warning.

Only use this on your own devices/network. Intercepting someone else's HTTPS is wiretapping.
Requires the `cryptography` package.
"""
from __future__ import annotations

import datetime
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    CRYPTO_OK = True
    CRYPTO_ERR = ""
except Exception as e:  # pragma: no cover
    CRYPTO_OK = False
    CRYPTO_ERR = f"{type(e).__name__}: {e}"

_UTC = datetime.timezone.utc


def _now():
    return datetime.datetime.now(_UTC)


def ensure_ca(ca_dir: Path):
    """Load the local CA, generating it on first use. Returns (cert, key, pem_bytes)."""
    ca_dir.mkdir(parents=True, exist_ok=True)
    crt_p, key_p = ca_dir / "netcut-ca.crt", ca_dir / "netcut-ca.key"
    if crt_p.exists() and key_p.exists():
        cert = x509.load_pem_x509_certificate(crt_p.read_bytes())
        key = serialization.load_pem_private_key(key_p.read_bytes(), None)
        return cert, key, crt_p.read_bytes()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "NetCut Local CA"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetCut")])
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_now() - datetime.timedelta(days=1))
            .not_valid_after(_now() + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         key_encipherment=False, content_commitment=False,
                                         data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(ski, critical=False)
            .sign(key, hashes.SHA256()))
    crt_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                      serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return cert, key, crt_p.read_bytes()


def make_leaf(hostname, ca_cert, ca_key, out: Path):
    """Mint a cert for `hostname` signed by the CA; write cert+key to `out`. Returns the path."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname[:64])])
    try:
        san = x509.SubjectAlternativeName([x509.DNSName(hostname)])
    except Exception:
        san = x509.SubjectAlternativeName([x509.DNSName("invalid.local")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_now() - datetime.timedelta(days=1))
            .not_valid_after(_now() + datetime.timedelta(days=397))
            .add_extension(san, critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=False,
                                         crl_sign=False, content_commitment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .sign(ca_key, hashes.SHA256()))
    out.write_bytes(cert.public_bytes(serialization.Encoding.PEM) +
                    key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.TraditionalOpenSSL,
                                      serialization.NoEncryption()))
    return out


class TlsServer:
    """HTTPS server on :443 that mints a cert per SNI host and serves the same serve/redirect rules."""

    def __init__(self, ca_dir: Path):
        self.ca_dir = ca_dir
        self.leaf_dir = ca_dir / "leaf"
        self.rules = {}                 # host(lower) -> rule dict {kind, url, html}
        self.httpd = None
        self.thread = None
        self._ctx_cache = {}
        self._lock = threading.Lock()
        self.ca_cert = self.ca_key = self.ca_pem = None

    def _lookup(self, host):
        host = (host or "").split(":")[0].lower()
        return self.rules.get(host) or next(
            (r for d, r in self.rules.items() if host.endswith("." + d)), None)

    def _ctx_for(self, host):
        with self._lock:
            ctx = self._ctx_cache.get(host)
            if ctx:
                return ctx
            path = make_leaf(host, self.ca_cert, self.ca_key, self.leaf_dir / (host[:60] + ".pem"))
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(path))
            self._ctx_cache[host] = ctx
            return ctx

    def start(self):
        if not CRYPTO_OK:
            return False
        self.leaf_dir.mkdir(parents=True, exist_ok=True)
        self.ca_cert, self.ca_key, self.ca_pem = ensure_ca(self.ca_dir)
        default = self._ctx_for("netcut.local")

        def sni(sslsock, servername, sslctx):
            if servername:
                try:
                    sslsock.context = self._ctx_for(servername)
                except Exception:
                    pass
        default.sni_callback = sni
        owner = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _handle(self):
                rule = owner._lookup(self.headers.get("Host", ""))
                if rule and rule.get("kind") == "serve":
                    body = (rule.get("html") or "").encode("utf-8", "replace")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                elif rule and rule.get("url"):
                    self.send_response(302)
                    self.send_header("Location", rule["url"])
                    body = b""
                else:
                    self.send_response(404)
                    body = b""
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD" and body:
                    self.wfile.write(body)

            do_GET = do_HEAD = do_POST = _handle

        try:
            self.httpd = ThreadingHTTPServer(("0.0.0.0", 443), H)
            self.httpd.socket = default.wrap_socket(self.httpd.socket, server_side=True)
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
