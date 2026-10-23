"""Host-observation relay for the mandatory real-binary Trivy acceptance gate (FEATURE-002-D design).

Runs in the `tvx-obs` container (NET_ADMIN; attached to the `--internal` network and the default bridge):

* DNS server (UDP and TCP 53) on the internal address: logs every query `(window, client, qname, qtype)`
  and answers A queries with its own internal address, AAAA (and every other type) with NODATA;
* TLS relay on :443: reads the ClientHello SNI without terminating TLS, logs `(window, client, sni)`,
  refuses names on the refuse list (RST) and splices allowed connections to the real `sni:443`
  resolved through the container's own upstream resolver on the bridge;
* catch-all on :9999 for every other TCP port (iptables REDIRECT), logging the original port
  (SO_ORIGINAL_DST) and closing;
* iptables INPUT LOG/ACCEPT counters for non-DNS UDP on the internal interface;
* control socket (`/run/obs.sock`, container-local only): `ctl reset|dump|refuse HOST...`.

Never part of the toolkit payload (scripts/tests is excluded). Never run by the default test suite.
"""

from __future__ import annotations

import json
import os
import select
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time

CTL = "/run/obs.sock"
SO_ORIGINAL_DST = 80
STATE = {"window": 0, "dns": [], "sni": [], "catchall": [], "refuse": set()}
LOCK = threading.Lock()


# --------------------------------------------------------------------------- pure helpers (offline-testable)
def parse_sni(hello: bytes) -> str | None:
    """Server name of a TLS ClientHello record, or None."""
    try:
        if len(hello) < 5 or hello[0] != 0x16:
            return None
        pos = 5 + 4 + 2 + 32  # record header, handshake header, version, random
        sid = hello[pos]
        pos += 1 + sid
        suites = struct.unpack("!H", hello[pos : pos + 2])[0]
        pos += 2 + suites
        comp = hello[pos]
        pos += 1 + comp
        end = pos + 2 + struct.unpack("!H", hello[pos : pos + 2])[0]
        pos += 2
        while pos + 4 <= end:
            ext, size = struct.unpack("!HH", hello[pos : pos + 4])
            pos += 4
            if ext == 0:
                name_len = struct.unpack("!H", hello[pos + 3 : pos + 5])[0]
                return hello[pos + 5 : pos + 5 + name_len].decode("ascii").lower().rstrip(".")
            pos += size
    except (IndexError, struct.error, UnicodeDecodeError):
        return None
    return None


def parse_query(packet: bytes) -> tuple[int, str, int, int]:
    """(id, qname, qtype, end of question) of a DNS query."""
    qid = struct.unpack("!H", packet[:2])[0]
    pos, labels = 12, []
    while packet[pos]:
        size = packet[pos]
        labels.append(packet[pos + 1 : pos + 1 + size].decode("ascii", "replace"))
        pos += 1 + size
    qtype = struct.unpack("!H", packet[pos + 1 : pos + 3])[0]
    return qid, ".".join(labels).lower().rstrip("."), qtype, pos + 5


def dns_answer(packet: bytes, address: str) -> bytes:
    """A → `address` (TTL 1); any other type → NODATA (NOERROR, no answer)."""
    qid, _, qtype, end = parse_query(packet)
    question = packet[12:end]
    if qtype == 1:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4) + socket.inet_aton(address)
        return struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + question + answer
    return struct.pack("!HHHHHH", qid, 0x8180, 1, 0, 0, 0) + question


# --------------------------------------------------------------------------- servers
def _log(kind: str, **entry) -> None:
    with LOCK:
        STATE[kind].append({"window": STATE["window"], "t": round(time.time(), 3), **entry})


def dns_udp(address: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, 53))
    while True:
        data, client = sock.recvfrom(4096)
        try:
            _, name, qtype, _ = parse_query(data)
            _log("dns", client=client[0], qname=name, qtype=qtype, proto="udp")
            sock.sendto(dns_answer(data, address), client)
        except (IndexError, struct.error):
            _log("dns", client=client[0], qname="<malformed>", qtype=0, proto="udp")


class _DnsTcp(socketserver.BaseRequestHandler):
    def handle(self):
        size = struct.unpack("!H", self.request.recv(2))[0]
        data = self.request.recv(size)
        _, name, qtype, _ = parse_query(data)
        _log("dns", client=self.client_address[0], qname=name, qtype=qtype, proto="tcp")
        out = dns_answer(data, self.server.address)
        self.request.sendall(struct.pack("!H", len(out)) + out)


def _splice(a: socket.socket, b: socket.socket) -> None:
    socks = [a, b]
    while True:
        ready, _, _ = select.select(socks, [], [], 300)
        if not ready:
            return
        for s in ready:
            data = s.recv(65536)
            if not data:
                return
            (b if s is a else a).sendall(data)


class _Tls(socketserver.BaseRequestHandler):
    def handle(self):
        hello = self.request.recv(16384, socket.MSG_PEEK)
        name = parse_sni(hello)
        _log("sni", client=self.client_address[0], sni=name or "<none>")
        with LOCK:
            refused = name is None or name in STATE["refuse"]
        if refused:
            self.request.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            return
        upstream = socket.create_connection((name, 443), timeout=30)
        try:
            _splice(self.request, upstream)
        finally:
            upstream.close()


class _CatchAll(socketserver.BaseRequestHandler):
    def handle(self):
        raw = self.request.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port = struct.unpack("!H", raw[2:4])[0]
        _log("catchall", client=self.client_address[0], port=port, dst=socket.inet_ntoa(raw[4:8]))


class _Threaded(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _iptables(iface: str) -> None:
    for rule in (
        [
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-i",
            iface,
            "-p",
            "tcp",
            "!",
            "--dport",
            "443",
            "-j",
            "REDIRECT",
            "--to-ports",
            "9999",
        ],
        ["-A", "INPUT", "-i", iface, "-p", "udp", "!", "--dport", "53", "-j", "LOG"],
        ["-A", "INPUT", "-i", iface, "-p", "udp", "!", "--dport", "53", "-j", "ACCEPT"],
    ):
        subprocess.run(["iptables", *rule], check=True)


def _udp_count(iface: str) -> int:
    out = subprocess.run(
        ["iptables", "-L", "INPUT", "-v", "-x", "-n"], capture_output=True, text=True, check=True
    )
    for line in out.stdout.splitlines():
        if "LOG" in line and iface in line and "udp" in line:
            return int(line.split()[0])
    return 0


def _control(iface: str) -> None:
    if os.path.exists(CTL):
        os.unlink(CTL)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(CTL)
    os.chmod(CTL, 0o600)
    server.listen(4)
    base = {"udp": _udp_count(iface)}
    while True:
        conn, _ = server.accept()
        with conn:
            cmd = conn.recv(65536).decode().split()
            with LOCK:
                if cmd and cmd[0] == "reset":
                    STATE["window"] += 1
                    for k in ("dns", "sni", "catchall"):
                        STATE[k].clear()
                    base["udp"] = _udp_count(iface)
                    reply = {"window": STATE["window"]}
                elif cmd and cmd[0] == "refuse":
                    STATE["refuse"] = {h.lower() for h in cmd[1:]}
                    reply = {"refuse": sorted(STATE["refuse"])}
                else:
                    reply = {k: list(STATE[k]) for k in ("dns", "sni", "catchall")}
                    reply.update(window=STATE["window"], udp=_udp_count(iface) - base["udp"])
            conn.sendall(json.dumps(reply).encode())


def serve(address: str, iface: str) -> None:
    _iptables(iface)
    threading.Thread(target=dns_udp, args=(address,), daemon=True).start()
    dns_tcp = _Threaded((address, 53), _DnsTcp)
    dns_tcp.address = address
    for server in (dns_tcp, _Threaded((address, 443), _Tls), _Threaded((address, 9999), _CatchAll)):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    _control(iface)


def ctl(args: list[str]) -> int:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(CTL)
    sock.sendall(" ".join(args).encode())
    sock.shutdown(socket.SHUT_WR)
    data = b""
    while chunk := sock.recv(65536):
        data += chunk
    print(data.decode())
    return 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["serve"]:
        serve(sys.argv[2], sys.argv[3])
    elif sys.argv[1:2] == ["ctl"]:
        sys.exit(ctl(sys.argv[2:]))
    else:
        print("usage: obs_relay.py serve ADDRESS IFACE | ctl reset|dump|refuse HOST...", file=sys.stderr)
        sys.exit(2)
