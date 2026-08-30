#!/usr/bin/env python3
"""verify-blocking.py - prove, rather than assert, that torrents are blocked.

Starts a throwaway Xray on localhost using the routing rules out of your x-ui.db,
then speaks each protocol a real torrent client speaks and reports what got
through. The live server is not touched: separate process, separate port, and it
only ever talks to 127.0.0.1.

    python3 verify-blocking.py
    python3 verify-blocking.py --db /etc/x-ui/x-ui.db --xray /usr/local/x-ui/bin/xray-linux-amd64

Exit status is 0 only if every case behaved as intended.

Why this exists: a routing rule that looks correct in the panel can still let a
modern client straight through, because protocol sniffing only ever names
PLAINTEXT BitTorrent over TCP. Reading the config cannot tell you that. Sending
the bytes can.
"""
import argparse
import json
import os
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time

TCP_HITS, UDP_HITS = [], []

DB_CANDIDATES = ["/etc/x-ui/x-ui.db", "/usr/local/x-ui/x-ui.db", "/opt/x-ui/x-ui.db",
                 "/usr/local/x-ui/bin/x-ui.db"]
XRAY_CANDIDATES = ["/usr/local/x-ui/bin/xray-linux-amd64", "/usr/local/x-ui/bin/xray",
                   "/usr/bin/xray", "/usr/local/bin/xray"]

# Addresses the probes aim at. Not one packet is ever sent to them - every
# outbound redirects to the local listener - but routing sees them, so IP rules
# are exercised for real.
#
# PEER_IP has to be a genuinely PUBLIC address. The obvious choice is a
# documentation range like 203.0.113.0/24, but geoip:private covers every
# reserved range - documentation, benchmark and CGNAT included - and almost every
# panel carries a geoip:private rule. Probing one of those would report the whole
# suite as blocked no matter what the torrent rules did.
PEER_IP = "185.199.108.153"       # public, stable, and never actually contacted
DISCORD_VOICE_IP = "66.22.192.7"  # inside Discord's voice range, 66.22.192.0/18

# Not one of DISCOVERY_PORTS: these cases test the protocol rules, and reusing a
# blocked port would let the port rule answer for them.
PEER_PORT = 51999


def first_existing(paths, what):
    for p in paths:
        if os.path.exists(p):
            return p
    sys.exit("could not find {0}; pass it explicitly".format(what))


def free_port():
    """A port free for BOTH TCP and UDP.

    The socks inbound and the probe listener each need the pair. Testing only TCP
    picks a port that Xray then fails to bind for UDP, and the whole run dies with
    a bind error that looks like a config fault.
    """
    for _ in range(60):
        # Ask the OS for a UDP port first: UDP is the fussier of the two, because
        # Windows and Hyper-V reserve wide swathes of the ephemeral range for it.
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.bind(("127.0.0.1", 0))
        port = u.getsockname()[1]
        u.close()
        t = socket.socket()
        try:
            t.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            t.close()
    sys.exit("could not find a port free for both TCP and UDP")


def tcp_listener(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(32)
    while True:
        c, _ = s.accept()
        try:
            c.settimeout(3)
            TCP_HITS.append(c.recv(64))
        except Exception:
            TCP_HITS.append(b"")
        finally:
            c.close()


def udp_listener(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    while True:
        data, _ = s.recvfrom(2048)
        UDP_HITS.append(data)


def via_tcp(socks_port, host, port, payload):
    """True if the payload never arrived, i.e. the rules dropped it."""
    before = len(TCP_HITS)
    try:
        s = socket.create_connection(("127.0.0.1", socks_port), timeout=6)
        s.settimeout(6)
        s.sendall(b"\x05\x01\x00")
        s.recv(2)
        s.sendall(b"\x05\x01\x00" + socks_addr(host) + struct.pack("!H", port))
        rep = s.recv(10)
        if len(rep) < 2 or rep[1] != 0:
            return True
        s.sendall(payload)
        time.sleep(1.0)
        s.close()
    except Exception:
        return True
    time.sleep(0.3)
    return len(TCP_HITS) == before


def socks_addr(host):
    """SOCKS5 address field: literal IP where we have one, otherwise the name."""
    try:
        return b"\x01" + socket.inet_aton(host)
    except OSError:
        hb = host.encode()
        return b"\x03" + bytes([len(hb)]) + hb


def via_udp(socks_port, host, port, payload):
    before = len(UDP_HITS)
    try:
        ctl = socket.create_connection(("127.0.0.1", socks_port), timeout=6)
        ctl.settimeout(6)
        ctl.sendall(b"\x05\x01\x00")
        ctl.recv(2)
        ctl.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0))
        rep = ctl.recv(10)
        if len(rep) < 10 or rep[1] != 0:
            return True
        relay = struct.unpack("!H", rep[8:10])[0]
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(4)
        hdr = b"\x00\x00\x00" + socks_addr(host) + struct.pack("!H", port)
        for _ in range(3):
            u.sendto(hdr + payload, ("127.0.0.1", relay))
            time.sleep(0.25)
        time.sleep(0.8)
        u.close()
        ctl.close()
    except Exception:
        return True
    time.sleep(0.3)
    return len(UDP_HITS) == before


def build_config(template, socks_port, sniffing, probe_port):
    """The server's own routing rules, reached through a local socks inbound.

    Every outbound that is not a blackhole becomes a freedom outbound that
    redirects to the probe listener. Routing still sees the real destination -
    address, port, sniffed protocol and all - so the rules under test behave
    exactly as they would in production, but anything they let through lands
    here instead of on the internet. That is what makes it possible to probe a
    destination like Discord's voice range without sending it a packet.
    """
    cfg = json.loads(json.dumps(template))
    rules = (cfg.get("routing") or {}).get("rules") or []
    sink = {"redirect": "127.0.0.1:{0}".format(probe_port)}

    outs = []
    for o in cfg.get("outbounds") or []:
        tag = str(o.get("tag") or "")
        if str(o.get("protocol", "")).lower() == "blackhole":
            outs.append({"tag": tag, "protocol": "blackhole", "settings": {}})
        else:
            outs.append({"tag": tag, "protocol": "freedom", "settings": dict(sink)})

    have = set(str(o.get("tag") or "") for o in outs)
    for r in rules:
        tag = str(r.get("outboundTag") or "")
        if tag and tag != "api" and tag not in have:
            outs.append({"tag": tag, "protocol": "freedom", "settings": dict(sink)})
            have.add(tag)
    if not any(o["protocol"] == "freedom" for o in outs):
        outs.insert(0, {"tag": "direct", "protocol": "freedom", "settings": dict(sink)})

    # There is no api inbound here, so an api rule would stop Xray starting.
    rules = [r for r in rules
             if "api" not in [str(x) for x in (r.get("inboundTag") or [])]
             and str(r.get("outboundTag")) != "api"]

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "probe", "listen": "127.0.0.1", "port": socks_port,
                      "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": True},
                      "sniffing": sniffing}],
        "outbounds": outs,
        "routing": {"rules": rules},
    }


def weakest_sniffing(rows):
    """What a customer actually gets is the weakest sniffing on any inbound."""
    best = {"enabled": True, "destOverride": ["http", "tls", "quic"],
            "metadataOnly": False, "routeOnly": True}
    for (raw,) in rows:
        try:
            sn = json.loads(raw) if isinstance(raw, str) else (raw or {})
        except Exception:
            continue
        if not sn.get("enabled") or sn.get("metadataOnly"):
            return {"enabled": bool(sn.get("enabled")),
                    "destOverride": sn.get("destOverride") or [],
                    "metadataOnly": bool(sn.get("metadataOnly")),
                    "routeOnly": bool(sn.get("routeOnly"))}
    return best


def main():
    ap = argparse.ArgumentParser(description="Prove torrents are actually blocked.")
    ap.add_argument("--db", help="path to x-ui.db")
    ap.add_argument("--xray", help="path to the xray binary")
    ap.add_argument("--keep", action="store_true", help="leave the generated config on disk")
    args = ap.parse_args()

    db = args.db or first_existing(DB_CANDIDATES, "x-ui.db")
    xray = args.xray or first_existing(XRAY_CANDIDATES, "the xray binary")

    con = sqlite3.connect(db)
    row = con.execute("select value from settings where key='xrayTemplateConfig'").fetchone()
    sniff_rows = list(con.execute("select sniffing from inbounds"))
    con.close()
    if row is None:
        sys.exit("no routing config saved in {0} - open the panel, press Save, try "
                 "again".format(db))

    socks_port = free_port()
    probe_port = free_port()
    cfg = build_config(json.loads(row[0]), socks_port, weakest_sniffing(sniff_rows),
                       probe_port)

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".verify-xray.json")
    with open(path, "w") as fh:
        json.dump(cfg, fh, indent=1)

    proc = subprocess.Popen([xray, "run", "-c", path],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        time.sleep(2.5)
        if proc.poll() is not None:
            sys.stdout.write(proc.stdout.read().decode("utf-8", "replace"))
            sys.exit("xray would not start with this routing config")

        threading.Thread(target=tcp_listener, args=(probe_port,), daemon=True).start()
        threading.Thread(target=udp_listener, args=(probe_port,), daemon=True).start()
        time.sleep(0.4)

        bt = b"\x13BitTorrent protocol" + b"\x00" * 8 + b"A" * 20 + b"B" * 20
        mse = os.urandom(96)
        utp = struct.pack("!BBHIIIHH", 0x41, 0, 0x1234, 0, 0, 1048576, 0, 0)

        def announce(host):
            return ("GET /announce?info_hash=aaaa HTTP/1.1\r\nHost: " + host +
                    "\r\n\r\n").encode()

        def web(host):
            return ("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n").encode()

        cases = [
            ("BitTorrent handshake, plaintext TCP", True,
             lambda: via_tcp(socks_port, PEER_IP, PEER_PORT, bt)),
            ("peer on a BitTorrent port, TCP", True,
             lambda: via_tcp(socks_port, PEER_IP, 6881, mse)),
            ("uTP to a peer on a BitTorrent port", True,
             lambda: via_udp(socks_port, PEER_IP, 6881, utp)),
            ("uTP to a peer on a random high port", True,
             lambda: via_udp(socks_port, PEER_IP, 54321, utp)),
            ("tracker announce (tracker.example.net)", True,
             lambda: via_tcp(socks_port, "tracker.example.net", 443,
                             announce("tracker.example.net"))),
            ("DHT bootstrap (router.bittorrent.com)", True,
             lambda: via_udp(socks_port, "router.bittorrent.com", 6881, utp)),
            ("ordinary web traffic", False,
             lambda: via_tcp(socks_port, "www.example.net", 443,
                             web("www.example.net"))),
            ("a site merely named *tracker*", False,
             lambda: via_tcp(socks_port, "mytracker.example.net", 443,
                             web("mytracker.example.net"))),
            ("QUIC / HTTP3 (UDP 443)", False,
             lambda: via_udp(socks_port, PEER_IP, 443, b"\x00" * 64)),
            ("DNS (UDP 53)", False,
             lambda: via_udp(socks_port, PEER_IP, 53, b"\x00" * 32)),
            ("Discord voice (UDP 50001 to 66.22.192.0/18)", False,
             lambda: via_udp(socks_port, DISCORD_VOICE_IP, 50001, b"\x80" + b"\x00" * 63)),
            ("encrypted peer handshake (MSE/PE)", None,
             lambda: via_tcp(socks_port, PEER_IP, PEER_PORT, mse)),
        ]

        print("")
        print("  {0:<44} {1:<9} {2}".format("case", "result", "verdict"))
        print("  " + "-" * 78)
        failures = 0
        for name, must_block, run in cases:
            blocked = run()
            got = "blocked" if blocked else "passed"
            if must_block is None:
                verdict = ("blocked" if blocked else
                           "known gap - blocking discovery is what stops this")
            elif must_block:
                verdict = "ok" if blocked else "*** LEAK ***"
                failures += 0 if blocked else 1
            else:
                verdict = "ok" if not blocked else "*** over-blocking ***"
                failures += 0 if not blocked else 1
            print("  {0:<44} {1:<9} {2}".format(name, got, verdict))
        print("")
        if failures:
            clamped = any(str(r.get("network") or "").lower() == "udp" and r.get("port")
                          for r in (cfg.get("routing") or {}).get("rules", []))
            print("{0} case(s) wrong.".format(failures))
            if not clamped:
                print("A client with a warm peer cache needs neither a tracker nor the "
                      "DHT, so blocking discovery does not stop one already running.")
                print("Two ways to finish it:")
                print("  sudo python3 extras/torrent-watch.py --install   "
                      "# cut off whoever trips the rules; nothing else affected")
                print("  sudo python3 block-torrents.py --strict --apply  "
                      "# close UDP; needs an allowlist for voice and games")
            else:
                print("  sudo python3 block-torrents.py --apply")
        else:
            print("Every case behaved as intended.")
        return 1 if failures else 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        if not args.keep and os.path.exists(path):
            os.remove(path)


if __name__ == "__main__":
    sys.exit(main())
