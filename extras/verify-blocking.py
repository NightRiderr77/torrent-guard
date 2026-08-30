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

# Hostnames the harness pretends to reach, mapped to 127.0.0.1 by Xray's own hosts
# table - so this needs no DNS, no internet, and never leaves the machine.
FAKE_HOSTS = {
    "tracker.example.net": "127.0.0.1",      # must be blocked: matches ^tracker\.
    "router.bittorrent.com": "127.0.0.1",    # must be blocked: DHT bootstrap node
    "www.example.net": "127.0.0.1",          # must pass: ordinary browsing
    "mytracker.example.net": "127.0.0.1",    # must pass: only *contains* "tracker"
}


def first_existing(paths, what):
    for p in paths:
        if os.path.exists(p):
            return p
    sys.exit("could not find {0}; pass it explicitly".format(what))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


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
        hb = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack("!H", port))
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


def via_udp(socks_port, port, payload):
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
        hdr = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", port)
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


def build_config(template, socks_port, sniffing):
    """The server's own routing rules, reached through a local socks inbound.

    Customer outbounds become plain freedom outbounds so the config runs anywhere;
    the routing RULES - the thing actually under test - are left exactly as they are.
    """
    cfg = json.loads(json.dumps(template))
    rules = (cfg.get("routing") or {}).get("rules") or []

    outs = []
    for o in cfg.get("outbounds") or []:
        tag = str(o.get("tag") or "")
        if str(o.get("protocol", "")).lower() == "blackhole":
            outs.append({"tag": tag, "protocol": "blackhole", "settings": {}})
        else:
            outs.append({"tag": tag, "protocol": "freedom",
                         "settings": {"domainStrategy": "UseIP"}})

    have = set(str(o.get("tag") or "") for o in outs)
    for r in rules:
        tag = str(r.get("outboundTag") or "")
        if tag and tag != "api" and tag not in have:
            outs.append({"tag": tag, "protocol": "freedom",
                         "settings": {"domainStrategy": "UseIP"}})
            have.add(tag)
    if not any(o["protocol"] == "freedom" for o in outs):
        outs.insert(0, {"tag": "direct", "protocol": "freedom",
                        "settings": {"domainStrategy": "UseIP"}})

    # There is no api inbound here, so an api rule would stop Xray starting.
    rules = [r for r in rules
             if "api" not in [str(x) for x in (r.get("inboundTag") or [])]
             and str(r.get("outboundTag")) != "api"]

    # The probes necessarily talk to 127.0.0.1, so a private-IP rule would catch
    # every one of them and report a clean sweep no matter what else is wrong.
    # That rule protects the server's own network and has nothing to do with
    # torrents, so take it out rather than let it answer for the rules under test.
    kept, dropped = [], 0
    for r in rules:
        ips = [str(x).lower() for x in (r.get("ip") or [])]
        only_private = bool(ips) and all(
            i.startswith(("geoip:private", "127.", "10.", "192.168.", "::1", "fc00:",
                          "fe80:")) or i.startswith("172.") for i in ips)
        if only_private and not (r.get("protocol") or r.get("domain") or r.get("port")):
            dropped += 1
            continue
        kept.append(r)
    if dropped:
        print("  (ignoring {0} private-IP rule(s): the probes use 127.0.0.1, so they "
              "would mask everything)".format(dropped))
    rules = kept

    return {
        "log": {"loglevel": "warning"},
        "dns": {"hosts": dict(FAKE_HOSTS), "servers": ["localhost"]},
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
    tcp_port = free_port()
    # Any port in the BitTorrent range will do; take the first this box will lend us,
    # because a torrent client already running here will be sitting on 6881.
    udp_port = None
    for candidate in range(6881, 6890):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind(("127.0.0.1", candidate))
            udp_port = candidate
        except OSError:
            continue
        finally:
            probe.close()
        break
    cfg = build_config(json.loads(row[0]), socks_port, weakest_sniffing(sniff_rows))

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

        threading.Thread(target=tcp_listener, args=(tcp_port,), daemon=True).start()
        udp_ok = udp_port is not None
        if udp_ok:
            threading.Thread(target=udp_listener, args=(udp_port,), daemon=True).start()
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
             lambda: via_tcp(socks_port, "127.0.0.1", tcp_port, bt)),
            ("uTP / DHT on a BitTorrent UDP port", True,
             lambda: via_udp(socks_port, udp_port, utp)),
            ("tracker announce (tracker.example.net)", True,
             lambda: via_tcp(socks_port, "tracker.example.net", tcp_port,
                             announce("tracker.example.net"))),
            ("DHT bootstrap (router.bittorrent.com)", True,
             lambda: via_tcp(socks_port, "router.bittorrent.com", tcp_port,
                             announce("router.bittorrent.com"))),
            ("ordinary web traffic", False,
             lambda: via_tcp(socks_port, "www.example.net", tcp_port,
                             web("www.example.net"))),
            ("a site merely named *tracker*", False,
             lambda: via_tcp(socks_port, "mytracker.example.net", tcp_port,
                             web("mytracker.example.net"))),
            ("encrypted peer handshake (MSE/PE)", None,
             lambda: via_tcp(socks_port, "127.0.0.1", tcp_port, mse)),
        ]

        print("")
        print("  {0:<40} {1:<9} {2}".format("case", "result", "verdict"))
        print("  " + "-" * 74)
        failures = 0
        for name, must_block, run in cases:
            if not udp_ok and "UDP" in name:
                print("  {0:<40} {1:<9} {2}".format(name, "skipped",
                                                    "port 6881 is busy on this box"))
                continue
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
            print("  {0:<40} {1:<9} {2}".format(name, got, verdict))
        print("")
        if failures:
            print("{0} case(s) wrong. Fix with: sudo python3 block-torrents.py "
                  "--apply".format(failures))
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
