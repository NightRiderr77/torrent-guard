#!/usr/bin/env python3
"""torrent-watch.py - cut off the customer, not the packet.

Routing rules drop torrent traffic, but they cannot stop a client that already
knows its peers: it keeps going over encrypted uTP on random UDP ports, and
nothing in Xray can pick that out of ordinary traffic. Closing UDP does stop it,
and takes voice chat and games with it.

There is a better lever. Every blocked torrent attempt is written to Xray's
access log with the customer's name on it:

    ... from tcp:203.0.113.9:51413 accepted tcp:1.2.3.4:6881 [in-443 >> TORRENT] email: bob@x.com

You never have to identify the encrypted flow - only the person. This tails that
log, and when someone trips the torrent rules it drops their IP in the firewall
for a while. Their torrent client stops dead, encrypted or not, and every other
customer is untouched.

    sudo python3 torrent-watch.py --install     # set up and start as a service
    sudo python3 torrent-watch.py               # run in the foreground
    sudo python3 torrent-watch.py --status      # who is blocked right now
    sudo python3 torrent-watch.py --unblock IP  # let someone back in early

Standard library only. Same idea as kutovoys/xray-torrent-blocker, which is worth
a look if you would rather run a maintained Go daemon: it does webhooks, panel
integrations and more. This exists so the whole thing stays one dependency-free
Python file next to block-torrents.py.
"""
import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time

__version__ = "1.0.0"

TORRENT_TAG = "TORRENT"
ACCESS_LOGS = ["/usr/local/x-ui/access.log", "/var/log/xray/access.log",
               "/usr/local/x-ui/bin/access.log", "/var/log/remnanode/access.log"]
STATE_FILE = "/var/lib/torrent-guard/blocked.json"
CHAIN = "TORRENT_GUARD"
SERVICE = "/etc/systemd/system/torrent-watch.service"
DEFAULT_MINUTES = 30

# Xray writes "from tcp:1.2.3.4:5678 accepted tcp:9.9.9.9:6881 [...]", and older
# builds drop the "from". Both the source and the destination look the same, so
# anchor on "accepted": the address before it is the customer, the one after is
# the peer. Blocking the peer would do nothing at all.
SRC = re.compile(
    r"(?:from\s+)?(?:tcp:|udp:)?"
    r"(\[[0-9a-fA-F:]+\]|\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,}:[0-9a-fA-F]{0,4})"
    r":\d+\s+accepted")
EMAIL = re.compile(r"email:\s*(\S+)")


def normalize_ip(raw):
    """Xray brackets IPv6 in the log; nft and ip6tables both reject the brackets."""
    return raw.strip("[]")

# Never block these however loudly they trip the rules: locking yourself out of
# your own server is a worse outcome than a customer seeding for another minute.
def default_bypass():
    out = {"127.0.0.1"}
    try:
        out.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass
    for var in ("SSH_CLIENT", "SSH_CONNECTION"):
        val = os.environ.get(var, "")
        if val:
            out.add(val.split()[0])
    return out


def run(cmd):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except (OSError, FileNotFoundError) as e:
        return 1, str(e)


def have(binary):
    return run(["which", binary])[0] == 0


class Firewall(object):
    """nftables if the box has it, iptables otherwise."""

    def __init__(self):
        self.kind = "nft" if have("nft") else ("iptables" if have("iptables") else None)
        if not self.kind:
            sys.exit("neither nft nor iptables is available; cannot block anything")

    def setup(self):
        if self.kind == "nft":
            run(["nft", "add", "table", "inet", CHAIN])
            # priority -100 puts this ahead of anything a panel adds later.
            run(["nft", "add", "chain", "inet", CHAIN, "input",
                 "{ type filter hook input priority -100 ; policy accept ; }"])
        else:
            for tool in ("iptables", "ip6tables"):
                if not have(tool):
                    continue
                if run([tool, "-n", "-L", CHAIN])[0] != 0:
                    run([tool, "-N", CHAIN])
                # -C tests for the jump first, so a restart does not stack it up.
                if run([tool, "-C", "INPUT", "-j", CHAIN])[0] != 0:
                    run([tool, "-I", "INPUT", "1", "-j", CHAIN])

    def block(self, ip):
        v6 = ":" in ip
        if self.kind == "nft":
            run(["nft", "add", "rule", "inet", CHAIN, "input",
                 "ip6" if v6 else "ip", "saddr", ip, "drop"])
        else:
            # Customers on IPv6 need ip6tables; blocking only v4 would leave them
            # torrenting happily over the other family.
            tool = "ip6tables" if v6 else "iptables"
            if run([tool, "-C", CHAIN, "-s", ip, "-j", "DROP"])[0] != 0:
                run([tool, "-A", CHAIN, "-s", ip, "-j", "DROP"])
        # Existing flows survive a new firewall rule, and a torrent client holds
        # its connections open for a long time. Cut them too, or the block does
        # nothing until the peer gives up on its own.
        if have("conntrack"):
            run(["conntrack", "-D", "-s", ip])

    def unblock(self, ip):
        if self.kind == "nft":
            code, out = run(["nft", "-a", "list", "chain", "inet", CHAIN, "input"])
            for line in out.splitlines():
                if (" " + ip + " ") in line and "handle" in line:
                    handle = line.rsplit("handle", 1)[1].strip()
                    run(["nft", "delete", "rule", "inet", CHAIN, "input", "handle", handle])
        else:
            tool = "ip6tables" if ":" in ip else "iptables"
            while run([tool, "-C", CHAIN, "-s", ip, "-j", "DROP"])[0] == 0:
                run([tool, "-D", CHAIN, "-s", ip, "-j", "DROP"])


def load_state():
    try:
        with open(STATE_FILE) as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_state(state):
    d = os.path.dirname(STATE_FILE)
    if not os.path.isdir(d):
        os.makedirs(d)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh, indent=1)
    os.replace(tmp, STATE_FILE)


def find_log(explicit=None):
    if explicit:
        return explicit
    for p in ACCESS_LOGS:
        if os.path.exists(p):
            return p
    sys.exit("could not find Xray's access log. Run block-torrents.py --apply first, "
             "which turns it on, or pass --log /path/to/access.log")


def follow(path):
    """Yield lines forever, surviving the log being rotated out from under us."""
    fh = open(path, "r", errors="replace")
    fh.seek(0, os.SEEK_END)
    inode = os.fstat(fh.fileno()).st_ino
    while True:
        line = fh.readline()
        if line:
            yield line
            continue
        time.sleep(0.4)
        try:
            if os.stat(path).st_ino != inode:
                fh.close()
                fh = open(path, "r", errors="replace")
                inode = os.fstat(fh.fileno()).st_ino
        except OSError:
            pass


def watch(args):
    fw = Firewall()
    fw.setup()
    log_path = find_log(args.log)
    bypass = default_bypass() | set(x.strip() for x in (args.bypass or "").split(",") if x.strip())
    state = load_state()

    # Re-apply anything still serving its time, in case we were restarted.
    now = time.time()
    for ip, entry in list(state.items()):
        if entry["until"] > now:
            fw.block(ip)
        else:
            fw.unblock(ip)
            del state[ip]
    save_state(state)

    print("watching {0} for '{1}', blocking for {2} minutes, firewall {3}".format(
        log_path, args.tag, args.minutes, fw.kind))
    print("never blocking: {0}".format(", ".join(sorted(bypass))))
    sys.stdout.flush()

    last_sweep = time.time()
    for line in follow(log_path):
        now = time.time()
        if now - last_sweep > 20:
            last_sweep = now
            for ip, entry in list(state.items()):
                if entry["until"] <= now:
                    fw.unblock(ip)
                    del state[ip]
                    print("[{0}] unblocked {1} ({2})".format(
                        time.strftime("%H:%M:%S"), ip, entry.get("user", "?")))
                    sys.stdout.flush()
            save_state(state)

        if args.tag not in line:
            continue
        m = SRC.search(line)
        if not m:
            continue
        ip = normalize_ip(m.group(1))
        if ip in bypass:
            continue
        who = EMAIL.search(line)
        user = who.group(1) if who else "unknown"

        if ip in state and state[ip]["until"] > now:
            state[ip]["hits"] += 1
            state[ip]["until"] = now + args.minutes * 60   # keep extending while they try
            save_state(state)
            continue

        state[ip] = {"user": user, "since": now, "until": now + args.minutes * 60, "hits": 1}
        fw.block(ip)
        save_state(state)
        print("[{0}] blocked {1} ({2}) for {3} min".format(
            time.strftime("%H:%M:%S"), ip, user, args.minutes))
        sys.stdout.flush()
        if args.webhook:
            post(args.webhook, {"ip": ip, "user": user, "action": "block",
                                "minutes": args.minutes,
                                "server": socket.gethostname()})


def post(url, payload):
    """Best effort. A webhook that is down must never stop us blocking."""
    try:
        import urllib.request
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5).read()
    except Exception as e:
        print("webhook failed: {0}".format(e))


def status():
    state = load_state()
    if not state:
        print("nobody is blocked.")
        return 0
    now = time.time()
    print("{0:<16} {1:<28} {2:>7} {3:>6}".format("ip", "customer", "left", "hits"))
    for ip, e in sorted(state.items(), key=lambda kv: kv[1]["until"]):
        left = int((e["until"] - now) / 60)
        print("{0:<16} {1:<28} {2:>5}m {3:>6}".format(ip, e.get("user", "?")[:28],
                                                      max(0, left), e.get("hits", 1)))
    return 0


UNIT = """[Unit]
Description=torrent-watch: block customers caught torrenting
After=network.target x-ui.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 {script} --log {log} --minutes {minutes} --tag {tag}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


def install(args):
    script = os.path.abspath(__file__)
    log_path = find_log(args.log)
    with open(SERVICE, "w") as fh:
        fh.write(UNIT.format(script=script, log=log_path, minutes=args.minutes,
                             tag=args.tag))
    print("wrote {0}".format(SERVICE))
    for cmd in (["systemctl", "daemon-reload"],
                ["systemctl", "enable", "torrent-watch"],
                ["systemctl", "restart", "torrent-watch"]):
        code, out = run(cmd)
        print("  {0}{1}".format(" ".join(cmd), "" if code == 0 else "  FAILED: " + out))
    print("")
    print("running. Watch it work with:  journalctl -u torrent-watch -f")
    return 0


SAMPLES = [
    # (log line, expected ip, expected user)
    ("2026/08/30 12:00:00 from tcp:203.0.113.9:51413 accepted tcp:1.2.3.4:6881 "
     "[in-443 >> TORRENT] email: bob@x.com", "203.0.113.9", "bob@x.com"),
    ("2026/08/30 12:00:00 203.0.113.9:51413 accepted udp:1.2.3.4:6881 "
     "[in-443 >> TORRENT] email: 12345.alice", "203.0.113.9", "12345.alice"),
    ("2026/08/30 12:00:00 from tcp:[2402:d000::7]:51413 accepted tcp:1.2.3.4:6881 "
     "[in-443 >> TORRENT] email: v6user", "[2402:d000::7]", "v6user"),
    ("2026/08/30 12:00:00 from tcp:198.51.100.5:443 accepted tcp:9.9.9.9:443 "
     "[in-443 >> direct] email: carol@x.com", "198.51.100.5", "carol@x.com"),
]


def selftest():
    ok = [True]

    def check(name, cond):
        ok[0] &= bool(cond)
        print("  {0}  {1}".format("PASS" if cond else "FAIL", name))

    print("parsing real access-log shapes:")
    for line, want_ip, want_user in SAMPLES:
        m = SRC.search(line)
        got_ip = m.group(1) if m else None
        u = EMAIL.search(line)
        got_user = u.group(1) if u else None
        check("{0!r} -> {1}".format(line.split("accepted")[0][20:44].strip(), want_ip),
              got_ip == want_ip and got_user == want_user)

    print("")
    print("the things that would be silent disasters:")
    line = SAMPLES[0][0]
    check("captures the customer, not the peer it dialled",
          SRC.search(line).group(1) == "203.0.113.9" != "1.2.3.4")
    check("a line without the tag is ignored", TORRENT_TAG not in SAMPLES[3][0])
    check("IPv6 sources are recognised, not skipped", ":" in SAMPLES[2][1])
    check("v6 addresses route to ip6tables", ":" in normalize_ip(SAMPLES[2][1]))
    check("the brackets Xray puts round IPv6 are stripped, or the firewall "
          "rejects it", normalize_ip("[2402:d000::7]") == "2402:d000::7")
    check("no match on a line with no address", SRC.search("nonsense") is None)

    print("")
    print("ALL CHECKS PASSED" if ok[0] else "FAILURES")
    return 0 if ok[0] else 1


def main():
    ap = argparse.ArgumentParser(
        prog="torrent-watch",
        description="Block the customer behind a torrent, instead of the packets.")
    ap.add_argument("--log", help="path to Xray's access log")
    ap.add_argument("--minutes", type=int, default=DEFAULT_MINUTES,
                    help="how long to block for (default {0})".format(DEFAULT_MINUTES))
    ap.add_argument("--tag", default=TORRENT_TAG,
                    help="outbound tag that marks torrent traffic (default {0})".format(
                        TORRENT_TAG))
    ap.add_argument("--bypass", help="comma-separated IPs never to block")
    ap.add_argument("--webhook", help="POST a JSON notification here on each block")
    ap.add_argument("--install", action="store_true", help="install and start as a service")
    ap.add_argument("--status", action="store_true", help="show who is blocked")
    ap.add_argument("--selftest", action="store_true",
                    help="check the log parsing; needs no root and no firewall")
    ap.add_argument("--unblock", metavar="IP", help="let an IP back in now")
    ap.add_argument("-V", "--version", action="version",
                    version="torrent-watch {0}".format(__version__))
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if args.status:
        return status()
    if args.unblock:
        Firewall().unblock(args.unblock)
        state = load_state()
        state.pop(args.unblock, None)
        save_state(state)
        print("unblocked {0}".format(args.unblock))
        return 0
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sys.exit("needs root, to change the firewall: sudo python3 torrent-watch.py")
    if args.install:
        return install(args)

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        watch(args)
    except KeyboardInterrupt:
        print("\nstopped. Blocks stay in place until they expire; "
              "'--status' lists them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
