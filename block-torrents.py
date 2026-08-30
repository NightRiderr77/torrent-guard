#!/usr/bin/env python3
"""block-torrents.py - stop BitTorrent on a 3X-UI server. Run it ON the server.

No panel login, no API token, no config file. 3X-UI keeps everything in a local
SQLite file, so running as root is all the access this needs.

    sudo python3 block-torrents.py            # look only, change nothing
    sudo python3 block-torrents.py --apply    # fix it, after taking a backup
    sudo python3 block-torrents.py --restore  # undo, using the newest backup

How the block works, in short:

    A torrent client announces itself in the first few bytes of a connection.
    Xray can look at those bytes and name the protocol - that peek is called
    "sniffing". A routing rule then says "anything named bittorrent goes to the
    blackhole outbound", and the blackhole simply drops it.

    Two things have to be true or the rule is decoration:
      1. sniffing is on, otherwise nothing is ever named "bittorrent";
      2. the rule is checked before any rule that matches your customers,
         because Xray stops at the first rule that matches.

Standard library only. Python 3.7+.
"""
import argparse
import copy
import datetime
import glob
import json
import os
import shutil
import sqlite3
import subprocess
import sys

__version__ = "1.5.0"

DB_CANDIDATES = [
    "/etc/x-ui/x-ui.db",
    "/usr/local/x-ui/x-ui.db",
    "/opt/x-ui/x-ui.db",
    "/usr/local/x-ui/bin/x-ui.db",
]

# routeOnly matters: without it, sniffing rewrites the connection's destination
# to whatever domain it found, which breaks any config that presents a different
# SNI on purpose. routeOnly gives routing the answer and leaves the destination
# alone. metadataOnly must be false or the payload - where the torrent
# announcement lives - is never read.
SNIFFING = {
    "enabled": True,
    "destOverride": ["http", "tls", "quic"],
    "metadataOnly": False,
    "routeOnly": True,
}

# Sniffing only ever names PLAINTEXT BitTorrent over TCP, and that is a small and
# shrinking share of real torrent traffic:
#
#   * uTorrent, qBittorrent and Transmission turn on protocol encryption (MSE/PE)
#     by default. The first bytes are then a Diffie-Hellman key - indistinguishable
#     from noise - so there is no "BitTorrent protocol" string left to match.
#   * Most peer traffic is uTP over UDP. Xray does carry a uTP sniffer, but it
#     only matches the ST_SYN packet that opens a connection, and only with exact
#     header framing. Everything after it - all the actual data - matches nothing.
#     On a live server with the rule in place and sniffing on, torrents ran at
#     full speed.
#
# See extras/verify-blocking.py, which reproduces all of this in ten seconds.
#
# So identifying peer traffic is a losing game. What actually works is cutting off
# peer DISCOVERY: a client that cannot reach a tracker or the DHT has no peer list,
# and encryption does not help it find one.

# Tracker and DHT ports. Both TCP and UDP - trackers answer on TCP too.
DISCOVERY_PORTS = "6881-6889,6969,1337,2710,51413"

# The public DHT bootstrap nodes, plus trackers by name. The regexes are anchored
# at the start of a label on purpose: "tracker.x.com" is caught, "mytracker.x.com"
# and "package-tracker.com" are not. A bare keyword match would block far too much.
TRACKER_DOMAINS = [
    "domain:router.bittorrent.com",
    "domain:router.utorrent.com",
    "domain:dht.transmissionbt.com",
    "domain:dht.libtorrent.org",
    "domain:router.bitcomet.com",
    "domain:dht.aelitis.com",
    "domain:opentrackr.org",
    "domain:openbittorrent.com",
    "domain:torrent.eu.org",
    r"regexp:^tracker[0-9]*\.",
    r"regexp:^(open|udp|bt)tracker[0-9]*\.",
    r"regexp:^announce\.",
    r"regexp:^dht\.",
]
DHT_SENTINEL = "domain:router.bittorrent.com"

# --strict only. Peers listen on random high UDP ports, so there is no list of
# torrent ports to block - the only thing that kills uTP is to close UDP and open
# back the few things that genuinely need it.
#
# Ports: DNS, NTP, QUIC, STUN/TURN, and Google's STUN range (WebRTC, which Discord
# and Meet use to find a path).
ESSENTIAL_UDP_PORTS = "53,123,443,3478-3481,19302-19309"

# Discord's voice servers do not live in one tidy range. They are hosted on
# i3D.net (AS49544), which announces 67 prefixes worldwide - and the ones a
# customer in Asia actually reaches are the Singapore and India blocks, not the
# US one. Allowing a single range is why voice still broke.
#
# AS49544's announced IPv4 space, collapsed, as of 2026-08-30. Refresh with:
#   curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS49544"
# i3D also host game servers, so this doubles as an allowlist for those.
ALLOW_UDP_IPS = [
    "5.180.216.0/22", "5.200.0.0/19", "31.204.128.0/19",
    "43.239.136.0/22", "45.147.87.0/24", "45.149.251.0/24",
    "45.153.18.0/23", "66.22.192.0/18", "89.104.160.0/20",
    "89.104.176.0/22", "89.104.180.0/23", "91.195.234.0/23",
    "91.216.207.0/24", "91.221.208.0/24", "91.233.67.0/24",
    "103.159.122.0/23", "103.194.164.0/22", "104.153.84.0/22",
    "109.200.192.0/19", "130.254.64.0/19", "138.128.136.0/21",
    "146.247.72.0/22", "162.244.52.0/22", "162.245.204.0/22",
    "185.38.20.0/22", "185.41.140.0/22", "185.50.104.0/22",
    "185.52.12.0/22", "185.77.208.0/22", "185.162.56.0/22",
    "185.171.240.0/22", "185.172.132.0/22", "185.179.200.0/22",
    "185.185.212.0/22", "185.191.240.0/22", "185.197.24.0/22",
    "185.218.164.0/23", "185.218.166.0/24", "188.122.64.0/19",
    "193.43.218.0/24", "194.2.155.0/24", "194.61.59.0/24",
    "194.169.249.0/24", "195.22.144.0/23", "195.85.225.0/24",
    "199.27.212.0/22", "202.59.232.0/23", "203.132.16.0/20",
    "212.19.224.0/22", "212.104.192.0/20", "213.163.64.0/19",
    "213.179.192.0/19", "213.190.22.0/24", "216.98.48.0/20",
]


def parse_ports(spec):
    """'53,3478-3481' -> [(53, 53), (3478, 3481)]"""
    out = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            out.append((int(lo), int(hi)))
        else:
            out.append((int(part), int(part)))
    return out


def complement_ports(allowed):
    """Every port 1-65535 that is NOT allowed, as an Xray port string.

    Derived rather than written out by hand: the allow list is the thing an
    operator reasons about, and one typo in a hand-written complement silently
    opens or closes a range nobody meant to touch.
    """
    merged = []
    for lo, hi in sorted(allowed):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append([lo, hi])
    out, cur = [], 1
    for lo, hi in merged:
        if lo > cur:
            out.append((cur, lo - 1))
        cur = max(cur, hi + 1)
    if cur <= 65535:
        out.append((cur, 65535))
    return ",".join("{0}-{1}".format(a, b) if a != b else str(a) for a, b in out)


# Where x-ui writes the config it is actually running. 3X-UI builds this from the
# saved template plus the inbounds, so it is the template with the inbounds added -
# which makes it a faithful way to recover a template that was never saved.
GENERATED_CONFIGS = [
    "/usr/local/x-ui/bin/config.json",
    "/etc/x-ui/bin/config.json",
    "/usr/local/x-ui/config.json",
    "/opt/x-ui/bin/config.json",
]

TEMPLATE_KEY = "xrayTemplateConfig"

# Torrent traffic goes to its own blackhole rather than the shared "blocked" one.
# Dropping it is identical either way - the point is the access log, which records
# the outbound each connection took. With its own tag, every torrent attempt
# becomes a line naming the customer who made it, and a watcher can cut that
# customer off entirely. That is the only thing that reliably stops an encrypted
# uTP flow, because you never have to identify the flow - only the person.
TORRENT_TAG = "TORRENT"
ACCESS_LOG = "/usr/local/x-ui/access.log"


def load_template(con):
    """(xray, key, source) - the routing config to edit, however it is stored.

    A fresh 3X-UI has no saved template at all: the panel shows its built-in
    default and writes nothing until someone presses Save. The routing page looks
    completely normal, which is why this is easy to miss.
    """
    row = con.execute("select value from settings where key=?", (TEMPLATE_KEY,)).fetchone()
    if row is not None:
        try:
            return json.loads(row[0]), TEMPLATE_KEY, "saved"
        except Exception:
            pass

    # Forks sometimes rename the key. Find it by shape instead of by name.
    for key, value in con.execute("select key, value from settings"):
        if not isinstance(value, str) or "outbounds" not in value:
            continue
        try:
            cfg = json.loads(value)
        except Exception:
            continue
        if isinstance(cfg, dict) and ("routing" in cfg or "outbounds" in cfg):
            return cfg, key, "saved"

    # Nothing saved. Recover the template from the running config: everything in it
    # except the inbounds came from the template, and the api inbound belongs to it.
    for p in GENERATED_CONFIGS:
        if not os.path.exists(p):
            continue
        try:
            with open(p) as fh:
                cfg = json.load(fh)
        except Exception:
            continue
        if not isinstance(cfg, dict) or "outbounds" not in cfg:
            continue
        cfg["inbounds"] = [ib for ib in (cfg.get("inbounds") or [])
                           if str(ib.get("tag")) == "api"]
        return cfg, TEMPLATE_KEY, p

    return None, TEMPLATE_KEY, None


def find_db(explicit=None):
    if explicit:
        if not os.path.exists(explicit):
            sys.exit("not found: {0}".format(explicit))
        return explicit
    for p in DB_CANDIDATES:
        if os.path.exists(p):
            return p
    sys.exit("Could not find x-ui.db. Pass it explicitly:\n"
             "  sudo python3 block-torrents.py --db /path/to/x-ui.db")


def loads(v, default):
    if isinstance(v, (dict, list)):
        return v
    try:
        return json.loads(v)
    except Exception:
        return copy.deepcopy(default)


def is_bt(rule):
    p = rule.get("protocol") or []
    if isinstance(p, str):
        p = [p]
    return "bittorrent" in [str(x).lower() for x in p]


def is_api(rule):
    t = rule.get("inboundTag") or []
    if isinstance(t, str):
        t = [t]
    return "api" in [str(x) for x in t] or str(rule.get("outboundTag")) == "api"


def is_discovery_ports(rule):
    return str(rule.get("port") or "") == DISCOVERY_PORTS and not rule.get("domain")


def is_tracker_domains(rule):
    return DHT_SENTINEL in (rule.get("domain") or [])


def is_udp_clamp(rule):
    return (str(rule.get("network") or "").lower() == "udp"
            and rule.get("port") and not rule.get("ip")
            and not rule.get("domain") and not rule.get("protocol"))


def is_udp_allow(rule):
    """The companion rule that lets voice and video through the clamp."""
    return (str(rule.get("network") or "").lower() == "udp"
            and rule.get("ip") and not rule.get("port")
            and not rule.get("domain") and not rule.get("protocol"))


def is_guard(rule):
    """Any rule this tool owns."""
    return (is_bt(rule) or is_discovery_ports(rule) or is_tracker_domains(rule)
            or is_udp_clamp(rule) or is_udp_allow(rule))


def guard_rules(hole, strict, allow_ips=None, allow_ports=None, passthrough="direct",
                clamp_ports=None):
    """The rules that stop torrents, in the order Xray must check them."""
    out = [
        {"type": "field", "protocol": ["bittorrent"], "outboundTag": hole, "enabled": True},
        {"type": "field", "port": DISCOVERY_PORTS, "outboundTag": hole, "enabled": True},
        {"type": "field", "domain": list(TRACKER_DOMAINS), "outboundTag": hole,
         "enabled": True},
    ]
    if strict:
        ips = list(allow_ips if allow_ips is not None else ALLOW_UDP_IPS)
        ports = allow_ports if allow_ports is not None else ESSENTIAL_UDP_PORTS
        # The allow rule has to sit ABOVE the clamp and name an outbound, because
        # Xray stops at the first match and has no "keep looking" verdict.
        if ips:
            out.append({"type": "field", "network": "udp", "ip": ips,
                        "outboundTag": passthrough, "enabled": True})
        out.append({"type": "field", "network": "udp",
                    "port": clamp_ports or complement_ports(parse_ports(ports)),
                    "outboundTag": hole, "enabled": True})
    return out


def rule_users(rule):
    u = rule.get("user")
    if isinstance(u, list):
        return [str(x) for x in u if str(x).strip()]
    if isinstance(u, str) and u.strip():
        return [x.strip() for x in u.split(",") if x.strip()]
    return []


def plan(db_path, strict=False, drop_strict=False, allow_ips=None,
         allow_ports=None):
    """Read the database and work out what is wrong. Changes nothing."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    problems, actions = [], []

    inbounds = list(con.execute("select id, tag, remark, port, sniffing from inbounds"))
    inbound_fixes = []
    for ib in inbounds:
        sn = loads(ib["sniffing"], {})
        name = ib["remark"] or ib["tag"] or "inbound {0}".format(ib["id"])
        if not sn.get("enabled"):
            problems.append("{0}: traffic is never inspected, so a torrent is never "
                            "recognised".format(name))
        elif sn.get("metadataOnly"):
            problems.append("{0}: only headers are inspected, and the torrent "
                            "announcement is in the body".format(name))
        else:
            continue
        new = dict(sn)
        new.update(SNIFFING)
        inbound_fixes.append((ib["id"], name, json.dumps(new)))
        actions.append("turn on traffic inspection for {0}".format(name))

    xray, template_key, source = load_template(con)
    con.close()

    if xray is None:
        return {"db": db_path, "problems": problems + [
            "No routing configuration is saved, and the running config could not be read, "
            "so the torrent rules cannot be placed."],
            "actions": actions, "inbound_fixes": inbound_fixes, "template_key": template_key,
            "xray_before": None, "xray_after": None, "routing_note":
            "Open the panel, go to Xray Configs / Routing and press Save, then run this "
            "again. That writes the routing config this script needs to edit."}

    seeded = source not in (None, "saved")
    if seeded:
        problems.append("Nothing is saved in Xray Configs / Routing, so the panel is running "
                        "its built-in defaults and there is nothing for the torrent rules to "
                        "be added to.")
        actions.append("save the routing config the panel is already running, taken from "
                       "{0}, and add the torrent rules to it".format(source))
    before = copy.deepcopy(xray)
    xray.setdefault("outbounds", [])
    routing = xray.setdefault("routing", {})
    rules = routing.setdefault("rules", [])

    hole = TORRENT_TAG
    if not any(str(o.get("tag")) == TORRENT_TAG
               and str(o.get("protocol", "")).lower() == "blackhole"
               for o in xray["outbounds"]):
        xray["outbounds"].append({"tag": TORRENT_TAG, "protocol": "blackhole",
                                  "settings": {}})
        problems.append("Torrent traffic has nowhere of its own to go, so it cannot be "
                        "told apart from anything else that is blocked.")
        actions.append("add a blackhole outbound tagged '{0}'".format(TORRENT_TAG))

    # No access log means no way to see WHICH customer is torrenting, which is the
    # whole basis of cutting one off.
    logcfg = xray.setdefault("log", {})
    access = str(logcfg.get("access") or "")
    if not access or access.lower() == "none":
        logcfg["access"] = ACCESS_LOG
        problems.append("Xray writes no access log, so there is no way to tell which "
                        "customer is torrenting.")
        actions.append("write the access log to {0}".format(ACCESS_LOG))

    # Everything this tool owns comes out, is rebuilt correctly, and goes back as one
    # block above the customer rules. Rebuilding beats patching in place: there is
    # only one shape to reason about, and a second run is a genuine no-op.
    existing = [(i, r) for i, r in enumerate(rules) if is_guard(r)]
    first_guard = existing[0][0] if existing else None
    have_bt = any(is_bt(r) for _, r in existing)
    have_ports = any(is_discovery_ports(r) for _, r in existing)
    have_domains = any(is_tracker_domains(r) for _, r in existing)
    have_clamp = any(is_udp_clamp(r) for _, r in existing)

    # Anything the operator edited in the panel is kept, unless this run names a
    # replacement. Their edits are the whole point of the rules being visible there.
    if allow_ips is None:
        prior = [r for _, r in existing if is_udp_allow(r)]
        allow_ips = prior[0].get("ip") if prior else None
    clamp_ports = None
    if allow_ports is None:
        prior = [r for _, r in existing if is_udp_clamp(r)]
        clamp_ports = str(prior[0].get("port")) if prior else None

    # The allow rule must name an outbound, so it needs the one ordinary traffic
    # would have taken anyway.
    passthrough = next((str(o.get("tag")) for o in xray["outbounds"]
                        if str(o.get("protocol", "")).lower() != "blackhole"
                        and o.get("tag")), "direct")

    # Count shadowing before anything moves, or the indexes stop meaning anything.
    shadowed = 0
    if first_guard is not None:
        shadowed = sum(len(rule_users(r)) for r in rules[:first_guard] if not is_api(r))

    for i, _ in reversed(existing):
        rules.pop(i)

    if not have_bt:
        problems.append("There is no rule for torrent traffic at all.")
        actions.append("add a rule sending torrents to '{0}'".format(hole))
    else:
        bt = [r for _, r in existing if is_bt(r)][0]
        if str(bt.get("outboundTag")) != hole:
            problems.append("The torrent rule forwards to '{0}' instead of dropping "
                            "it.".format(bt.get("outboundTag")))
            actions.append("point the torrent rule at '{0}'".format(hole))
        if bt.get("enabled") is False:
            problems.append("The torrent rule is switched off.")
            actions.append("switch the torrent rule back on")

    if not have_ports:
        problems.append("The tracker and DHT ports are open, so clients still find peers "
                        "and still torrent over UDP - which sniffing never sees.")
        actions.append("block the tracker and DHT ports ({0})".format(DISCOVERY_PORTS))

    if not have_domains:
        problems.append("The DHT bootstrap nodes and tracker hostnames are reachable, so a "
                        "client can fetch a peer list and encrypt everything after that.")
        actions.append("block the DHT bootstrap nodes and tracker hostnames")

    # The clamp is sticky: once an operator turns it on it stays on, because a later
    # plain --apply must not quietly undo a deliberate choice. --no-strict removes it.
    want_clamp = (strict or have_clamp) and not drop_strict
    if want_clamp and not have_clamp:
        problems.append("uTP over UDP still works. Peers listen on random high ports, so "
                        "nothing but a UDP clamp stops it.")
        actions.append("close UDP except {0}, and except traffic to {1} "
                       "(--strict)".format(ESSENTIAL_UDP_PORTS,
                                           ", ".join(allow_ips or ALLOW_UDP_IPS) or "nothing"))
    if have_clamp and not want_clamp:
        problems.append("The --strict UDP clamp is in place and you asked to remove it.")
        actions.append("remove the UDP clamp")

    insert_at = 0
    for r in rules:
        if is_api(r):
            insert_at += 1
        else:
            break

    if shadowed:
        problems.append("{0} customers are matched by an earlier rule, so the torrent rules "
                        "are never reached for them.".format(shadowed))
        actions.append("move the torrent rules above the customer rules "
                       "(position {0} to {1})".format(first_guard, insert_at))

    for offset, rule in enumerate(guard_rules(hole, want_clamp, allow_ips, allow_ports,
                                              passthrough, clamp_ports)):
        rules.insert(insert_at + offset, rule)

    if want_clamp:
        routed = sum(len(rule_users(r)) for r in rules if rule_users(r))
        if routed:
            problems.append("{0} customers are routed through a specific outbound. Voice and "
                            "video allowed past the UDP clamp will leave through '{1}' "
                            "instead, because Xray stops at the first matching rule."
                            .format(routed, passthrough))

    # Nothing detected, nothing to change: say so rather than inventing work.
    if before == xray and not inbound_fixes:
        problems, actions = [], []

    return {"db": db_path, "problems": problems, "actions": actions,
            "inbound_fixes": inbound_fixes, "xray_before": before, "xray_after": xray,
            "template_key": template_key,
            "routing_note": ("This writes the routing config for the first time. It is the "
                             "one the panel is already running, so nothing about routing "
                             "changes except the torrent rules - the same thing pressing "
                             "Save in the panel would do." if seeded else None)}


def _service(action):
    """Run x-ui start/stop/restart, whichever mechanism this box uses."""
    for cmd in (["x-ui", action], ["systemctl", action, "x-ui"]):
        try:
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if r.returncode == 0:
                return " ".join(cmd)
        except (OSError, FileNotFoundError):
            continue
    return None


def integrity(path):
    """(ok, detail). Never assume a database file is usable just because it exists."""
    try:
        con = sqlite3.connect(path)
        try:
            result = con.execute("pragma integrity_check").fetchone()[0]
            tables = [r[0] for r in con.execute(
                "select name from sqlite_master where type='table'")]
        finally:
            con.close()
    except Exception as e:
        return False, "unreadable ({0})".format(e)
    if result != "ok":
        return False, result
    if "inbounds" not in tables or "settings" not in tables:
        return False, "not an x-ui database (missing core tables)"
    return True, "ok"


def snapshot(db, dest):
    """Consistent copy of a LIVE SQLite database.

    A plain file copy is not safe here. If x-ui writes while the bytes are being
    read, the copy is torn - and a torn backup is worse than none, because it
    still looks restorable. SQLite's own backup API takes a proper snapshot.
    """
    src = sqlite3.connect(db)
    dst = sqlite3.connect(dest)
    try:
        with dst:
            src.backup(dst)
    finally:
        dst.close()
        src.close()
    ok, detail = integrity(dest)
    if not ok:
        try:
            os.remove(dest)
        except OSError:
            pass
        raise RuntimeError("backup failed its own integrity check ({0}); "
                           "nothing was changed".format(detail))
    return dest


def apply_plan(p, do_restart=True):
    db = p["db"]
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = "{0}.torrentguard-{1}.bak".format(db, stamp)
    snapshot(db, bak)
    print("  backup saved and verified: {0}".format(bak))

    con = sqlite3.connect(db)
    try:
        for ib_id, name, sniff_json in p["inbound_fixes"]:
            con.execute("update inbounds set sniffing=? where id=?", (sniff_json, ib_id))
        if p["xray_after"] is not None:
            # UPDATE alone silently changes nothing when the row does not exist yet,
            # which is exactly the case on a panel where Routing was never saved.
            key = p.get("template_key") or TEMPLATE_KEY
            value = json.dumps(p["xray_after"])
            if con.execute("update settings set value=? where key=?", (value, key)).rowcount == 0:
                con.execute("insert into settings (key, value) values (?, ?)", (key, value))
                print("  saved the routing config for the first time")
        con.commit()
    finally:
        con.close()
    print("  database updated")

    if do_restart:
        for cmd in (["x-ui", "restart"], ["systemctl", "restart", "x-ui"]):
            try:
                r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                if r.returncode == 0:
                    print("  restarted x-ui with: {0}".format(" ".join(cmd)))
                    return bak
            except (OSError, FileNotFoundError):
                continue
        print("  could not restart x-ui automatically - run: x-ui restart")
    else:
        print("  not restarted; changes take effect after: x-ui restart")
    return bak


def restore(db, which=None):
    baks = sorted(glob.glob(db + ".torrentguard-*.bak"))
    if not baks and not which:
        sys.exit("no backup found next to {0}".format(db))
    src = which if which and which is not True else baks[-1]
    if not os.path.exists(src):
        sys.exit("not found: {0}".format(src))

    # Check the backup BEFORE overwriting anything. Writing a damaged file over a
    # working database is how a reversible change becomes an outage.
    ok, detail = integrity(src)
    if not ok:
        sys.exit("Refusing to restore: {0} is damaged ({1}).\n"
                 "Your current database has NOT been touched.\n"
                 "Other backups available:\n  {2}".format(
                     src, detail, "\n  ".join(baks) or "(none)"))
    print("backup checks out: {0}".format(src))

    # x-ui holds the file open, and any -wal / -shm left behind by the running
    # database would be replayed on top of the restored file and corrupt it.
    stopped = _service("stop")
    print("stopped x-ui" if stopped else "could not stop x-ui - continuing, but "
          "stop it yourself if this fails")

    safety = "{0}.before-restore-{1}".format(
        db, datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
    try:
        shutil.copy2(db, safety)
        print("current database kept at: {0}".format(safety))
    except OSError:
        safety = None

    shutil.copy2(src, db)
    for side in ("-wal", "-shm", "-journal"):
        if os.path.exists(db + side):
            os.remove(db + side)
            print("removed stale {0}{1}".format(os.path.basename(db), side))

    ok, detail = integrity(db)
    if not ok:
        if safety:
            shutil.copy2(safety, db)
            print("restore produced a damaged database ({0}); put the previous one "
                  "back".format(detail))
        _service("start")
        sys.exit(1)

    print("restored {0} -> {1}".format(src, db))
    print("started x-ui with: {0}".format(_service("start") or "(run: x-ui start)"))


def show_state(db_path):
    """Print what the server is doing right now, without judging it."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    print("Inbounds")
    for ib in con.execute("select id, tag, remark, port, sniffing from inbounds order by id"):
        sn = loads(ib["sniffing"], {})
        if not sn.get("enabled"):
            state = "NOT inspected - torrents cannot be detected here"
        elif sn.get("metadataOnly"):
            state = "headers only - torrents cannot be detected here"
        else:
            state = "inspected" + ("" if sn.get("routeOnly") else "  (routeOnly is off)")
        print("  [{0}] port {1:<6} {2:<22} {3}".format(
            ib["id"], ib["port"], (ib["remark"] or ib["tag"] or "")[:22], state))

    xray, _key, source = load_template(con)
    con.close()
    if xray is None:
        print("")
        print("Routing: nothing saved, and the running config could not be read.")
        return
    if source not in (None, "saved"):
        print("")
        print("Routing: nothing saved - the panel is running its built-in defaults.")
        print("Shown below as read from {0}.".format(source))
    holes = [str(o.get("tag")) for o in xray.get("outbounds", [])
             if str(o.get("protocol", "")).lower() == "blackhole"]
    print("")
    print("Routing rules, in the order Xray checks them")
    hit = False
    for i, r in enumerate(xray.get("routing", {}).get("rules", [])):
        users = rule_users(r)
        if is_api(r):
            what = "panel api"
        elif is_bt(r):
            what = "TORRENTS, plaintext -> {0}".format(r.get("outboundTag"))
        elif is_discovery_ports(r):
            what = "tracker + DHT ports -> {0}".format(r.get("outboundTag"))
        elif is_tracker_domains(r):
            what = "tracker + DHT hostnames -> {0}".format(r.get("outboundTag"))
        elif is_udp_allow(r):
            what = "UDP to {0} -> {1} (allowed)".format(
                ",".join(r.get("ip") or [])[:34], r.get("outboundTag"))
        elif is_udp_clamp(r):
            what = "all other UDP -> {0}".format(r.get("outboundTag"))
        elif users:
            what = "{0} customers -> {1}".format(len(users), r.get("outboundTag"))
        else:
            what = "{0} -> {1}".format(
                ",".join(r.get("ip") or r.get("domain") or ["other"])[:30], r.get("outboundTag"))
        note = ""
        if is_guard(r):
            note = "  <-- torrent guard"
            if str(r.get("outboundTag")) not in holes:
                note += " (NOT a blackhole - it is being forwarded)"
            hit = True
        elif users and not hit:
            note = "  <-- these customers never reach the torrent rule"
        print("  [{0}] {1}{2}".format(i, what, note))
    if not hit:
        print("  (no torrent rules present)")


def rule_label(rule):
    """One short phrase naming what a rule is for, used in the before/after list."""
    if is_bt(rule):
        return "bittorrent, plaintext"
    if is_discovery_ports(rule):
        return "tracker + DHT ports"
    if is_tracker_domains(rule):
        return "tracker + DHT hostnames"
    if is_udp_allow(rule):
        return "udp allowed"
    if is_udp_clamp(rule):
        return "udp clamp"
    users = rule_users(rule)
    return "{0} customers".format(len(users)) if users else "other"


def show_diff(p):
    """Spell out the exact edits, so nothing is applied that was not shown first."""
    print("\nExact changes:")
    for ib_id, name, sniff_json in p["inbound_fixes"]:
        print("  inbounds[id={0}].sniffing".format(ib_id))
        print("    {0}".format(sniff_json))
    if p["xray_before"] is not None:
        b = [(("api" if is_api(r) else r.get("outboundTag")), rule_label(r))
             for r in (p["xray_before"].get("routing") or {}).get("rules", [])]
        a = [(("api" if is_api(r) else r.get("outboundTag")), rule_label(r))
             for r in p["xray_after"]["routing"]["rules"]]
        if b != a:
            print("  routing rule order")
            for i in range(max(len(b), len(a))):
                lhs = "{0} ({1})".format(*b[i]) if i < len(b) else ""
                rhs = "{0} ({1})".format(*a[i]) if i < len(a) else ""
                mark = "  " if lhs == rhs else "->"
                print("    [{0}] {1:<34} {2} {3}".format(i, lhs, mark, rhs))
        ob = [o.get("tag") for o in p["xray_before"].get("outbounds", [])]
        oa = [o.get("tag") for o in p["xray_after"].get("outbounds", [])]
        if ob != oa:
            print("  outbounds: {0} -> {1}".format(ob, oa))
        else:
            print("  outbounds: unchanged {0}".format(oa))
    print("\n  Customers, quotas, usage and per-customer routing are not touched.")


def main():
    ap = argparse.ArgumentParser(
        prog="block-torrents",
        description="Stop BitTorrent on a 3X-UI server. Run on the server, as root.")
    ap.add_argument("--apply", action="store_true", help="make the changes (default: just look)")
    ap.add_argument("--show", action="store_true",
                    help="print the current sniffing and rule order, then exit")
    ap.add_argument("--db", help="path to x-ui.db if it is somewhere unusual")
    ap.add_argument("--strict", action="store_true",
                    help="also block all UDP except DNS, NTP, QUIC and STUN. This is what "
                         "stops uTP, but it breaks games and voice chat. Stays on once set")
    ap.add_argument("--no-strict", action="store_true",
                    help="remove the --strict UDP clamp")
    ap.add_argument("--allow-udp-ip", metavar="CIDR,...",
                    help="destinations allowed on any UDP port under --strict. Defaults to "
                         "Discord's voice range ({0}). Give a comma-separated list to "
                         "replace it".format(",".join(ALLOW_UDP_IPS)))
    ap.add_argument("--allow-udp-port", metavar="PORTS",
                    help="UDP ports allowed to every destination under --strict "
                         "(default {0})".format(ESSENTIAL_UDP_PORTS))
    ap.add_argument("--no-restart", action="store_true", help="do not restart x-ui afterwards")
    ap.add_argument("--restore", nargs="?", const=True, metavar="BACKUP",
                    help="undo, using the newest backup or one you name")
    ap.add_argument("-V", "--version", action="version",
                    version="block-torrents {0}".format(__version__))
    args = ap.parse_args()

    db = find_db(args.db)
    if args.show:
        show_state(db)
        return 0
    if args.restore:
        restore(db, None if args.restore is True else args.restore)
        return 0

    if args.apply and hasattr(os, "geteuid") and os.geteuid() != 0:
        sys.exit("--apply needs root: sudo python3 block-torrents.py --apply")

    print("Reading {0}".format(db))
    allow_ips = ([x.strip() for x in args.allow_udp_ip.split(",") if x.strip()]
                 if args.allow_udp_ip else None)
    p = plan(db, strict=args.strict, drop_strict=args.no_strict,
             allow_ips=allow_ips, allow_ports=args.allow_udp_port)

    if not p["problems"]:
        print("\nTorrents are already blocked properly. Nothing to do.")
        return 0

    print("\nProblems found:")
    for i, prob in enumerate(p["problems"], 1):
        print("  {0}. {1}".format(i, prob))

    if p["routing_note"]:
        print("\n" + p["routing_note"])

    if not p["actions"]:
        return 1

    print("\nWhat would be changed:")
    for a in p["actions"]:
        print("  - {0}".format(a))
    show_diff(p)

    if not args.apply:
        print("\nNothing was changed. To apply:")
        print("  sudo python3 block-torrents.py --apply")
        return 1

    print("\nApplying:")
    apply_plan(p, do_restart=not args.no_restart)
    after = plan(db, strict=args.strict, drop_strict=args.no_strict,
                 allow_ips=allow_ips, allow_ports=args.allow_udp_port)
    print("\nRe-checked: " + ("all clear, torrents are blocked."
                              if not after["problems"]
                              else "{0} problem(s) remain".format(len(after["problems"]))))
    placed = ((p["xray_after"] or {}).get("routing") or {}).get("rules", [])
    if not any(is_udp_clamp(r) for r in placed):
        access = (((p["xray_after"] or {}).get("log") or {}).get("access")) or ACCESS_LOG
        print("")
        print("These rules drop torrent traffic, but a client that already knows its peers")
        print("keeps trying over encrypted UDP on random ports, and no rule can pick that")
        print("out of ordinary traffic. Two ways to finish the job:")
        print("")
        print("  1. Cut the customer off when they are caught. Every attempt above is now")
        print("     logged against their name in {0}.".format(access))
        print("       sudo python3 extras/torrent-watch.py --install")
        print("     Nothing else is affected - voice, games and QUIC keep working.")
        print("")
        print("  2. Close UDP outright:  --strict")
        print("     Blunter, and it needs an allowlist for anything using arbitrary UDP.")
    print("To undo:  sudo python3 block-torrents.py --restore")
    return 0


if __name__ == "__main__":
    sys.exit(main())
