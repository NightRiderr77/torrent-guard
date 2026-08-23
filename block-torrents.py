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

__version__ = "1.2.0"

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


def rule_users(rule):
    u = rule.get("user")
    if isinstance(u, list):
        return [str(x) for x in u if str(x).strip()]
    if isinstance(u, str) and u.strip():
        return [x.strip() for x in u.split(",") if x.strip()]
    return []


def plan(db_path):
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

    row = con.execute("select value from settings where key='xrayTemplateConfig'").fetchone()
    con.close()

    if row is None:
        return {"db": db_path, "problems": problems + [
            "No routing configuration is saved yet, so the torrent rule cannot be placed."],
            "actions": actions, "inbound_fixes": inbound_fixes,
            "xray_before": None, "xray_after": None, "routing_note":
            "Open the panel once, go to Xray Configs / Routing and press Save, then run "
            "this again. That writes the routing config this script needs to edit."}

    xray = json.loads(row["value"])
    before = copy.deepcopy(xray)
    xray.setdefault("outbounds", [])
    routing = xray.setdefault("routing", {})
    rules = routing.setdefault("rules", [])

    holes = [str(o.get("tag")) for o in xray["outbounds"]
             if str(o.get("protocol", "")).lower() == "blackhole" and o.get("tag")]
    if not holes:
        xray["outbounds"].append({"tag": "blocked", "protocol": "blackhole", "settings": {}})
        holes = ["blocked"]
        problems.append("There is no blackhole outbound, so there is nowhere to drop torrents.")
        actions.append("add a blackhole outbound called 'blocked'")
    hole = holes[0]

    bt_idx = next((i for i, r in enumerate(rules) if is_bt(r)), None)
    if bt_idx is None:
        rule = {"type": "field", "protocol": ["bittorrent"], "outboundTag": hole, "enabled": True}
        problems.append("There is no rule for torrent traffic at all.")
        actions.append("add a rule sending torrents to '{0}'".format(hole))
    else:
        rule = rules.pop(bt_idx)
        rule["type"] = rule.get("type", "field")
        rule["protocol"] = ["bittorrent"]
        if str(rule.get("outboundTag")) != hole:
            problems.append("The torrent rule forwards to '{0}' instead of dropping "
                            "it.".format(rule.get("outboundTag")))
            actions.append("point the torrent rule at '{0}'".format(hole))
            rule["outboundTag"] = hole
        if rule.get("enabled") is False:
            problems.append("The torrent rule is switched off.")
            actions.append("switch the torrent rule back on")
            rule["enabled"] = True

    insert_at = 0
    for r in rules:
        if is_api(r):
            insert_at += 1
        else:
            break

    if bt_idx is not None:
        shadowed = sum(len(rule_users(r)) for r in rules[:bt_idx] if not is_api(r))
        if shadowed:
            problems.append("{0} customers are matched by an earlier rule, so the torrent rule "
                            "is never reached for them.".format(shadowed))
            actions.append("move the torrent rule above the customer rules "
                           "(position {0} to {1})".format(bt_idx, insert_at))
    rules.insert(insert_at, rule)

    return {"db": db_path, "problems": problems, "actions": actions,
            "inbound_fixes": inbound_fixes, "xray_before": before, "xray_after": xray,
            "routing_note": None}


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
            con.execute("update settings set value=? where key='xrayTemplateConfig'",
                        (json.dumps(p["xray_after"]),))
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

    row = con.execute("select value from settings where key='xrayTemplateConfig'").fetchone()
    con.close()
    if row is None:
        print("")
        print("Routing: none saved yet.")
        return
    xray = json.loads(row["value"])
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
            what = "TORRENTS -> {0}".format(r.get("outboundTag"))
        elif users:
            what = "{0} customers -> {1}".format(len(users), r.get("outboundTag"))
        else:
            what = "{0} -> {1}".format(
                ",".join(r.get("ip") or r.get("domain") or ["other"])[:30], r.get("outboundTag"))
        note = ""
        if is_bt(r):
            note = "  <-- torrent rule"
            if str(r.get("outboundTag")) not in holes:
                note += " (NOT a blackhole - it is being forwarded)"
            hit = True
        elif users and not hit:
            note = "  <-- these customers never reach the torrent rule"
        print("  [{0}] {1}{2}".format(i, what, note))
    if not hit:
        print("  (no torrent rule present)")


def show_diff(p):
    """Spell out the exact edits, so nothing is applied that was not shown first."""
    print("\nExact changes:")
    for ib_id, name, sniff_json in p["inbound_fixes"]:
        print("  inbounds[id={0}].sniffing".format(ib_id))
        print("    {0}".format(sniff_json))
    if p["xray_before"] is not None:
        b = [(("api" if is_api(r) else r.get("outboundTag")),
              "bittorrent" if is_bt(r) else ("{0} customers".format(len(rule_users(r)))
                                             if rule_users(r) else "other"))
             for r in (p["xray_before"].get("routing") or {}).get("rules", [])]
        a = [(("api" if is_api(r) else r.get("outboundTag")),
              "bittorrent" if is_bt(r) else ("{0} customers".format(len(rule_users(r)))
                                             if rule_users(r) else "other"))
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
    p = plan(db)

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
    after = plan(db)
    print("\nRe-checked: " + ("all clear, torrents are blocked."
                              if not after["problems"]
                              else "{0} problem(s) remain".format(len(after["problems"]))))
    print("To undo:  sudo python3 block-torrents.py --restore")
    return 0


if __name__ == "__main__":
    sys.exit(main())
