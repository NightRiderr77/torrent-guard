#!/usr/bin/env python3
"""torrent-guard - audit and repair BitTorrent blocking on Xray / 3X-UI panels.

Most panels already carry a routing rule that looks like it blocks torrents:

    { "type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked" }

It is very easy for that rule to be completely inert, and the panel gives you no
hint that it is. This tool checks the two things that actually decide whether it
works, and can fix both:

  1. Sniffing must be ON for the inbound. `protocol` matching is driven by the
     sniffer. With "sniffing": {"enabled": false} there is no protocol metadata,
     so the rule matches nothing at all - ever.

  2. The rule must be ordered ABOVE any rule that matches your users. Xray
     routing is first-match-wins, so a per-user rule (routing someone through a
     specific outbound) placed earlier will win, and the torrent rule is never
     evaluated for that user.

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import argparse
import copy
import datetime
import http.cookiejar
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

__version__ = "1.1.0"

# routeOnly keeps the original destination and uses the sniffed result purely for
# routing decisions. That matters: plain destOverride rewrites the destination to
# the sniffed domain, which breaks setups that deliberately present a different
# SNI to the network. metadataOnly must stay False, or the payload is never read
# and BitTorrent is never identified.
SAFE_SNIFFING = {
    "enabled": True,
    "destOverride": ["http", "tls", "quic"],
    "metadataOnly": False,
    "routeOnly": True,
}
BT_PROTOCOLS = ["bittorrent"]

# Sniffing only ever names PLAINTEXT BitTorrent over TCP, and that is a small and
# shrinking share of real torrent traffic. Clients turn on protocol encryption
# (MSE/PE) by default, so the handshake is a Diffie-Hellman key with no
# "BitTorrent protocol" string left to match; and most peer traffic is uTP over
# UDP, which Xray does not content-sniff at all, so a protocol rule can never
# match it. Verified against Xray 26.1.23 - extras/verify-blocking.py reproduces
# all of it in about ten seconds.
#
# Identifying peer traffic is therefore a losing game. What works is cutting off
# peer DISCOVERY: a client that cannot reach a tracker or the DHT has no peer
# list, and encryption does not help it find one.
DISCOVERY_PORTS = "6881-6889,6969,1337,2710,51413"

# Anchored at the start of a label on purpose: "tracker.x.com" is caught,
# "mytracker.x.com" and "package-tracker.com" are not.
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

# strict only: every UDP port except 53 (DNS), 123 (NTP), 443 (QUIC) and
# 3478-3481 (STUN). This is what finally kills uTP, and it also breaks games and
# voice chat, which is why it is opt-in.
UDP_EXCEPT_ESSENTIAL = "1-52,54-122,124-442,444-3477,3482-65535"

OK, WARN, BAD = "ok", "warn", "bad"


# --------------------------------------------------------------------------- #
# Analysis. Pure functions over plain dicts, so they can be tested without a
# panel anywhere near them (see `selftest`).
# --------------------------------------------------------------------------- #
def _rule_users(rule):
    u = rule.get("user")
    if isinstance(u, list):
        return [str(x).strip() for x in u if str(x).strip()]
    if isinstance(u, str) and u.strip():
        return [x.strip() for x in u.split(",") if x.strip()]
    return []


def _is_api_rule(rule):
    tags = rule.get("inboundTag") or []
    if isinstance(tags, str):
        tags = [tags]
    return "api" in [str(t) for t in tags] or str(rule.get("outboundTag")) == "api"


def _is_bt_rule(rule):
    p = rule.get("protocol") or []
    if isinstance(p, str):
        p = [p]
    return "bittorrent" in [str(x).lower() for x in p]


def _is_discovery_ports_rule(rule):
    return str(rule.get("port") or "") == DISCOVERY_PORTS and not rule.get("domain")


def _is_tracker_domain_rule(rule):
    return DHT_SENTINEL in (rule.get("domain") or [])


def _is_udp_clamp_rule(rule):
    return (str(rule.get("network") or "").lower() == "udp"
            and str(rule.get("port") or "") == UDP_EXCEPT_ESSENTIAL)


def _is_guard_rule(rule):
    """Any rule this tool owns."""
    return (_is_bt_rule(rule) or _is_discovery_ports_rule(rule)
            or _is_tracker_domain_rule(rule) or _is_udp_clamp_rule(rule))


def guard_rules(hole, strict=False):
    """The rules that stop torrents, in the order Xray must check them."""
    out = [
        {"type": "field", "protocol": list(BT_PROTOCOLS), "outboundTag": hole,
         "enabled": True},
        {"type": "field", "port": DISCOVERY_PORTS, "outboundTag": hole, "enabled": True},
        {"type": "field", "domain": list(TRACKER_DOMAINS), "outboundTag": hole,
         "enabled": True},
    ]
    if strict:
        out.append({"type": "field", "network": "udp", "port": UDP_EXCEPT_ESSENTIAL,
                    "outboundTag": hole, "enabled": True})
    return out


def blackhole_tags(xray):
    return [
        str(o.get("tag"))
        for o in (xray.get("outbounds") or [])
        if str(o.get("protocol", "")).lower() == "blackhole" and o.get("tag")
    ]


def audit(xray, inbounds, strict=False):
    """Return a list of findings. An empty list means torrents are genuinely blocked."""
    findings = []
    rules = (xray.get("routing") or {}).get("rules") or []
    holes = blackhole_tags(xray)

    # --- inbound sniffing --------------------------------------------------- #
    for ib in inbounds:
        tag = ib.get("tag") or "inbound-{0}".format(ib.get("id"))
        sn = ib.get("sniffing")
        if isinstance(sn, str):
            try:
                sn = json.loads(sn)
            except Exception:
                sn = {}
        sn = sn or {}
        if not sn.get("enabled"):
            findings.append({
                "code": "sniffing-off", "severity": BAD, "where": tag,
                "detail": "sniffing is disabled, so no protocol is ever detected and "
                          "the bittorrent rule cannot match any traffic on this inbound",
                "fix": "enable sniffing (routeOnly, so the destination is left alone)",
            })
        elif sn.get("metadataOnly"):
            findings.append({
                "code": "sniffing-metadata-only", "severity": BAD, "where": tag,
                "detail": "metadataOnly skips payload inspection, and the BitTorrent "
                          "handshake is only visible in the payload",
                "fix": "set metadataOnly to false",
            })

    # --- a blackhole to send it to ------------------------------------------ #
    if not holes:
        findings.append({
            "code": "no-blackhole-outbound", "severity": BAD, "where": "outbounds",
            "detail": "no blackhole outbound exists, so there is nowhere to drop torrent traffic",
            "fix": 'add {"tag": "blocked", "protocol": "blackhole"}',
        })

    # --- peer discovery ----------------------------------------------------- #
    # These come first because they hold whether or not a bittorrent rule exists,
    # and the check below returns early when it does not.
    if not any(_is_discovery_ports_rule(r) for r in rules):
        findings.append({
            "code": "no-discovery-port-rule", "severity": BAD, "where": "routing.rules",
            "detail": "nothing blocks the tracker and DHT ports, so clients still find "
                      "peers and still torrent over UDP, which sniffing never sees",
            "fix": "block ports {0}".format(DISCOVERY_PORTS),
        })

    if not any(_is_tracker_domain_rule(r) for r in rules):
        findings.append({
            "code": "no-tracker-domain-rule", "severity": BAD, "where": "routing.rules",
            "detail": "the DHT bootstrap nodes and tracker hostnames are reachable, so a "
                      "client can fetch a peer list and encrypt everything after that",
            "fix": "block the DHT bootstrap nodes and tracker hostnames",
        })

    # Only when asked for: the clamp is a deliberate trade, not a defect, so a
    # plain check must not nag about something it should never turn on by itself.
    if strict and not any(_is_udp_clamp_rule(r) for r in rules):
        findings.append({
            "code": "no-udp-clamp", "severity": BAD, "where": "routing.rules",
            "detail": "uTP over UDP still works; peers listen on random high ports, so "
                      "only a UDP clamp stops it",
            "fix": "block all UDP except DNS, NTP, QUIC and STUN",
        })

    # --- the rule itself ---------------------------------------------------- #
    bt_idx = next((i for i, r in enumerate(rules) if _is_bt_rule(r)), None)
    if bt_idx is None:
        findings.append({
            "code": "no-bittorrent-rule", "severity": BAD, "where": "routing.rules",
            "detail": "no routing rule matches protocol bittorrent",
            "fix": "insert a bittorrent rule pointing at the blackhole outbound",
        })
        return findings

    bt = rules[bt_idx]
    if bt.get("enabled") is False:
        findings.append({
            "code": "bittorrent-rule-disabled", "severity": BAD,
            "where": "routing.rules[{0}]".format(bt_idx),
            "detail": "the bittorrent rule exists but is switched off",
            "fix": "enable the rule",
        })
    if holes and str(bt.get("outboundTag")) not in holes:
        findings.append({
            "code": "bittorrent-rule-not-blackholed", "severity": BAD,
            "where": "routing.rules[{0}]".format(bt_idx),
            "detail": "the bittorrent rule sends traffic to {0!r}, which is not a blackhole "
                      "outbound - torrents are being forwarded, not dropped".format(bt.get("outboundTag")),
            "fix": "point it at {0!r}".format(holes[0]),
        })

    # --- ordering: the quiet killer ----------------------------------------- #
    shadowed, first_idx = 0, None
    for i, r in enumerate(rules[:bt_idx]):
        if _is_api_rule(r):
            continue
        users = _rule_users(r)
        if users:
            shadowed += len(users)
            if first_idx is None:
                first_idx = i
    if shadowed:
        findings.append({
            "code": "bittorrent-rule-shadowed", "severity": BAD,
            "where": "routing.rules[{0}]".format(bt_idx),
            "detail": "{0} client entries match an earlier rule (from index {1}) and are routed "
                      "before the bittorrent rule is ever reached - those clients can torrent "
                      "freely".format(shadowed, first_idx),
            "fix": "move the bittorrent rule above every user-matching rule",
        })
    return findings


# --------------------------------------------------------------------------- #
# Repair
# --------------------------------------------------------------------------- #
def repair_xray(xray, strict=False, drop_strict=False):
    """Return (new_xray, [descriptions of what changed]). The input is not mutated."""
    x = copy.deepcopy(xray)
    changes = []
    x.setdefault("outbounds", [])
    x.setdefault("routing", {}).setdefault("rules", [])
    rules = x["routing"]["rules"]

    holes = blackhole_tags(x)
    if not holes:
        tag = "blocked"
        existing = set(str(o.get("tag")) for o in x["outbounds"])
        while tag in existing:
            tag += "_bh"
        x["outbounds"].append({"tag": tag, "protocol": "blackhole", "settings": {}})
        holes = [tag]
        changes.append("added blackhole outbound {0!r}".format(tag))
    hole = holes[0]

    # Everything this tool owns comes out, is rebuilt correctly, and goes back as
    # one block above the customer rules. Rebuilding beats patching in place: one
    # shape to reason about, and a second run is a genuine no-op.
    existing = [(i, r) for i, r in enumerate(rules) if _is_guard_rule(r)]
    first_guard = existing[0][0] if existing else None
    have_bt = any(_is_bt_rule(r) for _, r in existing)
    have_ports = any(_is_discovery_ports_rule(r) for _, r in existing)
    have_domains = any(_is_tracker_domain_rule(r) for _, r in existing)
    have_clamp = any(_is_udp_clamp_rule(r) for _, r in existing)

    for i, _ in reversed(existing):
        rules.pop(i)

    if not have_bt:
        changes.append("added a bittorrent routing rule")
    else:
        bt = [r for _, r in existing if _is_bt_rule(r)][0]
        if str(bt.get("outboundTag")) != hole:
            changes.append("repointed the bittorrent rule to {0!r}".format(hole))
        if bt.get("enabled") is False:
            changes.append("re-enabled the bittorrent rule")
    if not have_ports:
        changes.append("blocked the tracker and DHT ports ({0})".format(DISCOVERY_PORTS))
    if not have_domains:
        changes.append("blocked the DHT bootstrap nodes and tracker hostnames")

    # Sticky: a later plain run must not quietly undo a deliberate choice.
    want_clamp = (strict or have_clamp) and not drop_strict
    if want_clamp and not have_clamp:
        changes.append("blocked all UDP except DNS, NTP, QUIC and STUN (strict)")
    if have_clamp and not want_clamp:
        changes.append("removed the UDP clamp")

    # Slot the block directly after the api rules, which must stay first, and
    # therefore above every user-matching rule.
    insert_at = 0
    for i, r in enumerate(rules):
        if _is_api_rule(r):
            insert_at = i + 1
        else:
            break
    if first_guard is not None and first_guard != insert_at:
        changes.append("moved the torrent rules from index {0} to {1}, above the user "
                       "rules".format(first_guard, insert_at))
    for offset, rule in enumerate(guard_rules(hole, want_clamp)):
        rules.insert(insert_at + offset, rule)
    return x, changes


def repair_inbound_sniffing(inbound):
    ib = copy.deepcopy(inbound)
    sn = ib.get("sniffing")
    if isinstance(sn, str):
        try:
            sn = json.loads(sn)
        except Exception:
            sn = {}
    sn = dict(sn or {})
    before = json.dumps(sn, sort_keys=True)
    sn.update(SAFE_SNIFFING)
    if json.dumps(sn, sort_keys=True) == before:
        return ib, False
    ib["sniffing"] = json.dumps(sn) if isinstance(inbound.get("sniffing"), str) else sn
    return ib, True


# --------------------------------------------------------------------------- #
# Panel client
# --------------------------------------------------------------------------- #
class PanelError(RuntimeError):
    pass


class Panel:
    def __init__(self, cfg, insecure=False, timeout=30):
        self.name = cfg.get("name") or cfg.get("host", "panel")
        host = str(cfg["host"]).strip()
        port = int(cfg.get("port", 2053))
        base_path = str(cfg.get("web_base_path") or "/").strip()
        if not base_path.startswith("/"):
            base_path = "/" + base_path
        base_path = base_path.rstrip("/")
        scheme = cfg.get("scheme") or "https"
        self.base = "{0}://{1}:{2}{3}".format(scheme, host, port, base_path)
        self.username = cfg.get("username") or ""
        self.password = cfg.get("password") or ""
        self.api_token = cfg.get("api_token") or ""
        self.timeout = timeout
        jar = http.cookiejar.CookieJar()
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar),
            urllib.request.HTTPSHandler(context=ctx),
        )
        self.csrf = ""

    def _req(self, path, data=None, form=None, headers=None, method=None):
        url = path if path.startswith("http") else self.base + path
        h = {"Accept": "application/json",
             "User-Agent": "torrent-guard/{0}".format(__version__)}
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        elif data is not None:
            body = json.dumps(data).encode()
            h["Content-Type"] = "application/json"
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        if self.api_token:
            h["Authorization"] = "Bearer {0}".format(self.api_token)
        h.update(headers or {})
        req = urllib.request.Request(
            url, data=body, headers=h,
            method=method or ("POST" if body is not None else "GET"))
        try:
            resp = self.opener.open(req, timeout=self.timeout)
            try:
                raw = resp.read().decode("utf-8", "replace")
                status = resp.getcode()
            finally:
                resp.close()
        except urllib.error.HTTPError as e:
            raw, status = e.read().decode("utf-8", "replace"), e.code
        except Exception as e:
            raise PanelError("{0}: cannot reach {1} ({2}: {3})".format(
                self.name, url, type(e).__name__, e))
        try:
            return status, json.loads(raw)
        except Exception:
            return status, raw

    def login(self):
        st, j = self._req("/csrf-token")
        if isinstance(j, dict) and isinstance(j.get("obj"), str):
            self.csrf = j["obj"]
        if not self.username or not self.password:
            raise PanelError("{0}: username and password are required to read routing "
                             "settings".format(self.name))
        st, j = self._req("/login", form={"username": self.username, "password": self.password})
        if not (isinstance(j, dict) and j.get("success")):
            msg = j.get("msg") if isinstance(j, dict) else str(j)[:120]
            raise PanelError("{0}: panel login failed ({1})".format(self.name, msg))

    def _xray_endpoint(self, suffix, **kw):
        last = (None, None)
        for p in ("/panel/api/xray/" + suffix, "/panel/xray/" + suffix):
            st, j = self._req(p, **kw)
            if st != 404:
                return st, j
            last = (st, j)
        return last

    def get_xray(self):
        st, j = self._xray_endpoint("", method="POST")
        if not (isinstance(j, dict) and j.get("success")):
            raise PanelError("{0}: could not read xray settings (HTTP {1})".format(self.name, st))
        obj = j.get("obj")
        if isinstance(obj, str):
            obj = json.loads(obj)
        setting = (obj or {}).get("xraySetting")
        if isinstance(setting, str):
            setting = json.loads(setting)
        if not isinstance(setting, dict):
            raise PanelError("{0}: xray settings came back in an unexpected shape".format(self.name))
        return setting

    def put_xray(self, xray):
        st, j = self._xray_endpoint("update", form={"xraySetting": json.dumps(xray)})
        if not (isinstance(j, dict) and j.get("success")):
            msg = j.get("msg") if isinstance(j, dict) else str(j)[:160]
            raise PanelError("{0}: saving xray settings failed ({1})".format(self.name, msg))

    def get_inbounds(self):
        st, j = self._req("/panel/api/inbounds/list")
        if not (isinstance(j, dict) and j.get("success") and isinstance(j.get("obj"), list)):
            st, j = self._req("/panel/inbound/list", method="POST")
        if not (isinstance(j, dict) and j.get("success") and isinstance(j.get("obj"), list)):
            raise PanelError("{0}: could not list inbounds (HTTP {1})".format(self.name, st))
        return j["obj"]

    def put_inbound(self, ib):
        keys = ("id", "up", "down", "total", "remark", "enable", "expiryTime", "listen",
                "port", "protocol", "settings", "streamSettings", "sniffing", "allocate", "tag")
        payload = dict((k, ib.get(k)) for k in keys if ib.get(k) is not None)
        for k in ("settings", "streamSettings", "sniffing", "allocate"):
            if k in payload and not isinstance(payload[k], str):
                payload[k] = json.dumps(payload[k])
        st, j = self._req("/panel/api/inbounds/update/{0}".format(ib["id"]), data=payload)
        if not (isinstance(j, dict) and j.get("success")):
            msg = j.get("msg") if isinstance(j, dict) else str(j)[:160]
            raise PanelError("{0}: updating inbound {1} failed ({2})".format(
                self.name, ib.get("id"), msg))


# --------------------------------------------------------------------------- #
# Presentation
# --------------------------------------------------------------------------- #
class C:
    def __init__(self, on):
        self.on = on

    def _w(self, s, code):
        return "\033[{0}m{1}\033[0m".format(code, s) if self.on else s

    def red(self, s):
        return self._w(s, "31")

    def green(self, s):
        return self._w(s, "32")

    def yellow(self, s):
        return self._w(s, "33")

    def dim(self, s):
        return self._w(s, "2")

    def bold(self, s):
        return self._w(s, "1")


def load_config(path):
    if not os.path.exists(path):
        sys.exit("config not found: {0}\n"
                 "Copy panels.example.json to {0} and fill it in.".format(path))
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    panels = cfg.get("panels") if isinstance(cfg, dict) else cfg
    if not isinstance(panels, list) or not panels:
        sys.exit('{0}: expected a non-empty "panels" array'.format(path))
    return panels


def backup(dirname, name, xray):
    os.makedirs(dirname, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(name))
    p = os.path.join(dirname, "{0}-{1}.json".format(safe, stamp))
    with open(p, "w", encoding="utf-8") as f:
        json.dump(xray, f, indent=2)
    return p


def run(args):
    c = C(sys.stdout.isatty() and not args.no_color)
    if args.insecure:
        # Opt-in only, and never silent: a panel reached without certificate
        # verification can be impersonated, and this tool sends it credentials.
        print(c.yellow("warning: --insecure disables TLS verification. Your panel password "
                       "is sent over a connection that could be intercepted. Prefer a real "
                       "certificate, or pin the panel behind a trusted CA."), file=sys.stderr)
    panels = load_config(args.config)
    if args.only:
        wanted = set(s.strip().lower() for s in args.only.split(","))
        panels = [p for p in panels
                  if str(p.get("name", p.get("host", ""))).lower() in wanted]
        if not panels:
            sys.exit("no panel in {0} matched --only {1}".format(args.config, args.only))

    report, worst = [], 0
    for pcfg in panels:
        entry = {"panel": pcfg.get("name") or pcfg.get("host"),
                 "findings": [], "changes": [], "error": None}
        try:
            panel = Panel(pcfg, insecure=args.insecure, timeout=args.timeout)
            panel.login()
            xray = panel.get_xray()
            inbounds = panel.get_inbounds()
            entry["findings"] = audit(xray, inbounds, strict=args.strict)
            entry["inbounds"] = len(inbounds)

            if args.command == "apply" and entry["findings"]:
                entry["backup"] = backup(args.backup_dir, entry["panel"], xray)
                new_xray, changes = repair_xray(
                    xray, strict=args.strict, drop_strict=args.no_strict)
                if changes:
                    if not args.dry_run:
                        panel.put_xray(new_xray)
                    entry["changes"].extend(changes)
                for ib in inbounds:
                    fixed, changed = repair_inbound_sniffing(ib)
                    if changed:
                        if not args.dry_run:
                            panel.put_inbound(fixed)
                        entry["changes"].append("enabled sniffing on {0}".format(
                            ib.get("tag") or ib.get("id")))
                entry["findings_after"] = audit(
                    new_xray, [repair_inbound_sniffing(i)[0] for i in inbounds])
        except PanelError as e:
            entry["error"] = str(e)
        except Exception as e:  # one bad panel must not abort the rest
            entry["error"] = "{0}: {1}".format(type(e).__name__, e)
        report.append(entry)
        worst = max(worst, 2 if entry["error"] else (1 if entry["findings"] else 0))

    if args.json:
        print(json.dumps({"version": __version__, "command": args.command,
                          "panels": report}, indent=2))
        return 0 if worst == 0 else 1

    for e in report:
        print()
        print(c.bold("-- {0}".format(e["panel"])))
        if e["error"]:
            print("   " + c.red("unreachable: ") + e["error"])
            continue
        if not e["findings"]:
            print("   " + c.green("PASS") + c.dim("  torrents are blocked  ({0} inbounds "
                                                  "checked)".format(e.get("inbounds", 0))))
            continue
        for f in e["findings"]:
            mark = c.red("FAIL") if f["severity"] == BAD else c.yellow("WARN")
            print("   {0}  {1}  {2}".format(mark, c.bold(f["code"]), c.dim(f["where"])))
            print("         " + f["detail"])
            if args.command != "apply":
                print("         " + c.dim("fix: " + f["fix"]))
        for ch in e["changes"]:
            print("   " + c.green("FIXED") + " " + ch)
        if args.command == "apply":
            if e.get("backup"):
                print("   " + c.dim("previous routing saved to " + e["backup"]))
            left = e.get("findings_after") or []
            print("   " + (c.green("now clean") if not left
                           else c.red("{0} finding(s) still open".format(len(left)))))

    clean = sum(1 for e in report if not e["error"] and not e["findings"])
    print()
    print(c.bold("{0}/{1} panel(s) blocking torrents correctly.".format(clean, len(report))))
    if args.command == "check" and worst:
        print(c.dim("Run with `apply` to fix. Enabling sniffing restarts Xray on that panel."))
    return 0 if worst == 0 else 1


# --------------------------------------------------------------------------- #
# Self-test: exercises the analysis and repair logic with no network at all.
# --------------------------------------------------------------------------- #
SAMPLE = {
    "xray": {
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "blocked", "protocol": "blackhole", "settings": {}},
            {"tag": "lk", "protocol": "wireguard"},
        ],
        "routing": {"rules": [
            {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
            {"type": "field", "outboundTag": "lk", "user": ["a@x-1", "b@x-2", "c@x-3"]},
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
        ]},
    },
    "inbounds": [
        {"id": 1, "tag": "in-443-tcp", "sniffing": {"enabled": False}},
        {"id": 2, "tag": "in-80-tcp", "sniffing": {"enabled": True, "metadataOnly": True}},
    ],
}


def selftest():
    fails = []

    def check(label, cond):
        print(("  PASS  " if cond else "  FAIL  ") + label)
        if not cond:
            fails.append(label)

    print("audit, against a knowingly-broken config:")
    found = audit(SAMPLE["xray"], SAMPLE["inbounds"])
    codes = [f["code"] for f in found]
    check("flags sniffing-off", "sniffing-off" in codes)
    check("flags sniffing-metadata-only", "sniffing-metadata-only" in codes)
    check("flags bittorrent-rule-shadowed", "bittorrent-rule-shadowed" in codes)
    check("counts the 3 shadowed clients",
          any("3 client entries" in f["detail"] for f in found
              if f["code"] == "bittorrent-rule-shadowed"))
    check("does not invent a missing rule", "no-bittorrent-rule" not in codes)
    check("does not invent a missing blackhole", "no-blackhole-outbound" not in codes)

    print("\nrepair:")
    fixed, changes = repair_xray(SAMPLE["xray"])
    rules = fixed["routing"]["rules"]
    bt = next(i for i, r in enumerate(rules) if _is_bt_rule(r))
    first_user = next((i for i, r in enumerate(rules) if _rule_users(r)), len(rules))
    check("bittorrent rule now precedes every user rule", bt < first_user)
    check("api rule is still first", _is_api_rule(rules[0]))
    check("no rule was lost", len(rules) == len(SAMPLE["xray"]["routing"]["rules"]) + 2)
    check("tracker and DHT ports are blocked",
          any(_is_discovery_ports_rule(r) for r in rules))
    check("tracker and DHT hostnames are blocked",
          any(_is_tracker_domain_rule(r) for r in rules))
    check("every torrent rule precedes every user rule",
          max(i for i, r in enumerate(rules) if _is_guard_rule(r)) < first_user)
    check("no UDP clamp unless it was asked for",
          not any(_is_udp_clamp_rule(r) for r in rules))
    check("repair is idempotent", repair_xray(fixed)[0]["routing"]["rules"] == rules)
    _strict = repair_xray(SAMPLE["xray"], strict=True)[0]
    check("strict adds the UDP clamp",
          any(_is_udp_clamp_rule(r) for r in _strict["routing"]["rules"]))
    check("strict survives a later plain run",
          any(_is_udp_clamp_rule(r) for r in repair_xray(_strict)[0]["routing"]["rules"]))
    check("no-strict removes the clamp",
          not any(_is_udp_clamp_rule(r) for r
                  in repair_xray(_strict, drop_strict=True)[0]["routing"]["rules"]))
    check("a clean config still audits clean under --strict",
          audit(_strict, [], strict=True) == [])
    check("reported the move", any("moved" in ch for ch in changes))
    check("the caller's config was not mutated",
          SAMPLE["xray"]["routing"]["rules"][3]["protocol"] == ["bittorrent"])

    sn_fixed = [repair_inbound_sniffing(i)[0] for i in SAMPLE["inbounds"]]
    check("sniffing enabled everywhere", all(i["sniffing"]["enabled"] for i in sn_fixed))
    check("metadataOnly cleared", all(i["sniffing"]["metadataOnly"] is False for i in sn_fixed))
    check("routeOnly set, destination left alone", all(i["sniffing"]["routeOnly"] for i in sn_fixed))
    check("re-audit is clean", audit(fixed, sn_fixed) == [])

    print("\nedge cases:")
    fresh, _ = repair_xray({})
    check("builds a working ruleset from an empty config", audit(fresh, []) == [])
    strj = [{"id": 9, "tag": "t", "sniffing": '{"enabled": false}'}]
    out, changed = repair_inbound_sniffing(strj[0])
    check("handles sniffing stored as a JSON string", changed and isinstance(out["sniffing"], str))
    check("string form still audits clean", audit(fresh, [out]) == [])
    misdirected = {"outbounds": [{"tag": "blocked", "protocol": "blackhole"},
                                 {"tag": "direct", "protocol": "freedom"}],
                   "routing": {"rules": [{"type": "field", "protocol": ["bittorrent"],
                                          "outboundTag": "direct"}]}}
    check("catches a bittorrent rule pointed at a live outbound",
          "bittorrent-rule-not-blackholed" in [f["code"] for f in audit(misdirected, [])])

    print()
    print("ALL CHECKS PASSED" if not fails else "{0} FAILED: {1}".format(len(fails), fails))
    return 0 if not fails else 1


def main():
    ap = argparse.ArgumentParser(
        prog="torrent-guard",
        description="Audit and repair BitTorrent blocking on Xray / 3X-UI panels.")
    ap.add_argument("command", nargs="?", default="check",
                    choices=["check", "apply", "selftest"],
                    help="check (read-only, default), apply (fix), selftest (no network)")
    ap.add_argument("-c", "--config", default="panels.json",
                    help="panel list (default: panels.json)")
    ap.add_argument("--only", help="comma-separated panel names to act on")
    ap.add_argument("--dry-run", action="store_true",
                    help="with apply: show what would change without saving")
    ap.add_argument("--backup-dir", default="backups",
                    help="where to save routing backups (default: backups)")
    ap.add_argument("--strict", action="store_true",
                    help="also block all UDP except DNS, NTP, QUIC and STUN. This is "
                         "what stops uTP, but it breaks games and voice chat. Stays "
                         "on once set")
    ap.add_argument("--no-strict", action="store_true", help="remove the UDP clamp")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS verification (self-signed panels)")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("-V", "--version", action="version",
                    version="torrent-guard {0}".format(__version__))
    args = ap.parse_args()
    if args.command == "selftest":
        sys.exit(selftest())
    sys.exit(run(args))


if __name__ == "__main__":
    main()
