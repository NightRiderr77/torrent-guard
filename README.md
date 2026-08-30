<div align="center">

<img src="https://raw.githubusercontent.com/NightRiderr77/torrent-guard/main/assets/banner.svg" alt="torrent-guard — normal traffic passes, BitTorrent is dropped" width="100%">

<br><br>

<img alt="Python 3.6+" src="https://img.shields.io/badge/Python-3.6%2B-0B0F0B?style=flat-square&logo=python&logoColor=8FD14F">
<img alt="No dependencies" src="https://img.shields.io/badge/dependencies-none-0B0F0B?style=flat-square&logo=gnubash&logoColor=8FD14F">
<img alt="No login needed" src="https://img.shields.io/badge/panel_login-not_needed-0B0F0B?style=flat-square&logo=keycdn&logoColor=8FD14F">
<img alt="MIT licence" src="https://img.shields.io/badge/licence-MIT-0B0F0B?style=flat-square">

</div>

---

Stops BitTorrent on a 3X-UI / Xray server.

Most panels already have a rule that looks like it blocks torrents. **Usually it does almost nothing**, and the panel gives you no hint. This finds out, fixes it, and can prove the fix.

## Quick start

SSH into your server and run:

```bash
curl -O https://raw.githubusercontent.com/NightRiderr77/torrent-guard/main/block-torrents.py
sudo python3 block-torrents.py
```

That only looks. It prints what is wrong and exactly what it would change. To actually fix it:

```bash
sudo python3 block-torrents.py --apply
```

Changed your mind:

```bash
sudo python3 block-torrents.py --restore
```

**No panel username, no password, no API token, no config file.** 3X-UI keeps everything in a local file (`x-ui.db`); running as root on the server is all the access this needs. It finds the file itself.

## The part everyone gets wrong

Almost everyone has exactly this in their routing config:

```json
{ "type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked" }
```

That rule is driven by **sniffing** — Xray peeks at the first bytes of a connection and names the protocol. The catch is what sniffing can actually name:

> **Sniffing only ever recognises plaintext BitTorrent over TCP.**

That is a small and shrinking share of real torrent traffic, for two reasons:

**1. Clients encrypt the handshake, by default.** uTorrent, qBittorrent and Transmission all ship with protocol encryption (MSE/PE) turned on. The first bytes are then a Diffie-Hellman key — indistinguishable from noise. There is no `BitTorrent protocol` string left to match, so the sniffer says nothing and the rule never fires.

**2. Most peer traffic is µTP, over UDP.** Xray does carry a µTP sniffer, but it only recognises the `ST_SYN` packet that opens a µTP connection, and only with exact header framing: right type byte, zero timestamp difference, a valid extension chain that consumes the packet exactly. Everything after that first packet — all the actual data — matches nothing. On a live server with the rule in place and sniffing on, torrents kept running at full speed.

So a `protocol: ["bittorrent"]` rule reliably catches one thing: a plaintext TCP handshake.

| what a client sends | `protocol: ["bittorrent"]` alone |
| :-- | :-- |
| BitTorrent handshake, plaintext TCP | blocked |
| Encrypted peer handshake (MSE/PE) | **passes** |
| µTP to a peer on a random port | **passes** |

You can reproduce all of that in about ten seconds — see [Proving it](#proving-it) below.

There are two further ways the rule ends up inert, and this tool fixes both:

### Nobody is reading the bytes

If **sniffing is off** on the inbound, Xray never names anything, so nothing is ever called `bittorrent` — for any traffic, ever. Sniffing is off by default on a lot of inbounds, and the routing page still shows your rule sitting there looking healthy.

### Another rule grabs the customer first

Xray checks rules **top to bottom and stops at the first one that matches**. If you route particular customers through a particular outbound — a country exit, a WARP outbound, anything per-customer — that rule is higher up. Those customers get claimed before the torrent rule is ever reached.

<div align="center">
<img src="https://raw.githubusercontent.com/NightRiderr77/torrent-guard/main/assets/rule-order.svg" alt="Before: customer rules sit above the torrent rule so it is never reached. After: the torrent rule is first and always applies." width="100%">
</div>

So the block silently stops applying to exactly the customers you cared enough about to route specially.

## What actually works

Identifying peer traffic is a losing game — you cannot fingerprint an encrypted stream on a random port. So don't. **Cut off peer discovery instead.** A client that cannot reach a tracker or the DHT has no peer list, and encryption does not help it find one.

That is what this installs, as one block of rules placed above your customer rules:

| Rule | What it stops |
| :-- | :-- |
| `protocol: ["bittorrent"]` → blackhole | plaintext BitTorrent over TCP |
| ports `6881-6889, 6969, 1337, 2710, 51413` → blackhole | trackers and the DHT, on TCP and UDP |
| DHT bootstrap nodes and tracker hostnames → blackhole | peer discovery by name |

Plus, as before: sniffing turned on for every inbound, a `blocked` blackhole outbound created if missing, and the whole block moved above your customer rules so it is actually reached.

The tracker hostname patterns are anchored at the start of a label on purpose. `tracker.example.com` is caught; `mytracker.example.com` and `package-tracker.com` are not. A bare keyword match would take out far too much of the ordinary web.

### Blocking discovery is not enough on its own

Cutting off discovery stops a **new** torrent: no tracker, no DHT, no peer list.
It does **not** stop a client already running. uTorrent and qBittorrent keep a
warm DHT node cache and a peer list on disk, so they never look anything up
again — they go straight to peers on random high UDP ports, encrypted. Nothing in
a routing table can tell that apart from any other UDP.

If torrents keep going after `--apply`, this is why. There are two ways to finish
the job, and the first is much less disruptive.

## 1. Cut off the customer, not the packet — recommended

You never have to identify the encrypted flow. You only have to identify the
**person**, once. Every rule above now sends torrent traffic to its own `TORRENT`
blackhole rather than the shared one, and Xray writes a line naming the customer
each time it fires:

```
from tcp:203.0.113.9:51413 accepted tcp:1.2.3.4:6881 [in-443 >> TORRENT] email: bob@x.com
```

`torrent-watch.py` tails that log and drops the offender's IP in the firewall for
a while. Their torrent client dies instantly — encrypted, µTP, DHT, all of it,
because the whole address is gone. Every other customer is untouched, and voice,
games and QUIC keep working normally.

```bash
sudo python3 extras/torrent-watch.py --install   # runs as a systemd service
sudo python3 extras/torrent-watch.py --status    # who is blocked right now
sudo python3 extras/torrent-watch.py --unblock 203.0.113.9
```

Default block is 30 minutes (`--minutes`), and it extends while they keep trying.
It uses nftables where available and iptables otherwise, handles IPv4 and IPv6,
and kills existing connections with `conntrack` — a new firewall rule alone would
leave established torrent connections running until they time out. Your own SSH
address is never blocked.

> Credit where it is due: this approach is
> [kutovoys/xray-torrent-blocker](https://github.com/kutovoys/xray-torrent-blocker),
> a maintained Go daemon that does the same thing with webhooks, panel
> integrations and Telegram alerts. If you would rather run that, these rules are
> already compatible — it looks for exactly this `TORRENT` tag. The Python version
> here exists so the whole thing stays dependency-free next to `block-torrents.py`.
> One difference worth knowing: it tags only `protocol: bittorrent`, which sees
> plaintext TCP alone. The tracker, DHT and port rules installed here trip on far
> more, so the offender is caught sooner.

## 2. Close UDP outright — blunter

```bash
sudo python3 block-torrents.py --strict --apply
```

This blocks UDP everywhere except:

| Allowed | Why |
| :-- | :-- |
| ports `53, 123, 443, 3478-3481, 19302-19309` | DNS, NTP, QUIC/HTTP3, STUN/TURN, Google's STUN range |
| Discord's allocation and i3D.net's announced space | voice chat |

Voice is the awkward case: a call picks a random high port, exactly like a torrent
peer, so no port rule can separate them — but the **destination** can. Discord's
voice servers are not in one tidy block: they run on i3D.net (AS49544), whose
prefixes cover Singapore and India, which is what customers in Asia actually
reach. Allowing only Discord's US range is not enough.

Anything else needing arbitrary UDP — a game, a softphone — has to be added:

```bash
sudo python3 block-torrents.py --strict --allow-udp-ip 1.2.3.0/24 --apply
sudo python3 block-torrents.py --strict --allow-udp-port 27015-27050 --apply
```

Both lists become ordinary routing rules, visible and editable in the panel, and a
later run keeps whatever you changed there. Once `--strict` is on it stays on;
`--no-strict` removes it.

Expect complaints about games. Option 1 has none of this cost, which is why it is
the better answer for most people.

## Proving it

Reading a config cannot tell you whether it works. Sending the bytes can.

```bash
sudo python3 extras/verify-blocking.py
```

This starts a throwaway Xray on localhost using **your** routing rules, speaks each protocol a real torrent client speaks, and reports what got through. The live server is not touched — separate process, separate port, and it only ever talks to `127.0.0.1`.

Against the config almost everyone has:

```
  case                                         result    verdict
  ------------------------------------------------------------------------------
  BitTorrent handshake, plaintext TCP          blocked   ok
  peer on a BitTorrent port, TCP               blocked   ok
  uTP to a peer on a BitTorrent port           blocked   ok
  uTP to a peer on a random high port          passed    *** LEAK ***
  tracker announce (tracker.example.net)       passed    *** LEAK ***
  DHT bootstrap (router.bittorrent.com)        passed    *** LEAK ***
  ordinary web traffic                         passed    ok
  a site merely named *tracker*                passed    ok
  QUIC / HTTP3 (UDP 443)                       passed    ok
  DNS (UDP 53)                                 passed    ok
  Discord voice (UDP 50001 to 66.22.192.0/18)  passed    ok
  encrypted peer handshake (MSE/PE)            passed    known gap
```

After `--apply --strict`, every leak reads `ok` and Discord voice still passes. Exit status is 0 only if every case behaved as intended, so it works in a cron job or a fleet check.

## What is not touched

Your customers, their UUIDs, quotas, expiry dates, usage counters, inbound settings, certificates, or which outbound each customer routes through. The exact before/after is printed before anything changes, and `x-ui.db` is copied to a timestamped `.bak` next to itself first.

One detail worth knowing: sniffing is enabled with `routeOnly: true`. Without that, sniffing rewrites the connection's destination to whatever domain it detected, which breaks any config that presents a different SNI on purpose. `routeOnly` gives routing the answer and leaves the destination alone.

Backups are taken with SQLite's own backup API and verified before `--apply` writes anything, and `--restore` checks a backup's integrity, stops x-ui and clears stale `-wal`/`-shm` files before putting it back. A backup that fails its check is refused rather than written over a working database.

> **It restarts x-ui at the end**, because inbound changes only take effect on restart. That drops live connections for a second or two. Use `--no-restart` to do it yourself later.

## Options

```
sudo python3 block-torrents.py                  # look only (default)
sudo python3 block-torrents.py --show           # print current state, no verdict
sudo python3 block-torrents.py --apply          # fix it
sudo python3 block-torrents.py --strict         # close UDP (see option 2)
sudo python3 block-torrents.py --no-strict      # remove the UDP clamp
sudo python3 block-torrents.py --strict --allow-udp-ip  CIDR,...   # widen by destination
sudo python3 block-torrents.py --strict --allow-udp-port PORTS     # widen by port
sudo python3 block-torrents.py --restore        # undo, newest backup
sudo python3 block-torrents.py --no-restart     # don't restart x-ui
sudo python3 block-torrents.py --db /path/x-ui.db
```

Safe to run twice — if everything is already correct it says so and exits without touching anything.

## What it still can't do

- **An encrypted peer on an allowed destination.** With `--strict`, traffic to an
  allowlisted range on any port is waved through, and nothing in Xray can tell an
  encrypted peer from a voice call. Option 1 catches it anyway, because the client
  trips a tracker or DHT rule long before that and loses its whole address.
- **Traffic that never enters the tunnel.** If a customer's own ISP gives them
  IPv6 and their client is not routing it through the VPN, none of this sees it.
  That is a client-side problem, not a server one.
- This is not a copyright enforcement system. It stops torrents on your servers.

## Optional: checking many panels at once

If you run a fleet and want to audit panels remotely rather than SSH into each one, `torrent_guard.py` does the same job over the panel API, and installs the same rules. That one **does** need panel credentials, in a local `panels.json` (gitignored — see `panels.example.json`).

```bash
python3 torrent_guard.py check           # read-only, all panels
python3 torrent_guard.py apply           # fix them
python3 torrent_guard.py apply --strict  # fix them, and close UDP
python3 torrent_guard.py selftest        # no network, no credentials
```

Most people should just use `block-torrents.py` on the server.

## Licence

MIT. See [LICENSE](LICENSE).

<div align="center">
<br>
<sub>Built for the <a href="https://pxnstores.lk">PXN Stores LK</a> fleet. Works with any 3X-UI or Xray panel.</sub>
</div>
