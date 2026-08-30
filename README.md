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

**2. Most peer traffic is µTP, which runs over UDP.** Xray does not run content sniffers on UDP at all. A `protocol: ["bittorrent"]` rule can never match a UDP packet, no matter how the inbound is configured.

Here is the same config measured three ways, against Xray 26.1.23:

| what a client sends | `protocol: ["bittorrent"]` alone |
| :-- | :-- |
| BitTorrent handshake, plaintext TCP | blocked |
| Encrypted peer handshake (MSE/PE) | **passes** |
| µTP / DHT over UDP | **passes** |

You can reproduce that yourself in about ten seconds — see [Proving it](#proving-it) below.

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

### The one gap left, and how to close it

An **encrypted peer connection to a random port still gets through.** Nothing in Xray can tell it apart from any other encrypted stream. It matters much less once discovery is blocked — a new torrent finds nobody to talk to — but a client that is already connected to peers can keep going.

If you want that closed too:

```bash
sudo python3 block-torrents.py --strict --apply
```

`--strict` blocks **all UDP except 53 (DNS), 123 (NTP), 443 (QUIC) and 3478-3481 (STUN)**. That kills µTP outright, because peers listen on random high ports and there is no list to block.

> It also breaks games, voice chat and anything else needing arbitrary UDP. That is why it is off by default. Once you turn it on it stays on across later runs; `--no-strict` removes it.

## Proving it

Reading a config cannot tell you whether it works. Sending the bytes can.

```bash
sudo python3 extras/verify-blocking.py
```

This starts a throwaway Xray on localhost using **your** routing rules, speaks each protocol a real torrent client speaks, and reports what got through. The live server is not touched — separate process, separate port, and it only ever talks to `127.0.0.1`.

Against the config almost everyone has:

```
  case                                     result    verdict
  --------------------------------------------------------------------------
  BitTorrent handshake, plaintext TCP      blocked   ok
  uTP / DHT on a BitTorrent UDP port       passed    *** LEAK ***
  tracker announce (tracker.example.net)   passed    *** LEAK ***
  DHT bootstrap (router.bittorrent.com)    passed    *** LEAK ***
  ordinary web traffic                     passed    ok
  a site merely named *tracker*            passed    ok
  encrypted peer handshake (MSE/PE)        passed    known gap
```

After `--apply`, the three leaks read `ok`. Exit status is 0 only if every case behaved as intended, so it works in a cron job or a fleet check.

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
sudo python3 block-torrents.py --strict         # also clamp UDP (breaks games)
sudo python3 block-torrents.py --no-strict      # remove the UDP clamp
sudo python3 block-torrents.py --restore        # undo, newest backup
sudo python3 block-torrents.py --no-restart     # don't restart x-ui
sudo python3 block-torrents.py --db /path/x-ui.db
```

Safe to run twice — if everything is already correct it says so and exits without touching anything.

## What it still can't do

- **It only covers traffic through your VPN.** If a customer's own network reaches a peer directly — over IPv6 that never entered the tunnel, for instance — nothing here sees it. This is not a copyright enforcement system.
- **A determined customer can use a private tracker over HTTPS on port 443** and hand-configure peers. Discovery blocking raises the effort a long way; it does not make torrenting impossible.
- `extras/nft-bittorrent.sh` closes well-known tracker and DHT ports with nftables. It overlaps with what the routing rules now do and is kept as a second layer, not the control.

## Optional: checking many panels at once

If you run a fleet and want to audit panels remotely rather than SSH into each one, `torrent_guard.py` does the same job over the panel API, and installs the same rules. That one **does** need panel credentials, in a local `panels.json` (gitignored — see `panels.example.json`).

```bash
python3 torrent_guard.py check           # read-only, all panels
python3 torrent_guard.py apply           # fix them
python3 torrent_guard.py apply --strict  # fix them, and clamp UDP
python3 torrent_guard.py selftest        # no network, no credentials
```

Most people should just use `block-torrents.py` on the server.

## Licence

MIT. See [LICENSE](LICENSE).

<div align="center">
<br>
<sub>Built for the <a href="https://pxnstores.lk">PXN Stores LK</a> fleet. Works with any 3X-UI or Xray panel.</sub>
</div>
