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

Most panels already have a rule that looks like it blocks torrents. **Usually it does nothing**, and the panel gives you no hint. This finds out, and fixes it.

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

## How torrents get blocked

In plain terms:

1. **A torrent app announces itself.** The first few bytes of a BitTorrent connection are distinctive — they always look the same.
2. **Xray reads those first bytes and names the protocol.** This peek is called **sniffing**.
3. **A routing rule catches anything named `bittorrent`** and sends it to a **blackhole** — an outbound that throws traffic away instead of forwarding it.

The torrent can't reach any peers, so it stalls and gets nowhere. Browsing, streaming and games are unaffected, because they get named something else and follow their normal path.

## Why the usual rule does nothing

Almost everyone has this in their routing config:

```json
{ "type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked" }
```

It looks right. Two things quietly stop it working.

### 1. Nobody is reading the bytes

If **sniffing is off** on the inbound, Xray never names anything, so nothing is ever called `bittorrent` and the rule matches nothing — for any traffic, ever. Sniffing is off by default on a lot of inbounds, and the routing page still shows your rule sitting there looking healthy.

### 2. Another rule grabs the customer first

Xray checks rules **top to bottom and stops at the first one that matches**. If you route particular customers through a particular outbound — a country exit, a WARP outbound, anything per-customer — that rule is higher up. Those customers get claimed before the torrent rule is ever reached.

<div align="center">
<img src="https://raw.githubusercontent.com/NightRiderr77/torrent-guard/main/assets/rule-order.svg" alt="Before: customer rules sit above the torrent rule so it is never reached. After: the torrent rule is first and always applies." width="100%">
</div>

So the block silently stops applying to exactly the customers you cared enough about to route specially.

## What it changes

Four things, and nothing else:

| Change | Why |
| :-- | :-- |
| Turns on sniffing for every inbound | so torrents can be recognised at all |
| Adds a `blocked` blackhole outbound, if missing | somewhere to throw the traffic away |
| Creates / re-enables the torrent rule, pointed at the blackhole | the rule itself |
| Moves that rule above your customer rules | so it is actually reached |

**Not touched:** your customers, their UUIDs, quotas, expiry dates, usage counters, inbound settings, certificates, or which outbound each customer routes through. It prints the exact before/after before changing anything, and copies `x-ui.db` to a timestamped `.bak` next to itself first.

One detail worth knowing: sniffing is enabled with `routeOnly: true`. Without that, sniffing rewrites the connection's destination to whatever domain it detected, which breaks any config that presents a different SNI on purpose. `routeOnly` gives routing the answer and leaves the destination alone.

> **It restarts x-ui at the end**, because inbound changes only take effect on restart. That drops live connections for a second or two. Use `--no-restart` to do it yourself later.

## Options

```
sudo python3 block-torrents.py                  # look only (default)
sudo python3 block-torrents.py --apply          # fix it
sudo python3 block-torrents.py --restore        # undo, newest backup
sudo python3 block-torrents.py --no-restart     # don't restart x-ui
sudo python3 block-torrents.py --db /path/x-ui.db
```

Safe to run twice — if everything is already correct it says so and exits without touching anything.

## What it can't do

- **Encrypted torrent traffic can slip past.** Clients with protocol encryption (MSE/PE) hide that opening handshake. This catches the common cases, not every case.
- **It only covers traffic through your VPN.** It is not a copyright enforcement system.
- `extras/nft-bittorrent.sh` closes well-known tracker and DHT ports with nftables. Torrent clients use random high ports, so on its own that stops very little — it's a second layer, not the control.

## Optional: checking many panels at once

If you run a fleet and want to audit panels remotely rather than SSH into each one, `torrent_guard.py` does the same job over the panel API. That one **does** need panel credentials, in a local `panels.json` (gitignored — see `panels.example.json`).

```bash
python3 torrent_guard.py check      # read-only, all panels
python3 torrent_guard.py apply      # fix them
python3 torrent_guard.py selftest   # no network, no credentials
```

Most people should just use `block-torrents.py` on the server.

## Licence

MIT. See [LICENSE](LICENSE).

<div align="center">
<br>
<sub>Built for the <a href="https://pxnstores.lk">PXN Stores LK</a> fleet. Works with any 3X-UI or Xray panel.</sub>
</div>
