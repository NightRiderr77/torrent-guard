<div align="center">

<img src="https://raw.githubusercontent.com/NightRiderr77/torrent-guard/main/assets/banner.svg" alt="torrent-guard — normal traffic passes, BitTorrent is dropped at the Xray routing layer" width="100%">

<br><br>

<img alt="Python 3.8+" src="https://img.shields.io/badge/Python-3.8%2B-0B0F0B?style=flat-square&logo=python&logoColor=8FD14F">
<img alt="Zero dependencies" src="https://img.shields.io/badge/dependencies-none-0B0F0B?style=flat-square&logo=gnubash&logoColor=8FD14F">
<img alt="Xray and 3X-UI" src="https://img.shields.io/badge/Xray_%C2%B7_3X--UI-0B0F0B?style=flat-square&logo=v&logoColor=8FD14F">
<img alt="MIT licence" src="https://img.shields.io/badge/licence-MIT-0B0F0B?style=flat-square">

</div>

---

If you run a VPN, torrent traffic is what gets your IP ranges blacklisted, your abuse inbox filled, and eventually your server cancelled by the provider. So you add the rule everyone adds:

```json
{ "type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked" }
```

The panel shows it. It looks right. **It is very easy for that rule to do nothing at all, and nothing in the UI will tell you.**

`torrent-guard` checks the two things that actually decide whether it works, and fixes them.

## The two ways it silently fails

### 1. Sniffing is off

`protocol` matching is driven by Xray's sniffer. With `"sniffing": {"enabled": false}` on the inbound there is no protocol metadata to match against, so the rule never fires — **for any traffic, ever**. The same applies to `metadataOnly: true`, which skips the payload where the BitTorrent handshake actually lives.

This is the default on plenty of inbounds, and it is invisible: the rule sits in the routing tab looking perfectly healthy.

### 2. The rule is ordered below your user rules

Xray routing is **first-match-wins**. If you route particular customers through particular outbounds — a country exit, a WARP outbound, anything per-user — those rules are matched first. Every client named in one of them is claimed before the torrent rule is ever considered.

<div align="center">
<img src="https://raw.githubusercontent.com/NightRiderr77/torrent-guard/main/assets/rule-order.svg" alt="Before: user rules sit above the bittorrent rule so it is never reached. After: the bittorrent rule is first and always applies." width="100%">
</div>

Your torrent block silently stops applying to exactly the customers you cared enough about to route specially.

## Install

One file, standard library only. No `pip install`, nothing to build.

```bash
git clone https://github.com/NightRiderr77/torrent-guard.git
cd torrent-guard
cp panels.example.json panels.json   # then fill it in
```

`panels.json` is gitignored. Keep it that way.

```json
{
  "panels": [
    {
      "name": "sg1",
      "host": "panel.example.com",
      "port": 2053,
      "web_base_path": "/yourBasePath/",
      "username": "PANEL_USERNAME",
      "password": "PANEL_PASSWORD"
    }
  ]
}
```

Username and password are required — reading and writing routing settings goes through the panel session, not the API token. Add `"api_token"` if your panel wants it for the inbound endpoints.

## Use

```bash
python3 torrent_guard.py check
```

Read-only. Touches nothing. Exit code `0` if every panel is clean, `1` if anything is wrong.

```
-- sg1
   FAIL  sniffing-off  in-443-tcp
         sniffing is disabled, so no protocol is ever detected and the bittorrent
         rule cannot match any traffic on this inbound
         fix: enable sniffing (routeOnly, so the destination is left alone)
   FAIL  bittorrent-rule-shadowed  routing.rules[4]
         54 client entries match an earlier rule (from index 1) and are routed
         before the bittorrent rule is ever reached - those clients can torrent freely
         fix: move the bittorrent rule above every user-matching rule

0/1 panel(s) blocking torrents correctly.
```

Then fix it:

```bash
python3 torrent_guard.py apply --dry-run   # show the changes, save nothing
python3 torrent_guard.py apply             # actually apply them
```

Other flags: `--only sg1,sg4` to limit which panels, `--json` for machine-readable output, `--insecure` for self-signed panel certificates, `--config` for a different panel list.

```bash
python3 torrent_guard.py selftest
```

Runs the analysis and repair logic against a deliberately broken sample config. No network, no credentials — useful to confirm the tool behaves before you point it at anything real.

## What `apply` changes

Exactly four things, and nothing else:

| | |
| :-- | :-- |
| Sniffing | `enabled: true`, `metadataOnly: false`, `routeOnly: true`, `destOverride: [http, tls, quic]` on every inbound |
| Blackhole | adds `{"tag": "blocked", "protocol": "blackhole"}` if no blackhole outbound exists |
| The rule | creates it, re-enables it, or repoints it at the blackhole |
| Order | moves it directly below the `api` rules, above every user-matching rule |

Your outbounds, your per-user routing assignments and every other rule are left exactly as they were. The previous routing config is written to `backups/<panel>-<timestamp>.json` before anything is saved.

**`routeOnly: true` is deliberate.** Plain `destOverride` rewrites the connection's destination to whatever domain the sniffer found. If you present a different SNI to the network on purpose, that will break your configs. `routeOnly` gives routing the sniffed information while leaving the destination alone.

> **Applying sniffing changes restarts Xray on that panel.** Inbound edits regenerate the config, which drops live connections for a moment. Routing-only changes do not. Run it in a quiet window.

## Limits — read this before you trust it

- **Encrypted BitTorrent can evade sniffing.** Clients with protocol encryption (MSE/PE) obscure the handshake. Xray catches the common cases, not every case.
- **This blocks torrents through your tunnel.** It does not stop someone torrenting outside the VPN, and it is not a copyright enforcement system.
- **`extras/nft-bittorrent.sh`** closes well-known tracker and DHT ports on the server with nftables. Torrent clients use arbitrary high ports, so it stops very little on its own — it is a second layer, not the control.
- **Verify after applying.** `check` tells you the configuration is correct. It cannot tell you a particular client is defeated.

## Security

Panel credentials live only in your local `panels.json`, which is gitignored. Nothing is sent anywhere except your own panels. `--insecure` disables TLS verification for self-signed panels and prints a warning when used — your panel password crosses that connection, so prefer a real certificate.

## Licence

MIT. See [LICENSE](LICENSE).

<div align="center">
<br>
<sub>Built for the <a href="https://pxnstores.lk">PXN Stores LK</a> fleet. Works with any Xray or 3X-UI panel.</sub>
</div>
