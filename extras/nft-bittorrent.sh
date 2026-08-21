#!/usr/bin/env bash
# Defence in depth, NOT a replacement for the Xray rule.
#
# Xray's protocol sniffing is the real control: it identifies the BitTorrent
# handshake wherever it happens. This script only closes the well-known tracker
# and DHT ports. Torrent clients pick arbitrary high ports, so on its own this
# stops very little - it is here to catch the lazy default-port case and to make
# DHT bootstrapping fail early.
#
# Run on the VPN server as root. Requires nftables.
set -euo pipefail

TABLE=torrent_guard

if ! command -v nft >/dev/null 2>&1; then
  echo "nftables (nft) is not installed" >&2
  exit 1
fi

case "${1:-apply}" in
  apply)
    nft list table inet "$TABLE" >/dev/null 2>&1 && nft delete table inet "$TABLE"
    nft -f - <<'RULES'
table inet torrent_guard {
  chain output {
    type filter hook output priority 0; policy accept;

    # classic BitTorrent listen/tracker range
    tcp dport 6881-6889 counter drop
    udp dport 6881-6889 counter drop

    # mainline DHT bootstrap nodes and common alternates
    udp dport 6969 counter drop
    tcp dport 6969 counter drop

    # a few widely used tracker ports
    tcp dport { 2710, 2810, 51413 } counter drop
    udp dport { 2710, 2810, 51413 } counter drop
  }
}
RULES
    echo "applied. counters: nft list table inet $TABLE"
    ;;
  remove)
    nft delete table inet "$TABLE" && echo "removed"
    ;;
  status)
    nft list table inet "$TABLE"
    ;;
  *)
    echo "usage: $0 [apply|remove|status]" >&2
    exit 2
    ;;
esac
