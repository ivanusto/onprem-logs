#!/bin/sh
# pcap-run: build the tcpdump command line for one capture profile and exec
# it. Started by pcap@.service as the `pcap` user with CAP_NET_RAW; can also
# be run by hand with PCAP_DRYRUN=1 to see what a profile expands to.
#
#   pcap-run.sh <profile>            profile = /etc/pcap/<profile>.env
#
# Variables, from the profile's env file (defaults in brackets)
#   IFACE           interface, or "auto" to take the one that routes to PEER [auto]
#   PEER            address used to resolve IFACE=auto (e.g. the NAS)
#   FILTER          BPF filter; empty captures everything on IFACE []
#   SNAPLEN         bytes kept per packet [256]
#   MODE            timed | ring [timed]
#   ROTATE_SECONDS  timed: a new file every N seconds [600]
#   KEEP_FILES      timed: stop after this many files; ring: files in the ring [6]
#   SIZE_MB         ring: size of each file, millions of bytes (tcpdump -C) [50]
#   MAX_SECONDS     wall-clock cap; timed defaults to ROTATE_SECONDS*KEEP_FILES+60,
#                   ring defaults to 86400 (RuntimeMaxSec=1d in the unit backs it)
#
# Why these flags
#   -p   no promiscuous mode: these captures look at this host's own traffic
#        (NFS to the NAS, corosync between the nodes). Without promiscuous
#        mode CAP_NET_RAW is enough; a tap or bridge capture that must see
#        other hosts' frames needs CAP_NET_ADMIN as well.
#   -n   no name resolution: no DNS traffic caused by the capture itself
#   -s   a short snaplen keeps headers and drops payload. 256 bytes covers
#        Ethernet+IP+TCP+RPC+NFS compound headers; the file contents of an
#        NFS READ or WRITE are not kept. corosync is encrypted by knet, so
#        128 is enough there.
#   timed mode is -G/-W: tcpdump exits by itself after KEEP_FILES files. A
#        rotation happens on the first packet after the interval, so a
#        filter that matches nothing never rotates; MAX_SECONDS ends it.
#   ring mode is -C/-W: a fixed number of fixed-size files, the oldest
#        overwritten, for "stop it when the thing happens again".
set -eu

profile=${1:-}
[ -n "$profile" ] || { sed -n '2,8p' "$0"; exit 64; }
case "$profile" in *[!A-Za-z0-9_-]*) echo "profile name: letters, digits, - and _ only" >&2; exit 64 ;; esac

IFACE=${IFACE:-auto}
PEER=${PEER:-}
FILTER=${FILTER:-}
SNAPLEN=${SNAPLEN:-256}
MODE=${MODE:-timed}
ROTATE_SECONDS=${ROTATE_SECONDS:-600}
KEEP_FILES=${KEEP_FILES:-6}
SIZE_MB=${SIZE_MB:-50}
live=${PCAP_LIVE:-/var/lib/pcap/live}
TCPDUMP=${TCPDUMP:-/usr/bin/tcpdump}

if [ "$IFACE" = auto ]; then
  [ -n "$PEER" ] || { echo "IFACE=auto needs PEER=<address>" >&2; exit 64; }
  IFACE=$(ip -o route get "$PEER" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)
  [ -n "$IFACE" ] || { echo "no route to PEER $PEER" >&2; exit 1; }
fi

case "$MODE" in
  timed)
    MAX_SECONDS=${MAX_SECONDS:-$((ROTATE_SECONDS * KEEP_FILES + 60))}
    set -- -G "$ROTATE_SECONDS" -W "$KEEP_FILES" -w "$live/$profile-%Y%m%dT%H%M%SZ.pcap" ;;
  ring)
    MAX_SECONDS=${MAX_SECONDS:-86400}
    set -- -C "$SIZE_MB" -W "$KEEP_FILES" -w "$live/$profile.pcap" ;;
  *) echo "MODE must be timed or ring" >&2; exit 64 ;;
esac

# $FILTER is split into words on purpose: it is a BPF expression
if [ "${PCAP_DRYRUN:-0}" = 1 ]; then
  # shellcheck disable=SC2086
  printf '%s ' timeout -s INT "$MAX_SECONDS" "$TCPDUMP" -p -n -i "$IFACE" -s "$SNAPLEN" "$@" $FILTER; echo
  exit 0
fi
echo "pcap-run: $profile on $IFACE snaplen $SNAPLEN mode $MODE max ${MAX_SECONDS}s filter: ${FILTER:-<none>}"
# shellcheck disable=SC2086
exec timeout -s INT "$MAX_SECONDS" "$TCPDUMP" -p -n -i "$IFACE" -s "$SNAPLEN" "$@" $FILTER
