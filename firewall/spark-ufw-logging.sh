#!/bin/sh
# spark-ufw-logging: make the DGX Spark firewall say what it drops, at a rate
# the journal can live with, and prove the lines reach the collector.
#
#   sudo ./spark-ufw-logging.sh [low|medium]     default low
#
# ufw "low" logs blocked packets that match no rule plus rule-level logging;
# "medium" adds allowed packets that match no rule, invalid packets and
# rate-limited new connections. Both are rate limited by ufw itself
# (3/min burst 10 for the block rules). The lines go to the kernel ring
# buffer, journald stores them with _TRANSPORT=kernel and the prefix
# "[UFW BLOCK]", and Day 21's systemd-journal-upload ships them as is.
#
# It refuses to touch an inactive ufw: turning the firewall on is a change
# of its own (rules for every service, the CX7 links for NCCL), not a side
# effect of turning logging on. In the Day 22 lab both Sparks keep ufw
# disabled on purpose; see the article for the trade-off. Ports published
# by Docker bypass ufw either way.
set -eu
level=${1:-low}
case "$level" in low|medium) ;; *) echo "level must be low or medium (high/full flood the journal)" >&2; exit 64 ;; esac
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
command -v ufw >/dev/null || { echo "ufw not installed (Day 11 baseline expects it)" >&2; exit 1; }

ufw status | grep -q '^Status: active' || { echo "ufw is not active, refusing to change logging on an inactive firewall" >&2; exit 2; }
ufw logging "$level"
ufw status verbose | grep '^Logging'

# dmesg_restrict is on (Day 19), so the proof goes through journalctl
echo
echo "last blocked packets seen by this host:"
journalctl -k --since -1h --grep 'UFW BLOCK' -o cat --no-pager | tail -n 5 || true
echo
echo "on the collector, the same lines:"
echo "  curl -s http://127.0.0.1:9428/select/logsql/query -d 'query=_HOSTNAME:$(hostname) _TRANSPORT:=kernel \"[UFW BLOCK]\" | limit 5'"
