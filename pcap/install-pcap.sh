#!/bin/sh
# install-pcap: set up least-privilege packet capture on a DGX Spark (DGX OS 7,
# Ubuntu 24.04) or a Proxmox VE 9 node (Debian 13).
#
#   sudo ./install-pcap.sh [--pull-key /path/to/collector.pub]
#
# What it does
#   1. apt install tcpdump (and rsync, for the collector's pull)
#   2. a system user `pcap` (no shell, no sudo, not in docker) that owns
#      /var/lib/pcap/{live,done}; tcpdump runs as this user with CAP_NET_RAW
#      only, granted by the unit, never by setcap on the binary
#   3. pcap-run.sh, pcap-seal.sh, pcap@.service, the profiles in /etc/pcap
#      (existing profiles are kept), tmpfiles retention (live 2 d, done 7 d)
#   4. --pull-key: lets the collector read done/ over ssh as `pcap`, forced
#      to `rrsync -ro /var/lib/pcap/done` with `restrict`; when the host has
#      Day 11's `sshusers` group (sshd AllowGroups), pcap is added to it,
#      which is the only way that key can log in at all
#   5. where sudo is installed, a sudoers drop-in that lets members of
#      `pcap-ops` start, stop and inspect pcap@<profile> units, listed by
#      name, no wildcard
#
# It does not touch ufw, pve-firewall, Docker or AppArmor. On Ubuntu the
# tcpdump AppArmor profile already permits /**.pcap and /**.pcap[0-9]*;
# the script prints the profile's mode so you can confirm on Debian.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
PULL_KEY=""
[ "${1:-}" = --pull-key ] && { PULL_KEY=${2:-}; [ -s "$PULL_KEY" ] || { echo "--pull-key needs a readable public key file" >&2; exit 64; }; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

if ! command -v tcpdump >/dev/null || ! command -v rsync >/dev/null; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tcpdump rsync
fi

getent group pcap >/dev/null || groupadd --system pcap
getent passwd pcap >/dev/null || useradd --system -g pcap -d /var/lib/pcap -s /usr/sbin/nologin pcap
getent group pcap-ops >/dev/null || groupadd --system pcap-ops
install -d -o pcap -g pcap -m 0750 /var/lib/pcap /var/lib/pcap/live /var/lib/pcap/done
cat > /etc/tmpfiles.d/pcap.conf <<'EOF'
# written by onprem-logs/pcap/install-pcap.sh
# the node's own retention: an unsealed file older than 2 days and a sealed
# file older than 7 days are removed by systemd-tmpfiles-clean.timer; the
# collector pulls done/ hourly, so 7 days is a week of collector outage
d /var/lib/pcap      0750 pcap pcap -
d /var/lib/pcap/live 0750 pcap pcap 2d
d /var/lib/pcap/done 0750 pcap pcap 7d
EOF
systemd-tmpfiles --create /etc/tmpfiles.d/pcap.conf

install -m 0755 "$HERE/pcap-run.sh"  /usr/local/bin/pcap-run.sh
install -m 0755 "$HERE/pcap-seal.sh" /usr/local/bin/pcap-seal.sh
install -m 0644 "$HERE/pcap@.service" /etc/systemd/system/pcap@.service
install -d -m 0755 /etc/pcap
for p in "$HERE"/profiles/*.env; do
  b=$(basename "$p")
  [ -e "/etc/pcap/$b" ] || install -m 0644 "$p" "/etc/pcap/$b"
done
systemctl daemon-reload

# a Proxmox VE node often has no sudo at all (root logs in directly); the
# drop-in is only installed where sudo is, and checked before it counts
if command -v visudo >/dev/null; then
  install -m 0440 "$HERE/sudoers-pcap" /etc/sudoers.d/pcap
  visudo -cf /etc/sudoers.d/pcap >/dev/null || { rm -f /etc/sudoers.d/pcap; echo "sudoers-pcap failed visudo, not installed" >&2; exit 1; }
else
  echo "sudo is not installed: no sudoers drop-in, pcap-ops has no effect here"
fi

if [ -n "$PULL_KEY" ]; then
  command -v rrsync >/dev/null || { echo "rrsync not found (rsync >= 3.2.4 ships it in /usr/bin)" >&2; exit 1; }
  install -d -o pcap -g pcap -m 0700 /var/lib/pcap/.ssh
  printf 'command="%s -ro /var/lib/pcap/done",restrict %s\n' "$(command -v rrsync)" "$(head -n1 "$PULL_KEY")" \
    > /var/lib/pcap/.ssh/authorized_keys
  chown pcap:pcap /var/lib/pcap/.ssh/authorized_keys; chmod 0600 /var/lib/pcap/.ssh/authorized_keys
  # sshd runs a forced command through the account's shell, and nologin
  # refuses; /bin/sh is needed. Only this key can log in as pcap (no
  # password is set), and `restrict` forbids a pty, forwarding and agent
  usermod -s /bin/sh pcap
  if getent group sshusers >/dev/null; then
    usermod -aG sshusers pcap
    echo "pcap added to sshusers (sshd AllowGroups, Day 11); its key is forced to rrsync -ro"
  fi
fi

echo
echo "tcpdump: $(tcpdump --version 2>&1 | head -n1)"
if [ -e /etc/apparmor.d/usr.bin.tcpdump ] && command -v aa-status >/dev/null; then
  # aa-status lists profiles under "N profiles are in <mode> mode." headings
  mode=$(aa-status 2>/dev/null | awk '/profiles are in/ { m = $(NF-1) } /^ +(\/usr\/bin\/)?tcpdump$/ { print m; exit }')
  if [ -n "$mode" ]; then echo "apparmor: usr.bin.tcpdump in $mode mode"; else echo "apparmor: usr.bin.tcpdump present, not listed by aa-status"; fi
  grep -q 'pP\]\[cC\]\[aA\]\[pP\]\[0-9\]' /etc/apparmor.d/usr.bin.tcpdump \
    && echo "          /**.pcap and /**.pcap[0-9]* are allowed, live/ needs no local override" \
    || echo "          profile lacks the rotated-file rule; add '/var/lib/pcap/** rw,' to /etc/apparmor.d/local/usr.bin.tcpdump"
fi
echo
echo "profiles in /etc/pcap:"; ls /etc/pcap
echo
echo "dry run of the nfs profile:"
# shellcheck disable=SC1091
( set -a; . /etc/pcap/nfs.env; set +a; PCAP_DRYRUN=1 /usr/local/bin/pcap-run.sh nfs ) || true
echo
echo "start one:   sudo systemctl start pcap@nfs      (members of pcap-ops need no password)"
echo "watch it:    journalctl -fu pcap@nfs"
echo "stop early:  sudo systemctl stop pcap@nfs       (files are sealed into /var/lib/pcap/done)"
