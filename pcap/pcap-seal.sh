#!/bin/sh
# pcap-seal: move the finished capture files of one profile from live/ to
# done/ and write a sha256 next to each. Runs as ExecStopPost of
# pcap@.service, after tcpdump has exited, so nothing in live/ for that
# profile is still open. The sha256 sidecar is the signal the collector's
# pcap-pull.sh waits for: a file without one is not pulled.
#
#   pcap-seal.sh <profile>
#
# ring-mode files are named <profile>.pcap0, <profile>.pcap1 ... by tcpdump;
# they are renamed to <profile>-<mtime, UTC>.pcap so every file in done/
# carries the time it was closed; two closed in the same second get -1, -2.
# A file that holds the 24-byte pcap header and nothing else (a capture
# that saw no packet) is removed, not sealed.
set -eu

profile=${1:-}
[ -n "$profile" ] || { sed -n '2,10p' "$0"; exit 64; }
live=${PCAP_LIVE:-/var/lib/pcap/live}
done_dir=${PCAP_DONE:-/var/lib/pcap/done}
[ -d "$done_dir" ] || { echo "pcap-seal: $done_dir missing" >&2; exit 1; }

n=0
for f in "$live/$profile"-*.pcap "$live/$profile".pcap*; do
  [ -e "$f" ] || continue
  # 24 bytes is the pcap file header alone: a capture that saw nothing
  if [ "$(stat -c %s "$f")" -le 24 ]; then rm -f "$f"; echo "pcap-seal: $f empty, removed"; continue; fi
  base=$(basename "$f")
  case "$base" in
    "$profile".pcap*)
      stamp=$(date -u -r "$f" +%Y%m%dT%H%M%SZ)
      base="$profile-$stamp.pcap"
      i=0
      while [ -e "$done_dir/$base" ]; do i=$((i + 1)); base="$profile-$stamp-$i.pcap"; done ;;
  esac
  mv "$f" "$done_dir/$base"
  ( cd "$done_dir" && sha256sum "$base" > "$base.sha256" )
  printf 'pcap-seal: %s  %s bytes\n' "$base" "$(stat -c %s "$done_dir/$base")"
  n=$((n + 1))
done
echo "pcap-seal: $profile sealed $n file(s) into $done_dir"
