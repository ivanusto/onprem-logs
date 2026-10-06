#!/bin/sh
# smoke-pcap: the Day 23 path without a node or a WORM share.
#   1. pcap-run.sh builds the right tcpdump line for each profile (dry run)
#   2. a real capture on lo when running as root with tcpdump, otherwise a
#      pcap written by hand; pcap-stat.py counts it
#   3. pcap-seal.sh moves live/ to done/ with a sha256 sidecar, drops an
#      empty file, renames a ring file by its mtime
#   4. pcap-pull.sh from a local "node" publishes one batch with MANIFEST
#      and SHA256SUMS, writes the index; a second run publishes nothing; a
#      file without a sidecar is left alone; a sidecar that does not match
#      is refused
#   5. verify-pcap.sh passes, then fails on a tampered file and on a batch
#      that is not in the index; a truncated capture is counted and flagged
# shellcheck disable=SC1090,SC1091   # the profiles are sourced from a temp copy
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
count() { find "$1" -mindepth 1 -maxdepth 1 -name "$2" | wc -l | tr -d ' '; }
first() { find "$1" -mindepth 1 -maxdepth 1 -name "$2" -printf '%f\n' | LC_ALL=C sort | head -n1; }
last()  { find "$1" -mindepth 1 -maxdepth 1 -name "$2" -printf '%f\n' | LC_ALL=C sort | tail -n1; }
tmp=$(mktemp -d); trap 'chmod -R u+w "$tmp"; rm -rf "$tmp"' EXIT
export PCAP_LIVE="$tmp/node/live" PCAP_DONE="$tmp/node/done"
mkdir -p "$PCAP_LIVE" "$PCAP_DONE" "$tmp/etc"
cp "$here"/pcap/profiles/*.env "$tmp/etc/"

# 1. dry runs
for p in nfs corosync syslog custom; do
  line=$( set -a; . "$tmp/etc/$p.env"; set +a; IFACE=${IFACE%auto}; IFACE=${IFACE:-lo}; PCAP_DRYRUN=1 TCPDUMP=tcpdump "$here/pcap/pcap-run.sh" "$p" )
  case "$line" in *"tcpdump -p -n -i "*) ;; *) echo "dry run $p: $line"; exit 1 ;; esac
done
line=$( set -a; . "$tmp/etc/nfs.env"; set +a; IFACE=lo PCAP_DRYRUN=1 TCPDUMP=tcpdump "$here/pcap/pcap-run.sh" nfs )
[ "$line" = "timeout -s INT 3660 tcpdump -p -n -i lo -s 256 -G 600 -W 6 -w $PCAP_LIVE/nfs-%Y%m%dT%H%M%SZ.pcap host 192.168.2.2 and tcp port 2049 " ] \
  || { echo "nfs dry run differs: $line"; exit 1; }
line=$( set -a; . "$tmp/etc/corosync.env"; set +a; IFACE=lo PCAP_DRYRUN=1 TCPDUMP=tcpdump "$here/pcap/pcap-run.sh" corosync )
case "$line" in *"-C 50 -W 20 -w $PCAP_LIVE/corosync.pcap udp portrange 5405-5412 or tcp port 5403 ") ;; *) echo "corosync dry run differs: $line"; exit 1 ;; esac
rc=0; MODE=bogus PCAP_DRYRUN=1 "$here/pcap/pcap-run.sh" x >/dev/null 2>&1 || rc=$?
[ "$rc" = 64 ] || { echo "bad MODE: expected 64, got $rc"; exit 1; }
rc=0; PCAP_DRYRUN=1 "$here/pcap/pcap-run.sh" 'a;b' >/dev/null 2>&1 || rc=$?
[ "$rc" = 64 ] || { echo "bad profile name: expected 64, got $rc"; exit 1; }

# 2. a capture
write_pcap() { # $1 path  $2 packets  (classic pcap, 60-byte frames, 1 s apart)
  python3 -c '
import struct,sys
p,n=sys.argv[1],int(sys.argv[2])
with open(p,"wb") as f:
    f.write(struct.pack("<IHHiIII",0xa1b2c3d4,2,4,0,0,256,1))
    for i in range(n):
        f.write(struct.pack("<IIII",1760000000+i,123456,60,60)+bytes(60))
' "$1" "$2"
}
if [ "$(id -u)" -eq 0 ] && command -v tcpdump >/dev/null && [ "${SMOKE_PCAP_REAL:-1}" = 1 ]; then
  ( set -a; . "$tmp/etc/custom.env"; set +a
    IFACE=lo FILTER="udp port 17999" MODE=timed ROTATE_SECONDS=4 KEEP_FILES=1 MAX_SECONDS=20 \
      "$here/pcap/pcap-run.sh" custom >"$tmp/run.log" 2>&1 ) &
  # -G/-W: the file holds what arrives inside the interval; the first packet
  # after it triggers the rotation, reaches the file limit and ends tcpdump
  sleep 1
  python3 -c 'import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for i in range(12): s.sendto(b"smoke %d" % i, ("127.0.0.1", 17999)); time.sleep(0.5)' 
  wait
  f="$PCAP_LIVE/$(first "$PCAP_LIVE" "custom-*.pcap")"
  st=$(python3 -I "$here/pcap/pcap-stat.py" "$f")
  pk=$(printf '%s' "$st" | cut -f3)
  [ "$pk" -ge 2 ] || { echo "real capture on lo: expected packets, got: $st"; cat "$tmp/run.log"; exit 1; }
  echo "real capture: $pk packets on lo"
else
  write_pcap "$PCAP_LIVE/custom-20261007T020000Z.pcap" 8
fi
write_pcap "$PCAP_LIVE/corosync.pcap0" 5
write_pcap "$PCAP_LIVE/corosync.pcap1" 3
write_pcap "$PCAP_LIVE/corosync.pcap2" 0                 # header only: must be removed, not sealed
st=$(python3 -I "$here/pcap/pcap-stat.py" "$PCAP_LIVE/corosync.pcap0")
[ "$(printf '%s' "$st" | cut -f3,6)" = "$(printf '5\t0')" ] || { echo "pcap-stat: $st"; exit 1; }
rc=0; printf 'not a pcap' > "$tmp/junk"; python3 -I "$here/pcap/pcap-stat.py" "$tmp/junk" >/dev/null 2>&1 || rc=$?
[ "$rc" = 1 ] || { echo "pcap-stat on junk: expected 1, got $rc"; exit 1; }

# 3. seal
"$here/pcap/pcap-seal.sh" custom >/dev/null
"$here/pcap/pcap-seal.sh" corosync >/dev/null
[ -z "$(ls -A "$PCAP_LIVE")" ] || { echo "live/ not empty after seal: $(ls "$PCAP_LIVE")"; exit 1; }
[ "$(count "$PCAP_DONE" "*.pcap")" = 3 ] || { echo "done/ should hold 3 pcaps: $(ls "$PCAP_DONE")"; exit 1; }
for f in "$PCAP_DONE"/*.pcap; do
  [ -s "$f.sha256" ] || { echo "no sidecar for $f"; exit 1; }
  ( cd "$PCAP_DONE" && sha256sum -c --quiet "$(basename "$f").sha256" ) || { echo "sidecar mismatch $f"; exit 1; }
done
# two ring files closed in the same second: the second gets a -1 suffix
[ "$(count "$PCAP_DONE" "corosync-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z*.pcap")" = 2 ] || { echo "ring file not renamed by mtime: $(ls "$PCAP_DONE")"; exit 1; }
write_pcap "$PCAP_DONE/custom-unsealed.pcap" 2                # no sidecar: must not be pulled

# 4. pull
export ARCHIVE="$tmp/worm" STAGE="$tmp/stage" MIRROR="$tmp/mirror" INDEX="$tmp/state/shipped.tsv"
mkdir -p "$ARCHIVE"
PCAP_NODES="testnode=$PCAP_DONE/" "$here/pcap/pcap-pull.sh" > "$tmp/pull1.log"
b=$(first "$ARCHIVE/testnode" "*")
d="$ARCHIVE/testnode/$b"
[ "$(count "$d" "*.pcap")" = 3 ] || { echo "batch should hold 3 pcaps: $(ls "$d")"; cat "$tmp/pull1.log"; exit 1; }
if [ ! -e "$d/MANIFEST.tsv" ] || [ ! -e "$d/SHA256SUMS" ]; then echo "batch lacks MANIFEST or SHA256SUMS"; exit 1; fi
grep -q 'custom-unsealed' "$d/MANIFEST.tsv" && { echo "unsealed file was published"; exit 1; }
[ "$(grep -vc '^#' "$INDEX")" = 3 ] || { echo "index should have 3 rows"; cat "$INDEX"; exit 1; }
grep -q "$(printf '\t5\t')" "$d/MANIFEST.tsv" || { echo "manifest lacks the 5-packet row"; cat "$d/MANIFEST.tsv"; exit 1; }
chmod -R a-w "$d"                                            # WORM stand-in
PCAP_NODES="testnode=$PCAP_DONE/" "$here/pcap/pcap-pull.sh" > "$tmp/pull2.log"
[ "$(count "$ARCHIVE/testnode" "*")" = 1 ] || { echo "second pull made a new batch"; ls "$ARCHIVE/testnode"; exit 1; }
grep -q 'nothing new' "$tmp/pull2.log" || { echo "second pull: $(cat "$tmp/pull2.log")"; exit 1; }
[ "$(count "$MIRROR/testnode" "*.pcap")" = 1 ] || { echo "mirror should keep only the unsealed file: $(ls "$MIRROR/testnode")"; exit 1; }
# a sidecar that lies
write_pcap "$PCAP_DONE/custom-lie.pcap" 4
( cd "$PCAP_DONE" && printf '%s  custom-lie.pcap\n' "$(printf '%064d' 0)" > custom-lie.pcap.sha256 )
rc=0; PCAP_NODES="testnode=$PCAP_DONE/" "$here/pcap/pcap-pull.sh" > "$tmp/pull3.log" 2>&1 || rc=$?
[ "$rc" = 1 ] || { echo "lying sidecar: expected exit 1, got $rc"; cat "$tmp/pull3.log"; exit 1; }
[ "$(count "$ARCHIVE/testnode" "*")" = 1 ] || { echo "lying sidecar was published"; exit 1; }
rm -f "$PCAP_DONE/custom-lie.pcap" "$PCAP_DONE/custom-lie.pcap.sha256"
# a truncated capture (killed mid-write) is published and flagged
write_pcap "$PCAP_DONE/custom-cut.pcap" 6
truncate -s $((24 + 6 * 76 - 30)) "$PCAP_DONE/custom-cut.pcap"
( cd "$PCAP_DONE" && sha256sum custom-cut.pcap > custom-cut.pcap.sha256 )
PCAP_NODES="testnode=$PCAP_DONE/" "$here/pcap/pcap-pull.sh" > "$tmp/pull4.log"
b2=$(last "$ARCHIVE/testnode" "*"); d2="$ARCHIVE/testnode/$b2"
[ "$b2" != "$b" ] || { echo "truncated file made no batch"; cat "$tmp/pull4.log"; exit 1; }
grep -q "$(printf 'custom-cut.pcap\t[0-9]*\t5\t.*\t1\t')" "$d2/MANIFEST.tsv" || { echo "truncated row wrong"; cat "$d2/MANIFEST.tsv"; exit 1; }

# 5. verify
"$here/pcap/verify-pcap.sh" "testnode/$b" --against-index >/dev/null || { echo "verify failed on a good batch"; exit 1; }
DRILLS="$tmp/drills.jsonl" "$here/pcap/verify-pcap.sh" --latest --against-index >/dev/null || { echo "verify --latest failed"; exit 1; }
grep -q '"label":"pcap archive verify".*"result":"OK"' "$tmp/drills.jsonl" || { echo "drills.jsonl not written"; exit 1; }
chmod -R u+w "$d"
f="$d/$(first "$d" "corosync-*.pcap")"
truncate -s 24 "$f"                                          # tamper: header only
rc=0; "$here/pcap/verify-pcap.sh" "testnode/$b" >/dev/null 2>&1 || rc=$?
[ "$rc" = 1 ] || { echo "tampered batch: expected 1, got $rc"; exit 1; }
# a batch copied in by hand is intact but not in the index
cp -r "$d2" "$ARCHIVE/testnode/19990101T000000Z"
"$here/pcap/verify-pcap.sh" testnode/19990101T000000Z >/dev/null || { echo "hand copy should verify without index"; exit 1; }
rc=0; "$here/pcap/verify-pcap.sh" testnode/19990101T000000Z --against-index >/dev/null || rc=$?
[ "$rc" = 1 ] || { echo "hand copy against index: expected 1, got $rc"; exit 1; }
echo "smoke-pcap: OK"
