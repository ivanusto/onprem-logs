#!/bin/sh
# verify-pcap: prove one published capture batch is intact.
#   1. SHA256SUMS matches every file (nothing changed since it was written)
#   2. every MANIFEST row still has the same byte count and packet count
#      when the file is re-read with pcap-stat.py
#   3. with --against-index, every row is also in the collector's shipped
#      index with the same sha256 and the same batch name (the batch was
#      written by pcap-pull.sh, not copied in by hand)
#
#   verify-pcap.sh <node>/<batch> [--against-index]
#   verify-pcap.sh --latest [--against-index]      every node's newest batch
#
# DRILLS   optional drills.jsonl; one line per run, label "pcap archive
#          verify", so onprem-metrics' drills-textfile.py exposes the result
set -eu

ARCHIVE=${ARCHIVE:-/mnt/worm/pcap}
INDEX=${INDEX:-/var/lib/onprem-pcap/shipped.tsv}
here=$(cd "$(dirname "$0")" && pwd)
STAT=${PCAP_STAT:-$here/pcap-stat.py}

sel=${1:-}; [ -n "$sel" ] || { sed -n '2,13p' "$0"; exit 64; }
idx=0; [ "${2:-}" = "--against-index" ] && idx=1

verify_one() { # $1 node/batch
  dir="$ARCHIVE/$1"
  node=${1%%/*}; batch=${1#*/}
  [ -s "$dir/MANIFEST.tsv" ] || { echo "no manifest in $dir" >&2; return 2; }
  r=0
  fail=$(mktemp)   # never a temporary file on the WORM share
  if ( cd "$dir" && sha256sum -c --quiet SHA256SUMS ); then echo "sha256   : OK  $1"; else echo "sha256   : FAILED  $1"; r=1; fi
  grep -v '^#' "$dir/MANIFEST.tsv" | while IFS="$(printf '\t')" read -r file bytes pkts _ _ _ sum; do
    s="ok"
    if line=$(python3 -I "$STAT" "$dir/$file" 2>/dev/null); then
      now_b=$(printf '%s' "$line" | cut -f2); now_p=$(printf '%s' "$line" | cut -f3)
      [ "$now_b" = "$bytes" ] || s="bytes=$now_b"
      [ "$now_p" = "$pkts" ] || s="$s packets=$now_p"
    else
      s="unreadable"
    fi
    if [ "$idx" -eq 1 ]; then
      grep -q "^$sum	$node	$file	[0-9]*	[0-9]*	$batch\$" "$INDEX" || s="$s not-in-index"
    fi
    printf '%-40s bytes=%-10s packets=%-8s %s\n' "$file" "$bytes" "$pkts" "$s"
    [ "$s" = "ok" ] || echo "FAIL $file" >> "$fail"
  done
  # the loop runs in a subshell; the marker file carries the result out
  [ -s "$fail" ] && r=1
  rm -f "$fail"
  return "$r"
}

rc=0
if [ "$sel" = --latest ]; then
  for nd in "$ARCHIVE"/*/; do
    [ -d "$nd" ] || continue
    node=$(basename "$nd")
    latest=$(find "$nd" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort | tail -n1)
    [ -n "$latest" ] || continue
    verify_one "$node/$latest" || rc=1
  done
else
  verify_one "$sel" || rc=1
fi
if [ "$rc" -eq 0 ]; then result=OK; else result=FAIL; fi
echo "verify   : $result"
if [ -n "${DRILLS:-}" ]; then
  printf '{"t0":"%s","label":"pcap archive verify","selection":"%s","index":%s,"result":"%s","code":%s}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$sel" "$idx" "$result" "$rc" >> "$DRILLS"
fi
exit "$rc"
