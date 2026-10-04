#!/bin/sh
# verify-archive: prove one archived day is intact and complete.
#   1. SHA256SUMS matches every file (nothing changed since it was written)
#   2. every MANIFEST row has lines == hits (nothing was missing when written)
#   3. the gzip streams decompress and the line counts still match
# With --against-live it also re-asks VictoriaLogs for the day's hit count
# per source, which only works while the day is inside the hot retention.
#
#   verify-archive.sh YYYY-MM-DD [--against-live]
set -eu

VL=${VL:-http://127.0.0.1:9428}
ARCHIVE=${ARCHIVE:-/mnt/worm/logs}
day=${1:-}; [ -n "$day" ] || { sed -n '2,11p' "$0"; exit 64; }
live=0; [ "${2:-}" = "--against-live" ] && live=1
dir="$ARCHIVE/$(printf '%s' "$day" | tr - /)"
[ -s "$dir/MANIFEST.tsv" ] || { echo "no manifest in $dir" >&2; exit 2; }

rc=0
fail=$(mktemp)
if ( cd "$dir" && sha256sum -c --quiet SHA256SUMS ); then echo "sha256   : OK"; else echo "sha256   : FAILED"; rc=1; fi

start="${day}T00:00:00Z"; end=$(date -u -d "$day + 1 day" +%Y-%m-%dT00:00:00Z)
# shellcheck disable=SC2034
grep -v '^#' "$dir/MANIFEST.tsv" | while IFS="$(printf '\t')" read -r name lines hits bytes sum; do
  now_lines=$(gzip -dc "$dir/$name.jsonl.gz" | wc -l | tr -d ' ')
  s="ok"
  [ "$lines" = "$hits" ] || s="lines!=hits"
  [ "$now_lines" = "$lines" ] || s="$s decompressed=$now_lines"
  if [ "$live" -eq 1 ]; then
    case "$name" in
      journald-*) f="_HOSTNAME:=\"${name#journald-}\"" ;;
      syslog-*)   f="hostname:=\"${name#syslog-}\"" ;;
    esac
    live_hits=$(curl -sS --fail "$VL/select/logsql/query" -d "query=_time:[$start,$end) $f | stats count() as n" \
                | python3 -c 'import json,sys;l=sys.stdin.readline();print(json.loads(l)["n"] if l.strip() else 0)')
    [ "$live_hits" = "$hits" ] || s="$s live=$live_hits"
  fi
  printf '%-32s lines=%-8s hits=%-8s %s\n' "$name" "$lines" "$hits" "$s"
  [ "$s" = "ok" ] || echo "FAIL $name" >> "$fail"
done
[ -s "$fail" ] && rc=1
rm -f "$fail"
if [ "$rc" -eq 0 ]; then echo "verify   : OK $day"; else echo "verify   : FAILED $day"; fi
exit "$rc"
