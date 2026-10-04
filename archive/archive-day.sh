#!/bin/sh
# archive-day: export one UTC day of logs from VictoriaLogs into gzip'd JSONL
# files on a WORM share, with a manifest that lets Day 27 prove the archive
# is complete: for every source, the number of lines in the file must equal
# the number of hits VictoriaLogs reports for that day.
#
#   archive-day.sh [YYYY-MM-DD]        default: yesterday (UTC)
#
# Environment
#   VL        VictoriaLogs base URL, default http://127.0.0.1:9428
#   ARCHIVE   root of the archive, default /mnt/worm/logs
#             (a QuTS hero WORM share mounted on the collector, see retention.md)
#
# Layout
#   $ARCHIVE/2026/10/03/journald-pve1.jsonl.gz
#   $ARCHIVE/2026/10/03/syslog-nas-primary.jsonl.gz
#   $ARCHIVE/2026/10/03/MANIFEST.tsv       source  lines  hits  bytes  sha256
#   $ARCHIVE/2026/10/03/SHA256SUMS
#
# Files are written to a temp name and renamed into place. On a WORM share
# the rename is the last write that will ever succeed on that path, so the
# manifest is written after every data file is final.
set -eu

VL=${VL:-http://127.0.0.1:9428}
ARCHIVE=${ARCHIVE:-/mnt/worm/logs}
CURL="curl -sS --fail --max-time 600"

day=${1:-$(date -u -d yesterday +%Y-%m-%d)}
start="${day}T00:00:00Z"
end=$(date -u -d "$day + 1 day" +%Y-%m-%dT00:00:00Z)
dir="$ARCHIVE/$(printf '%s' "$day" | tr - /)"
mkdir -p "$dir"
if [ -s "$dir/MANIFEST.tsv" ]; then
  echo "archive-day: $dir already has a manifest, refusing to overwrite (WORM)" >&2
  exit 3
fi

# Each source is one file. journald rows carry _HOSTNAME, syslog rows carry
# hostname; discover both lists for the day so a new host appears by itself.
hosts_j=$($CURL "$VL/select/logsql/field_values" -d "query=_time:[$start,$end) _HOSTNAME:*" -d 'field=_HOSTNAME' \
          | python3 -c 'import json,sys;[print(v["value"]) for v in json.load(sys.stdin)["values"] if v["value"]]')
hosts_s=$($CURL "$VL/select/logsql/field_values" -d "query=_time:[$start,$end) hostname:*" -d 'field=hostname' \
          | python3 -c 'import json,sys;[print(v["value"]) for v in json.load(sys.stdin)["values"] if v["value"]]')

: > "$dir/.MANIFEST.tmp"
total=0
export_one() { # $1 source name  $2 LogsQL filter
  name=$1; filter=$2
  hits=$($CURL "$VL/select/logsql/query" -d "query=_time:[$start,$end) $filter | stats count() as n" \
         | python3 -c 'import json,sys;l=sys.stdin.readline();print(json.loads(l)["n"] if l.strip() else 0)')
  [ "$hits" -gt 0 ] || return 0
  tmp="$dir/.$name.jsonl.gz.tmp"
  $CURL "$VL/select/logsql/query" -d "query=_time:[$start,$end) $filter | sort by (_time)" | gzip -9 > "$tmp"
  lines=$(gzip -dc "$tmp" | wc -l | tr -d ' ')
  mv "$tmp" "$dir/$name.jsonl.gz"
  bytes=$(stat -c %s "$dir/$name.jsonl.gz")
  sum=$(sha256sum "$dir/$name.jsonl.gz" | cut -d' ' -f1)
  printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$lines" "$hits" "$bytes" "$sum" >> "$dir/.MANIFEST.tmp"
  if [ "$lines" -ne "$hits" ]; then
    echo "archive-day: $name lines=$lines hits=$hits MISMATCH" >&2
    status=1
  fi
  total=$((total + lines))
  printf '%-32s %10s lines %10s bytes\n' "$name" "$lines" "$bytes"
}

status=0
for h in $hosts_j; do export_one "journald-$h" "_HOSTNAME:=\"$h\""; done
for h in $hosts_s; do export_one "syslog-$h"   "hostname:=\"$h\""; done

if [ ! -s "$dir/.MANIFEST.tmp" ]; then
  echo "archive-day: no logs for $day" >&2
  rm -f "$dir/.MANIFEST.tmp"
  exit 2
fi
{
  printf '# onprem-logs archive  day=%s  range=[%s,%s)  written=%s  host=%s  vl=%s\n' \
    "$day" "$start" "$end" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(hostname)" "$VL"
  printf '# source\tlines\thits\tbytes\tsha256\n'
  cat "$dir/.MANIFEST.tmp"
} > "$dir/MANIFEST.tsv"
rm -f "$dir/.MANIFEST.tmp"
( cd "$dir" && sha256sum ./*.jsonl.gz MANIFEST.tsv > SHA256SUMS )
printf 'archive-day: %s  %s sources  %s lines  -> %s  (status %s)\n' \
  "$day" "$(grep -vc '^#' "$dir/MANIFEST.tsv")" "$total" "$dir" "$status"
exit "$status"
