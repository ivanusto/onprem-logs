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
#   STAGE     local scratch directory, default /var/tmp/onprem-logs-stage
#   FORCE     set to 1 to publish a day whose lines != hits (recorded as such)
#   ARCHIVE_SKIP  sources kept out of the archive by policy, space separated,
#             e.g. "syslog-fgt-edge" (Day 22: the edge firewall's traffic stays
#             in the 90-day hot tier only). A skipped source is not exported,
#             but its hit count is written to MANIFEST.tsv as a "# skipped"
#             line, so the manifest still accounts for every source of the day
#
# Layout
#   $ARCHIVE/2026/10/03/journald-pve1.jsonl.gz
#   $ARCHIVE/2026/10/03/syslog-nas-primary.jsonl.gz
#   $ARCHIVE/2026/10/03/MANIFEST.tsv       source  lines  hits  bytes  sha256
#   $ARCHIVE/2026/10/03/SHA256SUMS
#
# Everything is built and checked in $STAGE first. Only a complete, matching
# set is copied to the WORM share: data files, then MANIFEST.tsv, then
# SHA256SUMS. On a WORM share every file is locked a few minutes after its
# last write and can never be removed, so nothing temporary is ever written
# there, and SHA256SUMS is the marker that the day is complete.
set -eu

VL=${VL:-http://127.0.0.1:9428}
ARCHIVE=${ARCHIVE:-/mnt/worm/logs}
STAGE=${STAGE:-/var/tmp/onprem-logs-stage}
FORCE=${FORCE:-0}
ARCHIVE_SKIP=${ARCHIVE_SKIP:-}
CURL="curl -sS --fail --max-time 600"

day=${1:-$(date -u -d yesterday +%Y-%m-%d)}
start="${day}T00:00:00Z"
end=$(date -u -d "$day + 1 day" +%Y-%m-%dT00:00:00Z)
rel=$(printf '%s' "$day" | tr - /)
dir="$ARCHIVE/$rel"
if [ -e "$dir/SHA256SUMS" ]; then
  echo "archive-day: $dir is complete, refusing to overwrite (WORM)" >&2
  exit 3
fi
if [ -d "$dir" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then
  echo "archive-day: $dir has files but no SHA256SUMS, a previous copy was interrupted;" >&2
  echo "             the files there are locked, inspect them and record the gap by hand" >&2
  exit 4
fi
st="$STAGE/$day"
rm -rf "$st"
mkdir -p "$st"

# Each source is one file. journald rows carry _HOSTNAME, syslog rows carry
# hostname; discover both lists for the day so a new host appears by itself.
# Every request goes into a variable first: in `curl | python3` a failed
# request would read as "no hosts" or "0 hits" and a source would silently
# go missing from the archive.
values() { # $1 field_values response
  printf '%s' "$1" | python3 -c 'import json,sys;[print(v["value"]) for v in json.load(sys.stdin)["values"] if v["value"]]'
}
resp=$($CURL "$VL/select/logsql/field_values" -d "query=_time:[$start,$end) _HOSTNAME:*" -d "field=_HOSTNAME")
hosts_j=$(values "$resp")
resp=$($CURL "$VL/select/logsql/field_values" -d "query=_time:[$start,$end) hostname:*" -d "field=hostname")
hosts_s=$(values "$resp")

: > "$st/.rows"
: > "$st/.skipped"
total=0
status=0
export_one() { # $1 source name  $2 LogsQL filter
  name=$1; filter=$2
  resp=$($CURL "$VL/select/logsql/query" -d "query=_time:[$start,$end) $filter | stats count() as n")
  hits=$(printf '%s\n' "$resp" | python3 -c 'import json,sys;l=sys.stdin.readline();print(json.loads(l)["n"] if l.strip() else 0)')
  [ "$hits" -gt 0 ] || return 0
  case " $ARCHIVE_SKIP " in
    *" $name "*)
      printf '# skipped\t%s\t%s\tARCHIVE_SKIP\n' "$name" "$hits" >> "$st/.skipped"
      printf '%-32s %10s hits skipped (ARCHIVE_SKIP)\n' "$name" "$hits"
      return 0 ;;
  esac
  f="$st/$name.jsonl.gz"
  # one query per hour: `sort` runs in VictoriaLogs' memory and a whole day
  # of a busy host does not fit (the query fails with HTTP 400). Each hour is
  # sorted and appended in order. curl writes to a file rather than a pipe so
  # a failed request stops the script instead of leaving a short file.
  : > "$st/$name.jsonl"
  h=0
  while [ "$h" -lt 24 ]; do
    hs=$(date -u -d "$start + $h hour" +%Y-%m-%dT%H:%M:%SZ)
    he=$(date -u -d "$start + $((h + 1)) hour" +%Y-%m-%dT%H:%M:%SZ)
    $CURL "$VL/select/logsql/query" -d "query=_time:[$hs,$he) $filter | sort by (_time)" >> "$st/$name.jsonl"
    h=$((h + 1))
  done
  gzip -9 "$st/$name.jsonl"
  lines=$(gzip -dc "$f" | wc -l | tr -d ' ')
  bytes=$(stat -c %s "$f")
  sum=$(sha256sum "$f" | cut -d' ' -f1)
  printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$lines" "$hits" "$bytes" "$sum" >> "$st/.rows"
  if [ "$lines" -ne "$hits" ]; then
    echo "archive-day: $name lines=$lines hits=$hits MISMATCH" >&2
    status=1
  fi
  total=$((total + lines))
  printf '%-32s %10s lines %10s bytes\n' "$name" "$lines" "$bytes"
}

for h in $hosts_j; do export_one "journald-$h" "_HOSTNAME:=\"$h\""; done
for h in $hosts_s; do export_one "syslog-$h"   "hostname:=\"$h\""; done

if [ ! -s "$st/.rows" ]; then
  echo "archive-day: no logs for $day" >&2
  rm -rf "$st"
  exit 2
fi
if [ "$status" -ne 0 ] && [ "$FORCE" != 1 ]; then
  echo "archive-day: not publishing $day, staged files kept in $st; rerun, or FORCE=1 to publish as is" >&2
  exit 1
fi
{
  printf '# onprem-logs archive  day=%s  range=[%s,%s)  written=%s  host=%s  vl=%s\n' \
    "$day" "$start" "$end" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(hostname)" "$VL"
  printf '# source\tlines\thits\tbytes\tsha256\n'
  cat "$st/.rows"
  cat "$st/.skipped"
} > "$st/MANIFEST.tsv"
( cd "$st" && sha256sum ./*.jsonl.gz MANIFEST.tsv > SHA256SUMS )

# publish: data files, manifest, checksums last
mkdir -p "$dir"
for f in "$st"/*.jsonl.gz "$st/MANIFEST.tsv" "$st/SHA256SUMS"; do
  cp "$f" "$dir/"
done
if ! ( cd "$dir" && sha256sum -c --quiet SHA256SUMS ); then
  echo "archive-day: copy to $dir does not match the staged files" >&2
  exit 5
fi
rm -rf "$st"
printf 'archive-day: %s  %s sources  %s lines  -> %s  (status %s)\n' \
  "$day" "$(grep -vc '^#' "$dir/MANIFEST.tsv")" "$total" "$dir" "$status"
exit "$status"
