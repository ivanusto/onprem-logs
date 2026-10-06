#!/bin/sh
# smoke: start a throwaway VictoriaLogs (binary in $VLBIN or docker), feed one
# syslog line and one journald export entry, query them back, run the archive
# and verify scripts against a temp dir. This is the test the article's
# section 3 describes; CI runs it with docker.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d); trap 'kill $pid 2>/dev/null || true; chmod -R u+w "$tmp"; rm -rf "$tmp"' EXIT
if [ -n "${VLBIN:-}" ]; then
  "$VLBIN" -storageDataPath="$tmp/data" -httpListenAddr=127.0.0.1:19428 -syslog.listenAddr.tcp=127.0.0.1:15514 \
    -syslog.streamFields.tcp='["hostname","app_name"]' -journald.streamFields=_HOSTNAME,_SYSTEMD_UNIT >"$tmp/vl.log" 2>&1 &
  pid=$!
else
  cid=$(docker run -d --rm -p 127.0.0.1:19428:9428 -p 127.0.0.1:15514:514 victoriametrics/victoria-logs:v1.52.0 \
    -syslog.listenAddr.tcp=:514 -syslog.streamFields.tcp='["hostname","app_name"]' -journald.streamFields=_HOSTNAME,_SYSTEMD_UNIT)
  pid=""; trap 'docker stop "$cid" >/dev/null; chmod -R u+w "$tmp"; rm -rf "$tmp"' EXIT
fi
for _ in 1 2 3 4 5 6 7 8 9 10; do curl -sf http://127.0.0.1:19428/health >/dev/null && break; sleep 1; done
day=$(date -u +%Y-%m-%d)
printf '<14>1 %sT01:02:03Z nas-test qulogd 1 - - [System] smoke login\n' "$day" | nc -q1 127.0.0.1 15514
printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=node-test\n_SYSTEMD_UNIT=smoke.service\nPRIORITY=6\nMESSAGE=smoke journald\n\n' "$(( $(date +%s) * 1000000 ))" \
  | curl -sf -X POST -H 'Content-Type: application/vnd.fdo.journal' --data-binary @- http://127.0.0.1:19428/insert/journald/upload
sleep 2
n=$(curl -sf http://127.0.0.1:19428/select/logsql/query -d 'query=* | stats count() as n' | python3 -c 'import json,sys;print(json.loads(sys.stdin.readline())["n"])')
[ "$n" = "2" ] || { echo "expected 2 rows, got $n"; exit 1; }
export VL=http://127.0.0.1:19428 ARCHIVE="$tmp/arch" STAGE="$tmp/stage"
"$here/archive/archive-day.sh" "$day"
DRILLS="$tmp/drills.jsonl" "$here/archive/verify-archive.sh" "$day" --against-live
grep -q '"result":"OK"' "$tmp/drills.jsonl" || { echo "drills.jsonl not written"; exit 1; }

# WORM stand-in: lock the day like the share does, a rerun must refuse
# without leaving anything behind
d="$tmp/arch/$(printf '%s' "$day" | tr - /)"
chmod -R a-w "$d"
rc=0; "$here/archive/archive-day.sh" "$day" 2>/dev/null || rc=$?
[ "$rc" = 3 ] || { echo "rerun on a complete day: expected exit 3, got $rc"; exit 1; }
[ "$(find "$d" -mindepth 1 -printf '%f ' | tr ' ' '\n' | LC_ALL=C sort | tr '\n' ' ')" = "MANIFEST.tsv SHA256SUMS journald-node-test.jsonl.gz syslog-nas-test.jsonl.gz " ] \
  || { echo "unexpected files in $d: $(find "$d" -mindepth 1)"; exit 1; }
chmod -R u+w "$d"

# tamper: one line short must fail sha256 and the line count
gzip -dc "$d/syslog-nas-test.jsonl.gz" | head -0 | gzip > "$d/syslog-nas-test.jsonl.gz.new"
mv "$d/syslog-nas-test.jsonl.gz.new" "$d/syslog-nas-test.jsonl.gz"
rc=0; "$here/archive/verify-archive.sh" "$day" >/dev/null || rc=$?
[ "$rc" = 1 ] || { echo "tampered archive: expected exit 1, got $rc"; exit 1; }
# collector unreachable: must fail and write nothing to the archive
rc=0; VL=http://127.0.0.1:1 "$here/archive/archive-day.sh" 2000-01-01 2>/dev/null || rc=$?
if [ "$rc" = 0 ] || [ -e "$tmp/arch/2000" ]; then
  echo "dead collector: expected failure and no files, got rc=$rc"; exit 1
fi
# ARCHIVE_SKIP: the skipped source is not exported, the manifest says so with
# its hit count, and verify still passes
rc=0; ARCHIVE="$tmp/arch-skip" ARCHIVE_SKIP="syslog-nas-test" "$here/archive/archive-day.sh" "$day" >/dev/null || rc=$?
ds="$tmp/arch-skip/$(printf '%s' "$day" | tr - /)"
if [ "$rc" != 0 ] || [ -e "$ds/syslog-nas-test.jsonl.gz" ] || [ ! -e "$ds/journald-node-test.jsonl.gz" ]; then
  echo "ARCHIVE_SKIP: expected only the journald file, rc=$rc: $(ls "$ds" 2>&1)"; exit 1
fi
grep -q "$(printf '^# skipped\tsyslog-nas-test\t1\tARCHIVE_SKIP$')" "$ds/MANIFEST.tsv" \
  || { echo "ARCHIVE_SKIP: no skipped line in the manifest"; cat "$ds/MANIFEST.tsv"; exit 1; }
ARCHIVE="$tmp/arch-skip" "$here/archive/verify-archive.sh" "$day" --against-live >/dev/null \
  || { echo "ARCHIVE_SKIP: verify failed on a day with a skipped source"; exit 1; }
echo "smoke: OK"
