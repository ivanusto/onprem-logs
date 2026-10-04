#!/bin/sh
# smoke: start a throwaway VictoriaLogs (binary in $VLBIN or docker), feed one
# syslog line and one journald export entry, query them back, run the archive
# and verify scripts against a temp dir. This is the test the article's
# section 3 describes; CI runs it with docker.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d); trap 'kill $pid 2>/dev/null || true; rm -rf "$tmp"' EXIT
if [ -n "${VLBIN:-}" ]; then
  "$VLBIN" -storageDataPath="$tmp/data" -httpListenAddr=127.0.0.1:19428 -syslog.listenAddr.tcp=127.0.0.1:15514 \
    -syslog.streamFields.tcp='["hostname","app_name"]' -journald.streamFields=_HOSTNAME,_SYSTEMD_UNIT >"$tmp/vl.log" 2>&1 &
  pid=$!
else
  cid=$(docker run -d --rm -p 127.0.0.1:19428:9428 -p 127.0.0.1:15514:514 victoriametrics/victoria-logs:v1.52.0 \
    -syslog.listenAddr.tcp=:514 -syslog.streamFields.tcp='["hostname","app_name"]' -journald.streamFields=_HOSTNAME,_SYSTEMD_UNIT)
  pid=""; trap 'docker stop "$cid" >/dev/null; rm -rf "$tmp"' EXIT
fi
for _ in 1 2 3 4 5 6 7 8 9 10; do curl -sf http://127.0.0.1:19428/health >/dev/null && break; sleep 1; done
day=$(date -u +%Y-%m-%d)
printf '<14>1 %sT01:02:03Z nas-test qulogd 1 - - [System] smoke login\n' "$day" | nc -q1 127.0.0.1 15514
printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=node-test\n_SYSTEMD_UNIT=smoke.service\nPRIORITY=6\nMESSAGE=smoke journald\n\n' "$(( $(date +%s) * 1000000 ))" \
  | curl -sf -X POST -H 'Content-Type: application/vnd.fdo.journal' --data-binary @- http://127.0.0.1:19428/insert/journald/upload
sleep 2
n=$(curl -sf http://127.0.0.1:19428/select/logsql/query -d 'query=* | stats count() as n' | python3 -c 'import json,sys;print(json.loads(sys.stdin.readline())["n"])')
[ "$n" = "2" ] || { echo "expected 2 rows, got $n"; exit 1; }
VL=http://127.0.0.1:19428 ARCHIVE="$tmp/arch" "$here/archive/archive-day.sh" "$day"
VL=http://127.0.0.1:19428 ARCHIVE="$tmp/arch" "$here/archive/verify-archive.sh" "$day" --against-live
echo "smoke: OK"
