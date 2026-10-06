#!/bin/sh
# smoke-firewall: feed one line of each firewall log shape into a throwaway
# VictoriaLogs (binary in $VLBIN or docker, like smoke.sh) and check that
# fw-report.py counts them, writes valid metrics, and writes 0 for an
# expected host that dropped nothing (what FwSilent alerts on).
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d); pid=""; cid=""
cleanup() {
  [ -n "$pid" ] && kill "$pid" 2>/dev/null
  [ -n "$cid" ] && docker stop "$cid" >/dev/null
  rm -rf "$tmp"
}
trap cleanup EXIT
if [ -n "${VLBIN:-}" ]; then
  "$VLBIN" -storageDataPath="$tmp/data" -httpListenAddr=127.0.0.1:19429 -syslog.listenAddr.tcp=127.0.0.1:15515 \
    -syslog.streamFields.tcp='["hostname","app_name"]' -syslog.timezone=Asia/Taipei >"$tmp/vl.log" 2>&1 &
  pid=$!
else
  cid=$(docker run -d --rm -p 127.0.0.1:19429:9428 -p 127.0.0.1:15515:514 victoriametrics/victoria-logs:v1.52.0 \
    -syslog.listenAddr.tcp=:514 -syslog.streamFields.tcp='["hostname","app_name"]' -syslog.timezone=Asia/Taipei)
fi
for _ in 1 2 3 4 5 6 7 8 9 10; do curl -sf http://127.0.0.1:19429/health >/dev/null && break; sleep 1; done
now=$(( $(date +%s) * 1000000 ))
{
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=spark-t\n_SYSTEMD_UNIT=init.scope\n_TRANSPORT=kernel\nPRIORITY=4\nMESSAGE=[UFW BLOCK] IN=eth0 OUT= MAC=aa:bb SRC=10.0.0.5 DST=10.0.0.1 LEN=60 PROTO=TCP SPT=1 DPT=22 SYN\n\n' "$now"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=pve-t\n_SYSTEMD_UNIT=pvefw-journal.service\nSYSLOG_IDENTIFIER=pve-firewall\nPRIORITY=6\nMESSAGE=0 6 PVEFW-HOST-IN 06/Oct/2026:14:00:00 +0800 policy DROP: IN=vmbr0 OUT= SRC=10.0.0.6 DST=10.0.0.2 PROTO=TCP SPT=2 DPT=8006 SYN\n\n' "$now"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=init.scope\n_TRANSPORT=kernel\nPRIORITY=4\nMESSAGE=[DOCKER-USER DROP] IN=eth0 OUT=br-1 MAC=aa:bb:cc SRC=10.0.0.7 DST=172.18.0.3 LEN=60 PROTO=TCP SPT=3 DPT=9428 SYN\n\n' "$now"
} | curl -sf -X POST -H 'Content-Type: application/vnd.fdo.journal' --data-binary @- http://127.0.0.1:19429/insert/journald/upload
# FortiGate syslogd with format rfc5424: devname is the header hostname,
# _msg is key=value. One deny that counts, one accept that must not.
ts=$(date +%Y-%m-%dT%H:%M:%S%z | sed 's/\(..\)$/:\1/')
for a in deny accept; do
  printf '<189>1 %s fgt-t - - - - eventtime=1 tz="+0800" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.0.0.9 srcport=4 srcintf="internal" dstip=203.0.113.1 dstport=123 dstintf="wan1" proto=17 action="%s" policyid=4\n' "$ts" "$a"
done | nc -q1 127.0.0.1 15515
# QuLog connection log, RFC 3164 as QuTS hero 6.0.2 sends it: local time with
# no zone, read back with -syslog.timezone=Asia/Taipei, so stamp it in that zone
# whatever the runner runs in (CI is UTC)
printf '<30>%s nas-t qulogd[1]: conn log: Users: admin, Source IP: 10.0.0.8, Computer name: ---, Connection type: SSH/SFTP, Accessed resources: ---, Action: Login Fail\n' "$(TZ=Asia/Taipei LC_ALL=C date '+%b %e %H:%M:%S')" | nc -q1 127.0.0.1 15515
sleep 2
python3 -I "$here/firewall/fw-report.py" --vl http://127.0.0.1:19429 --window 1h --baseline 7d \
  --expect 'fortigate:fgt-t,docker-user:quiet-t' --textfile "$tmp/fw.prom" --out "$tmp/r.md"
fail() { echo "smoke-firewall: $1"; cat "$tmp/fw.prom"; exit 1; }
grep -q 'fw_blocked{source="ufw",host="spark-t"} 1' "$tmp/fw.prom" || fail "ufw count"
grep -q 'fw_blocked{source="pvefw",host="pve-t"} 1' "$tmp/fw.prom" || fail "pvefw count"
grep -q 'fw_blocked{source="docker-user",host="coll-t"} 1' "$tmp/fw.prom" || fail "docker-user count"
grep -q 'fw_blocked{source="fortigate",host="fgt-t"} 1' "$tmp/fw.prom" || fail "fortigate count (accept must not count)"
grep -q 'fw_blocked{source="docker-user",host="quiet-t"} 0' "$tmp/fw.prom" || fail "expected host with no drops must be 0"
grep -q 'nas_login_failed{nas="nas-t"} 1' "$tmp/fw.prom" || fail "nas login failure"
grep -q '10.0.0.8' "$tmp/r.md" || fail "nas source missing from the report"
grep -q '| fgt-t | UDP | 123 | 1 |' "$tmp/r.md" || fail "fortigate port table"
if command -v promtool >/dev/null; then promtool check metrics < "$tmp/fw.prom"; fi
echo "smoke-firewall: OK"
