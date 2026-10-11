#!/bin/sh
# smoke-audit: the Day 27 path. A throwaway VictoriaLogs with the two syslog
# listeners of the collector's compose (514 plain, 515 stamping
# audit=fortigate); one line of every administrative action shape; a fake
# onprem-changes clone with three records; then
#   1. audit-report.py attributes what falls inside a window, lists the rest,
#      applies the ignore list, and flags a done record with no change mark
#   2. the textfile carries the same numbers
#   3. archive-day.sh exports the audit stream as its own source while the
#      traffic on 514 is skipped, and verify-archive.sh accepts the day
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d); pid=""; cid=""
cleanup() {
  if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  [ -n "$cid" ] && docker stop "$cid" >/dev/null
  chmod -R u+w "$tmp" 2>/dev/null; rm -rf "$tmp"
}
trap cleanup EXIT
if [ -n "${VLBIN:-}" ]; then
  "$VLBIN" -storageDataPath="$tmp/data" -httpListenAddr=127.0.0.1:19433 -syslog.listenAddr.tcp=127.0.0.1:15533,127.0.0.1:15534 \
    -syslog.streamFields.tcp='["hostname","app_name"],["hostname","audit"]' -syslog.extraFields.tcp='{},{"audit":"fortigate"}' \
    -journald.streamFields=_HOSTNAME,_SYSTEMD_UNIT -syslog.timezone=Asia/Taipei >"$tmp/vl.log" 2>&1 &
  pid=$!
else
  cid=$(docker run -d --rm -p 127.0.0.1:19433:9428 -p 127.0.0.1:15533:514 -p 127.0.0.1:15534:515 victoriametrics/victoria-logs:v1.52.0 \
    -syslog.listenAddr.tcp=:514,:515 -syslog.streamFields.tcp='["hostname","app_name"],["hostname","audit"]' \
    -syslog.extraFields.tcp='{},{"audit":"fortigate"}' -journald.streamFields=_HOSTNAME,_SYSTEMD_UNIT -syslog.timezone=Asia/Taipei)
fi
for _ in 1 2 3 4 5 6 7 8 9 10; do curl -sf http://127.0.0.1:19433/health >/dev/null && break; sleep 1; done
VL=http://127.0.0.1:19433
now=$(date +%s)
iso() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; }
us() { echo "$(( $1 * 1000000 ))"; }
earlier=$((now - 1800))     # 30 minutes ago: outside the change window below

# journald: a PVE task, the nightly vzdump (ignored), a sudo outside the
# window, an ssh login inside it, and the change marks
{
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=pve-t\n_SYSTEMD_UNIT=pvedaemon.service\nSYSLOG_IDENTIFIER=pvedaemon\nPRIORITY=6\nMESSAGE=<root@pam> starting task UPID:pve-t:0000A1B2:00C3D4E5:68E9F000:qmstart:100:root@pam:\n\n' "$(us "$now")"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=pve-t\n_SYSTEMD_UNIT=pvedaemon.service\nSYSLOG_IDENTIFIER=pvedaemon\nPRIORITY=6\nMESSAGE=<root@pam> starting task UPID:pve-t:0000A1B3:00C3D4E6:68E9F001:vzdump::root@pam:\n\n' "$(us "$now")"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=session-9.scope\nSYSLOG_IDENTIFIER=sudo\nPRIORITY=5\nMESSAGE=    ivan : TTY=pts/0 ; PWD=/home/ivan ; USER=root ; COMMAND=/usr/bin/systemctl restart grafana\n\n' "$(us "$earlier")"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=pve-t\n_SYSTEMD_UNIT=ssh.service\nSYSLOG_IDENTIFIER=sshd\nPRIORITY=6\nMESSAGE=Accepted publickey for root from 10.0.0.10 port 50000 ssh2: ED25519 SHA256:abc\n\n' "$(us "$now")"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=session-9.scope\nSYSLOG_IDENTIFIER=change\nPRIORITY=5\nMESSAGE=CR-2026-0001 begin smoke change\n\n' "$(us $((now - 60)))"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=session-9.scope\nSYSLOG_IDENTIFIER=change\nPRIORITY=5\nMESSAGE=CR-2026-0001 end smoke change\n\n' "$(us $((now + 60)))"
} | curl -sf -X POST -H 'Content-Type: application/vnd.fdo.journal' --data-binary @- "$VL/insert/journald/upload"

# 514: FortiGate traffic (not an action) and the NAS event and connection logs
ts() { date -d "@$1" +%Y-%m-%dT%H:%M:%S%z | sed 's/\(..\)$/:\1/'; }
printf '<189>1 %s fgt-t - - - - eventtime=1 tz="+0800" logid="0000000013" type="traffic" subtype="forward" action="deny" srcip=10.0.0.9 dstport=123\n' "$(ts "$now")" | nc -q1 127.0.0.1 15533
lt() { TZ=Asia/Taipei LC_ALL=C date -d "@$1" '+%b %e %H:%M:%S'; }
printf '<30>%s nas-t qulogd[1]: event log: Users: admin, Source IP: 10.0.0.8, Computer name: ---, Category: Virtualization Station, Content: Created snapshot "CR-2026-0001-before" for VM qnetd\n' "$(lt "$now")" | nc -q1 127.0.0.1 15533
printf '<30>%s nas-t qulogd[1]: conn log: Users: admin, Source IP: 10.0.0.8, Computer name: ---, Connection type: HTTPS, Accessed resources: ---, Action: Login Success\n' "$(lt "$now")" | nc -q1 127.0.0.1 15533
# 515: the FortiGate event log, a config change inside the window and an admin login outside it
printf '<190>1 %s fgt-t - - - - eventtime=1 tz="+0800" logid="0100044546" type="event" subtype="system" level="information" logdesc="Attribute configured" user="admin" ui="jsconsole(10.0.0.10)" action="Edit" cfgtid=1 cfgpath="firewall.policy" cfgobj="1" cfgattr="utm-status[disable->enable]" msg="Edit firewall.policy 1"\n' "$(ts "$now")" | nc -q1 127.0.0.1 15534
printf '<190>1 %s fgt-t - - - - eventtime=1 tz="+0800" logid="0100032001" type="event" subtype="system" level="information" logdesc="Admin login successful" user="admin" ui="https(10.0.0.10)" action="login" status="success" msg="Administrator admin logged in successfully from https(10.0.0.10)"\n' "$(ts "$earlier")" | nc -q1 127.0.0.1 15534
sleep 2

# three change records: one open around now with marks, one backfilled last
# week (no marks expected), one done two hours ago with no marks
mkdir -p "$tmp/changes"
rec() { # id status start end tags
  printf -- '---\nid: %s\ntitle: smoke %s\nstatus: %s\ntype: standard\nrisk: low\nrequester: a\nimplementer: a\napprover: b\nassets:\n  - x/y\nwindow_start: %s\nwindow_end: %s\ntags: %s\n---\n\n## 目的\nx\n' "$1" "$1" "$2" "$3" "$4" "$5" > "$tmp/changes/$1-smoke.md"
}
rec CR-2026-0001 "done" "$(iso $((now - 600)))" "$(iso $((now + 1200)))" smoke
rec CR-2026-0002 "done" "$(iso $((now - 7 * 86400)))" "$(iso $((now - 7 * 86400 + 3600)))" "smoke, backfill"
rec CR-2026-0003 "done" "$(iso $((now - 10800)))" "$(iso $((now - 7200)))" smoke

python3 -I "$here/audit/audit-report.py" --vl "$VL" --window 1d --changes "$tmp/changes" --out "$tmp/r.md" --textfile "$tmp/audit.prom"
grep -q '^管理動作 6 筆（忽略清單排除 1 筆），有變更單的 4 筆，沒有的 2 筆$' "$tmp/r.md" || { echo "summary line wrong"; sed -n 1,6p "$tmp/r.md"; exit 1; }
grep -q 'sudo | coll-t | ivan | as root: /usr/bin/systemctl restart grafana' "$tmp/r.md" || { echo "sudo row missing from unattributed"; cat "$tmp/r.md"; exit 1; }
grep -q 'fortigate-login | fgt-t | admin | Admin login successful success (https(10.0.0.10))' "$tmp/r.md" || { echo "login row missing"; cat "$tmp/r.md"; exit 1; }
grep -q 'fortigate-config | fgt-t | admin | Edit firewall.policy 1 utm-status\[disable->enable\] (jsconsole(10.0.0.10))' "$tmp/r.md" || { echo "config row missing"; cat "$tmp/r.md"; exit 1; }
grep -q '\*\*CR-2026-0001\*\* smoke CR-2026-0001（done' "$tmp/r.md" || { echo "CR-0001 section missing"; exit 1; }
grep -q 'nas-event | nas-t | admin | Users: admin, Source IP: 10.0.0.8, Computer name: ---, Category: Virtualization Station, Content: Created snapshot' "$tmp/r.md" || { echo "nas row missing"; cat "$tmp/r.md"; exit 1; }
grep -q 'vzdump' "$tmp/r.md" && { echo "vzdump should be ignored"; exit 1; }
grep -q 'CR-2026-0003 | smoke CR-2026-0003' "$tmp/r.md" || { echo "CR-0003 should be listed without marks"; cat "$tmp/r.md"; exit 1; }
grep -q 'CR-2026-0002' "$tmp/r.md" && { echo "a backfilled record is not expected to have marks"; exit 1; }
for want in 'audit_actions{source="fortigate-config"} 1' 'audit_actions{source="pve-task"} 1' 'audit_actions{source="sudo"} 1' 'audit_actions{source="ssh-login"} 1' 'audit_actions{source="nas-event"} 1' \
            'audit_unattributed{source="sudo"} 1' 'audit_unattributed{source="fortigate-login"} 1' 'audit_unattributed{source="fortigate-config"} 0' 'audit_changes_without_marks 1'; do
  grep -qF "$want" "$tmp/audit.prom" || { echo "textfile lacks: $want"; cat "$tmp/audit.prom"; exit 1; }
done
[ "$(stat -c %a "$tmp/audit.prom")" = 644 ] || { echo "textfile mode"; exit 1; }
# an absolute range that misses every change record: all unattributed, no sections
python3 -I "$here/audit/audit-report.py" --vl "$VL" --since "$(iso $((now - 3600)))" --until "$(iso $((now + 3600)))" --changes "$tmp/nochanges" > "$tmp/r2.md" 2>"$tmp/r2.err"
grep -q 'no change records' "$tmp/r2.err" || { cat "$tmp/r2.err"; exit 1; }
grep -q '有變更單的 0 筆，沒有的 6 筆' "$tmp/r2.md" || { sed -n 1,4p "$tmp/r2.md"; exit 1; }

# archive: the audit stream is its own source, the traffic on 514 is skipped
day=$(date -u +%Y-%m-%d)
export VL ARCHIVE="$tmp/arch" STAGE="$tmp/stage"
ARCHIVE_SKIP="syslog-fgt-t" "$here/archive/archive-day.sh" "$day" > "$tmp/arch.log"
d="$tmp/arch/$(printf '%s' "$day" | tr - /)"
[ -e "$d/audit-fgt-t.jsonl.gz" ] || { echo "audit source not exported"; cat "$tmp/arch.log"; ls "$d"; exit 1; }
[ "$(gzip -dc "$d/audit-fgt-t.jsonl.gz" | wc -l)" = 2 ] || { echo "audit file should hold 2 lines"; exit 1; }
[ ! -e "$d/syslog-fgt-t.jsonl.gz" ] || { echo "traffic should be skipped"; exit 1; }
grep -q "$(printf '^# skipped\tsyslog-fgt-t\t1\tARCHIVE_SKIP$')" "$d/MANIFEST.tsv" || { echo "skipped line should count only the traffic line"; cat "$d/MANIFEST.tsv"; exit 1; }
grep -q "$(printf '^syslog-nas-t\t2\t2\t')" "$d/MANIFEST.tsv" || { echo "nas source should have 2 lines"; cat "$d/MANIFEST.tsv"; exit 1; }
"$here/archive/verify-archive.sh" "$day" --against-live > "$tmp/verify.log" || { cat "$tmp/verify.log"; exit 1; }
grep -q '^audit-fgt-t .* ok$' "$tmp/verify.log" || { cat "$tmp/verify.log"; exit 1; }
echo "smoke-audit: OK"
