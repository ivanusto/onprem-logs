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
#   4. --quiet-from marks an admin workstation's SSH logins, the sudo inside
#      its login session (traced through logind) and its FortiGate login,
#      leaves them out of audit_unattributed, and does not trace a session
#      whose lead-in has the same user logging in from two addresses
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

# journald, in the shapes the lab writes: an HA start of a guest
# (pve-ha-lrm), the daily apt refresh (pveupdate, ignored), a sudo with a
# terminal and a refused one without, an ssh login inside the window from
# OpenSSH 10 (sshd-session) and one outside it from 9.6 (sshd), the marks
# of CR-0001 and the begin of CR-0004, two hours before the 1 h report
{
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=pve-t\n_SYSTEMD_UNIT=pvedaemon.service\nSYSLOG_IDENTIFIER=pve-ha-lrm\nPRIORITY=6\nMESSAGE=<root@pam> starting task UPID:pve-t:0000A1B2:00C3D4E5:68E9F000:qmstart:100:root@pam:\n\n' "$(us "$now")"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=pve-t\n_SYSTEMD_UNIT=pve-daily-update.service\nSYSLOG_IDENTIFIER=pveupdate\nPRIORITY=6\nMESSAGE=<root@pam> starting task UPID:pve-t:0000A1B3:00C3D4E6:68E9F001:aptupdate::root@pam:\n\n' "$(us "$now")"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=session-9.scope\nSYSLOG_IDENTIFIER=sudo\nPRIORITY=5\nMESSAGE=    ops : TTY=pts/0 ; PWD=/home/ops ; USER=root ; COMMAND=/usr/bin/systemctl restart grafana\n\n' "$(us "$earlier")"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=session-9.scope\nSYSLOG_IDENTIFIER=sudo\nPRIORITY=3\nMESSAGE=  ops : a password is required ; PWD=/home/ops ; USER=root ; COMMAND=/usr/bin/true\n\n' "$(us "$earlier")"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=pve-t\n_SYSTEMD_UNIT=ssh.service\nSYSLOG_IDENTIFIER=sshd-session\nPRIORITY=6\nMESSAGE=Accepted publickey for root from 10.0.0.10 port 50000 ssh2: ED25519 SHA256:abc\n\n' "$(us "$now")"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=ssh.service\nSYSLOG_IDENTIFIER=sshd\nPRIORITY=6\nMESSAGE=Accepted password for ops from 10.0.0.2 port 50001 ssh2\n\n' "$(us "$earlier")"
  # an admin workstation (10.0.0.9) logs in, logind opens session 77 20 ms
  # later, a sudo runs in it; then user amb logs in from 10.0.0.9 and from
  # 10.0.0.3 half a second apart, so session 78 cannot be traced
  w=$((earlier + 10)); wu=$(us "$w")
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=ssh.service\nSYSLOG_IDENTIFIER=sshd\nPRIORITY=6\nMESSAGE=Accepted publickey for ops from 10.0.0.9 port 50010 ssh2: ED25519 SHA256:ws\n\n' "$wu"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=systemd-logind.service\nSYSLOG_IDENTIFIER=systemd-logind\nPRIORITY=6\nMESSAGE=New session 77 of user ops.\n\n' "$((wu + 20000))"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=session-77.scope\n_AUDIT_SESSION=77\nSYSLOG_IDENTIFIER=sudo\nPRIORITY=5\nMESSAGE=    ops : PWD=/home/ops ; USER=root ; COMMAND=/usr/bin/journalctl -n 5\n\n' "$((wu + 5000000))"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=ssh.service\nSYSLOG_IDENTIFIER=sshd\nPRIORITY=6\nMESSAGE=Accepted publickey for amb from 10.0.0.9 port 50011 ssh2: ED25519 SHA256:ws\n\n' "$((wu + 60000000))"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=ssh.service\nSYSLOG_IDENTIFIER=sshd\nPRIORITY=6\nMESSAGE=Accepted publickey for amb from 10.0.0.3 port 50012 ssh2: ED25519 SHA256:other\n\n' "$((wu + 60500000))"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=systemd-logind.service\nSYSLOG_IDENTIFIER=systemd-logind\nPRIORITY=6\nMESSAGE=New session 78 of user amb.\n\n' "$((wu + 60520000))"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=session-78.scope\n_AUDIT_SESSION=78\nSYSLOG_IDENTIFIER=sudo\nPRIORITY=5\nMESSAGE=    amb : PWD=/home/amb ; USER=root ; COMMAND=/usr/bin/id\n\n' "$((wu + 63000000))"
  # Day 29: two agent-gate decisions, an ALLOW inside CR-0001's window and a DENY an hour earlier
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=session-9.scope\nSYSLOG_IDENTIFIER=agent-gate\nPRIORITY=5\nMESSAGE=seq=7 principal=agent:ops operator=a cr=CR-2026-0001 tool=qdevice.restart_service level=L2 decision=ALLOW rc=0 hash=3f9c2a71b0e4d5c6\n\n' "$(us "$now")"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=session-9.scope\nSYSLOG_IDENTIFIER=agent-gate\nPRIORITY=5\nMESSAGE=seq=6 principal=agent:ops operator=a cr=CR-2026-0001 tool=qdevice.reboot level=L3 decision=DENY hash=aa11bb22cc33dd44\n\n' "$(us "$earlier")"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=session-9.scope\nSYSLOG_IDENTIFIER=change\nPRIORITY=5\nMESSAGE=CR-2026-0004 begin smoke change\n\n' "$(us $((now - 7000)))"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=session-9.scope\nSYSLOG_IDENTIFIER=change\nPRIORITY=5\nMESSAGE=CR-2026-0001 begin smoke change\n\n' "$(us $((now - 60)))"
  printf '__REALTIME_TIMESTAMP=%s\n_HOSTNAME=coll-t\n_SYSTEMD_UNIT=session-9.scope\nSYSLOG_IDENTIFIER=change\nPRIORITY=5\nMESSAGE=CR-2026-0001 end smoke change\n\n' "$(us $((now + 60)))"
} | curl -sf -X POST -H 'Content-Type: application/vnd.fdo.journal' --data-binary @- "$VL/insert/journald/upload"

# 514: FortiGate traffic (not an action) and the NAS event and connection logs
ts() { date -d "@$1" +%Y-%m-%dT%H:%M:%S%z | sed 's/\(..\)$/:\1/'; }
printf '<189>1 %s fgt-t - - - - eventtime=1 tz="+0800" logid="0000000013" type="traffic" subtype="forward" action="deny" srcip=10.0.0.9 dstport=123\n' "$(ts "$now")" | nc -q1 127.0.0.1 15533
lt() { TZ=Asia/Taipei LC_ALL=C date -d "@$1" '+%b %e %H:%M:%S'; }
printf '<30>%s nas-t qulogd[1]: event log: Users: admin, Source IP: 10.0.0.8, Computer name: ---, Application: Virtualization Station, Category: Snapshots, Content: [Virtualization Station] Created snapshot "CR-2026-0001-before" of VM "qnetd".\n' "$(lt "$now")" | nc -q1 127.0.0.1 15533
printf '<30>%s nas-t qulogd[1]: conn log: Users: admin, Source IP: 10.0.0.8, Computer name: ---, Connection type: HTTPS, Accessed resources: ---, Action: Login Success\n' "$(lt "$now")" | nc -q1 127.0.0.1 15533
# 515: the FortiGate event log, a config change inside the window and an admin login outside it
printf '<190>1 %s fgt-t - - - - eventtime=1 tz="+0800" logid="0100044547" type="event" subtype="system" level="information" vd="root" logdesc="Object attribute configured" user="admin" ui="https(10.0.0.10)" action="Edit" cfgtid=1 cfgpath="firewall.policy" cfgobj="1" cfgattr="utm-status[disable->enable]" msg="Edit firewall.policy 1"\n' "$(ts "$now")" | nc -q1 127.0.0.1 15534
printf '<190>1 %s fgt-t - - - - eventtime=1 tz="+0800" logid="0100032001" type="event" subtype="system" level="information" vd="root" logdesc="Admin login successful" sn="1" user="admin" ui="https(10.0.0.10)" method="https" srcip=10.0.0.10 dstip=10.0.0.1 action="login" status="success" reason="none" profile="super_admin" msg="Administrator admin logged in successfully from https(10.0.0.10)"\n' "$(ts "$earlier")" | nc -q1 127.0.0.1 15534
sleep 2

# four change records: one around now with marks, one backfilled last week
# (no marks expected), one done two hours ago with no marks, one that ended
# 40 minutes ago with its begin mark at the start of its two-hour window
mkdir -p "$tmp/changes"
rec() { # id status start end tags
  printf -- '---\nid: %s\ntitle: smoke %s\nstatus: %s\ntype: standard\nrisk: low\nrequester: a\nimplementer: a\napprover: b\nassets:\n  - x/y\nwindow_start: %s\nwindow_end: %s\ntags: %s\n---\n\n## 目的\nx\n' "$1" "$1" "$2" "$3" "$4" "$5" > "$tmp/changes/$1-smoke.md"
}
rec CR-2026-0001 "done" "$(iso $((now - 600)))" "$(iso $((now + 1200)))" smoke
rec CR-2026-0002 "done" "$(iso $((now - 7 * 86400)))" "$(iso $((now - 7 * 86400 + 3600)))" "smoke, backfill"
rec CR-2026-0003 "done" "$(iso $((now - 10800)))" "$(iso $((now - 7200)))" smoke
rec CR-2026-0004 "done" "$(iso $((now - 7200)))" "$(iso $((now - 2400)))" smoke

python3 -I "$here/audit/audit-report.py" --vl "$VL" --window 1d --changes "$tmp/changes" --out "$tmp/r.md" --textfile "$tmp/audit.prom"
grep -q '^管理動作 15 筆（忽略清單排除 1 筆），有變更單的 5 筆，沒有的 10 筆$' "$tmp/r.md" || { echo "summary line wrong"; sed -n 1,6p "$tmp/r.md"; exit 1; }
grep -q 'sudo | coll-t | ops | as root: /usr/bin/systemctl restart grafana' "$tmp/r.md" || { echo "sudo row missing from unattributed"; cat "$tmp/r.md"; exit 1; }
grep -q 'sudo | coll-t | ops | REFUSED as root: /usr/bin/true' "$tmp/r.md" || { echo "refused sudo without a terminal missing"; cat "$tmp/r.md"; exit 1; }
grep -q 'ssh-login | coll-t | ops | login password from 10.0.0.2 |' "$tmp/r.md" || { echo "sshd (9.6) login missing"; cat "$tmp/r.md"; exit 1; }
grep -q 'ssh-login | pve-t | root | login publickey from 10.0.0.10 key ED25519 SHA256:abc' "$tmp/r.md" || { echo "sshd-session login missing"; cat "$tmp/r.md"; exit 1; }
grep -q 'pve-task | pve-t | root@pam | qmstart 100 (pve-ha-lrm)' "$tmp/r.md" || { echo "pve task row missing"; cat "$tmp/r.md"; exit 1; }
grep -q 'fortigate-login | fgt-t | admin | Admin login successful (https(10.0.0.10)) | 1 |' "$tmp/r.md" || { echo "login row missing"; cat "$tmp/r.md"; exit 1; }
grep -q 'fortigate-config | fgt-t | admin | Edit firewall.policy 1 utm-status\[disable->enable\] (https(10.0.0.10))' "$tmp/r.md" || { echo "config row missing"; cat "$tmp/r.md"; exit 1; }
grep -q '\*\*CR-2026-0001\*\* smoke CR-2026-0001（done' "$tmp/r.md" || { echo "CR-0001 section missing"; exit 1; }
grep -q 'nas-event | nas-t | admin | Virtualization Station/Snapshots: \[Virtualization Station\] Created snapshot "CR-2026-0001-before"' "$tmp/r.md" || { echo "nas row missing"; cat "$tmp/r.md"; exit 1; }
grep -q 'agent-gate | coll-t | agent:ops | DENY qdevice.reboot (L3) under CR-2026-0001 seq 6 hash aa11bb22cc33dd44' "$tmp/r.md" || { echo "agent-gate DENY row missing from unattributed"; cat "$tmp/r.md"; exit 1; }
grep -q 'ALLOW qdevice.restart_service (L2) under CR-2026-0001 seq 7 hash 3f9c2a71b0e4d5c6' "$tmp/r.md" || { echo "agent-gate ALLOW row missing"; cat "$tmp/r.md"; exit 1; }
grep -q 'aptupdate' "$tmp/r.md" && { echo "aptupdate should be ignored"; exit 1; }
grep -q 'CR-2026-0004 | smoke' "$tmp/r.md" && { echo "CR-0004 has its begin mark inside its own window"; exit 1; }
grep -q 'CR-2026-0003 | smoke CR-2026-0003' "$tmp/r.md" || { echo "CR-0003 should be listed without marks"; cat "$tmp/r.md"; exit 1; }
grep -q 'CR-2026-0002' "$tmp/r.md" && { echo "a backfilled record is not expected to have marks"; exit 1; }
for want in 'audit_actions{source="fortigate-config"} 1' 'audit_actions{source="pve-task"} 1' 'audit_actions{source="sudo"} 4' 'audit_actions{source="agent-gate"} 2' 'audit_unattributed{source="agent-gate"} 1' 'audit_actions{source="ssh-login"} 5' 'audit_actions{source="nas-event"} 1' \
            'audit_unattributed{source="sudo"} 4' 'audit_unattributed{source="ssh-login"} 4' 'audit_unattributed_quiet{source="sudo"} 0' 'audit_unattributed{source="fortigate-login"} 1' 'audit_unattributed{source="fortigate-config"} 0' 'audit_changes_without_marks 1'; do
  grep -qF "$want" "$tmp/audit.prom" || { echo "textfile lacks: $want"; cat "$tmp/audit.prom"; exit 1; }
done
[ "$(stat -c %a "$tmp/audit.prom")" = 644 ] || { echo "textfile mode"; exit 1; }
# an absolute range that misses every change record: all unattributed, no sections
python3 -I "$here/audit/audit-report.py" --vl "$VL" --since "$(iso $((now - 3600)))" --until "$(iso $((now + 3600)))" --changes "$tmp/nochanges" > "$tmp/r2.md" 2>"$tmp/r2.err"
grep -q 'no change records' "$tmp/r2.err" || { cat "$tmp/r2.err"; exit 1; }
grep -q '有變更單的 0 筆，沒有的 15 筆' "$tmp/r2.md" || { sed -n 1,4p "$tmp/r2.md"; exit 1; }
# the 1 h run the textfile cron does: CR-0004 ended inside it and its begin
# mark is two hours old, outside the report range but inside its window
python3 -I "$here/audit/audit-report.py" --vl "$VL" --window 1h --changes "$tmp/changes" --out /dev/null --textfile "$tmp/audit1h.prom"
grep -qx 'audit_changes_without_marks 0' "$tmp/audit1h.prom" || { echo "1 h run: a mark outside the report range but inside the window was missed"; cat "$tmp/audit1h.prom"; exit 1; }
# a source that hits --limit says so
python3 -I "$here/audit/audit-report.py" --vl "$VL" --window 1d --limit 1 --changes "$tmp/changes" --out /dev/null 2>"$tmp/lim.err"
grep -q 'sudo hit --limit 1' "$tmp/lim.err" || { echo "limit warning missing"; cat "$tmp/lim.err"; exit 1; }
# admin workstations: 10.0.0.9's two SSH logins and the sudo in its session,
# 10.0.0.10's FortiGate login; the ambiguous session's sudo and the login
# from 10.0.0.3 still count
AUDIT_QUIET_FROM="10.0.0.9 10.0.0.10" python3 -I "$here/audit/audit-report.py" --vl "$VL" --window 1d --changes "$tmp/changes" --out "$tmp/rq.md" --textfile "$tmp/auditq.prom"
for want in 'audit_unattributed{source="ssh-login"} 2' 'audit_unattributed_quiet{source="ssh-login"} 2' 'audit_unattributed{source="sudo"} 3' 'audit_unattributed_quiet{source="sudo"} 1' \
            'audit_unattributed{source="fortigate-login"} 0' 'audit_unattributed_quiet{source="fortigate-login"} 1' 'audit_unattributed{source="fortigate-config"} 0'; do
  grep -qF "$want" "$tmp/auditq.prom" || { echo "quiet textfile lacks: $want"; cat "$tmp/auditq.prom"; exit 1; }
done
grep -q '^沒有變更單的動作裡，4 筆來自管理工作站（10.0.0.10 10.0.0.9）' "$tmp/rq.md" || { echo "quiet summary line missing"; sed -n 1,8p "$tmp/rq.md"; exit 1; }
grep -q 'sudo | coll-t | ops（工作站） | as root: /usr/bin/journalctl -n 5' "$tmp/rq.md" || { echo "sudo in the workstation session not marked"; cat "$tmp/rq.md"; exit 1; }
grep -q 'sudo | coll-t | amb | as root: /usr/bin/id' "$tmp/rq.md" || { echo "ambiguous session should not be marked"; cat "$tmp/rq.md"; exit 1; }
grep -q 'ssh-login | coll-t | amb | login publickey from 10.0.0.3' "$tmp/rq.md" || { echo "login from 10.0.0.3 should not be marked"; cat "$tmp/rq.md"; exit 1; }
grep -q '（工作站）' "$tmp/r.md" && { echo "without --quiet-from nothing is marked"; exit 1; }

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
