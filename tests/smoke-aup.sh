#!/bin/sh
# smoke-aup: the Day 24 path.
#   1. aup-compare.sh on the fixture: the export loaded into a throwaway
#      VictoriaLogs and the same file read offline give the same report
#   2. the offline report reconciles the file (lines = parsed + skipped)
#      and leaves non-webfilter lines out
#   3. --textfile writes every urgent category for every expected FortiGate,
#      0 included, and a silent FortiGate is written as 0
#   4. an export with a line that has no time is loaded without it, and the
#      line is counted as skipped, never dated now
#   5. a memory-log export (GUI download or REST raw) has no devname; both
#      sides name it with the same default and still agree
# Needs $VLBIN (victoria-logs-prod) or docker, like tests/smoke.sh.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fx="$here/tests/fixtures/fortigate-webfilter.log"

# 1. online == offline
PORT=19431 sh "$here/firewall/aup-compare.sh" "$fx" "$tmp/cmp" > "$tmp/cmp.log" 2>&1 || { cat "$tmp/cmp.log"; exit 1; }
grep -q '^aup-compare: SAME' "$tmp/cmp.log" || { cat "$tmp/cmp.log"; exit 1; }

# 2. reconciliation line and the counts the fixture is built to give
off="$tmp/cmp/offline.md"
grep -q '^檔案 7 行 = 6 解析 + 1 略過，其中 webfilter 以外 2 行不計$' "$off" || { echo "reconciliation line wrong"; sed -n 3p "$off"; exit 1; }
grep -q '^## fgt-edge  webfilter 4 筆，擋下 2 筆$' "$off" || { echo "totals wrong"; grep '^## ' "$off"; exit 1; }
grep -q 'login-verify.example.org | Phishing | blocked | 1' "$off" || { echo "urgent row missing"; exit 1; }
grep -q '192.168.2.49' "$off" && { echo "a traffic line leaked into the webfilter report"; exit 1; }

# 3. textfile: urgent categories always present, silent FortiGate written as 0
python3 -I "$here/firewall/aup-report.py" --from-file "$fx" --expect fgt-edge,fgt-silent --textfile "$tmp/aup.prom" --out /dev/null
grep -q '^aup_webfilter_total{fgt="fgt-edge"} 4$' "$tmp/aup.prom" || { echo "total metric"; cat "$tmp/aup.prom"; exit 1; }
grep -q '^aup_webfilter_blocked{fgt="fgt-edge"} 2$' "$tmp/aup.prom" || { echo "blocked metric"; exit 1; }
grep -q '^aup_webfilter_urgent{fgt="fgt-edge",catdesc="Phishing"} 1$' "$tmp/aup.prom" || { echo "urgent phishing"; exit 1; }
grep -q '^aup_webfilter_urgent{fgt="fgt-edge",catdesc="Malicious Websites"} 0$' "$tmp/aup.prom" || { echo "urgent zero row missing"; exit 1; }
grep -q '^aup_webfilter_total{fgt="fgt-silent"} 0$' "$tmp/aup.prom" || { echo "silent FortiGate not written as 0"; exit 1; }
grep -q '^aup_webfilter_urgent{fgt="fgt-silent",catdesc="Spam URLs"} 0$' "$tmp/aup.prom" || { echo "silent urgent zero missing"; exit 1; }
grep -q '^aup_webfilter_blocked_top_source{fgt="fgt-edge",who="192.168.2.23"} 2$' "$tmp/aup.prom" || { echo "top source"; exit 1; }
[ "$(stat -c %a "$tmp/aup.prom")" = 644 ] || { echo "textfile mode $(stat -c %a "$tmp/aup.prom"), want 644"; exit 1; }

# 4. a line without any time field is skipped by the loader, not dated now
printf 'type="utm" subtype="webfilter" srcip=192.168.2.5 hostname="a.example" action="passthrough" catdesc="Business"\n' > "$tmp/notime.log"
cat "$fx" >> "$tmp/notime.log"
rc=0; PORT=19432 sh "$here/firewall/aup-compare.sh" "$tmp/notime.log" "$tmp/cmp2" > "$tmp/cmp2.log" 2>&1 || rc=$?
grep -q '8 lines, 6 loaded, 2 skipped' "$tmp/cmp2.log" || { echo "loader did not skip the untimed line"; cat "$tmp/cmp2.log"; exit 1; }
# offline counts the untimed webfilter line (it has no time but is a record), online cannot hold it: the two differ by design here
[ "$rc" = 1 ] || { echo "expected the untimed line to make the reports differ, rc=$rc"; exit 1; }
grep -q '^+.*a.example' "$tmp/cmp2.log" || { echo "diff should show a.example on the offline side"; cat "$tmp/cmp2.log"; exit 1; }

# 5. no devname (memory-log export): both sides fall back to the same name
sed 's/devname="[^"]*" //; s/devid="[^"]*" //' "$fx" > "$tmp/nodev.log"
grep -q devname "$tmp/nodev.log" && { echo "fixture still has devname"; exit 1; }
PORT=19433 sh "$here/firewall/aup-compare.sh" "$tmp/nodev.log" "$tmp/cmp3" > "$tmp/cmp3.log" 2>&1 || { echo "no-devname export: online and offline differ"; cat "$tmp/cmp3.log"; exit 1; }
grep -q '^## FortiGate  webfilter 4 筆，擋下 2 筆$' "$tmp/cmp3/online.md" || { echo "no-devname online totals"; grep '^## ' "$tmp/cmp3/online.md"; exit 1; }
echo "smoke-aup: OK"
