#!/bin/sh
# aup-compare: run the online and the offline path of aup-report.py on the
# same export file and show that they agree.
#   1. start a throwaway VictoriaLogs (binary in $VLBIN, or docker)
#   2. load the file with fortigate-export-load.py, the way the live syslog
#      feed would have stored it
#   3. aup-report.py against that instance, bounded to the file's time span
#   4. aup-report.py --from-file on the same file
#   5. diff the two reports below their first lines (which name the source)
#
#   aup-compare.sh export.log [outdir]
#
# Prints the two reports' paths and "aup-compare: SAME" or the diff. The
# browser viewer (fortigate-log-viewer) is the third reading of the same
# file; its per-user table is read by eye against online.md.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
file=${1:-}; [ -s "$file" ] || { sed -n '2,15p' "$0"; exit 64; }
out=${2:-$(mktemp -d)}
mkdir -p "$out"
port=${PORT:-19428}
vl="http://127.0.0.1:$port"

if [ -n "${VLBIN:-}" ]; then
  "$VLBIN" -storageDataPath="$out/.vl-data" -httpListenAddr="127.0.0.1:$port" -retentionPeriod=100y >"$out/vl.log" 2>&1 &
  pid=$!; trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf "$out/.vl-data"' EXIT
else
  cid=$(docker run -d --rm -p "127.0.0.1:$port:9428" victoriametrics/victoria-logs:v1.52.0 -retentionPeriod=100y)
  trap 'docker stop "$cid" >/dev/null' EXIT
fi
for _ in 1 2 3 4 5 6 7 8 9 10; do curl -sf "$vl/health" >/dev/null && break; sleep 1; done

python3 -I "$here/fortigate-export-load.py" "$file" --vl "$vl"
sleep 2   # the inserted rows become searchable within a second or two

# the file's time span, from what VictoriaLogs now holds
span=$(curl -sf "$vl/select/logsql/query" -d 'query=* | stats min(_time) as lo, max(_time) as hi')
lo=$(printf '%s' "$span" | python3 -c 'import json,sys;print(json.loads(sys.stdin.readline())["lo"])')
hi=$(printf '%s' "$span" | python3 -c 'import json,sys;print(json.loads(sys.stdin.readline())["hi"])')
# --until is exclusive; push it one second past the last row
hi=$(python3 -c 'import datetime as d,sys;t=d.datetime.fromisoformat(sys.argv[1].replace("Z","+00:00"));print((t+d.timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$hi")

python3 -I "$here/aup-report.py" --vl "$vl" --since "$lo" --until "$hi" --out "$out/online.md" >/dev/null
python3 -I "$here/aup-report.py" --from-file "$file" --out "$out/offline.md" >/dev/null

# line 1 names the source and line 3 (offline only) reconciles the file;
# everything from the first "## " on must be identical
sed -n '/^## /,$p' "$out/online.md" > "$out/.online.body"
sed -n '/^## /,$p' "$out/offline.md" > "$out/.offline.body"
echo "online : $out/online.md"
echo "offline: $out/offline.md"
if diff -u "$out/.online.body" "$out/.offline.body"; then
  echo "aup-compare: SAME ($(grep -c '^|' "$out/.online.body") table rows)"
else
  echo "aup-compare: DIFFERENT" >&2
  exit 1
fi
