#!/usr/bin/env python3
"""fortigate-export-load: put an exported FortiGate log file into a
VictoriaLogs instance the way the live syslog feed would have, so the same
LogsQL can be run on it.

    fortigate-export-load.py export.log [--vl http://127.0.0.1:19428]

Each key=value line becomes one JSON line with
    _time     from eventtime (ns/us/ms/s), else date + time + tz
    hostname  devname           (the live feed puts the devname in the
                                 rfc5424 header, which VictoriaLogs stores
                                 as hostname; it is the stream field).
                                 A GUI or REST export of the memory log
                                 has no devname; --devname (default
                                 "FortiGate", what the viewer shows) fills
                                 it, and aup-report.py --from-file uses
                                 the same default
    source    "export"          so the rows can be told apart from the feed
    <k>       <v>               one per --field k=v (Day 28: audit=fortigate,
                                 so backfilled event rows land in the same
                                 stream shape as the 515 listener's and in
                                 the audit-<devname> archive source)
    _msg      the whole line
and is sent to /insert/jsonline; hostname, source and the --field keys are
the stream fields. Lines without a time are skipped and counted, never
stamped with now. Prints lines/loaded/skipped. --dry-run prints the JSON
lines instead of sending them.

Meant for a throwaway instance (aup-compare.sh, tests). Loading an export
into the production collector would double-count whatever the feed already
holds for those hours; if you must, the source field is what to filter on
(CR-2026-0008 backfills a known hole with --source backfill).
"""
import argparse, datetime as dt, json, re, sys, urllib.request

KV_RE = re.compile(r'([A-Za-z0-9_.-]+)=(?:"([^"]*)"|\'([^\']*)\'|([^\s,]+))')
TZ_RE = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


def parse_kv(line):
    return {m.group(1).lower(): next(g for g in m.groups()[1:] if g is not None) for m in KV_RE.finditer(line)}


def when(kv):
    """RFC 3339 with nanoseconds, or None."""
    et = kv.get("eventtime", "")
    if et.isdigit() and len(et) in (10, 13, 16, 19):   # s, ms, us, ns
        ns = int(et) * 10 ** (19 - len(et))
        sec, frac = divmod(ns, 10 ** 9)
        return dt.datetime.fromtimestamp(sec, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{frac:09d}Z"
    d, t, tz = kv.get("date"), kv.get("time"), kv.get("tz", "")
    if not d or not t:
        return None
    m = TZ_RE.match(tz)
    off = f"{m.group(1)}{m.group(2)}:{m.group(3)}" if m else "Z"
    try:
        dt.datetime.fromisoformat(f"{d.replace('/', '-')}T{t}{off if off != 'Z' else '+00:00'}")
    except ValueError:
        return None
    return f"{d.replace('/', '-')}T{t}{off}"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("file")
    ap.add_argument("--vl", default="http://127.0.0.1:19428")
    ap.add_argument("--source", default="export")
    ap.add_argument("--devname", default="FortiGate", help="for lines without devname (memory-log exports)")
    ap.add_argument("--field", action="append", default=[], metavar="K=V",
                    help="extra field on every row, also a stream field (e.g. audit=fortigate); repeatable")
    ap.add_argument("--dry-run", action="store_true", help="print the JSON lines, send nothing")
    a = ap.parse_args()
    extra = {}
    for kv_arg in a.field:
        k, sep, v = kv_arg.partition("=")
        if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", k) or k in ("_time", "_msg", "hostname", "source"):
            ap.error(f"--field wants k=v with a plain field name, got {kv_arg!r}")
        extra[k] = v
    lines = loaded = skipped = 0
    body = []
    with open(a.file, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            lines += 1
            kv = parse_kv(line)
            ts = when(kv) if kv else None
            if not kv or ts is None:
                skipped += 1
                continue
            row = {"_time": ts, "hostname": kv.get("devname") or a.devname, "source": a.source}
            row.update(extra)
            row["_msg"] = line
            body.append(json.dumps(row, ensure_ascii=False))
            loaded += 1
    if body and a.dry_run:
        sys.stdout.write("\n".join(body) + "\n")
    elif body:
        stream = ",".join(["hostname", "source"] + sorted(extra))
        url = a.vl.rstrip("/") + f"/insert/jsonline?_stream_fields={stream}&_time_field=_time&_msg_field=_msg"
        req = urllib.request.Request(url, data=("\n".join(body) + "\n").encode(), method="POST",
                                     headers={"Content-Type": "application/stream+json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            r.read()
    print(f"fortigate-export-load: {lines} lines, {loaded} loaded, {skipped} skipped (no key=value or no time)",
          file=sys.stderr if a.dry_run else sys.stdout)
    return 0 if loaded else 1


if __name__ == "__main__":
    sys.exit(main())
