#!/usr/bin/env python3
"""fortigate-export-load: put an exported FortiGate log file into a
VictoriaLogs instance the way the live syslog feed would have, so the same
LogsQL can be run on it.

    fortigate-export-load.py export.log [--vl http://127.0.0.1:19428]

Each key=value line becomes one JSON line with
    _time     from eventtime (ns/us/ms/s), else date + time + tz
    hostname  devname           (the live feed puts the devname in the
                                 rfc5424 header, which VictoriaLogs stores
                                 as hostname; it is the stream field)
    source    "export"          so the rows can be told apart from the feed
    _msg      the whole line
and is sent to /insert/jsonline. Lines without a time are skipped and
counted, never stamped with now. Prints lines/loaded/skipped.

Meant for a throwaway instance (aup-compare.sh, tests). Loading an export
into the production collector would double-count whatever the feed already
holds for those hours; if you must, the source="export" field is what to
filter on.
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
    a = ap.parse_args()
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
            body.append(json.dumps({"_time": ts, "hostname": kv.get("devname", ""), "source": a.source, "_msg": line}, ensure_ascii=False))
            loaded += 1
    if body:
        url = a.vl.rstrip("/") + "/insert/jsonline?_stream_fields=hostname,source&_time_field=_time&_msg_field=_msg"
        req = urllib.request.Request(url, data=("\n".join(body) + "\n").encode(), method="POST",
                                     headers={"Content-Type": "application/stream+json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            r.read()
    print(f"fortigate-export-load: {lines} lines, {loaded} loaded, {skipped} skipped (no key=value or no time)")
    return 0 if loaded else 1


if __name__ == "__main__":
    sys.exit(main())
