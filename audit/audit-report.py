#!/usr/bin/env python3
"""audit-report: the machine-written side of change management. Every
administrative action the pipeline already records (FortiGate config edits
and admin logins, Proxmox tasks, sudo and SSH logins on the nodes and the
collector, QuLog events on the NAS) is listed and matched against the
change records in onprem-changes: an action inside a record's window is
attributed to that record, anything else is unattributed and goes in the
report for a human to explain.

    audit-report.py --window 7d --changes /opt/onprem-changes/changes      # markdown to stdout
    audit-report.py --window 1h --changes ... --textfile /var/lib/node_exporter/textfile/audit.prom --out /dev/null
    audit-report.py --since 2026-10-10T22:00:00+08:00 --until 2026-10-11T00:00:00+08:00 --changes ...

Sources (LogsQL in SOURCES; the audit field is the 515 listener's stamp,
see audit/fortigate-syslogd3.md; the rest is Day 21's journald upload and
the NAS Log Sender). Each row becomes (time, source, host, who, what).

Attribution uses the records' window_start/window_end from their front
matter (statuses scheduled, in_progress, done, rolled_back). audit/ignore.txt
lists what is routine and never counts (one regex per line, applied to
"who what"): nightly vzdump, the collector's own cron, and so on. A done
record with no `change` journal mark inside its window is listed too: it was
either backfilled (fine, says so) or executed without change-mark.sh.

Textfile
    audit_actions{source}            actions in the window, ignore list applied
    audit_unattributed{source}       of those, outside every change window
    audit_changes_without_marks      done records in the window with no begin/end mark
    audit_report_last_run_timestamp

Standard library only.
"""
import argparse, collections, datetime as dt, glob, json, os, re, sys, tempfile, urllib.parse, urllib.request

SOURCES = {
    # FortiGate event log, config changes: every line that carries cfgpath
    "fortigate-config": {
        "filter": 'audit:=fortigate "type=\\"event\\"" "subtype=\\"system\\"" "cfgpath="',
        "pipes": "unpack_logfmt from _msg fields (user, ui, action, cfgpath, cfgobj, cfgattr, msg) | rename hostname as host",
        "fields": ["host", "user", "ui", "action", "cfgpath", "cfgobj", "cfgattr"],
        "who": lambda r: r.get("user", ""),
        "what": lambda r: " ".join(x for x in (r.get("action", ""), r.get("cfgpath", ""), r.get("cfgobj", ""), r.get("cfgattr", "")) if x) + f" ({r.get('ui', '')})",
    },
    # FortiGate admin logins and logouts (FortiOS logid 0100032001..3, 待查 against the lab's 7.6.7)
    "fortigate-login": {
        "filter": 'audit:=fortigate "subtype=\\"system\\"" ("logid=\\"0100032001\\"" OR "logid=\\"0100032002\\"" OR "logid=\\"0100032003\\"")',
        "pipes": "unpack_logfmt from _msg fields (user, ui, action, status, logdesc) | rename hostname as host",
        "fields": ["host", "user", "ui", "action", "status", "logdesc"],
        "who": lambda r: r.get("user", ""),
        "what": lambda r: f"{r.get('logdesc') or r.get('action', '')} {r.get('status', '')} ({r.get('ui', '')})".strip(),
    },
    # Proxmox VE: every task pvedaemon starts carries its UPID with the user
    "pve-task": {
        "filter": 'SYSLOG_IDENTIFIER:=pvedaemon "starting task UPID:"',
        "pipes": 'extract "starting task UPID:<node>:<pid>:<pstart>:<stime>:<ttype>:<tid>:<tuser>:" | rename _HOSTNAME as host',
        "fields": ["host", "ttype", "tid", "tuser"],
        "who": lambda r: r.get("tuser", ""),
        "what": lambda r: f"{r.get('ttype', '')} {r.get('tid', '')}".strip(),
    },
    # sudo on any journald host: "ivan : TTY=pts/0 ; PWD=... ; USER=root ; COMMAND=/usr/bin/..."
    "sudo": {
        "filter": 'SYSLOG_IDENTIFIER:=sudo "COMMAND="',
        "pipes": 'extract "<who> : TTY=" | extract " USER=<as> ;" | extract "COMMAND=<cmd>" | rename _HOSTNAME as host',
        "fields": ["host", "who", "as", "cmd"],
        "who": lambda r: r.get("who", "").strip(),
        "what": lambda r: f"as {r.get('as', '')}: {r.get('cmd', '')}",
    },
    # SSH logins on any journald host
    "ssh-login": {
        "filter": 'SYSLOG_IDENTIFIER:=sshd "Accepted "',
        "pipes": 'extract "Accepted <method> for <who> from <ip> port" | rename _HOSTNAME as host',
        "fields": ["host", "method", "who", "ip"],
        "who": lambda r: r.get("who", ""),
        "what": lambda r: f"login {r.get('method', '')} from {r.get('ip', '')}",
    },
    # QuLog event log (not the connection log): settings, services, VMs,
    # snapshots. The line shape is "event log: Users: x, Source IP: y, ..." (待查
    # the exact field list on QuTS hero 6.0.2); the whole text after "event
    # log:" is kept as `what`
    "nas-event": {
        "filter": '"event log:"',
        "pipes": 'extract "Users: <who>, Source IP: <ip>," | rename hostname as host',
        "fields": ["host", "who", "ip", "_msg"],
        "who": lambda r: r.get("who", ""),
        "what": lambda r: r.get("_msg", "").split("event log:", 1)[-1].strip(),
    },
}
MARKS = 'SYSLOG_IDENTIFIER:=change'


def q(vl, query):
    req = urllib.request.Request(vl.rstrip("/") + "/select/logsql/query",
                                 data=urllib.parse.urlencode({"query": query}).encode(), method="POST")
    with urllib.request.urlopen(req, timeout=120) as r:
        return [json.loads(l) for l in r.read().decode().splitlines() if l.strip()]


def time_filter(a):
    if a.since or a.until:
        s = a.since or "1970-01-01T00:00:00Z"; u = a.until or "2100-01-01T00:00:00Z"
        return f"_time:[{s}, {u})"
    return f"_time:{a.window}"


def parse_time(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def fetch(a):
    rows = []
    for name, src in SOURCES.items():
        qs = f'{time_filter(a)} {src["filter"]} | {src["pipes"]} | fields _time, {", ".join(src["fields"])} | sort by (_time) | limit {a.limit}'
        for r in q(a.vl, qs):
            rows.append({"time": parse_time(r["_time"]), "source": name, "host": r.get("host", ""),
                         "who": src["who"](r), "what": src["what"](r)})
    rows.sort(key=lambda r: r["time"])
    marks = q(a.vl, f'{time_filter(a)} {MARKS} | fields _time, _HOSTNAME, _msg | sort by (_time) | limit {a.limit}')
    return rows, marks


# ---------- change records ----------

KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):(.*)$")


def front_matter(path):
    meta, inside = {}, False
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i == 0:
                if line.strip() != "---":
                    return {}
                inside = True
                continue
            if line.strip() == "---":
                break
            m = KEY_RE.match(line)
            if m and inside:
                meta[m.group(1)] = m.group(2).strip()
    return meta


def windows(changes_dir):
    out = []
    for f in sorted(glob.glob(os.path.join(changes_dir, "CR-*.md"))):
        m = front_matter(f)
        if m.get("status") not in ("scheduled", "in_progress", "done", "rolled_back"):
            continue
        try:
            out.append({"id": m["id"], "status": m["status"], "title": m.get("title", ""),
                        "start": parse_time(m["window_start"]), "end": parse_time(m["window_end"]),
                        "backfill": "backfill" in m.get("tags", "")})
        except (KeyError, ValueError):
            continue
    return out


def load_ignore(path):
    rules = []
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line.strip() or line.startswith("#"):
                    continue
                src, _, rx = line.partition("\t")
                rules.append((src.strip(), re.compile(rx.strip())))
    return rules


def attribute(rows, wins, ignore):
    kept, ignored = [], 0
    for r in rows:
        if any(s in (r["source"], "*") and rx.search(f"{r['who']} {r['what']}") for s, rx in ignore):
            ignored += 1
            continue
        r["cr"] = next((w["id"] for w in wins if w["start"] <= r["time"] <= w["end"]), "")
        kept.append(r)
    return kept, ignored


def marks_missing(wins, marks, a):
    """done records whose window lies inside the report range but has no begin mark."""
    lo = a.since and parse_time(a.since)
    hi = a.until and parse_time(a.until)
    out = []
    for w in wins:
        if w["status"] not in ("done", "rolled_back") or w["backfill"]:
            continue
        if (lo and w["end"] < lo) or (hi and w["start"] > hi):
            continue
        if not a.since and not a.until:
            # a relative window: only records that ended within it
            span = dt.timedelta(seconds=dur_seconds(a.window))
            if w["end"] < dt.datetime.now(dt.timezone.utc) - span:
                continue
        if not any(f"{w['id']} begin" in m.get("_msg", "") for m in marks):
            out.append(w)
    return out


def dur_seconds(s):
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    m = re.fullmatch(r"(\d+)([smhdw])", s)
    return int(m.group(1)) * units[m.group(2)] if m else 0


# ---------- output ----------

def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(str(x).replace("|", "\\|") for x in r) + " |" for r in rows]
    return "\n".join(out) if rows else "_無_"


def t(x):
    return x.astimezone(dt.timezone(dt.timedelta(hours=8))).strftime("%m-%d %H:%M:%S")


def render(a, rows, ignored, wins, missing, now):
    L = [f"# 稽核軌跡  {time_filter(a)}，產生於 {now:%Y-%m-%d %H:%M} UTC", ""]
    by_src = collections.Counter(r["source"] for r in rows)
    un = [r for r in rows if not r["cr"]]
    L += [f"管理動作 {len(rows)} 筆（忽略清單排除 {ignored} 筆），有變更單的 {len(rows) - len(un)} 筆，沒有的 {len(un)} 筆", ""]
    L += ["## 依來源", md_table(["來源", "筆數", "沒有變更單"], [(s, n, sum(1 for r in un if r["source"] == s)) for s, n in sorted(by_src.items())]), ""]
    L += ["## 沒有變更單的動作", md_table(["時間 (+08)", "來源", "主機", "誰", "做了什麼"],
          [(t(r["time"]), r["source"], r["host"], r["who"], r["what"][:120]) for r in un[: a.top]]), ""]
    if len(un) > a.top:
        L += [f"_另 {len(un) - a.top} 筆未列_", ""]
    L += ["## 依變更單"]
    for w in wins:
        inside = [r for r in rows if r["cr"] == w["id"]]
        if not inside and not (a.since or a.until):
            continue
        L += ["", f"**{w['id']}** {w['title']}（{w['status']}，{t(w['start'])} 到 {t(w['end'])}）  {len(inside)} 筆", ""]
        if inside:
            L += [md_table(["時間 (+08)", "來源", "主機", "誰", "做了什麼"], [(t(r["time"]), r["source"], r["host"], r["who"], r["what"][:120]) for r in inside[: a.top]])]
    L += ["", "## 已完成但窗內沒有 change 標記的變更單", md_table(["編號", "標題", "窗"], [(w["id"], w["title"], f"{t(w['start'])} 到 {t(w['end'])}") for w in missing]), ""]
    return "\n".join(L)


def write_textfile(path, rows, missing, now):
    L = []
    def fam(n, h): L.extend([f"# HELP {n} {h}", f"# TYPE {n} gauge"])
    fam("audit_actions", "Administrative actions seen in the report window, ignore list applied")
    for s in SOURCES:
        L.append(f'audit_actions{{source="{s}"}} {sum(1 for r in rows if r["source"] == s)}')
    fam("audit_unattributed", "Administrative actions outside every change window")
    for s in SOURCES:
        L.append(f'audit_unattributed{{source="{s}"}} {sum(1 for r in rows if r["source"] == s and not r["cr"])}')
    fam("audit_changes_without_marks", "Done change records in the window with no change-mark begin line")
    L.append(f"audit_changes_without_marks {len(missing)}")
    fam("audit_report_last_run_timestamp", "Unix time of the last audit-report run")
    L.append(f"audit_report_last_run_timestamp {int(now.timestamp())}")
    body = "\n".join(L) + "\n"
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".audit.")
    with os.fdopen(fd, "w") as f:
        f.write(body)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--vl", default=os.environ.get("VL", "http://127.0.0.1:9428"))
    ap.add_argument("--window", default="7d")
    ap.add_argument("--since"); ap.add_argument("--until")
    ap.add_argument("--changes", default=os.environ.get("CHANGES_DIR", "/opt/onprem-changes/changes"), help="onprem-changes clone, changes/ directory")
    ap.add_argument("--ignore", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "ignore.txt"))
    ap.add_argument("--limit", type=int, default=20000, help="rows per source")
    ap.add_argument("--top", type=int, default=50)
    ap.add_argument("--out"); ap.add_argument("--textfile")
    a = ap.parse_args()
    now = dt.datetime.now(dt.timezone.utc)
    try:
        q(a.vl, "* | limit 1")
    except Exception as e:
        sys.exit(f"VictoriaLogs at {a.vl} unreachable: {e}")
    wins = windows(a.changes) if os.path.isdir(a.changes) else []
    if not wins:
        print(f"audit-report: no change records under {a.changes}; every action will be unattributed", file=sys.stderr)
    rows, marks = fetch(a)
    rows, ignored = attribute(rows, wins, load_ignore(a.ignore))
    missing = marks_missing(wins, marks, a)
    md = render(a, rows, ignored, wins, missing, now)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(md)
        if a.out != os.devnull:
            print(f"wrote {a.out}")
    else:
        sys.stdout.write(md)
    if a.textfile:
        write_textfile(a.textfile, rows, missing, now)


if __name__ == "__main__":
    main()
