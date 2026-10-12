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
"who what"): the daily apt refresh, collector jobs that log in with their
own key, and so on. A done
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
    # (7.6.7: mostly 0100044547 "Object attribute configured", some
    # 0100044546 "Attribute configured"; cfgobj is absent on singletons such
    # as log.syslogd2.filter)
    "fortigate-config": {
        "filter": 'audit:=fortigate "type=\\"event\\"" "subtype=\\"system\\"" "cfgpath="',
        "pipes": "unpack_logfmt from _msg fields (user, ui, action, cfgpath, cfgobj, cfgattr, msg) | rename hostname as host",
        "fields": ["host", "user", "ui", "action", "cfgpath", "cfgobj", "cfgattr"],
        "who": lambda r: r.get("user", ""),
        "what": lambda r: " ".join(x for x in (r.get("action", ""), r.get("cfgpath", ""), r.get("cfgobj", ""), r.get("cfgattr", "")) if x) + f" ({r.get('ui', '')})",
    },
    # FortiGate admin logins, failures and logouts: 0100032001, 0100032002
    # (level alert, reason e.g. internal_error), 0100032003 (reason timeout
    # when the session expired); checked on 7.6.7 build 3704
    "fortigate-login": {
        "filter": 'audit:=fortigate "subtype=\\"system\\"" ("logid=\\"0100032001\\"" OR "logid=\\"0100032002\\"" OR "logid=\\"0100032003\\"")',
        "pipes": "unpack_logfmt from _msg fields (user, ui, action, status, reason, logdesc) | rename hostname as host",
        "fields": ["host", "user", "ui", "action", "status", "reason", "logdesc"],
        "who": lambda r: r.get("user", ""),
        "what": lambda r: " ".join(x for x in (r.get("logdesc") or r.get("action", ""),
                                               f"reason={r['reason']}" if r.get("reason") not in (None, "", "none") else "",
                                               f"({r.get('ui', '')})") if x),
    },
    # Proxmox VE tasks. The UPID line is written by whoever starts the task:
    # pvedaemon for the GUI and API, qm for the CLI (an HA guest's start
    # becomes hastart), pve-ha-lrm for the HA manager, pveupdate for the
    # daily apt refresh, pvescheduler for scheduled jobs. The identifier goes
    # into `what`, so a manual start and the HA manager's are told apart.
    "pve-task": {
        "filter": '"starting task UPID:"',
        "pipes": 'extract "starting task UPID:<node>:<pid>:<pstart>:<stime>:<ttype>:<tid>:<tuser>:" | rename _HOSTNAME as host',
        "fields": ["host", "ttype", "tid", "tuser", "SYSLOG_IDENTIFIER"],
        "who": lambda r: r.get("tuser", ""),
        "what": lambda r: " ".join(x for x in (r.get("ttype", ""), r.get("tid", "")) if x) + f" ({r.get('SYSLOG_IDENTIFIER', '')})",
    },
    # sudo on any journald host: "ops : TTY=pts/0 ; PWD=... ; USER=root ;
    # COMMAND=...". Without a terminal there is no TTY= field, and a refused
    # sudo says why in the same position ("a password is required ; ...")
    "sudo": {
        "filter": 'SYSLOG_IDENTIFIER:=sudo "COMMAND="',
        "pipes": 'extract "<who> : " | extract " USER=<as> ;" | extract "COMMAND=<cmd>" | rename _HOSTNAME as host',
        "fields": ["host", "who", "as", "cmd", "_msg"],
        "who": lambda r: r.get("who", "").strip(),
        "what": lambda r: ("REFUSED " if REFUSED.search(r.get("_msg", "")) else "") + f"as {r.get('as', '')}: {r.get('cmd', '')}",
    },
    # SSH logins on any journald host. OpenSSH 9.8 and later (PVE 9, Debian
    # 13) log as sshd-session, older ones (Ubuntu 24.04) as sshd. The key
    # fingerprint stays in `what`: one address can stand for several
    # machines and people (a NAS, a subnet router that SNATs), the key cannot
    "ssh-login": {
        "filter": 'SYSLOG_IDENTIFIER:in(sshd, sshd-session) "Accepted "',
        "pipes": 'extract "Accepted <method> for <who> from <ip> port <port> ssh2<key>" | rename _HOSTNAME as host',
        "fields": ["host", "method", "who", "ip", "key"],
        "who": lambda r: r.get("who", ""),
        "what": lambda r: f"login {r.get('method', '')} from {r.get('ip', '')}" + (f" key {r['key'].lstrip(': ').strip()}" if r.get("key", "").strip(": ") else ""),
    },
    # QuLog event log (not the connection log): settings, services, VMs,
    # snapshots. QuTS hero 6.0.2 sends "event log: Users: x, Source IP: y,
    # Computer name: z, Application: a, Category: c, Content: ..." (Category
    # is missing on some lines); Users is "---" for what the NAS did on its
    # own and for some GUI actions too (a Virtualization Station snapshot)
    "nas-event": {
        "filter": '"event log:"',
        "pipes": 'extract "Users: <who>, Source IP: <ip>," | extract "Application: <app>, " | extract "Category: <cat>, " | extract "Content: <content>" | rename hostname as host',
        "fields": ["host", "who", "ip", "app", "cat", "content"],
        "who": lambda r: r.get("who", ""),
        "what": lambda r: "/".join(x for x in (r.get("app", ""), r.get("cat", "")) if x) + f": {r.get('content', '')}",
    },
}
REFUSED = re.compile(r"password is required|incorrect password|command not allowed|user NOT in sudoers|NOT allowed")
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
        got = q(a.vl, qs)
        if len(got) >= a.limit:
            print(f"audit-report: {name} hit --limit {a.limit}, the newest rows are missing", file=sys.stderr)
        for r in got:
            rows.append({"time": parse_time(r["_time"]), "source": name, "host": r.get("host", ""),
                         "who": src["who"](r), "what": src["what"](r)})
    rows.sort(key=lambda r: r["time"])
    return rows


def bounds(a, now):
    """the report range as two datetimes, for deciding which records it covers"""
    if a.since or a.until:
        return (parse_time(a.since) if a.since else dt.datetime.min.replace(tzinfo=dt.timezone.utc),
                parse_time(a.until) if a.until else now)
    return now - dt.timedelta(seconds=dur_seconds(a.window)), now


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


def marks_missing(wins, a, lo, hi):
    """done records whose window ended inside the report range but holds no
    begin mark. The marks are looked up in the record's own window, not in
    the report range: a two-hour window seen by the one-hour textfile run
    would otherwise lose its begin line and count as unmarked."""
    out = []
    for w in wins:
        if w["status"] not in ("done", "rolled_back") or w["backfill"]:
            continue
        if not (lo <= w["end"] <= hi):
            continue
        n = q(a.vl, f'_time:[{w["start"].isoformat()}, {w["end"].isoformat()}] {MARKS} "{w["id"]} begin" | stats count() as n')
        if not n or int(n[0].get("n", 0)) == 0:
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


def render(a, rows, ignored, wins, missing, now, lo, hi):
    L = [f"# 稽核軌跡  {time_filter(a)}，產生於 {now:%Y-%m-%d %H:%M} UTC", ""]
    by_src = collections.Counter(r["source"] for r in rows)
    un = [r for r in rows if not r["cr"]]
    L += [f"管理動作 {len(rows)} 筆（忽略清單排除 {ignored} 筆），有變更單的 {len(rows) - len(un)} 筆，沒有的 {len(un)} 筆", ""]
    L += ["## 依來源", md_table(["來源", "筆數", "沒有變更單"], [(s, n, sum(1 for r in un if r["source"] == s)) for s, n in sorted(by_src.items())]), ""]
    # the same action repeated (a key that logs in every minute) is one line
    # with a count; a week of routine would otherwise bury the one that matters
    grp = collections.OrderedDict()
    for r in un:
        k = (r["source"], r["host"], r["who"], r["what"][:120])
        g = grp.setdefault(k, [0, r["time"], r["time"]])
        g[0] += 1; g[2] = r["time"]
    top = sorted(grp.items(), key=lambda kv: -kv[1][0])[: a.top]
    L += ["## 沒有變更單的動作", "", "依動作彙總，筆數多的在前：", "",
          md_table(["來源", "主機", "誰", "做了什麼", "筆數", "最早 (+08)", "最晚 (+08)"],
                   [(*k, g[0], t(g[1]), t(g[2])) for k, g in top]), ""]
    if len(grp) > a.top:
        L += [f"_另 {len(grp) - a.top} 種動作未列_", ""]
    L += [f"最近 {min(len(un), a.top)} 筆：", "", md_table(["時間 (+08)", "來源", "主機", "誰", "做了什麼"],
          [(t(r["time"]), r["source"], r["host"], r["who"], r["what"][:120]) for r in un[-a.top:]]), ""]
    L += ["## 依變更單"]
    for w in wins:
        inside = [r for r in rows if r["cr"] == w["id"]]
        if w["end"] < lo or w["start"] > hi:
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
    ap.add_argument("--limit", type=int, default=200000, help="rows per source; a week of SSH logins on a lab with key-based polling is tens of thousands")
    ap.add_argument("--top", type=int, default=50)
    ap.add_argument("--out"); ap.add_argument("--textfile")
    a = ap.parse_args()
    now = dt.datetime.now(dt.timezone.utc)
    if a.since and not a.until:  # the header and every query then say where the report stops
        a.until = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    try:
        q(a.vl, "* | limit 1")
    except Exception as e:
        sys.exit(f"VictoriaLogs at {a.vl} unreachable: {e}")
    wins = windows(a.changes) if os.path.isdir(a.changes) else []
    if not wins:
        print(f"audit-report: no change records under {a.changes}; every action will be unattributed", file=sys.stderr)
    lo, hi = bounds(a, now)
    rows = fetch(a)
    rows, ignored = attribute(rows, wins, load_ignore(a.ignore))
    missing = marks_missing(wins, a, lo, hi)
    md = render(a, rows, ignored, wins, missing, now, lo, hi)
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
