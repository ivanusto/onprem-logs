#!/usr/bin/env python3
"""aup-report: who went where, from which workstation. The acceptable-use
review of the edge FortiGate's web-filter log, from either of two places
that must give the same answer:

  online   the lines already in VictoriaLogs (Day 21's syslogd2 feed)
  offline  an export file of key=value lines (FortiGate download,
           FortiAnalyzer, or a copy from the collector)

    aup-report.py --window 7d                        # markdown to stdout
    aup-report.py --since 2026-10-06T00:00:00Z --until 2026-10-07T00:00:00Z
    aup-report.py --from-file export.log
    aup-report.py --window 1h --textfile /var/lib/node_exporter/textfile/aup.prom \
        --expect fgt-edge --out /dev/null

Every row, from either source, is reduced to the same seven fields before
anything is counted: fgt (devname), src (srcip), who (user, else srcname,
else srcip), site (hostname, else dstip), cat (catdesc), action, blocked.
url is deliberately not used for the site, so that a path-only url="/"
and a full URL do not make two sites. The offline parser is the same set
of rules the browser viewer applies (fortigate-log-viewer v0.1.0), so the
three of them can be compared on one file; aup-compare.sh does that.

Four tables: sites per workstation, categories, blocked per workstation,
and hits on the urgent categories (default: Malicious Websites, Phishing,
Spam URLs). --textfile writes the counts for onprem-metrics'
rules-aup.yml; --expect names the FortiGates that must log something in
every window, written as 0 when they log nothing (AupSilent).

Standard library only. Exit 0 unless the source cannot be read.
"""
import argparse, collections, datetime as dt, json, os, re, sys, tempfile, urllib.parse, urllib.request

KV_RE = re.compile(r'([A-Za-z0-9_.-]+)=(?:"([^"]*)"|\'([^\']*)\'|([^\s,]+))')
BLOCKED = {"deny", "block", "blocked", "dropped", "reject", "drop"}
URGENT_DEFAULT = "Malicious Websites,Phishing,Spam URLs"
FIELDS = ["srcip", "srcname", "user", "hostname", "dstip", "catdesc", "action", "eventtype", "type", "subtype"]


def parse_kv(line):
    return {m.group(1).lower(): next(g for g in m.groups()[1:] if g is not None) for m in KV_RE.finditer(line)}


def norm(kv, fgt):
    """One raw record (dict of FortiOS fields) -> the seven fields."""
    src = kv.get("srcip", "")
    who = kv.get("user") or kv.get("srcname") or src or "unknown"
    site = kv.get("hostname") or kv.get("dstip") or "unknown"
    action = (kv.get("action") or kv.get("eventtype") or "").lower()
    return {"fgt": fgt, "src": src, "who": who, "site": site.split(":")[0].lower(),
            "cat": kv.get("catdesc") or "Unrated", "action": action, "blocked": action in BLOCKED}


# ---------- online: VictoriaLogs ----------

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


def rows_from_vl(a):
    # Fields exist only after unpack_logfmt, so the first stage filters on
    # raw words (Day 22's lesson). The rfc5424 header's `hostname` is the
    # devname and the web-filter line's `hostname` is the site; the header
    # field is renamed to fgt before the unpack so the two do not collide.
    fgt_filter = "(" + " OR ".join(f'hostname:="{h}"' for h in a.fgt) + ")" if a.fgt else "hostname:*"
    base = (f'{time_filter(a)} {fgt_filter} "type=\\"utm\\"" "subtype=\\"webfilter\\"" '
            f'| rename hostname as fgt '
            f'| unpack_logfmt from _msg fields ({", ".join(FIELDS)}) '
            f'| filter type:=utm subtype:=webfilter')
    rows = q(a.vl, f"{base} | stats by (fgt, srcip, srcname, user, hostname, dstip, catdesc, action) count() as n")
    out = []
    for r in rows:
        kv = {k: r.get(k, "") for k in FIELDS}
        out.append((norm(kv, r.get("fgt", "")), int(r["n"])))
    return out, None


# ---------- offline: export file ----------

def rows_from_file(path, a):
    agg = collections.Counter()
    stats = {"lines": 0, "parsed": 0, "skipped": 0, "not_webfilter": 0}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            stats["lines"] += 1
            kv = parse_kv(line)
            if not kv:
                stats["skipped"] += 1
                continue
            stats["parsed"] += 1
            if kv.get("type") != "utm" or kv.get("subtype") != "webfilter":
                stats["not_webfilter"] += 1
                continue
            fgt = kv.get("devname") or a.devname
            if a.fgt and fgt not in a.fgt:
                stats["not_webfilter"] += 1
                continue
            n = norm(kv, fgt)
            agg[tuple(sorted(n.items()))] += 1
    return [(dict(k), v) for k, v in agg.items()], stats


# ---------- counting ----------

def summarize(rows, urgent, top):
    S = {"total": collections.Counter(), "blocked": collections.Counter(),
         "by_who_site": collections.defaultdict(collections.Counter),
         "who_total": collections.Counter(), "who_blocked": collections.Counter(),
         "by_cat": collections.Counter(), "by_cat_blocked": collections.Counter(),
         "urgent": collections.defaultdict(collections.Counter), "urgent_rows": [],
         "who_src": {}}
    for r, n in rows:
        fgt, who = r["fgt"], r["who"]
        S["total"][fgt] += n
        S["who_total"][(fgt, who)] += n
        S["by_who_site"][(fgt, who)][(r["site"], r["cat"])] += n
        S["by_cat"][(fgt, r["cat"])] += n
        S["who_src"].setdefault((fgt, who), r["src"])
        if r["blocked"]:
            S["blocked"][fgt] += n
            S["who_blocked"][(fgt, who)] += n
            S["by_cat_blocked"][(fgt, r["cat"])] += n
        if r["cat"] in urgent:
            S["urgent"][fgt][r["cat"]] += n
            S["urgent_rows"].append((fgt, who, r["src"], r["site"], r["cat"], r["action"], n))
    S["urgent_rows"].sort(key=lambda t: (-t[6], t))
    return S


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(str(x) for x in r) + " |" for r in rows]
    return "\n".join(out) if rows else "_無_"


def render(a, S, stats, now, source):
    L = [f"# 可接受使用紀錄  {source}，產生於 {now:%Y-%m-%d %H:%M} UTC", ""]
    if stats:
        L += [f"檔案 {stats['lines']} 行 = {stats['parsed']} 解析 + {stats['skipped']} 略過，其中 webfilter 以外 {stats['not_webfilter']} 行不計", ""]
    fgts = sorted(set(S["total"]) | set(a.expect))
    for fgt in fgts:
        tot, blk = S["total"][fgt], S["blocked"][fgt]
        L += [f"## {fgt}  webfilter {tot} 筆，擋下 {blk} 筆", ""]
        if not tot:
            L += ["_視窗內沒有 webfilter 紀錄_", ""]
            continue
        L += ["### 緊急類別命中", md_table(["工作站", "來源", "網站", "類別", "動作", "筆數"],
              [(w, s, site, c, act, n) for f, w, s, site, c, act, n in S["urgent_rows"] if f == fgt][: a.top]), ""]
        L += ["### 依工作站列網站"]
        whos = sorted(((w, n) for (f, w), n in S["who_total"].items() if f == fgt), key=lambda t: (-t[1], t[0]))
        for who, n in whos[: a.top]:
            src = S["who_src"].get((fgt, who), "")
            L += ["", f"**{who}**（{src}）  {n} 筆，擋下 {S['who_blocked'][(fgt, who)]} 筆", ""]
            sites = sorted(S["by_who_site"][(fgt, who)].items(), key=lambda kv: (-kv[1], kv[0]))
            L += [md_table(["網站", "類別", "筆數"], [(s, c, m) for (s, c), m in sites[: a.top]])]
        L += ["", "### 依類別", md_table(["類別", "筆數", "其中擋下"],
              [(c, n, S["by_cat_blocked"][(fgt, c)]) for (f, c), n in sorted(S["by_cat"].items(), key=lambda kv: (-kv[1], kv[0])) if f == fgt][: a.top]), ""]
        L += ["### 被擋的，依工作站", md_table(["工作站", "來源", "擋下筆數"],
              [(w, S["who_src"].get((fgt, w), ""), n) for (f, w), n in sorted(S["who_blocked"].items(), key=lambda kv: (-kv[1], kv[0])) if f == fgt][: a.top]), ""]
    L += ["## 告警候選", ""]
    cands = [f"- `{f}` {w}（{s}）到 {site}，類別 {c}，{n} 筆，立即處理" for f, w, s, site, c, act, n in S["urgent_rows"]]
    cands += [f"- `{f}` {w} 被擋 {n} 次，超過 {a.burst}" for (f, w), n in S["who_blocked"].items() if n >= a.burst]
    L += cands or ["_無_"]
    L.append("")
    return "\n".join(L)


def write_textfile(path, S, urgent, expect, now):
    L = []
    def fam(n, h): L.extend([f"# HELP {n} {h}", f"# TYPE {n} gauge"])
    fgts = sorted(set(S["total"]) | set(expect))
    fam("aup_webfilter_total", "Web-filter log lines in the report window")
    L += [f'aup_webfilter_total{{fgt="{f}"}} {S["total"][f]}' for f in fgts]
    fam("aup_webfilter_blocked", "Web-filter lines with a blocking action in the window")
    L += [f'aup_webfilter_blocked{{fgt="{f}"}} {S["blocked"][f]}' for f in fgts]
    fam("aup_webfilter_urgent", "Hits on the urgent categories in the window (0 is written for every category so the rule has a series)")
    for f in fgts:
        for c in sorted(urgent):
            L.append(f'aup_webfilter_urgent{{fgt="{f}",catdesc="{c}"}} {S["urgent"][f][c]}')
    fam("aup_webfilter_blocked_top_source", "Blocked lines from the single most blocked workstation")
    for f in fgts:
        best = max(((w, n) for (ff, w), n in S["who_blocked"].items() if ff == f), key=lambda t: (t[1], t[0]), default=None)
        if best:
            L.append(f'aup_webfilter_blocked_top_source{{fgt="{f}",who="{best[0]}"}} {best[1]}')
    fam("aup_report_last_run_timestamp", "Unix time of the last aup-report run")
    L.append(f"aup_report_last_run_timestamp {int(now.timestamp())}")
    body = "\n".join(L) + "\n"
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".aup.")
    with os.fdopen(fd, "w") as f:
        f.write(body)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--vl", default=os.environ.get("VL", "http://127.0.0.1:9428"))
    ap.add_argument("--window", default="7d", help="LogsQL duration ending now, e.g. 1h, 24h, 7d")
    ap.add_argument("--since"); ap.add_argument("--until", help="RFC 3339 bounds instead of --window")
    ap.add_argument("--from-file", help="offline: an export of key=value lines instead of VictoriaLogs")
    ap.add_argument("--devname", default="FortiGate", help="--from-file: name for lines without devname (memory-log exports), as fortigate-export-load.py")
    ap.add_argument("--fgt", action="append", default=[], help="devname(s) to include; default all")
    ap.add_argument("--urgent", default=os.environ.get("AUP_URGENT", URGENT_DEFAULT), help="comma separated catdesc values that page")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--burst", type=int, default=20, help="candidate threshold, blocked lines from one workstation")
    ap.add_argument("--out", help="write markdown here instead of stdout")
    ap.add_argument("--textfile", help="also write Prometheus textfile metrics here")
    ap.add_argument("--expect", default=os.environ.get("AUP_EXPECT", ""), help="FortiGate devnames that must log web-filter lines; written as 0 when silent")
    a = ap.parse_args()
    a.expect = [x for x in re.split(r"[\s,]+", a.expect) if x]
    urgent = {x.strip() for x in a.urgent.split(",") if x.strip()}
    now = dt.datetime.now(dt.timezone.utc)

    if a.from_file:
        rows, stats = rows_from_file(a.from_file, a)
        source = f"檔案 {os.path.basename(a.from_file)}"
    else:
        try:
            q(a.vl, "* | limit 1")
        except Exception as e:
            sys.exit(f"VictoriaLogs at {a.vl} unreachable: {e}")
        rows, stats = rows_from_vl(a)
        source = f"VictoriaLogs {time_filter(a)}"
    S = summarize(rows, urgent, a.top)
    md = render(a, S, stats, now, source)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(md)
        if a.out != os.devnull:
            print(f"wrote {a.out}")
    else:
        sys.stdout.write(md)
    if a.textfile:
        write_textfile(a.textfile, S, urgent, a.expect, now)


if __name__ == "__main__":
    main()
