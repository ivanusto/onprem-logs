#!/usr/bin/env python3
"""fw-report: read the firewall drops already sitting in VictoriaLogs and
answer the three questions a weekly firewall review asks:

  1. who is knocking           top source addresses per host
  2. where are they knocking   top destination ports per host
  3. who is new                sources seen in the window but not in the
                               baseline period before it

plus, for the NAS, failed logins per source from QuLog's connection log.

Five log shapes, one script. Patterns live in SOURCES below; the field
names come from Day 21's ingestion (journald: _HOSTNAME, _TRANSPORT,
SYSLOG_IDENTIFIER; syslog: hostname, app_name). Every source ends up with
the same four fields, src dst proto dpt, so the rest of the script does
not care which wall a line came from.

    fw-report.py --window 24h --baseline 7d                 # markdown to stdout
    fw-report.py --window 1h --textfile /var/lib/node_exporter/textfile/fw.prom \
        --expect fortigate:fgt-edge
    fw-report.py --window 7d --out /srv/reports/fw-$(date +%F).md

--expect (or FW_EXPECT, space or comma separated source:host pairs) names
the hosts that must drop something in every window. A host with no drops
returns no row at all from "stats by (host)", so without this list the
textfile would simply lack its series and FwSilent could never fire.

Standard library only. Exit 0 always unless VictoriaLogs is unreachable;
the report is a review aid, the alerting is done by the textfile metrics
and Day 20's rules.
"""
import argparse, datetime as dt, json, os, re, sys, tempfile, urllib.parse, urllib.request

# Each source: a LogsQL filter that selects its drop lines, the host field,
# and the pipes that leave src, dst, proto and dpt on every row. "<...>" is
# LogsQL extract syntax; the kernel/pvefw lines share the netfilter LOG
# format, the leading space keeps " SRC=" from matching inside MAC=.
NETFILTER = ('extract " SRC=<src> " | extract " DST=<dst> " '
             '| extract " PROTO=<proto> " | extract " DPT=<dpt> "')
SOURCES = {
    # edge FortiGate: syslogd2 in rfc5424, so devname and date sit in the
    # header (hostname, _time) and _msg is key=value. Fields exist only
    # after unpack_logfmt, so the first stage filters on raw words.
    "fortigate": {"filter": 'format:rfc5424 "type=\\"traffic\\"" "action=\\"deny\\""', "host": "hostname",
                  "pipes": "unpack_logfmt from _msg fields (srcip, dstip, proto, dstport, action) "
                           "| filter action:=deny | rename srcip as src, dstip as dst, dstport as dpt"},
    # DGX Spark: ufw "low" logging, kernel transport, prefix [UFW BLOCK]
    "ufw": {"filter": '_TRANSPORT:=kernel "[UFW BLOCK]"', "host": "_HOSTNAME", "pipes": NETFILTER},
    # PVE: pve-firewall via pvefw-journal.service. The prefix comes from
    # PVE/Firewall.pm ruleset_add_chain_policy(): "policy DROP: " or
    # "policy REJECT: " after VMID, log level and chain.
    "pvefw": {"filter": 'SYSLOG_IDENTIFIER:=pve-firewall ("policy DROP:" OR "policy REJECT:")',
              "host": "_HOSTNAME", "pipes": NETFILTER},
    # collector: DOCKER-USER allowlist LOG rule, prefix [DOCKER-USER DROP]
    "docker-user": {"filter": '_TRANSPORT:=kernel "[DOCKER-USER DROP]"', "host": "_HOSTNAME", "pipes": NETFILTER},
}
# QuLog connection log over syslog (RFC 3164, one line), as seen on QuTS
# hero 6.0.2 / QuLog 3.0.1:
#   conn log: Users: <user>, Source IP: <ip>, Computer name: ---,
#   Connection type: SSH/SFTP|HTTP|HTTPS|..., Accessed resources: ...,
#   Action: Login Success|Logout|Login Fail
NAS = {
    "filter": '"conn log:"', "host": "hostname",
    "ip": 'extract "Source IP: <ip>,"', "action": 'extract "Action: <action>"',
    "ctype": 'extract "Connection type: <ctype>,"', "user": 'extract "Users: <user>,"',
    "fail_re": re.compile(r"fail|denied|invalid|locked", re.I),
}


def q(vl, query, limit=0):
    data = {"query": query}
    if limit:
        data["limit"] = str(limit)
    req = urllib.request.Request(vl.rstrip("/") + "/select/logsql/query",
                                 data=urllib.parse.urlencode(data).encode(), method="POST")
    with urllib.request.urlopen(req, timeout=120) as r:
        return [json.loads(l) for l in r.read().decode().splitlines() if l.strip()]


def window_filter(window, offset=None):
    """_time filter for the last <window>; with offset, the <window> that
    ended <offset> ago (LogsQL: _time:7d offset 24h = the 7 days before
    the last 24 hours)."""
    if offset is None:
        return f"_time:{window}"
    return f"_time:{window} offset {offset}"


def netfilter_stats(vl, name, src, window, offset=None):
    base = f"{window_filter(window, offset)} {src['filter']} | {src['pipes']}"
    host = src["host"]
    total = q(vl, f"{base} | stats by ({host}) count() as n")
    by_src = q(vl, f"{base} | stats by ({host}, src) count() as n | sort by (n) desc")
    by_dpt = q(vl, f"{base} | stats by ({host}, proto, dpt) count() as n | sort by (n) desc")
    by_hour = q(vl, f"{base} | stats by ({host}, _time:1h) count() as n | sort by (_time)")
    return {"host_field": host, "total": total, "by_src": by_src, "by_dpt": by_dpt, "by_hour": by_hour}


def netfilter_sources_set(vl, src, window, offset=None):
    base = f"{window_filter(window, offset)} {src['filter']} | {src['pipes']}"
    rows = q(vl, f"{base} | stats by ({src['host']}, src) count() as n")
    return {(r.get(src["host"], ""), r.get("src", "")) for r in rows if r.get("src")}


def nas_stats(vl, window):
    base = f"{window_filter(window)} {NAS['filter']} | {NAS['ip']} | {NAS['action']} | {NAS['ctype']} | {NAS['user']}"
    rows = q(vl, f"{base} | stats by ({NAS['host']}, ip, action, ctype) count() as n | sort by (n) desc")
    fails = [r for r in rows if NAS["fail_re"].search(r.get("action", ""))]
    by_ip = {}
    for r in fails:
        k = (r.get(NAS["host"], ""), r.get("ip", ""))
        by_ip[k] = by_ip.get(k, 0) + int(r["n"])
    return {"rows": rows, "fails": fails, "fails_by_ip": by_ip}


# FortiGate logs the IP protocol number, netfilter the name
PROTO = {"1": "ICMP", "6": "TCP", "17": "UDP", "58": "ICMPv6"}


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for r in rows:
        out.append("| " + " | ".join(str(x) for x in r) + " |")
    return "\n".join(out) if rows else "_無_"


def render_markdown(a, results, new_sources, nas, now):
    L = [f"# 防火牆日誌判讀  視窗 {a.window}，基線 {a.baseline}，產生於 {now:%Y-%m-%d %H:%M} UTC", ""]
    for name, r in results.items():
        hf = r["host_field"]
        tot = sum(int(x["n"]) for x in r["total"])
        L += [f"## {name}  共 {tot} 筆", ""]
        if not tot:
            L += ["_視窗內沒有被擋的封包_", ""]
            continue
        L += ["### 誰在敲", md_table(["主機", "來源", "筆數"], [(x.get(hf, ""), x.get("src", ""), x["n"]) for x in r["by_src"][: a.top]]), ""]
        L += ["### 敲哪裡", md_table(["主機", "協定", "目的埠", "筆數"], [(x.get(hf, ""), PROTO.get(x.get("proto", ""), x.get("proto", "")), x.get("dpt", ""), x["n"]) for x in r["by_dpt"][: a.top]]), ""]
        hours = {}
        for x in r["by_hour"]:
            hours[x["_time"][:13]] = hours.get(x["_time"][:13], 0) + int(x["n"])
        if hours:
            peak = max(hours.items(), key=lambda kv: kv[1])
            L += [f"### 時間分佈  {len(hours)} 個小時有紀錄，最高 {peak[0]}Z 有 {peak[1]} 筆", ""]
        ns = sorted(s for s in new_sources.get(name, set()))
        L += ["### 新面孔（視窗內出現，基線期間沒有）", md_table(["主機", "來源"], ns), ""]
    L += [f"## NAS 連線紀錄  {len(nas['rows'])} 種（主機、來源、動作、類型）組合", ""]
    L += ["### 登入失敗，依來源", md_table(["NAS", "來源", "筆數"],
          sorted(((k[0], k[1], v) for k, v in nas["fails_by_ip"].items()), key=lambda t: -t[2])[: a.top]), ""]
    L += ["### 全部動作", md_table(["NAS", "來源", "動作", "類型", "筆數"],
          [(x.get(NAS["host"], ""), x.get("ip", ""), x.get("action", ""), x.get("ctype", ""), x["n"]) for x in nas["rows"][: a.top]]), ""]
    L += ["## 告警候選", ""]
    cands = []
    for name, r in results.items():
        for x in r["by_src"]:
            if int(x["n"]) >= a.burst:
                cands.append(f"- `{name}` {x.get(r['host_field'], '')} 被 {x.get('src', '')} 敲了 {x['n']} 次，超過 {a.burst}")
    for (h, ip), n in nas["fails_by_ip"].items():
        if n >= a.nas_fail:
            cands.append(f"- NAS {h} 來自 {ip} 的登入失敗 {n} 次，超過 {a.nas_fail}")
    for name, s in new_sources.items():
        for h, ip in sorted(s):
            cands.append(f"- `{name}` {h} 第一次看到 {ip}")
    L += cands or ["_無_"]
    L.append("")
    return "\n".join(L)


def parse_expect(spec):
    """'fortigate:fgt1, ufw:spark02' -> {('fortigate', 'fgt1'), ('ufw', 'spark02')}"""
    out = set()
    for item in re.split(r"[\s,]+", spec or ""):
        if not item:
            continue
        name, sep, host = item.partition(":")
        if not sep or name not in SOURCES or not host:
            sys.exit(f"--expect: '{item}' is not source:host with source in {', '.join(SOURCES)}")
        out.add((name, host))
    return out


def write_textfile(path, results, new_sources, nas, now, expect=()):
    lines = []
    def fam(name, hlp, typ="gauge"):
        lines.append(f"# HELP {name} {hlp}"); lines.append(f"# TYPE {name} {typ}")
    fam("fw_blocked", "Blocked packets logged in the report window")
    for name, r in results.items():
        seen = set()
        for x in r["total"]:
            h = x.get(r["host_field"], "")
            seen.add(h)
            lines.append(f'fw_blocked{{source="{name}",host="{h}"}} {x["n"]}')
        # an expected host that dropped nothing has no row; say 0 so that
        # FwSilent has a series to look at
        for h in sorted(h for n, h in expect if n == name and h not in seen):
            lines.append(f'fw_blocked{{source="{name}",host="{h}"}} 0')
    fam("fw_top_source_blocked", "Blocked packets from the single busiest source in the window")
    for name, r in results.items():
        seen = set()
        for x in r["by_src"]:
            h = x.get(r["host_field"], "")
            if h in seen:
                continue
            seen.add(h)
            lines.append(f'fw_top_source_blocked{{source="{name}",host="{h}",src="{x.get("src", "")}"}} {x["n"]}')
    fam("fw_new_sources", "Sources seen in the window but not in the baseline")
    for name, s in new_sources.items():
        per = {}
        for h, _ in s:
            per[h] = per.get(h, 0) + 1
        for h, n in per.items():
            lines.append(f'fw_new_sources{{source="{name}",host="{h}"}} {n}')
    fam("nas_login_failed", "Failed logins in QuLog connection log in the window")
    per = {}
    for (h, _), n in nas["fails_by_ip"].items():
        per[h] = per.get(h, 0) + n
    for h, n in per.items():
        lines.append(f'nas_login_failed{{nas="{h}"}} {n}')
    fam("nas_login_failed_top_source", "Failed logins from the single busiest source")
    best = {}
    for (h, ip), n in nas["fails_by_ip"].items():
        if n > best.get(h, ("", 0))[1]:
            best[h] = (ip, n)
    for h, (ip, n) in best.items():
        lines.append(f'nas_login_failed_top_source{{nas="{h}",src="{ip}"}} {n}')
    fam("fw_report_last_run_timestamp", "Unix time of the last fw-report run")
    lines.append(f"fw_report_last_run_timestamp {int(now.timestamp())}")
    body = "\n".join(lines) + "\n"
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".fw.")
    with os.fdopen(fd, "w") as f:
        f.write(body)
    os.chmod(tmp, 0o644)   # Day 19: mkstemp gives 0600, node_exporter is not root
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--vl", default=os.environ.get("VL", "http://127.0.0.1:9428"))
    ap.add_argument("--window", default="24h", help="LogsQL duration, e.g. 1h, 24h, 7d")
    ap.add_argument("--baseline", default="7d", help="period before the window used to decide what is new")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--burst", type=int, default=100, help="candidate threshold, blocked packets from one source")
    ap.add_argument("--nas-fail", type=int, default=5, help="candidate threshold, failed logins from one source")
    ap.add_argument("--out", help="write markdown here instead of stdout")
    ap.add_argument("--textfile", help="also write Prometheus textfile metrics here")
    ap.add_argument("--only", choices=list(SOURCES), action="append", help="limit to these sources")
    ap.add_argument("--expect", default=os.environ.get("FW_EXPECT", ""),
                    help="source:host pairs that must log drops; written as 0 when they log none (FwSilent)")
    a = ap.parse_args()
    now = dt.datetime.now(dt.timezone.utc)

    try:
        q(a.vl, "* | limit 1")
    except Exception as e:
        sys.exit(f"VictoriaLogs at {a.vl} unreachable: {e}")

    expect = parse_expect(a.expect)
    names = a.only or list(SOURCES)
    results, new_sources = {}, {}
    for name in names:
        src = SOURCES[name]
        results[name] = netfilter_stats(a.vl, name, src, a.window)
        cur = netfilter_sources_set(a.vl, src, a.window)
        base = netfilter_sources_set(a.vl, src, a.baseline, offset=a.window)
        new_sources[name] = cur - base
    nas = nas_stats(a.vl, a.window)

    md = render_markdown(a, results, new_sources, nas, now)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(md)
        if a.out != os.devnull:
            print(f"wrote {a.out}")
    else:
        sys.stdout.write(md)
    if a.textfile:
        write_textfile(a.textfile, results, new_sources, nas, now, expect)


if __name__ == "__main__":
    main()
