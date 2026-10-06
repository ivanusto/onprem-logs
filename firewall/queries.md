# 防火牆日誌的 LogsQL

五種來源，三種格式。netfilter 的 LOG 行（ufw、pve-firewall、DOCKER-USER）都有 `SRC= DST= PROTO= DPT=`，用同一組 `extract`。FortiGate 的 traffic 日誌是 key=value，用 `unpack_logfmt`。QuLog 的連線紀錄是一行文字，欄位以「名稱: 值,」排列。主機名稱是代稱：`fgt-edge` 是邊界 FortiGate 的 devname，`metrics` 是收集端，`nas-primary` 是主 NAS。

```
# 邊界 FortiGate，被擋的連線，依來源、目的與目的埠
_time:24h hostname:=fgt-edge "type=\"traffic\"" "action=\"deny\""
  | unpack_logfmt from _msg fields (srcip, dstip, dstport, proto, policyid, action)
  | filter action:=deny
  | stats by (srcip, dstip, proto, dstport) count() as n | sort by (n) desc | limit 20

# 邊界 FortiGate，依政策與動作分（policyid 0 是 implicit deny）
_time:24h hostname:=fgt-edge "type=\"traffic\""
  | unpack_logfmt from _msg fields (subtype, policyid, policyname, action)
  | stats by (subtype, policyid, policyname, action) count() as n | sort by (n) desc

# 邊界 FortiGate，被 local-in-policy 擋下、打到防火牆自己的
_time:24h hostname:=fgt-edge "subtype=\"local\"" "action=\"deny\""
  | unpack_logfmt from _msg fields (srcip, dstport, policyid)
  | stats by (srcip, dstport, policyid) count() as n | sort by (n) desc | limit 20

# 收集端，DOCKER-USER 擋掉的（平常應該是空的）
_time:24h _TRANSPORT:=kernel "[DOCKER-USER DROP]"
  | extract " SRC=<src> " | extract " DPT=<dpt> " | stats by (_HOSTNAME, src, dpt) count() as n | sort by (n) desc

# NAS，登入失敗依來源
_time:24h "conn log:" | extract "Source IP: <ip>," | extract "Action: <action>"
  | filter action:~"(?i)fail" | stats by (hostname, ip) count() as n | sort by (n) desc

# NAS，排除收集端每分鐘的 SSH 之後，依來源、類型與動作
_time:24h "conn log:" -"Source IP: 192.168.2.49,"
  | extract "Source IP: <ip>," | extract "Connection type: <ctype>," | extract "Action: <action>"
  | stats by (hostname, ip, ctype, action) count() as n | sort by (n) desc

# NAS，一個來源做過的所有事
_time:7d "conn log:" "Source IP: 192.168.2.10," | sort by (_time) | limit 100

# 一道牆被擋的封包每小時分佈
_time:7d hostname:=fgt-edge "type=\"traffic\"" "action=\"deny\"" | stats by (_time:1h) count() as n

# DGX Spark，ufw 擋掉的（這個場域的 ufw 沒有啟用，啟用後才會有）
_time:24h _TRANSPORT:=kernel "[UFW BLOCK]"
  | extract " SRC=<src> " | extract " PROTO=<proto> " | extract " DPT=<dpt> "
  | stats by (_HOSTNAME, src, proto, dpt) count() as n | sort by (n) desc | limit 20

# PVE，pve-firewall 的 DROP（經 pvefw-journal.service；這個場域尚未開啟）
_time:24h SYSLOG_IDENTIFIER:=pve-firewall "policy DROP:"
  | extract " SRC=<src> " | extract " DPT=<dpt> "
  | stats by (_HOSTNAME, src, dpt) count() as n | sort by (n) desc | limit 20

# 新面孔，手動版（fw-report.py 做的是同一件事）
_time:24h hostname:=fgt-edge "action=\"deny\"" | unpack_logfmt from _msg fields (srcip) | stats by (srcip) count()
_time:7d offset 24h hostname:=fgt-edge "action=\"deny\"" | unpack_logfmt from _msg fields (srcip) | stats by (srcip) count()
```

幾個寫法上的理由：

- FortiGate 送 rfc5424 時，`devname`、`date`、`time` 會搬到 syslog 標頭，`_msg` 裡就沒有了。主機用 `hostname`，時間用 `_time`（有時區，不需要靠 `-syslog.timezone`）。用 `default` 格式送時沒有標頭，VictoriaLogs 會把整行當成 RFC 3164 的內容，`hostname` 是空的，`_time` 變成收到的時間。
- 欄位在 `unpack_logfmt` 之後才存在，所以第一段的篩選只能用原文關鍵字，`action:=deny` 放在後面的 `filter`。順序反過來，查到的會是空集合。`"action=\"deny\""` 先在原文篩一次，能讓 `unpack_logfmt` 少拆大部分的 accept。
- `extract " SRC=<src> "` 前後的空白是刻意的：`MAC=` 的值裡也有等號，沒有空白會對錯位。
- `_time:7d offset 24h` 是「到 24 小時前為止的 7 天」。順序寫反會變成「到 7 天前為止的 24 小時」，本機測試時踩過。
- 收集端的 Day 19 `nas-textfile.sh` 每分鐘以 SSH 登入兩台 NAS，每台每天約 1,440 筆 `Login Success`，看 NAS 的連線紀錄前先排除 192.168.2.49。
