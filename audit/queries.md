# 稽核軌跡的 LogsQL（Day 27）

六種管理動作，一個共同問題，這件事有沒有變更單。變更單的窗由 `audit-report.py` 從 onprem-changes 的 front matter 讀，這裡的查詢是人手查的版本。主機名稱是代稱。

```
# FortiGate 設定變更，誰從哪個介面改了什麼（cfgattr 是舊值到新值）
_time:7d audit:=fortigate "type=\"event\"" "subtype=\"system\"" "cfgpath="
  | unpack_logfmt from _msg fields (user, ui, action, cfgpath, cfgobj, cfgattr, cfgtid)
  | fields _time, user, ui, action, cfgpath, cfgobj, cfgattr, cfgtid | sort by (_time)

# 同一次交易的所有變更（cfgtid 相同）
_time:7d audit:=fortigate "cfgtid=12345" | unpack_logfmt from _msg fields (cfgpath, cfgobj, cfgattr) | fields _time, cfgpath, cfgobj, cfgattr

# FortiGate 管理員登入與失敗
_time:7d audit:=fortigate ("logid=\"0100032001\"" OR "logid=\"0100032002\"" OR "logid=\"0100032003\"")
  | unpack_logfmt from _msg fields (user, ui, status, logdesc) | fields _time, user, ui, status, logdesc | sort by (_time)

# 收到的事件有哪些類型（驗證 syslogd3 的 filter）
_time:1h audit:=fortigate | unpack_logfmt from _msg fields (type, subtype, logid) | stats by (type, subtype, logid) count() as n | sort by (n) desc

# PVE 的任務，誰起了什麼（UPID 的欄位：節點、pid、pstart、開始時間、類型、對象、使用者）
_time:7d SYSLOG_IDENTIFIER:=pvedaemon "starting task UPID:"
  | extract "starting task UPID:<node>:<pid>:<pstart>:<stime>:<ttype>:<tid>:<tuser>:"
  | stats by (_HOSTNAME, tuser, ttype) count() as n | sort by (n) desc

# PVE 的登入
_time:7d SYSLOG_IDENTIFIER:=pvedaemon "successful auth for user"
  | extract "successful auth for user '<user>'" | stats by (_HOSTNAME, user) count()

# 任何主機上的 sudo，誰以誰的身分跑了什麼
_time:7d SYSLOG_IDENTIFIER:=sudo "COMMAND="
  | extract "<who> : TTY=" | extract " USER=<as> ;" | extract "COMMAND=<cmd>"
  | fields _time, _HOSTNAME, who, as, cmd | sort by (_time)

# SSH 登入成功，依主機與帳號
_time:7d SYSLOG_IDENTIFIER:=sshd "Accepted "
  | extract "Accepted <method> for <who> from <ip> port" | stats by (_HOSTNAME, who, ip, method) count() as n | sort by (n) desc

# NAS 的事件日誌（不是連線紀錄），誰做了什麼
_time:7d "event log:" | extract "Users: <who>, Source IP: <ip>," | fields _time, hostname, who, ip, _msg | sort by (_time)

# 一張變更單的窗裡發生的所有事（窗從單子的 front matter 抄）
_time:[2026-10-10T22:45:00+08:00, 2026-10-10T23:45:00+08:00)
  (audit:=fortigate OR SYSLOG_IDENTIFIER:in(pvedaemon, sudo, sshd, change) OR "event log:")
  | fields _time, _HOSTNAME, hostname, SYSLOG_IDENTIFIER, _msg | sort by (_time)

# 變更單的標記本身（change-mark.sh 與操作者手敲的 logger -t change）
_time:7d SYSLOG_IDENTIFIER:=change | fields _time, _HOSTNAME, _msg | sort by (_time)
```

寫法上的兩點。`audit:=fortigate` 是 515 監聽器加的欄位，比 `hostname:=fgt-edge` 更準，後者也會抓到 514 的 traffic。`extract` 的樣式裡 `UPID:` 後的欄位以冒號分隔，最後一個 `:` 要寫在樣式裡，否則 `tuser` 會把後面的字串一起吃掉。
