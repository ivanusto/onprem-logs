# 稽核軌跡的 LogsQL（Day 27）

六種管理動作（Day 29 起七種，多了代理程式閘道的決定），一個共同問題，這件事有沒有變更單。變更單的窗由 `audit-report.py` 從 onprem-changes 的 front matter 讀，這裡的查詢是人手查的版本。主機名稱是代稱。

```
# FortiGate 設定變更，誰從哪個介面改了什麼（cfgattr 是舊值到新值）
_time:7d audit:=fortigate "type=\"event\"" "subtype=\"system\"" "cfgpath="
  | unpack_logfmt from _msg fields (user, ui, action, cfgpath, cfgobj, cfgattr, cfgtid)
  | fields _time, user, ui, action, cfgpath, cfgobj, cfgattr, cfgtid | sort by (_time)

# 同一次交易的所有變更（cfgtid 相同）
_time:7d audit:=fortigate "cfgtid=12345" | unpack_logfmt from _msg fields (cfgpath, cfgobj, cfgattr) | fields _time, cfgpath, cfgobj, cfgattr

# FortiGate 管理員登入、失敗、登出（7.6.7 實測：0100032001 成功、0100032002 失敗 level=alert、0100032003 登出帶 duration）
_time:7d audit:=fortigate ("logid=\"0100032001\"" OR "logid=\"0100032002\"" OR "logid=\"0100032003\"")
  | unpack_logfmt from _msg fields (user, ui, status, reason, logdesc) | fields _time, user, ui, status, reason, logdesc | sort by (_time)

# 收到的事件有哪些類型（驗證 syslogd3 的 filter）
_time:1h audit:=fortigate | unpack_logfmt from _msg fields (type, subtype, logid) | stats by (type, subtype, logid) count() as n | sort by (n) desc

# PVE 的任務，誰起了什麼（UPID 的欄位：節點、pid、pstart、開始時間、類型、對象、使用者）。
# 不限 SYSLOG_IDENTIFIER：這個場域一行 pvedaemon 都沒有，寫這種行的是 qm（CLI 與 HA 的
# hastart/hastop）、pve-ha-lrm（qmstart/qmstop）、pveupdate（aptupdate）。GUI 與 API 的動作
# 才會是 pvedaemon 或 pveproxy。
_time:7d "starting task UPID:"
  | extract "starting task UPID:<node>:<pid>:<pstart>:<stime>:<ttype>:<tid>:<tuser>:"
  | stats by (_HOSTNAME, SYSLOG_IDENTIFIER, tuser, ttype) count() as n | sort by (n) desc

# PVE 的登入
_time:7d SYSLOG_IDENTIFIER:=pvedaemon "successful auth for user"
  | extract "successful auth for user '<user>'" | stats by (_HOSTNAME, user) count()

# 任何主機上的 sudo，誰以誰的身分跑了什麼。沒有終端機的 sudo（ssh host sudo ...、cron）
# 沒有 TTY= 那一段，所以 who 取到第一個 " : " 為止；被拒的行（a password is required、
# command not allowed）也有 COMMAND=，要看 _msg
_time:7d SYSLOG_IDENTIFIER:=sudo "COMMAND="
  | extract "<who> : " | extract " USER=<as> ;" | extract "COMMAND=<cmd>"
  | fields _time, _HOSTNAME, who, as, cmd | sort by (_time)

# SSH 登入成功，依主機、帳號與金鑰指紋。PVE 9（Debian 13 的 OpenSSH）寫成 sshd-session，
# 只寫 sshd 會漏掉兩台 PVE。同一個來源 IP 可能是好幾個人或程式（NAS 同時是 tailnet 的
# SNAT 來源），分得開它們的是金鑰指紋
_time:7d SYSLOG_IDENTIFIER:in(sshd, sshd-session) "Accepted "
  | extract "Accepted <method> for <who> from <ip> port <port> ssh2<key>"
  | stats by (_HOSTNAME, who, ip, method, key) count() as n | sort by (n) desc

# NAS 的事件日誌（不是連線紀錄），誰做了什麼。QuLog 的實際欄位是 Users、Source IP、
# Computer name、Application、Category（有的沒有）、Content；系統自己做的事 Users 是 ---
_time:7d "event log:" | extract "Users: <who>, Source IP: <ip>," | extract "Application: <app>, "
  | extract "Category: <cat>, " | extract "Content: <content>"
  | fields _time, hostname, who, ip, app, cat, content | sort by (_time)

# 一張變更單的窗裡發生的所有事（窗從單子的 front matter 抄）
_time:[2026-10-10T22:45:00+08:00, 2026-10-10T23:45:00+08:00)
  (audit:=fortigate OR "starting task UPID:" OR SYSLOG_IDENTIFIER:in(sudo, sshd, sshd-session, change) OR "event log:")
  | fields _time, _HOSTNAME, hostname, SYSLOG_IDENTIFIER, _msg | sort by (_time)

# 一個 sudo 是從哪裡登入的：sudo 那一行有 _AUDIT_SESSION，sshd 的 Accepted 沒有；
# systemd-logind 在 Accepted 之後幾十毫秒寫 New session N of user U.，用主機、帳號
# 與時間把兩者串起來（audit-report.py 的 --quiet-from 就是這樣判斷管理工作站）
_time:1d _HOSTNAME:=collector SYSLOG_IDENTIFIER:=sudo | fields _time, _AUDIT_SESSION, _msg
_time:1d _HOSTNAME:=collector ((SYSLOG_IDENTIFIER:in(sshd, sshd-session) "Accepted ") OR (SYSLOG_IDENTIFIER:=systemd-logind "New session"))
  | fields _time, SYSLOG_IDENTIFIER, _msg | sort by (_time)

# 變更單的標記本身（change-mark.sh 與操作者手敲的 logger -t change）
_time:7d SYSLOG_IDENTIFIER:=change | fields _time, _HOSTNAME, _msg | sort by (_time)

# 代理程式閘道的決定（Day 29，onprem-agent-gate）：誰、在哪張單底下、要做什麼、放不放，hash 是鏈結稽核檔那一筆的前 16 碼
_time:7d SYSLOG_IDENTIFIER:=agent-gate "decision="
  | extract "seq=<seq> principal=<who> operator=<operator> cr=<cr> tool=<tool> level=<level> decision=<decision> " | extract "hash=<hash>"
  | fields _time, seq, who, cr, tool, level, decision, hash | sort by (_time)
# 被拒絕的呼叫，與拒絕的理由在收集端 gatectl tail 裡
_time:7d SYSLOG_IDENTIFIER:=agent-gate "decision=DENY" | fields _time, _msg
```

寫法上的兩點。`audit:=fortigate` 是 515 監聽器加的欄位，比 `hostname:=fgt-edge` 更準，後者也會抓到 514 的 traffic。`extract` 的樣式裡 `UPID:` 後的欄位以冒號分隔，最後一個 `:` 要寫在樣式裡，否則 `tuser` 會把後面的字串一起吃掉。
