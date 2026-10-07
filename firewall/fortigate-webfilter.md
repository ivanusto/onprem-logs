# 工作站的可接受使用：FortiGate webfilter 日誌（Day 24）

Day 22 問「誰在敲我的節點」，用的是 `type="traffic" action="deny"`。Day 24 問「我的人從哪台工作站去了哪裡」，用的是同一台邊界 FortiGate 的 `type="utm" subtype="webfilter"`。前者是安全事件，後者是可接受使用政策（AUP）與 ITGC 的「使用者活動紀錄可追溯」。

兩條線，同一份欄位定義，答案要一樣。

| 線 | 情境 | 工具 | 日誌怎麼來 |
|---|---|---|---|
| 線上 | 自己管的 FortiGate，能設 syslog 目的地 | Day 21 的 VictoriaLogs，下面的 LogsQL，`aup-report.py` | FortiGate syslogd2 → 514/tcp → 收集端（Day 22 已接） |
| 離線 | 代管的設備，只給匯出檔 | [fortigate-log-viewer](https://github.com/ivanusto/fortigate-log-viewer) 在瀏覽器裡解析，`aup-report.py --from-file` | FortiGate 或 FortiAnalyzer 匯出的 `.log`、`.txt`、`.csv` |

欄位的規則，三邊相同（LogsQL、`aup-report.py`、viewer 的 `fortigateParser.js`）：

| 欄位 | 規則 |
|---|---|
| 工作站 | `user`，沒有就 `srcname`，再沒有就 `srcip`。這個場域沒有使用者認證，`user` 是空的，所以是 `srcip`，`srcname` 來自裝置偵測，有就顯示 |
| 網站 | `hostname`，沒有就 `dstip`。`url` 刻意不用來決定網站，`url="/"` 與完整 URL 不該變成兩個網站 |
| 類別 | `catdesc`，空的算 `Unrated` |
| 擋下 | `action` 是 deny、block、blocked、dropped、reject、drop。webfilter 的放行是 `passthrough` |
| 時間 | 線上是 rfc5424 標頭的 `_time`。離線先用 `eventtime`（7.x 是奈秒），沒有就 `date`+`time`+`tz` |

## FortiGate 那一端

場域前面是 FortiGate 60F，自己管，Day 22 已把 syslogd2 接到收集端（rfc5424、TCP 514、只送 traffic 的 forward 與 local、排除 event 與 NTP）。Day 22 收到的只有 traffic，一筆 webfilter 都沒有，原因是 `policy 1`（內部到外部）沒有掛網頁過濾 profile，防火牆根本沒有產生 webfilter 日誌，與 syslog 的 filter 無關。要有紀錄，先讓防火牆記。

三件事，都是變更，照 Day 26 的變更單走。

1. **確認 FortiGuard Web Filter 授權**。類別（`catdesc`）由 FortiGuard 評等，沒有授權時網站照樣會記，類別會是空的或 Unrated。GUI 的 System → FortiGuard 看 Web Filtering 那一列【待查，場域的授權狀態與韌體版本】。
2. **建一個「全部監看、只擋緊急類別」的 webfilter profile**。GUI：Security Profiles → Web Filter → 新增 `aup-monitor`，FortiGuard Category Based Filter 全部設為 Monitor，再把 Security Risk 底下的 Malicious Websites、Phishing、Spam URLs 設為 Block。Monitor 會為每個放行的連線寫一筆 `eventtype="ftgd_allow" action="passthrough"`，這就是 AUP 要的紀錄。CLI 的等價寫法要列出每個類別，長度不適合放這裡，以 GUI 設完後 `show webfilter profile aup-monitor` 匯出留存。類別代碼以設備上的 `get webfilter categories` 為準【待查】。
3. **掛到 policy 1**。

```
config firewall policy
    edit 1
        set utm-status enable
        set ssl-ssh-profile "certificate-inspection"
        set webfilter-profile "aup-monitor"
        set logtraffic utm
    next
end
```

`certificate-inspection` 看的是 TLS 握手的 SNI 與憑證，不解密，所以 HTTPS 只有 `hostname`，`url` 會是 `/`。這是刻意的。AUP 要的只到「去了哪個網站」這一層，「看了哪一頁」要深度檢查，那需要另外的授權、憑證部署與政策決定。`logtraffic utm` 維持 Day 22 的設定，traffic 日誌只記有 UTM 事件的連線，量不會因為今天的變更暴增。

syslogd2 的 filter 不用改。webfilter 屬於 UTM 日誌，Day 22 的 free-style 排除的是 `event` 與 traffic 裡的 NTP，沒有碰 UTM。Day 22 文末寫「要多 include 一條 webfilter」是當時的推測，實際上只要防火牆有產生，收集端就會收到。驗證：

```
_time:1h hostname:=fgt-edge "subtype=\"webfilter\"" | stats count()
```

## LogsQL

`hostname` 在這裡有兩個：rfc5424 標頭的 `hostname` 是設備名稱（`fgt-edge`），webfilter 那一行裡的 `hostname` 是網站。`unpack_logfmt` 之後後者會蓋掉前者，所以先 `rename hostname as fgt` 再拆。欄位在 `unpack_logfmt` 之後才存在，第一段只能用原文關鍵字篩（Day 22 的教訓）。

```
# 依工作站列網站，7 天
_time:7d hostname:=fgt-edge "type=\"utm\"" "subtype=\"webfilter\""
  | rename hostname as fgt
  | unpack_logfmt from _msg fields (srcip, srcname, user, hostname, dstip, catdesc, action)
  | stats by (srcip, hostname, catdesc) count() as n
  | sort by (srcip, n desc) | limit 500

# 依類別，放行與擋下分開數
_time:7d hostname:=fgt-edge "type=\"utm\"" "subtype=\"webfilter\""
  | rename hostname as fgt
  | unpack_logfmt from _msg fields (catdesc, action)
  | stats by (catdesc, action) count() as n | sort by (n) desc

# 被擋的，依工作站
_time:7d hostname:=fgt-edge "subtype=\"webfilter\"" "action=\"blocked\""
  | rename hostname as fgt
  | unpack_logfmt from _msg fields (srcip, srcname, hostname, catdesc, action)
  | filter action:=blocked
  | stats by (srcip, srcname, hostname, catdesc) count() as n | sort by (n) desc | limit 50

# 緊急類別，逐筆
_time:7d hostname:=fgt-edge "subtype=\"webfilter\""
  | rename hostname as fgt
  | unpack_logfmt from _msg fields (srcip, srcname, hostname, url, catdesc, action)
  | filter catdesc:in("Malicious Websites", "Phishing", "Spam URLs")
  | sort by (_time) desc | limit 50

# 一台工作站一天去了哪（稽核抽查的那種問題）
_time:[2026-10-06T00:00:00+08:00, 2026-10-07T00:00:00+08:00) hostname:=fgt-edge "subtype=\"webfilter\"" "srcip=192.168.2.23"
  | rename hostname as fgt
  | unpack_logfmt from _msg fields (srcip, hostname, catdesc, action)
  | filter srcip:=192.168.2.23
  | stats by (hostname, catdesc, action) count() as n | sort by (n) desc

# 每小時幾筆，看一天的形狀
_time:7d hostname:=fgt-edge "subtype=\"webfilter\"" | stats by (_time:1h) count() as n
```

串流欄位維持 Day 21 的 `(hostname, app_name)`。不要把 `srcip` 或 `hostname`（網站）加進串流欄位，每台工作站乘每個網站會把串流數撐到幾千個，VictoriaLogs 的壓縮與查詢都會變差，而且不需要，`unpack_logfmt` 之後 `stats by` 就夠。

## 報告與告警

`aup-report.py` 把上面的查詢做成四張表（依工作站列網站、依類別、被擋的依工作站、緊急類別命中），每週一 08:25 一份 Markdown 到 `/srv/reports/`，每 10 分鐘一次 1 小時視窗寫 `aup.prom`。規則在 onprem-metrics 的 `prometheus/rules/aup.yml`（本目錄有一份複本 `rules-aup.yml`）：緊急類別一筆就 critical，單一工作站一小時被擋 20 次 warning，預期有紀錄的 FortiGate 6 小時零筆 info，報告過期 warning 並抑制其餘。Gambling 這類不響，進週報。

## 同一份檔案兩邊跑

`aup-compare.sh export.log` 起一個暫時的 VictoriaLogs，把匯出檔以 `fortigate-export-load.py` 灌進去（`_time` 取 `eventtime`，`hostname` 取 `devname`，與線上的存法相同），對它跑一次 `aup-report.py`，再對檔案跑一次 `--from-file`，`diff` 兩份報告的表格。差異只會來自三個地方：時區（線上是 `_time`，離線是 `eventtime` 或 `tz`，兩者都是絕對時間，不該差）、沒有時間的行（線上不能存、離線會計，`tests/smoke-aup.sh` 刻意放了一行驗這點）、`url` 的正規化（兩邊都不用 `url` 決定網站，所以也不該差）。viewer 是第三個讀法，它的「用戶存取網站列表」用眼睛對 `online.md` 的「依工作站列網站」。

匯出檔不要灌進生產的收集端，那些小時的紀錄會被算兩次。`fortigate-export-load.py` 在每一行加 `source="export"` 就是為了萬一灌錯時還分得出來。

## 隱私與保存

webfilter 日誌是個資，記的是「哪台工作站什麼時候去了哪裡」。目前的狀態：

- 熱層 90 天，與其他日誌相同。VictoriaLogs 的保留期是整個實例一個值，要給 webfilter 較短的期限得另開一個實例，或接受 90 天【待決定，依場域的個資保存程序】。
- 不進 WORM。Day 22 的 `ARCHIVE_SKIP=syslog-fgt-edge` 排除的是整台 FortiGate 的 syslog 來源，webfilter 跟 traffic 同一個來源，一起被排除。要封存時另開只送 webfilter 的目的地，與 Day 27 的 event 做法相同【待決定】。
- 誰能看：收集端的 Grafana 與 `/srv/reports/`，目前是維運帳號。AUP 的查詢是依請求、有目的的抽查，查詢本身要留紀錄（Day 27）。
- 匯出檔：看完刪，不留在工作站。viewer 不上傳、不存瀏覽器儲存，反查 DNS 要按才會啟動且不送內網位址，這三點是給離線這條線設的最低標準。

ISO 27701 的角度一句話，紀錄最小化（只記網站不記頁面）與目的限制（AUP 稽核，不做其他用途），兩者都要寫進政策，程式只是讓政策比較容易守。
