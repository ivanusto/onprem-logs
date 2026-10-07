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
| 工作站 | `user`，沒有就 `srcname`，再沒有就 `srcip`。這個場域沒有使用者認證，`user` 是空的；`srcname` 來自裝置偵測，FortiOS 7.6.7 只把它寫進 traffic 行，webfilter 行沒有，所以實際上是 `srcip`。viewer 依 `user` 或 `srcip` 分組，`srcname` 顯示在旁邊 |
| 網站 | `hostname`，沒有就 `dstip`。`url` 刻意不用來決定網站，`url="/"` 與完整 URL 不該變成兩個網站 |
| 類別 | `catdesc`，空的算 `Unrated`。沒有 FortiGuard 授權時每一筆都是這一格 |
| 擋下 | `action` 是 deny、block、blocked、dropped、reject、drop。webfilter 的放行是 `passthrough` |
| 時間 | 線上是 rfc5424 標頭的 `_time`。離線先用 `eventtime`（7.x 是奈秒），沒有就 `date`+`time`+`tz` |

## FortiGate 那一端

場域前面是 FortiGate 60F，自己管，Day 22 已把 syslogd2 接到收集端（rfc5424、TCP 514、只送 traffic 的 forward 與 local、排除 event 與 NTP）。Day 22 收到的只有 traffic，一筆 webfilter 都沒有，原因是 `policy 1`（內部到外部）沒有掛網頁過濾 profile，防火牆根本沒有產生 webfilter 日誌，與 syslog 的 filter 無關。要有紀錄，先讓防火牆記。

三件事，都是變更，照 Day 26 的變更單走。

1. **確認 FortiGuard Web Filter 授權**。類別（`catdesc`）由 FortiGuard 評等。GUI 的 System → FortiGuard 看 Web Filtering 那一列，或 `GET /api/v2/monitor/license/status` 的 `web_filtering`。場域是 FortiOS 7.6.7，授權已過期：每一個連線都寫一筆 `eventtype="ftgd_err" level="error" msg="A rating error occurs"`，沒有 `catdesc`。這時 profile 一定要有 `set options error-allow`，評等失敗才會放行（`action="passthrough"`），否則評等失敗的網站會被擋，整個網段等於斷網。有授權的場域照樣建議開，FortiGuard 連不上時也是同樣的情況。
2. **建一個「全部監看、只擋緊急類別」的 webfilter profile**。GUI：Security Profiles → Web Filter → 新增 `aup-monitor`，FortiGuard Category Based Filter 全部設為 Monitor，再把 Security Risk 底下的 Malicious Websites（26）、Phishing（61）、Spam URLs（86）設為 Block。Monitor 會為每個放行的連線寫一筆 `eventtype="ftgd_allow" action="passthrough"`（沒有授權時是 `ftgd_err`），這就是 AUP 要的紀錄。CLI 裡 monitor 是每個類別的預設動作，所以每一筆只有 `set category N`，block 的三筆多一行 `set action block`；類別代碼以設備上的清單為準（`GET /api/v2/monitor/webfilter/fortiguard-categories`，7.6.7 有 93 個含 Unrated）。設完以 `show webfilter profile aup-monitor` 留存。
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

`certificate-inspection` 看的是 TLS 握手的 SNI 與憑證，不解密，所以 HTTPS 只有主機名稱，`url` 是 `https://<hostname>/`，沒有路徑。這是刻意的。AUP 要的只到「去了哪個網站」這一層，「看了哪一頁」要深度檢查，那需要另外的授權、憑證部署與政策決定。

掛上之前看一下 `certificate-inspection` 的內容。`utm-status` 打開的那一刻它才開始生效，而 7.6.7 的預設會擋過期、撤銷、驗證失敗的伺服器憑證、低於 TLS 1.1 的連線與帶 ECH 的 Client Hello。這是收緊，不是只看，對整個網段生效，要一起寫進變更單。

靜態 URL filter（`config webfilter urlfilter`）在 flow 模式加 certificate-inspection 下只對 HTTP 生效。場域以一個測試網域驗證，HTTP 寫 `eventtype="urlfilter" action="blocked"`，同一個網域走 HTTPS 只有一筆評等紀錄、照樣放行。要擋 HTTPS 的特定網站，用 FortiGuard 類別或 DNS filter。

`logtraffic` 設回 `utm`。場域在 Day 22 時是 `utm`，Day 24 之前曾為了別的觀察改成 `all`（FortiGate 日誌一小時約 1.5 萬筆）。`utm` 只記有 UTM 事件的連線，但掛上全部監看的 profile 之後，每一個網頁連線都有 webfilter 事件，traffic 也跟著記一筆 `utmaction="allow"`。

場域實測（2026-10-08，21 台工作站，00:14:40 掛上後第一個小時）：FortiGate 共 15,281 筆，webfilter 5,415（HTTP 2,638、HTTPS 2,777），traffic 9,840（其中 5,217 筆帶 `utmaction="allow"`；其餘是 policy 4、本機與隱含拒絕這些原本就記的紀錄，以及長連線的中途紀錄 `logid="0000000020"`）。穩態約每小時 1 萬筆，Day 22 同時段約 1,100 筆，大約九倍。單一台 Firefox 的連線偵測（HTTP，每次一筆）就佔了第一小時的四成。收集端的容量照 Day 21 的算法重估，告警門檻（`FwSourceBurst` 只看 deny）不受影響。

syslogd2 的 filter 不用改。webfilter 屬於 UTM 日誌，Day 22 的 free-style 排除的是 `event` 與 traffic 裡的 NTP，沒有碰 UTM。Day 22 文末寫「要多 include 一條 webfilter」是當時的推測，場域實測掛上 profile 之後 5 秒就產生第一筆，兩分鐘後在收集端查得到 98 筆。webfilter 的 `level` 是 `error`（評等失敗）或 `warning`（擋下），filter 的 `severity information` 都會放行。驗證：

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

匯出檔的來源：GUI 的 Log & Report 下載，或 REST 的 `GET /api/v2/log/memory/webfilter/raw`（回應標頭的檔名與 GUI 相同，`memory-webfilter-<日期>_<時分>.log`）。60F 沒有本機磁碟，日誌在記憶體的環狀緩衝裡，場域在每小時約 5 千筆 webfilter 的量下只留得住最後約 2,100 行、30 分鐘。這種匯出檔的每一行都沒有 `devname` 與 `devid`，`fortigate-export-load.py` 與 `aup-report.py --from-file` 都以 `--devname`（預設 `FortiGate`，與 viewer 相同）補上同一個名字。

`aup-compare.sh export.log` 起一個暫時的 VictoriaLogs，把匯出檔以 `fortigate-export-load.py` 灌進去（`_time` 取 `eventtime`，`hostname` 取 `devname`，與線上的存法相同），對它跑一次 `aup-report.py`，再對檔案跑一次 `--from-file`，`diff` 兩份報告的表格。差異只會來自三個地方：時區（線上是 `_time`，離線是 `eventtime` 或 `tz`，兩者都是絕對時間，不該差）、沒有時間的行（線上不能存、離線會計，`tests/smoke-aup.sh` 刻意放了一行驗這點）、`url` 的正規化（兩邊都不用 `url` 決定網站，所以也不該差）。viewer 是第三個讀法，它的「用戶存取網站列表」切到「按用戶分組」，逐台對 `online.md` 的「依工作站列網站」。

拿匯出檔對生產收集端的時候還有第四個來源：生產收集端的 `_time` 是 rfc5424 標頭的時間，只到秒，而且比 `eventtime` 早不到一秒。用匯出檔的 `eventtime` 範圍去查收集端，邊界上會少幾筆；前後各放寬兩秒，再以 `sessionid` 加 `eventtime` 逐筆對。場域 2,160 行全部在收集端找到。

匯出檔不要灌進生產的收集端，那些小時的紀錄會被算兩次。`fortigate-export-load.py` 在每一行加 `source="export"` 就是為了萬一灌錯時還分得出來。

## 隱私與保存

webfilter 日誌是個資，記的是「哪台工作站什麼時候去了哪裡」。目前的狀態：

- 熱層 90 天，與其他日誌相同。VictoriaLogs 的保留期是整個實例一個值，要給 webfilter 較短的期限得另開一個實例，或接受 90 天【待決定，依場域的個資保存程序】。
- 不進 WORM。Day 22 的 `ARCHIVE_SKIP=syslog-fgt-edge` 排除的是整台 FortiGate 的 syslog 來源，webfilter 跟 traffic 同一個來源，一起被排除。要封存時另開只送 webfilter 的目的地，與 Day 27 的 event 做法相同【待決定】。
- 誰能看：收集端的 Grafana 與 `/srv/reports/`，目前是維運帳號。AUP 的查詢是依請求、有目的的抽查，查詢本身要留紀錄（Day 27）。
- 匯出檔：看完刪，不留在工作站。viewer 不上傳、不存瀏覽器儲存，反查 DNS 要按才會啟動且不送內網位址，這三點是給離線這條線設的最低標準。

ISO 27701 的角度一句話，紀錄最小化（只記網站不記頁面）與目的限制（AUP 稽核，不做其他用途），兩者都要寫進政策，程式只是讓政策比較容易守。
