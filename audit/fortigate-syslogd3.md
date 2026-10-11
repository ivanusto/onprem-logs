# FortiGate 的事件日誌：獨立來源，進 WORM（Day 27）

Day 22 把 60F 的 traffic 日誌接進收集端（syslogd2，514/tcp），並以 `ARCHIVE_SKIP` 讓它不進 WORM，理由是量大、稽核價值低、含內網的連線行為。當時留下一句，設定變更事件（`type="event"`，例如 logid `0100044546`「Attribute configured」）才是稽核軌跡的材料，Day 27 另開一個只送這類事件的目的地。今天開。

## 為什麼用第二個埠，第二個 filter 不夠

同一台 FortiGate 不論用哪個 syslogd 目的地，rfc5424 標頭的 `hostname` 都是 devname。收集端以 `hostname` 當封存的來源名稱，兩個目的地送到同一個埠就會混成同一個來源 `syslog-fgt-edge`，`ARCHIVE_SKIP` 一排除就連事件一起排除。所以事件走另一個埠 515，VictoriaLogs 的第二個監聽器在每一行加上 `audit="fortigate"`，串流欄位是 `(hostname, audit)`。封存腳本把帶 `audit` 欄的列當成自己的來源 `audit-fgt-edge`，`syslog-fgt-edge` 的查詢多一個 `-audit:*` 把它們排除。一行只會在一個檔裡，traffic 照舊不封存，事件天天進 WORM。

compose 的對應設定（一個監聽器一個值，依序）：

```
- -syslog.listenAddr.tcp=:514,:515
- -syslog.streamFields.tcp=["hostname","app_name"],["hostname","audit"]
- -syslog.extraFields.tcp={},{"audit":"fortigate"}
```

收集端的 DOCKER-USER 白名單多一個 `AUDIT_FROM`，只讓 FortiGate 進 515。

## FortiGate 這一端

先備份設定（`POST /api/v2/monitor/system/config/backup`，Day 22 的做法），寫變更單，再設 syslogd3。

```
config log syslogd3 setting
    set status enable
    set server "192.168.2.49"
    set mode reliable
    set port 515
    set format rfc5424
end
config log syslogd3 filter
    set severity information
    set forward-traffic disable
    set local-traffic disable
    set multicast-traffic disable
    set sniffer-traffic disable
    set ztna-traffic disable
    set http-transaction disable
    set anomaly disable
    set voip disable
    set forti-switch disable
    config free-style
        edit 1
            set category webfilter
            set filter "(type utm)"
            set filter-type exclude
        next
        edit 2
            set category event
            set filter "(subtype wireless)"
            set filter-type exclude
        next
    end
end
```

第二條 free-style 是實機加的。這台 60F 的事件日誌一天約 4,000 到 5,000 筆，86% 到 90% 是 wireless（AP 回報的 DHCP6 SOLICIT、Rogue AP、DHCP 交握），排除後一天約 500 筆。wireless 對稽核沒有用，又含終端的 MAC，所以在來源端就不送。

以 REST 設定時（`PUT /api/v2/cmdb/log.syslogd3/filter`，2026-10-11，FortiOS 7.6.7）有兩個現象。把所有開關放在同一個 PUT 裡，回應是 success，`forward-traffic` 讀回來卻仍是 enable，單獨再送一次才變 disable。`ztna-traffic` 單獨送 disable 也讀回 enable。這台沒有 ZTNA，實際收到的內容裡沒有任何 traffic（見下方驗證），所以以收到的內容為準。用 CLI 設定時同樣要讀回來確認。

兩件事在 Day 22 學過，這裡照用。第一，開關式的 filter 只管 traffic 那幾類，UTM 日誌（webfilter 等）沒有開關，要用 free-style 排除，每個 category 只能有一條。這台現在只產生 webfilter 一種 UTM 日誌（Day 24），所以排除一條就夠。之後若開了其他 UTM 功能，這裡要跟著加。第二，`severity` 要是 `information`，設定變更事件的 level 是 information，設成 notice 就一筆都收不到。

驗證，收集端上：

```
_time:1h audit:=fortigate | unpack_logfmt from _msg fields (type, subtype) | stats by (type, subtype) count()
```

應該只有 `event` 的 `system`、`user`（以及開了的其他事件子類型）。有任何 `traffic`、`utm` 或 `wireless` 出現，就是 filter 漏了。

場域的結果（2026-10-11 16:34:20 啟用，16:42:57 查）：收到 4 筆，全是 `event/system`，logid `0100022905`（syslogd3 啟用本身）、`0100044546`（syslogd3 setting 的變更）、`0100040704`、`0100026001`。60F 的記憶體日誌同一段時間是同樣的 4 筆 system，加上 7 筆 wireless，wireless 一筆都沒送出。

## 哪些事件是稽核軌跡

| 事件 | logid | 欄位 |
|---|---|---|
| 設定變更 | `0100044547` Object attribute configured（最常見）、`0100044546` Attribute configured、`0100044562`（讀取敏感表） | `user`、`ui`（哪個介面、哪個位址）、`action`、`cfgpath`、`cfgobj`、`cfgattr`（舊值到新值）、`cfgtid`（同一次交易的編號） |
| 管理員登入 | `0100032001` 成功、`0100032002` 失敗（level alert，`reason` 例如 `internal_error`）、`0100032003` 登出（`reason` 例如 `timeout`，帶 `duration`） | `user`、`ui`、`status`、`reason` |
| 管理員的其他動作 | `0100032095` 從 GUI 執行（例如下載設定）、`0100032096` 下載日誌、`0100032102` session 結束時的 Configuration changed | `user`、`ui`、`msg` |
| 系統 | 重開機、韌體升級、HA 狀態 | `logdesc`、`msg` |

`audit-report.py` 用的是 `cfgpath` 存在與否來認設定變更，不依賴 logid，logid 只用在登入那一組。上表是 60F 記憶體日誌 2026-10-03 到 10-11 實際出現過的 logid。

`ui` 記的是連線的來源位址。REST API 的變更記成 `ui="https(<工作站>)"`；經 tailnet 進來的管理連線，`ui` 是 NAS 的位址，因為 NAS 是 tailnet 的 subnet router，會做 SNAT。看到 NAS 的位址不代表是 NAS 自己改的。

登入失敗的 `user` 欄記的是對方送來的帳號字串，可能是打錯的密碼或 API token 的一部分（這台在 10/07 就有一筆）。報告與截圖對外前要看過這一欄。

## 進 WORM 的量

事件日誌的量與 traffic 差好幾個量級。排除 wireless 後，這台一天約 500 筆，其中 288 筆是每 5 分鐘一筆的 `0100040704` System performance statistics，174 筆是 `0100026001` DHCP Ack，設定變更與登入只佔個位數。以封存檔的格式壓縮後一天約 28 KB，一年約 10 MB。`archive-day.sh` 自動發現 `audit` 來源，`MANIFEST.tsv` 多一列 `audit-fgt-edge`，`verify-archive.sh` 用同樣的「行數等於查詢筆數」對帳。retention.md 的三層表因此多一列。
