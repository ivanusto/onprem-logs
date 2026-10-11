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
    end
end
```

兩件事在 Day 22 學過，這裡照用。第一，開關式的 filter 只管 traffic 那幾類，UTM 日誌（webfilter 等）沒有開關，要用 free-style 排除，每個 category 只能有一條。這台現在只產生 webfilter 一種 UTM 日誌（Day 24），所以排除一條就夠。之後若開了其他 UTM 功能，這裡要跟著加。第二，`severity` 要是 `information`，設定變更事件的 level 是 information，設成 notice 就一筆都收不到。

驗證，收集端上：

```
_time:1h audit:=fortigate | unpack_logfmt from _msg fields (type, subtype) | stats by (type, subtype) count()
```

應該只有 `event` 的 `system`、`user`（以及開了的其他事件子類型）。有任何 `traffic` 或 `utm` 出現，就是 filter 漏了【待填，場域第一個小時的結果】。

## 哪些事件是稽核軌跡

| 事件 | logid | 欄位 |
|---|---|---|
| 設定變更 | `0100044546` Attribute configured、`0100044547` Object configured 等（待查 7.6.7 實際出現的 logid） | `user`、`ui`（哪個介面、哪個位址）、`action`、`cfgpath`、`cfgobj`、`cfgattr`（舊值到新值）、`cfgtid`（同一次交易的編號） |
| 管理員登入 | `0100032001` 成功、`0100032002` 失敗、`0100032003` 登出（待查） | `user`、`ui`、`status`、`reason` |
| 系統 | 重開機、韌體升級、HA 狀態 | `logdesc`、`msg` |

`audit-report.py` 用的是 `cfgpath` 存在與否來認設定變更，不依賴 logid，logid 只用在登入那一組。第一週收到的 logid 清單要回頭核對這張表【待填】。

## 進 WORM 的量

事件日誌的量與 traffic 差好幾個量級。這台一天的設定變更與登入通常在百筆以內，一年不到 1 MB。`archive-day.sh` 自動發現 `audit` 來源，`MANIFEST.tsv` 多一列 `audit-fgt-edge`，`verify-archive.sh` 用同樣的「行數等於查詢筆數」對帳。retention.md 的三層表因此多一列。
