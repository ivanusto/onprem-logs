# QuLog Center 的 Log Sender 送到 VictoriaLogs

NAS 上不裝任何東西。QuLog Center（QTS 5.0 與 QuTS hero h5.0 以上內建）的 Log Sender 把系統事件與存取紀錄以 syslog 送出，收集端的 VictoriaLogs 以 `-syslog.listenAddr.tcp=:514` 接。

## 設定（兩台 NAS 各做一次）

1. QuLog Center → Log Sender → 新增目的地。
2. 伺服器 收集端 IP（192.168.2.49），協定 TCP，埠 514。
3. 格式選 RFC 5424 若介面有這個選項，沒有就用預設，VictoriaLogs 兩種都解析，`format` 欄位會寫明收到的是哪一種（待確認 QuTS hero 6 的介面選項）。
4. 要送的日誌勾 系統事件日誌 與 系統存取日誌。
5. 用「傳送測試訊息」送一筆，到收集端查。

```sh
curl -s http://127.0.0.1:9428/select/logsql/query -d 'query=hostname:nas-primary | sort by (_time) desc | limit 5'
```

## 解析出來的欄位

VictoriaLogs 把 syslog 拆成 `hostname`、`app_name`、`proc_id`、`facility`、`severity`、`level`、`_msg`，串流以 `(hostname, app_name)` 分。QuLog 的 `app_name` 是什麼值要看第一筆，依此寫 queries.md 的篩選。

## 時區

RFC 3164 的時間戳沒有時區，compose 以 `-syslog.timezone=Asia/Taipei` 解讀。若 QuLog 送的是 RFC 5424 帶時區，這個參數不影響。第一筆進來之後比對 `_time` 與 NAS 上的時間，差 8 小時就是格式與參數對不上。

## 不走 TLS 的理由與條件

QuLog Log Sender 是否支援 TLS 待查。目前走明文 TCP，條件是收集端與 NAS 在同一個管理 VLAN，收集端 ufw 只放兩台 NAS 的位址進 514。若 QuLog 支援 TLS，compose 加 `-syslog.tls=true -syslog.tlsCertFile -syslog.tlsKeyFile`，憑證用 Day 11 同一套。

## 保留哪一邊

QuLog 本機的日誌照它自己的設定保留，當 NAS 上的檢視介面。可稽核的那一份在收集端與 WORM 封存，見 retention.md。兩邊同一筆事件時間一致是 Day 27 要抽查的項目之一。
