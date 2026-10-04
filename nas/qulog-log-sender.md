# QuLog Center 的記錄傳送端送到 VictoriaLogs

NAS 上不裝任何東西。QuLog Center（QuTS hero 6.0.2 上為 3.0.1.1061）的「記錄傳送端」把事件記錄與存取記錄以 syslog 送出，收集端的 VictoriaLogs 以 `-syslog.listenAddr.tcp=:514` 接。

## 設定（兩台 NAS 各做一次）

1. QuLog Center → QuLog 服務 → 記錄傳送端 → 「傳送到 Syslog 伺服器」分頁（另一個分頁「傳送到 QuLog Center」是送給另一台 QNAP，不是這裡）。
2. 打開上方的總開關「傳送記錄到遠端 Syslog 伺服器」。**每列自己的開關是綠的不代表會送**，總開關關著時什麼都不出去；實測一台 NAS 的總開關預設是關的。
3. 新增目的地：主機名稱/IP 位址填收集端，埠號 514，傳輸通訊協定 TCP，記錄類型「事件記錄與存取記錄」。
4. 格式不能選，跟著協定走：TCP 與 UDP 是 **RFC-3164**，TLS（預設埠 6514）是 **RFC-5424**。「傳送測試訊息」按鈕只有選 TLS 時才出現。
5. 套用後，從任何一台機器 SSH 登入 NAS 一次，就會產生一筆存取記錄，到收集端查：

```sh
curl -s http://127.0.0.1:9428/select/logsql/query -d 'query=_time:5m hostname:* | sort by (_time) desc | limit 5'
```

## 收到的樣子

```
{"_time":"2026-10-04T14:26:13Z","hostname":"nas-primary","app_name":"qulogd","format":"rfc3164",
 "_msg":"conn log: Users: ops, Source IP: 192.168.2.131, Computer name: ---, Connection type: SSH/SFTP, Accessed resources: ---, Action: Login Success"}
```

- `app_name` 是 `qulogd`，事件記錄與存取記錄都是，用訊息開頭區分：存取記錄是 `conn log:`，事件記錄是 `event log:`。
- RFC-3164 沒有結構化欄位，使用者、來源 IP、動作都在 `_msg` 裡，要用 `extract` 取出：
  `hostname:nas-primary "conn log:" | extract "Users: <user>, Source IP: <ip>," | stats by (user, ip) count()`
- TLS 的 RFC-5424 會多出 `QuLog@Event.user`、`QuLog@Event.ip` 這類結構化欄位（測試訊息實測），`app_name` 變成 `qulogd:`（多一個冒號），兩種格式混用時篩選要寫 `app_name:qulogd`（字詞比對），不要寫 `app_name:=qulogd`。

## 時區

RFC-3164 的時間戳沒有時區，QuLog 送的是 NAS 的本地時間（Asia/Taipei）。compose 的 `-syslog.timezone=Asia/Taipei` 因此是必要的：不設時，VictoriaLogs 的預設是 `Local`，在 FROM scratch 的容器裡就是 UTC，每一筆會晚 8 小時。實測一次 SSH 登入發生在 14:26:13.37 UTC，`_time` 是 `14:26:13Z`，秒以下被 RFC-3164 截掉。NAS 與收集端的時鐘差在 1 秒內（兩邊都對時）。

## 不走 TLS 的理由與條件

QuLog 支援 TLS（RFC-5424、預設埠 6514），VictoriaLogs 也能收（`-syslog.tls`、`-syslog.tlsCertFile`、`-syslog.tlsKeyFile`）。目前走明文 TCP，條件是收集端與 NAS 在同一個管理網段，收集端的 DOCKER-USER 白名單只讓兩台 NAS 進 514（見 `collector/docker-user-allowlist.sh`）。要改 TLS 時，憑證用 Day 11 同一套，並把 queries.md 裡依 `_msg` 取欄位的查詢改成直接用結構化欄位。

## 保留哪一邊

QuLog 本機的記錄照它自己的設定保留，當 NAS 上的檢視介面。可稽核的那一份在收集端與 WORM 封存，見 retention.md。兩邊同一筆事件時間一致是 Day 27 要抽查的項目之一。

## 已知的雜訊

收集端 Day 19 的 `nas-textfile.sh` 每分鐘以 SSH 登入兩台 NAS 一次，每次都是一筆 `conn log ... Login Success`，每台每天約 1,440 筆。查登入異常時先排除 `Source IP: 192.168.2.49`。
