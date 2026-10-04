# 從告警跳到日誌，常用 LogsQL

Grafana 的 Explore 選 VictoriaLogs 資料源，貼查詢，時間範圍對準告警的 `startsAt` 前後 10 分鐘。主機名稱以 spark01、spark02、pve1、pve2、nas-primary、nas-secondary 代表，換成場域實際的 `hostname`。

欄位名稱來自場域實際收到的資料：journald 來的是大寫底線欄位（`_HOSTNAME`、`_SYSTEMD_UNIT`、`_TRANSPORT`、`PRIORITY`），syslog 來的是小寫（`hostname`、`app_name`、`severity`），兩邊都有 `level`。

兩個容易查空的地方：

- **systemd 自己替某個服務說的話不在那個服務底下。** 「Started／Stopped／Failed with result」這類訊息的 `_SYSTEMD_UNIT` 是 `init.scope`，服務名稱在 `UNIT` 欄位。timer 觸發的 oneshot（例如 `gb10-textfile.service`）自己幾乎不印東西，查它的失敗要查 `UNIT:=`。
- **QuLog 走 TCP 是 RFC-3164，沒有結構化欄位。** 使用者、來源 IP、動作都在 `_msg` 裡，存取記錄以 `conn log:` 開頭，事件記錄以 `event log:` 開頭，要用 `extract` 取欄位。

| Day 20 的告警 | 查什麼 | LogsQL | 場域 90 天筆數 |
|---|---|---|---|
| `Gb10SoakNearBudget`、`Gb10HotFlag` | 守護程式的狀態變化，與取樣器的失敗 | `_HOSTNAME:spark01 (_SYSTEMD_UNIT:="gb10-host-guard.service" OR UNIT:="gb10-host-guard.service" OR (UNIT:="gb10-textfile.service" -level:=info))` | 102 |
| 守護程式動手 | 觸發、DRY_RUN 下的 would_kill、實際送出的訊號 | `_SYSTEMD_UNIT:="gb10-host-guard.service" (trigger OR would_kill OR sigterm OR sigkill OR kill_failed)` | 0（上線以來沒觸發過） |
| `Gb10NvErrNoMemory` | 核心訊息原文 | `_HOSTNAME:in("spark01","spark02") _TRANSPORT:=kernel (NV_ERR_NO_MEMORY OR NVRM OR Xid)` | 6,995 |
| `PveQuorumLost`、`PveVoteMissing` | corosync 的成員變化 | `_SYSTEMD_UNIT:corosync.service (membership OR quorum OR "Sync members")` | 292 |
| `PveHaResourceError` | HA 狀態機的每一步 | `_SYSTEMD_UNIT:in("pve-ha-lrm.service","pve-ha-crm.service") "status change"` | 68 |
| `PveStorageUnavailable` | NFS 客戶端的逾時與恢復 | `_HOSTNAME:in("pve1","pve2") _TRANSPORT:=kernel "nfs: server"` | 202 |
| `NasPoolNotOnline`、`NasDiskNotGood` | NAS 自己的事件記錄 | `hostname:in("nas-primary","nas-secondary") "event log:"` | 自 10/04 起 |
| `NasTelnetEnabled`、Day 11 回歸 | 誰改了服務設定 | `hostname:in("nas-primary","nas-secondary") "event log:" i("telnet")` | 0（待第一次真實變更校正） |
| 任何 critical | 那 10 分鐘裡所有 error 以上 | `level:in("error","critical","alert","emergency")` | 只在 10 分鐘窗口內有意義 |

幾個統計，給 Day 22 與 Day 27 用。

```
# 每台主機每天的筆數，與 MANIFEST 的 hits 對帳
_time:1d | stats by (_HOSTNAME, hostname) count()

# NAS 的登入，排除收集端自己每分鐘的 SSH（Day 19 的 nas-textfile.sh）
hostname:* "conn log:" -"Source IP: 192.168.2.49" | extract "Users: <user>, Source IP: <ip>," | stats by (hostname, user, ip) count()

# sshd 登入失敗，依來源 IP
_SYSTEMD_UNIT:ssh.service "Failed password" | extract "from <ip> port" | stats by (ip) count() as n | sort by (n) desc

# 每個單元的日誌量，找出噪音來源（systemd 替別人說話的部分用 UNIT 分）
_time:1h | stats by (_HOSTNAME, _SYSTEMD_UNIT, UNIT) count() as n | sort by (n) desc | limit 20
```

訊息內容的關鍵字（`membership`、`status change`、`Failed password`）是依場域資料核對過的，沒有實際事件可核對的兩列已標明，第一次真的發生時再校正。
