# 從告警跳到日誌，常用 LogsQL

Grafana 的 Explore 選 VictoriaLogs 資料源，貼查詢，時間範圍對準告警的 `startsAt` 前後 10 分鐘。欄位名稱來自本機實測的解析結果，journald 來的是大寫底線欄位（`_HOSTNAME`、`_SYSTEMD_UNIT`、`PRIORITY`），syslog 來的是小寫（`hostname`、`app_name`、`severity`）。

| Day 20 的告警 | 查什麼 | LogsQL |
|---|---|---|
| `Gb10SoakNearBudget`、`Gb10HotFlag` | 守護程式與硬體取樣器在那段時間說了什麼 | `_HOSTNAME:spark01 _SYSTEMD_UNIT:in("gb10-host-guard.service","gb10-textfile.service")` |
| `Gb10NvErrNoMemory` | 核心訊息原文與前後的程序 | `_HOSTNAME:spark01 (NV_ERR_NO_MEMORY OR _SYSTEMD_UNIT:kernel OR _TRANSPORT:kernel)` |
| `PveQuorumLost`、`PveVoteMissing` | corosync 的成員變化 | `_SYSTEMD_UNIT:corosync.service (membership OR quorum OR "Sync members")` |
| `PveHaResourceError` | HA 狀態機的每一步 | `_SYSTEMD_UNIT:in("pve-ha-lrm.service","pve-ha-crm.service") "status change"` |
| `PveStorageUnavailable` | NFS 客戶端的逾時 | `_HOSTNAME:in("pve1","pve2") ("nfs: server" OR "not responding" OR "OK")` |
| `NasPoolNotOnline`、`NasDiskNotGood` | NAS 自己怎麼說 | `hostname:nas-primary (zfs OR pool OR disk OR SMART)` |
| `NasTelnetEnabled`、Day 11 回歸 | 誰改了設定 | `hostname:in("nas-primary","nas-secondary") app_name:qulogd ("Setting" OR "enabled" OR "disabled")` |
| 任何 critical | 那 10 分鐘裡所有 error 以上 | `level:in("error","critical","alert","emergency")` |

幾個統計，給 Day 22 與 Day 27 用。

```
# 每台主機每天的筆數，與 MANIFEST 的 hits 對帳
_time:1d | stats by (_HOSTNAME, hostname) count()

# sshd 登入失敗，依來源 IP
_SYSTEMD_UNIT:ssh.service "Failed password" | extract "from <ip> port" | stats by (ip) count() as n | sort by (n) desc

# 守護程式動手的次數，依節點
_SYSTEMD_UNIT:gb10-host-guard.service "killing" | stats by (_HOSTNAME) count()

# 每個單元的日誌量，找出噪音來源
_time:1h | stats by (_SYSTEMD_UNIT) count() as n | sort by (n) desc | limit 20
```

訊息內容的關鍵字（`membership`、`status change`、`Failed password`）依實際日誌校正，第一週每條查一次把空結果的改掉。
