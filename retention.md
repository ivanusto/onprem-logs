# 日誌保存政策

三個地方，三種期限，各自回答一個問題。

| 層 | 在哪 | 期限 | 回答的問題 | 誰能刪 |
|---|---|---|---|---|
| 來源 | 各節點 journald（持久化，`/var/log/journal`）、NAS 的 QuLog Center | 到容量上限為止（journald 預設為檔案系統的 10 %，上限 4 GiB） | 收集端斷線期間的日誌還在嗎 | 節點 root |
| 熱 | 收集端 VictoriaLogs，`-retentionPeriod=90d`，`-retention.maxDiskSpaceUsageBytes=12GiB` | 90 天，與 Prometheus 一致 | 告警那一刻前後發生了什麼 | 收集端 root，到期自動 |
| 封存 | QuTS hero WORM 共用資料夾 `LogArchive`，每日一目錄，`archive-day.sh` | **暫定 180 天，待確認** | 半年前某天的紀錄能不能拿出來且證明沒改過 | 沒有人，到期由 WORM 保留期釋放 |

## 數字的來源

90 天沿用 Day 19 的 Prometheus 保留期，同一段時間裡指標與日誌都查得到，Day 20 的告警註記才能跳到日誌。VictoriaLogs 收到早於保留期的資料會直接丟棄（`vl_rows_dropped_total{reason="too_small_timestamp"}`），所以節點第一次上傳整份 journal 時，90 天以前的部分不會佔空間。

12 GiB 是收集端 32 GiB 磁碟扣掉 Prometheus 與系統之後的保守值。容量上限先於天數上限觸發時，VictoriaLogs 會刪最舊的分割，不會停止寫入。哪一個先到要看場域的日量，算法與實測值見 Day 21 文章第四節。

封存的 180 天是暫定值，參照 ISO 27001 稽核實務的一般要求（標準本身不規定天數），**請依場域的紀錄保存程序定**。WORM 的保留期建立後只能延長，不能縮短，所以先取較短的值，確認後再延長。

## WORM 共用資料夾的設定

在 QuTS hero 6.0.2 的「儲存空間總管 → 建立 → 共用資料夾 → 進階設定 → 安全性設定」：

| 欄位 | 值 | 說明 |
|---|---|---|
| WORM (一寫多讀) | 啟用 | 建立後就無法停用或修改 WORM 屬性與類型 |
| 模式 | 企業等級 | 可經「安全刪除」流程移除整個資料夾；法規等級連資料夾都不能移除，只能刪整個儲存池 |
| 鎖定設定 | 在這段時間後自動鎖定：0 小時 10 分鐘 | 另一個選項是「手動鎖定 (設定檔案權限為唯讀)」。延遲最短 1 分鐘、最長 168 小時 59 分，誤差 ±1 分鐘，期間內再修改會重新計時，建立後不能改 |
| 設定保留期間 | 啟用，180 天 | 不啟用時檔案鎖定後沒有到期日 |

NFS 主機存取只給收集端，讀取/寫入，Squash 所有使用者，匿名 UID/GID 對到 NAS 上一個對此資料夾有寫入權的帳號，收集端以哪個 uid 寫都一樣。收集端以 `collector/mnt-worm.mount` 掛到 `/mnt/worm`（`noexec,nosuid,nodev`）。

### 鎖定延遲與封存腳本

鎖定延遲內檔案還能改、能刪（場域實測：寫入後立刻 `rm` 成功）；過了延遲，任何人都改不了、刪不掉，包括寫壞的半成品。所以 `archive-day.sh` 先在收集端本機的 `$STAGE` 匯出、壓縮、對帳、算 sha256，全部相符才一次複製到 WORM，順序是資料檔、`MANIFEST.tsv`、最後 `SHA256SUMS`。`SHA256SUMS` 存在就代表那一天完整；有檔案但沒有 `SHA256SUMS` 代表複製中斷，腳本拒絕再寫並以 4 結束，交由人工記錄缺口。

10 分鐘的延遲對這個流程是寬裕的：場域一天 4 個來源、約 33 萬行、18 MB，從匯出到複製完成 14 秒，複製本身不到 1 秒。

## 每天的流程

收集端時區是 Asia/Taipei，cron 用本地時間。

```
08:10  cron  archive-day.sh                      # 00:10 UTC，剛結束的那個 UTC 日，每台主機一個檔
08:20  cron  verify-archive.sh --against-live    # 立刻驗一次，結果寫進 drills.jsonl 的 logs 來源
每季   人工  verify-archive.sh <半年內的某天>      # 不帶 --against-live，只驗檔案，這是 Day 28 的演練項目之一
```

驗證結果以 `DRILLS=/srv/drills/onprem-logs/drills.jsonl` 寫一行，onprem-metrics 的 `drills-textfile.py` 讀成 `drill_last_result{source="logs"}`，Day 20 的 `DrillFailed` 因此也涵蓋封存。

MANIFEST 的 `lines` 與 `hits` 相等是完整性的證據，檔案的 sha256 在 SHA256SUMS 裡，SHA256SUMS 自己在 WORM 上。三者合起來回答稽核的兩個問題，當天收到的全部都在，寫進去之後沒有人動過。

## 不在這份政策裡的

Prometheus 的指標保留在 Day 19。HDP 備份的保留在 Day 16。NAS 快照在 Day 17。這份只管日誌。

## 不進封存的來源（Day 22）

邊界 FortiGate 的 traffic 日誌只留熱層 90 天，不進 WORM，用 `archive-day.sh` 的 `ARCHIVE_SKIP=syslog-<設備名稱>` 排除。理由有三：內容幾乎都是攝影機外連被 policy 4 擋下的重複紀錄，稽核價值低；含 MAC 與內網的連線行為，屬於應該最小化保存的資料；WORM 一旦寫入就無法撤回。被排除的來源不會無聲消失，`MANIFEST.tsv` 會多一行 `# skipped<TAB>syslog-<設備名稱><TAB><當天筆數><TAB>ARCHIVE_SKIP`，稽核時看得出那一天收到多少、是依政策刻意不封存，`verify-archive.sh` 會列出但不檢查這一行。

FortiGate 真正適合進封存的是設定變更事件（`type="event" subtype="system"`，例如 logid `0100044546`「Attribute configured」），那是 Day 27 稽核軌跡的材料；目前 syslogd2 的 filter 排除了 event，要封存時另開一個只送這些事件的目的地。
