# 日誌保存政策

三個地方，三種期限，各自回答一個問題。

| 層 | 在哪 | 期限 | 回答的問題 | 誰能刪 |
|---|---|---|---|---|
| 來源 | 各節點 journald（`Storage=persistent`，`SystemMaxUse=2G`）、NAS 的 QuLog Center | 到容量上限為止 | 收集端斷線期間的日誌還在嗎 | 節點 root |
| 熱 | 收集端 VictoriaLogs，`-retentionPeriod=90d`，`-retention.maxDiskSpaceUsageBytes=12GiB` | 90 天，與 Prometheus 一致 | 告警那一刻前後發生了什麼 | 收集端 root，到期自動 |
| 封存 | QuTS hero WORM 共用資料夾，每日一目錄，`archive-day.sh` | 待確認，預設 400 天 | 一年前某天的紀錄能不能拿出來且證明沒改過 | 沒有人，到期由 WORM 保留期釋放 |

## 數字的來源

90 天沿用 Day 19 的 Prometheus 保留期，同一段時間裡指標與日誌都查得到，Day 20 的告警註記才能跳到日誌。12 GiB 是收集端 32 GiB 磁碟扣掉 Prometheus 的 3.6 GiB 與系統之後的保守值，容量上限先於天數上限觸發時 VictoriaLogs 會刪最舊的分割，不會停止寫入。400 天是「一年加一個季度的稽核窗口」，ISO 27001 本身不規定天數，由組織的紀錄保存程序定，這一格請以場域的程序為準。

## WORM 共用資料夾的設定

QuTS hero 建共用資料夾時勾 WORM，類型 Enterprise，保留期與上表一致。觸發方式選「寫入後自動鎖定」並給一個短的等待時間（待確認選項名稱與最小值），`archive-day.sh` 在那段時間內完成寫檔與改名，之後任何修改與刪除都被拒。Day 16 在 HDP 的 WORM 資料夾上實測過 root 的 rm、mv、chmod、touch 全部 Operation not permitted，這裡是同一個機制。

收集端以 NFS 唯寫掛載這個共用資料夾到 `/mnt/worm`，Day 13 的掛載選項，加 `noexec,nosuid`。

## 每天的流程

```
02:10  cron  archive-day.sh            # 昨天 UTC 的日誌，每台主機一個檔，MANIFEST.tsv 與 SHA256SUMS
02:20  cron  verify-archive.sh --against-live   # 立刻驗一次，結果進 drills.jsonl 的 logs 來源
每季   人工  verify-archive.sh <一年前的某天>    # 不帶 --against-live，只驗檔案，這是 Day 28 的演練項目之一
```

MANIFEST 的 `lines` 與 `hits` 相等是完整性的證據，檔案的 sha256 在 SHA256SUMS 裡，SHA256SUMS 自己在 WORM 上。三者合起來回答稽核的兩個問題，當天收到的全部都在，寫進去之後沒有人動過。

## 不在這份政策裡的

Prometheus 的指標保留在 Day 19。HDP 備份的保留在 Day 16。NAS 快照在 Day 17。這份只管日誌。
