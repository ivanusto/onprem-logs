# onprem-logs

小型地端 AI 機房的日誌集中與保存。兩台 DGX Spark 與兩台 Proxmox VE 節點用 systemd 自帶的 `systemd-journal-upload` 把 journal 送到收集端，兩台 QuTS hero NAS 用 QuLog Center 內建的 Log Sender 送 syslog，收集端一個 VictoriaLogs 容器接兩種來源。節點與 NAS 上不裝任何新代理。熱資料留 90 天，每天把前一天的日誌匯出成 JSONL 寫進 NAS 的 WORM 共用資料夾（保留期暫定 180 天，待確認），附逐檔 sha256 與「行數等於查詢筆數」的對帳清單。

| 路徑 | 跑在哪 | 做什麼 |
|---|---|---|
| `docker-compose.yml` | 收集端 VM | VictoriaLogs v1.52.0（釘 digest），journald 與 syslog 兩種接收器，90 天與 12 GiB 的保留上限，加入 onprem-metrics 的 compose 網路讓 Grafana 以 `victorialogs:9428` 連到 |
| `collector/docker-user-allowlist.sh`、`onprem-logs-allowlist.service` | 收集端 VM | 只讓節點進 9428、NAS 進 514。Docker 發佈的埠不經 ufw，白名單要放在 DOCKER-USER 鏈 |
| `collector/mnt-worm.mount` | 收集端 VM | 把 NAS 的 WORM 共用資料夾掛到 `/mnt/worm` |
| `collector/prometheus-scrape.yml` | 併入 onprem-metrics | Prometheus 抓 VictoriaLogs 的 `/metrics`，映像沒有 shell，健康由 `up == 0` 看 |
| `node/install-journal-upload.sh` | 每台 DGX Spark 與 PVE 節點 | 裝 `systemd-journal-remote`，確認 journal 持久化，寫 `journal-upload.conf`，啟用服務；`--from-now` 可略過既有歷史 |
| `nas/qulog-log-sender.md` | 每台 NAS | QuLog Center Log Sender 的設定步驟、解析出的欄位、時區與 TLS 的條件 |
| `archive/archive-day.sh` | 收集端，cron 每日 08:10（00:10 UTC） | 在本機暫存區逐小時匯出前一個 UTC 日每台主機的日誌成 `.jsonl.gz`，對帳相符才複製到 WORM，最後寫 `MANIFEST.tsv` 與 `SHA256SUMS`；已完成的日期拒絕覆寫 |
| `archive/verify-archive.sh` | 收集端，cron 每日 08:20 與每季人工 | 驗 sha256、行數對帳、解壓後行數，`--against-live` 再向 VictoriaLogs 要一次當天筆數；`DRILLS=` 把結果寫進 drills.jsonl |
| `grafana/datasource-victorialogs.yml` | 併入 onprem-metrics | Grafana 的 VictoriaLogs 資料源 |
| `grafana/Dockerfile`、`fetch-plugin.sh`、`build.sh` | 收集端 VM | 把資料源外掛打進 Grafana 映像：base 釘 digest、外掛釘 sha256，啟動時不連外 |
| `queries.md` | 文件 | Day 20 每條告警對應的 LogsQL，與幾個對帳用的統計 |
| `retention.md` | 文件 | 來源、熱、封存三層的期限與依據，WORM 共用資料夾的設定 |
| `collector.cron` | 收集端 | 兩行 cron |
| `tests/smoke.sh` | CI 與本機 | 起一個暫時的 VictoriaLogs，送一筆 syslog 與一筆 journald，查回來，跑封存與驗證，模擬 WORM 鎖定後重跑與竄改偵測 |

## 為什麼不是 Graylog、Loki 或只用 QuLog Center

見 Day 21 文章第一節。一句話，收集端是 2 vCPU 4 GB 的 VM，節點上不想再裝代理，封存要能被 WORM 鎖住且能對帳。

## 快速開始

```sh
# 收集端
docker compose up -d
sudo install -m 0644 collector/onprem-logs-allowlist.default /etc/default/onprem-logs-allowlist   # 改成場域的節點與 NAS
sudo install -m 0644 collector/onprem-logs-allowlist.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now onprem-logs-allowlist
sudo install -m 0644 collector/mnt-worm.mount /etc/systemd/system/ && sudo systemctl enable --now mnt-worm.mount
sudo install -d -o metrics /var/log/onprem-logs /srv/drills/onprem-logs /var/tmp/onprem-logs-stage
sudo install -m 0644 collector.cron /etc/cron.d/onprem-logs

# 每台節點（DGX Spark、PVE）
sudo ./node/install-journal-upload.sh http://192.168.2.49:9428

# 每台 NAS 依 nas/qulog-log-sender.md 設定記錄傳送端

# Grafana：建映像，onprem-metrics 的 grafana 服務改用它
sudo ./grafana/build.sh

# 回到收集端
curl -s http://127.0.0.1:9428/select/logsql/query -d 'query=_time:5m | stats by (_HOSTNAME, hostname) count()'
```

## 測試

```sh
shellcheck -s sh archive/*.sh node/*.sh collector/*.sh grafana/*.sh tests/smoke.sh
VLBIN=/path/to/victoria-logs-prod sh tests/smoke.sh    # 或不設 VLBIN 用 docker
```

## 授權

Apache-2.0
