# onprem-logs

[English](README.md) | 繁體中文

小型地端 AI 機房的日誌集中與保存。兩台 DGX Spark 與兩台 Proxmox VE 節點用 systemd 自帶的 `systemd-journal-upload` 把 journal 送到收集端，兩台 QuTS hero NAS 用 QuLog Center 內建的 Log Sender 送 syslog，收集端一個 VictoriaLogs 容器接兩種來源。節點與 NAS 上不裝任何新代理。熱資料留 90 天，每天把前一天的日誌匯出成 JSONL 寫進 NAS 的 WORM 共用資料夾（保留期暫定 180 天，待確認），附逐檔 sha256 與「行數等於查詢筆數」的對帳清單。

| 路徑 | 跑在哪 | 做什麼 |
|---|---|---|
| `docker-compose.yml` | 收集端 VM | VictoriaLogs v1.52.0（釘 digest），journald 與 syslog 兩種接收器，90 天與 12 GiB 的保留上限，加入 onprem-metrics 的 compose 網路讓 Grafana 以 `victorialogs:9428` 連到 |
| `collector/docker-user-allowlist.sh`、`onprem-logs-allowlist.service` | 收集端 VM | 只讓節點進 9428、NAS 與邊界 FortiGate 進 514；每條 DROP 前有一條限速的 LOG（Day 22）。Docker 發佈的埠不經 ufw，白名單要放在 DOCKER-USER 鏈 |
| `collector/mnt-worm.mount` | 收集端 VM | 把 NAS 的 WORM 共用資料夾掛到 `/mnt/worm` |
| `collector/prometheus-scrape.yml` | 併入 onprem-metrics | Prometheus 抓 VictoriaLogs 的 `/metrics`，映像沒有 shell，健康由 `up == 0` 看 |
| `node/install-journal-upload.sh` | 每台 DGX Spark 與 PVE 節點 | 裝 `systemd-journal-remote`，確認 journal 持久化，寫 `journal-upload.conf`，啟用服務；`--from-now` 可略過既有歷史 |
| `nas/qulog-log-sender.md` | 每台 NAS | QuLog Center Log Sender 的設定步驟、解析出的欄位、時區與 TLS 的條件 |
| `archive/archive-day.sh` | 收集端，cron 每日 08:10（00:10 UTC） | 在本機暫存區逐小時匯出前一個 UTC 日每台主機的日誌成 `.jsonl.gz`，對帳相符才複製到 WORM，最後寫 `MANIFEST.tsv` 與 `SHA256SUMS`；已完成的日期拒絕覆寫；`ARCHIVE_SKIP` 依政策排除指定來源，筆數仍寫進 MANIFEST |
| `archive/verify-archive.sh` | 收集端，cron 每日 08:20 與每季人工 | 驗 sha256、行數對帳、解壓後行數，`--against-live` 再向 VictoriaLogs 要一次當天筆數；`DRILLS=` 把結果寫進 drills.jsonl |
| `grafana/datasource-victorialogs.yml` | 併入 onprem-metrics | Grafana 的 VictoriaLogs 資料源 |
| `grafana/Dockerfile`、`fetch-plugin.sh`、`build.sh` | 收集端 VM | 把資料源外掛打進 Grafana 映像：base 釘 digest、外掛釘 sha256，啟動時不連外 |
| `queries.md` | 文件 | Day 20 每條告警對應的 LogsQL，與幾個對帳用的統計 |
| `retention.md` | 文件 | 來源、熱、封存三層的期限與依據，WORM 共用資料夾的設定 |
| `collector.cron` | 收集端 | 兩行 cron |
| `tests/smoke.sh` | CI 與本機 | 起一個暫時的 VictoriaLogs，送一筆 syslog 與一筆 journald，查回來，跑封存與驗證，模擬 WORM 鎖定後重跑與竄改偵測 |
| `firewall/fw-report.py` | 收集端，cron 每 10 分鐘與每週一 08:15 | Day 22。從 VictoriaLogs 讀五道牆的拒絕紀錄（邊界 FortiGate、DGX Spark 的 ufw、PVE 的 pve-firewall、收集端的 DOCKER-USER、QuLog 連線紀錄），回答誰在敲、敲哪裡、誰是新的；Markdown 給人看，`fw.prom` 給 onprem-metrics 的 `firewall.yml`。`FW_EXPECT` 列出一定要擋到東西的牆，零筆時寫 0 |
| `firewall/collector-docker-user-log.md`、`pve-firewall.md`、`spark-ufw-logging.sh`、`pvefw-journal.service` | 文件、PVE 節點、DGX Spark | 每道牆怎麼開日誌、限速多少，以及這個場域的 Spark ufw 與 PVE 防火牆為什麼暫時不開 |
| `firewall/queries.md`、`firewall/collector.cron` | 文件、收集端 | 每道牆的 LogsQL（以場域資料驗過）；兩行 cron 與 `FW_EXPECT` |
| `tests/smoke-firewall.sh` | CI 與本機 | 每種防火牆格式各一筆送進暫時的 VictoriaLogs，驗計數、accept 不算、預期會擋卻零筆的主機寫 0、NAS 登入失敗 |
| `pcap/install-pcap.sh`、`pcap@.service`、`pcap-run.sh`、`pcap-seal.sh`、`profiles/*.env`、`sudoers-pcap` | 每台 DGX Spark 與 PVE 節點 | Day 23。能動的最小權限封包擷取。tcpdump 以系統帳號 `pcap` 執行，只有 `CAP_NET_RAW`（不開混雜模式，不對二進位 setcap），一個 profile 一個 systemd 實例（`systemctl start pcap@nfs`），預設 snaplen 很短（它限制內容的量，不會把內容去掉，見 pcap/README.md），有時間上限（`-G/-W`）或環狀檔（`-C/-W`），磁碟用量有界。tcpdump 結束後檔案封進 `done/`，每個檔附 sha256。`pcap-ops` 群組可用 sudo 啟停列名的 unit，沒有其他權限 |
| `pcap/pcap-pull.sh`、`pcap-stat.py`、`verify-pcap.sh`、`pcap/collector.cron` | 收集端，cron 每小時 | 經 ssh（強制 `rrsync -ro`）拉每台節點的 `done/`，逐檔對節點寫的 sha256，一台節點一批寫進 WORM 共用資料夾，附 `MANIFEST.tsv`（位元組、封包數、首末時間、截斷旗標、sha256）與 `SHA256SUMS`；已出貨索引讓同一個檔不會拉兩次。`verify-pcap.sh --latest --against-index` 重數封包並對索引，結果寫 drills.jsonl |
| `tests/smoke-pcap.sh` | CI 與本機 | 每個 profile 乾跑、root 時在 `lo` 真抓一次、封存、拉進 WORM 替身、第二次拉不出新批、說謊的 sidecar 被拒、截斷的擷取被標記、竄改與手動複製進來的批次驗證失敗 |
| `firewall/aup-report.py`、`firewall/fortigate-webfilter.md`、`firewall/rules-aup.yml` | 收集端，cron 每 10 分鐘與每週一 08:25 | Day 24。邊界 FortiGate webfilter 日誌的可接受使用判讀，依工作站列網站、依類別、被擋的依工作站、緊急類別命中。線上讀 VictoriaLogs，離線 `--from-file` 讀匯出檔，兩邊都先化成同樣的七個欄位。Markdown 給人看，`aup.prom` 給 onprem-metrics 的 `aup.yml`。.md 裡有 FortiGate 的變更（policy 1 掛全部監看的 profile）與 LogsQL |
| `firewall/aup-compare.sh`、`firewall/fortigate-export-load.py` | 有 docker 或 VictoriaLogs 二進位的地方 | 把匯出檔以線上的存法灌進暫時的 VictoriaLogs，對它與對檔案各跑一次 aup-report，diff 兩份報告。瀏覽器的 [fortigate-log-viewer](https://github.com/ivanusto/fortigate-log-viewer) 是第三個讀法 |
| `tests/smoke-aup.sh` | CI 與本機 | fixture 上線上等於離線、檔案對帳（行數 = 解析 + 略過）、webfilter 以外的行不計、textfile 寫出每個緊急類別且沉默的 FortiGate 寫 0、沒有時間的行被載入器略過並成為唯一的差異 |

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
shellcheck -s sh archive/*.sh node/*.sh collector/*.sh grafana/*.sh firewall/*.sh pcap/*.sh tests/*.sh
VLBIN=/path/to/victoria-logs-prod sh tests/smoke.sh    # 或不設 VLBIN 用 docker
sh tests/smoke-firewall.sh
sh tests/smoke-pcap.sh                                 # root 時會在 lo 真抓一次，SMOKE_PCAP_REAL=0 可略過
sh tests/smoke-aup.sh                                  # 跟 smoke.sh 一樣要 VLBIN 或 docker
```

## 授權

Apache-2.0
