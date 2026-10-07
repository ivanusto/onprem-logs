# 封包擷取（Day 23）

Day 22 的日誌說得出「誰在敲哪個埠」，說不出封包裡是什麼。這個目錄讓節點用 tcpdump 抓，用能動的最小權限抓，抓完的檔走 Day 21 同一條封存路到 WORM。

## 節點上

| 檔 | 裝到 | 做什麼 |
|---|---|---|
| `install-pcap.sh` | 每台 DGX Spark、PVE 節點 | 裝 tcpdump 與 rsync，建系統帳號 `pcap` 與群組 `pcap-ops`，建 `/var/lib/pcap/{live,done}`，裝以下所有檔，`--pull-key` 放收集端的公鑰 |
| `pcap@.service` | `/etc/systemd/system/` | 一個 profile 一個實例。`User=pcap`，`AmbientCapabilities=CAP_NET_RAW`，其餘能關的都關。`ExecStopPost` 封存 |
| `pcap-run.sh` | `/usr/local/bin/` | 把 profile 的變數組成 tcpdump 命令列並 `exec`。`PCAP_DRYRUN=1` 只印不跑 |
| `pcap-seal.sh` | `/usr/local/bin/` | tcpdump 結束後把 `live/` 的檔搬到 `done/`，每個檔旁邊寫 `.sha256`。只有標頭的空檔刪掉 |
| `profiles/*.env` | `/etc/pcap/` | `nfs`、`corosync`、`syslog`、`custom`。已存在的不覆寫 |
| `sudoers-pcap` | `/etc/sudoers.d/pcap` | `pcap-ops` 成員可 `systemctl start/stop/status pcap@<列名的 profile>`，不用密碼，沒有別的 |

```sh
sudo ./install-pcap.sh --pull-key collector-id_pcap.pub
sudo systemctl start pcap@nfs          # 一小時，六個十分鐘的檔，自己結束
journalctl -fu pcap@nfs
sudo systemctl stop pcap@nfs           # 提早停也會封存
ls -l /var/lib/pcap/done
```

### 權限為什麼是這樣

- **CAP_NET_RAW，沒有 CAP_NET_ADMIN。** 開 AF_PACKET 的 socket 要 `CAP_NET_RAW`，把介面切成混雜模式要 `CAP_NET_ADMIN`。這裡抓的是這台主機自己的流量（它跟 NAS 的 NFS、它跟另一台節點的 corosync），`-p` 不開混雜模式，所以第二個能力不給。在收集端用 `setpriv --ambient-caps=+net_raw` 以一個沒有任何其他權限的帳號跑過，抓得到。拿掉這個能力，tcpdump 回 `You don't have permission to perform this capture on that device`。要在 `tap` 或橋接介面看別台主機的框，再加 `CAP_NET_ADMIN`。
- **能力給在 unit，不 setcap 在二進位。** `setcap cap_net_raw+ep /usr/bin/tcpdump` 會讓任何能執行它的人都抓得到，而且 apt 升級後會掉。unit 的 `AmbientCapabilities` 只在這個服務的行程樹裡有效，`CapabilityBoundingSet` 讓它拿不到別的。
- **tcpdump 自己的降權不在這裡發生。** Debian 與 Ubuntu 的 tcpdump 以 root 啟動時會自己切到 `tcpdump` 使用者（`-Z`）。這裡它一開始就不是 root，`-Z` 沒有作用，檔案的擁有者是 `pcap`。
- **AppArmor。** Ubuntu 24.04（DGX OS 7）的 `/etc/apparmor.d/usr.bin.tcpdump` 允許讀寫任何路徑的 `*.pcap` 與 `*.pcap[0-9]*`，`/var/lib/pcap/live` 不需要 local override。Debian 13（PVE 9）的 tcpdump 4.99.5-2 也裝了同一個 profile、規則相同，兩台 PVE 實測為 enforce 模式，同樣不需要 override。`install-pcap.sh` 結尾會印出模式。
- **操作者的權限。** Day 11 的維運帳號本來就有 sudo。`sudoers-pcap` 是給沒有 sudo 的值班帳號用的，列名的 unit 才能啟停，不用 `pcap@*`，因為 sudoers 的萬用字元會連著後面的空白一起比對，`systemctl start pcap@nfs sshd` 也會過。

### 四個 profile

| profile | 抓什麼 | 介面 | snaplen | 模式 | 上限 |
|---|---|---|---|---|---|
| `nfs` | 到主 NAS 的 TCP 2049 | `auto`，走到 192.168.2.2 的那個介面（兩台 Spark 都是 10GbE 的 `enP7s7`，CX7 的兩個不在路由上） | 256 | timed | 10 分鐘一檔，6 檔後自己停 |
| `corosync` | UDP 5405 到 5412 與 TCP 5403 | `vmbr0` | 128 | ring | 20 檔各 50 MB，最舊的被覆寫，手動停 |
| `syslog` | TCP 514 與 9428 | `auto` | 128 | timed | 5 分鐘一檔，2 檔 |
| `custom` | 自己填 | `auto` | 256 | timed | 5 分鐘 1 檔 |

`SNAPLEN` 限制的是每個封包留多少，不是只留標頭。每個 TCP 段都留前 `SNAPLEN` 位元組，扣掉 Ethernet、IP、TCP 的標頭（54 位元組，有 TCP timestamp 時 66）剩下的就是內容：1 MiB 的 NFS READ 回應拆成很多段，每一段都留下約 200 位元組的檔案內容。場域一小時、一次 2.46 GB 的讀取，NAS 送來的 46,196 段共留下 9.3 MB 的內容切片。`nfs` 的 256 能看到 RPC 標頭與 compound 前幾個操作（這裡的 READ 呼叫 302 位元組，READ 本身在 256 之後），模型庫存的是公開權重所以維持 256，放文件的共用資料夾把 `SNAPLEN` 設成標頭長度（這裡的 NFS 連線沒有 TCP 選項，是 54），只留 TCP 標頭，判斷「誰沒回」仍然夠。corosync 經 knet 加密，128 留下的是密文。`timed` 模式是 `-G/-W`，檔案數到了 tcpdump 自己結束。rotation 發生在間隔過後的第一個封包，過濾式一個都不中的話不會 rotate，`MAX_SECONDS`（預設 `ROTATE_SECONDS × KEEP_FILES + 60`）用 `timeout -s INT` 收尾，unit 的 `RuntimeMaxSec=1d` 是最後一道。`ring` 模式是 `-C/-W`，固定數量固定大小的檔，給「等它再發生一次」用。

`/var/lib/pcap/live` 2 天、`done` 7 天，`systemd-tmpfiles` 依 mtime 清。7 天的意思是收集端可以停一週。

## 收集端

| 檔 | 做什麼 |
|---|---|
| `pcap-pull.sh` | 每小時從每台節點的 `done/` 拉（ssh，節點那端的 authorized_keys 強制 `rrsync -ro /var/lib/pcap/done`），逐檔對節點寫的 sha256，相符才發表。一台節點一批，寫到 `/mnt/worm/pcap/<節點>/<批次 UTC 時間>/`，資料檔、`MANIFEST.tsv`、最後 `SHA256SUMS`。已發表的檔記在 `/var/lib/onprem-pcap/shipped.tsv`，rsync 用它當排除清單，不會拉第二次 |
| `pcap-stat.py` | 不靠 tcpdump 讀 pcap，輸出位元組、封包數、首末封包時間、是否截斷。`MANIFEST.tsv` 的數字從這裡來，`verify-pcap.sh` 用它重數 |
| `verify-pcap.sh` | 驗一個批次或每台節點最新的批次。sha256、位元組、封包數重數一次，`--against-index` 再對索引（sha256、節點、檔名、批次名四者都要對），`DRILLS=` 寫一行進 drills.jsonl |
| `collector.cron` | 兩行，:40 拉、:55 驗（WORM 寫入後 10 分鐘才鎖，驗在鎖之後） |

```sh
# 收集端，以 metrics 身份
ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_pcap -C pcap-pull   # 公鑰給每台節點的 install-pcap.sh --pull-key
sudo install -d -o metrics -g metrics /var/lib/onprem-pcap
mkdir -p /mnt/worm/pcap      # the WORM share squashes every uid, so no chown here
PCAP_NODES="spark01=pcap@192.168.2.131:/" ARCHIVE=/mnt/worm/pcap ./pcap-pull.sh
ARCHIVE=/mnt/worm/pcap ./verify-pcap.sh --latest --against-index
```

`MANIFEST.tsv` 一行是 `file bytes packets first last truncated sha256`。`truncated=1` 代表檔案在一筆封包中間結束，是 tcpdump 被殺掉時留下的樣子，前面的封包照樣算數，檔照樣發表，只是旗標告訴你最後一段不完整。

## 這個目錄不做的

- 不在 NAS 上裝任何東西。NAS 那一端見 [`nas-capture.md`](nas-capture.md)。
- 不解析封包。抓回來的檔用 Wireshark 或 `tshark` 看，文章第四節有查詢。
- 不開 ufw 或 pve-firewall，不改 Docker 的鏈，不改 AppArmor。
