# Proxmox VE 節點的防火牆日誌

這個場域的兩台 PVE 節點**目前沒有開** `pve-firewall`（`pve-firewall status` 是 `disabled/running`，`/etc/pve/firewall/` 不存在）。這份文件記錄要開時的做法，以及開之前查到的三個事實；它們讓「先在一台開、通了再開第二台」這個直覺做法不成立。以下引用的行號是 pve-firewall 6.0.6（PVE 9.2）的 `/usr/share/perl5/PVE/Firewall.pm`。

PVE 節點不裝 ufw。Proxmox VE 有自己的防火牆（`pve-firewall`，PVE 8 起可在 `host.fw` 設 `nftables: 1` 切到 nftables 的 `proxmox-firewall`），規則在叢集層 `/etc/pve/firewall/cluster.fw`、節點層 `/etc/pve/nodes/<node>/host.fw`、客體層 `<vmid>.fw`，由叢集檔案系統同步到每一台節點。ufw 裝在同一台機器上會跟它搶 iptables 鏈，誰最後重載就聽誰的。

## 開之前要知道的三件事

1. **開關在叢集層。** `is_enabled_and_not_nftables()`（5524 行）只看 `cluster.fw` 的 `enable`。`cluster.fw` 一寫 `enable: 1`，所有節點的 `pve-firewall` 都會編譯並套用規則。`host.fw` 的 `enable: 0` 只會跳過該節點的主機規則（4525 行起），`apply_ruleset()` 仍然會執行。
2. **一開就打開橋接過濾。** `apply_ruleset()` 第一件事是 `enable_bridge_firewall()`（2082 行），把 `net.bridge.bridge-nf-call-iptables` 設成 1，從此橋接在 `vmbr0` 上的 VM 流量也要走 iptables 的 FORWARD 鏈。`PVEFW-FORWARD` 是用 `-A` **附加**在 FORWARD 最後（5103 行）。節點上如果有 Docker，Docker 已經把 FORWARD 的 policy 設成 DROP，它自己的鏈排在前面；VM 的新連線走完 Docker 的鏈與 `PVEFW-FORWARD` 都沒有被接受，就會掉到 policy DROP。這個場域的 pve1 上就有 Docker（`proxcenter-frontend`），而收集端 VM 正好跑在 pve1 上。
3. **`management` 一定包含整個本地網段。** 4408 行把 `local_network`（沒有另外定義時就是節點所在的網段，這裡是 192.168.2.0/24）無條件推進 `management` IPSet。自己定義一個比較窄的 `management` 並不能把網段其他位址擋在 22 與 8006 之外；要縮小範圍，得改 `local_network` 這個 alias。好處是鎖死自己的風險比想像中小，壞處是同網段的機器照樣可以碰管理埠。

## 日誌落在哪

規則日誌由 `pvefw-logger` 透過 NFLOG 收，寫到 `/var/log/pve-firewall.log`（root:adm 0640），不進 journald。前綴在 `ruleset_add_chain_policy()`（2620 行）組成，是 `policy DROP: ` 或 `policy REJECT: `。pvefw-logger 每一行的格式是

```
VMID LOGLEVEL CHAIN TIMESTAMP MESSAGE
0 5 - 06/Oct/2026:00:11:06 +0800 starting pvefw logger              # 節點上現有的唯一一行
0 6 PVEFW-HOST-IN 06/Oct/2026:14:02:11 +0800 policy DROP: IN=vmbr0 ... SRC=... DST=... PROTO=TCP SPT=... DPT=8006 SYN
```

第二行的 DROP 是依原始碼推出來的形狀，場域還沒開防火牆，所以沒有實際的樣本。VMID 0 是主機自己，LOGLEVEL 是 syslog 等級數字（6 是 info）。`pvefw-journal.service` 用 `tail -F | systemd-cat -t pve-firewall` 把這個檔案鏡射進 journal，Day 21 的上傳器就會送到收集端，查詢用 `SYSLOG_IDENTIFIER:=pve-firewall "policy DROP:"`。這個 unit 不能加 `LogLevelMax=notice`：它也會過濾 `systemd-cat -p info` 寫進來的行，等於把每一筆都丟掉（已在收集端用 `systemd-run` 驗證）。

## 開啟的順序

1. 有 Docker 的節點先處理橋接：在 `DOCKER-USER` 放行橋接在 `vmbr0` 上的流量，並寫成開機會套用的 unit，例如 `iptables -I DOCKER-USER -i vmbr0 -o vmbr0 -j ACCEPT`。這條規則也會讓客體層的防火牆在這台節點上失效，要用客體防火牆的話，得改成只放行沒有 `fwbr` 的介面。
2. 先開一條到每台節點的 SSH 不要關，另外開一個瀏覽器分頁在 8006。
3. 需要比整個網段更窄時才改 `local_network`。這個場域會用到管理埠的位址有：收集端（pve-exporter 與每分鐘的 `pvecm status`）、管理工作站、兩台節點、QDevice VM（192.168.2.148）、NAS（HDP 連 PVE 的 API）。
4. 叢集層 `cluster.fw`

```
[OPTIONS]
enable: 1
policy_in: DROP
policy_out: ACCEPT
log_ratelimit: enable=1,burst=5,rate=1/second
```

5. 節點層 `host.fw`。不想讓某台節點套主機規則時加 `enable: 0`，但第 2 點的橋接過濾一樣會生效。

```
[OPTIONS]
log_level_in: info
log_level_out: nolog
tcpflags: 1
tcp_flags_log_level: warning
```

6. 每台節點都先 `pve-firewall compile` 看編出來的規則，在 pve1 上確認 `iptables -S FORWARD` 裡第 1 點的 ACCEPT 排在 `PVEFW-FORWARD` 之前。然後 `pve-firewall start`，從收集端跑一次 `pve-quorum-textfile.sh` 與 pve-exporter 的抓取，再從一台 VM 對外開一條新連線。
7. 裝 `pvefw-journal.service`，從收集端以外的位址打一個沒開的埠（例如 111），到收集端查第一筆，用實際格式校正 `fw-report.py` 的 `pvefw` 篩選。

## 限速

`log_ratelimit` 預設每秒 1 筆、burst 5（210 行的全域預設是 `--limit 1/sec`）。同一台掃描器一秒打一千個埠，只會留下幾行。

## 回退

`pve-firewall stop` 立刻移除規則、放行所有流量，規則檔不動。持久的關法是 `cluster.fw` 的 `enable: 0`。`bridge-nf-call-iptables` 不會自動改回 0，要手動 `sysctl -w net.bridge.bridge-nf-call-iptables=0`。這三個指令都寫進 Day 26 變更單的回退欄。
