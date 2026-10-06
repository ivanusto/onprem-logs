# 收集端 DOCKER-USER 鏈的丟棄也要留痕

Day 21 的 `collector/docker-user-allowlist.sh` 在 DOCKER-USER 掛了 `ONPREM-LOGS` 鏈：9428 只放四台節點，514 只放兩台 NAS 與邊界的 FortiGate，其餘 DROP。從 Day 22 起這支腳本預設 `LOG_DROPS=1`，每條 DROP 前面多一條相同條件、限速的 LOG：

```
-A ONPREM-LOGS -p tcp -m conntrack --ctstate DNAT --ctorigdstport 9428 -m limit --limit 6/min --limit-burst 10 -j LOG --log-prefix "[DOCKER-USER DROP] "
-A ONPREM-LOGS -p tcp -m conntrack --ctstate DNAT --ctorigdstport 9428 -j DROP
```

LOG 要跟 DROP 用一樣的比對條件，不能只在鏈的最後放一條通用的 LOG。這條鏈也會經過容器自己往外連的流量，那些封包不符合任何一條 RETURN，會從鏈尾巴回到 DOCKER-USER，記下來全是雜訊。規則寫在腳本裡而不是手動 `iptables -I`，因為 `onprem-logs-allowlist.service` 每次重啟都會先把整條鏈清掉再重建。

被擋的封包進的是收集端自己的 journal，所以收集端也要跑上傳器，Day 21 只裝了四台節點：

```sh
sudo ./node/install-journal-upload.sh http://127.0.0.1:9428
```

走 loopback 的連線是本機產生的封包，不經 FORWARD 也不經 DOCKER-USER，不需要放行（實測收集端自己的筆數照常進來）。

## 讀的時候要知道的

- 計的是封包，不是連線。TCP 的 SYN 沒有回應時會重送，一次連線嘗試在日誌裡是 4 到 6 行。
- `DST=` 是容器的位址（172.18.0.x），因為 DNAT 已經做過；`DPT=` 剛好跟原本的埠一樣，是因為 compose 把 9428 對到 9428、514 對到 514。
- 這道牆平常就應該是零筆。名單內的來源不會被擋，所以 `FwSilent` 不監看它（`FW_EXPECT` 裡沒有它）；反過來，出現任何一筆都代表有一台新機器在送日誌卻不在名單裡，或者有東西在掃收集端。
