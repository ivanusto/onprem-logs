# NAS 那一端

兩台 QuTS hero NAS 不裝新東西，這是 Day 21 以來的原則。封包擷取在 NAS 上有三種可能，依場域實際查到的結果擇一，查的順序如下。

## 先查

```sh
# 以 admin 登入 NAS 的 SSH
which tcpdump; ls -l /usr/sbin/tcpdump /sbin/tcpdump /usr/local/sbin/tcpdump 2>/dev/null
tcpdump --version 2>&1 | head -n1
```

再看 App Center 裡 QNAP 自己的「診斷工具」（Diagnostic Tool）有沒有封包擷取的項目，以及 QuLog Center 以外還有哪些系統工具。**這兩項在撰寫時都還沒有在 QuTS hero 6.0.2 上確認（待查）**。2016 年的社群討論說 QTS 4.2.1 沒有 tcpdump，Qnapclub 與 myQNAP 都有第三方的 tcpdump QPKG，那只能證明「要另外裝」的版本存在。

## 三種情況

### 一、NAS 內建 tcpdump

以 admin 跑的 tcpdump 就是 root 的 tcpdump，Day 23 在節點上做的最小權限在這裡不成立，能做的是把其他三件事做到。

```sh
# 在 NAS 上，寫到一個不是 WORM、只有 admin 能讀的暫存共用資料夾
d=/share/PcapStage; mkdir -p "$d"; chmod 700 "$d"
tcpdump -p -n -i <介面> -s 256 -G 600 -W 6 -w "$d/nas-nfs-%Y%m%dT%H%M%SZ.pcap" 'tcp port 2049 and host <Spark 的位址>'
cd "$d" && for f in *.pcap; do sha256sum "$f" > "$f.sha256"; done     # 跟節點的 pcap-seal.sh 一樣的 sidecar
```

- `-p`、`-n`、`-s 256`，與節點相同的理由，標頭就夠，檔案內容不進檔。
- 寫到暫存共用資料夾，不直接寫 WORM。WORM 鎖定延遲只有 10 分鐘，一個寫到一半的檔會被鎖住、刪不掉。
- 搬回收集端：收集端每分鐘已經以 Day 19 `nas-textfile.sh` 的身份 SSH 到 NAS，用同一把金鑰 `scp` 到 `/var/lib/onprem-pcap/in/nas-primary/`，然後讓 `pcap-pull.sh` 把它當成本機來源，之後跟節點的檔走同一條路，同樣的 MANIFEST、同樣的驗證。

```sh
# 收集端，以 metrics 身份
scp -i ~/.ssh/<nas-textfile 的金鑰> 'admin@192.168.2.2:/share/PcapStage/*' /var/lib/onprem-pcap/in/nas-primary/
PCAP_NODES="nas-primary=/var/lib/onprem-pcap/in/nas-primary/" ARCHIVE=/mnt/worm/pcap ./pcap-pull.sh
```

抓完立刻刪 NAS 上的暫存檔，命令與時間寫進變更單（Day 26）。

### 二、診斷工具有封包擷取

照工具的介面抓，匯出的檔放到同一個暫存共用資料夾，後面的步驟與第一種相同。工具產生的檔若是 pcapng，`pcap-stat.py` 會以結束碼 2 拒絕，先用 `tshark -F pcap -r in.pcapng -w out.pcap` 轉成 pcap，或在 MANIFEST 以外另記。

### 三、都沒有

不裝第三方 QPKG。NFS 每個封包都有兩端，Spark 那一端的 `pcap@nfs` 抓到的就是 NAS 送出與收到的封包，少掉的只有「封包離開 NAS 網卡的那一刻」與「NAS 自己沒送出來的東西」。要分辨「NAS 沒回」與「網路沒送到」，兩個辦法。

1. 交換器鏡射。Mercury SE106 Pro 是否支援 port mirror 待查，支援的話把 NAS 的埠鏡射到一台工作站，用 Wireshark 抓，檔案走第一種的搬回路線。
2. 兩端對時。Spark 端的擷取檔配 NAS 的 QuLog 系統事件（Day 21 已進 VictoriaLogs），同一條時間軸上看 NFS 的 TCP 重傳開始的時間，與 NAS 那一刻有沒有記錄到任何事。這不是封包層的證據，但是這個場域今天就拿得到的。

## 不管哪一種

- NAS 上的擷取檔含內網位址與 MAC，與 Day 22 排除 FortiGate traffic 的理由相同，只在需要時抓，抓完即刪，WORM 裡那一份就是唯一的一份。
- 在 NAS 以 admin 跑過的每一條命令都寫進變更單。節點那邊 `systemctl start pcap@nfs` 會留在 journal 並上傳到收集端（PID 1 的 Started 行與 sudo 的紀錄），NAS 這邊沒有這個副產品，只能靠手寫。
