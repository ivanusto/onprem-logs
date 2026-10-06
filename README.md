# onprem-logs

English | [繁體中文](README.zh-TW.md)

Log collection and retention for a small on-prem AI lab. Two DGX Spark nodes and two Proxmox VE nodes ship their journal with `systemd-journal-upload`, the uploader that comes with systemd. Two QuTS hero NAS send syslog with the sender built into QuLog Center. One VictoriaLogs container on the collector receives both. Nothing new is installed on the nodes or the NAS. Hot data is kept for 90 days. Every day the previous UTC day is exported as JSONL onto a WORM shared folder on the NAS (retention tentatively 180 days, to be confirmed against the site's records retention procedure), with a per-file sha256 and a manifest that proves the line count equals the query hit count.

| Path | Runs on | What it does |
|---|---|---|
| `docker-compose.yml` | collector VM | VictoriaLogs v1.52.0 pinned by digest, journald and syslog receivers, 90-day and 12 GiB retention limits, joins the onprem-metrics compose network so Grafana reaches it as `victorialogs:9428` |
| `collector/docker-user-allowlist.sh`, `onprem-logs-allowlist.service` | collector VM | Only the nodes may reach 9428 and only the NAS and the edge FortiGate may reach 514; every DROP has a rate-limited LOG in front of it (Day 22). Ports published by Docker bypass ufw, so the allowlist lives in the DOCKER-USER chain |
| `collector/mnt-worm.mount` | collector VM | Mounts the NAS WORM shared folder at `/mnt/worm` |
| `collector/prometheus-scrape.yml` | merged into onprem-metrics | Prometheus scrapes VictoriaLogs `/metrics`; the image has no shell, so health is watched with `up == 0` |
| `node/install-journal-upload.sh` | every DGX Spark and PVE node | Installs `systemd-journal-remote`, makes sure the journal is persistent, writes `journal-upload.conf`, enables the service; `--from-now` skips the existing history |
| `nas/qulog-log-sender.md` | every NAS | QuLog Center sender setup, the fields that arrive, time zone and TLS notes (Traditional Chinese) |
| `archive/archive-day.sh` | collector, cron 08:10 local (00:10 UTC) | Exports the previous UTC day per host, hour by hour, into a local staging area; copies to WORM only when every count matches, then writes `MANIFEST.tsv` and `SHA256SUMS`; refuses to touch a completed day |
| `archive/verify-archive.sh` | collector, cron 08:20 and quarterly by hand | Checks sha256, lines equal hits, decompressed line counts; `--against-live` re-asks VictoriaLogs; `DRILLS=` appends the result to drills.jsonl |
| `grafana/datasource-victorialogs.yml` | merged into onprem-metrics | The Grafana VictoriaLogs datasource |
| `grafana/Dockerfile`, `fetch-plugin.sh`, `build.sh` | collector VM | Bakes the datasource plugin into the Grafana image: base pinned by digest, plugin pinned by sha256, nothing fetched at start |
| `queries.md` | docs | LogsQL for each Day 20 alert, checked against field data (Traditional Chinese) |
| `retention.md` | docs | Source, hot and archive tiers, their limits and the WORM settings (Traditional Chinese) |
| `collector.cron` | collector | Two cron lines |
| `tests/smoke.sh` | CI and local | Starts a throwaway VictoriaLogs, sends one syslog and one journald entry, queries them back, archives and verifies, simulates a WORM-locked rerun, a tampered file and an unreachable collector |
| `firewall/fw-report.py` | collector, cron every 10 min and Monday 08:15 | Day 22. Reads the drops of five walls from VictoriaLogs (edge FortiGate, DGX Spark ufw, PVE pve-firewall, the collector's DOCKER-USER, QuLog's connection log) and answers who is knocking, where, and who is new; Markdown for people, `fw.prom` for onprem-metrics' `firewall.yml`. `FW_EXPECT` names the walls that must drop something, written as 0 when they log nothing |
| `firewall/collector-docker-user-log.md`, `pve-firewall.md`, `spark-ufw-logging.sh`, `pvefw-journal.service` | docs, PVE nodes, DGX Spark | How each wall is made to log, with what rate limit, and why the lab's Spark ufw and PVE firewall stay off for now (Traditional Chinese docs) |
| `firewall/queries.md`, `firewall/collector.cron` | docs, collector | LogsQL per wall, checked against field data; the two cron lines and `FW_EXPECT` |
| `tests/smoke-firewall.sh` | CI and local | One line of each firewall shape into a throwaway VictoriaLogs; checks the counts, that an accept is not counted, that an expected silent host is written as 0, and the NAS failure |

## Why not Graylog, Loki, or QuLog Center alone

Graylog needs MongoDB and OpenSearch next to it and does not fit a 2 vCPU, 4 GB collector. Loki needs an agent on every node. QuLog Center lives on the NAS, which is exactly the box that is gone for eight minutes when it reboots. VictoriaLogs ingests the journald export format natively, so the nodes need nothing but the uploader systemd already ships.

## Things the field taught

- Docker-published ports never reach ufw's INPUT rules. Restrict them in DOCKER-USER, matching the original port with `-m conntrack --ctorigdstport`, and publish on `0.0.0.0` only: a `[::]` listener is served by docker-proxy through INPUT.
- `systemd-journal-upload.service` runs with `DynamicUser=yes`; there is no static user and the cursor lives in `/var/lib/private/systemd/journal-upload/state`.
- VictoriaLogs drops anything older than its retention at ingestion (`vl_rows_dropped_total{reason="too_small_timestamp"}`), so a first upload of a long journal costs nothing beyond the retention window.
- QuLog Center sends RFC 3164 over TCP and UDP and RFC 5424 only over TLS. RFC 3164 carries no time zone, so `-syslog.timezone` is required.
- A single query's `sort` is capped by the container memory (about 122 MB at a 1 GiB limit); the archive exports hour by hour.
- On a WORM share everything written is locked after the lock delay, including half-written temp files. Build and check the day locally, copy last.

## Quick start

```sh
# collector
docker compose up -d
sudo install -m 0644 collector/onprem-logs-allowlist.default /etc/default/onprem-logs-allowlist   # set your nodes and NAS
sudo install -m 0644 collector/onprem-logs-allowlist.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now onprem-logs-allowlist
sudo install -m 0644 collector/mnt-worm.mount /etc/systemd/system/ && sudo systemctl enable --now mnt-worm.mount
sudo install -d -o metrics /var/log/onprem-logs /srv/drills/onprem-logs /var/tmp/onprem-logs-stage
sudo install -m 0644 collector.cron /etc/cron.d/onprem-logs

# every node (DGX Spark, PVE)
sudo ./node/install-journal-upload.sh http://192.168.2.49:9428

# every NAS: follow nas/qulog-log-sender.md

# Grafana: build the image and point onprem-metrics' grafana service at it
sudo ./grafana/build.sh

# back on the collector
curl -s http://127.0.0.1:9428/select/logsql/query -d 'query=_time:5m | stats by (_HOSTNAME, hostname) count()'
```

## Tests

```sh
shellcheck -s sh archive/*.sh node/*.sh collector/*.sh grafana/*.sh tests/smoke.sh
VLBIN=/path/to/victoria-logs-prod sh tests/smoke.sh    # or leave VLBIN unset to use docker
```

## License

Apache-2.0
