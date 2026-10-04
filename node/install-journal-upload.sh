#!/bin/sh
# install-journal-upload: ship this host's journal to VictoriaLogs with the
# uploader that ships with systemd. No third-party agent, no new user, no
# new binary. Works on DGX OS 7 (Ubuntu 24.04) and Proxmox VE (Debian 12/13).
#
#   sudo ./install-journal-upload.sh http://192.168.2.49:9428
#
# What it does
#   1. apt install systemd-journal-remote (provides systemd-journal-upload)
#   2. make the journal persistent, so entries written while the collector
#      is down are uploaded later instead of lost at reboot
#   3. write /etc/systemd/journal-upload.conf with the URL
#   4. fix the state directory ownership (Debian ships it root-owned, the
#      service runs as systemd-journal-upload and fails silently)
#   5. enable and start systemd-journal-upload.service, then show the cursor
set -eu

URL=${1:-}
[ -n "$URL" ] || { sed -n '2,18p' "$0"; exit 64; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

case "$URL" in
  http://*|https://*) ;;
  *) echo "URL must start with http:// or https://" >&2; exit 64 ;;
esac

if ! command -v systemd-journal-upload >/dev/null 2>&1 && [ ! -x /lib/systemd/systemd-journal-upload ] && [ ! -x /usr/lib/systemd/systemd-journal-upload ]; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd-journal-remote
fi

# 2. persistent journal (idempotent)
mkdir -p /var/log/journal /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/10-persistent.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=2G
EOF
systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1 || true
systemctl restart systemd-journald

# 3. uploader config
cat > /etc/systemd/journal-upload.conf <<EOF
# written by onprem-logs/node/install-journal-upload.sh
[Upload]
URL=$URL/insert/journald
EOF

# 4. state dir: the cursor file lives here; wrong owner means every restart
#    re-uploads from the beginning or fails with EACCES
install -d -o systemd-journal-upload -g systemd-journal-upload -m 0755 /var/lib/systemd/journal-upload 2>/dev/null \
  || install -d -m 0755 /var/lib/systemd/journal-upload

# 5. run
systemctl enable --now systemd-journal-upload.service
sleep 2
systemctl --no-pager --lines=5 status systemd-journal-upload.service || true
echo
echo "cursor: $(cat /var/lib/systemd/journal-upload/state 2>/dev/null | head -c 200 || echo none)"
echo
echo "check on the collector:"
echo "  curl -s '$URL/select/logsql/query' -d \"query=_HOSTNAME:$(hostname) | stats count()\""
echo
echo "firewall on the collector must allow this host to reach $URL (tcp 9428)."
