#!/bin/sh
# install-journal-upload: ship this host's journal to VictoriaLogs with the
# uploader that ships with systemd. No third-party agent, no new user, no
# new binary. Works on DGX OS 7 (Ubuntu 24.04) and Proxmox VE 9 (Debian 13).
#
#   sudo ./install-journal-upload.sh http://192.168.2.49:9428 [--from-now]
#
# What it does
#   1. apt install systemd-journal-remote (provides systemd-journal-upload)
#   2. make sure the journal is persistent, so entries written while the
#      collector is down are uploaded later instead of lost at reboot
#   3. write /etc/systemd/journal-upload.conf with the URL
#   4. with --from-now, seed the upload cursor at the end of the journal so
#      the existing history is not sent; without it the whole journal on
#      disk is uploaded once (VictoriaLogs drops what is older than its
#      retention)
#   5. enable and start systemd-journal-upload.service, then show the cursor
#
# The unit runs with DynamicUser=yes and StateDirectory=, so there is no
# static systemd-journal-upload user and the cursor lives in
# /var/lib/private/systemd/journal-upload/state; systemd owns that directory.
set -eu

URL=${1:-}
[ -n "$URL" ] || { sed -n '2,22p' "$0"; exit 64; }
FROM_NOW=0; [ "${2:-}" = "--from-now" ] && FROM_NOW=1
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

case "$URL" in
  http://*|https://*) ;;
  *) echo "URL must start with http:// or https://" >&2; exit 64 ;;
esac

if [ ! -x /usr/lib/systemd/systemd-journal-upload ] && [ ! -x /lib/systemd/systemd-journal-upload ]; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd-journal-remote
fi

# 2. persistent journal. With the default Storage=auto the journal is already
#    persistent when /var/log/journal exists; the drop-in makes it explicit.
#    No SystemMaxUse here on purpose: lowering it vacuums history at once.
mkdir -p /var/log/journal /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/10-persistent.conf <<'EOF'
# written by onprem-logs/node/install-journal-upload.sh
[Journal]
Storage=persistent
EOF
systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1 || true
systemctl restart systemd-journald

# 3. uploader config; systemd-journal-upload appends /upload to the URL
cat > /etc/systemd/journal-upload.conf <<EOF
# written by onprem-logs/node/install-journal-upload.sh
[Upload]
URL=$URL/insert/journald
EOF

# 4. optional: start from now
state=/var/lib/private/systemd/journal-upload/state
if [ "$FROM_NOW" -eq 1 ] && [ ! -s "$state" ]; then
  cursor=$(journalctl -n0 --show-cursor -q | sed -n 's/^-- cursor: //p')
  [ -n "$cursor" ] || { echo "could not read the journal cursor" >&2; exit 1; }
  install -d -m 0700 /var/lib/private
  install -d -m 0755 /var/lib/private/systemd /var/lib/private/systemd/journal-upload
  printf '# This is private data. Do not parse.\nLAST_CURSOR=%s\n' "$cursor" > "$state"
fi

# 5. run
systemctl enable --now systemd-journal-upload.service
sleep 3
systemctl --no-pager --lines=5 status systemd-journal-upload.service || true
echo
echo "cursor: $(sed -n 's/^LAST_CURSOR=//p' "$state" 2>/dev/null | head -c 120)"
echo
echo "check on the collector:"
echo "  curl -s http://127.0.0.1:9428/select/logsql/query -d 'query=_HOSTNAME:=\"$(hostname)\" | stats count()'"
echo
echo "the collector must accept tcp 9428 from this host (DOCKER-USER allowlist)."
