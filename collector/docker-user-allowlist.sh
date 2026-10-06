#!/bin/sh
# docker-user-allowlist: only the log sources may reach VictoriaLogs.
#
# Ports published by Docker are DNAT'ed in PREROUTING and then FORWARDed to
# the container, so ufw's INPUT rules never see them. The one place Docker
# leaves for the operator is the DOCKER-USER chain. After DNAT the
# destination port is the container's, so match on the original port with
# conntrack.
#
#   docker-user-allowlist.sh apply|remove
#
# Environment (space separated)
#   JOURNALD_FROM  hosts allowed to POST to 9428/tcp (nodes)
#   SYSLOG_FROM    hosts allowed to send to 514/tcp+udp (NAS)
#   ADMIN_FROM     extra hosts allowed on 9428 (query from a workstation)
#   LOG_DROPS      1 (default) puts a rate-limited LOG in front of each DROP,
#                  prefix "[DOCKER-USER DROP] ", so refused senders show up
#                  in the collector's own journal; 0 drops silently
set -eu
JOURNALD_FROM=${JOURNALD_FROM:-}
SYSLOG_FROM=${SYSLOG_FROM:-}
ADMIN_FROM=${ADMIN_FROM:-}
LOG_DROPS=${LOG_DROPS:-1}
CH=ONPREM-LOGS

remove() {
  while iptables -D DOCKER-USER -j "$CH" 2>/dev/null; do :; done
  iptables -F "$CH" 2>/dev/null || true
  iptables -X "$CH" 2>/dev/null || true
}

case "${1:-}" in
  remove) remove; exit 0 ;;
  apply) ;;
  *) sed -n '2,20p' "$0"; exit 64 ;;
esac

remove
iptables -N "$CH"
# replies and anything not aimed at our ports pass through untouched
iptables -A "$CH" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
for h in $JOURNALD_FROM $ADMIN_FROM; do
  iptables -A "$CH" -s "$h" -p tcp -m conntrack --ctorigdstport 9428 -j RETURN
done
for h in $SYSLOG_FROM; do
  iptables -A "$CH" -s "$h" -p tcp -m conntrack --ctorigdstport 514 -j RETURN
  iptables -A "$CH" -s "$h" -p udp -m conntrack --ctorigdstport 514 -j RETURN
done
# the containers' own network (Grafana -> victorialogs:9428) is not DNAT'ed
drop() {
  # one LOG per DROP with the same match, so only what is dropped is logged;
  # 6/min per rule keeps a scanner from filling the journal
  if [ "$LOG_DROPS" = 1 ]; then
    iptables -A "$CH" -p "$1" -m conntrack --ctstate DNAT --ctorigdstport "$2" \
      -m limit --limit 6/min --limit-burst 10 -j LOG --log-prefix "[DOCKER-USER DROP] " --log-level 4
  fi
  iptables -A "$CH" -p "$1" -m conntrack --ctstate DNAT --ctorigdstport "$2" -j DROP
}
drop tcp 9428
drop tcp 514
drop udp 514
iptables -I DOCKER-USER 1 -j "$CH"
iptables -S "$CH"
