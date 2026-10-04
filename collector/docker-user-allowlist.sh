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
set -eu
JOURNALD_FROM=${JOURNALD_FROM:-}
SYSLOG_FROM=${SYSLOG_FROM:-}
ADMIN_FROM=${ADMIN_FROM:-}
CH=ONPREM-LOGS

remove() {
  while iptables -D DOCKER-USER -j "$CH" 2>/dev/null; do :; done
  iptables -F "$CH" 2>/dev/null || true
  iptables -X "$CH" 2>/dev/null || true
}

case "${1:-}" in
  remove) remove; exit 0 ;;
  apply) ;;
  *) sed -n '2,17p' "$0"; exit 64 ;;
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
iptables -A "$CH" -p tcp -m conntrack --ctstate DNAT --ctorigdstport 9428 -j DROP
iptables -A "$CH" -p tcp -m conntrack --ctstate DNAT --ctorigdstport 514 -j DROP
iptables -A "$CH" -p udp -m conntrack --ctstate DNAT --ctorigdstport 514 -j DROP
iptables -I DOCKER-USER 1 -j "$CH"
iptables -S "$CH"
