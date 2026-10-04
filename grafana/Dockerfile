# Grafana with the VictoriaLogs datasource baked in, so nothing is fetched
# from the Grafana catalog when the container starts. Both inputs are pinned:
# the base image by digest (same one onprem-metrics uses) and the plugin by
# the sha256 that fetch-plugin.sh checks. Build with ./build.sh.
FROM grafana/grafana:12.2.10@sha256:d2ac2dae86601550e941f7e1c0b4b7e1f21fadebfa5956ba06fe0b3a64de7cf4
# /var/lib/grafana is a named volume in onprem-metrics; anything the image
# put there would be hidden by the existing volume, so plugins live elsewhere
COPY plugins/ /opt/grafana-plugins/
ENV GF_PATHS_PLUGINS=/opt/grafana-plugins
