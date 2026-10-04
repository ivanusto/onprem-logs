#!/bin/sh
# fetch-plugin: download the VictoriaLogs datasource release and refuse it
# unless the sha256 matches the one pinned here. Upstream publishes sha1
# sums next to the release; the sha256 below was taken after that matched.
set -eu
VER=0.32.0
SHA256=e100b767f19cd614ac8ac3860458a3fb33f5aa7a876e924d0340010e40d1c0d4
URL=https://github.com/VictoriaMetrics/victorialogs-datasource/releases/download/v$VER/victoriametrics-logs-datasource-v$VER.tar.gz
here=$(cd "$(dirname "$0")" && pwd)
tgz="$here/victoriametrics-logs-datasource-v$VER.tar.gz"
[ -s "$tgz" ] || curl -sSfL -o "$tgz" "$URL"
echo "$SHA256  $tgz" | sha256sum -c -
rm -rf "$here/plugins"
mkdir -p "$here/plugins"
tar xzf "$tgz" -C "$here/plugins"
echo "plugin $VER unpacked into $here/plugins"
