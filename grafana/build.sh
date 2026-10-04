#!/bin/sh
# build: fetch and check the plugin, build the image, print its ID for the
# change record. The tag is what onprem-metrics' compose refers to.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
TAG=${TAG:-onprem/grafana:12.2.10-vlogs0.32.0}
"$here/fetch-plugin.sh"
docker build -q -t "$TAG" "$here"
docker image inspect -f '{{.Id}}  {{index .RepoTags 0}}' "$TAG"
