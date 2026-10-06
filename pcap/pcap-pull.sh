#!/bin/sh
# pcap-pull: on the collector, fetch sealed capture files from the nodes and
# publish them to the WORM share, one batch per node per run, with a
# manifest that lets Day 27 prove each file is the one the node sealed.
#
#   pcap-pull.sh                      cron, hourly (see collector.cron)
#
# Environment
#   PCAP_NODES  space separated list of <name>=<source>. The source is an
#               rsync source: "pcap@spark01:/" over ssh (the node's
#               authorized_keys forces `rrsync -ro /var/lib/pcap/done`, so
#               "/" is done/), or a local directory for tests
#   SSH_KEY     key for the ssh transport [~/.ssh/id_pcap]
#   MIRROR      local copy of each node's done/ [/var/lib/onprem-pcap/mirror]
#   INDEX       shipped files, one line each [/var/lib/onprem-pcap/shipped.tsv]
#               sha256  node  file  bytes  packets  batch
#   ARCHIVE     WORM root for captures [/mnt/worm/pcap]
#   STAGE       local scratch [/var/tmp/onprem-pcap-stage]
#
# Layout on the share
#   $ARCHIVE/spark01/20261007T034001Z/nfs-20261007T021000Z.pcap
#   $ARCHIVE/spark01/20261007T034001Z/MANIFEST.tsv
#   $ARCHIVE/spark01/20261007T034001Z/SHA256SUMS
#
# Rules, the same as archive-day.sh: everything is built and checked in
# $STAGE; a file is published only when the sha256 computed here equals
# the sha256 the node wrote next to it (the transfer is intact and the
# capture was sealed, not still being written); data files first,
# MANIFEST.tsv, then SHA256SUMS as the completion marker. A file already in
# $INDEX is never pulled again (rsync --exclude-from), so the node's own
# retention (tmpfiles, 7 days) is the only thing that deletes.
set -eu

PCAP_NODES=${PCAP_NODES:-}
SSH_KEY=${SSH_KEY:-$HOME/.ssh/id_pcap}
MIRROR=${MIRROR:-/var/lib/onprem-pcap/mirror}
INDEX=${INDEX:-/var/lib/onprem-pcap/shipped.tsv}
ARCHIVE=${ARCHIVE:-/mnt/worm/pcap}
STAGE=${STAGE:-/var/tmp/onprem-pcap-stage}
here=$(cd "$(dirname "$0")" && pwd)
STAT=${PCAP_STAT:-$here/pcap-stat.py}

[ -n "$PCAP_NODES" ] || { echo "pcap-pull: PCAP_NODES is empty" >&2; exit 64; }
[ -d "$ARCHIVE" ] || { echo "pcap-pull: $ARCHIVE not mounted" >&2; exit 1; }
mkdir -p "$MIRROR" "$STAGE" "$(dirname "$INDEX")"
[ -e "$INDEX" ] || printf '# sha256\tnode\tfile\tbytes\tpackets\tbatch\n' > "$INDEX"

rc=0
for spec in $PCAP_NODES; do
  node=${spec%%=*}; src=${spec#*=}
  case "$node" in *[!A-Za-z0-9_.-]*|"") echo "pcap-pull: bad node name in $spec" >&2; rc=1; continue ;; esac
  mdir="$MIRROR/$node"
  mkdir -p "$mdir"
  # files already shipped from this node are excluded by name, and so are
  # their sidecars; the node deletes them by age
  excl="$STAGE/.exclude-$node"
  awk -F'\t' -v n="$node" '$2 == n { print $3; print $3 ".sha256" }' "$INDEX" > "$excl"
  case "$src" in
    *:*) set -- rsync -rt --timeout=120 -e "ssh -i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=accept-new" ;;
    *)   set -- rsync -rt ;;
  esac
  # --delete-excluded: a file that is in the index, or gone from the node,
  # leaves the mirror too; the mirror holds only what is not yet published
  if ! "$@" --delete --delete-excluded --exclude-from="$excl" \
        --include='*.pcap' --include='*.pcap.sha256' --exclude='*' "$src" "$mdir/"; then
    echo "pcap-pull: $node: rsync from $src failed" >&2
    rc=1
    continue
  fi

  st="$STAGE/$node"
  rm -rf "$st"; mkdir -p "$st"
  : > "$st/.rows"
  for f in "$mdir"/*.pcap; do
    [ -e "$f" ] || continue
    base=$(basename "$f")
    [ -s "$f.sha256" ] || { echo "pcap-pull: $node/$base has no sha256 yet, skipped"; continue; }
    want=$(cut -d' ' -f1 "$f.sha256")
    have=$(sha256sum "$f" | cut -d' ' -f1)
    if [ "$want" != "$have" ]; then
      echo "pcap-pull: $node/$base sha256 differs from the node's sidecar, not published" >&2
      rc=1
      continue
    fi
    if grep -q "^$have	$node	" "$INDEX"; then continue; fi
    line=$(python3 -I "$STAT" "$f") || { echo "pcap-pull: $node/$base is not a readable pcap" >&2; rc=1; continue; }
    bytes=$(printf '%s' "$line" | cut -f2); pkts=$(printf '%s' "$line" | cut -f3)
    first=$(printf '%s' "$line" | cut -f4); last=$(printf '%s' "$line" | cut -f5); trunc=$(printf '%s' "$line" | cut -f6)
    cp "$f" "$st/$base"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$base" "$bytes" "$pkts" "$first" "$last" "$trunc" "$have" >> "$st/.rows"
  done
  if [ ! -s "$st/.rows" ]; then rm -rf "$st"; echo "pcap-pull: $node: nothing new"; continue; fi

  batch=$(date -u +%Y%m%dT%H%M%SZ)
  dir="$ARCHIVE/$node/$batch"
  while [ -e "$dir" ]; do sleep 1; batch=$(date -u +%Y%m%dT%H%M%SZ); dir="$ARCHIVE/$node/$batch"; done
  {
    printf '# onprem-logs pcap batch  node=%s  batch=%s  written=%s  collector=%s\n' \
      "$node" "$batch" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(hostname)"
    printf '# file\tbytes\tpackets\tfirst\tlast\ttruncated\tsha256\n'
    cat "$st/.rows"
  } > "$st/MANIFEST.tsv"
  ( cd "$st" && sha256sum ./*.pcap MANIFEST.tsv > SHA256SUMS )
  mkdir -p "$dir"
  for f in "$st"/*.pcap "$st/MANIFEST.tsv" "$st/SHA256SUMS"; do cp "$f" "$dir/"; done
  if ! ( cd "$dir" && sha256sum -c --quiet SHA256SUMS ); then
    echo "pcap-pull: copy to $dir does not match the staged files" >&2
    exit 5
  fi
  # the index is written only after the batch is complete on the share
  while IFS="$(printf '\t')" read -r base bytes pkts _ _ _ sum; do
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$sum" "$node" "$base" "$bytes" "$pkts" "$batch" >> "$INDEX"
  done < "$st/.rows"
  printf 'pcap-pull: %s  %s file(s) -> %s\n' "$node" "$(grep -vc '^#' "$dir/MANIFEST.tsv")" "$dir"
  rm -rf "$st"
done
exit "$rc"
