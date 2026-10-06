#!/usr/bin/env python3
"""pcap-stat: count the packets in a pcap file without tcpdump.

    pcap-stat.py FILE [FILE...]

Prints one TSV line per file:

    file  bytes  packets  first  last  truncated

first/last are the timestamps of the first and last complete packet record
(UTC, ISO 8601, microseconds). truncated is 1 when the file ends inside a
record, which is what a capture killed mid-write leaves behind; the packets
before the cut are still counted. Only the classic pcap format (what tcpdump
writes by default) is read; a pcapng file is reported as such and exits 2.

Used by pcap-pull.sh when it writes MANIFEST.tsv and by verify-pcap.sh when
it recounts; the two numbers must match.
"""
import struct
import sys
from datetime import datetime, timezone

MAGICS = {
    0xA1B2C3D4: ("<", 1_000_000),  # little endian, microseconds
    0xD4C3B2A1: (">", 1_000_000),
    0xA1B23C4D: ("<", 1_000_000_000),  # nanoseconds
    0x4D3CB2A1: (">", 1_000_000_000),
}


def stat(path):
    with open(path, "rb") as fh:
        head = fh.read(24)
        if len(head) < 24:
            return None, "short header"
        magic_le = struct.unpack("<I", head[:4])[0]
        if magic_le == 0x0A0D0D0A:
            return None, "pcapng"
        if magic_le not in MAGICS:
            return None, "not a pcap file"
        endian, scale = MAGICS[magic_le]
        snaplen = struct.unpack(endian + "I", head[16:20])[0]
        packets = 0
        first = last = None
        truncated = 0
        while True:
            rec = fh.read(16)
            if not rec:
                break
            if len(rec) < 16:
                truncated = 1
                break
            sec, frac, incl, _orig = struct.unpack(endian + "IIII", rec)
            if incl > snaplen + 65535:
                return None, "corrupt record length"
            data = fh.read(incl)
            if len(data) < incl:
                truncated = 1
                break
            packets += 1
            ts = sec + frac / scale
            if first is None:
                first = ts
            last = ts
    return (packets, first, last, truncated), None


def iso(ts):
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def main(argv):
    if len(argv) < 2:
        sys.stderr.write(__doc__)
        return 64
    rc = 0
    for path in argv[1:]:
        try:
            size = __import__("os").path.getsize(path)
            res, err = stat(path)
        except OSError as exc:
            sys.stderr.write(f"pcap-stat: {path}: {exc}\n")
            rc = 1
            continue
        if err:
            sys.stderr.write(f"pcap-stat: {path}: {err}\n")
            rc = 2 if err == "pcapng" else 1
            continue
        packets, first, last, truncated = res
        print(f"{path}\t{size}\t{packets}\t{iso(first)}\t{iso(last)}\t{truncated}")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
