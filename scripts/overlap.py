#!/usr/bin/env python3
"""Measure how much of our feed already appears on major public blocklists.

The README claims ~20-25% overlap with FireHOL/Spamhaus, measured once against
the old 114-entry list under the retired methodology. That claim is the whole
argument for the feed's value ("original sensor data, not a re-aggregation"),
so it should be a measured number, not a remembered one.
"""
import ipaddress
import sys
import urllib.request

FEED = "https://jacobrakai.org/feed/blocklist.txt"

# Aggregators most likely to already know these IPs. level1 is the
# conservative core; level3 is broader and includes attack sources.
LISTS = {
    "firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "firehol_level3": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset",
    "blocklist_de":   "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_de.ipset",
    "dshield":        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset",
    "spamhaus_drop":  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset",
    "sslbl":          "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/sslbl_aggressive.ipset",
}


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "overlap-check/1.0"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read().decode("utf-8", "replace")


def parse_nets(text):
    v4, v6 = [], []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        (v4 if net.version == 4 else v6).append(net)
    return v4, v6


def main():
    ours = []
    for line in fetch(FEED).splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            try:
                ours.append(ipaddress.ip_address(line))
            except ValueError:
                pass
    print(f"our feed: {len(ours)} IPs\n")

    matched_any = set()
    for name, url in LISTS.items():
        try:
            v4, v6 = parse_nets(fetch(url))
        except Exception as e:
            print(f"  {name:16} FETCH FAILED ({type(e).__name__})")
            continue
        # Exact /32s dominate these lists; use a set for those and only fall
        # back to linear CIDR scanning for the genuine ranges.
        singles = set()
        ranges = []
        for n in v4 + v6:
            if n.prefixlen == n.max_prefixlen:
                singles.add(n.network_address)
            else:
                ranges.append(n)
        hits = set()
        for ip in ours:
            if ip in singles or any(ip in n for n in ranges if n.version == ip.version):
                hits.add(ip)
        matched_any |= hits
        pct = 100.0 * len(hits) / len(ours) if ours else 0
        print(f"  {name:16} {len(hits):4d}/{len(ours)}  {pct:5.1f}%   "
              f"(list: {len(singles)} singles + {len(ranges)} ranges)")

    pct = 100.0 * len(matched_any) / len(ours) if ours else 0
    print(f"\n  {'ANY of the above':16} {len(matched_any):4d}/{len(ours)}  {pct:5.1f}%")
    print(f"  {'NOVEL (on none)':16} {len(ours)-len(matched_any):4d}/{len(ours)}  "
          f"{100-pct:5.1f}%")


if __name__ == "__main__":
    sys.exit(main())
