#!/usr/bin/env python3
"""Measure how much of this feed already appears on other public blocklists.

Two groups, because they answer different questions:

  AGGREGATES  (FireHOL, Spamhaus, blocklist.de, DShield) -- "is this list
              redundant?" A low number here is the argument for running your
              own sensor at all.

  PEERS       (dataplane.org per-protocol honeypot feeds, greensnow) -- "am I
              seeing the same attackers other honeypot operators see?" This is
              the more informative comparison, because it is like-for-like:
              other people's decoys rather than curated aggregations.

The peer numbers are what revealed this feed's actual composition: overlap with
dataplane's telnet feed runs ~5x higher than with its SSH feed, because the
list is dominated by telnet/IoT-botnet hosts rather than SSH bruteforcers.

LICENSING: dataplane.org is non-commercial use only and prohibits
redistribution. Computing overlap statistics against it is fine; its addresses
must never be merged into this CC0 feed. Pull for measurement, never for
publication -- otherwise the "original sensor data, not a re-aggregation"
claim stops being true.

Usage: python3 scripts/overlap.py
"""

import ipaddress
import sys
import urllib.request

FEED = "https://jacobrakai.org/feed/blocklist.txt"
UA = "jacobrakai-overlap/1.0 (+https://jacobrakai.org/feed/)"

# name -> (url, column index or None for one-per-line, delimiter)
AGGREGATES = {
    "firehol_level1": ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", None, None),
    "firehol_level3": ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset", None, None),
    "blocklist_de":   ("https://lists.blocklist.de/lists/all.txt", None, None),
    "dshield":        ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset", None, None),
    "spamhaus_drop":  ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset", None, None),
}

PEERS = {
    "dataplane sshpwauth (SSH)":      ("https://dataplane.org/sshpwauth.txt", 2, "|"),
    "dataplane telnetlogin (telnet)": ("https://dataplane.org/telnetlogin.txt", 2, "|"),
    "dataplane vncrfb (VNC)":         ("https://dataplane.org/vncrfb.txt", 2, "|"),
    "greensnow":                      ("https://blocklist.greensnow.co/greensnow.txt", None, None),
}


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read().decode("utf-8", "replace")


def parse(text, col=None, delim=None):
    """Return (exact_addresses, cidr_networks).

    Handles the three shapes these providers use: one-per-line, CIDR netsets,
    and delimited columns.
    """
    singles, nets = set(), []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tok = line.split(delim)[col].strip() if col is not None else line
        except IndexError:
            continue
        try:
            net = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            continue
        if net.prefixlen == net.max_prefixlen:
            singles.add(net.network_address)
        else:
            nets.append(net)
    return singles, nets


def overlap(ours, singles, nets):
    # Exact /32s dominate these lists, so hit the set first and only scan the
    # genuine CIDR ranges linearly.
    return {ip for ip in ours
            if ip in singles
            or any(ip in n for n in nets if n.version == ip.version)}


def run(title, lists, ours):
    print(f"\n  === {title} ===")
    matched = set()
    for name, (url, col, delim) in lists.items():
        try:
            singles, nets = parse(fetch(url), col, delim)
        except Exception as e:
            print(f"    {name:34} FETCH FAILED ({type(e).__name__})")
            continue
        hits = overlap(ours, singles, nets)
        matched |= hits
        pct = 100.0 * len(hits) / len(ours) if ours else 0
        print(f"    {name:34} {len(hits):4d}/{len(ours)}  {pct:5.1f}%   "
              f"(list: {len(singles) + len(nets)} entries)")
    pct = 100.0 * len(matched) / len(ours) if ours else 0
    print(f"    {'ANY of the above':34} {len(matched):4d}/{len(ours)}  {pct:5.1f}%")
    return matched


def main():
    ours = set()
    for line in fetch(FEED).splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            try:
                ours.add(ipaddress.ip_address(line))
            except ValueError:
                pass
    if not ours:
        print("could not read the feed", file=sys.stderr)
        return 1
    print(f"  our feed: {len(ours)} IPs")

    agg = run("AGGREGATES — is this list redundant?", AGGREGATES, ours)
    run("PEERS — do other honeypot operators see the same attackers?", PEERS, ours)

    novel = len(ours) - len(agg)
    print(f"\n  NOVEL vs all aggregates: {novel}/{len(ours)}  "
          f"{100.0 * novel / len(ours):5.1f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
