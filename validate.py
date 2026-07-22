#!/usr/bin/env python3
"""
Validate the published blocklist files.

This runs in CI on every push, including the hourly automated feed commits.
The point is that a bad generator run cannot quietly publish garbage to a list
other people firewall on: a private range, an unparseable address, or the three
formats disagreeing about who is on the list.

Exit non-zero on any failure. Usage: python3 validate.py [directory]
"""

import csv
import ipaddress
import json
import os
import sys

VALID_TIERS = {"credential", "scanner"}
REQUIRED_META = {
    "name", "description", "maintainer", "homepage", "contact",
    "inclusion_criteria", "window_days", "count", "count_by_tier",
    "updated", "license",
}
REQUIRED_ENTRY = {"ip", "tier", "bans", "attempts", "first_seen", "last_seen"}

errors = []
warnings = []


def err(msg):
    errors.append(msg)


def warn(msg):
    warnings.append(msg)


def check_ip(raw, where):
    """Return a parsed address, or None after recording why it is unusable."""
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        err(f"{where}: unparseable IP {raw!r}")
        return None
    # The whole value of the list is that it names real, routable attackers.
    # A private or reserved address here means a bogon filter regressed, and
    # would have consumers blocking their own infrastructure.
    if not addr.is_global or addr.is_multicast or addr.is_reserved:
        err(f"{where}: non-global address published: {addr}")
        return None
    return addr


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    jpath = os.path.join(d, "blocklist.json")
    tpath = os.path.join(d, "blocklist.txt")
    cpath = os.path.join(d, "blocklist.csv")

    for p in (jpath, tpath, cpath):
        if not os.path.exists(p):
            err(f"missing required file: {p}")
    if errors:
        report()

    # ---- JSON: the authoritative structure ----
    with open(jpath) as f:
        data = json.load(f)

    if not isinstance(data, dict) or "meta" not in data or "ips" not in data:
        err("blocklist.json must be an object with 'meta' and 'ips'")
        report()

    meta, entries = data["meta"], data["ips"]

    missing = REQUIRED_META - set(meta)
    if missing:
        err(f"meta is missing keys: {sorted(missing)}")

    if not entries:
        err("blocklist.json contains no entries")
        report()

    json_ips = set()
    by_tier = {}
    for i, e in enumerate(entries):
        where = f"blocklist.json[{i}]"
        missing = REQUIRED_ENTRY - set(e)
        if missing:
            err(f"{where}: missing fields {sorted(missing)}")
            continue
        addr = check_ip(e["ip"], where)
        if addr is None:
            continue
        if str(addr) in json_ips:
            err(f"{where}: duplicate entry for {addr}")
        json_ips.add(str(addr))

        if e["tier"] not in VALID_TIERS:
            err(f"{where}: unknown tier {e['tier']!r}")
        by_tier[e["tier"]] = by_tier.get(e["tier"], 0) + 1

        for field in ("bans", "attempts"):
            if not isinstance(e[field], int) or e[field] < 0:
                err(f"{where}: {field} must be a non-negative int, got {e[field]!r}")
        # Documented invariant: scanner-tier entries never carry ban cycles,
        # because those are tracked in a separate table upstream.
        if e["tier"] == "scanner" and e["bans"] != 0:
            err(f"{where}: scanner-tier entry has bans={e['bans']}, expected 0")
        if e["first_seen"] and e["last_seen"] and e["first_seen"] > e["last_seen"]:
            err(f"{where}: first_seen {e['first_seen']} is after last_seen {e['last_seen']}")

    # ---- meta counts must describe the payload ----
    if meta.get("count") != len(entries):
        err(f"meta.count={meta.get('count')} but {len(entries)} entries present")
    if meta.get("count_by_tier") != by_tier:
        err(f"meta.count_by_tier={meta.get('count_by_tier')} but actual is {by_tier}")

    # ---- TXT: comment header + one IP per line ----
    txt_ips = set()
    with open(tpath) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if check_ip(line, f"blocklist.txt:{n}"):
                if line in txt_ips:
                    err(f"blocklist.txt:{n}: duplicate {line}")
                txt_ips.add(line)

    # ---- CSV: header + rows ----
    csv_ips = set()
    with open(cpath, newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames and "ip" not in reader.fieldnames:
            err(f"blocklist.csv header lacks an 'ip' column: {reader.fieldnames}")
        else:
            for n, row in enumerate(reader, 2):
                if check_ip(row["ip"], f"blocklist.csv:{n}"):
                    csv_ips.add(row["ip"])
                if row.get("tier") not in VALID_TIERS:
                    err(f"blocklist.csv:{n}: unknown tier {row.get('tier')!r}")

    # ---- the three formats must name the same set ----
    if json_ips != txt_ips:
        only_j, only_t = sorted(json_ips - txt_ips), sorted(txt_ips - json_ips)
        err(f"json/txt disagree: {len(only_j)} only in json {only_j[:3]}, "
            f"{len(only_t)} only in txt {only_t[:3]}")
    if json_ips != csv_ips:
        only_j, only_c = sorted(json_ips - csv_ips), sorted(csv_ips - json_ips)
        err(f"json/csv disagree: {len(only_j)} only in json {only_j[:3]}, "
            f"{len(only_c)} only in csv {only_c[:3]}")

    # ---- README should not advertise a count it no longer ships ----
    rpath = os.path.join(d, "README.md")
    if os.path.exists(rpath):
        readme = open(rpath).read()
        if f"**{len(entries)} IPs**" not in readme:
            warn(f"README does not state the current count (**{len(entries)} IPs**) — "
                 "it drifted out of date once before")

    report()


def report():
    for w in warnings:
        print(f"WARN  {w}")
    for e in errors:
        print(f"ERROR {e}")
    if errors:
        print(f"\n{len(errors)} error(s)")
        sys.exit(1)
    print(f"OK — {len(warnings)} warning(s)")
    sys.exit(0)


if __name__ == "__main__":
    main()
